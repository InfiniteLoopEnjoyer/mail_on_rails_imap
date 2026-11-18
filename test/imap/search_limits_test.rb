# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# M5 (audit 2026-11-17), SEARCH side: nothing bounded the number of keys,
# and every sequence-set or store-answered key built its own Set at parse
# time - a 521 KB SEARCH of 130,400 keys over 300 messages cost +1.4 GB.
# Now the key count is capped, a repeated key is resolved once per
# command, and a sequence set is a few ranges rather than a Set of every
# message it covers.
class SearchLimitsTest < Minitest::Test
  include WireHarness

  Server = MailOnRails::ImapServer

  # A store that counts the pushdown queries it is asked.
  class CountingStore < MailOnRails::Imap::Store::Memory
    attr_reader :queries

    def initialize(*)
      super
      @queries = Hash.new(0)
    end

    %i[search_meta search_header search_text].each do |name|
      define_method(name) do |*args|
        @queries[name] += 1
        super(*args)
      end
    end
  end

  def setup
    super
    @store = CountingStore.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def selected(count)
    count.times do |i|
      @store.append(@account_id, "INBOX", "From: a#{i}@x.test\r\nSubject: message #{i}\r\n\r\nbody #{i}\r\n",
                    i.even? ? [ "\\Seen" ] : [], nil)
    end
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def search(client, tag, criteria, uid: false)
    reply = command(client, tag, "#{"UID " if uid}SEARCH #{criteria}")
    assert_match(/^#{tag} OK/, reply, criteria)
    reply[/^\* SEARCH ?(.*)\r\n/, 1].to_s.split.map(&:to_i)
  end

  # -- the cap -----------------------------------------------------------------

  test "more search keys than any client sends are refused" do
    c = selected(3)

    assert_equal "a1 NO [LIMIT] Too many search keys\r\n",
                 command(c, "a1", "SEARCH #{"ALL " * (Server::MAX_SEARCH_KEYS + 1)}")
    assert_equal "a2 NO [LIMIT] Too many search keys\r\n",
                 command(c, "a2", "SORT (ARRIVAL) UTF-8 #{"1:* " * (Server::MAX_SEARCH_KEYS + 1)}")
    assert_equal "a3 NO [LIMIT] Too many search keys\r\n",
                 command(c, "a3", "THREAD REFERENCES UTF-8 #{"UNSEEN " * (Server::MAX_SEARCH_KEYS + 1)}")
    assert_match(/\Aa4 OK/, command(c, "a4", "NOOP"))
  end

  test "NOT, OR and groups count as keys" do
    c = selected(3)
    nested = "NOT " * Server::MAX_SEARCH_KEYS # each NOT is a key, plus the ALL under them

    with_search_depth(Server::MAX_SEARCH_KEYS * 2) do
      assert_equal "a1 NO [LIMIT] Too many search keys\r\n", command(c, "a1", "SEARCH #{nested}ALL")
    end
  end

  def with_search_depth(depth)
    old = Server::MAX_SEARCH_DEPTH
    Server.send(:remove_const, :MAX_SEARCH_DEPTH)
    Server.const_set(:MAX_SEARCH_DEPTH, depth)
    yield
  ensure
    Server.send(:remove_const, :MAX_SEARCH_DEPTH)
    Server.const_set(:MAX_SEARCH_DEPTH, old)
  end

  test "a search at the cap runs" do
    c = selected(5)

    assert_equal [ 1, 2, 3, 4, 5 ], search(c, "a1", "ALL " * Server::MAX_SEARCH_KEYS)
  end

  # The kind of search a client builds from a user's filter rules, or to
  # find a set of messages by id: a few dozen terms.
  test "a forty-term OR chain of header searches is well under the cap" do
    c = selected(4)
    ids = (1..40).map { |i| "HEADER Message-ID <id#{i}@x.test>" }
    chain = ids[0..-2].map { |term| "OR #{term}" }.join(" ") + " #{ids.last}"

    assert_equal [], search(c, "a1", chain)
    assert_equal [ 2, 4 ], search(c, "a2", "#{"OR SUBJECT nomatch " * 30}UNSEEN")
  end

  # -- repeats are resolved once -------------------------------------------------

  test "a store-answered key repeated in one command is one store query" do
    c = selected(6)

    assert_equal [ 1, 2, 3, 4, 5, 6 ], search(c, "a1", "LARGER 0 " * 50)
    assert_equal 1, @store.queries[:search_meta]

    assert_equal [ 4 ], search(c, "a2", "#{"SUBJECT message " * 20}#{"BODY body " * 20}#{"FROM a3@x.test " * 20}")
    assert_equal 2, @store.queries[:search_header], "one for SUBJECT, one for FROM"
    assert_equal 1, @store.queries[:search_text]

    # Different values are different keys.
    search(c, "a3", "LARGER 0 LARGER 1 SMALLER 100000 LARGER 0")
    assert_equal 4, @store.queries[:search_meta]
  end

  test "a repeated sequence set is parsed once and held as ranges" do
    c = selected(3)
    session = @session_objects.last
    parses = 0
    original = session.method(:parse_ranges)
    session.define_singleton_method(:parse_ranges) do |set, max|
      parses += 1
      original.call(set, max)
    end
    sets_built = count_sets do
      assert_equal [ 1, 2, 3 ], search(c, "a1", "#{"1:* " * 50}#{"UID 1:* " * 50}")
    end

    assert_equal 2, parses, "one for the sequence set, one for the uid set"
    assert_operator sets_built, :<, 10, "no Set per key (#{sets_built} built)"
  end

  def count_sets
    before = ObjectSpace.each_object(Set).count
    GC.disable
    yield
    ObjectSpace.each_object(Set).count - before
  ensure
    GC.enable
  end

  # -- sequence-set keys still mean what they meant ------------------------------

  test "sequence and uid set keys select the same messages as before" do
    c = selected(10)
    command(c, "d1", "STORE 3,7 +FLAGS.SILENT (\\Deleted)")
    command(c, "d2", "EXPUNGE") # uids 1,2,4,5,6,8,9,10 at seqs 1..8

    {
      "1" => [ 1 ], "2:4" => [ 2, 3, 4 ], "4:2" => [ 2, 3, 4 ], "*" => [ 8 ], "7:*" => [ 7, 8 ], "*:7" => [ 7, 8 ],
      "1,3,5:6" => [ 1, 3, 5, 6 ], "9:20" => [], "0" => [], "2:3,3:5,1" => [ 1, 2, 3, 4, 5 ],
      "UID 4:6" => [ 3, 4, 5 ], "UID 3" => [], "UID 3,7,8" => [ 6 ], "UID 9:*" => [ 7, 8 ], "UID *" => [ 8 ],
      "UID 100:200" => [], "UID 1:3 2:*" => [ 2 ], "NOT 2:7" => [ 1, 8 ], "OR 1 UID 10" => [ 1, 8 ],
      "NOT UID 1:9" => [ 8 ], "1:4 UID 4:10 UNSEEN" => [ 3 ]
    }.each_with_index do |(criteria, expected), i|
      assert_equal expected, search(c, "q#{i}", criteria), criteria
    end
    assert_equal [ 4, 5, 6 ], search(c, "u1", "UID 4:6", uid: true)
  end

  test "sequence-set keys against an empty mailbox match nothing and parse nothing" do
    c = selected(0)

    assert_equal [], search(c, "a1", "1:* UID 1:* NOT 5")
    # As before: a set with too many ranges is only an error where there
    # are messages to resolve it against.
    assert_equal [], search(c, "a2", "UID #{(1..600).to_a.join(",")}")
  end

  test "the saved search result is still usable as a key, repeated or not" do
    c = selected(6)
    assert_match(/^a1 OK/, command(c, "a1", "SEARCH RETURN (SAVE) UNSEEN"))

    assert_equal [ 2, 4, 6 ], search(c, "a2", "$")
    assert_equal [ 4, 6 ], search(c, "a3", "$ UID $ $ 3:* NOT 5")
    assert_equal [ 1, 3, 5 ], search(c, "a4", "NOT $")
  end
end

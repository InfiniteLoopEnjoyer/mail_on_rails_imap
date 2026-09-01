# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# TEXT/BODY pushdown wiring: when the store offers search_text the
# session must resolve content keys store-side without ever fetching raw
# bytes; queries an index can't express (no word characters) and stores
# without search_text take the session's own substring scan. Substring
# *semantics* are audited in search_audit_test.rb - the memory store's
# search_text is RFC-exact, so those runs exercise the pushdown path too.
class SearchPushdownTest < Minitest::Test
  include WireHarness

  # Memory store that records pushdown calls and every fetch.
  class ProbeStore < MailOnRails::Imap::Store::Memory
    attr_reader :search_text_calls, :search_header_calls, :fetches

    def initialize(...)
      super
      @search_text_calls = []
      @search_header_calls = []
      @fetches = [] # [with_raw, uid count]
    end

    def search_text(mailbox_id, query, scope)
      @search_text_calls << [ query, scope ]
      super
    end

    def search_header(mailbox_id, field, query)
      @search_header_calls << [ field, query ]
      super
    end

    def fetch(mailbox_id, uids, with_raw)
      @fetches << [ with_raw, uids.length ]
      super
    end

    def raw_fetches = @fetches.count { |with_raw, _n| with_raw }
    def meta_fetches = @fetches.count { |with_raw, _n| !with_raw }
  end

  # A memory store with neither pushdown method: the session's own scans.
  class BareStore < MailOnRails::Imap::Store::Memory
    undef_method :search_text
    undef_method :search_header
  end

  RAW = "From: fred@example.test\r\nSubject: afternoon meeting\r\n\r\nthe kumquat budget?\r\n"

  def swap_store(store)
    @store = store
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def seed_and_select
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def search_hits(client, tag, criteria)
    command(client, tag, "SEARCH #{criteria}")[/^\* SEARCH ?([\d ]*)/, 1].to_s.split.map(&:to_i)
  end

  test "TEXT and BODY push down to search_text without fetching raw bytes" do
    swap_store(ProbeStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "p1", %(TEXT "kumquat"))
    assert_equal [ 1 ], search_hits(c, "p2", %(BODY "kumquat"))
    # BODY never matches header-only text; the scope must reach the store.
    assert_equal [], search_hits(c, "p3", %(BODY "afternoon"))

    assert_equal [ [ "kumquat", "text" ], [ "kumquat", "body" ], [ "afternoon", "body" ] ],
                 @store.search_text_calls
    assert_equal 0, @store.raw_fetches, "pushdown must not ship raw bytes to the session"
  end

  test "queries without word characters take the substring scan instead" do
    swap_store(ProbeStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "q1", %(TEXT "?"))
    assert_equal [ 1 ], search_hits(c, "q2", %(TEXT ""))
    assert_equal [], search_hits(c, "q3", %(BODY "!"))

    assert_empty @store.search_text_calls, "an FTS index can't answer these"
    assert_operator @store.raw_fetches, :>, 0
  end

  test "a store without search_text falls back to the substring scan" do
    swap_store(BareStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "f1", %(TEXT "kumquat"))
    assert_equal [ 1 ], search_hits(c, "f2", %(BODY "umqua")) # substring, RFC-exact
    assert_equal [], search_hits(c, "f3", %(BODY "afternoon"))
  end

  # -- M9: header pushdown and level-by-level fetching --------------------------

  test "FROM TO SUBJECT and their HEADER spellings push down to search_header" do
    swap_store(ProbeStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "h1", %(FROM "fred"))
    assert_equal [ 1 ], search_hits(c, "h2", %(SUBJECT "afternoon"))
    assert_equal [], search_hits(c, "h3", %(TO "fred"))
    assert_equal [ 1 ], search_hits(c, "h4", %(HEADER "Subject" "meeting"))
    assert_equal [], search_hits(c, "h5", %(NOT FROM "fred"))

    assert_equal [ %w[from fred], %w[subject afternoon], %w[to fred], %w[subject meeting], %w[from fred] ],
                 @store.search_header_calls
    assert_empty @store.fetches, "header pushdown must not fetch anything"
  end

  test "header values without word characters take the raw scan instead" do
    swap_store(ProbeStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "p1", %(SUBJECT " "))
    assert_equal [], search_hits(c, "p2", %(FROM "!"))
    assert_empty @store.search_header_calls
    assert_operator @store.raw_fetches, :>, 0
  end

  test "a store without search_header scans raw headers" do
    swap_store(BareStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "b1", %(FROM "fred@example"))
    assert_equal [ 1 ], search_hits(c, "b2", %(HEADER "subject" "noon meet")) # substring, RFC-exact
    assert_equal [], search_hits(c, "b3", %(TO "fred"))
  end

  # Keys the snapshot answers on its own (uid, seq, flags, modseq, $)
  # never call the store, however large the mailbox.
  test "snapshot-level keys never fetch" do
    swap_store(ProbeStore.new)
    200.times { @store.append(@account_id, "INBOX", RAW, [], nil) }
    @store.store_flags(inbox_id, [ 7, 9 ], "+", [ "\\Flagged", "custom" ])
    c = connect
    command(c, "s0", "SELECT INBOX")
    @store.fetches.clear

    assert_equal [ 1 ], search_hits(c, "u1", "UID 1")
    assert_equal [ 7, 9 ], search_hits(c, "u2", "FLAGGED")
    assert_equal [ 7, 9 ], search_hits(c, "u3", "KEYWORD custom")
    assert_equal [ 1, 2, 3 ], search_hits(c, "u4", "1:3 UNSEEN")
    assert_equal 198, search_hits(c, "u5", "UNFLAGGED").length
    assert_equal [ 7, 9 ], search_hits(c, "u6", "OR UID 7 UID 9")
    reply = command(c, "u7", "UID SEARCH UID 1")
    assert_match(/^\* SEARCH 1\r\n/, reply)
    assert_empty @store.fetches, "no store fetch for snapshot-level criteria"
  end

  # Metadata keys fetch without raw bytes, and only for the messages the
  # snapshot keys let through.
  test "metadata keys fetch metadata only, for snapshot survivors" do
    swap_store(ProbeStore.new)
    5.times { @store.append(@account_id, "INBOX", RAW, [], nil) }
    c = connect
    command(c, "s0", "SELECT INBOX")
    @store.fetches.clear

    assert_equal [ 2, 3 ], search_hits(c, "m1", "2:3 LARGER 10")
    assert_equal [ [ false, 2 ] ], @store.fetches, "one metadata fetch, for the two snapshot survivors"
  end

  # Raw keys (CC, HEADER <other>, SENT*) come last, in bounded batches,
  # only for the survivors of the cheaper phases.
  test "raw keys fetch in batches for survivors only" do
    swap_store(ProbeStore.new)
    120.times do |i|
      @store.append(@account_id, "INBOX", "From: f@x.test\r\nCc: cc#{i % 2}@x.test\r\nSubject: s\r\n\r\nb\r\n", [], nil)
    end
    c = connect
    command(c, "s0", "SELECT INBOX")
    @store.fetches.clear

    hits = search_hits(c, "r1", %(CC "cc1"))
    assert_equal 60, hits.length
    assert_equal [ [ false, 120 ] ], @store.fetches.reject { |with_raw, _n| with_raw }
    raw = @store.fetches.select { |with_raw, _n| with_raw }
    assert_operator raw.length, :>=, 3
    assert raw.all? { |_w, n| n <= MailOnRails::ImapServer::FETCH_RAW_BATCH }
    assert_equal 120, raw.sum { |_w, n| n }

    @store.fetches.clear
    assert_equal [ 2, 4 ], search_hits(c, "r2", %(2:4 CC "cc1"))
    assert_equal [ [ false, 3 ], [ true, 3 ] ], @store.fetches, "raw bytes only for the three candidates"
  end

  # Past MAX_SEARCH_RAW_MESSAGES / MAX_SEARCH_RAW_BYTES of raw work the
  # command fails with NO [LIMIT] rather than parsing the mailbox.
  test "raw search work is capped with NO LIMIT" do
    swap_store(ProbeStore.new)
    30.times { |i| @store.append(@account_id, "INBOX", "From: f@x.test\r\nCc: cc@x.test\r\nSubject: #{i}\r\n\r\nb\r\n", [], nil) }
    c = connect
    command(c, "s0", "SELECT INBOX")

    klass = MailOnRails::ImapServer
    old = klass.const_get(:MAX_SEARCH_RAW_MESSAGES)
    klass.send(:remove_const, :MAX_SEARCH_RAW_MESSAGES)
    klass.const_set(:MAX_SEARCH_RAW_MESSAGES, 10)
    begin
      assert_match(/\Al1 NO \[LIMIT\]/, command(c, "l1", %(SEARCH CC "cc")))
      assert_match(/\Al2 NO \[LIMIT\]/, command(c, "l2", %(SORT (CC) UTF-8 ALL)))
      assert_match(/\Al3 NO \[LIMIT\]/, command(c, "l3", %(THREAD REFERENCES UTF-8 ALL)))
      # Within the cap the same keys work, and narrowing counts.
      assert_equal [ 1, 2, 3 ], search_hits(c, "l4", %(1:3 CC "cc"))
      assert_match(/^l5 OK/, command(c, "l5", %(SORT (CC) UTF-8 1:5)))
      assert_match(/\Al6 OK/, command(c, "l6", "NOOP"))
    ensure
      klass.send(:remove_const, :MAX_SEARCH_RAW_MESSAGES)
      klass.const_set(:MAX_SEARCH_RAW_MESSAGES, old)
    end
  end
end

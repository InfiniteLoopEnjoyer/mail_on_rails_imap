require "test_helper"
require "wire_harness"

# SORT (RFC 5256): server-side ordering with SEARCH-style filtering.
class SortTest < Minitest::Test
  include WireHarness

  def build(from:, subject:, date:, body: "x")
    "From: #{from}\r\nTo: someone@example.test\r\nDate: #{date}\r\nSubject: #{subject}\r\n\r\n#{body}\r\n"
  end

  # Three messages whose arrival order, sent dates, sizes, senders, and
  # subjects all disagree, so each criterion produces a distinct order.
  # uid 1: arrived first (2020), sent 2022, from carol, subject "zebra", small
  # uid 2: arrived second (2021), sent 2021, from alice, subject "Re: apple", large
  # uid 3: arrived third (2022), sent 2020, from bob, subject "apple", medium
  def seed_and_select
    @store.append(@account_id, "INBOX",
                  build(from: "carol@example.test", subject: "zebra", date: "Sat, 1 Jan 2022 10:00:00 +0000"),
                  [], Time.utc(2020, 1, 1).to_i)
    @store.append(@account_id, "INBOX",
                  build(from: "Alice <alice@example.test>", subject: "Re: apple", date: "Fri, 1 Jan 2021 10:00:00 +0000", body: "y" * 500),
                  [], Time.utc(2021, 1, 1).to_i)
    @store.append(@account_id, "INBOX",
                  build(from: "bob@example.test", subject: "apple", date: "Wed, 1 Jan 2020 10:00:00 +0000", body: "z" * 100),
                  [], Time.utc(2022, 1, 1).to_i)
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def assert_sort(client, tag, criteria, expected, keys: "ALL", uid: false)
    reply = command(client, tag, "#{uid ? "UID " : ""}SORT #{criteria} UTF-8 #{keys}")
    assert_equal expected, reply[/^\* SORT ?([\d ]*)/, 1].to_s.split.map(&:to_i), "SORT #{criteria}"
    assert_match(/^#{tag} OK/, reply)
  end

  test "capability advertises sort" do
    c = connect(login: false)
    assert_match(/\bSORT\b/, command(c, "c1", "CAPABILITY"))
  end

  test "single criteria orders" do
    c = seed_and_select
    assert_sort(c, "t1", "(ARRIVAL)", [ 1, 2, 3 ])
    assert_sort(c, "t2", "(REVERSE ARRIVAL)", [ 3, 2, 1 ])
    assert_sort(c, "t3", "(DATE)", [ 3, 2, 1 ])
    assert_sort(c, "t4", "(SIZE)", [ 1, 3, 2 ])
    assert_sort(c, "t5", "(FROM)", [ 2, 3, 1 ], keys: "ALL")
    assert_sort(c, "t6", "(SUBJECT)", [ 2, 3, 1 ].sort_by { |s| [ s == 1 ? 1 : 0, s ] },
                keys: "ALL") # base subject: "apple"(2,3 tie -> seq order), then "zebra"
  end

  test "base subject strips reply and forward markers" do
    c = seed_and_select
    # uid 2 "Re: apple" and uid 3 "apple" share a base subject; the tie
    # breaks by sequence number, so 2 sorts before 3.
    reply = command(c, "b1", "SORT (SUBJECT) UTF-8 ALL")
    assert_match(/\* SORT 2 3 1\r\n/, reply)
  end

  test "multiple criteria tiebreak in order" do
    c = seed_and_select
    # Same base subject for 2 and 3: SIZE breaks the tie (3 is smaller).
    assert_sort(c, "m1", "(SUBJECT SIZE)", [ 3, 2, 1 ])
    assert_sort(c, "m2", "(SUBJECT REVERSE SIZE)", [ 2, 3, 1 ])
  end

  test "uid sort returns uids and search keys filter" do
    c = seed_and_select
    assert_sort(c, "u1", "(REVERSE DATE)", [ 1, 2, 3 ], uid: true)
    assert_sort(c, "u2", "(ARRIVAL)", [ 2, 3 ], keys: "SINCE 1-Jun-2020")
    assert_sort(c, "u3", "(ARRIVAL)", [], keys: "SUBJECT nosuchthing")
  end

  test "sort syntax and charset validation" do
    c = seed_and_select
    assert_match(/\Ax1 BAD/, command(c, "x1", "SORT (BOGUS) UTF-8 ALL"))
    assert_match(/\Ax2 BAD/, command(c, "x2", "SORT () UTF-8 ALL"))
    assert_match(/\Ax3 BAD/, command(c, "x3", "SORT (REVERSE) UTF-8 ALL"))
    assert_match(/\Ax4 BAD/, command(c, "x4", "SORT ARRIVAL UTF-8 ALL"), "criteria list must be parenthesized")
    assert_match(/\Ax5 NO \[BADCHARSET/, command(c, "x5", "SORT (ARRIVAL) KOI8-R ALL"))
    assert_match(/\Ax6 BAD/, command(c, "x6", "SORT (ARRIVAL) UTF-8"), "search keys required")
    assert_match(/\Ax7 BAD/, command(c, "x7", "SORT (ARRIVAL) UTF-8 BOGUSKEY"))
  end

  # RFC 5256 §2.1 base-subject cases the single-pass strip must keep
  # answering like the old strip-until-stable loop did.
  test "base subject semantics" do
    session = MailOnRails::ImapServer::Session.new(nil, @store, { tls: :implicit }, nil)
    base = ->(s) { session.send(:base_subject, s) }
    assert_equal "apple", base.call("Re: apple")
    assert_equal "apple", base.call("RE: FWD: Fw: re: apple")
    assert_equal "apple", base.call("re[2]: apple")
    assert_equal "apple", base.call("apple (fwd)")
    assert_equal "apple", base.call("apple (fwd) (FWD)")
    assert_equal "apple", base.call("re: apple (fwd)")
    assert_equal "apple", base.call("Fwd:   apple   (fwd)")
    assert_equal "apple pie", base.call("  Re:\tapple \r\n pie ")
    assert_equal "(fwd) re: x", base.call("re: (fwd) re: x (fwd)")
    assert_equal "", base.call("")
    assert_equal "", base.call(nil)
    assert_equal "reply", base.call("reply"), "a bare word starting with re is not a marker"
  end

  # A subject that is one long re: re: re: chain is stripped in linear
  # time (the old loop re-copied the subject per marker: 400 KB of them
  # took minutes), and a subject past MAX_BASE_SUBJECT_BYTES is cut
  # before normalizing.
  test "a 400 KB re: chain sorts promptly" do
    session = MailOnRails::ImapServer::Session.new(nil, @store, { tls: :implicit }, nil)
    subject = "re: " * 100_000 + "apple"
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = session.send(:base_subject, subject)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.25
    assert_equal "", result, "a cut chain of markers has no base subject left"
    assert_operator session.send(:base_subject, "x" * 5000).bytesize, :<=, MailOnRails::ImapServer::MAX_BASE_SUBJECT_BYTES

    @store.append(@account_id, "INBOX", build(from: "a@x.test", subject: subject, date: "Sat, 1 Jan 2022 10:00:00 +0000"), [], nil)
    @store.append(@account_id, "INBOX", build(from: "b@x.test", subject: "apple", date: "Sat, 1 Jan 2022 10:00:00 +0000"), [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    reply = command(c, "s1", "SORT (SUBJECT) UTF-8 ALL")
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
    assert_match(/^\* SORT 1 2\r\n/, reply, "the empty base subject sorts first")
  end

  test "sort requires a selected mailbox" do
    c = connect
    assert_match(/\An1 NO/, command(c, "n1", "SORT (ARRIVAL) UTF-8 ALL"))
  end
end

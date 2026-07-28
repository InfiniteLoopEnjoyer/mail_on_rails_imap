require "test_helper"
require "wire_harness"

# RFC 3501/9051 + RFC 4731 SEARCH compliance audit, ported from mox's
# imapserver/search_test.go. The mailbox is seeded so sequence numbers
# and UIDs diverge (four expunged placeholders first): seqs 1,2,3 are
# UIDs 5,6,7 — any confusion between the two fails loudly. mox cases for
# extensions we don't advertise (SAVEDATE, SEARCHRES, MULTISEARCH) are
# not ported.
class SearchAuditTest < Minitest::Test
  include WireHarness

  EXAMPLE = <<~MSG.gsub("\n", "\r\n")
    Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)
    From: Fred Foobar <foobar@Blurdybloop.example>
    Subject: afternoon meeting
    To: mooch@owatagu.siam.edu.example
    Message-Id: <B27397-0100000@Blurdybloop.example>
    MIME-Version: 1.0
    Content-Type: TEXT/PLAIN; CHARSET=US-ASCII

    Hello Joe, do you think we can meet at 3:30 tomorrow?

  MSG

  SEARCH_MSG = <<~MSG.gsub("\n", "\r\n")
    Date: Mon, 1 Jan 2022 10:00:00 +0100 (CEST)
    From: mjl <mjl@mox.example>
    Subject: mox
    To: mox <mox@mox.example>
    Cc: <xcc@mox.example>
    Bcc: <bcc@mox.example>
    Reply-To: <noreply@mox.example>
    Message-Id: <123@mox.example>
    MIME-Version: 1.0
    Content-Type: multipart/alternative; boundary=x

    --x
    Content-Type: text/plain; charset=utf-8

    this is plain text.

    --x
    Content-Type: text/html; charset=utf-8

    this is html.

    --x--
  MSG

  MOST_FLAGS = [
    "\\Deleted", "\\Seen", "\\Answered", "\\Flagged", "\\Draft",
    "$Forwarded", "$Junk", "$Notjunk", "$Phishing", "$MDNSent",
    "custom1", "Custom2"
  ].freeze

  # Seqs 1,2,3 = UIDs 5,6,7: EXAMPLE (old), SEARCH_MSG, SEARCH_MSG+flags.
  def seed_and_select
    4.times { @store.append(@account_id, "INBOX", "X: y\r\n\r\nplaceholder\r\n", [ "\\Deleted" ], nil) }
    @store.expunge(inbox_id)
    @store.append(@account_id, "INBOX", EXAMPLE, [], Time.utc(2020, 1, 1, 10).to_i)
    @store.append(@account_id, "INBOX", SEARCH_MSG, [], Time.utc(2022, 1, 1, 9).to_i)
    @store.append(@account_id, "INBOX", SEARCH_MSG, MOST_FLAGS.dup, Time.utc(2022, 1, 1, 9).to_i)
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def assert_search(client, tag, criteria, expected)
    reply = command(client, tag, "SEARCH #{criteria}")
    hits = reply[/^\* SEARCH ?([\d ]*)/, 1].to_s.split.map(&:to_i)
    assert_equal expected, hits, "SEARCH #{criteria}"
    assert_match(/^#{tag} OK/, reply)
  end

  def assert_uid_search(client, tag, criteria, expected)
    reply = command(client, tag, "UID SEARCH #{criteria}")
    hits = reply[/^\* SEARCH ?([\d ]*)/, 1].to_s.split.map(&:to_i)
    assert_equal expected, hits, "UID SEARCH #{criteria}"
  end

  test "search requires a selected mailbox" do
    c = connect
    assert_match(/\An1 NO/, command(c, "n1", "SEARCH ALL"))
  end

  test "search returns seqs and uid search returns uids" do
    c = seed_and_select
    assert_search(c, "t1", "ALL", [ 1, 2, 3 ])
    assert_uid_search(c, "t2", "ALL", [ 5, 6, 7 ])
  end

  test "flag search keys" do
    c = seed_and_select
    assert_search(c, "f1", "ANSWERED", [ 3 ])
    assert_search(c, "f2", "DELETED", [ 3 ])
    assert_search(c, "f3", "FLAGGED", [ 3 ])
    assert_search(c, "f4", "SEEN", [ 3 ])
    assert_search(c, "f5", "DRAFT", [ 3 ])
    assert_search(c, "f6", "UNANSWERED", [ 1, 2 ])
    assert_search(c, "f7", "UNDELETED", [ 1, 2 ])
    assert_search(c, "f8", "UNFLAGGED", [ 1, 2 ])
    assert_search(c, "f9", "UNSEEN", [ 1, 2 ])
    assert_search(c, "f10", "UNDRAFT", [ 1, 2 ])
    assert_search(c, "f11", "KEYWORD $Forwarded", [ 3 ])
    assert_search(c, "f12", "UNKEYWORD $Junk", [ 1, 2 ])
  end

  test "keyword search is case insensitive" do
    c = seed_and_select
    # Stored as "custom1" and "Custom2"; atoms match case-insensitively.
    assert_search(c, "k1", "KEYWORD Custom1", [ 3 ])
    assert_search(c, "k2", "KEYWORD custom2", [ 3 ])
    assert_search(c, "k3", "UNKEYWORD custom1", [ 1, 2 ])
  end

  test "new old recent" do
    c = seed_and_select
    assert_search(c, "o1", "NEW", [])
    assert_search(c, "o2", "RECENT", [])
    assert_search(c, "o3", "OLD", [ 1, 2, 3 ])
  end

  test "header and address searches" do
    c = seed_and_select
    assert_search(c, "h1", %(BCC "bcc@mox.example"), [ 2, 3 ])
    assert_search(c, "h2", %(CC "xcc@mox.example"), [ 2, 3 ])
    assert_search(c, "h3", %(FROM "foobar@Blurdybloop.example"), [ 1 ])
    assert_search(c, "h4", %(TO "mooch@owatagu.siam.edu.example"), [ 1 ])
    assert_search(c, "h5", %(SUBJECT "afternoon"), [ 1 ])
    assert_search(c, "h6", %(HEADER "subject" "afternoon"), [ 1 ])
  end

  test "body and text searches" do
    c = seed_and_select
    assert_search(c, "b1", %(BODY "Joe"), [ 1 ])
    assert_search(c, "b2", %(BODY "Joe" BODY "bogus"), [])
    assert_search(c, "b3", %(BODY "Joe" TEXT "Blurdybloop"), [ 1 ])
    assert_search(c, "b4", %(BODY "Joe" NOT TEXT "mox"), [ 1 ])
    assert_search(c, "b5", %(BODY "Joe" NOT NOT BODY "Joe"), [ 1 ])
    assert_search(c, "b6", %(BODY "this is plain text"), [ 2, 3 ])
    assert_search(c, "b7", %(BODY "this is html"), [ 2, 3 ])
    assert_search(c, "b8", %(TEXT "Joe"), [ 1 ])
    assert_search(c, "b9", %(NOT TEXT "mox"), [ 1 ])
  end

  test "internaldate searches use received date not date header" do
    c = seed_and_select
    assert_search(c, "d1", "BEFORE 1-Jan-2038", [ 1, 2, 3 ])
    # Message 1's Date header is 1994, but it was received 2020-01-01.
    assert_search(c, "d2", "BEFORE 1-Jan-2020", [])
    assert_search(c, "d3", "SINCE 1-Jan-2020", [ 1, 2, 3 ])
    assert_search(c, "d4", "ON 1-Jan-2022", [ 2, 3 ])
    assert_search(c, "d5", "OLDER 60", [ 1, 2, 3 ])
    assert_search(c, "d6", "YOUNGER 60", [])
  end

  test "sent date searches use the date header" do
    c = seed_and_select
    assert_search(c, "e1", "SENTBEFORE 8-Feb-1994", [ 1 ])
    assert_search(c, "e2", "SENTON 7-Feb-1994", [ 1 ])
    assert_search(c, "e3", "SENTSINCE 6-Feb-1994", [ 1, 2, 3 ])
  end

  test "size or not and uid keys" do
    c = seed_and_select
    assert_search(c, "g1", "LARGER 1", [ 1, 2, 3 ])
    assert_search(c, "g2", "SMALLER 9999999", [ 1, 2, 3 ])
    assert_search(c, "g3", "OR LARGER 1000000 SMALLER 1", [])
    assert_search(c, "g4", "OR SEEN UNSEEN", [ 1, 2, 3 ])
    assert_search(c, "g5", "OR UNSEEN SEEN", [ 1, 2, 3 ])
    # UIDs are 5:7 — a UID key of 1 matches nothing even though seq 1 exists.
    assert_search(c, "g6", "UID 1", [])
    assert_search(c, "g7", "UID 5", [ 1 ])
    # A bare number set is a *sequence* key even inside UID SEARCH; only
    # the reported results switch to UIDs (RFC 3501 §6.4.8).
    assert_uid_search(c, "g8", "1", [ 5 ])
    assert_uid_search(c, "g9", "5", [])
  end

  test "charset handling" do
    c = seed_and_select
    assert_match(/\Ac1 NO \[BADCHARSET/, command(c, "c1", %(SEARCH CHARSET KOI8-R TEXT "mox")))
    assert_search(c, "c2", %(CHARSET us-ascii TEXT "mox"), [ 2, 3 ])
    assert_search(c, "c3", %(CHARSET utf-8 TEXT "mox"), [ 2, 3 ])
    # CHARSET after RETURN options (RFC 4731 ordering).
    assert_match(/\Ac4 NO \[BADCHARSET/, command(c, "c4", %(SEARCH RETURN () CHARSET KOI8-R TEXT "mox")))
    assert_match(/ALL 2:3/, command(c, "c5", %(SEARCH RETURN () CHARSET us-ascii TEXT "mox")))
  end

  test "esearch return option matrix" do
    c = seed_and_select
    # RETURN () implies ALL.
    assert_match(/\A\* ESEARCH \(TAG "r1"\) ALL 1:3\r\n/, command(c, "r1", "SEARCH RETURN () ALL"))
    assert_match(/\A\* ESEARCH \(TAG "r2"\) MIN 1 MAX 3 COUNT 3 ALL 1:3\r\n/,
                 command(c, "r2", "SEARCH RETURN (MIN MAX COUNT ALL) ALL"))
    assert_match(/\A\* ESEARCH \(TAG "r3"\) MIN 1\r\n/, command(c, "r3", "SEARCH RETURN (MIN) ALL"))
    assert_match(/\A\* ESEARCH \(TAG "r4"\) MIN 3\r\n/, command(c, "r4", "SEARCH RETURN (MIN) 3"))
    assert_match(/\A\* ESEARCH \(TAG "r5"\) MAX 3\r\n/, command(c, "r5", "SEARCH RETURN (MAX) ALL"))
    assert_match(/\A\* ESEARCH \(TAG "r6"\) MAX 1\r\n/, command(c, "r6", "SEARCH RETURN (MAX) 1"))
    assert_match(/\A\* ESEARCH \(TAG "r7"\) MIN 1 MAX 3\r\n/, command(c, "r7", "SEARCH RETURN (MIN MAX) ALL"))

    # No matches: MIN/MAX/ALL are omitted, COUNT stays (as 0).
    assert_match(/\A\* ESEARCH \(TAG "r8"\)\r\n/, command(c, "r8", "SEARCH RETURN (MIN) NOT ALL"))
    assert_match(/\A\* ESEARCH \(TAG "r9"\)\r\n/, command(c, "r9", "SEARCH RETURN (MIN MAX ALL) NOT ALL"))
    assert_match(/\A\* ESEARCH \(TAG "r10"\) COUNT 0\r\n/, command(c, "r10", "SEARCH RETURN (MIN MAX ALL COUNT) NOT ALL"))

    # Subsets, including via a UID key inside a non-UID search.
    assert_match(/\A\* ESEARCH \(TAG "r11"\) MIN 1 MAX 3 COUNT 2 ALL 1,3\r\n/,
                 command(c, "r11", "SEARCH RETURN (MIN MAX COUNT ALL) 1,3"))
    assert_match(/\A\* ESEARCH \(TAG "r12"\) MIN 1 MAX 3 COUNT 2 ALL 1,3\r\n/,
                 command(c, "r12", "SEARCH RETURN (MIN MAX COUNT ALL) UID 5,7"))

    assert_match(/\Ar13 BAD/, command(c, "r13", "SEARCH RETURN (BOGUS) ALL"))
  end

  test "uid esearch reports uid marker and uid values" do
    c = seed_and_select
    assert_match(/\A\* ESEARCH \(TAG "u1"\) UID MIN 5 MAX 7 COUNT 3 ALL 5:7\r\n/,
                 command(c, "u1", "UID SEARCH RETURN (MIN MAX COUNT ALL) ALL"))
    # Sequence-set key inside a UID search selects seqs, reports uids.
    assert_match(/\A\* ESEARCH \(TAG "u2"\) UID MIN 5 MAX 7 COUNT 2 ALL 5,7\r\n/,
                 command(c, "u2", "UID SEARCH RETURN (MIN MAX COUNT ALL) 1,3"))
    assert_match(/\A\* ESEARCH \(TAG "u3"\) UID MIN 5 MAX 7 COUNT 2 ALL 5,7\r\n/,
                 command(c, "u3", "UID SEARCH RETURN (MIN MAX COUNT ALL) UID 5,7"))
  end

  test "unknown search key is bad" do
    c = seed_and_select
    assert_match(/\Ax1 BAD/, command(c, "x1", "SEARCH BOGUSKEY"))
  end
end

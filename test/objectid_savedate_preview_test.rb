require "test_helper"
require "wire_harness"

# OBJECTID (RFC 8474), SAVEDATE (RFC 8514), and PREVIEW (RFC 8970).
class ObjectidSavedatePreviewTest < Minitest::Test
  include WireHarness

  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nHello Joe, do you think we can meet at 3:30 tomorrow?\r\n"

  ALTERNATIVE = <<~MSG.gsub("\n", "\r\n")
    From: sender@remote.test
    Subject: alt
    MIME-Version: 1.0
    Content-Type: multipart/alternative; boundary=x

    --x
    Content-Type: text/plain; charset=utf-8
    Content-Transfer-Encoding: base64

    dGhpcyBpcyBwbGFpbiB0ZXh0Lg==

    --x
    Content-Type: text/html; charset=utf-8

    <p>this is html.</p>

    --x--
  MSG

  test "capabilities advertise objectid savedate preview" do
    c = connect(login: false)
    caps = command(c, "c1", "CAPABILITY")
    %w[OBJECTID SAVEDATE PREVIEW].each { |cap| assert_match(/\b#{cap}\b/, caps) }
  end

  # -- OBJECTID --------------------------------------------------------------

  test "mailboxid appears on select create and status, and survives rename" do
    c = connect
    select_id = command(c, "m1", "SELECT INBOX")[/\[MAILBOXID \(([^)]+)\)\]/, 1]
    assert_match(/\A[A-Za-z0-9_-]+\z/, select_id.to_s)
    assert_match(/MAILBOXID \(#{select_id}\)/, command(c, "m2", "STATUS INBOX (MAILBOXID)"))

    created_id = command(c, "m3", "CREATE Widgets")[/\[MAILBOXID \(([^)]+)\)\]/, 1]
    refute_nil created_id
    refute_equal select_id, created_id

    command(c, "m4", "RENAME Widgets Gadgets")
    assert_match(/MAILBOXID \(#{created_id}\)/, command(c, "m5", "STATUS Gadgets (MAILBOXID)"),
                 "MAILBOXID must survive rename")
  end

  test "emailid is stable across copy and searchable" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "e0", "SELECT INBOX")
    email_id = command(c, "e1", "FETCH 1 (EMAILID)")[/EMAILID \(([^)]+)\)/, 1]
    assert_match(/\A[A-Za-z0-9_-]+\z/, email_id.to_s)

    command(c, "e2", "COPY 1 Trash")
    command(c, "e3", "SELECT Trash")
    assert_match(/EMAILID \(#{email_id}\)/, command(c, "e4", "FETCH 1 (EMAILID)"),
                 "EMAILID must be identical for the COPY destination")

    assert_match(/\A\* SEARCH 1\r\n/, command(c, "e5", "SEARCH EMAILID #{email_id}"))
    assert_match(/\A\* SEARCH\r\n/, command(c, "e6", "SEARCH EMAILID Enosuchid"))
  end

  test "threadid is nil and never matches" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "t0", "SELECT INBOX")
    assert_match(/\* 1 FETCH \(THREADID NIL\)/, command(c, "t1", "FETCH 1 (THREADID)"))
    assert_match(/\A\* SEARCH\r\n/, command(c, "t2", "SEARCH THREADID T123"))
  end

  # -- SAVEDATE --------------------------------------------------------------

  test "savedate fetch item and search keys" do
    # INTERNALDATE far in the past; SAVEDATE is now.
    @store.append(@account_id, "INBOX", RAW, [], Time.utc(2020, 1, 1).to_i)
    c = connect
    command(c, "s0", "SELECT INBOX")

    fetch = command(c, "s1", "FETCH 1 (SAVEDATE)")
    assert_match(/SAVEDATE "\d{1,2}-\w{3}-#{Time.now.year} /, fetch)

    today = Time.now.strftime("%-d-%b-%Y")
    tomorrow = (Time.now + 86_400).strftime("%-d-%b-%Y")
    yesterday = (Time.now - 86_400).strftime("%-d-%b-%Y")
    assert_match(/\A\* SEARCH 1\r\n/, command(c, "s2", "SEARCH SAVEDON #{today}"))
    assert_match(/\A\* SEARCH 1\r\n/, command(c, "s3", "SEARCH SAVEDBEFORE #{tomorrow}"))
    assert_match(/\A\* SEARCH 1\r\n/, command(c, "s4", "SEARCH SAVEDSINCE #{yesterday}"))
    assert_match(/\A\* SEARCH\r\n/, command(c, "s5", "SEARCH SAVEDBEFORE #{yesterday}"))
    # ...while the client-supplied INTERNALDATE stays 2020 (ON vs SAVEDON).
    assert_match(/\A\* SEARCH\r\n/, command(c, "s6", "SEARCH ON #{today}"))
  end

  # -- PREVIEW ---------------------------------------------------------------

  test "preview returns the body text" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "p0", "SELECT INBOX")
    assert_match(/PREVIEW "Hello Joe, do you think we can meet at 3:30 tomorrow\?"/,
                 command(c, "p1", "FETCH 1 (PREVIEW)"))
    # LAZY modifier is accepted; unknown modifiers are BAD.
    assert_match(/PREVIEW "Hello Joe/, command(c, "p2", "FETCH 1 (PREVIEW (LAZY))"))
    assert_match(/\Ap3 BAD/, command(c, "p3", "FETCH 1 (PREVIEW (BOGUS))"))
  end

  test "preview decodes the first text part of multipart mail" do
    @store.append(@account_id, "INBOX", ALTERNATIVE, [], nil)
    c = connect
    command(c, "a0", "SELECT INBOX")
    assert_match(/PREVIEW "this is plain text\."/, command(c, "a1", "FETCH 1 (PREVIEW)"),
                 "base64 text/plain alternative must be decoded and preferred over html")
  end

  test "preview is capped at 200 characters" do
    long = "From: a@b.test\r\nSubject: long\r\n\r\n#{"word " * 100}\r\n"
    @store.append(@account_id, "INBOX", long, [], nil)
    c = connect
    command(c, "l0", "SELECT INBOX")
    preview = command(c, "l1", "FETCH 1 (PREVIEW)")[/PREVIEW "([^"]*)"/, 1]
    assert_operator preview.length, :<=, 200
    assert preview.start_with?("word word")
  end

  test "preview does not set seen" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "n0", "SELECT INBOX")
    command(c, "n1", "FETCH 1 (PREVIEW)")
    refute_match(/\\Seen/, command(c, "n2", "FETCH 1 (FLAGS)"))
  end
end

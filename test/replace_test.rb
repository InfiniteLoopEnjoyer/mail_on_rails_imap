require "test_helper"
require "wire_harness"

# REPLACE (RFC 8508): append-then-remove as one apparent action, used by
# clients to update drafts without a window where both (or neither)
# version exists.
class ReplaceTest < Minitest::Test
  include WireHarness

  OLD = "From: me@example.test\r\nSubject: draft v1\r\n\r\nfirst try\r\n"
  NEW = "From: me@example.test\r\nSubject: draft v2\r\n\r\nsecond try\r\n"

  test "capability advertises replace" do
    c = connect(login: false)
    assert_match(/\bREPLACE\b/, command(c, "c1", "CAPABILITY"))
  end

  test "replace swaps the message in the selected mailbox" do
    @store.append(@account_id, "INBOX", OLD, [], nil) # uid 1
    c = connect
    command(c, "r0", "SELECT INBOX")

    c.write("r1 REPLACE 1 INBOX (\\Seen) {#{NEW.bytesize}+}\r\n#{NEW}\r\n")
    reply = read_until_tagged(c, "r1")
    assert_match(/\* OK \[APPENDUID \d+ 2\] /, reply)
    assert_match(/\* 1 EXPUNGE|\* VANISHED 1/, reply)
    assert_match(/^r1 OK REPLACE completed/, reply)

    fetch = command(c, "r2", "FETCH 1:* (UID FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
    assert_match(/UID 2/, fetch)
    assert_match(/draft v2/, fetch)
    assert_match(/\\Seen/, fetch)
    refute_match(/UID 1[^\d]/, fetch, "the replaced message must be gone")
  end

  test "uid replace can target another mailbox" do
    @store.append(@account_id, "INBOX", OLD, [], nil) # uid 1
    c = connect
    command(c, "u0", "SELECT INBOX")

    c.write("u1 UID REPLACE 1 Drafts {#{NEW.bytesize}+}\r\n#{NEW}\r\n")
    reply = read_until_tagged(c, "u1")
    assert_match(/\* OK \[APPENDUID \d+ 1\] /, reply)
    assert_match(/\* 1 EXPUNGE/, reply, "original leaves the selected mailbox")
    assert_match(/^u1 OK/, reply)

    assert_match(/MESSAGES 0/, command(c, "u2", "STATUS INBOX (MESSAGES)"))
    assert_match(/MESSAGES 1/, command(c, "u3", "STATUS Drafts (MESSAGES)"))
  end

  test "replace error handling leaves the original intact" do
    @store.append(@account_id, "INBOX", OLD, [], nil) # uid 1
    c = connect
    command(c, "e0", "SELECT INBOX")

    # Append failure (missing destination): original must survive.
    c.write("e1 REPLACE 1 Nope {#{NEW.bytesize}+}\r\n#{NEW}\r\n")
    assert_match(/\Ae1 NO \[TRYCREATE\]/, read_until_tagged(c, "e1"))
    assert_match(/MESSAGES 1/, command(c, "e2", "STATUS INBOX (MESSAGES)"))

    assert_match(/\Ae3 BAD/, command(c, "e3", "REPLACE 1:2 INBOX {1+}\r\nx"))
    assert_match(/\Ae4 BAD/, command(c, "e4", "REPLACE 5 INBOX {1+}\r\nx"), "out-of-range seq")
    c.write("e5 UID REPLACE 99 INBOX {#{NEW.bytesize}+}\r\n#{NEW}\r\n")
    assert_match(/\Ae5 NO No such message/, read_until_tagged(c, "e5"))
  end

  test "replace is refused on a read-only mailbox" do
    @store.append(@account_id, "INBOX", OLD, [], nil)
    c = connect
    command(c, "x0", "EXAMINE INBOX")
    c.write("x1 REPLACE 1 INBOX {#{NEW.bytesize}+}\r\n#{NEW}\r\n")
    assert_match(/\Ax1 NO Mailbox is read-only/, read_until_tagged(c, "x1"))
  end

  test "qresync sessions see vanished for the replaced message" do
    @store.append(@account_id, "INBOX", OLD, [], nil)
    c = connect
    command(c, "q0", "ENABLE QRESYNC")
    command(c, "q1", "SELECT INBOX")
    c.write("q2 UID REPLACE 1 INBOX {#{NEW.bytesize}+}\r\n#{NEW}\r\n")
    reply = read_until_tagged(c, "q2")
    assert_match(/\* VANISHED 1\r\n/, reply)
    assert_match(/^q2 OK/, reply)
  end
end

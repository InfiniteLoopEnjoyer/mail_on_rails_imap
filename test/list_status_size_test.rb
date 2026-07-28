require "test_helper"
require "wire_harness"

# LIST-STATUS (RFC 5819) and STATUS=SIZE (RFC 8438): clients poll STATUS
# for every mailbox constantly; these let them batch that into one LIST
# and learn mailbox sizes without summing FETCH results.
class ListStatusSizeTest < Minitest::Test
  include WireHarness

  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  test "capabilities advertise list-status and status size" do
    c = connect(login: false)
    caps = command(c, "c1", "CAPABILITY")
    assert_match(/\bLIST-STATUS\b/, caps)
    assert_match(/\bSTATUS=SIZE\b/, caps)
  end

  test "status size sums message sizes" do
    2.times { @store.append(@account_id, "INBOX", RAW, [], nil) }
    c = connect
    reply = command(c, "s1", "STATUS INBOX (MESSAGES SIZE)")
    assert_match(/\* STATUS "INBOX" \(MESSAGES 2 SIZE #{2 * RAW.bytesize}\)/, reply)
    assert_match(/SIZE 0/, command(c, "s2", "STATUS Drafts (SIZE)"))
  end

  test "list return status interleaves status responses" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    @store.append(@account_id, "Sent", RAW, [ "\\Seen" ], nil)
    c = connect

    reply = command(c, "l1", %(LIST "" % RETURN (STATUS (MESSAGES UNSEEN))))
    # Every LIST line is followed by that mailbox's STATUS line (RFC 5819 §2).
    assert_match(/\* LIST \([^)]*\) "\/" "INBOX"\r\n\* STATUS "INBOX" \(MESSAGES 1 UNSEEN 1\)\r\n/, reply)
    assert_match(/\* LIST \([^)]*\\Sent\) "\/" "Sent"\r\n\* STATUS "Sent" \(MESSAGES 1 UNSEEN 0\)\r\n/, reply)
    assert_match(/\* STATUS "Trash" \(MESSAGES 0 UNSEEN 0\)\r\n/, reply)
    assert_match(/^l1 OK/, reply)
  end

  test "list return status supports size and highestmodseq" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    reply = command(c, "l1", %(LIST "" INBOX RETURN (STATUS (SIZE HIGHESTMODSEQ))))
    assert_match(/\* STATUS "INBOX" \(SIZE #{RAW.bytesize} HIGHESTMODSEQ \d+\)/, reply)

    # HIGHESTMODSEQ via LIST-STATUS is CONDSTORE-enabling like plain
    # STATUS (HIGHESTMODSEQ): MODSEQ rides along in later fetches.
    command(c, "l2", "SELECT INBOX")
    assert_match(/MODSEQ \(\d+\)/, command(c, "l3", "FETCH 1 (FLAGS)"))
  end

  test "list return validation" do
    c = connect
    assert_match(/\Ab1 BAD/, command(c, "b1", %(LIST "" % RETURN (BOGUS))))
    assert_match(/\Ab2 BAD/, command(c, "b2", %(LIST "" % RETURN (STATUS (UNKNOWN)))))
    assert_match(/\Ab3 BAD/, command(c, "b3", %(LIST "" % RETURN (STATUS ()))))
    assert_match(/\Ab4 BAD/, command(c, "b4", %(LIST "" % RETURN STATUS)))
    assert_match(/\Ab5 BAD/, command(c, "b5", %(LSUB "" % RETURN (STATUS (MESSAGES)))))

    # Empty RETURN list is valid (RFC 5258) - a plain LIST.
    reply = command(c, "b6", %(LIST "" INBOX RETURN ()))
    assert_match(/\* LIST [^\r]+"INBOX"\r\n/, reply)
    refute_match(/STATUS/, reply)
    assert_match(/^b6 OK/, reply)
  end

  test "hierarchy delimiter query takes no status" do
    c = connect
    reply = command(c, "d1", %(LIST "" ""))
    assert_match(/\* LIST \(\\Noselect\) "\/" ""/, reply)
    refute_match(/STATUS/, reply)
  end
end

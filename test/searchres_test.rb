require "test_helper"
require "wire_harness"

# SEARCHRES (RFC 5182), ported from mox's search_test.go SAVE block: a
# SEARCH RETURN (SAVE) stores its matches as "$", usable as the sequence
# set (or a search key) of later commands without round-tripping the
# UID list through the client.
class SearchresTest < Minitest::Test
  include WireHarness

  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # Seqs 1,2,3 = UIDs 5,6,7 so seq/uid mixups fail loudly.
  def seed_and_select
    4.times { @store.append(@account_id, "INBOX", "X: y\r\n\r\nplaceholder\r\n", [ "\\Deleted" ], nil) }
    @store.expunge(inbox_id)
    3.times { @store.append(@account_id, "INBOX", RAW, [], nil) } # uids 5,6,7
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  test "capability advertises searchres" do
    c = connect(login: false)
    assert_match(/\bSEARCHRES\b/, command(c, "c1", "CAPABILITY"))
  end

  test "save alone answers no esearch response and sets the marker" do
    c = seed_and_select
    reply = command(c, "v1", "SEARCH RETURN (SAVE) 2")
    refute_match(/ESEARCH/, reply, "SAVE-only search sends no untagged response")
    assert_match(/\Av1 OK/, reply)

    assert_match(/\* 2 FETCH \(UID 6\)/, command(c, "v2", "FETCH $ (UID)"))
    assert_match(/\* 2 FETCH \(FLAGS \([^)]*\) UID 6\)/, command(c, "v3", "UID FETCH $ (FLAGS)"))
  end

  test "dollar works as a search key and can resave itself" do
    c = seed_and_select
    command(c, "k1", "SEARCH RETURN (SAVE) 2")
    assert_match(/\A\* ESEARCH \(TAG "k2"\) ALL 2\r\n/, command(c, "k2", "SEARCH RETURN (ALL) $"))
    reply = command(c, "k3", "SEARCH RETURN (SAVE) $")
    refute_match(/ESEARCH/, reply)
    assert_match(/\A\* ESEARCH \(TAG "k4"\) ALL 2\r\n/, command(c, "k4", "SEARCH RETURN (ALL) $"))
  end

  test "save combined with other options returns them and saves the full result" do
    c = seed_and_select
    assert_match(/\A\* ESEARCH \(TAG "m1"\) ALL 1:3\r\n/, command(c, "m1", "SEARCH RETURN (SAVE ALL) ALL"))
    assert_match(/\A\* ESEARCH \(TAG "m2"\) ALL 1:3\r\n/, command(c, "m2", "SEARCH RETURN (ALL SAVE) ALL"))
    assert_match(/\A\* ESEARCH \(TAG "m3"\) ALL 1:3\r\n/, command(c, "m3", "SEARCH RETURN (ALL) $"))
  end

  test "save with only min or max narrows the marker to those messages" do
    c = seed_and_select
    reply = command(c, "n1", "SEARCH RETURN (MIN SAVE) ALL")
    assert_match(/\A\* ESEARCH \(TAG "n1"\) MIN 1\r\n/, reply)
    assert_match(/\A\* ESEARCH \(TAG "n2"\) ALL 1\r\n/, command(c, "n2", "SEARCH RETURN (ALL) $"))

    command(c, "n3", "SEARCH RETURN (SAVE MAX) ALL")
    assert_match(/\A\* ESEARCH \(TAG "n4"\) ALL 3\r\n/, command(c, "n4", "SEARCH RETURN (ALL) $"))

    command(c, "n5", "SEARCH RETURN (SAVE MIN MAX) ALL")
    assert_match(/\A\* ESEARCH \(TAG "n6"\) ALL 1,3\r\n/, command(c, "n6", "SEARCH RETURN (ALL) $"))

    # MIN/MAX plus COUNT saves the full result again (RFC 5182 §2.4).
    command(c, "n7", "SEARCH RETURN (SAVE MIN COUNT) ALL")
    assert_match(/\A\* ESEARCH \(TAG "n8"\) ALL 1:3\r\n/, command(c, "n8", "SEARCH RETURN (ALL) $"))
  end

  test "uid search save works and dollar spans commands" do
    c = seed_and_select
    command(c, "u1", "UID SEARCH RETURN (SAVE) UID 5,7")
    assert_match(/\A\* ESEARCH \(TAG "u2"\) UID ALL 5,7\r\n/, command(c, "u2", "UID SEARCH RETURN (ALL) $"))

    # $ in STORE and COPY.
    command(c, "u3", "UID STORE $ +FLAGS.SILENT (\\Flagged)")
    assert_match(/\A\* SEARCH 1 3\r\n/, command(c, "u4", "SEARCH FLAGGED"))
    assert_match(/\[COPYUID \d+ 5,7 \d+,\d+\]/, command(c, "u5", "UID COPY $ Trash"))
  end

  test "expunged messages drop out of the marker" do
    c = seed_and_select
    command(c, "e1", "SEARCH RETURN (SAVE) ALL")
    command(c, "e2", "UID STORE 6 +FLAGS.SILENT (\\Deleted)")
    command(c, "e3", "EXPUNGE")
    fetch = command(c, "e4", "UID FETCH $ (UID)")
    assert_match(/UID 5/, fetch)
    assert_match(/UID 7/, fetch)
    refute_match(/UID 6/, fetch, "expunged message must leave the saved result")
  end

  test "select resets the marker and empty marker matches nothing" do
    c = seed_and_select
    command(c, "r1", "SEARCH RETURN (SAVE) ALL")
    command(c, "r2", "SELECT INBOX")
    reply = command(c, "r3", "FETCH $ (UID)")
    refute_match(/\* \d+ FETCH/, reply, "SELECT resets the saved result to empty")
    assert_match(/\Ar3 OK/, reply)

    # An empty saved result also matches nothing as a search key.
    assert_match(/\A\* SEARCH\r\n/, command(c, "r4", "SEARCH $"))
  end
end

require "test_helper"
require "wire_harness"

# RFC 3501/9051 compliance audit for the remaining commands, ported from
# mox's imapserver selectexamine/create/delete/rename/copy/append/status/
# expunge/store test files. mox behavior that is IMAP4rev2-only (untagged
# LIST broadcasts, OldName), subscription-store-dependent (LSUB
# semantics), or mox policy (quota, name export rules) is not ported.
class CommandAuditTest < Minitest::Test
  include WireHarness

  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # -- SELECT / EXAMINE ------------------------------------------------------

  test "select and examine argument and error handling" do
    c = connect
    assert_match(/\As1 BAD/, command(c, "s1", "SELECT"))
    assert_match(/\As2 BAD/, command(c, "s2", "EXAMINE"))
    assert_match(/\As3 NO/, command(c, "s3", "SELECT bogus"))

    # Quoted mailbox names work, and INBOX is case-insensitive.
    assert_match(/\[READ-WRITE\]/, command(c, "s4", %(SELECT "inbox"))[/^s4 .*/])
    assert_match(/\[READ-ONLY\]/, command(c, "s5", "EXAMINE iNbOx")[/^s5 .*/])
  end

  test "select announces required untagged responses" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    select = command(c, "s1", "SELECT INBOX")
    assert_match(/^\* FLAGS \(/, select)
    assert_match(/^\* 1 EXISTS/, select)
    assert_match(/^\* 0 RECENT/, select)
    assert_match(/\[PERMANENTFLAGS \([^)]*\\\*\)\]/, select)
    assert_match(/\[UIDVALIDITY \d+\]/, select)
    assert_match(/\[UIDNEXT 2\]/, select)
    assert_match(/\[UNSEEN 1\]/, select, "unseen message present: UNSEEN code required")
  end

  # -- CREATE ----------------------------------------------------------------

  test "create existing and inbox are refused with alreadyexists" do
    c = connect
    assert_match(/\Ac1 NO \[ALREADYEXISTS\]/, command(c, "c1", "CREATE INBOX"))
    assert_match(/\Ac2 NO \[ALREADYEXISTS\]/, command(c, "c2", "CREATE Inbox"))
    command(c, "c3", "CREATE Projects")
    assert_match(/\Ac4 NO \[ALREADYEXISTS\]/, command(c, "c4", "CREATE Projects"))
  end

  test "create strips a trailing hierarchy separator" do
    c = connect
    assert_match(/\Ac1 OK/, command(c, "c1", "CREATE mailbox/"))
    list = command(c, "c2", %(LIST "" mailbox*))
    assert_includes list, %("mailbox")
    refute_includes list, %("mailbox/")
  end

  test "create makes missing superior names" do
    c = connect
    assert_match(/\Ac1 OK/, command(c, "c1", "CREATE INBOX/a/c"))
    list = command(c, "c2", %(LIST "" INBOX/*))
    assert_match(/"INBOX\/a"/, list, "intermediate parent must be created")
    assert_match(/"INBOX\/a\/c"/, list)
  end

  test "create validates names" do
    c = connect
    assert_match(/\Av1 NO/, command(c, "v1", "CREATE /bad/root"))
    assert_match(/\Av2 NO/, command(c, "v2", "CREATE bad//root"))
    assert_match(/\Av3 BAD/, command(c, "v3", "CREATE"))
    bad = "badname"
    assert_match(/\Av4 BAD/, command(c, "v4", %(CREATE "#{bad}")))
  end

  # -- DELETE / RENAME -------------------------------------------------------

  test "delete error cases carry response codes" do
    c = connect
    assert_match(/\Ad1 BAD/, command(c, "d1", "DELETE"))
    assert_match(/\Ad2 NO Cannot delete INBOX/, command(c, "d2", "DELETE INBOX"))
    assert_match(/\Ad3 NO \[NONEXISTENT\]/, command(c, "d3", "DELETE nonexistent"))
  end

  test "rename error cases carry response codes" do
    c = connect
    assert_match(/\Ar1 BAD/, command(c, "r1", "RENAME"))
    assert_match(/\Ar2 BAD/, command(c, "r2", "RENAME onlyone"))
    assert_match(/\Ar3 NO \[NONEXISTENT\]/, command(c, "r3", "RENAME doesnotexist newbox"))
    assert_match(/\Ar4 NO \[ALREADYEXISTS\]/, command(c, "r4", "RENAME Sent Trash"))
  end

  test "rename creates missing parents of the destination" do
    c = connect
    command(c, "p1", "CREATE a/b")
    assert_match(/\Ap2 OK/, command(c, "p2", "RENAME a/b x/y"))
    list = command(c, "p3", %(LIST "" x*))
    assert_match(/"x"/, list, "new parent x must exist")
    assert_match(/"x\/y"/, list)
  end

  test "rename of a parent renames the subtree" do
    c = connect
    command(c, "t1", "CREATE Projects/2026")
    assert_match(/\At2 OK/, command(c, "t2", "RENAME Projects Work"))
    list = command(c, "t3", %(LIST "" *))
    assert_includes list, "Work/2026"
    refute_includes list, "Projects"
  end

  test "rename inbox moves messages but keeps inbox and children" do
    @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil) # uid 1
    @store.append(@account_id, "INBOX", RAW, [ "label1" ], nil)    # uid 2
    c = connect
    command(c, "i0", "CREATE INBOX/a")
    command(c, "i1", "SELECT INBOX")
    command(c, "i2", "EXPUNGE") # uid 1 gone; uid 2 remains

    assert_match(/\Ai3 OK/, command(c, "i3", "RENAME INBOX Archive/oldmail"))

    # INBOX and its child still exist; destination was created.
    list = command(c, "i4", %(LIST "" *))
    assert_match(/"INBOX"/, list)
    assert_match(/"INBOX\/a"/, list)
    assert_match(/"Archive\/oldmail"/, list)

    # INBOX is now empty; the message lives in the new mailbox with a
    # renumbered UID.
    assert_match(/MESSAGES 0/, command(c, "i5", "STATUS INBOX (MESSAGES)"))
    command(c, "i6", "SELECT Archive/oldmail")
    fetch = command(c, "i7", "UID FETCH 1:* (FLAGS)")
    assert_match(/\* 1 FETCH \(FLAGS \(label1\) UID 1\)/, fetch)

    # Renaming INBOX onto an existing name is refused.
    assert_match(/\Ai8 NO \[ALREADYEXISTS\]/, command(c, "i8", "RENAME INBOX Trash"))
  end

  # -- COPY ------------------------------------------------------------------

  test "copy argument and error handling" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "c0", "SELECT INBOX")
    assert_match(/\Ac1 BAD/, command(c, "c1", "COPY"))
    assert_match(/\Ac2 BAD/, command(c, "c2", "COPY 1"))
    assert_match(/\Ac3 NO \[TRYCREATE\]/, command(c, "c3", "COPY 1 nonexistent"))
    assert_match(/\Ac4 BAD/, command(c, "c4", "COPY 2 Trash"), "out-of-range seq")
    assert_match(/\[COPYUID \d+ 1 1\]/, command(c, "c5", "COPY 1 Trash"))
  end

  # -- APPEND ----------------------------------------------------------------

  test "append syntax and flag validation" do
    c = connect
    assert_match(/\Aa1 BAD/, command(c, "a1", "APPEND"))
    assert_match(/\Aa2 BAD/, command(c, "a2", "APPEND INBOX"))

    # Unknown system flags cannot be invented by clients.
    reply = append(c, "a3", "INBOX", "x", flags: [ "\\Badflag" ])
    assert_match(/\Aa3 BAD/, reply)

    # Unparseable date-time is BAD, not silently ignored.
    reply = append(c, "a4", "INBOX", "x", date: "bad time")
    assert_match(/\Aa4 BAD/, reply)

    # Leftover arguments (e.g. unadvertised MULTIAPPEND) are BAD.
    c.write("a5 APPEND INBOX {1+}\r\nx {1+}\r\ny\r\n")
    assert_match(/\Aa5 BAD/, read_until_tagged(c, "a5"))

    assert_match(/MESSAGES 0/, command(c, "a6", "STATUS INBOX (MESSAGES)"),
                 "no rejected append may deliver anything")
  end

  test "append to a missing mailbox answers trycreate" do
    c = connect
    assert_match(/\At1 NO \[TRYCREATE\]/, append(c, "t1", "nobox", "x", flags: [ "\\Seen" ]))
  end

  test "append reports appenduid and exists to selected sessions" do
    c = connect
    command(c, "p0", "SELECT INBOX")
    observer = connect
    command(observer, "o0", "SELECT INBOX")
    unselected = connect

    reply = append(c, "p1", "INBOX", RAW, flags: [ "\\Seen", "Label1", "$label2" ], date: "1-Jan-2022 10:10:00 +0100")
    assert_match(/\A\* 1 EXISTS\r\n/, reply)
    assert_match(/OK \[APPENDUID \d+ 1\]/, reply)

    assert_match(/\* 1 EXISTS/, command(observer, "o1", "NOOP"))
    refute_match(/EXISTS/, command(unselected, "u1", "NOOP"), "no mailbox selected: nothing to report")

    flags = command(c, "p2", "FETCH 1 (FLAGS)")
    assert_match(/\\Seen/, flags)
    assert_match(/Label1/, flags)
    assert_match(/\$label2/, flags)
  end

  # -- STATUS ----------------------------------------------------------------

  test "status attribute list is mandatory and validated" do
    c = connect
    assert_match(/\At1 BAD/, command(c, "t1", "STATUS"))
    assert_match(/\At2 BAD/, command(c, "t2", "STATUS INBOX"))
    assert_match(/\At3 BAD/, command(c, "t3", "STATUS INBOX ()"))
    assert_match(/\At4 BAD/, command(c, "t4", "STATUS INBOX (UNKNOWN)"))
    assert_match(/\At5 NO \[NONEXISTENT\]/, command(c, "t5", "STATUS nonexistent (MESSAGES)"))
  end

  test "status reports requested attributes in order" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    reply = command(c, "t1", "STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN RECENT)")
    assert_match(/\* STATUS "INBOX" \(MESSAGES 1 UIDNEXT 2 UIDVALIDITY \d+ UNSEEN 1 RECENT 0\)/, reply)
  end

  # -- EXPUNGE ---------------------------------------------------------------

  test "expunge argument strictness" do
    c = connect
    command(c, "e0", "SELECT INBOX")
    assert_match(/\Ae1 BAD/, command(c, "e1", "EXPUNGE leftover"))
    assert_match(/\Ae2 BAD/, command(c, "e2", "UID EXPUNGE"))
    assert_match(/\Ae3 BAD/, command(c, "e3", "UID EXPUNGE 1 leftover"))
    reply = command(c, "e4", "EXPUNGE")
    refute_match(/\* \d+ EXPUNGE/, reply)
    assert_match(/^e4 OK/, reply)
  end

  test "expunge in examine mode is refused" do
    @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil)
    c = connect
    command(c, "x0", "EXAMINE INBOX")
    assert_match(/\Ax1 NO/, command(c, "x1", "EXPUNGE"))
    assert_match(/\Ax2 NO/, command(c, "x2", "UID EXPUNGE 1"))
  end

  test "uid expunge only removes deleted messages in the set" do
    # UIDs 1,2,3; mark 1,3 \Deleted; UID EXPUNGE 1:2 removes only uid 1.
    3.times { @store.append(@account_id, "INBOX", RAW, [], nil) }
    c = connect
    command(c, "u0", "SELECT INBOX")
    command(c, "u1", "UID STORE 1,3 +FLAGS.SILENT (\\Deleted)")
    reply = command(c, "u2", "UID EXPUNGE 1:2")
    assert_match(/\A\* 1 EXPUNGE\r\nu2 OK/, reply)
    fetch = command(c, "u3", "UID FETCH 1:* (FLAGS)")
    assert_match(/UID 2/, fetch)
    assert_match(/UID 3/, fetch, "uid 3 stays: outside the UID EXPUNGE set")
  end

  # -- STORE -----------------------------------------------------------------

  test "store flag list forms and dedup" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "f0", "SELECT INBOX")

    # Replace with duplicates: stored once.
    reply = command(c, "f1", "STORE 1 FLAGS (new new a b c)")
    assert_equal 1, reply.scan(/\bnew\b/).size, "duplicate flags collapse: #{reply.inspect}"

    # Bare flag atoms without parentheses are valid.
    assert_match(/^f2 OK/, command(c, "f2", "STORE 1 -FLAGS a b"))
    fetch = command(c, "f3", "FETCH 1 (FLAGS)")
    assert_match(/FLAGS \([^)]*c[^)]*\)/, fetch)
    refute_match(/\ba\b|\bb\b/, fetch[/FLAGS \([^)]*\)/])

    # Case-insensitive duplicate additions are no-ops.
    command(c, "f4", "STORE 1 FLAGS (custom1)")
    before = fetch_modseq(c, "f5", 1)
    command(c, "f6", "STORE 1 +FLAGS (Custom1)")
    assert_equal before, fetch_modseq(c, "f7", 1), "case-variant flag add must not change anything"
  end

  test "store syntax errors" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")
    assert_match(/\As1 BAD/, command(c, "s1", "STORE"))
    assert_match(/\As2 BAD/, command(c, "s2", "STORE 1"))
    assert_match(/\As3 BAD/, command(c, "s3", "STORE 1 +"))
    assert_match(/\As4 BAD/, command(c, "s4", "STORE 1 FLAGS"), "flag argument required")
    assert_match(/\As5 BAD/, command(c, "s5", "STORE 1 FLAGS (\\Nosuchflag)"), "unknown system flag")
    assert_match(/\As6 BAD/, command(c, "s6", "STORE 2 FLAGS ()"), "out-of-range seq")
    assert_match(/^s7 OK/, command(c, "s7", "STORE 1 FLAGS ()"), "empty parenthesized list is valid")
  end

  test "store in examine mode is refused" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "x0", "EXAMINE INBOX")
    assert_match(/\Ax1 NO/, command(c, "x1", "STORE 1 FLAGS (\\Seen)"))
  end
end

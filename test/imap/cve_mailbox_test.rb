require "test_helper"
require "wire_harness"

# Regression tests for three historical IMAP CVE classes, checked against
# this server's account-scoped, name-keyed store (no filesystem paths):
#
#   1. Mailbox-name traversal (CVE-2018-14355, CVE-2006-2414, ...): "..",
#      absolute paths and backslashes must be opaque names that never
#      resolve outside the authenticated account's namespace.
#   2. Modified UTF-7 handling (CVE-2007-3925 class): malformed
#      &-sequences must not crash the session, control characters must be
#      refused, and alternate encodings of one name must converge on one
#      mailbox instead of aliasing into several.
#   3. Cross-account authorization (Dovecot/Cyrus ACL-bypass class):
#      commands not covered by cross_account_isolation_test - LSUB,
#      GETQUOTAROOT, LIST RETURN (STATUS), UID ranges, rename collisions,
#      UTF-7 spellings of foreign names - must stay scoped to the caller.
#
# The second account exists so any escape shows up as a success (or a
# store-level side effect on @bob) where a NO is required.
class CveMailboxTest < Minitest::Test
  include WireHarness

  BOB = "bob@example.test"
  BOB_PRIVATE = "Bob-Private"
  BOB_UNICODE = "Sécret"                # "Sécret"; wire form S&AOk-cret
  BOB_RAW = "From: s@remote.test\r\nSubject: bob-only\r\n\r\nhis\r\n"
  ALICE_RAW = "From: s@remote.test\r\nSubject: alice-only\r\n\r\nhers\r\n"

  def setup
    super
    @bob = @store.add_account(email: BOB, password: PASSWORD)
    @store.create_mailbox(@bob, BOB_PRIVATE)
    @store.create_mailbox(@bob, BOB_UNICODE)
    @store.append(@bob, BOB_PRIVATE, BOB_RAW, [], nil)
    @store.append(@account_id, "INBOX", ALICE_RAW, [], nil)
  end

  def bob_count(name)
    @store.status(@bob, name)[:messages]
  end

  # -- 1. mailbox-name traversal ---------------------------------------------

  test "dotdot names never resolve outside the account's namespace" do
    c = connect
    # The store is keyed by (account, name); "../x" is an opaque string,
    # so every traversal spelling must fail closed as "no such mailbox".
    [ "../#{BOB_PRIVATE}", "../../#{BOB_PRIVATE}", "../INBOX", "..",
      "INBOX/../../#{BOB_PRIVATE}" ].each_with_index do |name, i|
      assert_match(/\At#{i} NO/, command(c, "t#{i}", "SELECT #{name}"), "SELECT #{name} must fail")
      assert_match(/\As#{i} NO/, command(c, "s#{i}", "STATUS #{name} (MESSAGES)"), "STATUS #{name} must fail")
    end
  end

  test "creating a dotdot name stays inside the caller's account" do
    c = connect
    # No filesystem behind the store: "../Escape" is legal as a literal
    # name and must land in Alice's namespace only.
    assert_match(/\Aa1 OK/, command(c, "a1", "CREATE ../Escape"))
    assert_includes @store.list_mailboxes(@account_id)[:mailboxes], "../Escape"
    bob_names = @store.list_mailboxes(@bob)[:mailboxes]
    refute_includes bob_names, "../Escape"
    refute_includes bob_names, "Escape"
  end

  test "absolute and degenerate hierarchy names are rejected" do
    c = connect
    assert_match(/\Aa1 NO/, command(c, "a1", "CREATE /etc/passwd"))
    assert_match(/\Aa2 NO/, command(c, "a2", "CREATE a//b"))
    assert_match(/\Aa3 NO/, command(c, "a3", "SELECT /etc/passwd"))
  end

  test "backslash names are literal and do not alias other mailboxes" do
    c = connect
    assert_match(/\Aa1 NO/, command(c, "a1", %(SELECT ..\\..\\INBOX)))
    assert_match(/\Aa2 NO/, command(c, "a2", %(SELECT ..\\#{BOB_PRIVATE})))
    # ...and the session survives to keep working.
    assert_match(/^a3 OK/, command(c, "a3", "SELECT INBOX"))
  end

  test "append and copy to traversal names fail closed and leave data intact" do
    c = connect
    reply = append(c, "a1", "../#{BOB_PRIVATE}", ALICE_RAW)
    assert_match(/\Aa1 NO/, reply)
    assert_equal 1, bob_count(BOB_PRIVATE)

    command(c, "s1", "SELECT INBOX")
    assert_match(/\Ac1 NO \[TRYCREATE\]/, command(c, "c1", "COPY 1 ../INBOX"))
    assert_match(/\Am1 NO \[TRYCREATE\]/, command(c, "m1", "MOVE 1 ../#{BOB_PRIVATE}"))
    # The refused MOVE must not have expunged the source.
    assert_equal 1, @store.status(@account_id, "INBOX")[:messages]
    assert_equal 1, bob_count(BOB_PRIVATE)
  end

  test "rename cannot traverse: sources resolve only in the caller's account" do
    c = connect
    assert_match(/\Aa1 NO \[NONEXISTENT\]/, command(c, "a1", "RENAME ../#{BOB_PRIVATE} Stolen"))
    refute_includes @store.list_mailboxes(@bob)[:mailboxes], "Stolen"
    refute_includes @store.list_mailboxes(@account_id)[:mailboxes], "Stolen"

    # A dotdot rename *target* is a literal name in the caller's own account.
    command(c, "a2", "CREATE Docs")
    assert_match(/\Aa3 OK/, command(c, "a3", "RENAME Docs ../Sneak"))
    assert_includes @store.list_mailboxes(@account_id)[:mailboxes], "../Sneak"
    refute_includes @store.list_mailboxes(@bob)[:mailboxes], "../Sneak"
    assert_equal 1, bob_count(BOB_PRIVATE)
  end

  test "list patterns are matched with imap wildcard semantics only" do
    c = connect
    command(c, "a0", "CREATE Work/2025")
    # "_" is not a wildcard in IMAP (unlike SQL LIKE): a store that leaked
    # the pattern into an unescaped LIKE would match INBOX here.
    refute_match(/INBOX/, command(c, "a1", %(LIST "" "INBO_")))
    # "%" must not cross the hierarchy delimiter.
    listing = command(c, "a2", %(LIST "" "%"))
    assert_match(/"Work"/, listing)
    refute_match(%r{Work/2025}, listing)
    # "*" does cross it.
    assert_match(%r{Work/2025}, command(c, "a3", %(LIST "" "Work/*")))
  end

  test "regex metacharacters in list patterns are inert" do
    c = connect
    # The pattern compiles to a regex; unescaped, ".*" or alternation
    # would match every mailbox.
    refute_match(/INBOX/, command(c, "a1", %(LIST "" ".*")))
    refute_match(/INBOX|Sent/, command(c, "a2", %(LIST "" "(INBOX|Sent)")).lines.grep(/^\* LIST/).join)
    refute_match(/INBOX/, command(c, "a3", %(LIST "" "INBOX$|^")))
    assert_match(/\Aa4 OK/, command(c, "a4", "NOOP"))
  end

  test "traversal list patterns reveal nothing" do
    c = connect
    listing = command(c, "a1", %(LIST "" "../*"))
    refute_match(/#{BOB_PRIVATE}/, listing)
    refute_match(/^\* LIST .*"/, listing.lines.grep_v(/\Aa1 /).join) if listing.lines.size > 1
    assert_match(/\Aa1 OK/, listing)
  end

  test "an oversized mailbox name is refused without crashing the session" do
    c = connect
    # CVE-2017-1274/CVE-2005-3690 class: a very long name must be handled
    # as data, and the session must remain usable afterwards.
    long = "X" * 8_000
    assert_match(/\Aa1 NO/, command(c, "a1", "SELECT #{long}"))
    assert_match(/\Aa2 NO/, command(c, "a2", "STATUS #{long} (MESSAGES)"))
    assert_match(/\Aa3 OK/, command(c, "a3", "NOOP"))
  end

  # -- 2. modified UTF-7 handling --------------------------------------------

  test "utf7 names decoding to control characters are refused" do
    c = connect
    # "&AAA-x" decodes to "\x00x": every by-name command runs the same
    # control-character gate CREATE does, so SELECT is BAD too.
    assert_match(/\Aa1 BAD/, command(c, "a1", "CREATE &AAA-x"))
    assert_match(/\Aa2 BAD/, command(c, "a2", "SELECT &AAA-x"))
    refute(@store.list_mailboxes(@account_id)[:mailboxes].any? { |n| n.include?("\x00") })
  end

  # A control-byte name can be planted through the store/admin API without
  # ever passing CREATE's validation - no by-name command may address it,
  # and control bytes smuggled raw inside a literal (CR/LF are ASCII, so
  # a 7-bit check alone misses them) must be refused everywhere.
  test "a store-planted control-byte mailbox is not addressable by any command" do
    planted = "Bad\rBox"
    @store.create_mailbox(@account_id, planted)
    c = connect

    {
      "s" => "SELECT",
      "t" => "STATUS",
      "d" => "DELETE",
      "a" => "APPEND"
    }.each do |tag_prefix, cmd|
      trailer = { "STATUS" => " (MESSAGES)", "APPEND" => " {3+}\r\nhi\r" }.fetch(cmd, "")
      c.write("#{tag_prefix}1 #{cmd} {#{planted.bytesize}+}\r\n#{planted}#{trailer}\r\n")
      assert_match(/\A#{tag_prefix}1 (NO|BAD)/, read_until_tagged(c, "#{tag_prefix}1"),
                   "#{cmd} must refuse a control-byte mailbox name")
    end

    command(c, "s2", "SELECT INBOX")
    assert_match(/\Ac2 (NO|BAD)/, command(c, "c2", "COPY 1 Bad&AA0-Box"),
                 "COPY must refuse a control-byte destination")
    assert_match(/\Am2 (NO|BAD)/, command(c, "m2", "MOVE 1 Bad&AA0-Box"),
                 "MOVE must refuse a control-byte destination")
    assert_match(/\Az9 OK/, command(c, "z9", "NOOP"), "the session must survive the refusals")
  end

  test "malformed utf7 sequences are handled without crash" do
    c = connect
    [ "&AEEA-",     # valid alphabet, odd UTF-16 byte count: decode fails
      "&AOk",       # unterminated shift sequence
      "&*bad-",     # characters outside the modified-base64 alphabet
      "&-",         # bare escaped ampersand
      "&&&&-" ].each_with_index do |name, i|
      assert_match(/\At#{i} NO/, command(c, "t#{i}", "SELECT #{name}"), "SELECT #{name.inspect}")
    end
    # CVE-2005-2933 shape: an unclosed quote must not desync the parser.
    assert_match(/\Aq1 NO/, command(c, "q1", %(SELECT "Unclosed)))
    assert_match(/\Az1 OK/, command(c, "z1", "NOOP"))
  end

  test "alternate utf7 encodings of one name converge on one mailbox" do
    c = connect
    # "&AEE-" is the (RFC-forbidden) UTF-7 encoding of plain "A". Both
    # spellings must address the same mailbox - two mailboxes behind one
    # name would make flags/expunges land unpredictably.
    assert_match(/\Aa1 OK/, command(c, "a1", "CREATE A"))
    assert_match(/\Aa2 NO \[ALREADYEXISTS\]/, command(c, "a2", "CREATE &AEE-"))
    assert_match(/\* STATUS "A"/, command(c, "a3", "STATUS &AEE- (MESSAGES)"))
    assert_equal 1, @store.list_mailboxes(@account_id)[:mailboxes].count { |n| n == "A" }
  end

  test "utf7 and canonical spellings round trip through create and list" do
    c = connect
    assert_match(/\Aa1 OK/, command(c, "a1", "CREATE Caf&AOk-"))
    assert_includes @store.list_mailboxes(@account_id)[:mailboxes], "Café"
    assert_match(/"Caf&AOk-"/, command(c, "a2", %(LIST "" "*")))
    assert_match(/\* STATUS "Caf&AOk-"/, command(c, "a3", "STATUS Caf&AOk- (MESSAGES)"))
  end

  test "raw utf8 bytes cannot write into a differently-encoded mailbox" do
    c = connect
    assert_match(/\Aa1 OK/, command(c, "a1", "CREATE T&AOk-l"))
    # Raw UTF-8 where modified UTF-7 is required (no ENABLE UTF8=ACCEPT
    # here) fails closed at the shared 7-bit gate, same as CREATE.
    c.write("a2 APPEND \"Tél\" {#{ALICE_RAW.bytesize}+}\r\n#{ALICE_RAW}\r\n")
    reply = read_until_tagged(c, "a2")
    assert_match(/\Aa2 BAD/, reply)
    assert_equal 1, bob_count(BOB_PRIVATE), "raw-UTF-8 name must never cross accounts"
    assert_match(/\Aa3 OK/, command(c, "a3", "NOOP"))
  end

  test "a raw utf8 mailbox name must not break list for the account" do
    # Regression for a real finding: CREATE with raw UTF-8 (non-UTF-7)
    # bytes used to store a binary-encoded name, after which every LIST
    # raised Encoding::CompatibilityError ("BAD Internal error", forever).
    # Raw 8-bit names are now refused outright (no UTF8=ACCEPT here), on
    # RENAME's destination as well - it stores a name just like CREATE.
    c = connect
    c.write("a1 CREATE \"Tél-raw\"\r\n")
    assert_match(/\Aa1 BAD/, read_until_tagged(c, "a1"),
                 "raw 8-bit CREATE must be refused")
    assert_match(/^a2 OK/, command(c, "a2", %(LIST "" "*")),
                 "LIST must keep working after a raw-UTF-8 CREATE attempt")
    assert_match(/\Aa3 OK/, command(c, "a3", "CREATE renameme"))
    c.write("a4 RENAME renameme \"Tél-raw\"\r\n")
    assert_match(/\Aa4 BAD/, read_until_tagged(c, "a4"),
                 "raw 8-bit RENAME destination must be refused")
    assert_match(/^a5 OK/, command(c, "a5", %(LIST "" "*")),
                 "LIST must keep working after a raw-UTF-8 RENAME attempt")
  end

  # -- 3. cross-account authorization ----------------------------------------

  test "lsub never shows another account's mailboxes" do
    listing = command(connect, "a1", %(LSUB "" "*"))
    refute_match(/#{BOB_PRIVATE}/, listing)
    assert_match(/"INBOX"/, listing)
  end

  test "list return status cannot probe another account's mailboxes" do
    reply = command(connect, "a1", %(LIST "" "*" RETURN (STATUS (MESSAGES))))
    refute_match(/#{BOB_PRIVATE}/, reply)
    refute_match(/S&AOk-cret/, reply)
    assert_match(/\* STATUS "INBOX"/, reply)
  end

  test "getquotaroot is not an existence oracle for foreign mailboxes" do
    c = connect
    # CVE-2026-47081 shape: probing a foreign mailbox must be
    # indistinguishable from probing a name that never existed.
    foreign = command(c, "a1", "GETQUOTAROOT #{BOB_PRIVATE}")
    missing = command(c, "a2", "GETQUOTAROOT No-Such-Mailbox")
    assert_match(/\Aa1 NO \[NONEXISTENT\]/, foreign)
    refute_match(/^\* QUOTAROOT/, foreign)
    assert_equal missing.sub("a2", "a1"), foreign
  end

  test "utf7 spelling of another account's mailbox is still refused" do
    c = connect
    assert_match(/\Aa1 NO/, command(c, "a1", "SELECT S&AOk-cret"))
    assert_match(/\Aa2 NO/, command(c, "a2", "STATUS S&AOk-cret (MESSAGES)"))
    assert_match(/\Aa3 NO/, append(c, "a3", "S&AOk-cret", ALICE_RAW))
    assert_equal 0, bob_count(BOB_UNICODE)
  end

  test "uid ranges beyond the selected mailbox resolve to nothing" do
    c = connect
    command(c, "s1", "SELECT INBOX")
    # UIDs outside the snapshot (which could exist in other mailboxes or
    # other accounts) must yield no data, not someone else's rows.
    reply = command(c, "a1", "UID FETCH 999999 (FLAGS)")
    assert_match(/\Aa1 OK/, reply)
    refute_match(/^\* \d+ FETCH/, reply)
    reply = command(c, "a2", "UID FETCH 2:4294967295 (BODY[HEADER.FIELDS (SUBJECT)])")
    refute_match(/bob-only/, reply)
    assert_match(/\Aa3 OK/, command(c, "a3", "UID STORE 999999 +FLAGS (\\Deleted)"))
    assert_equal 1, bob_count(BOB_PRIVATE)
  end

  test "renaming onto a name another account holds stays independent" do
    c = connect
    command(c, "a1", "CREATE Mine")
    # Bob already has BOB_PRIVATE; Alice renaming onto that name must
    # neither collide with nor touch his mailbox.
    assert_match(/^a2 OK/, command(c, "a2", "RENAME Mine #{BOB_PRIVATE}"))
    assert_equal 0, @store.status(@account_id, BOB_PRIVATE)[:messages]
    assert_equal 1, bob_count(BOB_PRIVATE)
  end

  test "namespace advertises no shared or other-user namespaces" do
    reply = command(connect, "a1", "NAMESPACE")
    assert_match(/\* NAMESPACE \(\("" "\/"\)\) NIL NIL/, reply)
  end
end

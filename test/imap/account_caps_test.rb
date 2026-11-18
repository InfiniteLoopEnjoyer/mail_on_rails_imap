# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# L22 (audit 2026-11-17): two things an account could grow without bound.
# Keywords: one STORE's flag list was capped, but +FLAGS accumulates - 40
# commands hung 5120 keywords (1.2 MiB of FLAGS line) on one message, sent
# again in every FETCH FLAGS and loaded into every session's snapshot.
# Mailboxes: CREATE had no ceiling, and every LIST walks them all.
class AccountCapsTest < Minitest::Test
  include WireHarness

  Server = MailOnRails::ImapServer

  def selected
    @store.append(@account_id, "INBOX", "Subject: one\r\n\r\nbody\r\n", [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def keywords(prefix, count) = (1..count).map { |i| "#{prefix}#{i}" }.join(" ")

  def flags_of(client, tag)
    command(client, tag, "FETCH 1 (FLAGS)")[/FLAGS \(([^)]*)\)/, 1].split
  end

  # -- keywords per message ------------------------------------------------------

  test "keywords accumulate up to the cap and no further" do
    c = selected
    assert_match(/^a1 OK/, command(c, "a1", "STORE 1 +FLAGS.SILENT (#{keywords("a", 100)})"))

    assert_equal "a2 NO [LIMIT] STORE failed: too many keywords on a message\r\n",
                 command(c, "a2", "STORE 1 +FLAGS.SILENT (#{keywords("b", 100)})")
    assert_equal 100, flags_of(c, "f1").length, "the refused STORE changed nothing"

    # Up to the cap exactly is fine, and so is re-adding what is there.
    assert_match(/^a3 OK/, command(c, "a3", "STORE 1 +FLAGS.SILENT (#{keywords("b", Server::MAX_KEYWORDS - 100)})"))
    assert_match(/^a4 OK/, command(c, "a4", "STORE 1 +FLAGS.SILENT (#{keywords("A", 100)})"))
    assert_equal Server::MAX_KEYWORDS, flags_of(c, "f2").length
    assert_match(/\Aa5 NO \[LIMIT\]/, command(c, "a5", "STORE 1 +FLAGS (one-more)"))
  end

  test "a message at the keyword cap can still be marked seen, flagged and deleted" do
    c = selected
    command(c, "a1", "STORE 1 +FLAGS.SILENT (#{keywords("k", Server::MAX_KEYWORDS)})")

    assert_match(/^a2 OK/, command(c, "a2", "STORE 1 +FLAGS.SILENT (\\Seen \\Flagged)"))
    assert_match(/^a3 OK/, command(c, "a3", "STORE 1 +FLAGS.SILENT (\\Deleted \\Answered \\Draft)"))
    flags = flags_of(c, "f")
    assert_equal Server::MAX_KEYWORDS + 5, flags.length
    assert_includes flags, "\\Seen"

    # Replacing and removing are never refused.
    assert_match(/^a4 OK/, command(c, "a4", "STORE 1 -FLAGS.SILENT (#{keywords("k", 50)})"))
    assert_match(/^a5 OK/, command(c, "a5", "STORE 1 FLAGS.SILENT (#{keywords("n", Server::MAX_KEYWORDS)})"))
    assert_equal Server::MAX_KEYWORDS, flags_of(c, "g").length
  end

  # A message that was already over the cap (stored before it existed, or
  # by another writer) is not locked: system flags still apply to it.
  test "a message already over the cap still takes system flags" do
    @store.append(@account_id, "INBOX", "Subject: one\r\n\r\nbody\r\n", (1..300).map { |i| "legacy#{i}" }, nil)
    c = connect
    command(c, "s0", "SELECT INBOX")

    assert_match(/^a1 OK/, command(c, "a1", "STORE 1 +FLAGS.SILENT (\\Seen)"))
    assert_match(/\Aa2 NO \[LIMIT\]/, command(c, "a2", "STORE 1 +FLAGS.SILENT (another)"))
    assert_match(/^a3 OK/, command(c, "a3", "STORE 1 +FLAGS.SILENT (legacy7)"), "nothing new: nothing to refuse")
  end

  test "the ordinary case: a handful of keywords on many messages in one STORE" do
    200.times { |i| @store.append(@account_id, "INBOX", "Subject: m#{i}\r\n\r\nb\r\n", [ "$Label1" ], nil) }
    c = connect
    command(c, "s0", "SELECT INBOX")

    reply = command(c, "a1", "STORE 1:* +FLAGS ($Forwarded $MDNSent NonJunk)")
    assert_match(/^a1 OK/, reply)
    assert_equal 200, reply.scan("$Label1 $Forwarded $MDNSent NonJunk").length
  end

  # -- mailboxes per account -----------------------------------------------------

  def with_max_mailboxes(count)
    old = Server::MAX_MAILBOXES
    Server.send(:remove_const, :MAX_MAILBOXES)
    Server.const_set(:MAX_MAILBOXES, count)
    yield
  ensure
    Server.send(:remove_const, :MAX_MAILBOXES)
    Server.const_set(:MAX_MAILBOXES, old)
  end

  def mailbox_count = @store.list_mailboxes(@account_id)[:mailboxes].length

  test "the cap is a thousand mailboxes" do
    assert_equal 1000, Server::MAX_MAILBOXES
  end

  test "CREATE is refused once the account holds the maximum" do
    c = connect
    existing = mailbox_count

    with_max_mailboxes(existing + 3) do
      3.times { |i| assert_match(/\Ac#{i} OK/, command(c, "c#{i}", "CREATE box#{i}")) }
      assert_equal "c9 NO [LIMIT] CREATE failed: too many mailboxes\r\n", command(c, "c9", "CREATE onemore")
      assert_equal existing + 3, mailbox_count

      # An existing name still answers as existing, and deleting makes room.
      assert_match(/\Ad1 NO \[ALREADYEXISTS\]/, command(c, "d1", "CREATE box0"))
      assert_match(/\Ad2 OK/, command(c, "d2", "DELETE box0"))
      assert_match(/\Ad3 OK/, command(c, "d3", "CREATE onemore"))
    end
  end

  test "the parents a CREATE or RENAME would make count toward the cap" do
    c = connect
    existing = mailbox_count

    with_max_mailboxes(existing + 3) do
      assert_equal "c1 NO [LIMIT] CREATE failed: too many mailboxes\r\n", command(c, "c1", "CREATE a/b/c/d")
      assert_equal existing, mailbox_count, "no parents left behind by the refused CREATE"
      assert_match(/\Ac2 OK/, command(c, "c2", "CREATE a/b/c"))

      assert_equal "r1 NO [LIMIT] RENAME failed: too many mailboxes\r\n", command(c, "r1", "RENAME a/b/c x/y")
      assert_match(/\Ar2 OK/, command(c, "r2", "RENAME a/b/c a/z"), "a rename that adds nothing is fine at the cap")
      assert_equal "r3 NO [LIMIT] RENAME failed: too many mailboxes\r\n", command(c, "r3", "RENAME INBOX Archive")
    end
  end

  test "an account already past the cap keeps working" do
    c = connect
    5.times { |i| @store.create_mailbox(@account_id, "old#{i}") }

    with_max_mailboxes(3) do
      assert_equal mailbox_count, command(c, "l", %(LIST "" "*")).scan(/^\* LIST/).length
      assert_match(/^a1 OK/, command(c, "a1", "SELECT old3"))
      assert_match(/\Aa2 OK/, command(c, "a2", "RENAME old1 renamed"))
      assert_match(/\Aa3 NO \[LIMIT\]/, command(c, "a3", "CREATE more"))
    end
  end
end

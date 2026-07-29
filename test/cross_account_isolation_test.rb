# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Account isolation: no command a session issues may read or write another
# account's mail. Every other wire suite runs one account against itself,
# so nothing there would notice a scoping regression.
#
# The guarantee has two halves, and both are tested here because both are
# easy to break in a refactor:
#
#   1. Name-addressed commands (LIST/SELECT/STATUS/CREATE/DELETE/RENAME/
#      APPEND) pass @account_id to the store, so a name only ever resolves
#      within the caller's account. Two accounts may hold the same mailbox
#      name; they are still different mailboxes.
#   2. Id-addressed commands (FETCH/STORE/COPY/MOVE/EXPUNGE/SEARCH) carry a
#      mailbox_id the session can only have received from its own
#      select_mailbox(@account_id, ...). The destination of COPY/MOVE is a
#      *name*, though, and the store must resolve it against the source
#      mailbox's owner - resolving it globally would let any session write
#      into any account's mailbox.
class CrossAccountIsolationTest < Minitest::Test
  ALICE = "alice@example.test"
  BOB = "bob@example.test"
  PASSWORD = "pw-123456"

  ALICE_RAW = "From: s@remote.test\r\nSubject: alice-only\r\n\r\nhers\r\n"
  BOB_RAW = "From: s@remote.test\r\nSubject: bob-only\r\n\r\nhis\r\n"

  # Bob's private mailbox: a name that does not exist on Alice's account,
  # so any leak shows up as a success where a NO is required.
  BOB_PRIVATE = "Bob-Private"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @alice = @store.add_account(email: ALICE, password: PASSWORD)
    @bob = @store.add_account(email: BOB, password: PASSWORD)

    @store.create_mailbox(@bob, BOB_PRIVATE)
    @store.append(@bob, BOB_PRIVATE, BOB_RAW, [], nil)
    @store.append(@bob, "INBOX", BOB_RAW, [], nil)
    @store.append(@alice, "INBOX", ALICE_RAW, [], nil)

    @listener = TCPServer.new("127.0.0.1", 0)
    @sessions = []
    @clients = []
    @acceptor = Thread.new do
      loop do
        sock = @listener.accept
        @sessions << Thread.new { MailOnRails::ImapServer::Session.new(sock, @store, { tls: :implicit }, nil).run }
      end
    rescue IOError, SystemCallError
      nil # listener closed in teardown
    end
  end

  def teardown
    @clients.each { |c| c.close rescue nil }
    @listener.close
    @acceptor.join(2)
    @sessions.each { |t| t.join(5) }
  end

  def connect(email)
    client = TCPSocket.new("127.0.0.1", @listener.addr[1])
    @clients << client
    client.gets("\r\n") # greeting
    command(client, "l0", "LOGIN #{email} #{PASSWORD}")
    client
  end

  def read_until_tagged(client, tag)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line.start_with?("#{tag} ")
    end
    lines.join
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_until_tagged(client, tag)
  end

  def alice_in_inbox
    client = connect(ALICE)
    command(client, "s0", "SELECT INBOX")
    client
  end

  # Message count straight from the store, bypassing the protocol entirely -
  # a leak that the wire hides still has to show up here.
  def message_count(account_id, name)
    @store.status(account_id, name)[:messages]
  end

  # -- name-addressed commands -----------------------------------------------

  test "list never shows another account's mailboxes" do
    listing = command(connect(ALICE), "a1", %(LIST "" "*"))
    refute_match(/#{BOB_PRIVATE}/, listing)
    assert_match(/"INBOX"/, listing) # ...but her own are there
  end

  test "select of another account's mailbox fails" do
    assert_match(/\Aa1 NO/, command(connect(ALICE), "a1", "SELECT #{BOB_PRIVATE}"))
  end

  test "examine of another account's mailbox fails" do
    assert_match(/\Aa1 NO/, command(connect(ALICE), "a1", "EXAMINE #{BOB_PRIVATE}"))
  end

  test "status of another account's mailbox fails" do
    reply = command(connect(ALICE), "a1", "STATUS #{BOB_PRIVATE} (MESSAGES)")
    assert_match(/\Aa1 NO/, reply)
    refute_match(/^\* STATUS/, reply)
  end

  test "delete of another account's mailbox fails and leaves it intact" do
    assert_match(/\Aa1 NO \[NONEXISTENT\]/, command(connect(ALICE), "a1", "DELETE #{BOB_PRIVATE}"))
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
  end

  test "rename of another account's mailbox fails and leaves it intact" do
    assert_match(/\Aa1 NO \[NONEXISTENT\]/, command(connect(ALICE), "a1", "RENAME #{BOB_PRIVATE} Stolen"))
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
    refute_includes @store.list_mailboxes(@bob)[:mailboxes], "Stolen"
  end

  test "append into another account's mailbox fails and leaves it intact" do
    client = connect(ALICE)
    client.write("a1 APPEND #{BOB_PRIVATE} {#{ALICE_RAW.bytesize}+}\r\n#{ALICE_RAW}\r\n")
    assert_match(/\Aa1 NO/, read_until_tagged(client, "a1"))
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
  end

  # A CREATE that collides with another account's name is a normal create,
  # not an "already exists" - the two mailboxes are unrelated.
  test "creating a mailbox another account already has succeeds independently" do
    assert_match(/\Aa1 OK/, command(connect(ALICE), "a1", "CREATE #{BOB_PRIVATE}"))
    assert_equal 0, message_count(@alice, BOB_PRIVATE)
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
  end

  # -- id-addressed commands -------------------------------------------------

  test "inboxes with the same name hold different mail" do
    fetch = command(alice_in_inbox, "a1", "FETCH 1:* (BODY[HEADER.FIELDS (SUBJECT)])")
    assert_match(/alice-only/, fetch)
    refute_match(/bob-only/, fetch)
  end

  # The COPY destination is a name resolved store-side. It must resolve
  # against the *source mailbox's* account, never globally.
  test "copy into another account's mailbox is refused" do
    reply = command(alice_in_inbox, "a1", "COPY 1 #{BOB_PRIVATE}")
    assert_match(/\Aa1 NO \[TRYCREATE\]/, reply)
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
  end

  test "uid copy into another account's mailbox is refused" do
    reply = command(alice_in_inbox, "a1", "UID COPY 1 #{BOB_PRIVATE}")
    assert_match(/\Aa1 NO \[TRYCREATE\]/, reply)
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
  end

  # A refused MOVE must also not destroy the source message: MOVE is
  # copy+expunge, and a destination lookup that failed open would delete
  # Alice's mail on the way to nowhere.
  test "move into another account's mailbox is refused and keeps the source" do
    reply = command(alice_in_inbox, "a1", "MOVE 1 #{BOB_PRIVATE}")
    assert_match(/\Aa1 NO \[TRYCREATE\]/, reply)
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
    assert_equal 1, message_count(@alice, "INBOX")
  end

  test "uid move into another account's mailbox is refused and keeps the source" do
    reply = command(alice_in_inbox, "a1", "UID MOVE 1 #{BOB_PRIVATE}")
    assert_match(/\Aa1 NO \[TRYCREATE\]/, reply)
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
    assert_equal 1, message_count(@alice, "INBOX")
  end

  # Same-named mailboxes on both accounts are the sharper version of the
  # COPY test: here the destination name *does* resolve for the attacker,
  # so a global lookup would silently pick one of the two.
  test "copy to a shared mailbox name lands in the caller's own mailbox" do
    @store.create_mailbox(@alice, "Archive")
    @store.create_mailbox(@bob, "Archive")

    assert_match(/\Aa1 OK \[COPYUID/, command(alice_in_inbox, "a1", "COPY 1 Archive"))
    assert_equal 1, message_count(@alice, "Archive")
    assert_equal 0, message_count(@bob, "Archive")
  end

  test "store flags cannot reach another account's messages" do
    bob_client = connect(BOB)
    command(bob_client, "s0", "SELECT #{BOB_PRIVATE}")

    # Alice flags every uid in her own selected mailbox; Bob's identically
    # numbered uid must be untouched.
    command(alice_in_inbox, "a1", "UID STORE 1:* +FLAGS (\\Deleted)")

    fetch = command(bob_client, "b1", "FETCH 1 (FLAGS)")
    refute_match(/\\Deleted/, fetch)
  end

  test "expunge cannot reach another account's messages" do
    command(alice_in_inbox, "a1", "UID STORE 1:* +FLAGS (\\Deleted)")
    command(alice_in_inbox, "a2", "EXPUNGE")
    assert_equal 1, message_count(@bob, BOB_PRIVATE)
    assert_equal 1, message_count(@bob, "INBOX")
  end

  test "search never matches another account's messages" do
    reply = command(alice_in_inbox, "a1", "SEARCH TEXT bob-only")
    assert_match(/\A\* SEARCH\r\n/, reply)
  end

  # -- identity switching ----------------------------------------------------

  # RFC 3501 §6.2: LOGIN is only valid when not authenticated. It is also
  # an isolation guard - a second login used to leave the first account's
  # selected mailbox_id in place, so the new identity kept reading the old
  # account's mail.
  test "login is refused once authenticated and does not rebind the session" do
    client = alice_in_inbox
    assert_match(/\Aa1 BAD/, command(client, "a1", "LOGIN #{BOB} #{PASSWORD}"))

    # Still Alice, still her mailbox...
    fetch = command(client, "a2", "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])")
    assert_match(/alice-only/, fetch)
    refute_match(/bob-only/, fetch)

    # ...and still without any of Bob's namespace.
    assert_match(/\Aa3 NO/, command(client, "a3", "SELECT #{BOB_PRIVATE}"))
  end

  test "authenticate is refused once authenticated" do
    client = alice_in_inbox
    initial = [ "\0#{BOB}\0#{PASSWORD}" ].pack("m0")
    assert_match(/\Aa1 BAD/, command(client, "a1", "AUTHENTICATE PLAIN #{initial}"))
  end

  # RFC 4616 allows an authzid ("act as this other user") in SASL PLAIN.
  # This server grants no such delegation: the authzid is ignored and the
  # session is bound to the authenticated identity, never the requested one.
  test "sasl plain authzid cannot request another account" do
    client = TCPSocket.new("127.0.0.1", @listener.addr[1])
    @clients << client
    client.gets("\r\n")

    # Authenticate as Bob while asking to act as Alice.
    initial = [ "#{ALICE}\0#{BOB}\0#{PASSWORD}" ].pack("m0")
    assert_match(/\Aa1 OK/, command(client, "a1", "AUTHENTICATE PLAIN #{initial}"))

    # Bound to Bob: his private mailbox resolves, and it holds his mail.
    assert_match(/^a2 OK/, command(client, "a2", "SELECT #{BOB_PRIVATE}"))
    assert_match(/bob-only/, command(client, "a3", "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])"))
  end
end

# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The pre-authentication literal cap: before a session authenticates, the
# only legitimate literals are LOGIN arguments - so an unauthenticated
# peer must not be able to force a MAX_LITERAL_BYTES (30 MiB) read via
# LITERAL+ before a single command dispatches.
class PreauthLiteralTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  CAP = MailOnRails::ImapServer::MAX_PREAUTH_LITERAL_BYTES

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def session
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    thread = Thread.new do
      MailOnRails::ImapServer::Session.new(session_socket, @store, { tls: :implicit }, nil).run
    end
    @cleanup << -> { client.close }
    @cleanup << -> { thread.join(5) }
    @cleanup << -> { server.close }
    client.gets("\r\n") # greeting
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

  def drain(client)
    rest = +""
    rest << client.gets("\r\n").to_s while !client.eof?
    rest
  rescue IOError, SystemCallError
    rest
  end

  def login(client, tag = "l1")
    command(client, tag, "LOGIN #{EMAIL} #{PASSWORD}")
  end

  # -- legitimate pre-auth literals keep working -----------------------------

  test "login with a small literal password authenticates" do
    client = session
    client.write("a1 LOGIN #{EMAIL} {#{PASSWORD.bytesize}}\r\n")
    assert_match(/\A\+ /, client.gets("\r\n"))
    client.write("#{PASSWORD}\r\n")

    assert_match(/\Aa1 OK/, read_until_tagged(client, "a1"))
  end

  # -- the cap ---------------------------------------------------------------

  test "an oversize pre-auth synchronizing literal is refused and the session survives" do
    client = session
    client.write("a1 LOGIN #{EMAIL} {#{CAP + 1}}\r\n")

    # No continuation, so nothing to drain: a polite refusal.
    assert_match(/\Aa1 NO \[TOOBIG\]/, read_until_tagged(client, "a1"))
    assert_match(/\Aa2 OK/, login(client, "a2"))
  end

  # LITERAL+ is the attack shape: the octets come without waiting for a
  # continuation, so "refuse and drain" would still be the forced read.
  # The connection must drop instead - before the payload is read.
  test "an oversize pre-auth non-synchronizing literal drops the connection unread" do
    client = session
    # Only the header is sent; a server that tried to drain the declared
    # payload would block on this socket until the read timeout.
    client.write("a1 LOGIN #{EMAIL} {#{30 * 1024 * 1024}+}\r\n")

    reply = read_until_tagged(client, "a1")
    assert_match(/\Aa1 NO \[TOOBIG\]/, reply)
    assert_match(/\* BYE/, drain(client))
    assert client.eof?
  end

  test "pre-auth literals over the aggregate cap drop the connection" do
    client = session
    chunk = CAP / 2
    # Three LITERAL+ literals, each under the per-literal cap, together
    # over it: the third header must be refused without reading its payload.
    client.write("a1 X {#{chunk}+}\r\n#{"x" * chunk}{#{chunk}+}\r\n#{"x" * chunk}{#{chunk}+}\r\n")

    assert_match(/\Aa1 NO \[TOOBIG\]/, read_until_tagged(client, "a1"))
    assert_match(/\* BYE/, drain(client))
  end

  # Each refusal used to recurse into read_command (no tail-call
  # elimination), so a client streaming oversize synchronizing literals
  # could blow the session-thread stack - and SystemStackError is not
  # StandardError, so the thread died without even the error log line.
  # The refusal loop must keep the stack flat.
  test "a stream of refused literals does not grow the session stack" do
    client = session
    rounds = 5_000
    # Pipelined in batches so neither side's socket buffer fills.
    rounds.times.each_slice(500) do |batch|
      batch.each { |i| client.write("t#{i} LOGIN #{EMAIL} {#{CAP + 1}}\r\n") }
      batch.each { |i| assert_match(/\At#{i} NO \[TOOBIG\]/, read_until_tagged(client, "t#{i}")) }
    end

    assert_match(/\Aa9 OK/, login(client, "a9"), "the session must still work after the refusals")
  end

  # -- the cap is pre-auth only ----------------------------------------------

  test "authenticated sessions still accept literals over the pre-auth cap" do
    client = session
    assert_match(/\Aa1 OK/, login(client, "a1"))

    payload = "Subject: big\r\n\r\n#{"y" * CAP}"
    client.write("a2 APPEND INBOX {#{payload.bytesize}}\r\n")

    assert_match(/\A\+ /, client.gets("\r\n"), "an authenticated literal over the pre-auth cap must get a continuation")
    client.write("#{payload}\r\n")

    assert_match(/\Aa2 OK/, read_until_tagged(client, "a2"))
  end
end

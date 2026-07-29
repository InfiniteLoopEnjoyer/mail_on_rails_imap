# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The plaintext listener and the STARTTLS upgrade on it. Every other wire
# suite builds sessions with spec tls: :implicit, so the whole "credentials
# are refused until the channel is encrypted" half of the server is only
# exercised here.
class StarttlsTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # One self-signed pair for the whole suite; generating RSA keys per test
  # dominates the runtime otherwise.
  def self.tls_context
    @tls_context ||= MailOnRails::Imap::TLS.context(MailOnRails::Imap::TLS.generate_self_signed)
  end

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @store.append(@account_id, "INBOX", "From: a@b.test\r\nSubject: hi\r\n\r\nx\r\n", [], nil)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # A session on a plaintext (STARTTLS-capable) listener. tls_ctx nil
  # models a listener with no TLS material at all.
  def plaintext_session(tls_ctx: self.class.tls_context)
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    thread = Thread.new do
      MailOnRails::ImapServer::Session.new(session_socket, @store, { tls: :starttls }, tls_ctx).run
    end
    @cleanup << -> { client.close }
    @cleanup << -> { thread.join(5) }
    @cleanup << -> { server.close }
    client
  end

  def tls_connect(socket)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    tls.sync_close = true
    tls.connect
    tls
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

  # -- capability advertisement ----------------------------------------------

  test "plaintext greeting advertises starttls and logindisabled but no auth mechanisms" do
    greeting = plaintext_session.gets("\r\n")
    assert_match(/STARTTLS/, greeting)
    assert_match(/LOGINDISABLED/, greeting)
    refute_match(/AUTH=PLAIN/, greeting)
    refute_match(/AUTH=SCRAM-SHA-256/, greeting)
  end

  test "a listener with no tls material still advertises logindisabled and offers no starttls" do
    greeting = plaintext_session(tls_ctx: nil).gets("\r\n")
    assert_match(/LOGINDISABLED/, greeting)
    refute_match(/STARTTLS/, greeting)
  end

  test "capability after starttls drops logindisabled and offers auth mechanisms" do
    client = plaintext_session
    client.gets("\r\n")
    command(client, "a1", "STARTTLS")
    tls = tls_connect(client)

    caps = command(tls, "a2", "CAPABILITY")
    assert_match(/AUTH=PLAIN/, caps)
    assert_match(/AUTH=SCRAM-SHA-256/, caps)
    refute_match(/LOGINDISABLED/, caps)
    refute_match(/STARTTLS/, caps)
  end

  # -- credentials are refused in the clear ----------------------------------

  test "login in the clear is refused with privacyrequired" do
    client = plaintext_session
    client.gets("\r\n")
    assert_match(/\Aa1 NO \[PRIVACYREQUIRED\]/, command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}"))
    # ...and it really did not authenticate.
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  test "authenticate plain in the clear is refused with privacyrequired" do
    client = plaintext_session
    client.gets("\r\n")
    initial = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
    assert_match(/\Aa1 NO \[PRIVACYREQUIRED\]/, command(client, "a1", "AUTHENTICATE PLAIN #{initial}"))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  test "authenticate scram in the clear is refused with privacyrequired" do
    client = plaintext_session
    client.gets("\r\n")
    initial = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")
    assert_match(/\Aa1 NO \[PRIVACYREQUIRED\]/, command(client, "a1", "AUTHENTICATE SCRAM-SHA-256 #{initial}"))
  end

  # A refused plaintext LOGIN must not burn an auth attempt: the credentials
  # were never checked, so this is a client misconfiguration, not a guess.
  test "privacyrequired refusals do not count toward the auth attempt cap" do
    client = plaintext_session
    client.gets("\r\n")
    (MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS + 2).times do |i|
      assert_match(/\Ar#{i} NO \[PRIVACYREQUIRED\]/, command(client, "r#{i}", "LOGIN #{EMAIL} #{PASSWORD}"))
    end
  end

  # -- the upgrade itself ----------------------------------------------------

  test "login succeeds after starttls" do
    client = plaintext_session
    client.gets("\r\n")
    assert_match(/\Aa1 OK Begin TLS/, command(client, "a1", "STARTTLS"))
    tls = tls_connect(client)

    assert_match(/\Aa2 OK/, command(tls, "a2", "LOGIN #{EMAIL} #{PASSWORD}"))
    assert_match(/^\* 1 EXISTS/, command(tls, "a3", "SELECT INBOX"))
  end

  test "starttls is refused when the listener has no tls material" do
    client = plaintext_session(tls_ctx: nil)
    client.gets("\r\n")
    assert_match(/\Aa1 NO TLS not available/, command(client, "a1", "STARTTLS"))
  end

  test "a second starttls inside the tls session is refused" do
    client = plaintext_session
    client.gets("\r\n")
    command(client, "a1", "STARTTLS")
    tls = tls_connect(client)
    assert_match(/\Aa2 NO TLS already active/, command(tls, "a2", "STARTTLS"))
  end

  # The CVE-2011-0411 class: a client pipelines a command behind STARTTLS in
  # the same segment, hoping the server buffers it in the clear and then
  # runs it as though it had arrived encrypted. It must be discarded.
  test "commands pipelined behind starttls are never executed" do
    client = plaintext_session
    client.gets("\r\n")

    # One write, so the LOGIN is already in the server's socket when the
    # handshake begins.
    client.write("a1 STARTTLS\r\na2 LOGIN #{EMAIL} #{PASSWORD}\r\n")
    assert_match(/\Aa1 OK Begin TLS/, client.gets("\r\n"))

    tls = tls_connect(client)

    # The smuggled LOGIN neither ran nor produced a response: the session is
    # still unauthenticated, and the next tagged reply is a3's.
    assert_match(/\Aa3 NO Not authenticated/, command(tls, "a3", "SELECT INBOX"))
  end

  # Same attack aimed at the state reset rather than at authentication: even
  # a pipelined SELECT must not leave a mailbox selected across the upgrade.
  test "state does not survive the starttls upgrade" do
    client = plaintext_session
    client.gets("\r\n")
    client.write("a1 STARTTLS\r\na2 SELECT INBOX\r\n")
    assert_match(/\Aa1 OK Begin TLS/, client.gets("\r\n"))

    tls = tls_connect(client)
    # FETCH requires a selected mailbox; nothing may be selected here.
    assert_match(/\Aa3 NO No mailbox selected/, command(tls, "a3", "FETCH 1 (UID)"))
  end
end

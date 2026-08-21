# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Penetration-test scenarios for IMAP: pre-auth command surface, TLS gating,
# and parser edges that commonly show up in real-world audits. Account
# isolation has its own suite (cross_account_isolation_test.rb).
#
# Run via bin/rails test:imap_server (or bin/rails test with this path).
class ImapPenTest < Minitest::Test
  ALICE = "alice@example.test"
  BOB = "bob@example.test"
  PASSWORD = "pw-123456"
  ALICE_RAW = "From: s@remote.test\r\nSubject: alice-only\r\n\r\nhers\r\n"
  RAW = "From: sender@remote.test\r\nSubject: pen\r\n\r\nbody\r\n"

  def self.tls_context
    @tls_context ||= MailOnRails::Netserv::Tls.context(MailOnRails::Netserv::Tls.generate_self_signed)
  end

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @alice_id = @store.add_account(email: ALICE, password: PASSWORD)
    @bob_id = @store.add_account(email: BOB, password: PASSWORD)
    @store.append(@alice_id, "INBOX", ALICE_RAW, [], nil)
    @store.create_mailbox(@bob_id, "Bob-Secret")
    @store.append(@bob_id, "Bob-Secret", RAW, [], nil)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def implicit_session
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
    client
  end

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

  def with_imap_const(name, value)
    klass = MailOnRails::ImapServer
    old = klass.const_get(name)
    klass.send(:remove_const, name)
    klass.const_set(name, value)
    yield
  ensure
    klass.send(:remove_const, name)
    klass.const_set(name, old)
  end

  # -- pre-auth command surface ----------------------------------------------

  def test_pre_auth_select_is_refused
    client = implicit_session
    client.gets("\r\n")
    assert_match(/\Aa1 (NO|BAD)/, command(client, "a1", "SELECT INBOX"))
  end

  def test_pre_auth_append_is_refused
    client = implicit_session
    client.gets("\r\n")
    assert_match(/\Aa1 (NO|BAD)/, command(client, "a1", "APPEND INBOX"))
  end

  def test_pre_auth_fetch_is_refused
    client = implicit_session
    client.gets("\r\n")
    assert_match(/\Aa1 (NO|BAD)/, command(client, "a1", "FETCH 1 BODY[]"))
  end

  def test_pre_auth_search_is_refused
    client = implicit_session
    client.gets("\r\n")
    assert_match(/\Aa1 (NO|BAD)/, command(client, "a1", "SEARCH ALL"))
  end

  def test_pre_auth_idle_is_refused
    client = implicit_session
    client.gets("\r\n")
    assert_match(/\Aa1 (NO|BAD)/, command(client, "a1", "IDLE"))
  end

  def test_pre_auth_capability_and_noop_are_allowed
    client = implicit_session
    greeting = client.gets("\r\n")
    assert_match(/\A\* OK/, greeting)
    assert_match(/a1 OK CAPABILITY/, command(client, "a1", "CAPABILITY"))
    assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"))
  end

  # -- TLS gating ------------------------------------------------------------

  def test_plaintext_login_is_refused_with_privacy_required
    client = plaintext_session
    client.gets("\r\n")
    reply = command(client, "a1", "LOGIN #{ALICE} #{PASSWORD}")
    assert_match(/\Aa1 NO \[PRIVACYREQUIRED\]/, reply)
  end

  def test_authenticate_on_plaintext_is_refused
    client = plaintext_session
    client.gets("\r\n")
    initial = [ "\0#{ALICE}\0#{PASSWORD}" ].pack("m0")
    reply = command(client, "a1", "AUTHENTICATE PLAIN #{initial}")
    assert_match(/\Aa1 NO \[PRIVACYREQUIRED\]/, reply)
  end

  def test_login_after_starttls_succeeds
    client = plaintext_session
    client.gets("\r\n")
    assert_match(/\Aa1 OK/, command(client, "a1", "STARTTLS"))
    tls = tls_connect(client)
    assert_match(/\Aa2 OK/, command(tls, "a2", "LOGIN #{ALICE} #{PASSWORD}"))
  end

  # -- authorization probes --------------------------------------------------

  def test_unauthenticated_list_does_not_reveal_another_accounts_private_mailbox
    client = implicit_session
    client.gets("\r\n")
    command(client, "a1", "LOGIN #{ALICE} #{PASSWORD}")
    listing = command(client, "a2", %(LIST "" "*"))
    refute_match(/Bob-Secret/, listing)
  end

  def test_select_of_another_accounts_mailbox_fails_closed
    client = implicit_session
    client.gets("\r\n")
    command(client, "a1", "LOGIN #{ALICE} #{PASSWORD}")
    assert_match(/\Aa2 NO/, command(client, "a2", "SELECT Bob-Secret"))
  end

  def test_sasl_plain_authzid_cannot_switch_into_another_account
    client = implicit_session
    client.gets("\r\n")
    initial = [ "#{ALICE}\0#{BOB}\0#{PASSWORD}" ].pack("m0")
    assert_match(/\Aa1 OK/, command(client, "a1", "AUTHENTICATE PLAIN #{initial}"))
    assert_match(/a2 OK \[READ-WRITE\] SELECT/, command(client, "a2", "SELECT Bob-Secret"))
    fetch = command(client, "a3", "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])")
    assert_match(/pen/, fetch)
    select = command(client, "a4", "SELECT INBOX")
    refute_match(/\* 1 EXISTS/, select, "authzid must not bind the session to Alice's INBOX")
    search = command(client, "a5", "SEARCH TEXT alice-only")
    refute_match(/alice-only/, search)
  end

  # -- parser edges ----------------------------------------------------------

  def test_mailbox_name_with_embedded_quotes_cannot_select_another_users_data
    client = implicit_session
    client.gets("\r\n")
    command(client, "a1", "LOGIN #{ALICE} #{PASSWORD}")
    assert_match(/\Aa2 NO/, command(client, "a2", %(SELECT "Bob-Secret")))
    assert_match(/\Aa3 NO/, command(client, "a3", %(SELECT Bob-Secret")))
  end

  def test_oversize_literal_append_is_refused_and_session_stays_usable
    client = implicit_session
    client.gets("\r\n")
    command(client, "a1", "LOGIN #{ALICE} #{PASSWORD}")
    with_imap_const(:MAX_LITERAL_BYTES, 64) do
      reply = command(client, "a2", "APPEND INBOX {128}")
      assert_match(/\Aa2 NO \[TOOBIG\]/, reply)
      assert_match(/\Aa3 OK/, command(client, "a3", "NOOP"))
    end
  end
end

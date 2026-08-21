require "test_helper"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Honeypot behavior on the IMAP session: a canary login is observed while the
# attacker browses (SELECT/FETCH), exploit-probe payloads are recorded and
# refused, credentials are redacted from the transcript, and a deceptive banner
# can replace the greeting. Driven directly over a loopback socket - no Rails.
class ImapHoneypotSessionTest < Minitest::Test
  CANARY = "admin@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: decoy\r\n\r\nlure body\r\n"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @canary_id = @store.add_account(email: CANARY, password: PASSWORD, honeypot: true)
    @store.append(@canary_id, "INBOX", RAW, [], nil)
    @store.add_account(email: "real@example.test", password: PASSWORD)
  end

  def with_session(spec: { tls: :implicit })
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    @session = MailOnRails::ImapServer::Session.new(session_socket, @store, spec, nil)
    thread = Thread.new { @session.run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    @session&.finalize_honeypot # the Server calls this at teardown
    server&.close
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

  def test_canary_login_is_recorded_and_browsing_is_observed
    with_session do |client|
      client.gets("\r\n")
      assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{CANARY} #{PASSWORD}"))
      command(client, "a2", "SELECT INBOX")
      command(client, "a3", "FETCH 1 (BODY[])")
      command(client, "a4", "LOGOUT")
    end

    assert_equal 1, @store.honeypot_events.size
    event = @store.honeypot_events.first
    assert_equal "canary_auth", event[:trigger]
    assert_equal "imap", event[:protocol]
    assert_equal CANARY, event[:username]
    # The post-login browsing (flushed at teardown) is captured.
    assert_includes event[:transcript], "SELECT INBOX"
    assert_includes event[:transcript], "FETCH 1 (BODY[])"
  end

  def test_transcript_redacts_the_login_password
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{CANARY} #{PASSWORD}")
      command(client, "a2", "LOGOUT")
    end

    transcript = @store.honeypot_events.first[:transcript]
    assert_includes transcript, "a1 LOGIN [redacted]"
    refute_includes transcript, PASSWORD
  end

  def test_a_normal_account_login_records_nothing
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN real@example.test #{PASSWORD}")
      command(client, "a2", "LOGOUT")
    end

    assert_empty @store.honeypot_events
  end

  def test_exploit_probe_is_recorded_and_refused
    with_session do |client|
      client.gets("\r\n")
      reply = command(client, "a1", "SELECT () { :; }; /bin/sh")
      assert_match(/\Aa1 BAD/, reply)
      command(client, "a2", "LOGOUT")
    end

    event = @store.honeypot_events.first
    assert_equal "exploit_probe", event[:trigger]
    assert_equal "shellshock", event[:signature]
  end

  def test_deceptive_banner_replaces_the_greeting
    with_session(spec: { tls: :implicit, honeypot_banner: "Dovecot ready" }) do |client|
      assert_match(/Dovecot ready/, client.gets("\r\n"))
      command(client, "a1", "LOGOUT")
    end
  end
end

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

  # An HTTP scanner's request line: the tag it "sends" is GET, so the BAD
  # is tagged GET; recorded under its own trigger for protocol_auto_ban.
  def test_http_request_at_the_imap_port_is_recorded_as_a_foreign_protocol
    with_session do |client|
      client.gets("\r\n")
      assert_match(/\AGET BAD Unknown command\r\n\z/, command(client, "GET", "/ HTTP/1.1"))
      command(client, "a2", "LOGOUT")
    end

    event = @store.honeypot_events.first
    assert_equal "foreign_protocol", event[:trigger]
    assert_equal "http_request", event[:signature]
    assert_includes event[:transcript], "<= GET / HTTP/1.1"
  end

  # A scanner's binary blob carries no CRLF, so it reaches handle as one
  # unterminated line at EOF. It is named, recorded, and the junk "tag" is
  # not echoed back (before, the BAD carried the first run of bytes as its
  # tag).
  def test_tls_handshake_on_the_plaintext_port_is_recorded_and_not_reflected
    with_session do |client|
      client.gets("\r\n")
      client.write("\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03\xff\xfe".b)
      client.close_write
      assert_equal "* BAD Unknown command\r\n", client.gets("\r\n")
    end

    event = @store.honeypot_events.first
    assert_equal "foreign_protocol", event[:trigger]
    assert_equal "tls_handshake", event[:signature]
  end

  def test_garbage_bytes_are_recorded_and_refused_and_the_session_survives
    with_session do |client|
      client.gets("\r\n")
      # The junk "tag" is cut at its first non-printable byte, so the
      # reply is tagged "b" - the test's tag-matching reader can't be used.
      client.write("b\x00/{m<;s3gMm>.4 ;1\r\n")
      assert_equal "b BAD Unknown command\r\n", client.gets("\r\n")
      client.write("\xff\xfe junk\r\n".b)
      assert_equal "* BAD Unknown command\r\n", client.gets("\r\n")
      assert_match(/\Aa3 OK/, command(client, "a3", "NOOP"), "the session is still usable afterwards")
      command(client, "a4", "LOGOUT")
    end

    assert_equal 1, @store.honeypot_events.size, "one event per session, not per line"
    event = @store.honeypot_events.first
    assert_equal "garbage", event[:trigger]
    assert_equal "control_bytes", event[:signature]
  end
end

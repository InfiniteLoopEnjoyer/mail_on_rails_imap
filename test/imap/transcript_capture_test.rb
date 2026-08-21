# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Session-level rules for imap_trace_capture (Session#transcript_capture),
# the IMAP twin of test/smtp/transcript_capture_test.rb: only abnormally
# ended sessions hand a transcript to the teardown path, the capture is
# opt-in, honeypot sessions are excluded (their transcript lands in the
# HoneypotEvent instead), and credentials never appear in the captured
# dialogue. Driven directly over a loopback socket - no Rails, no
# database. tls: :implicit with a nil context marks the session TLS so
# LOGIN is permitted without a real handshake.
class ImapTranscriptCaptureTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new(max_account_failures: 1000, max_ip_failures: 1000)
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def with_session(spec_extra: {})
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    spec = { host: "127.0.0.1", port: server.addr[1], tls: :implicit, trace_capture: true }.merge(spec_extra)
    @session = MailOnRails::ImapServer::Session.new(session_socket, @store, spec, nil)
    thread = Thread.new { @session.run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    server&.close
  end

  def read_until_tagged(client, tag)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line.start_with?("#{tag} ")
    end
    lines.join
  rescue IOError, SystemCallError
    lines.join
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_until_tagged(client, tag)
  end

  def test_clean_logout_session_captures_nothing
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "NOOP")
      command(client, "a2", "LOGOUT")
    end
    assert_nil @session.transcript_capture
  end

  def test_bare_eof_without_logout_captures_nothing
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "NOOP")
    end
    assert_nil @session.transcript_capture
  end

  def test_protocol_errors_capture_the_dialogue_even_after_clean_logout
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "BOGUS")
      command(client, "a2", "LOGOUT")
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "protocol_errors", capture[:close_reason]
    assert_includes capture[:transcript], "<= a1 BOGUS"
    assert_includes capture[:transcript], "=> a1 BAD Unknown command"
  end

  def test_failed_login_captures_with_redacted_credentials
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{EMAIL} wrong-password")
      command(client, "a2", "LOGOUT")
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "auth_failed", capture[:close_reason]
    assert_includes capture[:transcript], "<= a1 LOGIN [redacted]"
    refute_includes capture[:transcript], "wrong-password"
  end

  def test_successful_login_then_logout_captures_nothing
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}")
      command(client, "a2", "LOGOUT")
    end
    assert_nil @session.transcript_capture
  end

  def test_session_timeout_captures_with_timeout_reason
    with_session(spec_extra: { timeout: 0.2 }) do |client|
      client.gets("\r\n")
      command(client, "a1", "NOOP")
      sleep 0.5 # outlive the timeout without sending anything
    end
    capture = @session.transcript_capture
    refute_nil capture
    assert_equal "timeout", capture[:close_reason]
  end

  def test_capture_disabled_yields_nothing_even_on_errors
    with_session(spec_extra: { trace_capture: false }) do |client|
      client.gets("\r\n")
      command(client, "a1", "BOGUS")
      command(client, "a2", "LOGOUT")
    end
    assert_nil @session.transcript_capture
  end

  def test_honeypot_sessions_are_excluded
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN () { :; } shellshock") # probe signature
      command(client, "a2", "LOGOUT")
    end
    assert @session.honeypot_fired?, "probe must have fired the honeypot"
    assert_nil @session.transcript_capture
  end
end

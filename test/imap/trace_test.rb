# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The opt-in protocol trace (imap_trace): every command and response line
# reaches the store log, credentials redacted, message literals truncated.
class ImapTraceTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # A memory store that records what gets logged.
  class LoggingStore < MailOnRails::Imap::Store::Memory
    attr_reader :logged

    def initialize(*)
      super
      @logged = []
    end

    def log(level, message)
      @logged << [ level, message ]
      nil
    end
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def run_session(trace:)
    store = LoggingStore.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    @cleanup << -> { listener.close rescue nil }
    session = MailOnRails::ImapServer::Session.new(listener.accept, store, { tls: :implicit, trace: trace }, nil)
    thread = Thread.new { session.run }
    @cleanup << -> { thread.kill }

    client.gets("\r\n") # greeting
    client.write("a1 LOGIN #{EMAIL} #{PASSWORD}\r\n")
    client.gets("\r\n")
    client.write("a2 NOOP\r\n")
    client.gets("\r\n")
    client.write("a3 LOGOUT\r\n")
    thread.join(5)
    store.logged
  end

  def test_traces_commands_and_responses_with_credentials_redacted
    logged = run_session(trace: true)
    lines = logged.select { |_level, msg| msg.start_with?("IMAP <=", "IMAP =>") }

    assert lines.any? { |_l, msg| msg.include?("<= a2 NOOP") }, "commands must be traced"
    assert lines.any? { |_l, msg| msg.include?("=> a2 OK") }, "responses must be traced"
    assert lines.any? { |_l, msg| msg.include?("a1 LOGIN [redacted]") }, "LOGIN must be redacted"
    refute lines.any? { |_l, msg| msg.include?(PASSWORD) }, "the password must never be logged"
  end

  def test_trace_off_logs_no_protocol_lines
    logged = run_session(trace: false)

    refute logged.any? { |_level, msg| msg.start_with?("IMAP <=", "IMAP =>") }
  end
end

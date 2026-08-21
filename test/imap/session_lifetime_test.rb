# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The absolute session lifetime (Netserv::Server's reaper) applied to IMAP.
# IMAP IDLE is legitimately long-lived so the cap is disabled by default,
# but when an operator sets imap_session_seconds the generic reaper must
# close an over-age connection on age alone - a NOOP-trickling peer is
# never idle, so only the absolute lifetime can end it.
class ImapSessionLifetimeTest < Minitest::Test
  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def start_server(session_lifetime:)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls,
             tcp_server: listener, session_lifetime: session_lifetime }
    thread = Thread.new { MailOnRails::ImapServer.run(@store, [ spec ], nil) }
    @cleanup << -> { thread.kill }
    spec
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    assert_match(/\A\* OK /, client.gets("\r\n"))
    client
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  test "an active session is closed once it outlives the cap" do
    spec = start_server(session_lifetime: 0.5)
    client = connect(spec)

    started = monotonic
    closed = false
    n = 0
    while monotonic - started < 5
      begin
        client.write("a#{n += 1} NOOP\r\n")
        break closed = true unless client.gets("\r\n")
      rescue IOError, SystemCallError
        break closed = true
      end
      sleep 0.05
    end

    assert closed, "the reaper must close an IMAP session past its lifetime"
    assert_operator monotonic - started, :>=, 0.3, "must not close a fresh session"
  end

  test "a zero lifetime disables the reaper" do
    spec = start_server(session_lifetime: 0)
    client = connect(spec)

    deadline = monotonic + 1.2
    n = 0
    while monotonic < deadline
      client.write("a#{n += 1} NOOP\r\n")
      assert_match(/OK/, client.gets("\r\n"), "session must stay open with the reaper disabled")
      sleep 0.1
    end
  end
end

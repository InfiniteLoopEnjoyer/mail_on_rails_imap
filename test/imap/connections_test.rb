# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The live-connections registry behind the Rails UI's IMAP page:
# Server#connections snapshots each connection as plain values (no socket
# or thread escapes), Session#live_info tracks login/SELECT/IDLE, and
# Server#kick force-closes a banned address's live sessions.
class ImapConnectionsTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # A memory store that also keeps connection history, standing in for
  # the Rails backend's optional record_closed_connection. The plain
  # Memory store used everywhere else lacks the method, which doubles as
  # the pin on the server's respond_to? guard.
  class RecordingStore < MailOnRails::Imap::Store::Memory
    attr_reader :closed

    def initialize(*)
      super
      @closed = []
    end

    def record_closed_connection(info)
      @closed << info
      {}
    end
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_server(store: MailOnRails::Imap::Store::Memory.new)
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :none, tcp_server: listener }
    server = MailOnRails::ImapServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    server.wait_ready(5)
    [ server, spec ]
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def eventually(timeout = 5, message = "condition not met")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk "#{message} within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
  end

  def test_connections_snapshots_registry_and_preauth_state
    server, spec = build_server

    assert_empty server.connections

    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))
    eventually(5, "connection not registered") { server.connections.size == 1 }

    conn = server.connections.first

    assert_equal "IMAP", conn[:protocol]
    assert_equal "127.0.0.1", conn[:peer_ip]
    assert_equal spec[:port], conn[:port]
    assert_nil conn[:role]
    assert_kind_of Time, conn[:connected_at]
    assert_equal "pre-auth", conn[:state]
    assert_nil conn[:user]
    assert_nil conn[:tarpit], "loopback peers are rate-limit exempt"

    client.write("a1 LOGOUT\r\n")
    eventually(5, "connection not deregistered") { server.connections.empty? }
  end

  def test_kick_closes_only_matching_connections
    server, spec = build_server
    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))
    eventually(5, "connection not registered") { server.connections.size == 1 }

    assert_equal 0, server.kick { |ip| ip == "198.51.100.1" }
    assert_equal 1, server.kick { |ip| ip == "127.0.0.1" }

    assert_nil client.gets("\r\n"), "kicked client must see EOF"
    eventually(5, "kicked connection not deregistered") { server.connections.empty? }
  end

  def test_close_reports_history_to_a_store_that_keeps_it
    store = RecordingStore.new
    _server, spec = build_server(store: store)
    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))
    client.write("a1 LOGOUT\r\n")

    eventually(5, "close not reported") { store.closed.size == 1 }
    info = store.closed.first

    assert_equal "imap", info[:protocol]
    assert_equal "127.0.0.1", info[:ip]
    assert_equal spec[:port], info[:port]
    assert_nil info[:role]
    assert_equal "pre-auth", info[:state]
    assert_nil info[:user]
    assert_kind_of Time, info[:connected_at]
    assert_kind_of Time, info[:closed_at]
    assert_operator info[:duration_seconds], :>=, 0
    assert_nil info[:tarpit_seconds], "loopback peers are rate-limit exempt"
  end

  # A rate limiter that tarpits every connection, standing in for the real
  # one (loopback peers are exempt from it, so a wire test can't trip it).
  class FixedRate
    def initialize(delay)
      @delay = delay
    end

    def delay(_ip) = @delay
  end

  def test_tarpitted_connection_is_marked_live_and_in_history
    store = RecordingStore.new
    server, spec = build_server(store: store)
    server.instance_variable_set(:@rate, FixedRate.new(0.2))
    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))
    eventually(5, "connection not registered") { server.connections.size == 1 }
    assert_in_delta 0.2, server.connections.first[:tarpit]

    client.write("a1 LOGOUT\r\n")
    eventually(5, "close not reported") { store.closed.size == 1 }

    assert_in_delta 0.2, store.closed.first[:tarpit_seconds]
  end

  def test_lockouts_snapshots_the_auth_throttle
    server, _spec = build_server

    assert_empty server.lockouts

    limit = server.send(:auth_lockout_failures)
    limit.times { server.send(:record_auth_failure, "203.0.113.5") }
    lockouts = server.lockouts

    assert_equal [ "203.0.113.5" ], lockouts.keys
    assert_operator lockouts["203.0.113.5"], :>, 0
  end

  # Session-level live_info, driven over a real wire but with the session
  # built directly (tls: :implicit so LOGIN is permitted without a
  # handshake, the wire-test convention).
  def test_live_info_tracks_login_select_and_idle
    store = MailOnRails::Imap::Store::Memory.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    @cleanup << -> { listener.close rescue nil }
    session = MailOnRails::ImapServer::Session.new(listener.accept, store, { tls: :implicit }, nil)
    thread = Thread.new { session.run }
    @cleanup << -> { thread.kill }

    assert_match(/\A\* OK /, client.gets("\r\n"))
    assert_equal({ user: nil, state: "pre-auth", tls: true }, session.live_info)

    client.write("a1 LOGIN #{EMAIL} #{PASSWORD}\r\n")
    client.gets("\r\n")

    assert_equal EMAIL, session.live_info[:user]
    assert_equal "authenticated", session.live_info[:state]

    client.write("a2 SELECT INBOX\r\n")
    until (line = client.gets("\r\n")).nil? || line.start_with?("a2 "); end

    assert_equal "SELECT INBOX", session.live_info[:state]

    client.write("a3 IDLE\r\n")

    assert_match(/\A\+ /, client.gets("\r\n"))
    assert_equal "IDLE INBOX", session.live_info[:state]

    client.write("DONE\r\n")

    assert_match(/\Aa3 OK/, client.gets("\r\n"))
    assert_equal "SELECT INBOX", session.live_info[:state]
  end
end

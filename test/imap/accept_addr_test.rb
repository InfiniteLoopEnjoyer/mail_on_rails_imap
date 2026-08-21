# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The accept-time peer address. Production listeners are plain Sockets so
# accept(2)'s own Addrinfo names the peer; that address stays valid even
# for a scanner that resets the connection before the accept thread can
# getpeername it (ENOTCONN) - such connections used to land in the
# history and logs with no IP at all.
class ImapAcceptAddrTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # A memory store that also keeps connection history, standing in for
  # the Rails backend's optional record_closed_connection.
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

  # A production-shaped listener (what build_listener creates), bound to
  # an ephemeral port so the spec can name the port before the server
  # starts accepting.
  def socket_listener
    listener = Socket.new(:INET, :STREAM)
    listener.setsockopt(:SOCKET, :REUSEADDR, true)
    listener.bind(Addrinfo.tcp("127.0.0.1", 0))
    listener.listen(5)
    @cleanup << -> { listener.close rescue nil }
    listener
  end

  def start_server(store, listener)
    spec = { host: "127.0.0.1", port: listener.local_address.ip_port,
             tls: :none, tcp_server: listener }
    server = MailOnRails::ImapServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    server.wait_ready(5)
    [ server, spec ]
  end

  def eventually(timeout = 5, message = "condition not met")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk "#{message} within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
  end

  # The production scenario behind the "?" history rows: a scanner
  # connects and sends an immediate RST (SO_LINGER 0 close), so by the
  # time the accept thread looks, getpeername raises ENOTCONN. Queueing
  # the connection before the server starts makes the race
  # deterministic. accept(2)'s Addrinfo must still name the peer.
  def test_history_names_the_peer_that_reset_before_accept
    store = RecordingStore.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = socket_listener

    scanner = TCPSocket.new("127.0.0.1", listener.local_address.ip_port)
    scanner.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [ 1, 0 ].pack("ii"))
    scanner.close # linger 0: close sends RST instead of FIN
    sleep 0.2     # let the RST land while the connection is still queued

    start_server(store, listener)

    eventually(5, "reset connection not reported") { store.closed.size == 1 }

    assert_equal "127.0.0.1", store.closed.first[:ip]
  end

  # A normal session over a Socket-accepted connection (production
  # listeners yield Socket, not TCPSocket): banner and commands flow,
  # and the registry and history rows carry the accept-time address.
  def test_socket_listener_serves_a_session_and_records_its_ip
    store = RecordingStore.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = socket_listener
    server, spec = start_server(store, listener)

    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }

    assert_match(/\A\* OK /, client.gets("\r\n"))
    eventually(5, "connection not registered") { server.connections.size == 1 }
    assert_equal "127.0.0.1", server.connections.first[:peer_ip]

    client.write("a1 LOGOUT\r\n")
    eventually(5, "close not reported") { store.closed.size == 1 }

    assert_equal "127.0.0.1", store.closed.first[:ip]
    assert_equal "pre-auth", store.closed.first[:state]
  end

  # The default path with no injected listener: build_listener must
  # bind, listen, and serve. Bound to port 0; the real port is read off
  # the listener socket.
  def test_build_listener_binds_and_serves
    store = MailOnRails::Imap::Store::Memory.new
    server = MailOnRails::ImapServer.new(store, [ { host: "127.0.0.1", port: 0, tls: :none } ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { server.shutdown(drain: 0) rescue nil }
    @cleanup << -> { thread.kill }

    assert server.wait_ready(5), "listener did not bind"

    port = server.instance_variable_get(:@listener_sockets).first.local_address.ip_port
    client = TCPSocket.new("127.0.0.1", port)
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }

    assert_match(/\A\* OK /, client.gets("\r\n"))
  end

  # The server seeds sessions with the accept-time address; the session
  # must prefer it over its own getpeername (dead by the time a
  # scanner's session unwinds) and keep the "?" fallback when nothing
  # seeded it. UNIXSocket stands in for a socket whose peer address
  # yields no IP.
  def test_session_prefers_seeded_address_over_getpeername
    store = MailOnRails::Imap::Store::Memory.new
    sock, other = UNIXSocket.pair
    @cleanup << -> { sock.close rescue nil }
    @cleanup << -> { other.close rescue nil }

    unseeded = MailOnRails::ImapServer::Session.new(sock, store, { tls: :none }, nil)

    assert_equal "?", unseeded.send(:peer_ip)

    seeded = MailOnRails::ImapServer::Session.new(sock, store, { tls: :none }, nil)
    seeded.peer_ip = "203.0.113.9"

    assert_equal "203.0.113.9", seeded.send(:peer_ip)
  end
end

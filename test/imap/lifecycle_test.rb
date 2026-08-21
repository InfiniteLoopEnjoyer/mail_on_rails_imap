# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Readiness and graceful shutdown: the host process (Puma) must be able to
# wait for bound listeners before reporting healthy, and to stop the
# server without stranding threads - polite sessions get a drain window,
# stragglers are force-closed and unwind through their ensure paths.
class LifecycleTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_server
    store = MailOnRails::Imap::Store::Memory.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :none, tcp_server: listener }
    server = MailOnRails::ImapServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    [ server, spec ]
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def test_wait_ready_then_serve_then_shutdown_refuses_new_connections
    server, spec = build_server

    assert server.wait_ready(5), "listeners must bind promptly"
    assert_predicate server, :ready?
    assert_match(/\A\* OK /, connect(spec).gets("\r\n"))

    server.shutdown(drain: 1)

    refute_predicate server, :ready?
    assert_raises(Errno::ECONNREFUSED) { TCPSocket.new("127.0.0.1", spec[:port]) }
  end

  def test_healthy_goes_false_when_a_listener_dies
    server, spec = build_server
    assert server.wait_ready(5)
    assert_predicate server, :healthy?

    spec[:tcp_server].close # the accept loop dies on the closed socket

    deadline = Time.now + 5
    sleep 0.02 while server.healthy? && Time.now < deadline
    refute_predicate server, :healthy?
    # ready? cannot see a dead listener (bound count never decrements) -
    # that gap is exactly why healthy? exists and what the monitor probes.
    assert_predicate server, :ready?
  end

  def test_shutdown_returns_as_soon_as_sessions_finish
    server, spec = build_server
    server.wait_ready(5)

    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))

    finisher = Thread.new do
      sleep 0.2
      client.write("a1 LOGOUT\r\n")
    end
    @cleanup << -> { finisher.kill }

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    server.shutdown(drain: 10)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_operator elapsed, :<, 5, "shutdown must not wait out the full drain once sessions are gone"
    finisher.join(2)
  end

  def test_shutdown_force_closes_idle_stragglers
    server, spec = build_server
    server.wait_ready(5)

    idler = connect(spec)

    assert_match(/\A\* OK /, idler.gets("\r\n"))

    server.shutdown(drain: 0.3)

    assert_nil idler.gets("\r\n"), "an idle session must be closed once the drain window lapses"
  end

  def test_wait_ready_times_out_when_a_listener_cannot_bind
    # Two specs on the same pre-bound port: the second listener dies
    # binding, so readiness must never be reached.
    holder = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { holder.close rescue nil }
    port = holder.addr[1]
    store = MailOnRails::Imap::Store::Memory.new
    server = MailOnRails::ImapServer.new(store, [ { host: "127.0.0.1", port: port, tls: :none } ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }

    refute server.wait_ready(0.5)
    refute_predicate server, :ready?
  end
end

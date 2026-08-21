# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The denylist as a client experiences it: the full server stack booted on
# loopback (worker_pool_test's seam), with the bans seeded through the
# memory store's ban_ip seam. A banned peer gets a bare close before any
# greeting; everyone else gets the normal banner.
class DenylistWireTest < Minitest::Test
  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def start_server(banned: [])
    store = MailOnRails::Imap::Store::Memory.new
    banned.each { |cidr| store.ban_ip(cidr) }
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :none, tcp_server: listener }
    thread = Thread.new { MailOnRails::ImapServer.run(store, [ spec ], nil) }
    @cleanup << -> { thread.kill }
    spec
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  test "a banned peer is closed without a greeting" do
    spec = start_server(banned: %w[127.0.0.1])

    assert_nil connect(spec).gets("\r\n"), "expected EOF before any greeting"
  end

  test "a banned range covering the peer is enough" do
    spec = start_server(banned: %w[127.0.0.0/8])

    assert_nil connect(spec).gets("\r\n")
  end

  test "an empty denylist serves the normal greeting" do
    spec = start_server

    greeting = connect(spec).gets("\r\n")
    assert_match(/\A\* OK/, greeting.to_s)
  end
end

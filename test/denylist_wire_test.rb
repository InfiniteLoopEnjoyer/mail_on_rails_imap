# frozen_string_literal: true

require "test_helper"
require "socket"
require "tmpdir"
require "fileutils"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The denylist as a client experiences it: the full server stack booted on
# loopback (worker_pool_test's seam), with MAIL_ON_RAILS_IMAP_DENYLIST_FILE
# pointing at a scratch file. A banned peer gets a bare close before any
# greeting; everyone else gets the normal banner.
class DenylistWireTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @path = File.join(@dir, "banned_ips")
    ENV["MAIL_ON_RAILS_IMAP_DENYLIST_FILE"] = @path
    @cleanup = []
  end

  def teardown
    ENV.delete("MAIL_ON_RAILS_IMAP_DENYLIST_FILE")
    @cleanup.each { |c| c.call rescue nil }
    FileUtils.remove_entry(@dir)
  end

  def start_server
    store = MailOnRails::Imap::Store::Memory.new
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :none, tcp_server: listener }
    thread = Thread.new { MailOnRails::ImapServer.run(store, [ spec ], nil, workers: 1) }
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
    File.write(@path, "127.0.0.1\n")
    spec = start_server

    assert_nil connect(spec).gets("\r\n"), "expected EOF before any greeting"
  end

  test "a banned range covering the peer is enough" do
    File.write(@path, "127.0.0.0/8\n")
    spec = start_server

    assert_nil connect(spec).gets("\r\n")
  end

  test "an empty denylist serves the normal greeting" do
    File.write(@path, "")
    spec = start_server

    greeting = connect(spec).gets("\r\n")
    assert_match(/\A\* OK/, greeting.to_s)
  end

  test "a missing denylist file serves the normal greeting" do
    spec = start_server

    greeting = connect(spec).gets("\r\n")
    assert_match(/\A\* OK/, greeting.to_s)
  end
end

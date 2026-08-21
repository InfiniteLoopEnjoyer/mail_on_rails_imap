# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The MailOnRails.on_connection_activity seam: the server tells the host
# whenever the live-connection picture changes (session registered,
# session ended, IP locked out) so a dashboard can push an update instead
# of polling. Since the picture is projected to the database by the
# server's Netserv::OpsSync tick, the hook fires from that tick - once per
# changed picture, after the rows are written - so the servers here pin a
# fast tick. This suite is Rails-free, so the module attribute the Rails
# glue normally defines is stood up on the singleton here - which also
# pins the respond_to? guard the server resolves the hook through.
class ConnectionActivityTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # Every guard permissive: these tests are about lifecycle, not limits.
  class QuietServer < MailOnRails::ImapServer
    MAX_CONNECTIONS = 8
    MAX_CONNECTIONS_PER_IP = 0
    AUTH_LOCKOUT_FAILURES = 0
    CONN_RATE_LIMIT = 0
    OPS_SYNC_INTERVAL = 0.05
  end

  # Lockout on the second failed auth, so one connection can produce a
  # registered -> locked -> ended event sequence.
  class LockoutServer < MailOnRails::ImapServer
    MAX_CONNECTIONS = 8
    MAX_CONNECTIONS_PER_IP = 0
    AUTH_LOCKOUT_FAILURES = 2
    AUTH_LOCKOUT_SECONDS = 900
    CONN_RATE_LIMIT = 0
    OPS_SYNC_INTERVAL = 0.05
  end

  def setup
    @cleanup = []
    unless MailOnRails.respond_to?(:on_connection_activity)
      MailOnRails.singleton_class.attr_accessor :on_connection_activity
    end
    @events = Queue.new
    MailOnRails.on_connection_activity = ->(protocol) { @events << protocol }
  end

  def teardown
    MailOnRails.on_connection_activity = nil
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_store
    store = MailOnRails::Imap::Store::Memory.new(max_account_failures: 1000, max_ip_failures: 1000)
    store.add_account(email: EMAIL, password: PASSWORD)
    store
  end

  def start_server(server_class, tls: :none)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: tls, tcp_server: listener }
    material = tls == :implicit ? self.class.tls_material : nil
    thread = Thread.new { server_class.run(build_store, [ spec ], material) }
    @cleanup << -> { thread.kill }
    spec
  end

  def self.tls_material
    @tls_material ||= MailOnRails::Netserv::Tls.generate_self_signed
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def connect_tls(spec)
    raw = connect(spec)
    ssl = OpenSSL::SSL::SSLSocket.new(raw)
    ssl.sync_close = true
    ssl.connect
    @cleanup << -> { ssl.close rescue nil }
    assert_match(/\A\* OK/, ssl.gets("\r\n").to_s)
    ssl
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

  def next_event
    @events.pop(timeout: 5)
  end

  test "a connection's arrival and departure both notify the hook" do
    spec = start_server(QuietServer)

    client = connect(spec)
    assert_match(/\A\* OK/, client.gets("\r\n").to_s)
    assert_equal :imap, next_event, "registration notifies"

    client.write("x1 LOGOUT\r\n")
    read_until_tagged(client, "x1")
    client.close
    assert_equal :imap, next_event, "teardown notifies"
  end

  test "locking an IP out notifies between the arrival and departure events" do
    spec = start_server(LockoutServer, tls: :implicit)

    client = connect_tls(spec)
    assert_equal :imap, next_event

    client.write("f1 LOGIN #{EMAIL} wrong-1\r\n")
    read_until_tagged(client, "f1")
    sleep 0.2 # a couple of ticks
    assert @events.empty?, "a failure below the limit is not an event"

    client.write("f2 LOGIN #{EMAIL} wrong-2\r\n")
    read_until_tagged(client, "f2")
    assert_equal :imap, next_event, "crossing the lockout limit notifies"

    client.close
    assert_equal :imap, next_event
  end

  test "a raising hook never disturbs the session" do
    MailOnRails.on_connection_activity = ->(_protocol) { raise "boom" }
    spec = start_server(QuietServer)

    client = connect(spec)
    assert_match(/\A\* OK/, client.gets("\r\n").to_s, "greeting still arrives")
    client.write("x1 LOGOUT\r\n")
    assert_match(/x1 OK/, read_until_tagged(client, "x1"), "session still serves commands")
  end

  test "no hook set is a no-op" do
    MailOnRails.on_connection_activity = nil
    spec = start_server(QuietServer)

    client = connect(spec)
    assert_match(/\A\* OK/, client.gets("\r\n").to_s)
    client.write("x1 LOGOUT\r\n")
    assert_match(/x1 OK/, read_until_tagged(client, "x1"))
  end
end

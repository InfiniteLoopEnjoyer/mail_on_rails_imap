# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The accept-side per-IP protections as a client experiences them: the
# full server stack booted on loopback with tight caps, driven over real
# sockets. These are the protections the old IMAP listener fork was
# missing entirely (the SMTP server had them first); the unit behavior of
# the shared classes lives in test/vendored/smtp/{conn_limiter,
# auth_throttle,rate_limiter}_test.rb.
#
# Each scenario subclasses ImapServer with small literal caps - the base
# reads them via self.class::CONST - so a test states its limits instead
# of looping through the production defaults.
class AcceptHardeningTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # One concurrent connection per IP; everything else off.
  class PerIpCapServer < MailOnRails::ImapServer
    MAX_CONNECTIONS = 8
    MAX_CONNECTIONS_PER_IP = 1
    AUTH_LOCKOUT_FAILURES = 0
    CONN_RATE_LIMIT = 0
  end

  # Lockout after two failed auths; per-IP connection cap off so the
  # lockout is what a refused connection proves.
  class LockoutServer < MailOnRails::ImapServer
    MAX_CONNECTIONS = 8
    MAX_CONNECTIONS_PER_IP = 0
    AUTH_LOCKOUT_FAILURES = 2
    AUTH_LOCKOUT_SECONDS = 900
    CONN_RATE_LIMIT = 0
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_store(max_account_failures: 1000)
    store = MailOnRails::Imap::Store::Memory.new(
      max_account_failures: max_account_failures, max_ip_failures: 1000
    )
    store.add_account(email: EMAIL, password: PASSWORD)
    store
  end

  # tls: :implicit (with generated self-signed material) when a test needs
  # to LOGIN - credentials are refused on a plaintext channel
  # ([PRIVACYREQUIRED]) - and tls: :none where greetings are enough.
  def start_server(server_class, store: build_store, tls: :none)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: tls, tcp_server: listener }
    material = tls == :implicit ? self.class.tls_material : nil
    thread = Thread.new { server_class.run(store, [ spec ], material) }
    @cleanup << -> { thread.kill }
    spec
  end

  # Generating a keypair is slow enough to share across the suite.
  def self.tls_material
    @tls_material ||= MailOnRails::Netserv::Tls.generate_self_signed
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  # Client side of the implicit-TLS listener; the greeting the server sent
  # is left in @last_greeting. Accept-side refusals (busy, locked) are
  # written to the raw socket before any handshake, so those are read with
  # plain #connect instead.
  def connect_tls(spec)
    raw = connect(spec)
    ssl = OpenSSL::SSL::SSLSocket.new(raw)
    ssl.sync_close = true
    ssl.connect
    @cleanup << -> { ssl.close rescue nil }
    @last_greeting = ssl.gets("\r\n").to_s
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

  def login(client, tag, password: PASSWORD)
    client.write("#{tag} LOGIN #{EMAIL} #{password}\r\n")
    read_until_tagged(client, tag)
  end

  # -- per-IP connection cap -------------------------------------------------

  test "a second concurrent connection from the same IP is refused busy" do
    spec = start_server(PerIpCapServer)

    first = connect(spec)
    assert_match(/\A\* OK/, first.gets("\r\n").to_s, "first connection gets the greeting")

    second = connect(spec)
    assert_match(/\A\* BYE Too many connections/, second.gets("\r\n").to_s)
    assert_nil second.gets("\r\n"), "refused connection is closed"
  end

  test "closing a connection frees its per-IP slot" do
    spec = start_server(PerIpCapServer)

    first = connect(spec)
    first.gets("\r\n")
    first.write("x1 LOGOUT\r\n")
    read_until_tagged(first, "x1")
    first.close

    # The slot is released in the connection thread's ensure; give it a
    # moment rather than racing it.
    greeting = nil
    10.times do
      greeting = connect(spec).gets("\r\n").to_s
      break if greeting.start_with?("* OK")

      sleep 0.05
    end
    assert_match(/\A\* OK/, greeting)
  end

  # -- accept-side auth lockout ----------------------------------------------

  test "failed logins across connections lock the IP out before the greeting" do
    spec = start_server(LockoutServer, tls: :implicit)

    # Two failures on two separate connections: the accounting has to
    # survive the reconnect, which is exactly what the per-connection
    # MAX_AUTH_ATTEMPTS cap cannot do.
    2.times do |i|
      client = connect_tls(spec)
      assert_match(/NO \[AUTHENTICATIONFAILED\]/, login(client, "f#{i}", password: "wrong"))
      client.close
    end

    refused = connect(spec)
    assert_match(/\A\* BYE Too many failed authentication attempts/, refused.gets("\r\n").to_s,
                 "locked-out IP is refused before any TLS handshake or greeting")
    assert_nil refused.gets("\r\n"), "refused connection is closed"
  end

  test "store-throttled attempts do not count toward the accept-side lockout" do
    # The store blocks the account after one failure; the accept-side
    # lockout needs two. The store-throttled UNAVAILABLE refusals that
    # follow the first failure never checked credentials, so they must
    # not push the accept-side count over its limit.
    spec = start_server(LockoutServer, store: build_store(max_account_failures: 1), tls: :implicit)

    client = connect_tls(spec)
    assert_match(/NO \[AUTHENTICATIONFAILED\]/, login(client, "f0", password: "wrong"))
    assert_match(/NO \[UNAVAILABLE\]/, login(client, "t0", password: "wrong"))
    assert_match(/NO \[UNAVAILABLE\]/, login(client, "t1", password: "wrong"))
    client.close

    connect_tls(spec)
    assert_match(/\A\* OK/, @last_greeting,
                 "one real failure plus throttled refusals must not trip the two-failure lockout")
  end
end

# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The session's on_auth_failure probe - the seam the accept-side per-IP
# lockout hangs off (Netserv::Server wires it to AuthThrottle#record).
# Contract: it fires once per adjudicated failed LOGIN/AUTHENTICATE
# attempt, including SCRAM proofs rejected in the daemon, and never for
# outcomes where the credentials were not checked (store throttled).
class OnAuthFailureTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new(max_account_failures: 1000, max_ip_failures: 1000)
    @store.add_account(email: EMAIL, password: PASSWORD)
    @fired = Queue.new
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def fired_count
    @fired.size
  end

  def listener
    @listener ||= begin
      server = TCPServer.new("127.0.0.1", 0)
      @cleanup << -> { server.close }
      acceptor = Thread.new do
        loop do
          sock = server.accept
          Thread.new do
            session = MailOnRails::ImapServer::Session.new(sock, @store, { tls: :implicit }, nil)
            session.on_auth_failure = -> { @fired << :fired }
            session.run
          end
        end
      rescue IOError, SystemCallError
        nil
      end
      @cleanup << -> { acceptor.kill }
      server
    end
  end

  def connect
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    client.timeout = 5
    @cleanup << -> { client.close }
    client.gets("\r\n") # greeting
    client
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

  test "a failed LOGIN fires the probe once" do
    client = connect
    assert_match(/NO \[AUTHENTICATIONFAILED\]/, login(client, "x1", password: "wrong"))
    assert_equal 1, fired_count
  end

  test "a successful LOGIN does not fire the probe" do
    client = connect
    assert_match(/\Ax1 OK/, login(client, "x1"))
    assert_equal 0, fired_count
  end

  test "a rejected SCRAM proof fires the probe" do
    client = connect
    initial = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")
    client.write("x1 AUTHENTICATE SCRAM-SHA-256 #{initial}\r\n")
    line = client.gets("\r\n")
    assert line.to_s.start_with?("+ "), "expected the server-first continuation"

    server_first = line[2..].chomp("\r\n").unpack1("m0")
    nonce = server_first.split(",").find { |p| p.start_with?("r=") }[2..]
    bogus = [ "c=#{[ "n,," ].pack("m0")},r=#{nonce},p=#{[ "\x00" * 32 ].pack("m0")}" ].pack("m0")
    client.write("#{bogus}\r\n")
    assert_match(/NO \[AUTHENTICATIONFAILED\]/, read_until_tagged(client, "x1"))
    assert_equal 1, fired_count
  end

  test "store-throttled attempts do not fire the probe" do
    @store = MailOnRails::Imap::Store::Memory.new(max_account_failures: 1, max_ip_failures: 1000)
    @store.add_account(email: EMAIL, password: PASSWORD)

    client = connect
    assert_match(/NO \[AUTHENTICATIONFAILED\]/, login(client, "f0", password: "wrong"))
    assert_equal 1, fired_count

    assert_match(/NO \[UNAVAILABLE\]/, login(client, "t0", password: "wrong"))
    assert_equal 1, fired_count, "an unadjudicated attempt must not count"
  end
end

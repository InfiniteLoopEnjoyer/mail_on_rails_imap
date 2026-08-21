# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The session-side per-IP lockout re-check (auth_locked): the accept-side
# lockout only refuses NEW connections, so a session opened before the IP
# locked must be cut off too - LOGIN, PLAIN and SCRAM alike, and for
# SCRAM before the store credential lookup the throttle never sees.
class LockoutRecheckTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new(max_account_failures: 1000, max_ip_failures: 1000)
    @store.add_account(email: EMAIL, password: PASSWORD)
    @locked = false
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # Sessions driven directly (the on_auth_failure_test pattern), with
  # auth_locked wired to a flag the test flips mid-session - exactly what
  # Netserv::Server wires to AuthThrottle#locked?.
  def listener
    @listener ||= begin
      server = TCPServer.new("127.0.0.1", 0)
      @cleanup << -> { server.close }
      acceptor = Thread.new do
        loop do
          sock = server.accept
          Thread.new do
            session = MailOnRails::ImapServer::Session.new(sock, @store, { tls: :implicit }, nil)
            session.auth_locked = -> { @locked }
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
    @cleanup << -> { client.close rescue nil }
    assert_match(/\A\* OK/, client.gets("\r\n"))
    client
  end

  def command(client, line)
    client.write("#{line}\r\n")
    tag = line.split(" ", 2).first
    lines = []
    while (reply = client.gets("\r\n"))
      lines << reply
      break if reply.start_with?("#{tag} ")
    end
    lines.join
  end

  test "LOGIN with correct credentials is refused while the IP is locked" do
    client = connect

    @locked = true

    # UNAVAILABLE, not AUTHENTICATIONFAILED: the password was never
    # checked (it is the right one), so the client must not re-prompt.
    assert_match(/\ANO \[UNAVAILABLE\]/, command(client, "a1 LOGIN #{EMAIL} #{PASSWORD}").sub(/\Aa1 /, ""))
  end

  test "the lockout lifting mid-session restores service" do
    client = connect

    @locked = true

    assert_match(/NO \[UNAVAILABLE\]/, command(client, "a1 LOGIN #{EMAIL} #{PASSWORD}"))

    @locked = false

    assert_match(/\Aa2 OK/, command(client, "a2 LOGIN #{EMAIL} #{PASSWORD}"))
  end

  test "locked refusals burn per-connection attempts and hang up" do
    client = connect

    @locked = true
    command(client, "a1 LOGIN #{EMAIL} #{PASSWORD}")
    command(client, "a2 LOGIN #{EMAIL} #{PASSWORD}")
    final = command(client, "a3 LOGIN #{EMAIL} #{PASSWORD}")

    assert_match(/NO \[UNAVAILABLE\]/, final)
    # The BYE follows the tagged refusal, then the connection drops.
    assert_match(/\A\* BYE/, client.gets("\r\n").to_s)
    assert_nil client.gets("\r\n"), "connection must be closed after the attempt cap"
  end

  test "SCRAM is refused before the store credential lookup" do
    @store.define_singleton_method(:scram_credentials) do |*, **|
      raise "scram_credentials must not be consulted while the IP is locked"
    end
    client = connect

    @locked = true
    client_first = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")

    assert_match(/NO \[UNAVAILABLE\]/, command(client, "a1 AUTHENTICATE SCRAM-SHA-256 #{client_first}"))
  end
end

# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Brute-force throttling as a client experiences it.
#
# MAX_AUTH_ATTEMPTS caps failures on one connection, which does nothing
# about an attacker who hangs up and dials again - so the guarantee that
# actually matters is enforced by the store and can only be observed across
# connections. That is what this suite drives: fresh TCP sessions, one
# after another, until the store stops answering credential checks at all.
class AuthThrottleWireTest < Minitest::Test
  EMAIL = "user@example.test"
  OTHER = "other@example.test"
  PASSWORD = "pw-123456"

  # Small limits so the suite states its intent instead of looping twenty
  # times. The ip limit is left high where a test is about the account
  # scope, so the two can't be confused for each other.
  def build_store(max_account_failures: 5, max_ip_failures: 1000)
    store = MailOnRails::Imap::Store::Memory.new(
      max_account_failures: max_account_failures, max_ip_failures: max_ip_failures
    )
    store.add_account(email: EMAIL, password: PASSWORD)
    store.add_account(email: OTHER, password: PASSWORD)
    store
  end

  def setup
    @store = build_store
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def listener
    @listener ||= begin
      server = TCPServer.new("127.0.0.1", 0)
      @cleanup << -> { server.close }
      acceptor = Thread.new do
        loop do
          sock = server.accept
          Thread.new { MailOnRails::ImapServer::Session.new(sock, @store, { tls: :implicit }, nil).run }
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

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_until_tagged(client, tag)
  end

  def login(client, tag, email: EMAIL, password: PASSWORD)
    command(client, tag, "LOGIN #{email} #{password}")
  end

  # Burns +count+ failed logins, opening a fresh connection every
  # MAX_AUTH_ATTEMPTS because the server hangs up at that point. Returns
  # the last reply.
  def burn_failures(count, email: EMAIL)
    cap = MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS
    reply = nil
    client = nil
    count.times do |i|
      client = connect if (i % cap).zero?
      reply = login(client, "f#{i}", email: email, password: "wrong-password")
    end
    reply
  end

  # -- the reconnect bypass --------------------------------------------------

  test "failures below the limit still authenticate normally" do
    burn_failures(4)
    assert_match(/\Ax1 OK/, login(connect, "x1"))
  end

  # The per-connection cap is three, so reaching the store's limit of five
  # takes two connections. Each of those five is adjudicated normally - the
  # fifth is what trips the block - and the *next* connection is the one
  # that finds the door shut. That last step is the reconnect bypass being
  # closed; without the store's counter it would authenticate as usual.
  test "failures across separate connections accumulate and throttle" do
    assert_match(/\Af4 NO \[AUTHENTICATIONFAILED\]/, burn_failures(5))
    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, login(connect, "x1", password: "wrong-password"))
  end

  # The response code matters as much as the refusal: a client told
  # AUTHENTICATIONFAILED asks the user to retype a password that is very
  # likely correct, and iOS in particular will not stop asking.
  test "a throttled login is unavailable, not authenticationfailed" do
    burn_failures(5)
    reply = login(connect, "x1")
    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, reply)
    refute_match(/AUTHENTICATIONFAILED/, reply)
  end

  test "the correct password is refused while throttled" do
    burn_failures(5)
    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, login(connect, "x1", password: PASSWORD))
  end

  test "a throttled session cannot reach any mailbox" do
    burn_failures(5)
    client = connect
    login(client, "x1")
    assert_match(/\Ax2 NO Not authenticated/, command(client, "x2", "SELECT INBOX"))
  end

  # -- scope isolation -------------------------------------------------------

  test "throttling one account leaves another account usable" do
    burn_failures(5, email: EMAIL)
    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, login(connect, "x1", email: EMAIL))
    assert_match(/\Ax2 OK/, login(connect, "x2", email: OTHER))
  end

  # The address scope is what stops an attacker spraying many accounts from
  # one host: no single account ever reaches its own limit, but the source
  # does.
  test "spraying many accounts from one address trips the ip scope" do
    @store = build_store(max_account_failures: 1000, max_ip_failures: 5)
    cap = MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS
    client = nil
    reply = nil
    5.times do |i|
      client = connect if (i % cap).zero?
      reply = login(client, "s#{i}", email: "victim#{i}@example.test", password: "wrong")
    end
    # No single account came close to its own limit...
    assert_match(/\As4 NO \[AUTHENTICATIONFAILED\]/, reply)

    # ...but the source address did, so even a real account with a real
    # password is refused from here.
    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, login(connect, "x1"))
  end

  # -- connection handling ---------------------------------------------------

  # A throttled attempt still burns a per-connection attempt, so a client
  # that ignores the refusal is disconnected instead of being allowed to
  # spin on a cheap endpoint forever.
  test "throttled attempts count toward the per-connection cap" do
    burn_failures(5)
    client = connect
    (MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS - 1).times do |i|
      assert_match(/\At#{i} NO \[UNAVAILABLE\]/, login(client, "t#{i}"))
    end

    last = login(client, "tlast")
    assert_match(/\Atlast NO \[UNAVAILABLE\]/, last)

    rest = +""
    begin
      rest << client.gets("\r\n").to_s while !client.eof?
    rescue IOError, SystemCallError
      nil
    end
    assert_match(/\* BYE Too many failed authentication attempts/, rest)
  end

  # -- SCRAM -----------------------------------------------------------------

  # SCRAM verifies the proof in the daemon, so its failures only reach the
  # store because the session reports them. Without that this path would be
  # an unthrottled way around the LOGIN throttle.
  test "bad scram proofs feed the same counter as failed logins" do
    cap = MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS
    client = nil
    5.times do |i|
      client = connect if (i % cap).zero?
      scram_attempt(client, "s#{i}")
    end

    # The LOGIN path now sees the block SCRAM's failures created.
    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, login(connect, "x1"))
  end

  test "scram is refused while throttled and hands out no verifier material" do
    burn_failures(5)
    client = connect
    initial = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")
    reply = command(client, "x1", "AUTHENTICATE SCRAM-SHA-256 #{initial}")

    assert_match(/\Ax1 NO \[UNAVAILABLE\]/, reply)
    # No continuation, so no salt and no iteration count went out.
    refute_match(/\A\+ /, reply)
  end

  # One SCRAM exchange with a proof that cannot verify.
  def scram_attempt(client, tag)
    initial = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")
    client.write("#{tag} AUTHENTICATE SCRAM-SHA-256 #{initial}\r\n")
    line = client.gets("\r\n")
    return line unless line.to_s.start_with?("+ ")

    server_first = line[2..].chomp("\r\n").unpack1("m0")
    nonce = server_first.split(",").find { |p| p.start_with?("r=") }[2..]
    bogus = [ "c=#{[ "n,," ].pack("m0")},r=#{nonce},p=#{[ "\x00" * 32 ].pack("m0")}" ].pack("m0")
    client.write("#{bogus}\r\n")
    read_until_tagged(client, tag)
  end
end

# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "timeout"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# H2 (audit 2026-11-17): the command-line cap has to hold on TLS.
#
# IO#gets(eol, limit) on a TCP socket stops at the limit;
# OpenSSL::Buffering#gets reads until the terminator shows up and only
# then applies it. On 993, or after STARTTLS on 143, a peer streaming
# bytes with no CRLF therefore grew the session's buffer without bound,
# re-scanned in full after every record - no login needed, and the read
# timeout never fires while data keeps coming.
#
# Every other wire suite runs sessions on plain loopback sockets, where
# the bug cannot show; these run through a real TLS handshake.
class TlsLineLimitTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  Server = MailOnRails::ImapServer

  def self.tls_context
    @tls_context ||= MailOnRails::Netserv::Tls.context(MailOnRails::Netserv::Tls.generate_self_signed)
  end

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def tls_client(socket)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    tls.sync_close = true
    tls.connect
    tls
  end

  # A session on an implicit-TLS listener, as Netserv::Server builds one:
  # the handshake is done before the session sees the socket.
  def implicit_tls_session(spec: {})
    server = TCPServer.new("127.0.0.1", 0)
    raw = TCPSocket.new("127.0.0.1", server.addr[1])
    raw.timeout = 10
    accepted = server.accept
    @thread = Thread.new do
      socket = MailOnRails::Netserv::Tls.accept(accepted, self.class.tls_context)
      @session = Server::Session.new(socket, @store, { tls: :implicit }.merge(spec), self.class.tls_context)
      @session.run
    end
    client = tls_client(raw)
    @cleanup << -> { client.close }
    @cleanup << -> { @thread.join(5) }
    @cleanup << -> { server.close }
    client
  end

  def starttls_session
    server = TCPServer.new("127.0.0.1", 0)
    raw = TCPSocket.new("127.0.0.1", server.addr[1])
    raw.timeout = 10
    accepted = server.accept
    @session = Server::Session.new(accepted, @store, { tls: :starttls }, self.class.tls_context)
    @thread = Thread.new { @session.run }
    @cleanup << -> { raw.close }
    @cleanup << -> { @thread.join(5) }
    @cleanup << -> { server.close }
    raw.gets("\r\n") # greeting
    raw.write("s1 STARTTLS\r\n")
    assert_match(/\As1 OK/, raw.gets("\r\n"))
    tls_client(raw)
  end

  def read_until_tagged(client, tag)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line.start_with?("#{tag} ")
    end
    lines.join
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_until_tagged(client, tag)
  end

  # Bytes the session's reader is holding right now.
  def buffered_bytes
    @session.instance_variable_get(:@reader).instance_variable_get(:@buffer).bytesize
  end

  # Streams +megabytes+ of "A" with no CRLF, watching the reader's buffer
  # from the side. Returns [what the server said, the largest buffer seen].
  def flood(client, megabytes)
    peak = 0
    watcher = Thread.new do
      loop do
        peak = [ peak, buffered_bytes ].max
        sleep 0.001
      end
    end
    chunk = "A" * 65_536
    begin
      (megabytes * 16).times { client.write(chunk) }
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil # the server hung up mid-flood, as it should
    end
    reply = begin
      Timeout.timeout(10) { client.gets("\r\n") }
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end
    @thread.join(10)
    [ reply, peak ]
  ensure
    watcher&.kill
  end

  def allowed_buffer(limit) = limit + MailOnRails::Netserv::BoundedReader::BLOCK

  test "megabytes with no CRLF on implicit TLS take the too-long path with a bounded buffer" do
    client = implicit_tls_session
    assert_match(/\A\* OK/, client.gets("\r\n"))

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    reply, peak = flood(client, 8)

    assert_equal "* BAD Command line too long\r\n", reply
    refute @thread.alive?, "the session must end, not keep reading"
    assert_operator peak, :<=, allowed_buffer(Server::MAX_PREAUTH_COMMAND_BYTES)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
    assert_equal "protocol_abuse", @session.send(:capture_reason)
  end

  test "the same after STARTTLS, and for an authenticated session at the full line cap" do
    client = starttls_session
    assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}"))

    reply, peak = flood(client, 8)

    assert_equal "* BAD Command line too long\r\n", reply
    refute @thread.alive?
    assert_operator peak, :<=, allowed_buffer(Server::MAX_LINE)
  end

  # The reader takes TLS input in blocks, so a block can hold more than
  # the line being read. Everything behind that line has to come back out
  # of the reader's buffer - the next command, a literal's octets, and
  # the DONE that IDLE waits for by sleeping on the socket.
  test "pipelined commands and literals in one TLS record are all read" do
    client = implicit_tls_session
    client.gets("\r\n")
    raw = "Subject: over tls\r\n\r\nbody\r\n"

    client.write("a1 LOGIN #{EMAIL} #{PASSWORD}\r\n" \
                 "a2 APPEND INBOX {#{raw.bytesize}+}\r\n#{raw}\r\n" \
                 "a3 SELECT INBOX\r\na4 FETCH 1 (BODY.PEEK[])\r\na5 NOOP\r\n")

    reply = Timeout.timeout(10) { read_until_tagged(client, "a5") }
    assert_match(/^a1 OK/, reply)
    assert_match(/^a2 OK \[APPENDUID/, reply)
    assert_match(/^\* 1 EXISTS/, reply)
    assert_includes reply, "BODY[] {#{raw.bytesize}}\r\n#{raw}"
    assert_match(/^a5 OK/, reply)
  end

  test "IDLE sees a DONE that arrived in the same TLS record as the IDLE" do
    client = implicit_tls_session
    client.gets("\r\n")
    command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}")

    # Were the buffered DONE missed, IDLE would sleep on a socket with
    # nothing more to deliver until its poll interval (30 s by default).
    client.write("a2 IDLE\r\nDONE\r\na3 NOOP\r\n")
    reply = Timeout.timeout(5) { read_until_tagged(client, "a3") }

    assert_match(/^\+ idling/, reply)
    assert_match(/^a2 OK IDLE terminated/, reply)
    assert_match(/^a3 OK/, reply)
  end

  test "a synchronizing literal works across the TLS reader" do
    client = implicit_tls_session
    client.gets("\r\n")
    client.write("a1 LOGIN #{EMAIL} {#{PASSWORD.bytesize}}\r\n")
    assert_match(/\A\+ /, client.gets("\r\n"))
    client.write("#{PASSWORD}\r\na2 NOOP\r\n")

    reply = Timeout.timeout(5) { read_until_tagged(client, "a2") }
    assert_match(/^a1 OK/, reply)
    assert_match(/^a2 OK/, reply)
  end

  # M8: the connect-to-auth deadline closes the socket from another
  # thread; that has to unblock a session sitting in a TLS read too.
  test "the pre-auth deadline ends a TLS session that is being trickled a command" do
    client = implicit_tls_session(spec: { preauth_deadline: 0.5, preauth_timeout: 0.4 })
    client.gets("\r\n")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    begin
      40.times do
        client.write("a")
        sleep 0.1
      end
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end
    @thread.join(5)

    refute @thread.alive?
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
    assert_equal "preauth_deadline", @session.send(:capture_reason)
  end
end

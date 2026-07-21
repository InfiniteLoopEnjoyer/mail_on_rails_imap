# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# End-to-end runs of the full server stack - accept threads, worker
# dispatch, fiber-scheduled sessions - over real loopback sockets.
#
# Thread mode (injected Store::Memory) covers the mailbox flow, STARTTLS
# and implicit TLS under the scheduler, fiber concurrency on a single
# worker, and the connection cap. Ractor mode covers the fd handoff,
# per-Ractor store/TLS construction, and the release pipe that frees
# ConnLimiter slots.
class WorkerPoolTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # A store worker Ractors can rebuild (Store::Memory can't cross the
  # boundary, and per-Ractor mailboxes would be invisible to assertions
  # anyway, so Ractor-mode tests assert protocol behavior only).
  class RactorSafeStore
    def self.from_config(_config = {}) = new
    def worker_config = { store_class: self.class }
    def log(_level, _message) = nil
    def authenticate(_email, _password) = { account_id: nil, email: nil }
  end

  # A one-connection server subclass, to exercise cap + release paths.
  class TinyServer < MailOnRails::ImapServer
    MAX_CONNECTIONS = 1
  end

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each(&:call)
  end

  # Boots a server on ephemeral loopback ports (pre-bound listeners via the
  # spec[:tcp_server] seam) and returns the specs with ports filled in.
  def start_server(store, listeners, tls_material: nil, workers: 2, server_class: MailOnRails::ImapServer)
    specs = listeners.map do |tls|
      listener = TCPServer.new("127.0.0.1", 0)
      @cleanup << -> { listener.close rescue nil }
      { host: "127.0.0.1", port: listener.addr[1], tls: tls, tcp_server: listener }
    end
    thread = Thread.new { server_class.run(store, specs, tls_material, workers: workers) }
    @cleanup << -> { thread.kill }
    specs
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def tls_connect(socket)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(socket, ctx)
    tls.sync_close = true
    tls.connect
    @cleanup << -> { tls.close rescue nil }
    tls
  end

  # Everything up to and including the tagged completion for +tag+.
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

  def memory_store
    store = MailOnRails::Imap::Store::Memory.new
    account_id = store.add_account(email: EMAIL, password: PASSWORD)
    store.append(account_id, "INBOX", RAW, [ "\\Seen" ], nil)
    store
  end

  def tls_material
    @@tls_material ||= MailOnRails::Imap::TLS.generate_self_signed
  end

  # -- thread mode ---------------------------------------------------------

  def test_thread_mode_serves_mailbox_over_implicit_tls_end_to_end
    spec = start_server(memory_store, [ :implicit ], tls_material: tls_material).first
    client = tls_connect(connect(spec))

    assert_match(/\A\* OK \[CAPABILITY IMAP4rev1/, client.gets("\r\n"))
    assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}"))

    select = command(client, "a2", "SELECT INBOX")

    assert_match(/^\* 1 EXISTS/, select)
    assert_match(/\[READ-WRITE\]/, select[/a2 .*/])

    fetch = command(client, "a3", "FETCH 1 (UID FLAGS RFC822.SIZE)")

    assert_match(/UID 1/, fetch)
    assert_match(/RFC822\.SIZE #{RAW.bytesize}/, fetch)

    logout = command(client, "a4", "LOGOUT")

    assert_match(/\A\* BYE/, logout)
    assert_match(/^a4 OK/, logout)
  end

  def test_thread_mode_starttls_then_login_under_the_scheduler
    spec = start_server(memory_store, [ :starttls ], tls_material: tls_material).first
    client = connect(spec)

    assert_match(/STARTTLS/, client.gets("\r\n"))
    assert_match(/\Aa1 OK Begin TLS/, command(client, "a1", "STARTTLS"))

    tls = tls_connect(client)

    assert_match(/\Aa2 OK/, command(tls, "a2", "LOGIN #{EMAIL} #{PASSWORD}"))
    assert_match(/\* 1 EXISTS/, command(tls, "a3", "SELECT INBOX"))
  end

  def test_thread_mode_single_worker_serves_sessions_concurrently
    spec = start_server(memory_store, [ :starttls ], workers: 1).first

    first = connect(spec)
    second = connect(spec)

    assert_match(/\A\* OK /, first.gets("\r\n"))
    assert_match(/\A\* OK /, second.gets("\r\n"))
    # Interleave: only completes if one worker thread multiplexes both.
    2.times do |round|
      assert_match(/\At#{round} OK/, command(first, "t#{round}", "NOOP"))
      assert_match(/\At#{round} OK/, command(second, "t#{round}", "NOOP"))
    end
  end

  def test_thread_mode_connection_cap_and_release
    spec = start_server(memory_store, [ :starttls ], server_class: TinyServer).first

    holder = connect(spec)

    assert_match(/\A\* OK /, holder.gets("\r\n"))

    refused = connect(spec)

    assert_match(/\A\* BYE Too many connections/, refused.gets("\r\n"))

    assert_match(/^a1 OK/, command(holder, "a1", "LOGOUT"))
    assert wait_for_free_slot(spec), "slot was not released after LOGOUT"
  end

  def test_accepted_sockets_get_keepalive_tuning
    server = MailOnRails::ImapServer.new(memory_store, [], nil)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    @cleanup << -> { client.close rescue nil }
    accepted = listener.accept
    @cleanup << -> { accepted.close rescue nil }

    server.send(:tune_keepalive, accepted)

    assert_predicate accepted.getsockopt(:SOCKET, :KEEPALIVE), :bool
    skip "no TCP_KEEP* constants on this platform" unless Socket.const_defined?(:TCP_KEEPIDLE)

    assert_equal MailOnRails::Imap::Server::KEEPALIVE_IDLE, accepted.getsockopt(:TCP, :KEEPIDLE).int
    assert_equal MailOnRails::Imap::Server::KEEPALIVE_INTERVAL, accepted.getsockopt(:TCP, :KEEPINTVL).int
    assert_equal MailOnRails::Imap::Server::KEEPALIVE_PROBES, accepted.getsockopt(:TCP, :KEEPCNT).int
  end

  # -- Ractor mode ---------------------------------------------------------

  def test_ractor_mode_serves_protocol_from_worker_ractors
    spec = start_server(RactorSafeStore.new, [ :implicit ], tls_material: tls_material).first

    2.times do |i| # round-robin across both worker Ractors
      client = tls_connect(connect(spec))

      assert_match(/\A\* OK \[CAPABILITY IMAP4rev1/, client.gets("\r\n"))
      assert_match(/AUTH=PLAIN/, command(client, "c#{i}", "CAPABILITY"))
      # Reaches authenticate on the store rebuilt inside the worker Ractor.
      assert_match(/\Al#{i} NO \[AUTHENTICATIONFAILED\]/, command(client, "l#{i}", "LOGIN nobody wrong"))
      assert_match(/^q#{i} OK/, command(client, "q#{i}", "LOGOUT"))
    end
  end

  def test_ractor_mode_release_pipe_frees_slots
    spec = start_server(RactorSafeStore.new, [ :starttls ], server_class: TinyServer).first

    holder = connect(spec)

    assert_match(/\A\* OK /, holder.gets("\r\n"))

    refused = connect(spec)

    assert_match(/\A\* BYE Too many connections/, refused.gets("\r\n"))

    assert_match(/^a1 OK/, command(holder, "a1", "LOGOUT"))
    assert wait_for_free_slot(spec), "release pipe did not free the slot"
  end

  private

  # LOGOUT's release is asynchronous to the client seeing the tagged OK;
  # poll briefly.
  def wait_for_free_slot(spec)
    20.times do
      client = connect(spec)
      reply = client.gets("\r\n").to_s
      client.close
      return true if reply.start_with?("* OK")

      sleep 0.05
    end
    false
  end
end

# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# What a closing session tells the store about itself for the idle
# accounting (info[:idle], the idle_auto_ban setting): the shape of a
# connection that never tried to log in, and nothing for one that did.
# Driven through the whole server, since the verdict only matters where
# Server#report_closed hands it over.
class ImapIdleReasonTest < Minitest::Test
  TLS = MailOnRails::Netserv::Tls
  EMAIL = "bob@example.test"
  PASSWORD = "correct-horse-battery"

  class RecordingStore < MailOnRails::Imap::Store::Memory
    attr_reader :closed

    def initialize(*)
      super
      @closed = []
    end

    def record_closed_connection(info)
      @closed << info
      {}
    end
  end

  def setup
    @cleanup = []
    @store = RecordingStore.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def tls_material
    @@tls_material ||= TLS.generate_self_signed
  end

  def start_server(tls: :none)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close rescue nil }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: tls, tcp_server: listener }
    @server = MailOnRails::ImapServer.new(@store, [ spec ], tls_material)
    thread = Thread.new { @server.run }
    @cleanup << -> { thread.kill }
    @server.wait_ready(5)
    spec
  end

  def command(client, line)
    tag = line.split(" ", 2).first
    client.write("#{line}\r\n")
    lines = []
    while (reply = client.gets("\r\n"))
      lines << reply
      break if reply.start_with?("#{tag} ", "+ ")
    end
    lines.join
  end

  def upgrade(client)
    assert_match(/\Aa0 OK/, command(client, "a0 STARTTLS"))
    ssl = OpenSSL::SSL::SSLSocket.new(client, OpenSSL::SSL::SSLContext.new)
    ssl.sync_close = true
    ssl.connect
    @cleanup << -> { ssl.close rescue nil }
    ssl
  end

  # Runs one session to its end and returns what the store was told.
  def closed_after(**server_options)
    spec = start_server(**server_options)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client.gets("\r\n") unless spec[:tls] == :implicit
    client = yield(client) || client
    client.close
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    sleep 0.02 while @store.closed.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    assert_equal 1, @store.closed.size, "the close must be reported"
    @store.closed.first
  end

  def test_greeting_grab_is_silent
    assert_equal "silent", closed_after { |_client| nil }[:idle]
  end

  def test_capability_and_logout_is_no_auth
    info = closed_after { |client|
      assert_match(/IMAP4rev1/, command(client, "a1 CAPABILITY"))
      command(client, "a2 LOGOUT")
      nil
    }

    assert_equal "no_auth", info[:idle]
    assert_equal "pre-auth", info[:state]
  end

  def test_certificate_grab_is_no_auth
    info = closed_after(tls: :starttls) { |client|
      ssl = upgrade(client)
      command(ssl, "a2 CAPABILITY")
      ssl
    }

    assert_equal "no_auth", info[:idle]
  end

  def test_a_failed_login_belongs_to_auth_auto_ban
    refute closed_after(tls: :starttls) { |client|
      ssl = upgrade(client)
      assert_match(/\Aa1 NO/, command(ssl, "a1 LOGIN #{EMAIL} wrong-password"))
      ssl
    }.key?(:idle)
  end

  def test_a_login_refused_for_want_of_tls_is_still_an_attempt
    refute closed_after(tls: :starttls) { |client|
      assert_match(/PRIVACYREQUIRED/, command(client, "a1 LOGIN #{EMAIL} #{PASSWORD}"))
      nil
    }.key?(:idle)
  end

  def test_a_login_abandoned_mid_challenge_is_an_attempt
    refute closed_after(tls: :starttls) { |client|
      ssl = upgrade(client)
      assert_match(/\A\+ /, command(ssl, "a1 AUTHENTICATE PLAIN"))
      ssl
    }.key?(:idle)
  end

  def test_a_successful_login_is_not_idle
    info = closed_after(tls: :starttls) { |client|
      ssl = upgrade(client)
      assert_match(/^a1 OK/, command(ssl, "a1 LOGIN #{EMAIL} #{PASSWORD}"))
      command(ssl, "a2 LOGOUT")
      ssl
    }

    assert_equal EMAIL, info[:user]
    refute info.key?(:idle)
  end

  def test_a_honeypot_hit_belongs_to_protocol_auto_ban
    refute closed_after { |client|
      client.write("GET / HTTP/1.1\r\n")
      client.gets("\r\n")
      nil
    }.key?(:idle)
  end

  def test_a_kicked_session_is_not_idle
    info = closed_after { |_client|
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      sleep 0.02 while @server.connections.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      @server.kick { |_ip| true }
      nil
    }

    refute info.key?(:idle)
  end

  def test_plaintext_at_the_implicit_tls_port_is_a_failed_handshake
    info = closed_after(tls: :implicit) { |client|
      client.write("a1 CAPABILITY\r\n")
      nil
    }

    assert_equal "tls_handshake_failed", info[:idle]
  end
end

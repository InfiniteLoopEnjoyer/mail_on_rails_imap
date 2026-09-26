# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The per-account concurrent-session cap: one stolen password worked from
# many addresses (each under the per-IP cap) must not hold unbounded IDLE
# sessions. Policy under test: the cap counts authenticated sessions per
# account across the process; a login over the cap gets NO [LIMIT] and is
# not an authentication failure; the slot is freed when the session ends.
class ImapAccountSessionsTest < Minitest::Test
  EMAIL = "user@example.test"
  OTHER = "other@example.test"
  PASSWORD = "pw-123456"

  def setup
    @cleanup = []
    @store = MailOnRails::Imap::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)
    @store.add_account(email: OTHER, password: PASSWORD)
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # Sessions are built directly on loopback sockets (tls: :implicit marks
  # the channel as already encrypted, so LOGIN is permitted without a real
  # handshake); the cap lives on the Session class, so it is shared by
  # every session in the process exactly as it is under a Server.
  def build_server(max_sessions:)
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    { port: listener.addr[1], listener: listener, tls: :implicit, max_sessions_per_account: max_sessions }
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    session_socket = spec[:listener].accept
    thread = Thread.new { MailOnRails::ImapServer::Session.new(session_socket, @store, spec, nil).run }
    @cleanup << -> { client.close rescue nil }
    @cleanup << -> { thread.join(5) }
    assert_match(/\A\* OK /, client.gets("\r\n"))
    client
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    lines = []
    while (reply = client.gets("\r\n"))
      lines << reply
      break if reply.start_with?("#{tag} ")
    end
    lines.join
  end

  def login(client, tag, email = EMAIL)
    command(client, tag, "LOGIN #{email} #{PASSWORD}")
  end

  def test_second_session_for_the_account_is_refused_until_the_first_ends
    spec = build_server(max_sessions: 1)
    first = connect(spec)
    second = connect(spec)

    assert_match(/\Aa1 OK/, login(first, "a1"))
    assert_match(/\Ab1 NO \[LIMIT\] Too many simultaneous sessions/, login(second, "b1"))
    assert_match(/\Ab2 OK/, login(second, "b2", OTHER), "other accounts are unaffected")

    third = connect(spec)
    assert_match(/\Ac1 NO \[LIMIT\]/, login(third, "c1"))
    command(first, "a2", "LOGOUT")
    sleep 0.05
    assert_match(/\Ac2 OK/, login(third, "c2"), "the slot is freed when the holder logs out")
  end

  def test_a_refusal_is_not_an_authentication_failure
    spec = build_server(max_sessions: 1)
    holder = connect(spec)
    assert_match(/\Aa1 OK/, login(holder, "a1"))

    client = connect(spec)
    # MAX_AUTH_ATTEMPTS failures would drop the connection; refusals are
    # not failures, so the connection survives them and then succeeds.
    (MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS + 1).times do |i|
      assert_match(/\Ab#{i} NO \[LIMIT\]/, login(client, "b#{i}"))
    end
    holder.close
    sleep 0.05
    assert_match(/\Ab9 OK/, login(client, "b9"), "a dropped holder frees its slot")
  end

  def test_the_slot_is_freed_when_the_connection_is_lost
    spec = build_server(max_sessions: 1)
    holder = connect(spec)
    assert_match(/\Aa1 OK/, login(holder, "a1"))
    holder.close
    sleep 0.05

    client = connect(spec)
    assert_match(/\Ab1 OK/, login(client, "b1"))
  end
end

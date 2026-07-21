require "test_helper"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# End-to-end IMAP session over a real loopback socket, backed by the
# contract's reference store - no Rails, no database. The session is
# constructed as an implicit-TLS listener would build it (spec tls:
# :implicit) so LOGIN is permitted on what is, here, a plain test socket.
class ImapSessionTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @store.append(@account_id, "INBOX", RAW, [ "\\Seen" ], nil)
  end

  def with_session
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    thread = Thread.new { MailOnRails::ImapServer::Session.new(session_socket, @store, { tls: :implicit }, nil).run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    server&.close
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

  def test_login_select_fetch_logout_end_to_end
    with_session do |client|
      assert_match(/\A\* OK \[CAPABILITY IMAP4rev1/, client.gets("\r\n"))

      assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}"))

      select = command(client, "a2", "SELECT INBOX")
      assert_match(/^\* 1 EXISTS/, select)
      assert_match(/UIDVALIDITY/, select)
      assert_match(/\[READ-WRITE\]/, select[/a2 .*/])

      fetch = command(client, "a3", "FETCH 1 (UID FLAGS RFC822.SIZE)")
      assert_match(/\A\* 1 FETCH \(/, fetch)
      assert_match(/UID 1/, fetch)
      assert_match(/\\Seen/, fetch)
      assert_match(/RFC822\.SIZE #{RAW.bytesize}/, fetch)
      assert_match(/^a3 OK/, fetch)

      logout = command(client, "a4", "LOGOUT")
      assert_match(/\A\* BYE/, logout)
      assert_match(/^a4 OK/, logout)
    end
  end

  def test_login_is_rejected_with_bad_credentials
    with_session do |client|
      client.gets("\r\n")
      assert_match(/\Aa1 NO/, command(client, "a1", "LOGIN #{EMAIL} wrong-password"))
      assert_match(/\Aa2 BAD Not authenticated|\Aa2 NO/, command(client, "a2", "SELECT INBOX"))
      command(client, "a3", "LOGOUT")
    end
  end

  def test_append_and_expunge_round_trip
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}")
      command(client, "a2", "SELECT INBOX")

      assert_match(/^a3 OK/, command(client, "a3", "STORE 1 +FLAGS (\\Deleted)"))
      expunge = command(client, "a4", "EXPUNGE")
      assert_match(/\A\* 1 EXPUNGE/, expunge)
      assert_match(/^a4 OK/, expunge)

      command(client, "a5", "LOGOUT")
    end

    assert_equal 0, @store.status(@account_id, "INBOX")[:messages]
  end
end

# frozen_string_literal: true

require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Shared wire-level IMAP harness for the RFC compliance audits: a real
# loopback listener backed by the memory store, supporting any number of
# concurrent sessions so cross-session broadcasts can be asserted.
# Include after defining EMAIL/PASSWORD or use the defaults here.
module WireHarness
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @listener = TCPServer.new("127.0.0.1", 0)
    @sessions = []
    @clients = []
    @acceptor = Thread.new do
      loop do
        sock = @listener.accept
        @sessions << Thread.new { MailOnRails::ImapServer::Session.new(sock, @store, { tls: :implicit }, nil).run }
      end
    rescue IOError, SystemCallError
      # listener closed in teardown
    end
  end

  def teardown
    @clients.each { |c| c.close rescue nil }
    @listener.close
    @acceptor.join(2)
    @sessions.each { |t| t.join(5) }
  end

  def connect(login: true)
    client = TCPSocket.new("127.0.0.1", @listener.addr[1])
    @clients << client
    client.gets("\r\n") # greeting
    command(client, "l0", "LOGIN #{EMAIL} #{PASSWORD}") if login
    client
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

  # Appends via the wire (LITERAL+) so the full APPEND path is exercised.
  def append(client, tag, mailbox, raw, flags: nil, date: nil)
    args = [ mailbox ]
    args << "(#{flags.join(" ")})" if flags
    args << %("#{date}") if date
    client.write("#{tag} APPEND #{args.join(" ")} {#{raw.bytesize}+}\r\n#{raw}\r\n")
    read_until_tagged(client, tag)
  end

  def inbox_id
    @store.select_mailbox(@account_id, "INBOX")[:mailbox_id]
  end

  def highest_modseq
    @store.status(@account_id, "INBOX")[:highest_modseq]
  end

  def fetch_modseq(client, tag, seq)
    command(client, tag, "FETCH #{seq} (MODSEQ)")[/MODSEQ \((\d+)\)/, 1].to_i
  end
end

require "test_helper"
require "net/imap"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Drives the server with net-imap - the strictest widely-deployed IMAP
# client parser. Anything malformed in our responses (ENVELOPE shape,
# BODYSTRUCTURE line counts, resp-text codes, literals) raises in the
# client instead of silently corrupting a real mailbox view.
class NetImapClientTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = <<~MSG.gsub("\n", "\r\n")
    From: Amy Sender <amy@remote.test>
    To: user@example.test
    Subject: greetings
    Date: Tue, 15 Jul 2025 10:00:00 +0000
    Message-Id: <m1@remote.test>
    Content-Type: multipart/alternative; boundary=b

    --b
    Content-Type: text/plain

    plain body
    --b
    Content-Type: text/html

    <p>html body</p>
    --b--
  MSG

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @store.append(@account_id, "INBOX", RAW, [], nil)
  end

  def with_client
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      socket = server.accept
      MailOnRails::ImapServer::Session.new(socket, @store, { tls: :implicit }, nil).run
    end
    imap = Net::IMAP.new("127.0.0.1", port: server.addr[1])
    yield imap
  ensure
    begin
      imap&.logout
    rescue StandardError
      nil
    end
    imap&.disconnect
    thread&.join(5)
    server&.close
  end

  def test_full_session_parses_cleanly
    with_client do |imap|
      assert imap.capable?("IDLE")
      assert imap.capable?("MOVE")
      assert imap.capable?("UIDPLUS")

      # AUTHENTICATE PLAIN with SASL-IR (net-imap sends the initial
      # response because SASL-IR + AUTH=PLAIN are advertised).
      imap.authenticate("PLAIN", EMAIL, PASSWORD)

      mailboxes = imap.list("", "*")
      inbox = mailboxes.find { |m| m.name == "INBOX" }
      assert inbox
      sent = mailboxes.find { |m| m.name == "Sent" }
      assert_includes sent.attr, :Sent

      imap.select("INBOX")

      fetched = imap.fetch(1, %w[UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE]).first
      envelope = fetched.attr["ENVELOPE"]
      assert_equal "greetings", envelope.subject
      assert_equal "amy", envelope.from.first.mailbox
      assert_equal "remote.test", envelope.from.first.host
      assert_nil envelope.cc, "absent address lists must come back as NIL"

      structure = fetched.attr["BODYSTRUCTURE"]
      assert_equal "ALTERNATIVE", structure.subtype
      assert_equal %w[PLAIN HTML], structure.parts.map(&:subtype)

      body = imap.fetch(1, "BODY[1]").first.attr["BODY[1]"]
      assert_equal "plain body", body.chomp

      partial = imap.fetch(1, "BODY.PEEK[1]<0.5>").first.attr["BODY[1]<0>"]
      assert_equal "plain", partial

      header = imap.fetch(1, "BODY.PEEK[HEADER.FIELDS (SUBJECT)]").first
      assert_match(/Subject: greetings/i, header.attr.values.join)

      assert_equal [ 1 ], imap.search([ "SUBJECT", "greetings" ])
      assert_equal [ 1 ], imap.search([ "SENTON", Date.new(2025, 7, 15) ])
      assert_equal [], imap.search([ "SENTON", Date.new(2024, 1, 1) ])
    end
  end

  def test_uid_workflows_move_store_expunge
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 2
    with_client do |imap|
      imap.authenticate("PLAIN", EMAIL, PASSWORD)
      imap.select("INBOX")

      imap.uid_move(1, "Trash")
      assert_equal 1, imap.responses("EXPUNGE", &:last)
      assert_equal 1, @store.select_mailbox(@account_id, "Trash")[:messages].size

      imap.uid_store(2, "+FLAGS", [ :Deleted ])
      # UID EXPUNGE of an unrelated uid must not touch uid 2.
      imap.uid_expunge(999)
      assert_equal [ 2 ], imap.uid_search([ "DELETED" ])
      imap.uid_expunge(2)
      assert_equal [], imap.uid_search([ "ALL" ])
    end
  end

  def test_idle_receives_exists_update
    poll = MailOnRails::ImapServer::IDLE_POLL_SECONDS
    MailOnRails::ImapServer.send(:remove_const, :IDLE_POLL_SECONDS)
    MailOnRails::ImapServer.const_set(:IDLE_POLL_SECONDS, 0.05)

    with_client do |imap|
      imap.authenticate("PLAIN", EMAIL, PASSWORD)
      imap.select("INBOX")

      appended = false
      responses = []
      imap.idle(2) do |resp|
        unless appended
          appended = true
          @store.append(@account_id, "INBOX", RAW, [], nil)
        end
        responses << resp
        imap.idle_done if resp.is_a?(Net::IMAP::UntaggedResponse) && resp.name == "EXISTS"
      end

      exists = responses.find { |r| r.is_a?(Net::IMAP::UntaggedResponse) && r.name == "EXISTS" }
      assert exists, "expected an untagged EXISTS while idling"
      assert_equal 2, exists.data
    end
  ensure
    MailOnRails::ImapServer.send(:remove_const, :IDLE_POLL_SECONDS)
    MailOnRails::ImapServer.const_set(:IDLE_POLL_SECONDS, poll)
  end
end

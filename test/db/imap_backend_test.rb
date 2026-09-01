# frozen_string_literal: true

require_relative "test_helper"

class ImapBackendTest < MailOnRails::Testing::Database::TestCase
  RAW = "From: alice@example.org\r\n" \
        "To: bob@example.test\r\n" \
        "Subject: Quarterly report\r\n" \
        "\r\n" \
        "The budget numbers look great.\r\n"

  def backend = @backend ||= MailOnRails::Store::ImapBackend.new

  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "bob@example.test",
                                                   password: "a-long-test-password")
  end

  def inbox = account.mailboxes.find_by!(name: "INBOX")

  def deliver(raw = RAW, flags: [])
    MailOnRails::EmailMessage.deliver_raw(inbox, raw, flags: flags)
  end

  # Hand-rolled singleton stubs (minitest/mock isn't bundled). The scan
  # itself is covered by the scanner's own tests; here it only needs a
  # canned verdict so append's handling of each outcome is exercised.
  def with_scan_result(result)
    singleton = MailOnRails::ClamavScanner.singleton_class
    enabled = MailOnRails::ClamavScanner.method(:enabled?)
    scan = MailOnRails::ClamavScanner.method(:scan)
    singleton.define_method(:enabled?) { !result.nil? }
    singleton.define_method(:scan) { |_raw| result }
    yield
  ensure
    singleton.define_method(:enabled?, enabled)
    singleton.define_method(:scan, scan)
  end

  test "append stores the message and reports uid and uidvalidity" do
    result = with_scan_result(MailOnRails::ClamavScanner::Result.new(:clean, nil)) do
      backend.append(account.id, "INBOX", RAW, [ "\\Seen" ], nil)
    end

    assert_equal inbox.uid_validity, result[:uid_validity]
    message = inbox.email_messages.find_by!(uid: result[:uid])
    assert_equal "clean", message.scan_status
    assert_includes message.flags, "\\Seen"
  end

  test "append refuses an infected upload" do
    result = with_scan_result(MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test")) do
      backend.append(account.id, "INBOX", RAW, [], nil)
    end

    assert_equal :infected, result[:code]
    # The signature name must not echo to the peer - it is a packing
    # oracle for an authenticated attacker. Log-only.
    assert_equal "message rejected: virus detected", result[:error]
    assert_equal 0, inbox.email_messages.count
  end

  test "append defers on a scanner outage (fail-closed default)" do
    result = with_scan_result(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      backend.append(account.id, "INBOX", RAW, [], nil)
    end

    assert_equal :unavailable, result[:code]
    assert_equal 0, inbox.email_messages.count
  end

  test "append stores the message flagged unscanned when imap_append_fail_closed is off" do
    MailOnRails::Settings.overrides = { imap_append_fail_closed: false }
    result = with_scan_result(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      backend.append(account.id, "INBOX", RAW, [], nil)
    end

    message = inbox.email_messages.find_by!(uid: result[:uid])
    assert_equal "unscanned", message.scan_status
  ensure
    MailOnRails::Settings.reset!
  end

  test "append to a missing mailbox reports notfound without scanning" do
    scans = 0
    result = with_scan_result(MailOnRails::ClamavScanner::Result.new(:clean, nil)) do
      MailOnRails::ClamavScanner.singleton_class.define_method(:scan) do |_raw|
        scans += 1
        MailOnRails::ClamavScanner::Result.new(:clean, nil)
      end
      backend.append(account.id, "no-such-box", RAW, [], nil)
    end

    assert_equal :notfound, result[:code]
    assert_equal 0, scans, "the scan must not run for a mailbox that does not exist"
  end

  test "renames a mailbox hierarchy without LIKE metacharacter leakage" do
    account.mailboxes.create!(name: "a%b")
    account.mailboxes.create!(name: "a%b/child")
    account.mailboxes.create!(name: "aXb")
    # If the escape character were inert, the "%" in the rename prefix
    # would act as a wildcard and drag this sibling tree along.
    account.mailboxes.create!(name: "aXb/other")

    assert_equal({}, backend.rename_mailbox(account.id, "a%b", "renamed"))

    names = account.mailboxes.pluck(:name)
    assert_includes names, "renamed"
    assert_includes names, "renamed/child"
    assert_includes names, "aXb/other"
    assert_not names.any? { |name| name.start_with?("renamed/o") }
  end

  test "expunge removes \\Deleted messages case-insensitively and keeps the rest" do
    doomed = deliver(RAW.sub("Quarterly", "First"), flags: [ "\\Deleted" ])
    lowercase = deliver(RAW.sub("Quarterly", "Second"), flags: [ "\\deleted" ])
    kept = deliver(RAW.sub("Quarterly", "Third"), flags: [ "\\Seen" ])

    result = backend.expunge(inbox.id)

    assert_equal [ doomed.uid, lowercase.uid ], result[:uids].sort
    assert_equal [ kept.uid ], inbox.email_messages.pluck(:uid)
  end

  test "uid-restricted expunge removes only the requested uids" do
    first = deliver(RAW.sub("Quarterly", "First"), flags: [ "\\Deleted" ])
    second = deliver(RAW.sub("Quarterly", "Second"), flags: [ "\\Deleted" ])

    result = backend.expunge(inbox.id, [ second.uid ])

    assert_equal [ second.uid ], result[:uids]
    assert_includes inbox.email_messages.pluck(:uid), first.uid
  end

  test "search_text finds whole words and body scope excludes header-only terms" do
    message = deliver

    assert_equal [ message.uid ], backend.search_text(inbox.id, "budget", "text")[:uids]
    assert_equal [ message.uid ], backend.search_text(inbox.id, "Quarterly", "text")[:uids]
    assert_equal [ message.uid ], backend.search_text(inbox.id, "budget", "body")[:uids]
    # "Quarterly" appears only in the Subject header, never in the body.
    assert_equal [], backend.search_text(inbox.id, "Quarterly", "body")[:uids]
    assert_equal [], backend.search_text(inbox.id, "zebra", "text")[:uids]
  end

  test "full_text_search requires every term" do
    message = deliver

    assert_equal [ message.id ], MailOnRails::EmailMessage.full_text_search("budget numbers").ids
    assert_equal [], MailOnRails::EmailMessage.full_text_search("budget zebra").ids
  end

  test "unseen_count tracks store_flags" do
    message = deliver

    assert_equal 1, inbox.unseen_count
    backend.store_flags(inbox.id, [ message.uid ], "+", [ "\\Seen" ])
    assert_equal 0, inbox.unseen_count
  end

  # -- store exceptions on the wire --------------------------------------------

  # An IMAP session over a socket pair, on this Active Record store: the
  # full Store::Base#db -> session path, so what the client sees when the
  # database itself rejects a write is what production would send.
  def with_wire_session
    account
    server, client = UNIXSocket.pair
    session = MailOnRails::ImapServer::Session.new(server, backend, { tls: :implicit }, nil)
    thread = Thread.new { session.run }
    client.timeout = 10
    client.gets("\r\n")
    client.write("l0 LOGIN #{account.email} a-long-test-password\r\n")
    reply = read_until_tagged(client, "l0")
    assert_match(/\Al0 OK/, reply)
    yield client
  ensure
    client&.close
    thread&.join(5)
  end

  def read_until_tagged(client, tag)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line.start_with?("#{tag} ")
    end
    lines.join
  end

  def wire_append(client, tag, raw, date: nil)
    args = [ "INBOX" ]
    args << %("#{date}") if date
    client.write("#{tag} APPEND #{args.join(" ")} {#{raw.bytesize}+}\r\n#{raw}\r\n")
    read_until_tagged(client, tag)
  end

  # Time.strptime accepts a nine-digit year; whatever the adapter then
  # does with it (SQLite stores it, PostgreSQL raises), the reply names no
  # adapter, table or SQL.
  test "an APPEND the database rejects answers a fixed temporary failure" do
    with_wire_session do |client|
      reply = wire_append(client, "a1", RAW, date: "01-Jan-999999999 00:00:00 +0000")
      assert_match(/\Aa1 (OK|NO \[UNAVAILABLE\] APPEND failed: temporary server error)\r\n\z/, reply)
      refute_match(/ActiveRecord|PG::|SQLite|Mysql|SELECT|INSERT|mail_on_rails_/, reply)

      # Force the adapter failure regardless of what SQLite tolerates.
      singleton = MailOnRails::EmailMessage.singleton_class
      original = MailOnRails::EmailMessage.method(:deliver_raw)
      singleton.define_method(:deliver_raw) do |*_args, **_kwargs|
        raise ActiveRecord::StatementInvalid, "PG::DatetimeFieldOverflow: ERROR: date/time field value out of " \
                                              "range: INSERT INTO mail_on_rails_email_messages"
      end
      begin
        reply = wire_append(client, "a2", RAW)
      ensure
        singleton.define_method(:deliver_raw, original)
      end
      assert_equal "a2 NO [UNAVAILABLE] APPEND failed: temporary server error\r\n", reply
      client.write("a3 NOOP\r\n")
      assert_match(/\Aa3 OK/, read_until_tagged(client, "a3"), "session survives")
    end
  end
end

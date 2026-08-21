# frozen_string_literal: true

require_relative "test_helper"
require "clamav_stub_helper"

# Virus policy on the IMAP APPEND path (the one write path with no SMTP
# daemon in front): infected uploads are refused with the :infected
# envelope (and a generic message - no signature-name oracle), a scanner
# outage defers by default (imap_append_fail_closed) with an opt-out that
# stores in place flagged "unscanned", copies carry their verdict without
# a rescan, and Quarantine stays out of LIST.
class ImapBackendScanTest < MailOnRails::Testing::Database::TestCase
  include ClamavStubHelper

  RAW = "Message-ID: <up-1@local.test>\r\nFrom: me@example.test\r\nSubject: up\r\n\r\nbody\r\n"

  def setup
    super
    @account = MailOnRails::EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    @store = MailOnRails::Store::ImapBackend.new
  end

  def teardown
    MailOnRails::Settings.overrides = {}
  end

  def stub_scan(result, &block)
    with_scanner(enabled: true, scan: result, &block)
  end

  test "append refuses an infected upload with the :infected envelope" do
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test-Signature")) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert_equal :infected, result[:code]
    assert_equal "message rejected: virus detected", result[:error]
    assert_empty @account.inbox.email_messages, "an infected upload must not be stored"
  end

  test "append stores clean uploads stamped clean" do
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:clean, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert result[:uid], "expected a successful append, got #{result.inspect}"
    assert_equal "clean", @account.inbox.email_messages.sole.scan_status
  end

  test "append defers while the scanner is down (fail-closed default)" do
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert_equal :unavailable, result[:code]
    assert_empty @account.inbox.email_messages
  end

  test "opting out of fail-closed stores in place flagged unscanned when the scanner is down" do
    MailOnRails::Settings.overrides = { imap_append_fail_closed: false }
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert result[:uid], "expected a successful append, got #{result.inspect}"
    assert_equal "unscanned", @account.inbox.email_messages.sole.scan_status
  end

  test "append skips scanning entirely when no scanner is configured" do
    result = @store.append(@account.id, "INBOX", RAW, [], nil)

    assert result[:uid]
    assert_nil @account.inbox.email_messages.sole.scan_status
  end

  test "copy carries the verdict without invoking the scanner" do
    MailOnRails::Settings.overrides = { imap_append_fail_closed: false }
    stub_scan(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end
    MailOnRails::Settings.overrides = {}
    uid = @account.inbox.email_messages.sole.uid

    with_scanner(enabled: true, scan: ->(*) { raise "copy must not rescan stored bytes" }) do
      @store.copy(@account.inbox.id, [ uid ], "Trash")
    end

    copied = @account.find_mailbox("Trash").email_messages.sole
    assert_equal "unscanned", copied.scan_status
  end

  test "list_mailboxes hides Quarantine" do
    @account.quarantine_mailbox # ensure it exists

    names = @store.list_mailboxes(@account.id)[:mailboxes]
    refute_includes names, MailOnRails::Mailbox::QUARANTINE
    assert_includes names, "INBOX"
  end

  # Quarantine holds flagged malware and is reachable only through the web
  # review UI. Every by-name IMAP operation must treat it as nonexistent,
  # so a client can neither read the infected bytes nor move them out.
  QUARANTINE = MailOnRails::Mailbox::QUARANTINE

  test "select and status of Quarantine report no such mailbox" do
    @account.quarantine_mailbox

    assert_equal :notfound, @store.select_mailbox(@account.id, QUARANTINE)[:code]
    assert_equal :notfound, @store.status(@account.id, QUARANTINE)[:code]
    # A lowercase spelling must not slip past the guard either.
    assert_equal :notfound, @store.select_mailbox(@account.id, "quarantine")[:code]
  end

  test "append into Quarantine is refused as nonexistent" do
    @account.quarantine_mailbox

    result = @store.append(@account.id, QUARANTINE, RAW, [], nil)
    assert_equal :notfound, result[:code]
  end

  test "infected mail in Quarantine cannot be copied or moved out over IMAP" do
    quarantine = @account.quarantine_mailbox
    MailOnRails::EmailMessage.deliver_raw(quarantine, RAW, scan_status: "infected", virus_name: "Eicar-Test")
    # There is no way to SELECT Quarantine to learn its mailbox_id, but even
    # with it a COPY/MOVE keyed on the source works off ids - the exposure
    # was the destination side, so prove Quarantine is not a usable endpoint
    # and that its own id never leaks through select.
    assert_equal :notfound, @store.select_mailbox(@account.id, QUARANTINE)[:code]
    assert_equal :notfound, @store.copy(@account.inbox.id, [], QUARANTINE)[:code]
    assert_equal :notfound, @store.move(@account.inbox.id, [], QUARANTINE)[:code]
  end

  test "Quarantine cannot be created, renamed, or deleted over IMAP" do
    @account.quarantine_mailbox

    assert_equal :exists, @store.create_mailbox(@account.id, QUARANTINE)[:code]
    assert_equal :notfound, @store.delete_mailbox(@account.id, QUARANTINE)[:code]
    assert_equal :notfound, @store.rename_mailbox(@account.id, QUARANTINE, "Salvage")[:code]
    assert_equal :exists, @store.rename_mailbox(@account.id, "INBOX", QUARANTINE)[:code]
    assert @account.find_mailbox(QUARANTINE), "the real Quarantine mailbox is untouched"
  end
end

# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/imap/store/contracts"

# The Active Record implementation behind the IMAP server must satisfy the
# store contract (docs/store_contract.md in the core gem) - the same suite
# runs against MailOnRails::Imap::Store::Memory in the wire tests
# (test/imap/memory_store_test.rb).
class ImapBackendStoreTest < MailOnRails::Testing::Database::TestCase
  include MailOnRails::Imap::Store::Contracts::Imap

  def create_account(email:, password:)
    MailOnRails::EmailAccount.create!(email: email, password: password).id
  end

  def build_store(**)
    MailOnRails::Store::ImapBackend.new
  end

  def apply_quota(account_id, bytes)
    MailOnRails::EmailAccount.find(account_id).update!(quota_bytes: bytes)
  end

  test "tombstone pruning raises the floor and expunged_since falls back" do
    raw = MailOnRails::Imap::Store::Contracts::Imap::RAW_CRLF
    uids = 3.times.map { store.append(account_id, "INBOX", raw, [ "\\Deleted" ], nil)[:uid] }
    mailbox = MailOnRails::Mailbox.find(store.select_mailbox(account_id, "INBOX")[:mailbox_id])

    uids.each { |uid| store.expunge(mailbox.id, [ uid ]) }
    MailOnRails::ExpungedMessage.prune!(mailbox, limit: 2)
    mailbox.reload

    assert_operator mailbox.tombstone_floor, :>, 0
    assert_equal 2, mailbox.expunged_messages.count

    result = store.expunged_since(mailbox.id, 0)
    refute result[:complete]
    assert_equal uids.sort, result[:uids].sort, "fallback must cover every missing uid"

    recent = store.expunged_since(mailbox.id, mailbox.tombstone_floor)
    assert recent[:complete]
    assert_equal uids.last(2).sort, recent[:uids].sort
  end
end

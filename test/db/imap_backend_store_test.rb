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
    assert_nil result[:uids], "the fallback is reported as gaps, never a uid list sized by uid_next"
    assert_equal [ [ uids.first, uids.last ] ], result[:ranges], "fallback must cover every missing uid"

    recent = store.expunged_since(mailbox.id, mailbox.tombstone_floor)
    assert recent[:complete]
    assert_equal uids.last(2).sort, recent[:uids].sort
  end

  # M10: a mailbox whose uid_next is huge (uids are never reused, so a
  # long-lived mailbox gets there) must not turn one QRESYNC fallback into
  # a uid_next-sized allocation - gaps come from the present uids alone.
  test "the tombstone fallback is sized by the mailbox, not by uid_next" do
    raw = MailOnRails::Imap::Store::Contracts::Imap::RAW_CRLF
    kept = store.append(account_id, "INBOX", raw, [], nil)[:uid]
    gone = store.append(account_id, "INBOX", raw, [ "\\Deleted" ], nil)[:uid]
    mailbox = MailOnRails::Mailbox.find(store.select_mailbox(account_id, "INBOX")[:mailbox_id])
    store.expunge(mailbox.id, [ gone ])
    MailOnRails::ExpungedMessage.prune!(mailbox, limit: 0)
    mailbox.update!(uid_next: 50_000_000)

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = store.expunged_since(mailbox.id, 0)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
    refute result[:complete]
    assert_equal [ [ gone, 49_999_999 ] ], result[:ranges]
    assert_equal 1, kept
  end

  # COPY/MOVE load raw rows COPY_BATCH at a time; the uid pairing must
  # survive the batching, in uid order.
  test "copy and move batch their row loads and keep uid pairs aligned" do
    raw = MailOnRails::Imap::Store::Contracts::Imap::RAW_CRLF
    count = MailOnRails::Store::ImapBackend::COPY_BATCH * 2 + 5
    uids = count.times.map { store.append(account_id, "INBOX", raw, [], nil)[:uid] }
    inbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

    copied = store.copy(inbox_id, uids.shuffle, "Trash")
    assert_equal uids, copied[:src_uids]
    assert_equal copied[:dest_uids].sort, copied[:dest_uids]
    assert_equal count, copied[:dest_uids].length

    moved = store.move(inbox_id, uids.shuffle, "Sent")
    assert_equal uids, moved[:src_uids]
    assert_equal count, moved[:dest_uids].length
    assert_equal [], store.select_mailbox(account_id, "INBOX")[:messages]
  end

  # search_header (M9) answers FROM/TO/SUBJECT from the delivery-time
  # columns: the like_search semantics (substring, every word required).
  test "search_header uses the subject and address columns" do
    raw = "From: Alice Example <alice@example.org>\r\nTo: bob@example.test\r\n" \
          "Subject: Quarterly budget review\r\n\r\nbody\r\n"
    uid = store.append(account_id, "INBOX", raw, [], nil)[:uid]
    store.append(account_id, "INBOX", "From: x@example.org\r\nSubject: lunch\r\n\r\nbudget\r\n", [], nil)
    inbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

    assert_equal [ uid ], store.search_header(inbox_id, "subject", "BUDGET review")[:uids]
    assert_equal [ uid ], store.search_header(inbox_id, "from", "alice@")[:uids]
    assert_equal [ uid ], store.search_header(inbox_id, "to", "bob")[:uids]
    assert_equal [], store.search_header(inbox_id, "subject", "lunch review")[:uids]
    assert_equal [], store.search_header(inbox_id, "cc", "bob")[:uids], "unsupported fields match nothing"
  end
end

# frozen_string_literal: true

require_relative "test_helper"

# H4 (audit 2026-11-17): the message's bytes (raw) and its extracted text
# (body_text) sit in the same row as its uid and flags, so a full-row load
# reads them. Selecting a mailbox, NOOP, every IDLE poll, a metadata
# FETCH, a flag change and an expunge used to do exactly that - the whole
# contents of every message, for a few integers - which made the cost of
# an idle connection whatever anyone chose to mail in.
#
# Every store path that does not hand the bytes to its caller is run here
# with the SQL captured: none may name those two columns or select "*".
class ImapBackendColumnsTest < MailOnRails::Testing::Database::TestCase
  RAW = "From: sender@remote.test\r\nTo: user@example.test\r\nSubject: columns\r\n\r\nneedle body text\r\n"

  def backend = @backend ||= MailOnRails::Store::ImapBackend.new

  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "columns-#{SecureRandom.hex(4)}@example.test",
                                                   password: "pw-123456")
  end

  def inbox = account.mailboxes.find_by!(name: "INBOX")

  def deliver(flags: [])
    MailOnRails::EmailMessage.deliver_raw(inbox, RAW, flags: flags)
  end

  # The SELECTs against the messages table issued inside the block.
  def message_selects
    table = MailOnRails::EmailMessage.table_name
    statements = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") do |*, payload|
      sql = payload[:sql]
      statements << sql if payload[:name] != "SCHEMA" && sql.match?(/\ASELECT\b/i) && sql.include?(table)
    end
    yield
    statements
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  def assert_no_content_columns(statements, path)
    refute_empty statements, "#{path}: expected at least one query against the messages table"
    statements.each do |sql|
      # The select list only: a WHERE may name any column.
      selected = sql[/\ASELECT\s+(.*?)\s+FROM\b/im, 1].to_s
      refute_match(/\.\*|\braw\b|\bbody_text\b/, selected, "#{path} loads message content: #{sql}")
    end
  end

  test "select_mailbox reads uid, flags and modseq only" do
    3.times { deliver(flags: [ "\\Seen" ]) }
    result = nil
    statements = message_selects { result = backend.select_mailbox(account.id, "INBOX") }

    assert_no_content_columns(statements, "select_mailbox")
    assert_equal 3, result[:messages].length
    uid, flags, modseq = result[:messages].first
    assert_kind_of Integer, uid
    assert_equal [ "\\Seen" ], flags, "flags must still come back deserialized"
    assert_kind_of Integer, modseq
  end

  test "a metadata fetch does not load the message bytes" do
    message = deliver
    result = nil
    statements = message_selects { result = backend.fetch(inbox.id, [ message.uid ], false) }

    assert_no_content_columns(statements, "fetch(with_raw: false)")
    entry = result[:messages].first
    assert_equal message.uid, entry[:uid]
    assert_equal RAW.bytesize, entry[:size]
    assert_equal message.email_object_id, entry[:email_id]
    assert_equal message.thread_id, entry[:thread_id]
    assert_equal message.internal_date.to_i, entry[:internal_date]
    assert_equal message.created_at.to_i, entry[:saved_date]
    refute entry.key?(:raw)
  end

  test "a raw fetch still returns the bytes, without the extracted text" do
    message = deliver
    result = nil
    statements = message_selects { result = backend.fetch(inbox.id, [ message.uid ], true) }

    assert_equal RAW, result[:messages].first[:raw]
    statements.each do |sql|
      selected = sql[/\ASELECT\s+(.*?)\s+FROM\b/im, 1].to_s
      refute_match(/\.\*|\bbody_text\b/, selected, "fetch(with_raw: true) loads more than it returns: #{sql}")
    end
  end

  test "store_flags changes flags and modseq without loading the message bytes" do
    message = deliver
    before = message.modseq
    result = nil
    statements = message_selects { result = backend.store_flags(inbox.id, [ message.uid ], "+", [ "\\Flagged" ]) }

    assert_no_content_columns(statements, "store_flags")
    uid, flags, modseq = result[:messages].first
    assert_equal message.uid, uid
    assert_equal [ "\\Flagged" ], flags
    assert_operator modseq, :>, before
    message.reload
    assert_equal [ "\\Flagged" ], message.flags
    assert_equal RAW, message.raw, "the stored message must be untouched"
    assert_equal modseq, message.modseq
  end

  test "expunge removes the message, its bytes from the quota and leaves a tombstone, without loading it" do
    kept = deliver
    gone = deliver(flags: [ "\\Deleted" ])
    used_before = account.reload.used_bytes
    result = nil
    statements = message_selects { result = backend.expunge(inbox.id) }

    assert_no_content_columns(statements, "expunge")
    assert_equal [ gone.uid ], result[:uids]
    assert_equal [ kept.uid ], inbox.email_messages.pluck(:uid)
    assert_equal used_before - RAW.bytesize, account.reload.used_bytes
    assert_equal [ gone.uid ], MailOnRails::ExpungedMessage.where(mailbox_id: inbox.id).pluck(:uid)
    assert_equal inbox.reload.highest_modseq, result[:highest_modseq]
  end

  test "status, list and the search pushdowns never load a message row" do
    message = deliver
    statements = message_selects do
      backend.status(account.id, "INBOX")
      backend.list_mailboxes(account.id)
      backend.search_text(inbox.id, "needle", "body")
      backend.search_text(inbox.id, "needle", "text")
      backend.search_header(inbox.id, "subject", "columns")
      backend.search_meta(inbox.id, "size", (0..))
      backend.expunged_since(inbox.id, 0)
    end

    assert_no_content_columns(statements, "status/search")
    assert_equal [ message.uid ], backend.search_text(inbox.id, "needle", "body")[:uids]
  end

  # COPY and MOVE do need the bytes; what they must not do is read a
  # whole batch of large messages in one result set.
  test "copy loads its source rows in byte-bounded batches" do
    uids = 5.times.map { deliver.uid }
    account.mailboxes.create!(name: "Archive")
    batches = backend.send(:byte_bounded_batches, uids.map { |uid| [ uid, RAW.bytesize ] })
    assert_equal [ uids ], batches, "small messages share one batch"

    limit = MailOnRails::Store::ImapBackend::COPY_BATCH_BYTES
    sizes = [ [ 1, limit / 2 ], [ 2, limit / 2 ], [ 3, 10 ], [ 4, limit * 2 ], [ 5, 10 ] ]
    assert_equal [ [ 1, 2 ], [ 3 ], [ 4 ], [ 5 ] ], backend.send(:byte_bounded_batches, sizes)

    result = backend.copy(inbox.id, uids, "Archive")
    assert_equal uids, result[:src_uids]
    assert_equal 5, account.mailboxes.find_by!(name: "Archive").email_messages.count
  end
end

# frozen_string_literal: true

require_relative "test_helper"

# A client's MOVE/COPY/APPEND across the Junk boundary is the user's spam
# verdict: the backend records a SenderRule and enqueues rspamd learning,
# and never lets that bookkeeping break the IMAP operation itself.
class ImapBackendJunkFeedbackTest < MailOnRails::Testing::Database::TestCase
  RAW = "From: Spammer@Remote.TEST\r\nTo: bob@example.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def setup
    super
    enqueued.clear
    @account_id = MailOnRails::EmailAccount.create!(email: "bob@example.test", password: "a-long-test-password").id
    @store = MailOnRails::Store::ImapBackend.new
  end

  attr_reader :store, :account_id

  def account = MailOnRails::EmailAccount.find(account_id)
  def mailbox_id(name) = store.select_mailbox(account_id, name)[:mailbox_id]
  def append(name, raw = RAW) = store.append(account_id, name, raw, [], nil)[:uid]

  # Seeds a message the way the mailroom files spam - without a verdict.
  def seed_junk
    MailOnRails::EmailMessage.deliver_raw(account.junk_mailbox, RAW).uid
  end

  def enqueued
    MailOnRails::LearnSpamJob.queue_adapter.enqueued_jobs
  end

  def learn_classes
    enqueued.select { |job| job[:job] == MailOnRails::LearnSpamJob }.map { |job| job[:args].last }
  end

  def rules
    account.sender_rules.order(:address).pluck(:address, :verdict, :source)
  end

  test "MOVE into Junk denies the sender and learns spam" do
    uid = append("INBOX")
    enqueued.clear

    result = store.move(mailbox_id("INBOX"), [ uid ], "Junk")

    assert_equal [ uid ], result[:src_uids]
    assert_equal 1, result[:dest_uids].size
    assert_equal [ [ "spammer@remote.test", "deny", "imap" ] ], rules
    assert_equal [ "spam" ], learn_classes
    learned = MailOnRails::EmailMessage.find(enqueued.last[:args].first)
    assert_equal result[:dest_uids], [ learned.uid ], "the job names the row in Junk"
  end

  test "MOVE out of Junk to INBOX flips the sender to allow and learns ham" do
    MailOnRails::SenderRule.record!(account, "spammer@remote.test", "deny", source: "imap")
    uid = seed_junk

    store.move(mailbox_id("Junk"), [ uid ], "INBOX")

    assert_equal [ [ "spammer@remote.test", "allow", "imap" ] ], rules
    assert_equal [ "ham" ], learn_classes
  end

  test "MOVE from Junk to Trash is not a verdict" do
    uid = seed_junk

    store.move(mailbox_id("Junk"), [ uid ], "Trash")

    assert_empty rules
    assert_empty learn_classes
  end

  test "COPY into Junk is a spam verdict and keeps the source copy" do
    uid = append("INBOX")
    enqueued.clear

    result = store.copy(mailbox_id("INBOX"), [ uid ], "Junk")

    assert_equal 1, result[:dest_uids].size
    assert_equal [ uid ], store.select_mailbox(account_id, "INBOX")[:messages].map(&:first)
    assert_equal [ [ "spammer@remote.test", "deny", "imap" ] ], rules
    assert_equal [ "spam" ], learn_classes
  end

  test "APPEND into Junk is a spam verdict; APPEND elsewhere is not" do
    append("INBOX")
    append("Trash")
    assert_empty rules
    assert_empty learn_classes

    append("Junk")
    assert_equal [ [ "spammer@remote.test", "deny", "imap" ] ], rules
    assert_equal [ "spam" ], learn_classes
  end

  test "a batch MOVE into Junk writes one rule and one learn per message" do
    uids = 3.times.map { append("INBOX") }
    enqueued.clear

    store.move(mailbox_id("INBOX"), uids, "Junk")

    assert_equal 1, account.sender_rules.count
    assert_equal %w[spam spam spam], learn_classes
  end

  test "learning is enqueued only after the move's transaction commits" do
    uid = append("INBOX")
    enqueued.clear
    seen_inside = nil

    MailOnRails::SenderRule.singleton_class.alias_method(:record_without_probe!, :record!)
    probe = enqueued
    MailOnRails::SenderRule.define_singleton_method(:record!) do |*args, **kwargs|
      seen_inside = probe.size
      record_without_probe!(*args, **kwargs)
    end

    store.move(mailbox_id("INBOX"), [ uid ], "Junk")

    assert_equal 0, seen_inside
    assert_equal [ "spam" ], learn_classes
  ensure
    MailOnRails::SenderRule.singleton_class.alias_method(:record!, :record_without_probe!)
    MailOnRails::SenderRule.singleton_class.remove_method(:record_without_probe!)
  end

  test "a failing rule write does not turn the MOVE into an error" do
    uid = append("INBOX")
    enqueued.clear
    MailOnRails::SenderRule.singleton_class.alias_method(:record_without_failure!, :record!)
    MailOnRails::SenderRule.define_singleton_method(:record!) { |*| raise "boom" }

    result = store.move(mailbox_id("INBOX"), [ uid ], "Junk")

    assert_nil result[:error]
    assert_equal [ uid ], result[:src_uids]
    assert_equal [], store.select_mailbox(account_id, "INBOX")[:messages]
    assert_equal 1, store.select_mailbox(account_id, "Junk")[:messages].size
    assert_empty rules
    assert_empty learn_classes
  ensure
    MailOnRails::SenderRule.singleton_class.alias_method(:record!, :record_without_failure!)
    MailOnRails::SenderRule.singleton_class.remove_method(:record_without_failure!)
  end
end

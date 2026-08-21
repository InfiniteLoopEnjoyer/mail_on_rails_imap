require "test_helper"
require "mail_on_rails/imap/store/memory"
require "mail_on_rails/imap/store/contracts"

# The dependency-free reference store must satisfy the IMAP store contract
# (Store::Contracts) - it's what this gem's session tests run against.
module MemoryStoreConformance
  def build_store(**limits)
    MailOnRails::Imap::Store::Memory.new(**limits)
  end

  def create_account(email:, password:)
    store.add_account(email: email, password: password)
  end

  def apply_quota(account_id, bytes)
    store.set_quota(account_id, bytes)
  end
end

class MemoryImapStoreTest < Minitest::Test
  include MemoryStoreConformance
  include MailOnRails::Imap::Store::Contracts::Imap

  RAW = MailOnRails::Imap::Store::Contracts::Imap::RAW_CRLF

  # Pruned tombstone history must degrade to complete: false with the
  # every-missing-uid fallback, never to silently dropped VANISHED uids.
  def test_tombstone_pruning_raises_the_floor_and_falls_back
    store = build_store(tombstone_limit: 2)
    account = store.add_account(email: "prune@example.test", password: "pw")
    uids = 3.times.map { store.append(account, "INBOX", RAW, [ "\\Deleted" ], nil)[:uid] }
    mailbox_id = store.select_mailbox(account, "INBOX")[:mailbox_id]

    store.expunge(mailbox_id, [ uids[0] ])
    store.expunge(mailbox_id, [ uids[1] ])
    store.expunge(mailbox_id, [ uids[2] ]) # prunes the first tombstone

    result = store.expunged_since(mailbox_id, 0)
    refute result[:complete], "history before the floor cannot be answered precisely"
    assert_equal uids.sort, result[:uids].sort, "fallback must cover every missing uid"

    recent = store.expunged_since(mailbox_id, store.status(account, "INBOX")[:highest_modseq] - 1)
    assert recent[:complete]
    assert_equal [ uids[2] ], recent[:uids]
  end

  # -- honeypot seams ---------------------------------------------------------

  def test_authenticate_and_scram_report_the_canary_flag
    store = build_store
    store.add_account(email: "real@example.test", password: "pw-123456")
    store.add_account(email: "canary@example.test", password: "pw-123456", honeypot: true)

    refute store.authenticate("real@example.test", "pw-123456")[:honeypot]
    assert store.authenticate("canary@example.test", "pw-123456")[:honeypot]
    assert store.scram_credentials("canary@example.test")[:honeypot]
  end

  def test_record_and_update_honeypot_event
    store = build_store
    id = store.record_honeypot_event(protocol: "imap", trigger: "exploit_probe",
                                     signature: "shellshock", ip: "203.0.113.9",
                                     transcript: "partial")[:id]
    store.update_honeypot_transcript(id, transcript: "full")

    assert_equal 1, store.honeypot_events.size
    event = store.honeypot_events.first
    assert_equal "exploit_probe", event[:trigger]
    assert_equal "full", event[:transcript]
  end
end

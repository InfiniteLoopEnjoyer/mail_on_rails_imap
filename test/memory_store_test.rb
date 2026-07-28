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
end

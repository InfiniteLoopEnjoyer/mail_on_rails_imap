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
end

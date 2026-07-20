# frozen_string_literal: true

require "monitor"

module MailOnRails
  module Imap
    module Store
      # In-memory reference implementation of the IMAP side of the store
      # contract (docs/store_contract.md in the main mail_on_rails app repo),
      # with no Rails or database dependency. It exists so protocol behavior
      # can be tested without an app or a database, and it doubles as the
      # executable answer to "what must a store do". Not for production:
      # everything lives (unencrypted, unbounded) in one process's memory.
      #
      # Beyond the contract it exposes one test seam: +add_account+ to
      # provision credentials.
      class Memory
        DEFAULT_MAILBOXES = %w[INBOX Sent Drafts Trash Junk].freeze

        def initialize(logger: nil)
          @logger = logger
          @accounts = {} # id => { id:, email:, password:, mailboxes: { name => mailbox } }
          @counters = Hash.new(0)
          @lock = Monitor.new
        end

        # -- test seams (not part of the contract) -----------------------------

        def add_account(email:, password:)
          @lock.synchronize do
            account = { id: next_id(:account), email: normalize(email), password: password.to_s, mailboxes: {} }
            DEFAULT_MAILBOXES.each { |name| account[:mailboxes][name] = new_mailbox(name) }
            @accounts[account[:id]] = account
            account[:id]
          end
        end

        # -- shared interface ---------------------------------------------------

        def log(level, message)
          @logger&.public_send(level, "[mail_on_rails] #{message}")
          nil
        end

        def authenticate(email, password)
          @lock.synchronize do
            account = @accounts.values.find { |a| a[:email] == normalize(email) }
            account = nil unless account && !password.to_s.empty? && account[:password] == password.to_s
            { account_id: account&.dig(:id), email: account&.dig(:email) }
          end
        end

        # -- IMAP interface -----------------------------------------------------

        def list_mailboxes(account_id)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            { mailboxes: account[:mailboxes].keys.sort }
          end
        end

        def create_mailbox(account_id, name)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            return { error: "mailbox exists", code: :exists } if find_mailbox(account, name)

            account[:mailboxes][name] = new_mailbox(name)
            {}
          end
        end

        def select_mailbox(account_id, name)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            mailbox = find_mailbox(account, name)
            return { error: "no such mailbox", code: :notfound } unless mailbox

            {
              mailbox_id: mailbox[:id],
              name: mailbox[:name],
              uid_validity: mailbox[:uid_validity],
              uid_next: mailbox[:uid_next],
              messages: sorted(mailbox).map { |m| [ m[:uid], m[:flags].dup ] }
            }
          end
        end

        def status(account_id, name)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            mailbox = find_mailbox(account, name)
            return { error: "no such mailbox", code: :notfound } unless mailbox

            {
              messages: mailbox[:messages].size,
              unseen: mailbox[:messages].count { |m| !m[:flags].include?("\\Seen") },
              uid_next: mailbox[:uid_next],
              uid_validity: mailbox[:uid_validity]
            }
          end
        end

        def fetch(mailbox_id, uids, with_raw)
          @lock.synchronize do
            mailbox = mailbox_by_id(mailbox_id)
            messages = mailbox ? sorted(mailbox).select { |m| uids.include?(m[:uid]) } : []
            entries = messages.map do |m|
              entry = { uid: m[:uid], flags: m[:flags].dup, internal_date: m[:internal_date].to_i, size: m[:size] }
              entry[:raw] = m[:raw] if with_raw
              entry
            end
            { messages: entries }
          end
        end

        def store_flags(mailbox_id, uids, mode, flags)
          @lock.synchronize do
            mailbox = mailbox_by_id(mailbox_id)
            messages = mailbox ? sorted(mailbox).select { |m| uids.include?(m[:uid]) } : []
            updated = messages.map do |m|
              m[:flags] =
                case mode
                when "+" then (m[:flags] | flags)
                when "-" then (m[:flags] - flags)
                else flags.dup
                end
              [ m[:uid], m[:flags].dup ]
            end
            { messages: updated }
          end
        end

        def expunge(mailbox_id)
          @lock.synchronize do
            mailbox = mailbox_by_id(mailbox_id)
            return { uids: [] } unless mailbox

            doomed, kept = mailbox[:messages].partition { |m| m[:flags].include?("\\Deleted") }
            mailbox[:messages] = kept
            { uids: doomed.map { |m| m[:uid] }.sort }
          end
        end

        def append(account_id, mailbox_name, raw, flags, internal_date_epoch)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            mailbox = find_mailbox(account, mailbox_name)
            return { error: "no such mailbox", code: :notfound } unless mailbox

            internal_date = internal_date_epoch ? Time.at(internal_date_epoch) : Time.now
            message = deliver_raw(mailbox, raw, flags: Array(flags), internal_date: internal_date)
            { uid: message[:uid], uid_validity: mailbox[:uid_validity] }
          end
        end

        def copy(mailbox_id, uids, dest_name)
          @lock.synchronize do
            source = mailbox_by_id(mailbox_id)
            return internal_error("unknown mailbox") unless source

            account = @accounts.values.find { |a| a[:mailboxes].value?(source) }
            dest = find_mailbox(account, dest_name)
            return { error: "no such mailbox", code: :notfound } unless dest

            src_uids = []
            dest_uids = []
            sorted(source).select { |m| uids.include?(m[:uid]) }.each do |m|
              copied = deliver_raw(dest, m[:raw], flags: m[:flags].dup, internal_date: m[:internal_date])
              src_uids << m[:uid]
              dest_uids << copied[:uid]
            end
            { uid_validity: dest[:uid_validity], src_uids: src_uids, dest_uids: dest_uids }
          end
        end

        private

        def normalize(email)
          email.to_s.strip.downcase
        end

        def next_id(kind)
          @counters[kind] += 1
        end

        def new_mailbox(name)
          { id: next_id(:mailbox), name: name, uid_validity: Time.now.to_i, uid_next: 1, messages: [] }
        end

        # INBOX is matched case-insensitively (RFC 3501); other names exactly.
        def find_mailbox(account, name)
          return account[:mailboxes].values.find { |m| m[:name].casecmp?("INBOX") } if name.to_s.casecmp?("INBOX")

          account[:mailboxes][name]
        end

        def mailbox_by_id(mailbox_id)
          @accounts.each_value do |account|
            account[:mailboxes].each_value { |m| return m if m[:id] == mailbox_id }
          end
          nil
        end

        def sorted(mailbox)
          mailbox[:messages].sort_by { |m| m[:uid] }
        end

        def deliver_raw(mailbox, raw, flags:, internal_date:)
          normalized = raw.gsub(/(?<!\r)\n/, "\r\n")
          message = {
            uid: mailbox[:uid_next],
            raw: normalized,
            size: normalized.bytesize,
            flags: flags,
            internal_date: internal_date
          }
          mailbox[:uid_next] += 1
          mailbox[:messages] << message
          message
        end

        def internal_error(message)
          { error: message, code: :internal }
        end
      end
    end
  end
end

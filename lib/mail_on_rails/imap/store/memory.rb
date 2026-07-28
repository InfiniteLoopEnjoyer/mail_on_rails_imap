# frozen_string_literal: true

require "monitor"
require_relative "../scram"

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
        # Expunge tombstones kept per mailbox for QRESYNC's VANISHED
        # (EARLIER); beyond this the oldest are pruned and the floor rises.
        TOMBSTONE_LIMIT = 1000

        def initialize(logger: nil, tombstone_limit: TOMBSTONE_LIMIT)
          @logger = logger
          @accounts = {} # id => { id:, email:, password:, mailboxes: { name => mailbox } }
          @counters = Hash.new(0)
          @tombstone_limit = tombstone_limit
          @lock = Monitor.new
        end

        # -- test seams (not part of the contract) -----------------------------

        def add_account(email:, password:)
          @lock.synchronize do
            account = { id: next_id(:account), email: normalize(email), password: password.to_s,
                        scram: Imap::Scram.derive(password.to_s), mailboxes: {} }
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

        # SCRAM-SHA-256 verifier material for AUTHENTICATE (never the
        # password itself). :notfound when the account is unknown or has
        # no derived credentials.
        def scram_credentials(email)
          @lock.synchronize do
            account = @accounts.values.find { |a| a[:email] == normalize(email) }
            scram = account&.dig(:scram)
            return { error: "no scram credentials", code: :notfound } unless scram

            {
              account_id: account[:id],
              email: account[:email],
              salt_base64: [ scram[:salt] ].pack("m0"),
              iterations: scram[:iterations],
              stored_key_base64: [ scram[:stored_key] ].pack("m0"),
              server_key_base64: [ scram[:server_key] ].pack("m0")
            }
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

        def delete_mailbox(account_id, name)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            mailbox = find_mailbox(account, name)
            return { error: "no such mailbox", code: :notfound } unless mailbox

            account[:mailboxes].delete(mailbox[:name])
            {}
          end
        end

        # Renames the mailbox and everything under it in the "/" hierarchy.
        def rename_mailbox(account_id, from, to)
          @lock.synchronize do
            account = @accounts.fetch(account_id) { return internal_error("unknown account") }
            mailbox = find_mailbox(account, from)
            return { error: "no such mailbox", code: :notfound } unless mailbox
            return { error: "mailbox exists", code: :exists } if find_mailbox(account, to)

            from_name = mailbox[:name]
            prefix = "#{from_name}/"
            account[:mailboxes].keys
                   .select { |n| n == from_name || n.start_with?(prefix) }
                   .each do |old_name|
              moved = account[:mailboxes].delete(old_name)
              moved[:name] = to + old_name[from_name.length..]
              account[:mailboxes][moved[:name]] = moved
            end
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
              highest_modseq: mailbox[:highest_modseq],
              messages: sorted(mailbox).map { |m| [ m[:uid], m[:flags].dup, m[:modseq] ] }
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
              uid_validity: mailbox[:uid_validity],
              highest_modseq: mailbox[:highest_modseq]
            }
          end
        end

        def fetch(mailbox_id, uids, with_raw)
          @lock.synchronize do
            mailbox = mailbox_by_id(mailbox_id)
            messages = mailbox ? sorted(mailbox).select { |m| uids.include?(m[:uid]) } : []
            entries = messages.map do |m|
              entry = { uid: m[:uid], flags: m[:flags].dup, internal_date: m[:internal_date].to_i,
                        size: m[:size], modseq: m[:modseq] }
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
              new_flags =
                case mode
                when "+" then (m[:flags] | flags)
                when "-" then (m[:flags] - flags)
                else flags.dup
                end
              # A store that changes nothing gets no new modseq: clients
              # would otherwise re-sync messages whose state is identical.
              if new_flags.sort != m[:flags].sort
                m[:flags] = new_flags
                m[:modseq] = next_modseq(mailbox)
              end
              [ m[:uid], m[:flags].dup, m[:modseq] ]
            end
            { messages: updated }
          end
        end

        # uids: nil removes every \Deleted message; a list restricts removal
        # to \Deleted messages with those UIDs (UID EXPUNGE).
        def expunge(mailbox_id, uids = nil)
          @lock.synchronize do
            mailbox = mailbox_by_id(mailbox_id)
            return { uids: [] } unless mailbox

            doomed, kept = mailbox[:messages].partition do |m|
              m[:flags].include?("\\Deleted") && (uids.nil? || uids.include?(m[:uid]))
            end
            mailbox[:messages] = kept
            removed = doomed.map { |m| m[:uid] }.sort
            add_tombstones(mailbox, removed)
            { uids: removed, highest_modseq: mailbox[:highest_modseq] }
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

        # QRESYNC: uids expunged after since_modseq. complete: false means
        # tombstone history was pruned past since_modseq, so the answer
        # falls back to every uid ever allocated but no longer present
        # (uids are never reused, so that set is correct, just larger).
        def expunged_since(mailbox_id, since_modseq)
          @lock.synchronize do
            mailbox = mailbox_by_id(mailbox_id)
            return { uids: [], complete: true } unless mailbox

            if since_modseq >= mailbox[:tombstone_floor]
              uids = mailbox[:tombstones].filter_map { |uid, modseq| uid if modseq > since_modseq }
              { uids: uids.sort.uniq, complete: true }
            else
              present = mailbox[:messages].map { |m| m[:uid] }
              { uids: (1...mailbox[:uid_next]).to_a - present, complete: false }
            end
          end
        end

        # Atomic copy+remove (RFC 6851 MOVE): the message never exists in
        # both mailboxes from an observer's point of view.
        def move(mailbox_id, uids, dest_name)
          @lock.synchronize do
            source = mailbox_by_id(mailbox_id)
            return internal_error("unknown mailbox") unless source

            account = @accounts.values.find { |a| a[:mailboxes].value?(source) }
            dest = find_mailbox(account, dest_name)
            return { error: "no such mailbox", code: :notfound } unless dest

            src_uids = []
            dest_uids = []
            moved = sorted(source).select { |m| uids.include?(m[:uid]) }
            moved.each do |m|
              copied = deliver_raw(dest, m[:raw], flags: m[:flags].dup, internal_date: m[:internal_date])
              src_uids << m[:uid]
              dest_uids << copied[:uid]
            end
            source[:messages] = source[:messages].reject { |m| src_uids.include?(m[:uid]) }
            add_tombstones(source, src_uids)
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
          { id: next_id(:mailbox), name: name, uid_validity: Time.now.to_i, uid_next: 1,
            highest_modseq: 1, messages: [], tombstones: [], tombstone_floor: 0 }
        end

        # Records [uid, modseq] for an expunged message, pruning history
        # beyond the limit; the floor remembers the highest pruned modseq
        # so expunged_since can tell precise answers from truncated ones.
        def add_tombstones(mailbox, uids)
          return if uids.empty?

          modseq = next_modseq(mailbox)
          uids.each { |uid| mailbox[:tombstones] << [ uid, modseq ] }
          overflow = mailbox[:tombstones].length - @tombstone_limit
          if overflow.positive?
            pruned = mailbox[:tombstones].shift(overflow)
            mailbox[:tombstone_floor] = [ mailbox[:tombstone_floor], pruned.map(&:last).max ].max
          end
          modseq
        end

        # Every mutation of a mailbox's contents gets the next per-mailbox
        # mod-sequence (RFC 7162 CONDSTORE).
        def next_modseq(mailbox)
          mailbox[:highest_modseq] += 1
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
            internal_date: internal_date,
            modseq: next_modseq(mailbox)
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

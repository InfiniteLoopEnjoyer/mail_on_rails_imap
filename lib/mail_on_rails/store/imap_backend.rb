# frozen_string_literal: true

require "active_support/key_generator"
require "mail_on_rails/clamav_scanner"
require "mail_on_rails/scram"

module MailOnRails
  module Store
    # The app-side implementation of the IMAP store contract: everything
    # the IMAP server is allowed to do, on Active Record, in the same
    # process as the unified mail server (see docs/store_contract.md).
    class ImapBackend < Base
      # Quarantine holds flagged malware and is reachable only through the
      # web review UI, never over IMAP: it is hidden from LIST and every
      # by-name operation resolves it to "no such mailbox", so a client can
      # neither SELECT/STATUS/APPEND it nor COPY/MOVE across it, and cannot
      # tell it apart from a name that was never created.
      def list_mailboxes(account_id)
        db do
          account = EmailAccount.find(account_id)
          { mailboxes: account.mailboxes.where.not(name: Mailbox::QUARANTINE).order(:name).pluck(:name) }
        end
      end

      def create_mailbox(account_id, name)
        db do
          # Quarantine is reserved: a client must not create one (which
          # would mix its own mail into the malware review folder) - report
          # the same collision as any existing name.
          next { error: "mailbox exists", code: :exists } if reserved_quarantine?(name)

          account = EmailAccount.find(account_id)
          next { error: "mailbox exists", code: :exists } if account.find_mailbox(name)

          mailbox = account.mailboxes.create!(name: name)
          { mailbox_object_id: mailbox_object_id(mailbox) }
        end
      end

      # MAILBOXID (RFC 8474): pk + uid_validity - survives rename, never
      # reused (pks are monotonic; validity disambiguates any reuse).
      def mailbox_object_id(mailbox)
        "M#{mailbox.id}-#{mailbox.uid_validity}"
      end

      def delete_mailbox(account_id, name)
        db do
          mailbox = find_visible_mailbox(EmailAccount.find(account_id), name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          mailbox.destroy!
          {}
        end
      end

      # Renames the mailbox and everything under it in the "/" hierarchy.
      def rename_mailbox(account_id, from, to)
        db do
          account = EmailAccount.find(account_id)
          # Quarantine is neither a rename source (invisible) nor a rename
          # target (reserved).
          next { error: "no such mailbox", code: :notfound } if reserved_quarantine?(from)
          next { error: "mailbox exists", code: :exists } if reserved_quarantine?(to)

          mailbox = account.find_mailbox(from)
          next { error: "no such mailbox", code: :notfound } unless mailbox
          next { error: "mailbox exists", code: :exists } if account.find_mailbox(to)

          Mailbox.transaction do
            prefix = "#{mailbox.name}/"
            # "!" as the explicit LIKE escape: SQLite has no default escape
            # character and MySQL double-processes backslashes.
            escaped = Mailbox.sanitize_sql_like(prefix, "!")
            account.mailboxes.where("name LIKE ? ESCAPE '!'", "#{escaped}%").find_each do |child|
              child.update!(name: to + child.name[mailbox.name.length..])
            end
            mailbox.update!(name: to)
          end
          {}
        end
      end

      def select_mailbox(account_id, name)
        db do
          mailbox = find_visible_mailbox(EmailAccount.find(account_id), name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          messages = mailbox.email_messages.order(:uid).map { |m| [ m.uid, m.flags, m.modseq ] }
          {
            mailbox_id: mailbox.id,
            name: mailbox.name,
            mailbox_object_id: mailbox_object_id(mailbox),
            uid_validity: mailbox.uid_validity,
            uid_next: mailbox.uid_next,
            highest_modseq: mailbox.highest_modseq,
            messages: messages
          }
        end
      end

      def status(account_id, name)
        db do
          mailbox = find_visible_mailbox(EmailAccount.find(account_id), name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          {
            messages: mailbox.email_messages.count,
            unseen: mailbox.unseen_count,
            uid_next: mailbox.uid_next,
            uid_validity: mailbox.uid_validity,
            highest_modseq: mailbox.highest_modseq,
            size: mailbox.email_messages.sum(:size),
            mailbox_object_id: mailbox_object_id(mailbox)
          }
        end
      end

      # Returns per-message metadata for the given UIDs; raw message bytes are
      # included only when requested (they can be large).
      def fetch(mailbox_id, uids, with_raw)
        db do
          scope = EmailMessage.where(mailbox_id: mailbox_id, uid: uids).order(:uid)
          messages = scope.map do |m|
            entry = {
              uid: m.uid,
              flags: m.flags,
              internal_date: m.internal_date.to_i,
              size: m.size,
              modseq: m.modseq,
              email_id: m.email_object_id,
              # THREADID (RFC 8474): resolved at delivery time from the
              # message's References/In-Reply-To ancestry.
              thread_id: m.thread_id,
              # SAVEDATE (RFC 8514): when the row entered this mailbox -
              # COPY/MOVE create fresh rows, so created_at is exactly it.
              saved_date: m.created_at.to_i
            }
            entry[:raw] = m.raw.to_s if with_raw
            entry
          end
          { messages: messages }
        end
      end

      # mode: "+" adds, "-" removes, "=" replaces. Flags are
      # case-insensitive atoms: adding a case-variant of a present flag is
      # a no-op (first-seen spelling kept), removal matches any case, and
      # a store that changes nothing claims no new modseq.
      def store_flags(mailbox_id, uids, mode, flags)
        db do
          updated = EmailMessage.where(mailbox_id: mailbox_id, uid: uids).map do |m|
            new_flags =
              case mode
              when "+" then m.flags + flags.reject { |f| m.flags.any? { |e| e.casecmp?(f) } }
              when "-" then m.flags.reject { |e| flags.any? { |f| e.casecmp?(f) } }
              else flags
              end
            m.update!(flags: new_flags) if new_flags.sort != m.flags.sort
            [ m.uid, m.flags, m.modseq ]
          end
          { messages: updated }
        end
      end

      # uids: nil removes every \Deleted message; a list restricts removal
      # to \Deleted messages with those UIDs (UID EXPUNGE).
      def expunge(mailbox_id, uids = nil)
        db do
          mailbox = Mailbox.find(mailbox_id)
          # The LIKE is only an index-free prefilter over the
          # JSON-serialized flags column (backslash-in-LIKE semantics
          # differ across adapters, so the pattern skips the "\"; LOWER
          # because IMAP flags are case-insensitive atoms and PostgreSQL's
          # LIKE is not); the Ruby check on the loaded rows is the exact,
          # case-insensitive (RFC 3501) match.
          deleted = EmailMessage.where(mailbox_id: mailbox_id)
                                .where("LOWER(flags) LIKE ?", "%deleted%")
                                .order(:uid)
          deleted = deleted.where(uid: uids) if uids
          deleted = deleted.select { |m| m.flags.any? { |f| f.casecmp?("\\Deleted") } }
          removed = deleted.map(&:uid)
          deleted.each(&:destroy!)
          # The post-expunge modseq rides the tagged OK as HIGHESTMODSEQ
          # (RFC 7162); tombstone recording above just advanced it.
          { uids: removed, highest_modseq: mailbox.reload.highest_modseq }
        end
      end

      # APPEND is an authenticated write path with no scan in front of it
      # (unlike inbound mail, which the mailroom scans), so it scans here
      # (whenever SMTP_CLAMAV_ADDR is configured). Infected uploads are
      # refused - the IMAP server renders the envelope as
      # "NO APPEND failed: ...". The refusal is deliberately generic: the
      # signature name goes to the server log only, because an APPEND that
      # echoes it hands an authenticated attacker (or a stolen mailbox
      # password) a fast oracle for tuning malware packing against the
      # scanner. A scanner outage answers NO [UNAVAILABLE] and the client
      # retries, mirroring the SMTP edge's 451 (imap_append_fail_closed,
      # default on). Deployments that would rather keep mail clients
      # working through clamd downtime - storing the user's own
      # Sent/Drafts copies flagged "unscanned" for the rescan job to catch
      # up on - set imap_append_fail_closed to 0 and accept that a stolen
      # mailbox password can park malware in Sent during the outage.
      #
      # The scan runs between two db blocks, never inside one: the executor
      # keeps its pool connection leased until the block completes, so a
      # slow clamd (up to the 10s scan timeout) inside the block would pin
      # a connection per concurrent APPEND and starve the pool.
      def append(account_id, mailbox_name, raw, flags, internal_date_epoch)
        mailbox = db { find_visible_mailbox(EmailAccount.find(account_id), mailbox_name) }
        return { error: "no such mailbox", code: :notfound } unless mailbox

        scan_status = nil
        if MailOnRails::ClamavScanner.enabled?
          result = MailOnRails::ClamavScanner.scan(raw)
          if result.infected?
            log(:warn, "IMAP APPEND refused for account #{account_id}: virus #{result.virus}")
            return { error: "message rejected: virus detected", code: :infected }
          end
          if result.unavailable? && Settings[:imap_append_fail_closed]
            log(:error, "IMAP APPEND deferred for account #{account_id}: virus scanner unavailable")
            return { error: "virus scanner unavailable, try again later", code: :unavailable }
          end
          scan_status = result.clean? ? "clean" : "unscanned"
        end

        db do
          internal_date = internal_date_epoch && Time.zone.at(internal_date_epoch)
          begin
            message = EmailMessage.deliver_raw(mailbox, raw, flags: flags, internal_date: internal_date,
                                               scan_status: scan_status)
          rescue EmailMessage::OverQuota => e
            next { error: e.message, code: :overquota }
          end
          { uid: message.uid, uid_validity: mailbox.uid_validity }
        end
      end

      def copy(mailbox_id, uids, dest_name)
        db do
          source = Mailbox.find(mailbox_id)
          dest = find_visible_mailbox(source.email_account, dest_name)
          next { error: "no such mailbox", code: :notfound } unless dest

          src_uids = []
          dest_uids = []
          begin
            # One transaction so an over-quota refusal midway leaves
            # nothing half-copied.
            EmailMessage.transaction do
              EmailMessage.where(mailbox_id: mailbox_id, uid: uids).order(:uid).each do |m|
                # Same bytes, same verdict - no rescan on copy.
                copied = EmailMessage.deliver_raw(dest, m.raw, flags: m.flags, internal_date: m.internal_date,
                                                  scan_status: m.scan_status, virus_name: m.virus_name)
                src_uids << m.uid
                dest_uids << copied.uid
              end
            end
          rescue EmailMessage::OverQuota => e
            next { error: e.message, code: :overquota }
          end
          { uid_validity: dest.uid_validity, src_uids: src_uids, dest_uids: dest_uids }
        end
      end

      # GETQUOTA/GETQUOTAROOT (RFC 2087/9208): the account's storage usage
      # and cap. limit_bytes nil = no quota configured.
      def quota(account_id)
        db do
          account = EmailAccount.find(account_id)
          { used_bytes: account.used_bytes, limit_bytes: account.quota_bytes }
        end
      end

      # QRESYNC: uids expunged after since_modseq. complete: false means
      # tombstone history was pruned past since_modseq; the fallback set
      # (every uid ever allocated but no longer present) is still correct,
      # just larger, because uids are never reused.
      def expunged_since(mailbox_id, since_modseq)
        db do
          mailbox = Mailbox.find(mailbox_id)
          if since_modseq >= mailbox.tombstone_floor
            uids = ExpungedMessage.where(mailbox_id: mailbox_id)
                                  .where("modseq > ?", since_modseq)
                                  .distinct.order(:uid).pluck(:uid)
            { uids: uids, complete: true }
          else
            present = EmailMessage.where(mailbox_id: mailbox_id).pluck(:uid)
            { uids: (1...mailbox.uid_next).to_a - present, complete: false }
          end
        end
      end

      # TEXT/BODY search pushdown (see the store contract), instead of
      # shipping every raw message to the IMAP session for a substring
      # scan. On PostgreSQL it matches against the GIN-indexed tsvector
      # over subject/from/to/body_text - word-level matching (the
      # Dovecot-style FTS trade-off the contract allows): whole words
      # always hit, mid-word substrings may not; scope "body" re-checks
      # candidates against a body-only vector, with the indexed match
      # narrowing first so the recompute touches a few rows, not the
      # mailbox. Other adapters use EmailMessage.like_search, whose
      # substring matching is strictly more generous - also allowed.
      def search_text(mailbox_id, query, scope)
        db do
          relation = EmailMessage.where(mailbox_id: mailbox_id)
          relation =
            if MailOnRails::AdapterSupport.postgresql?
              scoped = relation.where("search_vector @@ plainto_tsquery('simple', ?)", query)
              if scope.to_s == "body"
                scoped = scoped.where("to_tsvector('simple', coalesce(body_text, '')) @@ plainto_tsquery('simple', ?)",
                                      query)
              end
              scoped
            elsif scope.to_s == "body"
              relation.merge(EmailMessage.like_search(query, columns: %w[body_text]))
            else
              relation.merge(EmailMessage.like_search(query))
            end
          { uids: relation.order(:uid).pluck(:uid) }
        end
      end

      # RFC 6851 MOVE as one transaction: copy into the destination and
      # remove the source rows together, so a failure leaves the message
      # in exactly one mailbox.
      def move(mailbox_id, uids, dest_name)
        db do
          source = Mailbox.find(mailbox_id)
          dest = find_visible_mailbox(source.email_account, dest_name)
          next { error: "no such mailbox", code: :notfound } unless dest

          src_uids = []
          dest_uids = []
          EmailMessage.transaction do
            EmailMessage.where(mailbox_id: mailbox_id, uid: uids).order(:uid).each do |m|
              # Same bytes, same verdicts - no rescan on move (see move_to!).
              copied = m.move_to!(dest)
              src_uids << m.uid
              dest_uids << copied.uid
            end
          end
          { uid_validity: dest.uid_validity, src_uids: src_uids, dest_uids: dest_uids }
        end
      end

      private

      # Resolves a mailbox by name for IMAP, treating Quarantine as
      # nonexistent so it can never be SELECTed, STATUSed, APPENDed, or
      # used as a COPY/MOVE endpoint (see the class comment).
      def find_visible_mailbox(account, name)
        return nil if reserved_quarantine?(name)

        account.find_mailbox(name)
      end

      def reserved_quarantine?(name)
        name.to_s.casecmp?(Mailbox::QUARANTINE)
      end
    end
  end
end

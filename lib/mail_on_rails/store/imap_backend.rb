# frozen_string_literal: true

require "active_support/key_generator"
require "mail_on_rails/clamav_scanner"
require "mail_on_rails/junk_feedback"
require "mail_on_rails/scram"
require "mail_on_rails/imap/store/memory" # Imap::Store.missing_uid_ranges

module MailOnRails
  module Store
    # The app-side implementation of the IMAP store contract: everything
    # the IMAP server is allowed to do, on Active Record, in the same
    # process as the unified mail server (see docs/store_contract.md).
    class ImapBackend < Base
      # Rows loaded per query inside COPY/MOVE: the IMAP session already
      # batches what it asks for, but a store call must not load a whole
      # uid list of raw messages either.
      COPY_BATCH = 100
      # ...and no more than this many message bytes per batch (plus one
      # message): a hundred rows of mail at the size SMTP accepts would be
      # gigabytes in one result set.
      COPY_BATCH_BYTES = 32 * 1024 * 1024

      # The message's bytes (raw) and its extracted text (body_text) live
      # in the same table row as its uid and flags, and a full-row load
      # ships them: selecting a mailbox, a NOOP, every IDLE poll, a flag
      # change and an expunge each used to read the entire contents of
      # every message they touched - whatever anyone had mailed in - to
      # get at a few integers. Every query below that does not hand the
      # bytes to its caller names its columns.
      FETCH_COLUMNS = %i[id mailbox_id uid flags internal_date size modseq email_object_id thread_id created_at].freeze
      FLAG_COLUMNS = %i[id mailbox_id uid flags modseq].freeze
      EXPUNGE_COLUMNS = %i[id mailbox_id uid flags size].freeze

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
        rescue ActiveRecord::RecordInvalid => e
          unusable_mailbox_name(e)
        end
      end

      # The Mailbox model has the last word on what a folder may be called
      # (it guards every writer, not only IMAP), and its rules go beyond
      # what the session checks before calling: edge whitespace, a second
      # "inbox", a child that a parent's rename would push past the length
      # or depth bound. A name it refuses is the client's request being
      # declined - :cannot, which the session answers NO [CANNOT] - not a
      # store fault for db's handler to log at error level. The reason is
      # one of the model's own fixed strings, never client bytes. Anything
      # else that fails validation is still a fault and re-raised.
      def unusable_mailbox_name(invalid)
        errors = invalid.record.errors
        raise invalid if errors[:name].empty?
        # The uniqueness check losing a race with another session's CREATE.
        return { error: "mailbox exists", code: :exists } if errors.of_kind?(:name, :taken)

        { error: "invalid mailbox name (#{errors[:name].first})", code: :cannot }
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
        rescue ActiveRecord::RecordInvalid => e
          # Raised by the mailbox or by any child being renamed with it;
          # the transaction has rolled the whole rename back.
          unusable_mailbox_name(e)
        end
      end

      def select_mailbox(account_id, name)
        db do
          mailbox = find_visible_mailbox(EmailAccount.find(account_id), name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          messages = mailbox.email_messages.order(:uid).pluck(:uid, :flags, :modseq)
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
          scope = scope.select(*FETCH_COLUMNS, *(:raw if with_raw))
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
          updated = EmailMessage.where(mailbox_id: mailbox_id, uid: uids).select(*FLAG_COLUMNS).map do |m|
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
                                .select(*EXPUNGE_COLUMNS)
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
          # Some clients "move" with APPEND + \Deleted + EXPUNGE; an APPEND
          # into Junk is the user's spam verdict either way. DB writes and
          # an after-commit enqueue only - no network inside the db block.
          MailOnRails::JunkFeedback.filed(message, from: nil, to: mailbox, source: "imap")
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
              each_message_batch(mailbox_id, uids) do |m|
                # Same bytes, same verdict - no rescan on copy.
                copied = EmailMessage.deliver_raw(dest, m.raw, flags: m.flags, internal_date: m.internal_date,
                                                  scan_status: m.scan_status, virus_name: m.virus_name)
                # Clients without MOVE emulate it as COPY + \Deleted +
                # EXPUNGE, so a COPY across the Junk boundary is the same
                # verdict a MOVE is (JunkFeedback decides which).
                MailOnRails::JunkFeedback.filed(copied, from: source, to: dest, source: "imap")
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
      # just larger, because uids are never reused - so it is reported as
      # [lo, hi] gaps under :ranges, sized by the mailbox rather than by
      # uid_next (see Imap::Store.missing_uid_ranges).
      def expunged_since(mailbox_id, since_modseq)
        db do
          mailbox = Mailbox.find(mailbox_id)
          if since_modseq >= mailbox.tombstone_floor
            uids = ExpungedMessage.where(mailbox_id: mailbox_id)
                                  .where("modseq > ?", since_modseq)
                                  .distinct.order(:uid).pluck(:uid)
            { uids: uids, complete: true }
          else
            present = EmailMessage.where(mailbox_id: mailbox_id).order(:uid).pluck(:uid)
            { ranges: MailOnRails::Imap::Store.missing_uid_ranges(present, mailbox.uid_next), complete: false }
          end
        end
      end

      # FROM/TO/SUBJECT search pushdown (see the store contract), from the
      # columns deliver_raw extracts at delivery: substring, case-
      # insensitive, every word of a multi-word query required (the
      # like_search semantics TEXT/BODY already accept on non-PostgreSQL
      # adapters). The address columns hold addresses, not display names,
      # so FROM/TO match the address part - the trade-off that keeps a
      # header search from shipping every raw message to the session.
      HEADER_SEARCH_COLUMNS = { "subject" => "subject", "from" => "from_address", "to" => "to_addresses" }.freeze

      def search_header(mailbox_id, field, query)
        column = HEADER_SEARCH_COLUMNS[field.to_s.downcase]
        return { uids: [] } unless column

        db do
          relation = EmailMessage.where(mailbox_id: mailbox_id).merge(EmailMessage.like_search(query, columns: [ column ]))
          { uids: relation.order(:uid).pluck(:uid) }
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

      # Columns search_meta reads; the datetime ones take an epoch-second
      # Range that is widened to Time so the adapter compares timestamps.
      META_SEARCH_COLUMNS = {
        "size" => :size, "internal_date" => :internal_date, "saved_date" => :created_at,
        "email_id" => :email_object_id, "thread_id" => :thread_id
      }.freeze
      META_TIME_COLUMNS = %i[internal_date created_at].freeze

      # Size/date/id search pushdown (see the store contract): one indexed
      # query instead of the session paging every message's metadata to
      # compare a column itself. +value+ is an integer Range (bytes, or
      # epoch seconds, either end open) or an exact id string.
      def search_meta(mailbox_id, field, value)
        column = META_SEARCH_COLUMNS[field.to_s]
        return { uids: [] } unless column

        db do
          if value.is_a?(Range) && META_TIME_COLUMNS.include?(column)
            value = Range.new(value.begin && Time.zone.at(value.begin), value.end && Time.zone.at(value.end),
                              value.exclude_end?)
          end
          { uids: EmailMessage.where(mailbox_id: mailbox_id, column => value).order(:uid).pluck(:uid) }
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
            each_message_batch(mailbox_id, uids) do |m|
              # Same bytes, same verdicts - no rescan on move (see move_to!,
              # which also records a move across the Junk boundary as the
              # user's spam verdict).
              copied = m.move_to!(dest, source: "imap")
              src_uids << m.uid
              dest_uids << copied.uid
            end
          end
          { uid_validity: dest.uid_validity, src_uids: src_uids, dest_uids: dest_uids }
        end
      end

      private

      # Yields the mailbox's messages for +uids+ in uid order, as full
      # rows (COPY and MOVE need the bytes and every recorded verdict),
      # loading at most COPY_BATCH rows and COPY_BATCH_BYTES of message
      # (plus one message) per query: the sizes are read first, without
      # the bytes, and the batches cut from them. The uid list is sliced
      # in Ruby rather than find_each'd so the order stays by uid, not
      # primary key.
      def each_message_batch(mailbox_id, uids, &block)
        uids.sort.each_slice(COPY_BATCH) do |slice|
          sizes = EmailMessage.where(mailbox_id: mailbox_id, uid: slice).order(:uid).pluck(:uid, :size)
          byte_bounded_batches(sizes).each do |batch|
            EmailMessage.where(mailbox_id: mailbox_id, uid: batch).order(:uid).each(&block)
          end
        end
      end

      # [[uid, size], ...] cut into uid lists of at most COPY_BATCH_BYTES
      # each (a single larger message is a batch of its own).
      def byte_bounded_batches(sizes)
        batches = []
        bytes = 0
        sizes.each do |uid, size|
          if batches.empty? || bytes + size.to_i > COPY_BATCH_BYTES
            batches << []
            bytes = 0
          end
          batches.last << uid
          bytes += size.to_i
        end
        batches
      end

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

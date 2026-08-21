# frozen_string_literal: true

module MailOnRails
  module Imap
    module Store
      # Executable form of the IMAP side of the store contract - the
      # authoritative spec of what a backing store must provide (the SMTP
      # side lives in the mail_on_rails_smtp gem). Include Contracts::Imap
      # in a Minitest test class and provide:
      #
      #   build_store(**)                    -> the store under test
      #   create_account(email:, password:)  -> account id, provisioned however
      #                                         the implementation stores accounts
      #
      # Any store passing this suite is interchangeable in front of the
      # IMAP server - it runs against Store::Memory in this gem, and a host
      # app can run it against its own adapters.
      module Contracts
        module Helpers
          EMAIL = "user@example.test"
          PASSWORD = "correct-horse-battery"

          def store
            @store ||= build_store
          end

          def account_id
            @account_id ||= create_account(email: EMAIL, password: PASSWORD)
          end
        end

        module Shared
          include Helpers

          def test_authenticate_returns_id_and_normalized_email
            account_id
            result = store.authenticate(EMAIL, PASSWORD)
            assert result[:account_id], "expected an account_id"
            assert_equal EMAIL, result[:email]
          end

          def test_authenticate_is_case_and_whitespace_insensitive_on_email
            account_id
            result = store.authenticate("  #{EMAIL.upcase}  ", PASSWORD)
            assert_equal EMAIL, result[:email]
          end

          def test_authenticate_rejects_wrong_password
            account_id
            result = store.authenticate(EMAIL, "wrong")
            assert_nil result[:account_id]
            assert_nil result[:email]
          end

          def test_authenticate_rejects_unknown_account
            result = store.authenticate("nobody@example.test", PASSWORD)
            assert_nil result[:account_id]
            assert_nil result[:email]
          end

          def test_log_returns_nil
            assert_nil store.log(:info, "contract check")
          end

          # -- brute-force throttling ------------------------------------------
          # A store must refuse credential checks for an address or account
          # that has failed too often, independently of any per-connection
          # cap the protocol server applies (that one bounds a single
          # connection; this one bounds an attacker who reconnects). Limits
          # and windows are the implementation's to choose, so these tests
          # discover the limit rather than assume one.

          # Fails auth until the store throttles, up to +within+ attempts.
          # Returns the throttled result, or nil if it never throttled.
          def fail_until_throttled(ip: "203.0.113.9", email: EMAIL, within: 60)
            within.times do
              result = store.authenticate(email, "definitely-not-the-password", ip: ip)
              return result if result[:throttled]
            end
            nil
          end

          def test_a_single_failed_login_is_not_throttled
            account_id
            result = store.authenticate(EMAIL, "wrong", ip: "203.0.113.9")
            assert_nil result[:throttled], "one failure must not throttle"
          end

          def test_repeated_failed_logins_are_throttled_with_a_retry_after
            account_id
            result = fail_until_throttled
            assert result, "expected repeated failures to be throttled"
            assert_operator result[:retry_after], :>, 0, "a throttled result must say how long to wait"
            assert_nil result[:account_id]
          end

          # The whole point: once throttled, knowing the password is not
          # enough. Otherwise an attacker who guesses right on attempt 500
          # still wins.
          def test_a_throttled_caller_is_refused_even_with_the_correct_password
            account_id
            assert fail_until_throttled, "expected repeated failures to be throttled"

            result = store.authenticate(EMAIL, PASSWORD, ip: "203.0.113.9")
            assert result[:throttled], "a live block must outrank correct credentials"
            assert_nil result[:account_id]
          end

          # Salt and iteration count are all a SCRAM client gets before it
          # proves anything, and they are enough to grind a password
          # offline. A throttled caller must not receive them.
          def test_scram_credentials_are_refused_while_throttled
            account_id
            assert fail_until_throttled, "expected repeated failures to be throttled"

            result = store.scram_credentials(EMAIL, ip: "203.0.113.9")
            assert result[:throttled], "verifier material must not be served mid-block"
            assert_nil result[:salt_base64]
          end

          # Throttling one identity must not lock out everyone else, or the
          # control becomes a denial-of-service tool.
          def test_throttling_is_scoped_to_the_offending_ip_and_account
            account_id
            other = create_account(email: "bystander@example.test", password: PASSWORD)
            assert other, "contract host must provision a second account"
            assert fail_until_throttled(ip: "203.0.113.9", email: EMAIL)

            result = store.authenticate("bystander@example.test", PASSWORD, ip: "198.51.100.4")
            assert_nil result[:throttled], "an unrelated account from an unrelated ip must be unaffected"
            assert result[:account_id]
          end

          # Failures the protocol server adjudicates itself (a bad SCRAM
          # proof never reaches the store) still have to count, or SCRAM is
          # an unthrottled path around the LOGIN throttle.
          def test_record_auth_failure_counts_toward_the_throttle
            account_id
            60.times do
              store.record_auth_failure(EMAIL, ip: "203.0.113.9")
              break if store.authenticate(EMAIL, PASSWORD, ip: "203.0.113.9")[:throttled]
            end

            result = store.authenticate(EMAIL, PASSWORD, ip: "203.0.113.9")
            assert result[:throttled], "reported failures must feed the same counter"
          end

          # A user who mistypes and then gets it right must not accumulate
          # toward a lockout across the day.
          def test_a_successful_login_clears_the_accounts_failure_count
            account_id
            3.times { store.authenticate(EMAIL, "wrong", ip: "203.0.113.9") }
            assert store.authenticate(EMAIL, PASSWORD, ip: "203.0.113.9")[:account_id]

            # The counter restarted, so the next run of failures gets a full
            # budget rather than tripping early.
            3.times do
              assert_nil store.authenticate(EMAIL, "wrong", ip: "198.51.100.9")[:throttled]
            end
          end

          def test_scram_credentials_derive_from_the_account_password
            require "mail_on_rails/scram"
            account_id
            creds = store.scram_credentials(EMAIL)
            assert_equal account_id, creds[:account_id]
            assert_equal EMAIL, creds[:email]
            assert_operator creds[:iterations], :>=, 4096

            expected = MailOnRails::Scram.derive(
              PASSWORD, salt: creds[:salt_base64].unpack1("m0"), iterations: creds[:iterations]
            )
            assert_equal [ expected[:stored_key] ].pack("m0"), creds[:stored_key_base64]
            assert_equal [ expected[:server_key] ].pack("m0"), creds[:server_key_base64]
          end

          # An unknown account must not be distinguishable from a real one:
          # the store hands back verifier-shaped decoy material (no
          # account_id) rather than a miss, so the AUTHENTICATE exchange
          # is byte-identical and the server can't be a username oracle.
          def test_scram_credentials_for_an_unknown_account_are_decoy_material
            first = store.scram_credentials("nobody@example.test")
            assert_nil first[:account_id], "an unknown account must not resolve to a real one"
            assert_nil first[:code], "an unknown account must not signal :notfound"
            assert first[:salt_base64], "decoy salt must be present, like a real account's"
            assert_operator first[:iterations], :>=, 4096

            second = store.scram_credentials("nobody@example.test")
            assert_equal first[:salt_base64], second[:salt_base64],
                         "the decoy salt must be stable per username"
            other = store.scram_credentials("someone-else@example.test")
            assert first[:salt_base64] != other[:salt_base64],
                   "different unknown usernames get different decoy salts"
          end
        end

        module Imap
          include Shared

          RAW_CRLF = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"
          RAW_BARE_LF = "From: a@b.test\nSubject: hi\n\nbody\n"

          def test_new_account_has_inbox
            assert_includes store.list_mailboxes(account_id)[:mailboxes], "INBOX"
          end

          def test_list_mailboxes_is_sorted_and_grows_with_create
            assert_nil store.create_mailbox(account_id, "Archive")[:error]
            names = store.list_mailboxes(account_id)[:mailboxes]
            assert_includes names, "Archive"
            assert_equal names.sort, names
          end

          def test_create_mailbox_rejects_duplicates_including_inbox_case
            assert_equal :exists, store.create_mailbox(account_id, "inbox")[:code]
          end

          def test_delete_mailbox_removes_it
            store.create_mailbox(account_id, "Zed")
            store.append(account_id, "Zed", RAW_CRLF, [], nil)
            assert_empty store.delete_mailbox(account_id, "Zed")
            refute_includes store.list_mailboxes(account_id)[:mailboxes], "Zed"
            assert_equal :notfound, store.delete_mailbox(account_id, "Zed")[:code]
          end

          def test_rename_mailbox_renames_children_and_keeps_messages
            store.create_mailbox(account_id, "Work")
            store.create_mailbox(account_id, "Work/2025")
            uid = store.append(account_id, "Work", RAW_CRLF, [], nil)[:uid]

            assert_empty store.rename_mailbox(account_id, "Work", "Job")
            names = store.list_mailboxes(account_id)[:mailboxes]
            assert_includes names, "Job"
            assert_includes names, "Job/2025"
            refute_includes names, "Work"
            assert_equal [ uid ], store.select_mailbox(account_id, "Job")[:messages].map(&:first)
          end

          def test_rename_mailbox_rejects_missing_source_and_existing_target
            store.create_mailbox(account_id, "A")
            assert_equal :notfound, store.rename_mailbox(account_id, "Nope", "B")[:code]
            assert_equal :exists, store.rename_mailbox(account_id, "A", "Trash")[:code]
          end

          def test_expunged_since_reports_tombstones_by_modseq
            first = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Deleted" ], nil)[:uid]
            keep = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            assert_equal [], store.expunged_since(mailbox_id, 0)[:uids]

            before = store.status(account_id, "INBOX")[:highest_modseq]
            store.expunge(mailbox_id)
            result = store.expunged_since(mailbox_id, before)
            assert_equal [ first ], result[:uids]
            assert result[:complete]

            # Nothing vanished after the expunge itself.
            after = store.status(account_id, "INBOX")[:highest_modseq]
            assert_equal [], store.expunged_since(mailbox_id, after)[:uids]

            # MOVE leaves tombstones too.
            store.move(mailbox_id, [ keep ], "Trash")
            assert_equal [ first, keep ].sort, store.expunged_since(mailbox_id, before)[:uids].sort
          end

          def test_move_transfers_messages_with_fresh_uids
            uid = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Seen" ], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            assert_equal :notfound, store.move(mailbox_id, [ uid ], "Nope")[:code]

            result = store.move(mailbox_id, [ uid ], "Trash")
            assert_equal [ uid ], result[:src_uids]
            assert_equal 1, result[:dest_uids].size
            assert_equal [], store.select_mailbox(account_id, "INBOX")[:messages]

            trash_id = store.select_mailbox(account_id, "Trash")[:mailbox_id]
            moved = store.fetch(trash_id, result[:dest_uids], true)[:messages].first
            assert_equal RAW_CRLF, moved[:raw]
            assert_equal [ "\\Seen" ], moved[:flags]
          end

          def test_select_mailbox_shape_and_inbox_case_insensitivity
            result = store.select_mailbox(account_id, "inbox")
            assert result[:mailbox_id]
            assert_equal "INBOX", result[:name]
            assert_kind_of Integer, result[:uid_validity]
            assert_equal 1, result[:uid_next]
            assert_equal [], result[:messages]
          end

          def test_select_mailbox_unknown_is_notfound
            assert_equal :notfound, store.select_mailbox(account_id, "Nope")[:code]
          end

          def test_append_assigns_ascending_uids_and_bumps_uid_next
            assert_equal 1, store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            assert_equal 2, store.append(account_id, "INBOX", RAW_CRLF, [ "\\Seen" ], nil)[:uid]

            result = store.select_mailbox(account_id, "INBOX")
            assert_equal 3, result[:uid_next]
            assert_equal [ [ 1, [] ], [ 2, [ "\\Seen" ] ] ],
                         result[:messages].map { |uid, flags, _modseq| [ uid, flags ] }
          end

          def test_modseq_tracks_mutations_and_highest_modseq
            store.append(account_id, "INBOX", RAW_CRLF, [], nil)
            store.append(account_id, "INBOX", RAW_CRLF, [], nil)

            result = store.select_mailbox(account_id, "INBOX")
            modseqs = result[:messages].map(&:last)
            assert modseqs.all? { |m| m.is_a?(Integer) && m.positive? }, "per-message modseq required"
            assert_equal modseqs, modseqs.sort, "modseq must be ascending with delivery order"
            assert_operator result[:highest_modseq], :>=, modseqs.max

            mailbox_id = result[:mailbox_id]
            before = result[:highest_modseq]
            updated = store.store_flags(mailbox_id, [ 1 ], "+", [ "\\Seen" ])[:messages].first
            assert_operator updated[2], :>, before, "flag change must advance the message's modseq"

            after = store.select_mailbox(account_id, "INBOX")
            assert_operator after[:highest_modseq], :>=, updated[2]
            assert_equal after[:highest_modseq], store.status(account_id, "INBOX")[:highest_modseq]

            store.store_flags(mailbox_id, [ 2 ], "+", [ "\\Deleted" ])
            highest = store.status(account_id, "INBOX")[:highest_modseq]
            store.expunge(mailbox_id)
            assert_operator store.status(account_id, "INBOX")[:highest_modseq], :>, highest,
                            "expunge must advance HIGHESTMODSEQ"
          end

          def test_store_flags_matches_case_insensitively_and_skips_noop_modseq
            uid = store.append(account_id, "INBOX", RAW_CRLF, [ "custom1" ], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]
            before = store.status(account_id, "INBOX")[:highest_modseq]

            # Flags are case-insensitive atoms: a case-variant add changes
            # nothing, and a store that changes nothing must not claim a
            # new modseq (clients would re-sync unchanged messages).
            result = store.store_flags(mailbox_id, [ uid ], "+", [ "Custom1" ])
            assert_equal [ "custom1" ], result[:messages].first[1]
            assert_equal before, store.status(account_id, "INBOX")[:highest_modseq],
                         "no-op flag store must not advance HIGHESTMODSEQ"

            # A case-variant removal still matches the stored flag.
            result = store.store_flags(mailbox_id, [ uid ], "-", [ "CUSTOM1" ])
            assert_equal [], result[:messages].first[1]
            assert_operator store.status(account_id, "INBOX")[:highest_modseq], :>, before
          end

          def test_status_reports_total_message_size
            assert_equal 0, store.status(account_id, "INBOX")[:size]

            store.append(account_id, "INBOX", RAW_CRLF, [], nil)
            store.append(account_id, "INBOX", RAW_BARE_LF, [], nil) # normalized to CRLF size
            assert_equal 2 * RAW_CRLF.bytesize, store.status(account_id, "INBOX")[:size],
                         "STATUS=SIZE needs the summed message sizes"
          end

          # objectid grammar: 1*255(ALPHA / DIGIT / "_" / "-") (RFC 8474).
          OBJECTID_RE = /\A[A-Za-z0-9_-]{1,255}\z/

          def test_mailbox_object_ids_are_stable_and_distinct
            created = store.create_mailbox(account_id, "Stable")[:mailbox_object_id]
            assert_match OBJECTID_RE, created

            selected = store.select_mailbox(account_id, "Stable")
            assert_equal created, selected[:mailbox_object_id]
            assert_equal created, store.status(account_id, "Stable")[:mailbox_object_id]

            # MAILBOXID survives rename and differs between mailboxes.
            store.rename_mailbox(account_id, "Stable", "Moved")
            assert_equal created, store.select_mailbox(account_id, "Moved")[:mailbox_object_id]
            refute_equal created, store.select_mailbox(account_id, "INBOX")[:mailbox_object_id]
          end

          def test_email_ids_are_content_derived_and_survive_copy_and_move
            uid = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            other = store.append(account_id, "INBOX", "X: y\r\n\r\ndifferent\r\n", [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            entries = store.fetch(mailbox_id, [ uid, other ], false)[:messages]
            first, second = entries.map { |e| e[:email_id] }
            assert_match OBJECTID_RE, first
            refute_equal first, second, "different content must get different EMAILIDs"

            # RFC 8474: the destination of COPY/MOVE keeps the EMAILID.
            copied = store.copy(mailbox_id, [ uid ], "Trash")
            trash_id = store.select_mailbox(account_id, "Trash")[:mailbox_id]
            assert_equal first, store.fetch(trash_id, copied[:dest_uids], false)[:messages].first[:email_id]

            moved = store.move(mailbox_id, [ uid ], "Archive2") if store.create_mailbox(account_id, "Archive2")
            assert_equal first,
                         store.fetch(store.select_mailbox(account_id, "Archive2")[:mailbox_id],
                                     moved[:dest_uids], false)[:messages].first[:email_id]
          end

          def test_thread_ids_group_replies_and_split_strangers
            root = "Message-Id: <root@x.test>\r\nSubject: hi\r\n\r\nhello\r\n"
            reply = "Message-Id: <r1@x.test>\r\nIn-Reply-To: <root@x.test>\r\n" \
                    "References: <root@x.test>\r\nSubject: Re: hi\r\n\r\nyo\r\n"
            other = "Message-Id: <other@x.test>\r\nSubject: unrelated\r\n\r\nbye\r\n"
            uids = [ root, reply, other ].map { |raw| store.append(account_id, "INBOX", raw, [], nil)[:uid] }
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            entries = store.fetch(mailbox_id, uids, false)[:messages]
            thread_ids = entries.map { |e| e[:thread_id] }
            assert thread_ids.all? { |t| t&.match?(OBJECTID_RE) }, "THREADID must use the objectid grammar"
            assert_equal thread_ids[0], thread_ids[1], "a reply joins its ancestor's thread"
            refute_equal thread_ids[0], thread_ids[2], "unrelated messages get their own thread"
          end

          def test_thread_ids_converge_when_a_reply_arrives_first
            reply = "Message-Id: <r1@x.test>\r\nReferences: <root@x.test>\r\nSubject: Re: hi\r\n\r\nyo\r\n"
            root = "Message-Id: <root@x.test>\r\nSubject: hi\r\n\r\nhello\r\n"
            first = store.append(account_id, "INBOX", reply, [], nil)[:uid]
            second = store.append(account_id, "INBOX", root, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            entries = store.fetch(mailbox_id, [ first, second ], false)[:messages]
            assert_equal entries[0][:thread_id], entries[1][:thread_id],
                         "out-of-order delivery must still converge on one thread"
          end

          def test_thread_ids_are_account_wide_so_copies_stay_in_thread
            raw = "Message-Id: <root@x.test>\r\nSubject: hi\r\n\r\nhello\r\n"
            uid = store.append(account_id, "INBOX", raw, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]
            original = store.fetch(mailbox_id, [ uid ], false)[:messages].first

            copied = store.copy(mailbox_id, [ uid ], "Trash")
            trash_id = store.select_mailbox(account_id, "Trash")[:mailbox_id]
            copy = store.fetch(trash_id, copied[:dest_uids], false)[:messages].first
            assert_equal original[:thread_id], copy[:thread_id]
          end

          def test_fetch_reports_saved_date
            uid = store.append(account_id, "INBOX", RAW_CRLF, [], 1_000_000)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            entry = store.fetch(mailbox_id, [ uid ], false)[:messages].first
            assert_kind_of Integer, entry[:saved_date]
            # SAVEDATE is when the message entered the mailbox (now), not
            # the INTERNALDATE the client supplied (1970).
            assert_operator entry[:saved_date], :>, entry[:internal_date]
          end

          def test_expunge_reports_the_updated_highest_modseq
            store.append(account_id, "INBOX", RAW_CRLF, [ "\\Deleted" ], nil)
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]
            before = store.status(account_id, "INBOX")[:highest_modseq]

            # The IMAP server needs the post-expunge value for the
            # RFC 7162 HIGHESTMODSEQ response code on the tagged OK.
            result = store.expunge(mailbox_id)
            assert_operator result[:highest_modseq], :>, before
            assert_equal store.status(account_id, "INBOX")[:highest_modseq], result[:highest_modseq]
          end

          def test_append_to_unknown_mailbox_is_notfound
            assert_equal :notfound, store.append(account_id, "Nope", RAW_CRLF, [], nil)[:code]
          end

          def test_append_normalizes_bare_lf_to_crlf
            uid = store.append(account_id, "INBOX", RAW_BARE_LF, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            entry = store.fetch(mailbox_id, [ uid ], true)[:messages].first
            assert_equal RAW_CRLF, entry[:raw]
            assert_equal RAW_CRLF.bytesize, entry[:size]
          end

          def test_fetch_returns_metadata_and_raw_only_on_request
            epoch = Time.now.to_i - 3600
            uid = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Seen" ], epoch)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            entry = store.fetch(mailbox_id, [ uid, 999 ], false)[:messages].first
            assert_equal uid, entry[:uid]
            assert_equal [ "\\Seen" ], entry[:flags]
            assert_equal epoch, entry[:internal_date]
            assert_equal RAW_CRLF.bytesize, entry[:size]
            refute entry.key?(:raw)

            assert_equal RAW_CRLF, store.fetch(mailbox_id, [ uid ], true)[:messages].first[:raw]
          end

          def test_store_flags_modes
            uid = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Seen" ], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            without_modseq = ->(result) { result[:messages].map { |u, flags, _modseq| [ u, flags ] } }
            assert_equal [ [ uid, [ "\\Seen", "\\Flagged" ] ] ],
                         without_modseq.call(store.store_flags(mailbox_id, [ uid ], "+", [ "\\Flagged" ]))
            assert_equal [ [ uid, [ "\\Flagged" ] ] ],
                         without_modseq.call(store.store_flags(mailbox_id, [ uid ], "-", [ "\\Seen" ]))
            assert_equal [ [ uid, [ "\\Draft" ] ] ],
                         without_modseq.call(store.store_flags(mailbox_id, [ uid ], "=", [ "\\Draft" ]))
          end

          def test_expunge_removes_only_deleted_flagged_messages
            keep = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            doomed = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Deleted" ], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            assert_equal [ doomed ], store.expunge(mailbox_id)[:uids]
            assert_equal [ keep ], store.select_mailbox(account_id, "INBOX")[:messages].map(&:first)
            assert_equal [], store.expunge(mailbox_id)[:uids]
          end

          def test_expunge_with_uids_removes_only_listed_deleted_messages
            first = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Deleted" ], nil)[:uid]
            second = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Deleted" ], nil)[:uid]
            undeleted = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            # Only \Deleted messages in the list go; an undeleted uid in the
            # list is ignored, an unlisted \Deleted one survives.
            assert_equal [ first ], store.expunge(mailbox_id, [ first, undeleted ])[:uids]
            assert_equal [ second, undeleted ],
                         store.select_mailbox(account_id, "INBOX")[:messages].map(&:first)
          end

          def test_status_counts_messages_and_unseen
            store.append(account_id, "INBOX", RAW_CRLF, [ "\\Seen" ], nil)
            store.append(account_id, "INBOX", RAW_CRLF, [], nil)

            result = store.status(account_id, "INBOX")
            assert_equal 2, result[:messages]
            assert_equal 1, result[:unseen]
            assert_equal 3, result[:uid_next]

            assert_equal :notfound, store.status(account_id, "Nope")[:code]
          end

          def test_copy_assigns_fresh_uids_in_destination
            uid = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Seen" ], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            result = store.copy(mailbox_id, [ uid ], "Trash")
            assert_equal [ uid ], result[:src_uids]
            assert_equal 1, result[:dest_uids].size

            trash_id = store.select_mailbox(account_id, "Trash")[:mailbox_id]
            copied = store.fetch(trash_id, result[:dest_uids], true)[:messages].first
            assert_equal RAW_CRLF, copied[:raw]
            assert_equal [ "\\Seen" ], copied[:flags]

            assert_equal :notfound, store.copy(mailbox_id, [ uid ], "Nope")[:code]
          end

          # -- search_text (optional TEXT/BODY pushdown) -----------------------
          # The contract asks for whole-word, case-insensitive matching at
          # minimum: scope "text" over at least the subject, address
          # headers and body text; scope "body" over the body only. A
          # store may match more generously (the memory store does exact
          # RFC 3501 substrings); it must never hit body-scope on text
          # that appears only in headers. Stores without search_text skip
          # these - the IMAP server falls back to its own substring scan.

          SEARCHABLE_RAW = "From: sender@example.test\r\nTo: rcpt@example.test\r\n" \
                           "Subject: quarterly numbers\r\n\r\nThe kumquat budget is ready.\r\n"
          UNRELATED_RAW = "From: other@example.test\r\nSubject: lunch\r\n\r\nSee you at noon.\r\n"

          def search_seed
            skip "store does not implement search_text" unless store.respond_to?(:search_text)
            uid = store.append(account_id, "INBOX", SEARCHABLE_RAW, [], nil)[:uid]
            store.append(account_id, "INBOX", UNRELATED_RAW, [], nil)
            [ store.select_mailbox(account_id, "INBOX")[:mailbox_id], uid ]
          end

          def test_search_text_matches_whole_words_case_insensitively
            mailbox_id, uid = search_seed
            assert_equal [ uid ], store.search_text(mailbox_id, "KUMQUAT", "text")[:uids]
            assert_equal [ uid ], store.search_text(mailbox_id, "kumquat", "body")[:uids]
            assert_equal [], store.search_text(mailbox_id, "zebra", "text")[:uids]
          end

          def test_search_text_requires_every_word_of_a_multiword_query
            mailbox_id, uid = search_seed
            assert_equal [ uid ], store.search_text(mailbox_id, "kumquat budget", "text")[:uids]
            assert_equal [], store.search_text(mailbox_id, "kumquat noon", "text")[:uids]
          end

          def test_search_text_body_scope_never_matches_header_only_text
            mailbox_id, uid = search_seed
            assert_equal [ uid ], store.search_text(mailbox_id, "quarterly", "text")[:uids]
            assert_equal [], store.search_text(mailbox_id, "quarterly", "body")[:uids]
          end

          def test_search_text_returns_ascending_uids_and_empty_for_unknown_mailbox
            mailbox_id, = search_seed
            third = store.append(account_id, "INBOX", SEARCHABLE_RAW, [], nil)[:uid]
            uids = store.search_text(mailbox_id, "kumquat", "text")[:uids]
            assert_includes uids, third
            assert_equal uids.sort, uids
            assert_equal [], store.search_text(-1, "kumquat", "text")[:uids]
          end

          # -- quota (optional storage accounting) ------------------------------
          # A store that implements quota(account_id) reports used_bytes
          # (the sum of stored message sizes, CRLF-normalized) and
          # limit_bytes (nil = unlimited), and refuses append/copy with
          # code :overquota when the write would exceed the limit. Moves
          # within the account are net-zero and stay exempt. Contract
          # hosts provide apply_quota(account_id, bytes) to set the limit
          # however their implementation stores it.

          def quota_seed(limit_bytes)
            skip "store does not implement quota" unless store.respond_to?(:quota)
            skip "contract host does not provide apply_quota" unless respond_to?(:apply_quota)
            apply_quota(account_id, limit_bytes)
          end

          def test_quota_reports_used_bytes_and_a_nil_limit_by_default
            skip "store does not implement quota" unless store.respond_to?(:quota)
            assert_equal({ used_bytes: 0, limit_bytes: nil }, store.quota(account_id))

            2.times { store.append(account_id, "INBOX", RAW_CRLF, [], nil) }
            assert_equal 2 * RAW_CRLF.bytesize, store.quota(account_id)[:used_bytes]
          end

          def test_append_is_refused_with_overquota_once_the_limit_is_reached
            quota_seed(RAW_CRLF.bytesize)
            assert_nil store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:error]

            result = store.append(account_id, "INBOX", RAW_CRLF, [], nil)
            assert_equal :overquota, result[:code]
            assert result[:error], "an over-quota refusal must carry a message"
            assert_equal RAW_CRLF.bytesize, store.quota(account_id)[:used_bytes]
          end

          def test_copy_is_refused_with_overquota_when_the_copy_would_not_fit
            quota_seed(RAW_CRLF.bytesize)
            uid = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            assert_equal :overquota, store.copy(mailbox_id, [ uid ], "Trash")[:code]
          end

          def test_move_within_the_account_is_exempt_from_quota
            quota_seed(RAW_CRLF.bytesize)
            uid = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            result = store.move(mailbox_id, [ uid ], "Trash")
            assert_nil result[:error], "a full account must still be able to file mail away"
            assert_equal RAW_CRLF.bytesize, store.quota(account_id)[:used_bytes]
          end
        end
      end
    end
  end
end

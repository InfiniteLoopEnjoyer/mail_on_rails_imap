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
        end

        module Imap
          include Shared

          RAW_CRLF = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"
          RAW_BARE_LF = "From: a@b.test\nSubject: hi\n\nbody\n"

          def test_new_account_has_inbox
            assert_includes store.list_mailboxes(account_id)[:mailboxes], "INBOX"
          end

          def test_list_mailboxes_is_sorted_and_grows_with_create
            assert_empty store.create_mailbox(account_id, "Archive")
            names = store.list_mailboxes(account_id)[:mailboxes]
            assert_includes names, "Archive"
            assert_equal names.sort, names
          end

          def test_create_mailbox_rejects_duplicates_including_inbox_case
            assert_equal :exists, store.create_mailbox(account_id, "inbox")[:code]
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
            assert_equal [ [ 1, [] ], [ 2, [ "\\Seen" ] ] ], result[:messages]
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

            assert_equal [ [ uid, [ "\\Seen", "\\Flagged" ] ] ],
                         store.store_flags(mailbox_id, [ uid ], "+", [ "\\Flagged" ])[:messages]
            assert_equal [ [ uid, [ "\\Flagged" ] ] ],
                         store.store_flags(mailbox_id, [ uid ], "-", [ "\\Seen" ])[:messages]
            assert_equal [ [ uid, [ "\\Draft" ] ] ],
                         store.store_flags(mailbox_id, [ uid ], "=", [ "\\Draft" ])[:messages]
          end

          def test_expunge_removes_only_deleted_flagged_messages
            keep = store.append(account_id, "INBOX", RAW_CRLF, [], nil)[:uid]
            doomed = store.append(account_id, "INBOX", RAW_CRLF, [ "\\Deleted" ], nil)[:uid]
            mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

            assert_equal [ doomed ], store.expunge(mailbox_id)[:uids]
            assert_equal [ keep ], store.select_mailbox(account_id, "INBOX")[:messages].map(&:first)
            assert_equal [], store.expunge(mailbox_id)[:uids]
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
        end
      end
    end
  end
end

# frozen_string_literal: true

require "logger"
require_relative "../internal_api"

module MailOnRails
  module Imap
    module Store
      # The IMAP server's store, implemented entirely over HTTP - the daemon
      # holds no database credentials. Every operation POSTs to the host
      # app's private API (InternalApi), which delegates to the app's own
      # store; raw message bytes are base64-framed both directions so
      # arbitrary binary survives JSON.
      #
      # If the app is unreachable, operations degrade to the store
      # contract's error envelope and the IMAP session reports a temporary
      # failure (see Store::Contracts). One HTTP round-trip per store
      # call - chatty for IMAP, accepted for the isolation.
      class Http
        # Names this edge in the app's attempt log (AuthAttempt).
        SOURCE = "imap"

        def initialize(api: nil, logger: Logger.new($stdout))
          @logger = logger
          @api = api || InternalApi.new
        end

        # -- worker Ractor support ---------------------------------------------
        # This store is an env-configured HTTP client plus a stdout logger, so
        # each worker Ractor can simply build its own instance; #worker_config
        # advertises that to Server (its presence selects Ractor mode) and
        # .from_config performs the rebuild inside the worker.

        def worker_config
          { store_class: self.class }
        end

        def self.from_config(_config = {})
          new(logger: Logger.new($stdout, progname: "mail_on_rails_imap"))
        end

        def log(level, message)
          @logger.public_send(level, "[mail_on_rails] #{message}")
          nil
        end

        def authenticate(email, password, ip: nil, source: SOURCE)
          wrap { @api.authenticate(email.to_s, password.to_s, ip: ip, source: source) }
        end

        def scram_credentials(email, ip: nil)
          op(:scram_credentials, email: email, ip: ip)
        end

        # SCRAM proofs are checked in the daemon, so the app only learns of
        # those failures when we report them - without this the SCRAM path
        # would be an unthrottled way around the LOGIN throttle.
        def record_auth_failure(email, ip: nil, source: SOURCE)
          op(:record_auth_failure, email: email, ip: ip, source: source)
        end

        def list_mailboxes(account_id)
          op(:list_mailboxes, account_id: account_id)
        end

        def create_mailbox(account_id, name)
          op(:create_mailbox, account_id: account_id, name: name)
        end

        def delete_mailbox(account_id, name)
          op(:delete_mailbox, account_id: account_id, name: name)
        end

        def rename_mailbox(account_id, from, to)
          op(:rename_mailbox, account_id: account_id, from: from, to: to)
        end

        def select_mailbox(account_id, name)
          op(:select_mailbox, account_id: account_id, name: name)
        end

        def status(account_id, name)
          op(:status, account_id: account_id, name: name)
        end

        def fetch(mailbox_id, uids, with_raw)
          op(:fetch, mailbox_id: mailbox_id, uids: uids, with_raw: with_raw)
        end

        def store_flags(mailbox_id, uids, mode, flags)
          op(:store_flags, mailbox_id: mailbox_id, uids: uids, mode: mode, flags: flags)
        end

        def expunge(mailbox_id, uids = nil)
          op(:expunge, mailbox_id: mailbox_id, uids: uids)
        end

        def append(account_id, mailbox_name, raw, flags, internal_date_epoch)
          op(:append, account_id: account_id, mailbox_name: mailbox_name,
                      raw_base64: [ raw.to_s ].pack("m0"), flags: flags,
                      internal_date_epoch: internal_date_epoch)
        end

        def copy(mailbox_id, uids, dest_name)
          op(:copy, mailbox_id: mailbox_id, uids: uids, dest_name: dest_name)
        end

        def move(mailbox_id, uids, dest_name)
          op(:move, mailbox_id: mailbox_id, uids: uids, dest_name: dest_name)
        end

        def expunged_since(mailbox_id, since_modseq)
          op(:expunged_since, mailbox_id: mailbox_id, since_modseq: since_modseq)
        end

        private

        def op(name, payload)
          wrap { @api.imap_op(name, payload) }
        end

        # Mirrors the app-side stores' error envelope, without the database.
        def wrap
          yield
        rescue InternalApi::Error => e
          @logger.error("[mail_on_rails] store error: #{e.message}")
          { error: e.message, code: e.code }
        rescue StandardError => e
          @logger.error("[mail_on_rails] store error: #{e.class}: #{e.message}")
          { error: "#{e.class}: #{e.message}", code: :internal }
        end
      end
    end
  end
end

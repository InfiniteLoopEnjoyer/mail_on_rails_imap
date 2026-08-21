# frozen_string_literal: true

# The IMAP protocol gem's entry point: loads the server tree and its
# ActiveRecord store, and registers the protocol with MailOnRails::Runtime
# so `plugin :mail_on_rails` / bin/mail_server can start it. Requiring this
# file is what makes IMAP "installed" - a host without it never boots an
# IMAP listener and the runtime rejects `--protocols imap` with a clear
# message.
#
# The server itself (ImapServer, Imap::Daemon, the memory store) stays
# Rails-free and is required directly by the protocol test suites; only
# this glue knows about the ActiveRecord backend.
require "mail_on_rails" # the core gem: models, settings, netserv, runtime
require_relative "imap/version"
require_relative "imap/daemon"
require_relative "store/imap_backend"
require "mail_on_rails/store/with_source"

module MailOnRails
  module Imap
    # Runtime adapter: how the core runtime starts, checks and preflights
    # IMAP. See MailOnRails::Runtime.register.
    module Protocol
      module_function

      def start(logger:, tls_dir:)
        store = MailOnRails::Store::WithSource.new(MailOnRails::Store::ImapBackend.new, "imap")
        Daemon.start(store: store, logger: logger, tls_dir: tls_dir)
      end

      def check_config(logger:)
        Daemon.check_config(logger: logger)
      end

      def preflight!
        require_explicit_tls!
      end

      # Production must never serve IMAP on the self-signed development
      # fallback (see Smtp::Protocol.require_explicit_tls!).
      def require_explicit_tls!
        return if Settings.static(:imap_tls_cert) || Settings.static(:imap_tls_key)

        raise "production requires explicit TLS material for the IMAP server " \
              "(self-signed fallback is development-only): set MAIL_ON_RAILS_TLS_CERT/MAIL_ON_RAILS_TLS_KEY"
      end
    end
  end

  Runtime.register(:imap, Imap::Protocol)
end

# frozen_string_literal: true

require "logger"
require "mail_on_rails/settings"
require "mail_on_rails/netserv/config"
require_relative "../imap_server"

module MailOnRails
  module Imap
    # Env-driven runtime for the IMAP server: builds the listener specs and
    # TLS material, then runs the server on a thread inside the host process
    # (the Rails app's Puma, via the :mail_on_rails plugin). The caller
    # injects the store - in the app that's the ActiveRecord-backed
    # MailOnRails::Store::ImapBackend.
    module Daemon
      # What start returns: the running server plus its thread, with the
      # lifecycle calls the host process needs (readiness before reporting
      # healthy, graceful shutdown from the Puma hooks).
      Handle = Struct.new(:server, :thread, keyword_init: true) do
        def ready? = server.ready?
        def wait_ready(timeout = 15) = server.wait_ready(timeout)
        def shutdown(drain: 5) = server.shutdown(drain: drain)
      end

      module_function

      # Boot preflight: validates the same configuration start would use
      # and logs a one-line summary. Returns true when bootable; fatal
      # problems log an error and return false. (Suspicious-but-runnable
      # settings are Settings::Check's department - the CLI's `check`
      # runs both.)
      def check_config(logger: default_logger)
        Settings.validate_env!
        host = Settings.static(:imap_host)
        specs = listeners(host)
        tls = Netserv::Tls.for(:imap).material(dir: Settings.static(:imap_tls_dir), logger: logger)
        tls_summary = tls ? (tls[:cert_path] ? "from #{tls[:cert_path]}" : "self-signed") : "UNAVAILABLE (plaintext only)"
        logger.info "[mail_on_rails] IMAP config OK: ports #{specs.map { |s| s[:port] }.join("/")} on #{host}, " \
                    "TLS #{tls_summary}"
        true
      rescue Netserv::Tls::Error, Netserv::Config::Error => e
        logger.error "[mail_on_rails] IMAP config error: #{e.message}"
        false
      end

      # Starts the server on a named thread and returns a Handle. A server
      # that dies logs the error and its thread ends; the embedding web
      # process carries on serving web requests.
      def start(store:, logger: default_logger, host: nil, tls_dir: nil)
        # Every declared variable is parsed here so a typo fails the boot
        # (as the old load-time constants did) rather than per connection.
        Settings.validate_env!
        host ||= Settings.static(:imap_host)
        specs = listeners(host)
        tls = tls_material(logger, tls_dir || Settings.static(:imap_tls_dir))

        logger.info "[mail_on_rails] IMAP #{specs.map { |s| s[:port] }.join("/")} on #{host}"
        server = ImapServer.new(store, specs, tls)
        thread = Thread.new do
          Thread.current.name = "mail_on_rails_imap"
          server.run
        rescue StandardError => e
          logger.error "[mail_on_rails] mail_on_rails_imap died: #{e.class}: #{e.message}"
        end
        Handle.new(server: server, thread: thread)
      end

      def listeners(host)
        specs = [
          { host: host, port: Settings.static(:imap_port), tls: :starttls },
          { host: host, port: Settings.static(:imaps_port), tls: :implicit }
        ]
        # Optional deceptive fingerprint in the greeting (see the SMTP daemon
        # and Netserv::HoneypotSession); unset = the real banner.
        if (banner = Settings.static(:honeypot_banner))
          specs.each { |spec| spec[:honeypot_banner] = banner }
        end
        ports = specs.map { |s| s[:port] }
        unless ports.uniq.size == ports.size
          raise Netserv::Config::Error, "listener ports must be distinct, got #{ports.join(", ")}"
        end

        specs
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      def tls_material(logger, dir)
        material = Netserv::Tls.for(:imap).material(dir: dir, logger: logger)
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_imap")
      end
    end
  end
end

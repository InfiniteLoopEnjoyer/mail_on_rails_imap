# frozen_string_literal: true

require "logger"
require_relative "../imap_server"
require_relative "tls"
require_relative "store/http"

module MailOnRails
  module Imap
    # Env-driven runtime for the IMAP server: builds the listener specs, TLS
    # material, and the HTTP-backed store, then runs the server on a thread.
    # Used two ways:
    #
    #   - bin/server in this repo (`Daemon.run!`), the foreground process the
    #     Kamal service runs - no Rails anywhere in the container. With the
    #     default HTTP store this serves sessions from one worker Ractor per
    #     core (see Imap::Server / Imap::Worker).
    #   - embedded in a host process via `Daemon.start` (e.g. a Rails app
    #     running the server inside Puma in development, passing its own
    #     store/logger). An injected store keeps sessions on worker threads
    #     in this process - Ractor workers can't share an in-process store.
    module Daemon
      module_function

      def run!(logger: default_logger)
        start(logger: logger).join
        # The server thread only returns once every listener has died - exit
        # non-zero so Docker restarts the container.
        logger.error "[mail_on_rails] IMAP server exited - shutting down"
        exit 1
      end

      # Starts the server on a named thread and returns it. A server that
      # dies logs the error and its thread ends; callers decide whether that
      # is fatal (run! exits, an embedding web process carries on).
      def start(logger: default_logger, store: nil, host: nil, tls_dir: nil)
        store ||= Store::Http.new(logger: logger)
        host ||= ENV.fetch("MAIL_ON_RAILS_HOST", "0.0.0.0")
        specs = listeners(host)
        tls = tls_material(logger, tls_dir || ENV.fetch("MAIL_ON_RAILS_TLS_DIR", "storage/tls"))

        logger.info "[mail_on_rails] IMAP #{specs.map { |s| s[:port] }.join("/")} on #{host}"
        Thread.new do
          Thread.current.name = "mail_on_rails_imap"
          ImapServer.run(store, specs, tls)
        rescue StandardError => e
          logger.error "[mail_on_rails] mail_on_rails_imap died: #{e.class}: #{e.message}"
        end
      end

      def listeners(host)
        [
          { host: host, port: env_port("MAIL_ON_RAILS_IMAP_PORT", 1143), tls: :starttls },
          { host: host, port: env_port("MAIL_ON_RAILS_IMAPS_PORT", 1993), tls: :implicit }
        ]
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      def tls_material(logger, dir)
        material = TLS.material(dir: dir, logger: logger)
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def env_port(name, default)
        Integer(ENV.fetch(name, default))
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_imap")
      end
    end
  end
end

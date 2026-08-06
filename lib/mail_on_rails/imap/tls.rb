# frozen_string_literal: true

require "openssl"
require "socket"
require "fileutils"

module MailOnRails
  module Imap
    # TLS material for the SMTP/IMAP servers.
    #
    # In production, point MAIL_ON_RAILS_TLS_CERT / MAIL_ON_RAILS_TLS_KEY at real PEM
    # files (e.g. from Let's Encrypt). In development, a self-signed cert is
    # generated once and cached under storage/tls so it stays stable across
    # restarts (a changing cert would re-trigger the iOS "untrusted" prompt).
    #
    # `material` runs at boot and returns plain PEM strings or file paths.
    # Each server then builds its own OpenSSL::SSL::SSLContext from them (via
    # ContextProvider); a single context instance is safely shared by that
    # server's connection threads.
    module TLS
      module_function

      # Returns TLS material (a Hash of plain strings) or nil if TLS can't be
      # provisioned. When MAIL_ON_RAILS_TLS_CERT/KEY are set, returns
      # { cert_path:, key_path: } so each server re-reads the files when the
      # cert is renewed (see ContextProvider); otherwise generates/loads a
      # self-signed cert under +dir+ and returns its PEMs inline as
      # { cert:, key: }. +dir+ and +logger+ are injected by the caller so this
      # module stays free of Rails (the store contract in the main
      # mail_on_rails app repo follows the same principle on the storage side).
      def material(dir: nil, logger: nil)
        cert_path = ENV["MAIL_ON_RAILS_TLS_CERT"]
        key_path = ENV["MAIL_ON_RAILS_TLS_KEY"]

        if cert_path && key_path
          context(cert: File.read(cert_path), key: File.read(key_path)) # fail at boot, not first connection
          { cert_path: cert_path, key_path: key_path }
        else
          load_or_generate_self_signed(dir, logger)
        end
      rescue StandardError => e
        logger&.error "[mail_on_rails] TLS material unavailable: #{e.class}: #{e.message}"
        nil
      end

      def load_or_generate_self_signed(dir, logger)
        raise ArgumentError, "MAIL_ON_RAILS_TLS_CERT/KEY unset and no self-signed dir given" unless dir

        cert_file = File.join(dir, "selfsigned.crt")
        key_file = File.join(dir, "selfsigned.key")

        if File.exist?(cert_file) && File.exist?(key_file)
          return { cert: File.read(cert_file), key: File.read(key_file) }
        end

        pems = generate_self_signed
        FileUtils.mkdir_p(dir)
        File.write(key_file, pems[:key])
        File.chmod(0o600, key_file)
        File.write(cert_file, pems[:cert])
        logger&.info "[mail_on_rails] generated self-signed TLS cert at #{cert_file}"
        pems
      end

      def generate_self_signed
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = 1
        cert.not_before = Time.now - 3600
        cert.not_after = Time.now + (10 * 365 * 24 * 3600)

        name = OpenSSL::X509::Name.parse("/CN=#{hostnames.first}")
        cert.subject = name
        cert.issuer = name
        cert.public_key = key.public_key

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert
        san = hostnames.map { |h| "DNS:#{h}" }.join(",")
        cert.add_extension(ef.create_extension("subjectAltName", san, false))
        cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
        cert.sign(key, OpenSSL::Digest.new("SHA256"))

        { cert: cert.to_pem, key: key.to_pem }
      end

      def hostnames
        hosts = ENV.fetch("MAIL_ON_RAILS_TLS_HOSTS", "localhost").split(",").map(&:strip)
        hosts << Socket.gethostname
        hosts.reject(&:empty?).uniq
      end

      # Builds an SSLContext from PEM strings.
      def context(material)
        ctx = OpenSSL::SSL::SSLContext.new
        # The cert PEM may hold a whole chain (Let's Encrypt fullchain.pem =
        # leaf + intermediate); clients need the extras served too. PKey.read
        # autodetects the key type - LE issues EC keys, our self-signed is RSA.
        chain = OpenSSL::X509::Certificate.load(material[:cert])
        ctx.add_certificate(chain.first, OpenSSL::PKey.read(material[:key]), chain.drop(1))
        ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
        # TLS 1.2 AEAD-only (no CBC, silences LUCKY13); TLS 1.3 suites are
        # AEAD by construction and unaffected by this list.
        ctx.ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20"
        # We never verify client certs; clients verify us (or accept self-signed).
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ctx.session_id_context = "mail_on_rails"
        ctx
      end

      # Thread-safe SSLContext source, one per server. For path-based material
      # (real certs), the files' mtimes are checked on each call and the
      # context is rebuilt after certbot renews them - no process restart
      # needed. PEM material (self-signed) is static.
      class ContextProvider
        def initialize(material)
          @cert_path = material[:cert_path]
          @key_path = material[:key_path]
          @mutex = Mutex.new
          @ctx = TLS.context(read_material(material))
          @mtimes = current_mtimes if @cert_path
        end

        def context
          return @ctx unless @cert_path

          @mutex.synchronize do
            mtimes = current_mtimes
            if mtimes != @mtimes
              @ctx = TLS.context(read_material(cert_path: @cert_path, key_path: @key_path))
              @mtimes = mtimes
            end
            @ctx
          end
        rescue StandardError
          @ctx # a failed reload (e.g. mid-renewal) keeps serving the old cert
        end

        private

        def read_material(material)
          if material[:cert_path]
            { cert: File.read(material[:cert_path]), key: File.read(material[:key_path]) }
          else
            material
          end
        end

        # File.stat follows symlinks, so a renewal that only repoints
        # live/*.pem into archive/ still changes these.
        def current_mtimes
          [ File.stat(@cert_path).mtime, File.stat(@key_path).mtime ]
        end
      end

      # Wraps an accepted plaintext socket in server-side TLS.
      def accept(raw_socket, ctx)
        ssl = OpenSSL::SSL::SSLSocket.new(raw_socket, ctx)
        ssl.sync_close = true
        ssl.accept
        ssl
      end
    end
  end
end

# frozen_string_literal: true

require "socket"
require_relative "conn_limiter"
require_relative "tls"

module MailOnRails
  module Imap
    # Shared listener scaffolding for the SMTP and IMAP servers: one accept
    # thread per listener spec, one thread per connection, a connection cap,
    # and TLS wrapping for implicit-TLS listeners. Keeping this in one place
    # means the connection-flood and TLS-accept behavior can't drift apart
    # between the two protocols.
    #
    # Subclasses define MAX_CONNECTIONS and the protocol specifics:
    # protocol_name, busy_line (sent when the connection cap is hit),
    # listener_label(spec) and new_session(socket, spec, ctx).
    class Server
      def self.run(store, listeners, tls_material)
        new(store, listeners, tls_material).run
      end

      def initialize(store, listeners, tls_material)
        @store = store
        @listeners = listeners
        @tls_material = tls_material
        @limiter = ConnLimiter.new(self.class::MAX_CONNECTIONS)
      end

      def run
        tls = @tls_material && TLS::ContextProvider.new(@tls_material)

        threads = @listeners.map do |spec|
          next if spec[:tls] == :implicit && tls.nil?

          Thread.new(spec) { |listener| accept_loop(listener, tls) }
        end.compact
        @store.log(:info, "#{protocol_name} listening: #{@listeners.map { |s| listener_label(s) }.join(", ")}")
        threads.each(&:join)
      end

      private

      def accept_loop(spec, tls)
        server = TCPServer.new(spec[:host], spec[:port])
        loop do
          raw = server.accept
          Thread.new(raw) { |sock| handle_connection(sock, spec, tls) }
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}")
      end

      def handle_connection(raw, spec, tls)
        unless @limiter.acquire
          begin
            raw.write("#{busy_line}\r\n")
            raw.close
          rescue StandardError
            nil
          end
          return
        end

        begin
          ctx = tls&.context # current cert snapshot; the session keeps it
          socket = spec[:tls] == :implicit ? TLS.accept(raw, ctx) : raw
          new_session(socket, spec, ctx).run
        rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
          raw.close rescue nil
        ensure
          @limiter.release
        end
      end
    end
  end
end

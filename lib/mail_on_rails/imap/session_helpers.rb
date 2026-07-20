# frozen_string_literal: true

module MailOnRails
  module Imap
    # Transport helpers shared by the SMTP and IMAP session classes. Both keep
    # the current socket in @socket, which is a plain TCPSocket until a TLS
    # upgrade swaps in an OpenSSL::SSL::SSLSocket.
    module SessionHelpers
      private

      # The underlying IO (an SSLSocket wraps the TCP socket it was built on).
      def io_for(socket)
        socket.respond_to?(:to_io) ? socket.to_io : socket
      end

      # Remote IP for log lines; memoized because STARTTLS swaps @socket.
      def peer_ip
        @peer_ip ||= io_for(@socket).remote_address.ip_address
      rescue StandardError
        "?"
      end

      def set_timeout(seconds)
        io = io_for(@socket)
        io.timeout = seconds if io.respond_to?(:timeout=)
      rescue StandardError
        nil
      end

      # RFC 4616 SASL PLAIN: base64("authzid\0authcid\0password"). Raises
      # ArgumentError on invalid base64 ("m0" unpacking is strict).
      def decode_sasl_plain(str)
        str.to_s.unpack1("m0").to_s.split("\0", 3)
      end
    end
  end
end

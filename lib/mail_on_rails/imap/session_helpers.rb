# frozen_string_literal: true

module MailOnRails
  module Imap
    # Transport helpers shared by the SMTP and IMAP session classes. Both keep
    # the current socket in @socket, which is a plain TCPSocket until a TLS
    # upgrade swaps in an OpenSSL::SSL::SSLSocket.
    module SessionHelpers
      # Raised for base64 a *client* sent that won't decode. Subclasses
      # ArgumentError, which is what strict "m0" unpacking raises, so a
      # caller that rescues ArgumentError keeps working; the point is to
      # give callers something narrower to catch. A blanket ArgumentError
      # rescue around an authentication exchange also swallows errors from
      # everything else in it - a store method called with the wrong
      # signature once surfaced to clients as "BAD Invalid base64".
      class InvalidBase64 < ArgumentError; end

      private

      # Strict base64 decode of client input. Use this (not bare unpack1)
      # wherever the bytes came off the wire; material that came from the
      # store should decode without wrapping, so a malformed verifier is
      # reported as a server error rather than blamed on the client.
      def decode_base64(str)
        str.to_s.unpack1("m0").to_s
      rescue ArgumentError
        raise InvalidBase64, "malformed base64"
      end

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
      # InvalidBase64 (an ArgumentError) on malformed input.
      def decode_sasl_plain(str)
        decode_base64(str).split("\0", 3)
      end
    end
  end
end

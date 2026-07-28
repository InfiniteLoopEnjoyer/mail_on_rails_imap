# frozen_string_literal: true

require "openssl"

module MailOnRails
  module Imap
    # SCRAM-SHA-256 primitives (RFC 5802 / RFC 7677), shared by the
    # server-side AUTHENTICATE exchange and by stores that derive
    # credentials from a plaintext password at password-set time.
    #
    # SASLprep (RFC 4013) is deliberately not applied: account emails and
    # passwords here are ASCII in practice, and net-imap's client applies
    # it only to non-ASCII input, which would then simply fail to match.
    module Scram
      DIGEST = "SHA256"
      KEY_LENGTH = 32
      ITERATIONS = 4096 # RFC 7677 minimum; the expensive PBKDF2 runs client-side

      module_function

      # => { salt:, iterations:, stored_key:, server_key: } (raw bytes)
      def derive(password, salt: OpenSSL::Random.random_bytes(16), iterations: ITERATIONS)
        salted = OpenSSL::KDF.pbkdf2_hmac(password.to_s, salt: salt, iterations: iterations,
                                          length: KEY_LENGTH, hash: DIGEST)
        client_key = hmac(salted, "Client Key")
        {
          salt: salt,
          iterations: iterations,
          stored_key: h(client_key),
          server_key: hmac(salted, "Server Key")
        }
      end

      # Verifies a client proof against the AuthMessage (RFC 5802 §3).
      # ClientKey = proof XOR HMAC(StoredKey, AuthMessage); valid iff
      # H(ClientKey) equals StoredKey.
      def valid_proof?(stored_key, auth_message, proof)
        return false unless proof.bytesize == stored_key.bytesize

        client_key = xor(proof, hmac(stored_key, auth_message))
        OpenSSL.fixed_length_secure_compare(h(client_key), stored_key)
      end

      def server_signature(server_key, auth_message)
        hmac(server_key, auth_message)
      end

      def hmac(key, data)
        OpenSSL::HMAC.digest(DIGEST, key, data)
      end

      def h(data)
        OpenSSL::Digest.digest(DIGEST, data)
      end

      def xor(a, b)
        a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack("C*")
      end
    end
  end
end

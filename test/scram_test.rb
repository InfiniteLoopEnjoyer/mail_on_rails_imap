require "test_helper"
require "mail_on_rails/imap/scram"

# The crypto is pinned to the worked example in RFC 7677 §3:
# user "user", password "pencil", the salts and nonces given there.
class ScramTest < Minitest::Test
  Scram = MailOnRails::Imap::Scram

  CLIENT_FIRST_BARE = "n=user,r=rOprNGfwEbeRWgbNEkqO"
  SERVER_FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," \
                 "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
  CLIENT_FINAL_BARE = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
  PROOF_B64 = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
  SERVER_SIG_B64 = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

  def credentials
    @credentials ||= Scram.derive("pencil", salt: "W22ZaJ0SNY7soEsUEjb6gQ==".unpack1("m0"), iterations: 4096)
  end

  def auth_message
    "#{CLIENT_FIRST_BARE},#{SERVER_FIRST},#{CLIENT_FINAL_BARE}"
  end

  def test_rfc7677_client_proof_verifies
    assert Scram.valid_proof?(credentials[:stored_key], auth_message, PROOF_B64.unpack1("m0"))
  end

  def test_rfc7677_server_signature_matches
    assert_equal SERVER_SIG_B64,
                 [ Scram.server_signature(credentials[:server_key], auth_message) ].pack("m0")
  end

  def test_wrong_password_fails_proof
    wrong = Scram.derive("pencils", salt: "W22ZaJ0SNY7soEsUEjb6gQ==".unpack1("m0"), iterations: 4096)
    refute Scram.valid_proof?(wrong[:stored_key], auth_message, PROOF_B64.unpack1("m0"))
  end

  def test_malformed_proof_length_is_rejected
    refute Scram.valid_proof?(credentials[:stored_key], auth_message, "short")
  end
end

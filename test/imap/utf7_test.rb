require "test_helper"
require "net/imap"
require "mail_on_rails/imap/utf7"

# The hand-rolled modified-UTF-7 codec is checked against net-imap's
# implementation as the oracle, both directions.
class Utf7Test < Minitest::Test
  Utf7 = MailOnRails::Imap::Utf7

  SAMPLES = [
    "INBOX",
    "Sent/2025",
    "Télécom",
    "日本語/メール",
    "a&b",
    "&",
    "&-already&AOk-encoded", # "&" and non-ASCII mixed
    "mail 📧 box",           # astral plane -> UTF-16 surrogate pair
    "ünïcode & slash/es"
  ].freeze

  def test_encode_matches_net_imap
    SAMPLES.each do |name|
      assert_equal Net::IMAP.encode_utf7(name), Utf7.encode(name), "encoding #{name.inspect}"
    end
  end

  def test_decode_matches_net_imap_and_round_trips
    SAMPLES.each do |name|
      encoded = Net::IMAP.encode_utf7(name)
      assert_equal Net::IMAP.decode_utf7(encoded), Utf7.decode(encoded), "decoding #{encoded.inspect}"
      assert_equal name, Utf7.decode(Utf7.encode(name)), "round-tripping #{name.inspect}"
    end
  end

  def test_decode_leaves_garbage_intact_rather_than_raising
    assert_equal "plain", Utf7.decode("plain")
    # Unterminated shift sequence: no "-" terminator, so nothing matches.
    assert_equal "&AOk", Utf7.decode("&AOk")
  end

  def test_encode_accepts_binary_encoded_utf8_bytes
    # Mailbox names arriving as IMAP literals are read as binary.
    assert_equal "T&AOk-l&AOk-com", Utf7.encode("Télécom".b)
  end
end

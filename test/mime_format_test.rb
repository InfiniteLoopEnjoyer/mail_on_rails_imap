require "test_helper"
require "mail_on_rails/mime"

# Locks in the response-format rules that strict clients (net-imap's
# parser in particular) hard-fail on: ENVELOPE address lists must be NIL
# when empty (never "()"), text parts must carry a trailing line count,
# and quoted/literal encoding must round-trip arbitrary values.
class MimeFormatTest < Minitest::Test
  Mime = MailOnRails::Mime

  def test_envelope_uses_nil_for_absent_and_unparseable_address_lists
    raw = "From: not an address at all\r\nSubject: hi\r\n\r\nbody\r\n"
    envelope = Mime.envelope(Mime.parse(raw))

    refute_includes envelope, "()", "empty address lists must be NIL, not ()"
    # date subject from sender reply-to to cc bcc in-reply-to message-id
    assert_match(/\A\(NIL "hi" NIL NIL NIL NIL NIL NIL NIL NIL\)\z/, envelope)
  end

  def test_envelope_defaults_sender_and_reply_to_to_from
    raw = "From: Amy <amy@example.test>\r\n\r\nbody\r\n"
    envelope = Mime.envelope(Mime.parse(raw))
    assert_equal 3, envelope.scan('(("Amy" NIL "amy" "example.test"))').size,
                 "sender and reply-to must default to from"
  end

  def test_text_bodystructure_ends_with_line_count
    raw = "Content-Type: text/plain\r\n\r\nline one\r\nline two\r\n"
    assert_match(/\A\("TEXT" "PLAIN" NIL NIL NIL "7BIT" \d+ 2\)\z/,
                 Mime.bodystructure(Mime.parse(raw)))
  end

  def test_default_content_type_carries_charset_param_and_line_count
    raw = "Subject: x\r\n\r\nbody\r\n"
    assert_match(/\A\("TEXT" "PLAIN" \("CHARSET" "us-ascii"\) NIL NIL "7BIT" \d+ 1\)\z/,
                 Mime.bodystructure(Mime.parse(raw)))
  end

  def test_multipart_bodystructure_nests_children_before_subtype
    raw = <<~MSG.gsub("\n", "\r\n")
      Content-Type: multipart/alternative; boundary=b

      --b
      Content-Type: text/plain

      plain
      --b
      Content-Type: text/html

      <p>html</p>
      --b--
    MSG
    structure = Mime.bodystructure(Mime.parse(raw))
    assert_match(/\A\(\("TEXT" "PLAIN" .*\)\("TEXT" "HTML" .*\) "ALTERNATIVE"\)\z/, structure)
  end

  def test_quote_escapes_backslashes_and_quotes
    assert_equal %("a\\"b\\\\c"), Mime.quote(%(a"b\\c))
  end

  def test_quote_uses_synchronizing_literal_for_non_ascii
    quoted = Mime.quote("café")
    bytes = "café".b
    assert_equal "{#{bytes.bytesize}}\r\n#{bytes}", quoted.b
    refute_match(/\{\d+\+\}/, quoted, "server responses must never use LITERAL+ form")
  end
end

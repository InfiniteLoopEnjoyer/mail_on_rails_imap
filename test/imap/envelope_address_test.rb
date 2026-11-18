# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# M7 (audit 2026-11-17): ENVELOPE (and SORT FROM/TO/CC) parsed address
# headers of any size, character by character, From three times over. The
# header is the sender's - SMTP bounds only line length and message size
# - so one delivered message with megabytes of folded addresses cost
# every FETCH ENVELOPE 2.2 s of CPU per MiB and an 8x larger response.
class EnvelopeAddressTest < Minitest::Test
  include WireHarness

  Mime = MailOnRails::Imap::Mime

  def seconds
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  # -- what an address list parses to (unchanged) --------------------------------

  test "address forms parse as they always did" do
    {
      "John Doe <john@example.org>" => [ [ "John Doe", "john", "example.org" ] ],
      %("Doe, John" <john@example.org>, bob@x.test) => [ [ "Doe, John", "john", "example.org" ], [ nil, "bob", "x.test" ] ],
      "a@b" => [ [ nil, "a", "b" ] ],
      "<a@b>" => [ [ nil, "a", "b" ] ],
      "  spaced@out.test  ,\r\n\tnext@line.test" => [ [ nil, "spaced", "out.test" ], [ nil, "next", "line.test" ] ],
      "=?utf-8?q?J=C3=B6rg?= <j@x.test>" => [ [ "=?utf-8?q?J=C3=B6rg?=", "j", "x.test" ] ],
      %("a" b <x@y>) => [ [ %("a" b), "x", "y" ] ],
      %("quoted"<q@r>) => [ [ "quoted", "q", "r" ] ],
      %("" <e@f>) => [ [ nil, "e", "f" ] ],
      "Name<n@o>" => [ [ "Name", "n", "o" ] ],
      "a <b@c> trailing" => [],
      "a <b@c>, , d@e" => [ [ "a", "b", "c" ], [ nil, "d", "e" ] ],
      "Team <<t@u>" => [ [ "Team", "<t", "u" ] ],
      "x <@<a@b>" => [ [ "x <@", "a", "b" ] ],
      "no address here" => [],
      "broken <a@>" => [],
      "undisclosed-recipients:;" => [],
      "   " => [],
      "" => []
    }.each do |header, expected|
      assert_equal expected, Mime.parse_addresses(header), header.inspect
    end
    assert_equal [], Mime.parse_addresses(nil)
  end

  test "invalid bytes in an address header are parsed as bytes, not raised on" do
    assert_equal [ [ "J\xF6rg".b, "j", "x.test" ] ], Mime.parse_addresses("J\xF6rg <j@x.test>")
    assert_equal [ [ nil, "a", "b" ] ], Mime.parse_addresses("\xFF\xFE, a@b".dup.force_encoding("UTF-8"))
  end

  # -- the caps ------------------------------------------------------------------

  test "only the first MAX_ADDRESSES of a header are listed" do
    header = (1..1_000).map { |i| "user#{i}@example.org" }.join(", ")
    addresses = Mime.parse_addresses(header)

    assert_equal Mime::MAX_ADDRESSES, addresses.length
    assert_equal [ nil, "user1", "example.org" ], addresses.first
    assert_equal [ nil, "user#{Mime::MAX_ADDRESSES}", "example.org" ], addresses.last
  end

  test "a recipient list of ordinary size is listed in full" do
    header = (1..200).map { |i| "Person Number #{i} <person#{i}@example.org>" }.join(",\r\n ")

    assert_equal 200, Mime.parse_addresses(header).length
  end

  test "nothing past MAX_ADDRESS_HEADER_BYTES is read" do
    padding = "#{"x" * 1000}, " * 70 # 70 KiB of things that are not addresses
    assert_operator padding.bytesize, :>, Mime::MAX_ADDRESS_HEADER_BYTES

    assert_equal [], Mime.parse_addresses("#{padding}late@example.org")
    assert_equal [ [ nil, "early", "example.org" ] ], Mime.parse_addresses("early@example.org, #{padding}")
  end

  test "an address longer than any address is skipped" do
    long = "#{"n" * Mime::MAX_ADDRESS_BYTES} <a@b>"

    assert_equal [ [ nil, "ok", "x.test" ] ], Mime.parse_addresses("#{long}, ok@x.test")
  end

  # -- cost ----------------------------------------------------------------------

  # Each of these is a megabyte a sender can put in one header. The old
  # parser took 2.2 s for the first; the others are the shapes that make
  # a backtracking match quadratic.
  test "megabyte address headers cost milliseconds" do
    megabyte = 1024 * 1024
    hostile = [
      "a@b," * (megabyte / 4),
      "#{" " * megabyte}x",
      "#{"<" * megabyte}>",
      "#{"n " * (megabyte / 2)}<",
      %("#{"q" * megabyte}),
      "#{"a <@" * (megabyte / 4)}>",
      "\"" * megabyte
    ]

    hostile.each do |header|
      elapsed = seconds { Mime.parse_addresses(header) }
      assert_operator elapsed, :<, 0.25, "#{header[0, 12].inspect}... took #{elapsed.round(2)}s"
    end
  end

  test "ENVELOPE parses the From header once" do
    part = Mime.parse("From: Only <only@example.org>\r\nSubject: s\r\n\r\nbody\r\n")
    parsed = []
    original = Mime.method(:parse_addresses)
    Mime.singleton_class.define_method(:parse_addresses) do |value|
      parsed << value unless value.nil?
      original.call(value)
    end

    begin
      envelope = Mime.envelope(part)
    ensure
      Mime.singleton_class.define_method(:parse_addresses, original)
    end

    assert_equal [ "Only <only@example.org>" ], parsed, "sender and reply-to reuse the From list"
    from = %((("Only" NIL "only" "example.org")))
    assert_equal %((NIL "s" #{from} #{from} #{from} NIL NIL NIL NIL NIL)), envelope
  end

  test "Sender and Reply-To still override the From default" do
    part = Mime.parse("From: f@x.test\r\nSender: s@x.test\r\nReply-To: r@x.test\r\n\r\n")

    assert_equal %((NIL NIL ((NIL NIL "f" "x.test")) ((NIL NIL "s" "x.test")) ((NIL NIL "r" "x.test")) NIL NIL NIL NIL NIL)),
                 Mime.envelope(part)
  end

  # -- on the wire ---------------------------------------------------------------

  test "FETCH ENVELOPE of a message with megabytes of addresses is quick and bounded" do
    megabyte = 1024 * 1024
    folded = ([ "a@b," ] * megabyte).each_slice(200).map(&:join).join("\r\n ") # 4 MiB, folded under the line limit
    raw = "From: #{folded}\r\nTo: #{folded}\r\nCc: #{folded}\r\nSubject: flood\r\n\r\nbody\r\n"
    @store.append(@account_id, "INBOX", raw, [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")

    reply = nil
    elapsed = seconds { reply = command(c, "a1", "FETCH 1 (ENVELOPE)") }

    assert_match(/^a1 OK/, reply)
    assert_operator elapsed, :<, 2, "took #{elapsed.round(2)}s"
    # Five lists (from, sender, reply-to, to, cc) of at most MAX_ADDRESSES
    # 17-byte entries - not a response several times the message.
    assert_operator reply.bytesize, :<, 5 * Mime::MAX_ADDRESSES * 20 + 200
    assert_equal 5 * Mime::MAX_ADDRESSES, reply.scan(%((NIL NIL "a" "b"))).length

    sorted = nil
    elapsed = seconds { sorted = command(c, "a2", "SORT (FROM TO CC) UTF-8 ALL") }
    assert_match(/^\* SORT 1\r\n/, sorted)
    assert_operator elapsed, :<, 2
  end
end

# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# M5 / L18 and the partial-fetch note (audit 2026-11-17), FETCH side.
#
# The item list was neither deduplicated nor capped, and each message's
# response was assembled as one string: 100 x BODY.PEEK[] on one 4 MiB
# message was a 400 MiB response and +2.2 GB of memory. And one message
# whose bytes tripped PREVIEW failed the whole command, for every message
# in the set.
class FetchLimitsTest < Minitest::Test
  include WireHarness

  Server = MailOnRails::ImapServer

  def raw_message(body, subject: "limits")
    "From: Sender <sender@remote.test>\r\nTo: user@example.test\r\nSubject: #{subject}\r\n" \
      "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-Id: <#{subject}@remote.test>\r\n\r\n#{body}"
  end

  def selected(*raws)
    raws.each { |raw| @store.append(@account_id, "INBOX", raw, [], nil) }
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  # Reads one tagged response without assuming a line never contains
  # CRLF: literals are consumed by their declared length. Returns
  # [untagged responses as whole strings, the tagged line].
  def read_response(client, tag)
    responses = []
    loop do
      line = client.gets("\r\n")
      return [ responses, line ] if line.start_with?("#{tag} ")

      while (m = line.match(/\{(\d+)\}\r\n\z/))
        line << client.read(m[1].to_i) << client.gets("\r\n")
      end
      responses << line
    end
  end

  def fetch(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_response(client, tag)
  end

  # -- the item list -----------------------------------------------------------

  test "a repeated item is answered once" do
    raw = raw_message("x" * 200_000)
    c = selected(raw)

    responses, tagged = fetch(c, "a1", "FETCH 1 (#{([ "BODY.PEEK[]" ] * 60).join(" ")} body.peek[] UID uid Uid)")

    assert_match(/\Aa1 OK/, tagged)
    assert_equal 1, responses.length
    assert_equal 1, responses.first.scan("BODY[] {").length
    assert_equal 1, responses.first.scan(/\bUID 1\b/).length
    assert_operator responses.first.bytesize, :<, raw.bytesize + 200, "one copy of the message, not sixty-one"
  end

  test "more distinct items than any client asks for are refused" do
    c = selected(raw_message("body\r\n"))
    over = (0..Server::MAX_FETCH_ITEMS).map { |i| "BODY.PEEK[]<#{i}.10>" }

    assert_equal "a1 BAD Too many FETCH data items\r\n", command(c, "a1", "FETCH 1 (#{over.join(" ")})")
    assert_match(/\Aa2 OK/, command(c, "a2", "NOOP"))
  end

  test "the cap itself is usable: sixty-four part fetches in one command" do
    raw = raw_message("0123456789" * 100)
    c = selected(raw)
    items = (0...Server::MAX_FETCH_ITEMS).map { |i| "BODY.PEEK[]<#{i}.10>" }

    responses, tagged = fetch(c, "a1", "FETCH 1 (#{items.join(" ")})")

    assert_match(/\Aa1 OK/, tagged)
    (0...Server::MAX_FETCH_ITEMS).each do |i|
      assert_includes responses.first, "BODY[]<#{i}> {10}\r\n#{raw.byteslice(i, 10)}", "partial at #{i}"
    end
  end

  # What iOS Mail and Thunderbird send, as a regression fence around the cap.
  test "the item lists real clients send are unaffected" do
    c = selected(raw_message("hello\r\n"))
    ios = "UID FETCH 1 (INTERNALDATE UID RFC822.SIZE FLAGS EMAILID THREADID " \
          "BODY.PEEK[HEADER.FIELDS (date subject from to cc message-id in-reply-to references content-type " \
          "x-priority x-uniform-type-identifier x-universally-unique-identifier list-id list-unsubscribe " \
          "bimi-indicator bimi-location x-bimi-indicator-hash authentication-results dkim-signature)])"
    thunderbird = "UID FETCH 1 (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date " \
                  "Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To)])"

    [ ios, thunderbird, "FETCH 1 ALL", "FETCH 1 FULL", "FETCH 1 (BODYSTRUCTURE ENVELOPE PREVIEW)" ].each_with_index do |line, i|
      responses, tagged = fetch(c, "c#{i}", line)
      assert_match(/\Ac#{i} OK/, tagged, line)
      assert_equal 1, responses.length, line
    end
  end

  # -- the response is written as it is built ----------------------------------

  # Large literals go to the socket on their own and small ones through
  # the buffer; the bytes on the wire must be exactly the old response.
  test "a response mixing small items and large literals is byte-exact" do
    big = "B" * (Server::FETCH_DIRECT_WRITE_BYTES * 3)
    raw = raw_message("#{big}\r\n", subject: "mixed")
    header, body = raw.split("\r\n\r\n", 2)
    header << "\r\n\r\n"
    c = selected(raw)

    responses, tagged = fetch(c, "a1", "FETCH 1 (UID RFC822.SIZE BODY.PEEK[HEADER] BODY.PEEK[TEXT] FLAGS " \
                                       "BODY.PEEK[]<0.50> RFC822.HEADER BODY.PEEK[] BODY.PEEK[HEADER.FIELDS (Subject)])")

    expected = "* 1 FETCH (UID 1 RFC822.SIZE #{raw.bytesize} " \
               "BODY[HEADER] {#{header.bytesize}}\r\n#{header} " \
               "BODY[TEXT] {#{body.bytesize}}\r\n#{body} " \
               "FLAGS () " \
               "BODY[]<0> {50}\r\n#{raw.byteslice(0, 50)} " \
               "RFC822.HEADER {#{header.bytesize}}\r\n#{header} " \
               "BODY[] {#{raw.bytesize}}\r\n#{raw} " \
               "BODY[HEADER.FIELDS (SUBJECT)] {18}\r\nSubject: mixed\r\n\r\n)\r\n"
    assert_match(/\Aa1 OK/, tagged)
    assert_equal expected.b, responses.first.b
  end

  # The reviewer's shape: many large sections of one message in a single
  # response. Building the line first held every one of them at once.
  test "many large sections of one message do not accumulate in memory" do
    megabyte = 1024 * 1024
    raw = raw_message("M" * (4 * megabyte))
    c = selected(raw)
    items = (0...48).map { |i| "BODY.PEEK[]<#{i}.#{4 * megabyte}>" }
    GC.start
    before = rss_megabytes
    peak = before
    watcher = Thread.new do
      loop do
        peak = [ peak, rss_megabytes ].max
        sleep 0.005
      end
    end

    c.write("a1 FETCH 1 (#{items.join(" ")})\r\n")
    total = 0
    line = c.gets("\r\n")
    while (m = line.match(/\{(\d+)\}\r\n\z/))
      total += c.read(m[1].to_i).bytesize
      line = c.gets("\r\n")
    end
    watcher.kill

    assert_operator total, :>, 180 * megabyte, "the client did get its ~192 MiB"
    assert_match(/\Aa1 OK/, c.gets("\r\n"))
    # One message, its parse, one section in flight, and what this test
    # itself reads (client and server share the process): measured at
    # 80-100 MiB, against about 1 GB when the response was assembled as
    # one line. The bound sits well clear of both.
    assert_operator peak - before, :<, 300, "response building must not hold every section (rose #{peak - before} MiB)"
  end

  def rss_megabytes
    File.read("/proc/self/status")[/VmRSS:\s+(\d+)/, 1].to_i / 1024
  end

  # -- partials and part numbers -----------------------------------------------

  test "an origin or count past a machine word is clamped, not an internal error" do
    raw = raw_message("0123456789\r\n")
    c = selected(raw)

    responses, tagged = fetch(c, "a1", "FETCH 1 (BODY.PEEK[]<99999999999999999999.5>)")
    assert_match(/\Aa1 OK/, tagged)
    assert_equal "* 1 FETCH (BODY[]<99999999999999999999> {0}\r\n)\r\n", responses.first

    responses, tagged = fetch(c, "a2", "FETCH 1 (BODY.PEEK[]<5.99999999999999999999>)")
    assert_match(/\Aa2 OK/, tagged)
    assert_includes responses.first, "BODY[]<5> {#{raw.bytesize - 5}}\r\n#{raw.byteslice(5..)}"

    responses, tagged = fetch(c, "a3", "FETCH 1 (BODY.PEEK[99999999999999999999] BODY.PEEK[1.99999999999999999999.MIME])")
    assert_match(/\Aa3 OK/, tagged)
    assert_equal "* 1 FETCH (BODY[99999999999999999999] NIL BODY[1.99999999999999999999.MIME] NIL)\r\n", responses.first
  end

  # -- PREVIEW (L18) -----------------------------------------------------------

  QP_STRAY = "From: x@example.org\r\nSubject: hello\r\nContent-Type: text/plain; charset=utf-8\r\n" \
             "Content-Transfer-Encoding: quoted-printable\r\n\r\nHi =\x89 there\r\n".b
  UTF8_MAIL = "From: a@example.org\r\nSubject: caf\xC3\xA9\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" \
              "Gr\xC3\xBC\xC3\x9Fe aus M\xC3\xBCnchen\r\n".b

  test "a quoted-printable body with a stray 8-bit byte gets a preview, not a failed command" do
    c = selected(QP_STRAY, raw_message("plain ascii\r\n"))

    responses, tagged = fetch(c, "a1", "FETCH 1:2 (UID PREVIEW)")

    assert_match(/\Aa1 OK/, tagged)
    assert_equal 2, responses.length, "every message in the set is answered"
    assert_equal "* 1 FETCH (UID 1 PREVIEW {13}\r\nHi =\u{FFFD} there)\r\n".b, responses[0].b
    assert_equal %(* 2 FETCH (UID 2 PREVIEW "plain ascii")\r\n), responses[1]
  end

  test "PREVIEW beside a binary item on ordinary UTF-8 mail" do
    c = selected(UTF8_MAIL)

    responses, tagged = fetch(c, "a1", "FETCH 1 (PREVIEW BODY.PEEK[TEXT] ENVELOPE)")

    assert_match(/\Aa1 OK/, tagged)
    preview = "Grüße aus München"
    assert_includes responses.first.b, "PREVIEW {#{preview.bytesize}}\r\n#{preview}".b
    text = "Gr\xC3\xBC\xC3\x9Fe aus M\xC3\xBCnchen\r\n".b
    assert_includes responses.first.b, "BODY[TEXT] {#{text.bytesize}}\r\n".b + text
    assert_includes responses.first.b, "ENVELOPE (NIL {5}\r\ncaf\xC3\xA9 ((NIL NIL \"a\" \"example.org\"))".b
  end

  test "previews are valid UTF-8 whatever the message declares" do
    mime = MailOnRails::Imap::Mime
    bodies = [ "caf\xE9", "abc \xE2\x82 def", "<p>Gr\xFC\xDFe</p>\xA0", " =\x89", "=E2=82", "/+7/" ]
    charsets = [ nil, "utf-8", "bogus", "\xBA", "utf-7", "UTF-16", "iso-8859-1", "caf\xC3\xA9", "x\x15y" ]
    encodings = [ nil, "quoted-printable", "base64", "8bit", "binary" ]

    bodies.product(charsets, encodings, %w[plain html]).each do |body, charset, encoding, subtype|
      head = +"Content-Type: text/#{subtype}"
      head << "; charset=#{charset}" if charset
      head << "\r\nContent-Transfer-Encoding: #{encoding}" if encoding
      preview = mime.preview(mime.parse("#{head}\r\n\r\n#{body}\r\n".b))

      assert_equal Encoding::UTF_8, preview.encoding, head
      assert preview.valid_encoding?, "#{head.inspect} / #{body.inspect}"
      assert_operator preview.bytesize, :<=, mime::PREVIEW_MAX_OCTETS
      assert_operator preview.length, :<=, mime::PREVIEW_MAX_CHARS
    end
  end

  test "a preview is made from the head of the body, not megabytes of it" do
    mime = MailOnRails::Imap::Mime
    part = mime.parse("Content-Type: text/html\r\n\r\n<p>Lead paragraph</p>#{"<i>filler</i> " * 1_000_000}".b)

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    preview = mime.preview(part)

    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.5
    assert preview.start_with?("Lead paragraph filler")
  end

  # -- one bad message degrades, the command goes on ---------------------------

  # Stands in for "this message's bytes trip a bug in the MIME code": by
  # the time an item is computed, part of the response is on the wire, so
  # the item gets its empty form and the rest of the set is still served.
  test "an item that raises is answered empty and the other messages are unaffected" do
    c = selected(raw_message("first\r\n", subject: "poison"), raw_message("second\r\n", subject: "fine"))
    mime = MailOnRails::Imap::Mime.singleton_class
    original = MailOnRails::Imap::Mime.method(:parse)
    mime.define_method(:parse) do |raw, **kwargs|
      raise Encoding::CompatibilityError, "simulated parser failure" if raw.include?("Subject: poison")

      original.call(raw, **kwargs)
    end

    begin
      responses, tagged = fetch(c, "a1", "FETCH 1:2 (UID ENVELOPE BODYSTRUCTURE PREVIEW BODY.PEEK[HEADER] RFC822.HEADER FLAGS)")
    ensure
      mime.define_method(:parse, original)
    end

    assert_match(/\Aa1 OK/, tagged)
    assert_equal 2, responses.length
    assert_equal "* 1 FETCH (UID 1 ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) " \
                 "BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0) PREVIEW NIL BODY[HEADER] NIL RFC822.HEADER NIL FLAGS ())\r\n",
                 responses[0]
    assert_includes responses[1], "ENVELOPE (\"Mon, 1 Jan 2024 10:00:00 +0000\" \"fine\""
    assert_includes responses[1], %(PREVIEW "second")
  end

  # -- HEADER.FIELDS -----------------------------------------------------------

  test "a header list thousands of names long is matched per line by lookup" do
    mime = MailOnRails::Imap::Mime
    block = "#{(1..2_000).map { |i| "X-Header-#{i}: value #{i}" }.join("\r\n")}\r\nSubject: found\r\n\r\n"
    names = (1..20_000).map { |i| "X-Absent-#{i}" } << "SUBJECT"

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    kept = mime.header_fields(block, names)
    dropped = mime.header_fields(block, names, negate: true)

    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.5
    assert_equal "Subject: found\r\n\r\n", kept
    assert_equal 2_000, dropped.scan("X-Header-").length
  end
end

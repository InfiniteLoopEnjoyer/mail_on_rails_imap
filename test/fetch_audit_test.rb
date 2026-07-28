require "test_helper"
require "wire_harness"

# RFC 3501/9051 FETCH compliance audit, ported from mox's
# imapserver/fetch_test.go. Uses the same fixture messages: the RFC 3501
# §8 "afternoon meeting" example and the RFC 2049 nested-multipart
# example. mox cases for extensions we don't advertise (BINARY, SAVEDATE,
# PREVIEW) are not ported.
class FetchAuditTest < Minitest::Test
  include WireHarness

  EXAMPLE = <<~MSG.gsub("\n", "\r\n")
    Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)
    From: Fred Foobar <foobar@Blurdybloop.example>
    Subject: afternoon meeting
    To: mooch@owatagu.siam.edu.example
    Message-Id: <B27397-0100000@Blurdybloop.example>
    MIME-Version: 1.0
    Content-Type: TEXT/PLAIN; CHARSET=US-ASCII

    Hello Joe, do you think we can meet at 3:30 tomorrow?

  MSG

  EXAMPLE_HEADER = EXAMPLE[0...(EXAMPLE.index("\r\n\r\n") + 4)]
  EXAMPLE_BODY = EXAMPLE[(EXAMPLE.index("\r\n\r\n") + 4)..]

  NESTED = <<~MSG.gsub("\n", "\r\n")
    MIME-Version: 1.0
    From: Nathaniel Borenstein <nsb@nsb.fv.com>
    To: Ned Freed <ned@innosoft.com>
    Date: Fri, 07 Oct 1994 16:15:05 -0700 (PDT)
    Subject: A multipart example
    Content-Type: multipart/mixed;
                  boundary=unique-boundary-1

    This is the preamble area of a multipart message.

    --unique-boundary-1

      ... Some text appears here ...

    [Note that the blank between the boundary and the start
     of the text in this part means no header fields were
     given and this is text in the US-ASCII character set.]

    --unique-boundary-1
    Content-type: text/plain; charset=US-ASCII

    This could have been part of the previous part, but
    illustrates explicit versus implicit typing of body
    parts.

    --unique-boundary-1
    Content-Type: multipart/parallel; boundary=unique-boundary-2

    --unique-boundary-2
    Content-Type: audio/basic
    Content-Transfer-Encoding: base64

    aGVsbG8NCndvcmxkDQo=

    --unique-boundary-2
    Content-Type: image/jpeg
    Content-Transfer-Encoding: base64
    Content-Disposition: inline; filename=image.jpg


    --unique-boundary-2--

    --unique-boundary-1
    Content-type: text/enriched

    This is <bold><italic>enriched.</italic></bold>

    --unique-boundary-1
    Content-Type: message/rfc822
    Content-MD5: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
    Content-Language: en,de
    Content-Location: http://localhost

    From: info@mox.example
    To: mox <info@mox.example>
    Subject: (subject in US-ASCII)
    Content-Type: Text/plain; charset=ISO-8859-1
    Content-Transfer-Encoding: Quoted-printable

      ... Additional text in ISO-8859-1 goes here ...

    --unique-boundary-1--
  MSG

  def select_with_example(client = connect)
    @store.append(@account_id, "INBOX", EXAMPLE, [], nil) # uid 1
    command(client, "s0", "SELECT INBOX")
    client
  end

  # -- macros and basic items ------------------------------------------------

  test "fetch macros expand to their item sets" do
    c = select_with_example
    all = command(c, "m1", "FETCH 1 ALL")
    %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE].each { |i| assert_match(/#{i}/, all) }
    refute_match(/BODY/, all)

    fast = command(c, "m2", "FETCH 1 FAST")
    %w[FLAGS INTERNALDATE RFC822.SIZE].each { |i| assert_match(/#{i}/, fast) }
    refute_match(/ENVELOPE/, fast)

    full = command(c, "m3", "FETCH 1 FULL")
    %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY].each { |i| assert_match(/#{i}/, full) }
  end

  test "envelope for the rfc3501 example message" do
    c = select_with_example
    env = command(c, "e1", "FETCH 1 ENVELOPE")
    assert_match(/"afternoon meeting"/, env)
    assert_match(/\("Fred Foobar" NIL "foobar" "Blurdybloop.example"\)/, env)
    assert_match(/\(NIL NIL "mooch" "owatagu.siam.edu.example"\)/, env)
    assert_match(/"<B27397-0100000@Blurdybloop.example>"/, env)
  end

  test "bodystructure basic fields and extension data" do
    c = select_with_example
    # BODY: plain form, ending at the line count.
    body = command(c, "b1", "FETCH 1 BODY")
    assert_match(/BODY \("TEXT" "PLAIN" \("CHARSET" "US-ASCII"\) NIL NIL "7BIT" #{EXAMPLE_BODY.bytesize} 2\)/, body)

    # BODYSTRUCTURE: extended form with md5/disposition/language/location.
    bs = command(c, "b2", "FETCH 1 BODYSTRUCTURE")
    assert_match(/BODYSTRUCTURE \("TEXT" "PLAIN" \("CHARSET" "US-ASCII"\) NIL NIL "7BIT" #{EXAMPLE_BODY.bytesize} 2 NIL NIL NIL NIL\)/, bs)
  end

  # -- body sections ---------------------------------------------------------

  test "body sections of a simple message" do
    c = select_with_example
    full = command(c, "s1", "FETCH 1 BODY.PEEK[]")
    assert_match(/BODY\[\] \{#{EXAMPLE.bytesize}\}/, full)
    assert_includes full, "Hello Joe"

    header = command(c, "s2", "FETCH 1 BODY.PEEK[HEADER]")
    assert_match(/BODY\[HEADER\] \{#{EXAMPLE_HEADER.bytesize}\}/, header)
    assert_includes header, "Subject: afternoon meeting"
    refute_includes header, "Hello Joe"

    text = command(c, "s3", "FETCH 1 BODY.PEEK[TEXT]")
    assert_match(/BODY\[TEXT\] \{#{EXAMPLE_BODY.bytesize}\}/, text)
    assert_includes text, "Hello Joe"

    # Part 1 of a non-multipart message is its body.
    part1 = command(c, "s4", "FETCH 1 BODY.PEEK[1]")
    assert_match(/BODY\[1\] \{#{EXAMPLE_BODY.bytesize}\}/, part1)
  end

  test "body partials honor origin and count" do
    c = select_with_example
    two = command(c, "p1", "FETCH 1 BODY.PEEK[]<1.2>")
    assert_match(/BODY\[\]<1> \{2\}\r\n#{Regexp.escape(EXAMPLE[1, 2])}/, two)

    # Origin past the end yields an empty literal.
    empty = command(c, "p2", "FETCH 1 BODY.PEEK[]<100000.100000>")
    assert_match(/BODY\[\]<100000> \{0\}/, empty)
  end

  test "header fields and header fields not" do
    c = select_with_example
    date = command(c, "h1", "FETCH 1 BODY.PEEK[HEADER.FIELDS (DATE)]")
    assert_includes date, "Date: Mon, 7 Feb 1994"
    refute_includes date, "Subject:"

    nodate = command(c, "h2", "FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT (DATE)]")
    refute_includes nodate, "Date: Mon"
    assert_includes nodate, "Subject: afternoon meeting"
  end

  test "rfc822 family matches body section equivalents" do
    c = select_with_example
    assert_match(/RFC822\.HEADER \{#{EXAMPLE_HEADER.bytesize}\}/, command(c, "r1", "FETCH 1 RFC822.HEADER"))
    # RFC822.HEADER is equivalent to BODY.PEEK[HEADER]: no \Seen.
    refute_match(/\\Seen/, command(c, "r2", "FETCH 1 FLAGS"))

    assert_match(/RFC822\.TEXT \{#{EXAMPLE_BODY.bytesize}\}/, command(c, "r3", "FETCH 1 RFC822.TEXT"))
    assert_match(/RFC822 \{#{EXAMPLE.bytesize}\}/, command(c, "r4", "FETCH 1 RFC822"))
    # Those two are non-peek: \Seen is now set.
    assert_match(/\\Seen/, command(c, "r5", "FETCH 1 FLAGS"))
  end

  # -- \Seen semantics -------------------------------------------------------

  test "non peek body fetch sets and announces seen" do
    c = select_with_example
    fetch = command(c, "n1", "FETCH 1 BODY[]")
    assert_match(/FLAGS \([^)]*\\Seen[^)]*\)/, fetch, "implicit \\Seen must be announced")
    assert_match(/\\Seen/, command(c, "n2", "FETCH 1 FLAGS"))
  end

  test "peek does not set seen" do
    c = select_with_example
    command(c, "k1", "FETCH 1 BODY.PEEK[]")
    refute_match(/\\Seen/, command(c, "k2", "FETCH 1 FLAGS"))
  end

  test "examine never sets seen" do
    c = connect
    @store.append(@account_id, "INBOX", EXAMPLE, [], nil)
    command(c, "x1", "EXAMINE INBOX")
    command(c, "x2", "FETCH 1 BODY[]")
    refute_match(/\\Seen/, command(c, "x3", "FETCH 1 FLAGS"))
  end

  # -- sequence sets ---------------------------------------------------------

  test "sequence set forms resolve in mailbox order" do
    c = select_with_example
    @store.append(@account_id, "INBOX", EXAMPLE, [], nil) # uid 2
    command(c, "q0", "NOOP")

    %w[1:2 1,2 2:1 1:* *:1].each_with_index do |set, i|
      reply = command(c, "q#{i + 1}", "FETCH #{set} (UID)")
      assert_match(/\* 1 FETCH \(UID 1\)/, reply, "set #{set}")
      assert_match(/\* 2 FETCH \(UID 2\)/, reply, "set #{set}")
    end

    star = command(c, "q6", "FETCH * (UID)")
    refute_match(/\* 1 FETCH/, star)
    assert_match(/\* 2 FETCH \(UID 2\)/, star, "* means the highest sequence number")

    high = command(c, "q7", "FETCH *:2 (UID)")
    assert_match(/\* 2 FETCH \(UID 2\)/, high)
    refute_match(/\* 1 FETCH/, high)
  end

  test "uid fetch of a missing uid is ok and empty" do
    c = select_with_example
    reply = command(c, "u1", "UID FETCH 99 BODY[]")
    refute_match(/\* \d+ FETCH/, reply)
    assert_match(/\Au1 OK/, reply)
  end

  test "uid fetch always reports uid" do
    c = select_with_example
    assert_match(/UID 1/, command(c, "u2", "UID FETCH 1 (FLAGS)"))
  end

  # -- syntax validation (mox invalid-syntax block) --------------------------

  test "fetch syntax errors are bad" do
    c = select_with_example
    [
      "FETCH",                                # missing everything
      "FETCH 1",                              # at least one item required
      "FETCH 1 ()",                           # empty list
      "FETCH 1 UNKNOWN",                      # unknown item
      "FETCH 1 (UNKNOWN)",                    # unknown item in list
      "FETCH 1 (ALL)",                        # macros not allowed in lists
      "FETCH 1 (FLAGS ALL)",                  # macros not allowed with items
      "FETCH 1 BODY[]<1>",                    # partial count required
      "FETCH 1 BODY[]<1.0>",                  # partial count must be nonzero
      "FETCH 1 BODY[HEADER.FIELDS]",          # header list required
      "FETCH 1 BODY[HEADER.FIELDS ()]",       # header list must be non-empty
      "FETCH 1 BODY[MIME]",                   # MIME needs a part number
      "FETCH 2 BODY[]",                       # sequence number out of range
      "FETCH 0 FLAGS"                         # sequence numbers start at 1
    ].each_with_index do |line, i|
      assert_match(/\Az#{i} BAD/, command(c, "z#{i}", line), "expected BAD for: #{line}")
    end
  end

  # -- nested multipart (RFC 2049 example) -----------------------------------

  def select_with_nested(client = connect)
    @store.append(@account_id, "INBOX", NESTED, [], nil) # uid 1
    command(client, "s0", "SELECT INBOX")
    client
  end

  test "nested multipart bodystructure" do
    c = select_with_nested
    bs = command(c, "n1", "FETCH 1 BODYSTRUCTURE")
    assert_match(/"MIXED"/, bs)
    assert_match(/"PARALLEL"/, bs)
    assert_match(/"AUDIO" "BASIC"/, bs)
    assert_match(/"IMAGE" "JPEG"/, bs)
    assert_match(/"MESSAGE" "RFC822"/, bs)
    # The embedded message carries its own envelope...
    assert_match(/"\(subject in US-ASCII\)"/, bs)
    # ...and extension data surfaces disposition, language, location, md5.
    assert_match(/\("INLINE" \("FILENAME" "image.jpg"\)\)/, bs)
    assert_match(/\("en" "de"\)/, bs)
    assert_match(/"http:\/\/localhost"/, bs)
    assert_match(/"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="/, bs)
    # Multipart extension data includes the boundary param.
    assert_match(/"BOUNDARY" "unique-boundary-1"/, bs)

    # Plain BODY omits all extension data.
    body = command(c, "n2", "FETCH 1 BODY")
    refute_match(/INLINE|BOUNDARY|localhost/, body)
  end

  test "nested multipart sections" do
    c = select_with_nested

    part1 = command(c, "p1", "FETCH 1 BODY.PEEK[1]")
    assert_includes part1, "... Some text appears here ..."

    part31 = command(c, "p2", "FETCH 1 BODY.PEEK[3.1]")
    assert_includes part31, "aGVsbG8NCndvcmxkDQo="
    refute_includes part31, "Content-Type: audio/basic"

    mime2 = command(c, "p3", "FETCH 1 BODY.PEEK[2.MIME]")
    assert_includes mime2, "Content-type: text/plain; charset=US-ASCII"

    # Sections of the embedded message/rfc822 part.
    hdr5 = command(c, "p4", "FETCH 1 BODY.PEEK[5.HEADER]")
    assert_includes hdr5, "Subject: (subject in US-ASCII)"
    refute_includes hdr5, "Additional text"

    text5 = command(c, "p5", "FETCH 1 BODY.PEEK[5.TEXT]")
    assert_includes text5, "Additional text in ISO-8859-1 goes here"
    refute_includes text5, "Subject:"

    sub51 = command(c, "p6", "FETCH 1 BODY.PEEK[5.1]")
    assert_includes sub51, "Additional text in ISO-8859-1 goes here"

    full5 = command(c, "p7", "FETCH 1 BODY.PEEK[5]")
    assert_includes full5, "Subject: (subject in US-ASCII)"
    assert_includes full5, "Additional text in ISO-8859-1 goes here"
  end
end

# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# CVE-class regression audit for the IMAP wire protocol. Each test maps to a
# known family of IMAP server vulnerabilities and pins the gem's defense so a
# refactor can't silently reintroduce it. Grouped by class:
#
#   1. literal_handling   - {n} / {n+} sizes: zero, astronomically large,
#                           malformed/negative, and literals used as an
#                           argument (CVE-2018-14351, CVE-2024-34055,
#                           CVE-2025-43857, CVE-2003-029x integer-overflow set)
#   2. cmd_parse_overflow - overlong lines/atoms, deeply nested parens,
#                           unterminated quotes (the C buffer-overflow class
#                           mapped to Ruby; CVE-2026-67194 SEARCH recursion,
#                           CVE-2010-2777/4717 long CREATE/LIST args)
#   4. response_inject    - CRLF / quote / control bytes in mailbox names and
#                           header fields echoed into untagged responses
#                           (CVE-2006-0377, CVE-2026-42257/42258 CRLF class)
#   5. nul_ctrl_bytes     - NUL / control bytes in mailbox names, keywords,
#                           and astrings (CVE-2007-5740, CVE-2005-1249)
#
# Class 3 (STARTTLS plaintext injection, CVE-2011-0411 family) is exercised
# in starttls_test.rb - "commands pipelined behind starttls are never
# executed" drives the same-TCP-segment buffering vector in a single write -
# so it is not duplicated here.
#
# Run via bin/rails test:imap_server (rake test:imap).
class CveWireTest < Minitest::Test
  include WireHarness

  MAX_LINE = MailOnRails::ImapServer::MAX_LINE
  MAX_LITERAL = MailOnRails::ImapServer::MAX_LITERAL_BYTES

  # Reads a single line without the tagged-completion loop (for the raw
  # continuation / abort probes).
  def read_line(client)
    client.gets("\r\n")
  end

  def drain(client)
    rest = +""
    rest << client.gets("\r\n").to_s while !client.eof?
    rest
  rescue IOError, SystemCallError
    rest
  end

  # ==========================================================================
  # Class 1: literal_handling
  # ==========================================================================

  # A synchronizing literal is a legitimate way to carry an argument
  # (RFC 3501 §4.3). The reader must handle it as an argument value, drive the
  # continuation, and dispatch normally - the "literal inside an argument"
  # shape that older parsers mishandled.
  test "a synchronizing literal supplies a mailbox-name argument" do
    c = connect
    c.write("s1 SELECT {5}\r\n")
    assert_match(/\A\+ /, read_line(c), "server must request the continuation")
    c.write("INBOX\r\n")
    assert_match(/^s1 OK \[READ-WRITE\]/, read_until_tagged(c, "s1"))
  end

  # A zero-length literal {0} must be read as an empty octet run - not a hang,
  # not a negative allocation - and the resulting empty argument handled
  # cleanly (an empty mailbox name is BAD, and the session survives).
  test "a zero-length literal is read and yields a clean BAD" do
    c = connect
    c.write("z1 CREATE {0}\r\n")
    assert_match(/\A\+ /, read_line(c))
    c.write("\r\n")
    assert_match(/\Az1 BAD/, read_until_tagged(c, "z1"))
    assert_match(/\Az2 OK/, command(c, "z2", "NOOP"))
  end

  # CVE-2025-43857 / CVE-2003-029x class: a receiver that allocates the
  # declared byte count up front OOMs on a huge {n}. An astronomically large
  # synchronizing literal must be refused with TOOBIG *before* any allocation
  # or continuation, and the session must stay framed.
  test "an astronomically large synchronizing literal is refused without allocating" do
    c = connect
    c.write("h1 APPEND INBOX {999999999999999}\r\n")
    reply = read_until_tagged(c, "h1")
    assert_match(/\Ah1 NO \[TOOBIG\]/, reply)
    refute_match(/\A\+ /, reply, "no continuation may be sent for an over-limit literal")
    assert_match(/\Ah2 OK/, command(c, "h2", "NOOP"))
  end

  # A malformed literal count ({-1}) does not match the literal grammar, so it
  # must NOT be treated as a literal - the server must not send a continuation
  # and hang waiting for octets that never come. It degrades to an ordinary
  # (here failing) command and the session stays responsive.
  test "a negative/malformed literal count is not treated as a literal" do
    c = connect
    c.write("m1 SELECT bad{-1}\r\n")
    reply = read_until_tagged(c, "m1")
    refute_match(/\A\+ /, reply, "a malformed {n} must not trigger a continuation request")
    assert_match(/\Am1 (NO|BAD)/, reply)
    assert_match(/\Am2 OK/, command(c, "m2", "NOOP"))
  end

  # ==========================================================================
  # Class 2: cmd_parse_overflow
  # ==========================================================================

  # CVE-2013-1752 / long-line DoS class: a command line with no CRLF must be
  # bounded at MAX_LINE, aborting the session rather than buffering unbounded
  # bytes. (imap_session_test covers the AUTHENTICATE-continuation path; this
  # is the first-command-line path through the same reader.)
  test "an overlong first command line is refused and drops the session" do
    c = connect(login: false)
    c.write("A" * (MAX_LINE + 4096))
    assert_match(/\A\* BAD Command line too long/, read_line(c).to_s)
    assert c.eof?, "the session must drop rather than drain attacker bytes"
  rescue Errno::ECONNRESET
    # An abort with surplus bytes unread can surface as a reset.
  end

  # CVE-2010-2777 / CVE-2010-4717 class: a very long single argument (mailbox
  # name) must not overflow anything - it is just a miss. The session survives.
  test "a very long argument atom is handled as an ordinary miss" do
    c = connect
    long_name = "z" * 20_000
    assert_match(/\Ag1 NO/, command(c, "g1", "SELECT #{long_name}"))
    assert_match(/\Ag2 OK/, command(c, "g2", "NOOP"))
  end

  # CVE-2026-67194 class: a deeply nested parenthesized SEARCH key must be
  # bounded by MAX_SEARCH_DEPTH, yielding a tagged BAD instead of recursing
  # into a SystemStackError that would escape the handler and kill the thread.
  # (imap_session_test lowers the constant to 5; this drives the real default
  # limit with ~500 levels.)
  test "a deeply nested search key past the default depth is rejected not fatal" do
    c = connect
    command(c, "d0", "SELECT INBOX")
    nested = "#{"(" * 500}ALL#{")" * 500}"
    assert_match(/\Ad1 BAD/, command(c, "d1", "SEARCH #{nested}"))
    assert_match(/\Ad2 OK/, command(c, "d2", "NOOP"))
  end

  # A deeply nested parenthesized list outside SEARCH (the lexer flattens
  # parens to a token stream, so this must be O(n) memory with no recursion)
  # must not crash the parser either.
  test "deeply nested parentheses in a non-search command do not crash the parser" do
    c = connect
    command(c, "p0", "SELECT INBOX")
    nested = "#{"(" * 1000}UID#{")" * 1000}"
    reply = command(c, "p1", "FETCH 1 #{nested}")
    assert_match(/\Ap1 (OK|NO|BAD)/, reply)
    assert_match(/\Ap2 OK/, command(c, "p2", "NOOP"))
  end

  # An unterminated quoted string must not hang the reader or crash it; the
  # parser recovers and the command is answered (here a miss) with the session
  # intact.
  test "an unterminated quoted string is handled without hanging" do
    c = connect
    reply = command(c, "q1", %(SELECT "Ghostbox))
    assert_match(/\Aq1 (NO|BAD)/, reply)
    assert_match(/\Aq2 OK/, command(c, "q2", "NOOP"))
  end

  # ==========================================================================
  # Class 4: response_inject (CRLF / quote in echoed strings)
  # ==========================================================================

  # CVE-2006-0377 / CRLF-injection class: an attacker-controlled mailbox name
  # echoed into an untagged LIST response must be neutralized - a CR is
  # modified-UTF-7 encoded and a double-quote is backslash-escaped - so it
  # cannot forge a response line or break the quoted string. The name is
  # planted through the store (IMAP CREATE rejects control chars up front,
  # which is its own defense), modelling a name that reached the mailbox list
  # by some other path.
  test "control and quote bytes in a mailbox name cannot inject into a LIST response" do
    @store.create_mailbox(@account_id, %(ev\r* 9 EXISTS\ril"box))
    c = connect
    listing = command(c, "L1", %(LIST "" "*"))
    line = listing.lines.find { |l| l.include?("box") }
    refute_nil line, "the crafted mailbox must still be listed"
    refute_includes line, "\r* 9 EXISTS", "no forged untagged line may appear"
    assert_equal 1, line.scan("\r\n").size, "the name must not add CR/LF to the response line"
    assert_includes line, "&", "the CR must be modified-UTF-7 encoded"
    assert_includes line, %(\\"), "the double-quote must be backslash-escaped"
  end

  # A header value echoed into an ENVELOPE response is quoted/escaped: a
  # double-quote in the Subject is backslash-escaped so it can't terminate the
  # quoted string early (CVE-2026-42257 CRLF/quote class applied to server
  # output).
  test "a double-quote in a header is escaped in the envelope response" do
    raw = %(From: s@remote.test\r\nSubject: he said "hi"\r\n\r\nbody\r\n)
    @store.append(@account_id, "INBOX", raw, [], nil)
    c = connect
    command(c, "e0", "SELECT INBOX")
    env = command(c, "e1", "FETCH 1 (ENVELOPE)")
    assert_match(/ENVELOPE \(.*"he said \\"hi\\""/, env)
    assert_match(/^e1 OK/, env)
  end

  # A non-ASCII header value cannot be represented as a quoted string safely,
  # so it is emitted as a counted {n} literal - the client reads exactly n
  # octets, so embedded CR/LF in the value can never be mistaken for protocol
  # framing (the safe half of the response-injection defense).
  test "a non-ascii header value is emitted as a counted literal in the envelope" do
    raw = "From: s@remote.test\r\nSubject: caf\xC3\xA9 \xE2\x80\x94 report\r\n\r\nbody\r\n".b
    @store.append(@account_id, "INBOX", raw, [], nil)
    c = connect
    command(c, "e0", "SELECT INBOX")
    env = command(c, "e1", "FETCH 1 (ENVELOPE)")
    assert_match(/ENVELOPE \(NIL \{\d+\}\r\n/, env, "8-bit subject must ride a literal, not a bare quoted string")
    assert_match(/^e1 OK/, env)
  end

  # ==========================================================================
  # Class 5: nul_ctrl_bytes
  # ==========================================================================

  # CVE-2005-1249 / control-byte class: CREATE with a control byte in the name
  # is rejected with BAD (the name never reaches the store) and the session
  # survives. Pins the mailbox_name_error control-char guard.
  test "create with a control byte in the mailbox name is refused" do
    c = connect
    assert_match(/\Ac1 BAD/, command(c, "c1", "CREATE bad\x01name"))
    assert_match(/\Ac2 BAD/, command(c, "c2", "CREATE nul\x00name"))
    # ...and nothing was created.
    refute_match(/name/, command(c, "c3", %(LIST "" "*")))
    assert_match(/\Ac4 OK/, command(c, "c4", "NOOP"))
  end

  # CVE-2007-5740 class (NUL in a tag / astring): a NUL byte inside a mailbox
  # astring argument must fail closed (BAD, the shared mailbox-name gate),
  # never crash the parser or leak another mailbox, and the session survives.
  test "a NUL byte in a mailbox astring fails closed" do
    c = connect
    assert_match(/\As1 BAD/, command(c, "s1", "SELECT INBOX\x00extra"))
    assert_match(/\As2 OK/, command(c, "s2", "NOOP"))
  end

  # A control byte carried in a STORE keyword must not break response framing:
  # whatever the server does with the keyword, the FETCH/STORE reply is still a
  # single CRLF-terminated line - a control byte cannot split the stream the
  # way a CRLF would.
  test "a control byte in a keyword flag cannot break response framing" do
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    c = connect
    command(c, "k0", "SELECT INBOX")
    reply = command(c, "k1", "STORE 1 +FLAGS (foo\x01bar)")
    assert_match(/^k1 (OK|BAD)/, reply)
    # Response framing is intact: the STORE emits exactly one untagged FETCH
    # line before its tagged completion - a control byte in the keyword did
    # not split the stream into extra bogus responses the way a CRLF would.
    assert_equal 2, reply.scan("\r\n").size, "the control byte must not add response lines"
    refute_match(/^\* \d+ EXISTS/, reply)
    assert_match(/\Ak2 OK/, command(c, "k2", "NOOP"))
  end
end

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

  # A control byte carried in a STORE keyword is not an atom: the flag list
  # is refused with BAD (nothing stored, nothing echoed) and the reply is a
  # single CRLF-terminated line - a control byte cannot split the stream
  # the way a CRLF would.
  test "a control byte in a keyword flag cannot break response framing" do
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    c = connect
    command(c, "k0", "SELECT INBOX")
    reply = command(c, "k1", "STORE 1 +FLAGS (foo\x01bar)")
    assert_match(/\Ak1 BAD/, reply)
    assert_equal 1, reply.scan("\r\n").size, "the control byte must not add response lines"
    refute_match(/^\* \d+ EXISTS/, reply)
    refute_match(/foo/, command(c, "k2", "FETCH 1 (FLAGS)"), "the keyword was never stored")
    assert_match(/\Ak3 OK/, command(c, "k3", "NOOP"))
  end

  # Flags may arrive as literals, so a keyword can carry CRLF: it is
  # rejected by the atom grammar before it can be stored and later echoed
  # as "* 5 EXPUNGE" in the middle of a FETCH response.
  test "a literal keyword carrying CRLF is refused and never echoed" do
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    c = connect
    command(c, "k0", "SELECT INBOX")
    payload = "x)\r\n* 5 EXPUNGE\r\n"
    c.write("k1 STORE 1 +FLAGS ({#{payload.bytesize}}\r\n")
    assert_match(/\A\+ /, read_line(c))
    c.write("#{payload})\r\n")
    reply = read_until_tagged(c, "k1")
    assert_match(/\Ak1 BAD/, reply)
    refute_match(/EXPUNGE/, reply)
    assert_equal 1, reply.scan("\r\n").size
    fetched = command(c, "k2", "FETCH 1 (FLAGS)")
    refute_match(/EXPUNGE/, fetched)
    assert_match(/FLAGS \(\)/, fetched)
    assert_match(/\Ak3 OK/, command(c, "k3", "NOOP"))
  end

  # The keyword grammar and caps: atom-specials, 8-bit, over-long, and
  # too many keywords are BAD on STORE and APPEND alike; a plain keyword
  # at the size cap is fine.
  test "keyword flags must be short atoms and few" do
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    c = connect
    command(c, "k0", "SELECT INBOX")
    max = MailOnRails::ImapServer::MAX_KEYWORD_BYTES
    [ "a]b", "a%b", "a*b", "a{b", "a\"b", "a\\b", "\xC3\xA9".b, "k" * (max + 1) ].each_with_index do |bad, i|
      c.write("b#{i} STORE 1 +FLAGS ({#{bad.bytesize}+}\r\n#{bad})\r\n")
      assert_match(/\Ab#{i} BAD/, read_until_tagged(c, "b#{i}"), bad.inspect)
    end
    many = Array.new(MailOnRails::ImapServer::MAX_KEYWORDS + 1) { |i| "kw#{i}" }.join(" ")
    assert_match(/\Ab9 BAD/, command(c, "b9", "STORE 1 +FLAGS (#{many})"))
    assert_match(/\Ab10 BAD/, append(c, "b10", "INBOX", "x", flags: [ "bad]kw" ]))
    assert_match(/^b11 OK/, command(c, "b11", "STORE 1 +FLAGS (#{"k" * max} $Label1)"))
    assert_match(/FLAGS \(#{"k" * max} \$Label1\)/, command(c, "b12", "FETCH 1 (FLAGS)"))
  end

  # The ESEARCH TAG correlator is client-supplied and must be quoted and
  # escaped, so a backslash (or quote) in the tag can't close the string.
  test "the esearch tag correlator is quoted and escaped" do
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    c = connect
    command(c, "e0", "SELECT INBOX")
    reply = command(c, 't\1', "SEARCH RETURN (COUNT) ALL")
    assert_match(/^\* ESEARCH \(TAG "t\\\\1"\) COUNT 1\r\n/, reply)
    assert_match(/^t\\1 OK/, reply)
  end

  # Credentials are redacted from the transcript even when the command
  # line carries leading whitespace (which the lexer tolerates).
  test "login and authenticate lines are redacted regardless of leading whitespace" do
    session = MailOnRails::ImapServer::Session.new(nil, @store, { tls: :implicit }, nil)
    assert_equal "a1 LOGIN [redacted]", session.send(:redact_imap, "  a1 login user pass")
    assert_equal "a1 LOGIN [redacted]", session.send(:redact_imap, "\ta1 LOGIN user pass")
    assert_equal "a2 AUTHENTICATE PLAIN [redacted]", session.send(:redact_imap, " \t a2 AUTHENTICATE PLAIN AHUAcA==")
    assert_equal "a2 AUTHENTICATE PLAIN", session.send(:redact_imap, "   a2 authenticate PLAIN")
    assert_equal "a3 NOOP", session.send(:redact_imap, "a3 NOOP")
  end

  # ==========================================================================
  # Class 6: store failure text (information disclosure)
  # ==========================================================================

  # A store whose write paths raise the way the Active Record backend does
  # when the database rejects a row: Store::Base#db turns the exception
  # into { error: "Class: message", code: :internal } - text naming the
  # adapter, the table and the SQL.
  class FailingStore < MailOnRails::Imap::Store::Memory
    INTERNAL = { error: "ActiveRecord::StatementInvalid: PG::DatetimeFieldOverflow: ERROR: date/time field value " \
                        "out of range: SELECT 1 FROM mail_on_rails_email_messages", code: :internal }.freeze

    attr_accessor :failing

    %i[create_mailbox delete_mailbox rename_mailbox append copy move].each do |name|
      define_method(name) { |*args| failing ? INTERNAL.dup : super(*args) }
    end
  end

  test "store exception text never reaches the client" do
    @store = FailingStore.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    @store.failing = true
    c = connect
    command(c, "s0", "SELECT INBOX")
    replies = {
      "CREATE" => command(c, "f1", "CREATE Box"),
      "DELETE" => command(c, "f2", "DELETE Sent"),
      "RENAME" => command(c, "f3", "RENAME Sent Sent2"),
      "APPEND" => append(c, "f4", "INBOX", "Subject: x\r\n\r\nbody\r\n", date: "01-Jan-999999999 00:00:00 +0000"),
      "COPY" => command(c, "f5", "COPY 1 Sent"),
      "MOVE" => command(c, "f6", "MOVE 1 Sent")
    }
    replies.each do |verb, reply|
      assert_match(/\Af\d NO \[UNAVAILABLE\] #{verb} failed: temporary server error\r\n\z/, reply, verb)
      refute_match(/ActiveRecord|PG::|SELECT|mail_on_rails_/, reply, verb)
    end
    assert_match(/\Af7 OK/, command(c, "f7", "NOOP"))
  end

  # ...while the store's own short reasons for the codes it defines still
  # come through with their response codes.
  test "known store failure codes keep their response codes" do
    @store.append(@account_id, "INBOX", "From: s@r.test\r\nSubject: k\r\n\r\nx\r\n", [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")
    assert_match(/\Ak1 NO \[TRYCREATE\] COPY failed: no such mailbox/, command(c, "k1", "COPY 1 Nope"))
    assert_match(/\Ak2 NO \[ALREADYEXISTS\] CREATE failed: mailbox exists/, command(c, "k2", "CREATE Sent"))
    assert_match(/\Ak3 NO \[NONEXISTENT\] DELETE failed: no such mailbox/, command(c, "k3", "DELETE Nope"))
  end
end

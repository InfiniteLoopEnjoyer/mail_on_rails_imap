# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# H3 (audit 2026-11-17): the lexer runs on every line a peer sends, before
# any state check, and it was quadratic in two shapes of line; and one
# pre-auth command could be 16 MiB, all of it tokenized. Covered here: the
# lexer is one pass, a command's total text and token count are capped
# (tightly before authentication), and the bare commands refuse arguments
# - while the large commands real clients send still work.
class CommandLimitsTest < Minitest::Test
  include WireHarness

  Server = MailOnRails::ImapServer
  Lexer = Server.const_get(:Lexer)

  def seconds
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  def drain(client)
    rest = +""
    while (line = client.gets("\r\n"))
      rest << line
    end
    rest
  rescue IOError, SystemCallError
    rest
  end

  # -- the lexer ---------------------------------------------------------------

  # Each of these took 8 s for a single 64 KiB line (0.14 s at 8 KiB,
  # quadrupling per doubling). One pass is a few milliseconds; the bound
  # only has to tell the two apart on a slow machine.
  test "an unterminated quote followed by escaped quotes is lexed in one pass" do
    line = %(x NOOP "#{'\\"' * 32_000}\r\n)
    lexer = nil

    assert_operator seconds { lexer = Lexer.new([ line ]) }, :<, 0.5
    assert_equal "Unterminated quoted string", lexer.error
    assert_equal %w[x NOOP], lexer.tokens, "the tokens before the error stay available (the tag)"
  end

  test "unbalanced brackets are balanced in one pass" do
    k = 21_000
    lexer = nil

    assert_operator seconds { lexer = Lexer.new([ "x NOOP #{"[" * k}#{" ]" * k}\r\n" ]) }, :<, 0.5
    assert_nil lexer.error
    assert_equal 3, lexer.tokens.length

    # Nothing but openers, space separated: each atom used to search the
    # rest of the line for a "]" that is not there.
    assert_operator seconds { lexer = Lexer.new([ "x NOOP #{"[ " * 30_000}\r\n" ]) }, :<, 0.5
    assert_equal 30_002, lexer.tokens.length
  end

  test "bracketed sections still lex as one token" do
    {
      "a FETCH 1 (BODY.PEEK[HEADER.FIELDS (DATE SUBJECT)]<0.2048> UID)" =>
        [ "a", "FETCH", "1", :lparen, "BODY.PEEK[HEADER.FIELDS (DATE SUBJECT)]<0.2048>", "UID", :rparen ],
      "a FETCH 1 BODY[1.2.HEADER.FIELDS.NOT (To Cc)]" => [ "a", "FETCH", "1", "BODY[1.2.HEADER.FIELDS.NOT (To Cc)]" ],
      "a X [[a b] c] d" => [ "a", "X", "[[a b] c]", "d" ],
      "a X [open (never closed" => [ "a", "X", "[open", :lparen, "never", "closed" ],
      %(a LOGIN "us\\"er" "p\\\\w") => [ "a", "LOGIN", 'us"er', "p\\w" ],
      "a STORE 1 +FLAGS (\\Seen $Forwarded)" => [ "a", "STORE", "1", "+FLAGS", :lparen, "\\Seen", "$Forwarded", :rparen ]
    }.each do |line, tokens|
      lexer = Lexer.new([ "#{line}\r\n" ])
      assert_nil lexer.error, line
      assert_equal tokens, lexer.tokens, line
    end
  end

  test "literals are tokens of their own and the literal marker is not" do
    lexer = Lexer.new([ "a LOGIN {4}\r\n", [ :lit, "us er" ], " {2+}\r\n", [ :lit, "p\"" ], "\r\n" ])

    assert_nil lexer.error
    assert_equal [ "a", "LOGIN", "us er", "p\"" ], lexer.tokens
  end

  test "the lexer stops at its token cap" do
    lexer = Lexer.new([ "a X #{"y " * 100}\r\n" ], max_tokens: 10)

    assert_equal "Too many arguments", lexer.error
    assert_equal 10, lexer.tokens.length
  end

  # -- on the wire: syntax errors are errors -----------------------------------

  test "an unterminated quote is BAD with the command's tag, and the session goes on" do
    c = connect
    assert_equal "a1 BAD Unterminated quoted string\r\n", command(c, "a1", %(NOOP "oops))
    assert_equal "a2 BAD Unterminated quoted string\r\n", command(c, "a2", %(SELECT "INBOX))
    assert_match(/\Aa3 OK/, command(c, "a3", "NOOP"))
  end

  test "NOOP, CAPABILITY and LOGOUT refuse trailing arguments" do
    c = connect(login: false)
    assert_equal "a1 BAD NOOP takes no arguments\r\n", command(c, "a1", "NOOP please")
    assert_equal "a2 BAD CAPABILITY takes no arguments\r\n", command(c, "a2", "CAPABILITY (x)")
    assert_equal "a3 BAD LOGOUT takes no arguments\r\n", command(c, "a3", %(LOGOUT "now"))
    # ...and the bare forms are untouched.
    assert_match(/\Aa4 OK NOOP/, command(c, "a4", "NOOP"))
    assert_match(/^a5 OK CAPABILITY/, command(c, "a5", "CAPABILITY"))
    assert_match(/^a6 OK LOGOUT/, command(c, "a6", "LOGOUT"))
  end

  # -- on the wire: before authentication --------------------------------------

  # These send exactly the bytes that reach the cap and no more: the
  # server hangs up without draining, and unread input would turn its
  # close into a reset that can swallow the BAD line the test reads.
  test "a pre-auth line over the pre-auth cap ends the session" do
    c = connect(login: false)
    c.write("x NOOP #{"a" * Server::MAX_PREAUTH_COMMAND_BYTES}"[0, Server::MAX_PREAUTH_COMMAND_BYTES])

    assert_equal "* BAD Command line too long\r\n", c.gets("\r\n")
    assert_nil c.gets("\r\n"), "the connection is closed"
  end

  # The reviewer's 16 MiB command: 256 empty LITERAL+ literals, each
  # followed by another 64 KiB line of one-byte atoms. It cost +544 MB.
  # Now the first fragment is already over the pre-auth line cap.
  test "a pre-auth command cannot be stretched across literals" do
    c = connect(login: false)
    first = "x NOSUCH #{"a " * 2_000}{0+}\r\n" # 4 KiB: under the line cap on its own
    c.write(first)
    # The second fragment gets what the first left of the cap.
    c.write("a" * (Server::MAX_PREAUTH_COMMAND_BYTES - first.bytesize))

    assert_equal "* BAD Command line too long\r\n", c.gets("\r\n")
    assert_nil c.gets("\r\n")
  end

  test "a pre-auth command gets a few literals, not hundreds" do
    c = connect(login: false)
    c.write("x NOSUCH #{"{1+}\r\ny" * (Server::MAX_PREAUTH_LITERALS + 1)}\r\n")

    assert_match(/\Ax NO \[TOOBIG\]/, c.gets("\r\n"))
    assert_match(/\* BYE/, drain(c))
  end

  test "pre-auth commands are held to the pre-auth token cap" do
    c = connect(login: false)
    line = "x ID (#{%("k" "v" ) * 70})" # 140 strings: over 128 tokens, under 8 KiB

    assert_equal "x BAD Too many arguments\r\n", command(c, "x", line)
  end

  test "the commands a client sends before logging in fit the pre-auth caps" do
    c = connect(login: false)
    # RFC 2971's maximum: 30 field/value pairs.
    id = (1..30).map { |i| %("field#{i}" "value number #{i} of an ordinary client") }.join(" ")
    assert_match(/^a1 OK ID/, command(c, "a1", "ID (#{id})"))

    # LOGIN with both arguments as literals.
    c.write("a2 LOGIN {#{EMAIL.bytesize}+}\r\n#{EMAIL} {#{PASSWORD.bytesize}+}\r\n#{PASSWORD}\r\n")
    assert_match(/\Aa2 OK/, read_until_tagged(c, "a2"))
  end

  test "AUTHENTICATE PLAIN with an initial response fits the pre-auth caps" do
    c = connect(login: false)
    response = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")

    assert_match(/\Aa1 OK/, command(c, "a1", "AUTHENTICATE PLAIN #{response}"))
  end

  # -- on the wire: authenticated ----------------------------------------------

  test "an authenticated command's text across its literals is held to one line's worth" do
    c = connect
    first = "x NOSUCH #{"a " * (Server::MAX_LINE / 4)}{0+}\r\n" # half the line cap
    second = "#{"a " * (Server::MAX_LINE / 8)}{0+}\r\n"          # three quarters with this
    c.write(first + second)
    c.write("a" * (Server::MAX_LINE - first.bytesize - second.bytesize))

    assert_equal "* BAD Command line too long\r\n", c.gets("\r\n")
    assert_nil c.gets("\r\n")
  end

  test "an authenticated command is held to the token cap" do
    c = connect
    command(c, "s", "SELECT INBOX")

    assert_equal "a1 BAD Too many arguments\r\n", command(c, "a1", "SEARCH #{"ALL " * (Server::MAX_COMMAND_TOKENS + 1)}")
    assert_match(/\Aa2 OK/, command(c, "a2", "NOOP"), "the session survives")
  end

  # What must keep working: the largest things real clients send.
  test "a sequence set tens of kilobytes long is one token and is accepted" do
    c = connect
    3.times { |i| append(c, "p#{i}", "INBOX", "Subject: m#{i}\r\n\r\nb\r\n") }
    command(c, "s", "SELECT INBOX")
    # 500 ranges (under MAX_SEQUENCE_CHUNKS), padded to ~60 KiB with
    # leading zeros - the shape of a client listing every uid it knows.
    set = (1..500).map { |i| format("%0110d", i) }.join(",")
    assert_operator set.bytesize, :>, 55_000

    reply = command(c, "f", "UID FETCH #{set} (FLAGS)")
    assert_equal 3, reply.scan(/^\* \d+ FETCH/).length
    assert_match(/^f OK/, reply)
  end

  test "APPEND with a large literal and SEARCH with several literals still work" do
    c = connect
    body = "x" * (2 * 1024 * 1024)
    assert_match(/\Aa1 OK \[APPENDUID/, append(c, "a1", "INBOX", "Subject: big one\r\n\r\n#{body}\r\n", flags: %w[\\Seen $Label1]))
    command(c, "s", "SELECT INBOX")

    c.write("a2 SEARCH OR SUBJECT {3+}\r\nbig SUBJECT {7+}\r\nmissing NOT FROM {5+}\r\nx@y.z\r\n")
    assert_match(/^\* SEARCH 1\r\n/, read_until_tagged(c, "a2"))

    # Synchronizing literals, one continuation each.
    c.write("a3 SEARCH SUBJECT {3}\r\n")
    assert_match(/\A\+ /, c.gets("\r\n"))
    c.write("big TEXT {3}\r\n")
    assert_match(/\A\+ /, c.gets("\r\n"))
    c.write("one\r\n")
    assert_match(/^\* SEARCH 1\r\n/, read_until_tagged(c, "a3"))
  end

  test "a STORE with the maximum flag list and a long FETCH item list are under the token cap" do
    c = connect
    append(c, "p", "INBOX", "Subject: m\r\n\r\nb\r\n")
    command(c, "s", "SELECT INBOX")
    keywords = (1..Server::MAX_KEYWORDS).map { |i| "kw#{i}" }

    assert_match(/^a1 OK/, command(c, "a1", "STORE 1 +FLAGS.SILENT (#{keywords.join(" ")})"))
    items = (1..40).map { |i| "BODY.PEEK[HEADER.FIELDS (X-H#{i} Subject)]" }
    reply = command(c, "a2", "FETCH 1 (UID FLAGS #{items.join(" ")})")
    assert_match(/^a2 OK/, reply)
    assert_equal 40, reply.scan("BODY[HEADER.FIELDS").length
  end
end

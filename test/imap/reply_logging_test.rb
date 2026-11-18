# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# What the session writes down about itself: the transcript (stored by
# imap_trace_capture, and in honeypot events) and the imap_trace log.
#
# M9 (audit 2026-11-17): replies were handed over whole, so a captured
# session held ENVELOPEs, previews and bodies - a reset during a large
# FETCH stored the entire literal, past the transcript's size cap - while
# the stored row is documented as "no message content".
# L19: the credential redaction matched a pattern against the raw line and
# disagreed with the lexer about what the command was.
class ReplyLoggingTest < Minitest::Test
  include WireHarness

  SECRET_BODY = "Your one-time code is 493817."
  SUBJECT = "private subject line"

  class LoggingStore < MailOnRails::Imap::Store::Memory
    attr_reader :logged

    def initialize(**)
      super
      @logged = []
    end

    def log(level, message)
      @logged << [ level, message ]
      nil
    end
  end

  def session_spec = { tls: :implicit, trace: true, trace_capture: true }

  def setup
    super
    @store = LoggingStore.new(max_account_failures: 1000, max_ip_failures: 1000)
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def transcript = @session_objects.last.send(:honeypot_transcript).to_s

  def trace_lines = @store.logged.map(&:last).select { |line| line.start_with?("IMAP <=", "IMAP =>") }

  def wait_for_sessions
    @clients.each { |c| c.close rescue nil }
    @sessions.each { |t| t.join(5) }
  end

  def raw_message(body = SECRET_BODY)
    "From: Alice Sender <alice@remote.test>\r\nTo: user@example.test\r\nSubject: #{SUBJECT}\r\n" \
      "Content-Type: text/plain; charset=utf-8\r\n\r\n#{body}\r\n"
  end

  # -- M9: replies ---------------------------------------------------------------

  test "a captured session holds the shape of its FETCH responses, not the mail" do
    @store.append(@account_id, "INBOX", raw_message, [], nil)
    c = connect
    command(c, "s", "SELECT INBOX")
    command(c, "f1", "FETCH 1 (UID FLAGS ENVELOPE BODYSTRUCTURE PREVIEW)")
    command(c, "f2", "FETCH 1 (BODY.PEEK[] BODY.PEEK[HEADER.FIELDS (Subject)] RFC822.SIZE)")
    command(c, "f3", "FETCH 1 (BODY[TEXT] RFC822.HEADER)")
    command(c, "e", "BOGUS") # a protocol error: the session now qualifies for capture
    wait_for_sessions

    capture = @session_objects.last.transcript_capture
    refute_nil capture
    text = capture[:transcript]
    [ SECRET_BODY, "493817", SUBJECT, "Alice Sender", "alice", "remote.test" ].each do |content|
      refute_includes text, content, "the transcript must not hold #{content.inspect}"
      refute trace_lines.any? { |line| line.include?(content) }, "nor the trace log"
    end

    raw = raw_message
    assert_includes text, "=> * 1 FETCH (UID 1 FLAGS () ENVELOPE <omitted> BODYSTRUCTURE <omitted> PREVIEW <omitted>)"
    assert_includes text, "=> * 1 FETCH (BODY[] {#{raw.bytesize}}<omitted> BODY[HEADER.FIELDS (SUBJECT)] {#{SUBJECT.bytesize + 13}}<omitted> " \
                          "RFC822.SIZE #{raw.bytesize})"
    assert_match(/=> \* 1 FETCH \(BODY\[TEXT\] \{\d+\}<omitted> RFC822\.HEADER \{\d+\}<omitted> FLAGS \(\\Seen\)\)/, text)
    # The commands are the part worth keeping, and are.
    assert_includes text, "<= f2 FETCH 1 (BODY.PEEK[] BODY.PEEK[HEADER.FIELDS (Subject)] RFC822.SIZE)"
    assert_includes text, "=> f3 OK FETCH completed"
  end

  # The reviewer's 5,200,055-byte capture: the connection drops during a
  # FETCH of a large message, so the response is the transcript's last
  # line - the one line the byte cap never dropped.
  test "a connection lost during a large FETCH does not leave the message in the transcript" do
    @store.append(@account_id, "INBOX", raw_message("TOP-SECRET-MAIL-BODY " * 250_000), [], nil)
    c = connect
    command(c, "s", "SELECT INBOX")
    c.write("f FETCH 1 (BODY.PEEK[])\r\n")
    c.close # without reading: the server's 5 MB write fails part-way
    @sessions.each { |t| t.join(5) }

    capture = @session_objects.last.transcript_capture
    assert_equal "connection_lost", capture[:close_reason]
    text = capture[:transcript]
    assert_operator text.bytesize, :<, 2_000
    refute_includes text, "TOP-SECRET"
    # The response never finished, so it is not recorded as sent; the
    # command that was being answered is the last thing in the dialogue.
    assert text.end_with?("<= f FETCH 1 (BODY.PEEK[])"), text.lines.last
  end

  test "literals in other replies are recorded by size" do
    long = "L" * 600 # past the quoted-string length: LIST sends it as a literal
    @store.create_mailbox(@account_id, long)
    c = connect

    reply = command(c, "l", %(LIST "" "*"))
    assert_includes reply, "{600}\r\n#{long}", "the client still gets the name"
    assert_includes transcript, %(=> * LIST (\\HasNoChildren) "/" {600}<omitted>)
    refute_includes transcript, "LLLL"
  end

  test "a long reply line is cut short in the transcript and the trace" do
    300.times { |i| @store.append(@account_id, "INBOX", "Subject: m#{i}\r\n\r\nb\r\n", [], nil) }
    c = connect
    command(c, "s", "SELECT INBOX")
    reply = command(c, "q", "SEARCH ALL")
    full = reply.lines.first.chomp

    assert_operator full.bytesize, :>, MailOnRails::ImapServer::MAX_LOGGED_REPLY_BYTES
    logged = transcript.lines.find { |line| line.start_with?("=> * SEARCH") }.chomp
    assert_equal "=> #{full.byteslice(0, MailOnRails::ImapServer::MAX_LOGGED_REPLY_BYTES)}... (#{full.bytesize} bytes)", logged
  end

  # -- the trace log -------------------------------------------------------------

  test "a lone CR in a command reaches the trace log as an escape" do
    c = connect
    c.write("n1 NOOP\r[mail_on_rails] IMAP login admin@example.test (10.0.0.1)\r\n")
    read_until_tagged(c, "n1")

    line = trace_lines.find { |l| l.include?("n1 NOOP") }
    refute_nil line
    refute_includes line, "\r"
    assert_includes line, 'n1 NOOP\r[mail_on_rails]'
  end

  # -- L19: credentials ----------------------------------------------------------

  test "credentials are redacted however the login command is spelled" do
    plain = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
    wrong = [ "\0#{EMAIL}\0wrongpass-SECRET4" ].pack("m0")
    lines = [
      "a1 LOGIN #{EMAIL} wrongpass-SECRET0",
      "a2 UID LOGIN #{EMAIL} wrongpass-SECRET1",
      %(a3 "LOGIN" #{EMAIL} wrongpass-SECRET2),
      %("a 4" LOGIN #{EMAIL} wrongpass-SECRET3),
      "a5 UID AUTHENTICATE PLAIN #{wrong}",
      %(a6 "AUTHENTICATE" PLAIN #{wrong}),
      %(a7 "login" "#{EMAIL}" "wrongpass-SECRET5"),
      %(a8 LOGIN #{EMAIL} "wrongpass-SECRET6), # unterminated quote: never lexed to the end
      %("a9 LOGIN #{EMAIL} wrongpass-SECRET7),
      "\ta10\tLOGIN\t#{EMAIL}\twrongpass-SECRET8",
      "a11 AUTHENTICATE PLAIN #{plain}"
    ]

    lines.each do |line|
      c = connect(login: false)
      c.write("#{line}\r\n")
      c.gets("\r\n")
      c.close
    end
    @sessions.each { |t| t.join(5) }

    recorded = @session_objects.map { |s| s.send(:honeypot_transcript).to_s }.join("\n") + trace_lines.join("\n")
    refute_match(/SECRET\d/, recorded)
    refute_includes recorded, wrong
    refute_includes recorded, plain
    refute_includes recorded, PASSWORD
    assert_includes recorded, "<= a1 LOGIN [redacted]"
    assert_includes recorded, "<= a3 LOGIN [redacted]"
    assert_includes recorded, "<= a 4 LOGIN [redacted]"
    assert_includes recorded, "<= a6 AUTHENTICATE PLAIN [redacted]"
    assert_includes recorded, "<= [redacted: unparsed line naming LOGIN or AUTHENTICATE]"
  end

  test "UID is refused in front of commands that are not message commands" do
    c = connect(login: false)
    assert_equal "a1 BAD UID is not valid with LOGIN\r\n", command(c, "a1", "UID LOGIN #{EMAIL} #{PASSWORD}")
    assert_equal "a2 BAD UID is not valid with STARTTLS\r\n", command(c, "a2", "UID STARTTLS")
    assert_equal "a3 BAD UID is not valid with NOOP\r\n", command(c, "a3", "UID NOOP")
    assert_match(/\Aa4 NO Not authenticated/, command(c, "a4", "SELECT INBOX"), "UID LOGIN did not log in")

    assert_match(/\Aa5 OK/, command(c, "a5", "LOGIN #{EMAIL} #{PASSWORD}"))
    @store.append(@account_id, "INBOX", raw_message, [], nil)
    command(c, "a6", "SELECT INBOX")
    {
      "UID FETCH 1 (FLAGS)" => /OK FETCH/, "UID STORE 1 +FLAGS.SILENT (\\Flagged)" => /OK STORE/,
      "UID SEARCH ALL" => /OK SEARCH/, "UID SORT (ARRIVAL) UTF-8 ALL" => /OK SORT/,
      "UID THREAD REFERENCES UTF-8 ALL" => /OK THREAD/, "UID COPY 1 INBOX" => /OK \[COPYUID/,
      "UID EXPUNGE 99" => /OK EXPUNGE/, "UID MOVE 99 INBOX" => /OK MOVE/,
      "UID SELECT INBOX" => /BAD UID is not valid with SELECT/, "UID" => /BAD Unknown command UID/
    }.each_with_index do |(line, expected), i|
      assert_match(/^u#{i} #{expected.source}/, command(c, "u#{i}", line), line)
    end
  end
end

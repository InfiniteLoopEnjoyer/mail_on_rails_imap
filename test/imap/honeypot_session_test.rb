require "test_helper"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# Honeypot behavior on the IMAP session: a canary login is observed while the
# attacker browses (SELECT/FETCH), exploit-probe payloads are recorded and
# refused, credentials are redacted from the transcript, and a deceptive banner
# can replace the greeting. Driven directly over a loopback socket - no Rails.
class ImapHoneypotSessionTest < Minitest::Test
  CANARY = "admin@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: decoy\r\n\r\nlure body\r\n"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @canary_id = @store.add_account(email: CANARY, password: PASSWORD, honeypot: true)
    @store.append(@canary_id, "INBOX", RAW, [], nil)
    @store.add_account(email: "real@example.test", password: PASSWORD)
  end

  def with_session(spec: { tls: :implicit })
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    @session = MailOnRails::ImapServer::Session.new(session_socket, @store, spec, nil)
    thread = Thread.new { @session.run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    @session&.finalize_honeypot # the Server calls this at teardown
    server&.close
  end

  def read_until_tagged(client, tag)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line.start_with?("#{tag} ")
    end
    lines.join
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_until_tagged(client, tag)
  end

  def test_canary_login_is_recorded_and_browsing_is_observed
    with_session do |client|
      client.gets("\r\n")
      assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{CANARY} #{PASSWORD}"))
      command(client, "a2", "SELECT INBOX")
      command(client, "a3", "FETCH 1 (BODY[])")
      command(client, "a4", "LOGOUT")
    end

    assert_equal 1, @store.honeypot_events.size
    event = @store.honeypot_events.first
    assert_equal "canary_auth", event[:trigger]
    assert_equal "imap", event[:protocol]
    assert_equal CANARY, event[:username]
    # The post-login browsing (flushed at teardown) is captured.
    assert_includes event[:transcript], "SELECT INBOX"
    assert_includes event[:transcript], "FETCH 1 (BODY[])"
  end

  # M6 (audit 2026-11-17): a canary session used to be an ordinary
  # full-privilege session for up to 24 h - whoever guessed the decoy's
  # password could store unlimited mail, and file it into and out of Junk
  # to train the server-wide spam classifier. It is now look-only: every
  # mailbox opens read-only, every write is refused the way a locked or
  # full account refuses it, and nothing in the store changes.
  def test_canary_session_can_look_but_not_change_anything
    @store.create_mailbox(@canary_id, "Archive")
    before = canary_state

    with_session do |client|
      client.gets("\r\n")
      assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{CANARY} #{PASSWORD}"))

      select = command(client, "s1", "SELECT INBOX")
      assert_match(/^\* 1 EXISTS/, select)
      assert_match(/^s1 OK \[READ-ONLY\] SELECT completed/, select)

      # Looking works, and leaves no trace: BODY[] would set \Seen.
      assert_includes command(client, "f1", "FETCH 1 (BODY[])"), "lure body"
      refute_match(/Seen/, command(client, "f2", "FETCH 1 (FLAGS)"))
      assert_match(/^\* SEARCH 1\r\n/, command(client, "f3", "SEARCH TEXT lure"))
      assert_match(/^\* LIST .* "Archive"/, command(client, "f4", %(LIST "" "*")))
      assert_match(/^f5 OK/, command(client, "f5", "STATUS Archive (MESSAGES)"))

      {
        "STORE 1 +FLAGS (\\Deleted)" => /NO Mailbox is read-only/,
        "EXPUNGE" => /NO Mailbox is read-only/,
        "UID EXPUNGE 1" => /NO Mailbox is read-only/,
        "MOVE 1 Junk" => /NO Mailbox is read-only/,
        "COPY 1 Junk" => /NO \[OVERQUOTA\] COPY failed: quota exceeded/,
        "UID COPY 1 Archive" => /NO \[OVERQUOTA\]/,
        "CREATE Loot" => /NO \[NOPERM\] CREATE failed: permission denied/,
        "DELETE Archive" => /NO \[NOPERM\]/,
        "RENAME Archive Elsewhere" => /NO \[NOPERM\]/,
        "RENAME INBOX Elsewhere" => /NO \[NOPERM\]/
      }.each_with_index do |(line, expected), i|
        assert_match(/\Aw#{i} #{expected.source}/, command(client, "w#{i}", line), line)
      end

      # APPEND, both literal forms: the message is taken off the wire (the
      # stream stays framed) and thrown away.
      client.write("p1 APPEND Junk {#{RAW.bytesize}+}\r\n#{RAW}\r\n")
      assert_match(/\Ap1 NO \[OVERQUOTA\] APPEND failed: quota exceeded/, read_until_tagged(client, "p1"))
      client.write("p2 APPEND INBOX {#{RAW.bytesize}}\r\n")
      assert_match(/\A\+ /, client.gets("\r\n"))
      client.write("#{RAW}\r\n")
      assert_match(/\Ap2 NO \[OVERQUOTA\]/, read_until_tagged(client, "p2"))

      # REPLACE and CLOSE's implicit expunge go the read-only way too.
      client.write("p3 REPLACE 1 INBOX {#{RAW.bytesize}+}\r\n#{RAW}\r\n")
      assert_match(/\Ap3 NO Mailbox is read-only/, read_until_tagged(client, "p3"))
      assert_match(/\Ac1 OK/, command(client, "c1", "CLOSE"))
      command(client, "z", "LOGOUT")
    end

    assert_equal before, canary_state
    assert_includes @store.honeypot_events.first[:transcript], "APPEND Junk", "the attempts are still the intel"
  end

  def canary_state
    @store.list_mailboxes(@canary_id)[:mailboxes].sort.to_h do |name|
      [ name, @store.select_mailbox(@canary_id, name)[:messages] ]
    end
  end

  def test_a_real_account_keeps_read_write_mailboxes
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN real@example.test #{PASSWORD}")
      assert_match(/^a2 OK \[READ-WRITE\] SELECT completed/, command(client, "a2", "SELECT INBOX"))
      assert_match(/^a3 OK/, command(client, "a3", "CREATE Projects"))
      client.write("a4 APPEND Projects {#{RAW.bytesize}+}\r\n#{RAW}\r\n")
      assert_match(/\Aa4 OK \[APPENDUID/, read_until_tagged(client, "a4"))
      command(client, "a5", "LOGOUT")
    end
  end

  # A canary session ends after HONEYPOT_SESSION_SECONDS whatever it is
  # doing - here, sitting in IDLE, which no inactivity timeout touches.
  def test_canary_session_is_ended_after_its_short_lifetime
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    with_session(spec: { tls: :implicit, honeypot_session_seconds: 0.5 }) do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{CANARY} #{PASSWORD}")
      command(client, "a2", "SELECT INBOX")
      client.write("a3 IDLE\r\n")
      assert_match(/\A\+ /, client.gets("\r\n"))

      assert_nil client.gets("\r\n"), "the server hangs up"
    end

    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
    assert_equal "honeypot_session_limit", @session.instance_variable_get(:@close_reason)
    assert_equal 300, MailOnRails::ImapServer::HONEYPOT_SESSION_SECONDS
  end

  def test_a_real_session_has_no_such_lifetime
    with_session(spec: { tls: :implicit, honeypot_session_seconds: 0.3 }) do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN real@example.test #{PASSWORD}")
      sleep 0.8
      assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"))
      command(client, "a3", "LOGOUT")
    end
  end

  # L21 (audit 2026-11-17): the probe signatures ran on authenticated
  # lines too, where they match ordinary commands - this APPEND read as
  # shellshock, so the user's draft was dropped and a honeypot event
  # recorded against the user.
  def test_probe_signatures_are_not_run_on_an_authenticated_session
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN real@example.test #{PASSWORD}")
      command(client, "a2", "CREATE Drafts")
      client.write("a3 APPEND Drafts () {#{RAW.bytesize}}\r\n")
      assert_match(/\A\+ /, client.gets("\r\n"), "the literal is accepted")
      client.write("#{RAW}\r\n")
      assert_match(/\Aa3 OK \[APPENDUID/, read_until_tagged(client, "a3"))
      command(client, "a4", "SELECT Drafts")
      assert_match(/^a5 OK/, command(client, "a5", %(SEARCH HEADER Message-ID "<${run{x}}@evil.example>")))
      command(client, "a6", "LOGOUT")
    end

    assert_empty @store.honeypot_events
    refute @session.honeypot_fired?
  end

  def test_transcript_redacts_the_login_password
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{CANARY} #{PASSWORD}")
      command(client, "a2", "LOGOUT")
    end

    transcript = @store.honeypot_events.first[:transcript]
    assert_includes transcript, "a1 LOGIN [redacted]"
    refute_includes transcript, PASSWORD
  end

  def test_a_normal_account_login_records_nothing
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN real@example.test #{PASSWORD}")
      command(client, "a2", "LOGOUT")
    end

    assert_empty @store.honeypot_events
  end

  def test_exploit_probe_is_recorded_and_refused
    with_session do |client|
      client.gets("\r\n")
      reply = command(client, "a1", "SELECT () { :; }; /bin/sh")
      assert_match(/\Aa1 BAD/, reply)
      command(client, "a2", "LOGOUT")
    end

    event = @store.honeypot_events.first
    assert_equal "exploit_probe", event[:trigger]
    assert_equal "shellshock", event[:signature]
  end

  def test_deceptive_banner_replaces_the_greeting
    with_session(spec: { tls: :implicit, honeypot_banner: "Dovecot ready" }) do |client|
      assert_match(/Dovecot ready/, client.gets("\r\n"))
      command(client, "a1", "LOGOUT")
    end
  end

  # An HTTP scanner's request line: the tag it "sends" is GET, so the BAD
  # is tagged GET; recorded under its own trigger for protocol_auto_ban.
  def test_http_request_at_the_imap_port_is_recorded_as_a_foreign_protocol
    with_session do |client|
      client.gets("\r\n")
      assert_match(/\AGET BAD Unknown command\r\n\z/, command(client, "GET", "/ HTTP/1.1"))
      command(client, "a2", "LOGOUT")
    end

    event = @store.honeypot_events.first
    assert_equal "foreign_protocol", event[:trigger]
    assert_equal "http_request", event[:signature]
    assert_includes event[:transcript], "<= GET / HTTP/1.1"
  end

  # A scanner's binary blob carries no CRLF, so it reaches handle as one
  # unterminated line at EOF. It is named, recorded, and the junk "tag" is
  # not echoed back (before, the BAD carried the first run of bytes as its
  # tag).
  def test_tls_handshake_on_the_plaintext_port_is_recorded_and_not_reflected
    with_session do |client|
      client.gets("\r\n")
      client.write("\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03\xff\xfe".b)
      client.close_write
      assert_equal "* BAD Unknown command\r\n", client.gets("\r\n")
    end

    event = @store.honeypot_events.first
    assert_equal "foreign_protocol", event[:trigger]
    assert_equal "tls_handshake", event[:signature]
  end

  def test_garbage_bytes_are_recorded_and_refused_and_the_session_survives
    with_session do |client|
      client.gets("\r\n")
      # The junk "tag" is cut at its first non-printable byte, so the
      # reply is tagged "b" - the test's tag-matching reader can't be used.
      client.write("b\x00/{m<;s3gMm>.4 ;1\r\n")
      assert_equal "b BAD Unknown command\r\n", client.gets("\r\n")
      client.write("\xff\xfe junk\r\n".b)
      assert_equal "* BAD Unknown command\r\n", client.gets("\r\n")
      assert_match(/\Aa3 OK/, command(client, "a3", "NOOP"), "the session is still usable afterwards")
      command(client, "a4", "LOGOUT")
    end

    assert_equal 1, @store.honeypot_events.size, "one event per session, not per line"
    event = @store.honeypot_events.first
    assert_equal "garbage", event[:trigger]
    assert_equal "control_bytes", event[:signature]
  end
end

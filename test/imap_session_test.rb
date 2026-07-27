require "test_helper"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# End-to-end IMAP session over a real loopback socket, backed by the
# contract's reference store - no Rails, no database. The session is
# constructed as an implicit-TLS listener would build it (spec tls:
# :implicit) so LOGIN is permitted on what is, here, a plain test socket.
class ImapSessionTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @store.append(@account_id, "INBOX", RAW, [ "\\Seen" ], nil)
  end

  def with_session
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    session_socket = server.accept
    thread = Thread.new { MailOnRails::ImapServer::Session.new(session_socket, @store, { tls: :implicit }, nil).run }
    yield client
  ensure
    client&.close
    thread&.join(5)
    server&.close
  end

  # Everything up to and including the tagged completion for +tag+.
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

  def test_login_select_fetch_logout_end_to_end
    with_session do |client|
      assert_match(/\A\* OK \[CAPABILITY IMAP4rev1/, client.gets("\r\n"))

      assert_match(/\Aa1 OK/, command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}"))

      select = command(client, "a2", "SELECT INBOX")
      assert_match(/^\* 1 EXISTS/, select)
      assert_match(/UIDVALIDITY/, select)
      assert_match(/\[READ-WRITE\]/, select[/a2 .*/])

      fetch = command(client, "a3", "FETCH 1 (UID FLAGS RFC822.SIZE)")
      assert_match(/\A\* 1 FETCH \(/, fetch)
      assert_match(/UID 1/, fetch)
      assert_match(/\\Seen/, fetch)
      assert_match(/RFC822\.SIZE #{RAW.bytesize}/, fetch)
      assert_match(/^a3 OK/, fetch)

      logout = command(client, "a4", "LOGOUT")
      assert_match(/\A\* BYE/, logout)
      assert_match(/^a4 OK/, logout)
    end
  end

  def test_login_is_rejected_with_bad_credentials
    with_session do |client|
      client.gets("\r\n")
      assert_match(/\Aa1 NO/, command(client, "a1", "LOGIN #{EMAIL} wrong-password"))
      assert_match(/\Aa2 BAD Not authenticated|\Aa2 NO/, command(client, "a2", "SELECT INBOX"))
      command(client, "a3", "LOGOUT")
    end
  end

  def login_and_select(client)
    client.gets("\r\n")
    command(client, "l1", "LOGIN #{EMAIL} #{PASSWORD}")
    command(client, "l2", "SELECT INBOX")
  end

  # Temporarily overrides a session tuning constant (literal cap, IDLE
  # poll interval) so limits are testable without 30 MiB payloads or
  # 30-second waits.
  def with_imap_const(name, value)
    klass = MailOnRails::ImapServer
    old = klass.const_get(name)
    klass.send(:remove_const, name)
    klass.const_set(name, value)
    yield
  ensure
    klass.send(:remove_const, name)
    klass.const_set(name, old)
  end

  def with_max_literal(bytes, &block)
    with_imap_const(:MAX_LITERAL_BYTES, bytes, &block)
  end

  def test_uid_expunge_honors_its_sequence_set
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 2
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 3
    with_session do |client|
      login_and_select(client)

      command(client, "a1", "STORE 1:2 +FLAGS.SILENT (\\Deleted)")
      expunge = command(client, "a2", "UID EXPUNGE 1")
      assert_match(/\A\* 1 EXPUNGE\r\na2 OK/, expunge)

      # uid 2 is still present (and still \Deleted); uid 3 untouched.
      fetch = command(client, "a3", "FETCH 1:* (UID)")
      assert_match(/\* 1 FETCH \(UID 2\)/, fetch)
      assert_match(/\* 2 FETCH \(UID 3\)/, fetch)
      command(client, "a4", "LOGOUT")
    end
  end

  def test_uid_expunge_requires_a_sequence_set
    with_session do |client|
      login_and_select(client)
      assert_match(/\Aa1 BAD/, command(client, "a1", "UID EXPUNGE"))
      command(client, "a2", "LOGOUT")
    end
  end

  def test_oversize_synchronizing_literal_is_refused_and_session_survives
    with_max_literal(100) do
      with_session do |client|
        login_and_select(client)
        refused = command(client, "a1", "APPEND INBOX {200}")
        assert_match(/\Aa1 NO literal too large/, refused)
        assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"))
        command(client, "a3", "LOGOUT")
      end
    end
  end

  def test_oversize_nonsync_literal_is_drained_not_parsed_as_commands
    with_max_literal(100) do
      with_session do |client|
        login_and_select(client)
        # LITERAL+ clients send the octets without waiting; the payload is
        # crafted to look like IMAP commands so a desync would surface as
        # responses to them.
        payload = "x9 STORE 1 +FLAGS (\\Deleted)\r\n" * 7
        payload = payload[0, 200]
        client.write("a1 APPEND INBOX {200+}\r\n#{payload}\r\n")
        assert_match(/\Aa1 NO literal too large/, read_until_tagged(client, "a1"))
        assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"))
        command(client, "a3", "LOGOUT")
      end
    end
  end

  def test_authenticate_continuation_line_is_length_capped
    with_session do |client|
      client.gets("\r\n")
      client.write("a1 AUTHENTICATE PLAIN\r\n")
      assert_equal "+ \r\n", client.gets("\r\n")
      client.write("A" * (MailOnRails::ImapServer::MAX_LINE + 1024))
      assert_match(/\A\* BAD Command line too long/, client.gets("\r\n"))
      # The server aborts with our surplus bytes unread, so the close can
      # surface as EOF or a reset depending on timing.
      last = begin
        client.gets("\r\n")
      rescue Errno::ECONNRESET
        nil
      end
      assert_nil last
    end
  end

  def test_search_unknown_key_is_bad
    with_session do |client|
      login_and_select(client)
      assert_match(/\Aa1 BAD Unknown search key BOGUSKEY/, command(client, "a1", "SEARCH BOGUSKEY"))
      command(client, "a2", "LOGOUT")
    end
  end

  def test_search_rejects_unsupported_charset
    with_session do |client|
      login_and_select(client)
      assert_match(/\Aa1 NO \[BADCHARSET \(US-ASCII UTF-8\)\]/, command(client, "a1", "SEARCH CHARSET KOI8-R ALL"))
      assert_match(/\A\* SEARCH 1\r\n/, command(client, "a2", "SEARCH CHARSET UTF-8 ALL"))
      command(client, "a3", "LOGOUT")
    end
  end

  def test_sent_date_searches_use_the_date_header_not_internaldate
    dated = "From: sender@remote.test\r\nDate: Tue, 15 Jul 2025 10:00:00 +0000\r\nSubject: old\r\n\r\nbody\r\n"
    @store.append(@account_id, "INBOX", dated, [], Time.now.to_i) # uid 2, delivered today
    with_session do |client|
      login_and_select(client)
      assert_match(/\A\* SEARCH 2\r\n/, command(client, "s1", "SEARCH SENTON 15-Jul-2025"))
      assert_match(/\A\* SEARCH\r\n/, command(client, "s2", "SEARCH ON 15-Jul-2025"))
      # The setup message has no Date header: SENT* must not match it.
      assert_match(/\A\* SEARCH 2\r\n/, command(client, "s3", "SEARCH SENTSINCE 1-Jan-2000"))
      command(client, "s4", "LOGOUT")
    end
  end

  def test_idle_pushes_new_mail_and_terminates_on_done
    with_imap_const(:IDLE_POLL_SECONDS, 0.05) do
      with_session do |client|
        login_and_select(client)
        client.write("i1 IDLE\r\n")
        assert_equal "+ idling\r\n", client.gets("\r\n")

        @store.append(@account_id, "INBOX", RAW, [], nil)
        assert_equal "* 2 EXISTS\r\n", client.gets("\r\n")

        client.write("DONE\r\n")
        assert_match(/\Ai1 OK/, read_until_tagged(client, "i1"))
        command(client, "i2", "LOGOUT")
      end
    end
  end

  def test_resync_reports_external_flag_changes
    with_session do |client|
      login_and_select(client)
      mailbox_id = @store.select_mailbox(@account_id, "INBOX")[:mailbox_id]
      @store.store_flags(mailbox_id, [ 1 ], "+", [ "\\Flagged" ])

      noop = command(client, "n1", "NOOP")
      assert_match(/\A\* 1 FETCH \(FLAGS \([^)]*\\Flagged[^)]*\)\)/, noop)
      command(client, "n2", "LOGOUT")
    end
  end

  def test_move_emits_copyuid_then_expunge
    with_session do |client|
      login_and_select(client)
      move = command(client, "m1", "MOVE 1 Trash")
      assert_match(/\A\* OK \[COPYUID \d+ 1 1\]\r\n\* 1 EXPUNGE\r\nm1 OK/, move)
      assert_match(/MESSAGES 1/, command(client, "m2", "STATUS Trash (MESSAGES)"))
      assert_match(/\* 0 EXISTS|MESSAGES 0/, command(client, "m3", "STATUS INBOX (MESSAGES)"))
      command(client, "m4", "LOGOUT")
    end
  end

  def test_uid_move_to_missing_mailbox_says_trycreate
    with_session do |client|
      login_and_select(client)
      assert_match(/\Am1 NO \[TRYCREATE\]/, command(client, "m1", "UID MOVE 1 Nope"))
      command(client, "m2", "LOGOUT")
    end
  end

  def test_unselect_leaves_deleted_messages_unexpunged
    with_session do |client|
      login_and_select(client)
      command(client, "u1", "STORE 1 +FLAGS.SILENT (\\Deleted)")
      assert_match(/\Au2 OK/, command(client, "u2", "UNSELECT"))
      assert_match(/\Au3 NO No mailbox selected/, command(client, "u3", "FETCH 1 (UID)"))
      assert_match(/^\* 1 EXISTS/, command(client, "u4", "SELECT INBOX"))
      command(client, "u5", "LOGOUT")
    end
  end

  def test_delete_and_rename_mailboxes
    with_session do |client|
      login_and_select(client)
      command(client, "d1", "CREATE Projects")
      command(client, "d2", "CREATE Projects/2026")

      assert_match(/\Ad3 OK/, command(client, "d3", "RENAME Projects Work"))
      list = command(client, "d4", "LIST \"\" *")
      assert_includes list, "Work/2026"
      refute_includes list, "Projects"

      assert_match(/\Ad5 NO Cannot delete INBOX/, command(client, "d5", "DELETE INBOX"))
      assert_match(/\Ad6 NO Cannot rename INBOX/, command(client, "d6", "RENAME INBOX Elsewhere"))
      assert_match(/\Ad7 OK/, command(client, "d7", "DELETE Work/2026"))
      refute_includes command(client, "d8", "LIST \"\" *"), "2026"
      command(client, "d9", "LOGOUT")
    end
  end

  def test_list_reports_children_and_special_use_attributes
    with_session do |client|
      login_and_select(client)
      command(client, "l3", "CREATE Work")
      command(client, "l4", "CREATE Work/2026")

      list = command(client, "l5", "LIST \"\" *")
      assert_match(/\* LIST \(\\HasChildren\) "\/" "Work"/, list)
      assert_match(/\* LIST \(\\HasNoChildren\) "\/" "Work\/2026"/, list)
      assert_match(/\* LIST \(\\HasNoChildren \\Sent\) "\/" "Sent"/, list)
      assert_match(/\* LIST \(\\HasNoChildren \\Trash\) "\/" "Trash"/, list)
      command(client, "l6", "LOGOUT")
    end
  end

  def test_utf7_mailbox_names_round_trip_through_create_list_select
    encoded = "T&AOk-l&AOk-com" # "Télécom"
    with_session do |client|
      login_and_select(client)
      assert_match(/\Ac1 OK/, command(client, "c1", "CREATE #{encoded}"))
      assert_includes command(client, "c2", "LIST \"\" *"), %("#{encoded}")
      assert_match(/^c3 OK/, command(client, "c3", "SELECT #{encoded}"))
      assert_match(/STATUS "#{Regexp.escape(encoded)}"/, command(client, "c4", "STATUS #{encoded} (MESSAGES)"))
      command(client, "c5", "LOGOUT")
    end

    assert_includes @store.list_mailboxes(@account_id)[:mailboxes], "Télécom"
  end

  def test_id_reports_server_identity
    with_session do |client|
      client.gets("\r\n")
      response = command(client, "z1", %(ID ("name" "test-client" "version" "1.0")))
      assert_match(/\A\* ID \("name" "mail_on_rails" "version" "[\d.]+"\)\r\nz1 OK/, response)
      command(client, "z2", "LOGOUT")
    end
  end

  def test_capabilities_advertise_new_extensions
    with_session do |client|
      greeting = client.gets("\r\n")
      %w[IDLE MOVE UNSELECT NAMESPACE SPECIAL-USE CHILDREN UIDPLUS LITERAL\+ SASL-IR].each do |cap|
        assert_match(/#{cap}/, greeting)
      end
      command(client, "g1", "LOGOUT")
    end
  end

  def test_append_and_expunge_round_trip
    with_session do |client|
      client.gets("\r\n")
      command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}")
      command(client, "a2", "SELECT INBOX")

      assert_match(/^a3 OK/, command(client, "a3", "STORE 1 +FLAGS (\\Deleted)"))
      expunge = command(client, "a4", "EXPUNGE")
      assert_match(/\A\* 1 EXPUNGE/, expunge)
      assert_match(/^a4 OK/, expunge)

      command(client, "a5", "LOGOUT")
    end

    assert_equal 0, @store.status(@account_id, "INBOX")[:messages]
  end
end

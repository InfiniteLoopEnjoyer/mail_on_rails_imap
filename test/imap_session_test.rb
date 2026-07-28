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

  # Simulates the app being unreachable: credential lookups degrade to the
  # HTTP store's error envelope instead of a credential verdict.
  class UnreachableStore < MailOnRails::Imap::Store::Memory
    def authenticate(_email, _password) = { error: "Net::OpenTimeout", code: :internal }
    def scram_credentials(_email) = { error: "Net::OpenTimeout", code: :internal }
  end

  def test_login_with_unreachable_store_is_a_temporary_failure_not_bad_credentials
    @store = UnreachableStore.new
    with_session do |client|
      client.gets("\r\n")
      reply = command(client, "a1", "LOGIN #{EMAIL} #{PASSWORD}")
      assert_match(/\Aa1 NO \[UNAVAILABLE\]/, reply)
      refute_match(/AUTHENTICATIONFAILED/, reply)

      # Temporary failures must not count toward MAX_AUTH_ATTEMPTS: the
      # connection survives more of them than the failed-auth cap allows.
      (MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS + 1).times do |i|
        assert_match(/\Ar#{i} NO \[UNAVAILABLE\]/, command(client, "r#{i}", "LOGIN #{EMAIL} #{PASSWORD}"))
      end
      command(client, "a2", "LOGOUT")
    end
  end

  def test_scram_with_unreachable_store_is_a_temporary_failure
    @store = UnreachableStore.new
    with_session do |client|
      client.gets("\r\n")
      initial = [ "n,,n=#{EMAIL},r=clientnonce" ].pack("m0")
      assert_match(/\As1 NO \[UNAVAILABLE\]/, command(client, "s1", "AUTHENTICATE SCRAM-SHA-256 #{initial}"))
      command(client, "s2", "LOGOUT")
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
        assert_match(/\Aa1 NO \[TOOBIG\] literal too large/, refused)
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
        assert_match(/\Aa1 NO \[TOOBIG\] literal too large/, read_until_tagged(client, "a1"))
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
      # RFC 3501 §6.3.5: renaming INBOX moves its messages to the new
      # mailbox and leaves an empty INBOX behind.
      assert_match(/\Ad6 OK/, command(client, "d6", "RENAME INBOX Elsewhere"))
      assert_match(/MESSAGES 1/, command(client, "e1", "STATUS Elsewhere (MESSAGES)"))
      assert_match(/MESSAGES 0/, command(client, "e2", "STATUS INBOX (MESSAGES)"))
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
      %w[IDLE MOVE UNSELECT NAMESPACE SPECIAL-USE CHILDREN ESEARCH WITHIN CONDSTORE UIDPLUS LITERAL\+ SASL-IR].each do |cap|
        assert_match(/#{cap}/, greeting)
      end
      command(client, "g1", "LOGOUT")
    end
  end

  def test_condstore_select_status_and_fetch_modseq
    with_session do |client|
      client.gets("\r\n")
      command(client, "c1", "LOGIN #{EMAIL} #{PASSWORD}")
      select = command(client, "c2", "SELECT INBOX (CONDSTORE)")
      assert_match(/\* OK \[HIGHESTMODSEQ \d+\]/, select)

      assert_match(/HIGHESTMODSEQ \d+/, command(client, "c3", "STATUS INBOX (MESSAGES HIGHESTMODSEQ)"))
      refute_match(/HIGHESTMODSEQ/, command(client, "c4", "STATUS INBOX (MESSAGES)"), "STATUS omits HIGHESTMODSEQ unless requested")

      assert_match(/\* 1 FETCH \(MODSEQ \(\d+\)\)/, command(client, "c5", "FETCH 1 (MODSEQ)"))
      # CONDSTORE is now enabled for the session: plain FETCHes carry MODSEQ too.
      assert_match(/MODSEQ \(\d+\)/, command(client, "c6", "FETCH 1 (FLAGS)"))
      command(client, "c7", "LOGOUT")
    end
  end

  def fetch_modseq(client, tag, seq)
    command(client, tag, "FETCH #{seq} (MODSEQ)")[/MODSEQ \((\d+)\)/, 1].to_i
  end

  def test_store_unchangedsince_applies_and_reports_modified
    with_session do |client|
      login_and_select(client)
      baseline = fetch_modseq(client, "u1", 1)

      fresh = command(client, "u2", "STORE 1 (UNCHANGEDSINCE #{baseline}) +FLAGS (\\Flagged)")
      assert_match(/\A\* 1 FETCH \(FLAGS \([^)]*\\Flagged[^)]*\) MODSEQ \(\d+\)\)\r\nu2 OK STORE completed/, fresh)

      # baseline is stale now: the store must be refused with MODIFIED.
      stale = command(client, "u3", "STORE 1 (UNCHANGEDSINCE #{baseline}) +FLAGS (\\Draft)")
      assert_match(/\Au3 OK \[MODIFIED 1\] Conditional STORE completed/, stale)
      refute_match(/\\Draft/, command(client, "u4", "FETCH 1 (FLAGS)"))
      command(client, "u5", "LOGOUT")
    end
  end

  def test_fetch_changedsince_returns_only_newer_messages
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 2
    with_session do |client|
      login_and_select(client)
      baseline = fetch_modseq(client, "f1", 2)
      command(client, "f2", "STORE 1 +FLAGS.SILENT (\\Flagged)")

      changed = command(client, "f3", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE #{baseline})")
      assert_match(/\* 1 FETCH \(.*MODSEQ \(\d+\)/, changed)
      refute_match(/\* 2 FETCH/, changed, "unchanged message must be filtered by CHANGEDSINCE")
      command(client, "f4", "LOGOUT")
    end
  end

  def test_enable_qresync_switches_expunge_to_vanished
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 2
    with_session do |client|
      client.gets("\r\n")
      command(client, "e1", "LOGIN #{EMAIL} #{PASSWORD}")
      enabled = command(client, "e2", "ENABLE QRESYNC")
      assert_match(/\A\* ENABLED QRESYNC\r\ne2 OK/, enabled)
      command(client, "e3", "SELECT INBOX")

      command(client, "e4", "STORE 1:2 +FLAGS.SILENT (\\Deleted)")
      expunge = command(client, "e5", "EXPUNGE")
      assert_match(/\A\* VANISHED 1:2\r\ne5 OK/, expunge)
      refute_match(/EXPUNGE\r\n/, expunge[/\A.*(?=e5)/m].to_s, "QRESYNC sessions get VANISHED, not EXPUNGE")
      command(client, "e6", "LOGOUT")
    end
  end

  def test_select_qresync_param_reports_vanished_earlier_and_flag_changes
    @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil) # uid 2
    with_session do |client|
      client.gets("\r\n")
      command(client, "q1", "LOGIN #{EMAIL} #{PASSWORD}")

      # A client without ENABLE QRESYNC must be refused the parameter.
      assert_match(/\Aq2 BAD/, command(client, "q2", "SELECT INBOX (QRESYNC (1 1))"))

      command(client, "q3", "ENABLE QRESYNC")
      select = command(client, "q4", "SELECT INBOX")
      uidvalidity = select[/UIDVALIDITY (\d+)/, 1].to_i
      known_modseq = select[/HIGHESTMODSEQ (\d+)/, 1].to_i

      # Another session's changes while this client is "offline".
      mailbox_id = @store.select_mailbox(@account_id, "INBOX")[:mailbox_id]
      @store.expunge(mailbox_id)                              # uid 2 vanishes
      @store.store_flags(mailbox_id, [ 1 ], "+", [ "\\Flagged" ]) # uid 1 changes

      resync = command(client, "q5", "SELECT INBOX (QRESYNC (#{uidvalidity} #{known_modseq}))")
      assert_match(/\* OK \[CLOSED\]/, resync)
      assert_match(/\* VANISHED \(EARLIER\) 2\r\n/, resync)
      assert_match(/\* 1 FETCH \(UID 1 FLAGS \([^)]*\\Flagged[^)]*\) MODSEQ \(\d+\)\)/, resync)

      # Wrong UIDVALIDITY: no catch-up responses at all.
      stale = command(client, "q6", "SELECT INBOX (QRESYNC (#{uidvalidity + 1} #{known_modseq}))")
      refute_match(/VANISHED/, stale)
      command(client, "q7", "LOGOUT")
    end
  end

  def test_uid_fetch_vanished_modifier
    @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil) # uid 2
    with_session do |client|
      client.gets("\r\n")
      command(client, "v1", "LOGIN #{EMAIL} #{PASSWORD}")
      command(client, "v2", "ENABLE QRESYNC")
      select = command(client, "v3", "SELECT INBOX")
      baseline = select[/HIGHESTMODSEQ (\d+)/, 1].to_i

      mailbox_id = @store.select_mailbox(@account_id, "INBOX")[:mailbox_id]
      @store.expunge(mailbox_id) # uid 2 vanishes behind the session's back

      fetch = command(client, "v4", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE #{baseline} VANISHED)")
      assert_match(/\A\* VANISHED \(EARLIER\) 2\r\n/, fetch)

      # VANISHED without QRESYNC prerequisites is BAD.
      assert_match(/\Av5 BAD/, command(client, "v5", "FETCH 1:* (FLAGS) (CHANGEDSINCE #{baseline} VANISHED)"))
      command(client, "v6", "LOGOUT")
    end
  end

  def test_search_modseq_key_appends_highest_match_modseq
    with_session do |client|
      login_and_select(client)
      modseq = fetch_modseq(client, "m1", 1)
      assert_match(/\A\* SEARCH 1 \(MODSEQ #{modseq}\)\r\n/, command(client, "m2", "SEARCH MODSEQ 1"))
      assert_match(/\A\* SEARCH\r\n/, command(client, "m3", "SEARCH MODSEQ #{modseq + 1000}"))
      esearch = command(client, "m4", "SEARCH RETURN (ALL) MODSEQ 1")
      assert_match(/\A\* ESEARCH \(TAG "m4"\) ALL 1 MODSEQ #{modseq}\r\n/, esearch)
      command(client, "m5", "LOGOUT")
    end
  end

  def test_esearch_return_options
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 2
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 3
    with_session do |client|
      login_and_select(client)

      count = command(client, "e1", "SEARCH RETURN (COUNT) ALL")
      assert_match(/\A\* ESEARCH \(TAG "e1"\) COUNT 3\r\ne1 OK/, count)

      full = command(client, "e2", "UID SEARCH RETURN (MIN MAX ALL) 2:3")
      assert_match(/\A\* ESEARCH \(TAG "e2"\) UID MIN 2 MAX 3 ALL 2:3\r\ne2 OK/, full)

      # RETURN () means ALL (RFC 4731); no matches omits MIN/MAX/ALL.
      empty_opts = command(client, "e3", "SEARCH RETURN () ALL")
      assert_match(/\A\* ESEARCH \(TAG "e3"\) ALL 1:3\r\ne3 OK/, empty_opts)
      none = command(client, "e4", "SEARCH RETURN (MIN COUNT) SUBJECT nosuch")
      assert_match(/\A\* ESEARCH \(TAG "e4"\) COUNT 0\r\ne4 OK/, none)

      assert_match(/\Ae5 BAD/, command(client, "e5", "SEARCH RETURN (BOGUS) ALL"))
      command(client, "e6", "LOGOUT")
    end
  end

  def test_older_and_younger_match_message_age
    old_epoch = Time.now.to_i - 7200
    @store.append(@account_id, "INBOX", RAW, [], old_epoch) # uid 2, two hours old
    with_session do |client|
      login_and_select(client)
      assert_match(/\A\* SEARCH 2\r\n/, command(client, "w1", "SEARCH OLDER 3600"))
      assert_match(/\A\* SEARCH 1\r\n/, command(client, "w2", "SEARCH YOUNGER 3600"))
      assert_match(/\Aw3 BAD/, command(client, "w3", "SEARCH OLDER soon"))
      command(client, "w4", "LOGOUT")
    end
  end

  def test_body_searches_exclude_headers_unlike_text
    with_session do |client|
      login_and_select(client)
      # "hi" appears only in the Subject header; "line" only in the body.
      assert_match(/\A\* SEARCH 1\r\n/, command(client, "b1", "SEARCH TEXT hi"))
      assert_match(/\A\* SEARCH\r\n/, command(client, "b2", "SEARCH BODY hi"))
      assert_match(/\A\* SEARCH 1\r\n/, command(client, "b3", "SEARCH BODY line"))
      command(client, "b4", "LOGOUT")
    end
  end

  def test_keyword_flags_persist_and_search
    with_session do |client|
      login_and_select(client)
      store = command(client, "k1", "STORE 1 +FLAGS ($Forwarded)")
      assert_match(/\$Forwarded/, store)
      assert_match(/\$Forwarded/, command(client, "k2", "FETCH 1 (FLAGS)"))
      assert_match(/\A\* SEARCH 1\r\n/, command(client, "k3", "SEARCH KEYWORD $Forwarded"))
      assert_match(/\A\* SEARCH\r\n/, command(client, "k4", "SEARCH UNKEYWORD $Forwarded"))
      command(client, "k5", "LOGOUT")
    end
  end

  def test_multi_literal_login_round_trip
    with_session do |client|
      client.gets("\r\n")
      client.write("a1 LOGIN {#{EMAIL.bytesize}}\r\n")
      assert_equal "+ OK\r\n", client.gets("\r\n")
      client.write("#{EMAIL} {#{PASSWORD.bytesize}}\r\n")
      assert_equal "+ OK\r\n", client.gets("\r\n")
      client.write("#{PASSWORD}\r\n")
      assert_match(/\Aa1 OK/, read_until_tagged(client, "a1"))
      command(client, "a2", "LOGOUT")
    end
  end

  def test_append_with_flags_and_internaldate
    with_session do |client|
      login_and_select(client)
      client.write(%(p1 APPEND INBOX (\\Flagged) "15-Jul-2025 10:00:00 +0000" {#{RAW.bytesize}+}\r\n#{RAW}\r\n))
      append = read_until_tagged(client, "p1")
      assert_match(/\A\* 2 EXISTS\r\n/, append, "APPEND into the selected mailbox must announce EXISTS")
      assert_match(/^p1 OK \[APPENDUID \d+ 2\]/, append)

      fetch = command(client, "p2", "UID FETCH 2 (FLAGS INTERNALDATE)")
      assert_match(/\\Flagged/, fetch)
      assert_match(/INTERNALDATE "15-Jul-2025/, fetch)
      command(client, "p3", "LOGOUT")
    end
  end

  def test_empty_mailbox_star_sets_and_search_are_harmless
    with_session do |client|
      client.gets("\r\n")
      command(client, "s1", "LOGIN #{EMAIL} #{PASSWORD}")
      command(client, "s2", "SELECT Drafts")
      assert_match(/\As3 OK/, command(client, "s3", "FETCH 1:* (UID)"))
      assert_match(/\A\* SEARCH\r\ns4 OK/, command(client, "s4", "SEARCH ALL"))
      assert_match(/\As5 OK/, command(client, "s5", "UID FETCH 1:* (FLAGS)"))
      command(client, "s6", "LOGOUT")
    end
  end

  # Records every fetch so tests can assert when raw bytes were pulled.
  class SpyStore < MailOnRails::Imap::Store::Memory
    def fetches = @fetches ||= []

    def fetch(mailbox_id, uids, with_raw)
      fetches << [ uids.dup.sort, with_raw ]
      super
    end
  end

  def test_search_fetches_raw_bytes_only_for_metadata_survivors
    spy = SpyStore.new
    @store = spy
    @account_id = spy.add_account(email: EMAIL, password: PASSWORD)
    spy.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil) # uid 1
    spy.append(@account_id, "INBOX", RAW, [], nil)              # uid 2

    with_session do |client|
      login_and_select(client)
      assert_match(/\A\* SEARCH 1\r\n/, command(client, "q1", "SEARCH DELETED SUBJECT hi"))
      command(client, "q2", "LOGOUT")
    end

    assert_includes spy.fetches, [ [ 1, 2 ], false ], "metadata pass should cover the whole mailbox"
    assert_equal [ [ [ 1 ], true ] ], spy.fetches.select { |_uids, raw| raw },
                 "raw bytes should be fetched only for the \\Deleted survivor"
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

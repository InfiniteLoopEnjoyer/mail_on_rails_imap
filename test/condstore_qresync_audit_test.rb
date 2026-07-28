require "test_helper"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# RFC 7162 (CONDSTORE/QRESYNC) compliance audit, ported from mox's
# imapserver/condstore_test.go — the same wire-level style as
# imap_session_test.rb, but with multiple concurrent sessions against one
# store so cross-session broadcasts (the part real clients depend on) are
# exercised. UIDs/modseqs are recomputed for this store's numbering; mox
# cases that depend on its database internals (legacy modseq-0 rows,
# UIDONLY) are not ported.
class CondstoreQresyncAuditTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"
  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @listener = TCPServer.new("127.0.0.1", 0)
    @sessions = []
    @clients = []
    @acceptor = Thread.new do
      loop do
        sock = @listener.accept
        @sessions << Thread.new { MailOnRails::ImapServer::Session.new(sock, @store, { tls: :implicit }, nil).run }
      end
    rescue IOError, SystemCallError
      # listener closed in teardown
    end
  end

  def teardown
    @clients.each { |c| c.close rescue nil }
    @listener.close
    @acceptor.join(2)
    @sessions.each { |t| t.join(5) }
  end

  def connect(login: true)
    client = TCPSocket.new("127.0.0.1", @listener.addr[1])
    @clients << client
    client.gets("\r\n") # greeting
    command(client, "l0", "LOGIN #{EMAIL} #{PASSWORD}") if login
    client
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

  def inbox_id
    @store.select_mailbox(@account_id, "INBOX")[:mailbox_id]
  end

  def highest_modseq
    @store.status(@account_id, "INBOX")[:highest_modseq]
  end

  def fetch_modseq(client, tag, seq)
    command(client, tag, "FETCH #{seq} (MODSEQ)")[/MODSEQ \((\d+)\)/, 1].to_i
  end

  # -- empty-mailbox basics (mox testCondstoreQresync head) ------------------

  test "empty mailbox condstore basics" do
    c = connect
    command(c, "t1", "ENABLE CONDSTORE")
    select = command(c, "t2", "SELECT Drafts")
    assert_match(/\* OK \[HIGHESTMODSEQ \d+\]/, select)

    assert_match(/HIGHESTMODSEQ \d+/, command(c, "t3", "STATUS Drafts (HIGHESTMODSEQ)"))

    # No messages: CHANGEDSINCE fetches and MODSEQ searches match nothing.
    assert_match(/\At4 OK/, command(c, "t4", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE 12345)"))
    refute_match(/\* \d+ FETCH/, command(c, "t5", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1)"))
    assert_match(/\A\* SEARCH\r\n/, command(c, "t6", "SEARCH MODSEQ 0"), "MODSEQ 0 is valid syntax")
    assert_match(/\A\* SEARCH\r\n/, command(c, "t7", "SEARCH MODSEQ 12345"))
    # Optional entry-name/entry-type prefix.
    assert_match(/\A\* SEARCH\r\n/, command(c, "t8", %(SEARCH MODSEQ "/flags/\\\\Draft" all 12345)))
    assert_match(/\A\* SEARCH\r\n/, command(c, "t9", "SEARCH OR MODSEQ 12345 MODSEQ 54321"))
    # ESEARCH with no matches keeps the TAG correlator, drops MIN/MAX/ALL.
    assert_match(/\A\* ESEARCH \(TAG "t10"\)\r\n/, command(c, "t10", "SEARCH RETURN (ALL) MODSEQ 123"))
  end

  # -- CONDSTORE enabling commands (mox checkCondstoreEnabled) ---------------

  # Every construct RFC 7162 §3.1 lists must flip the session into
  # CONDSTORE mode, observable as MODSEQ riding along in the unsolicited
  # FETCH when another agent changes a flag.
  [
    [ "select_condstore_param", [ "SELECT INBOX (CONDSTORE)" ] ],
    [ "status_highestmodseq", [ "STATUS INBOX (HIGHESTMODSEQ)", "SELECT INBOX" ] ],
    [ "fetch_modseq_item", [ "SELECT INBOX", "UID FETCH 1 (MODSEQ)" ] ],
    [ "search_modseq_key", [ "SELECT INBOX", "UID SEARCH UID 1 MODSEQ 1" ] ],
    [ "fetch_changedsince", [ "SELECT INBOX", "UID FETCH 1 (FLAGS) (CHANGEDSINCE 99999)" ] ],
    [ "store_unchangedsince", [ "SELECT INBOX", "UID STORE 1 (UNCHANGEDSINCE 0) FLAGS ()" ] ],
    [ "enable_condstore", [ "ENABLE CONDSTORE", "SELECT INBOX" ] ],
    [ "enable_qresync", [ "ENABLE QRESYNC", "SELECT INBOX" ] ]
  ].each_with_index do |(label, commands), n|
    test "condstore is enabled by #{label}" do
      @store.append(@account_id, "INBOX", RAW, [], nil) # uid 1
      c = connect
      commands.each_with_index { |line, i| command(c, "e#{i}", line) }

      @store.store_flags(inbox_id, [ 1 ], "+", [ "label#{n}" ])
      noop = command(c, "n1", "NOOP")
      assert_match(/\* 1 FETCH \([^)]*FLAGS \([^)]*label#{n}[^)]*\)[^)]*MODSEQ \(\d+\)/, noop,
                   "#{label} must make unsolicited FETCHes carry MODSEQ")
    end
  end

  test "unsolicited fetch carries uid under qresync" do
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 1
    c = connect
    command(c, "q1", "ENABLE QRESYNC")
    command(c, "q2", "SELECT INBOX")
    @store.store_flags(inbox_id, [ 1 ], "+", [ "\\Flagged" ])
    assert_match(/\* 1 FETCH \(UID 1 FLAGS \([^)]*\\Flagged[^)]*\) MODSEQ \(\d+\)\)/, command(c, "q3", "NOOP"))
  end

  test "plain session unsolicited fetch has neither uid nor modseq" do
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 1
    c = connect
    command(c, "p1", "SELECT INBOX")
    @store.store_flags(inbox_id, [ 1 ], "+", [ "\\Flagged" ])
    assert_match(/\* 1 FETCH \(FLAGS \([^)]*\\Flagged[^)]*\)\)\r\n/, command(c, "p2", "NOOP"))
  end

  # -- conditional STORE (mox store/uid-store section) -----------------------

  test "unchangedsince zero never passes" do
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 1
    c = connect
    command(c, "z1", "SELECT INBOX")
    reply = command(c, "z2", "STORE 1 (UNCHANGEDSINCE 0) +FLAGS ()")
    assert_match(/\Az2 OK \[MODIFIED 1\]/, reply)
  end

  test "duplicate uid in conditional store set does not defeat itself" do
    # RFC 7162 §3.1.3 (mox ../rfc/7162:823): the same message twice in
    # one UNCHANGEDSINCE set must not fail because the first application
    # changed its modseq.
    @store.append(@account_id, "INBOX", RAW, [ "label1" ], nil) # uid 1
    c = connect
    command(c, "d1", "SELECT INBOX")
    baseline = fetch_modseq(c, "d2", 1)
    reply = command(c, "d3", "UID STORE 1,1 (UNCHANGEDSINCE #{baseline}) -FLAGS (label1)")
    refute_match(/MODIFIED/, reply)
    assert_match(/^d3 OK/, reply)
  end

  test "noop flag store does not advance modseq or broadcast" do
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 1
    c = connect
    command(c, "n1", "SELECT INBOX (CONDSTORE)")
    before = fetch_modseq(c, "n2", 1)

    observer = connect
    command(observer, "o1", "SELECT INBOX (CONDSTORE)")

    # Removing a flag the message doesn't have changes nothing.
    command(c, "n3", "STORE 1 -FLAGS (label1)")
    assert_equal before, fetch_modseq(c, "n4", 1), "no-change STORE must not bump modseq"
    refute_match(/\* \d+ FETCH/, command(observer, "o2", "NOOP"), "no-change STORE must not broadcast")
  end

  # -- EXPUNGE (mox expunge section + RFC 7162 §3.2.7/§3.2.9) ----------------

  test "expunge answers highestmodseq code and vanished under qresync" do
    3.times { @store.append(@account_id, "INBOX", RAW, [], nil) } # uids 1-3

    q = connect
    command(q, "q1", "ENABLE QRESYNC")
    command(q, "q2", "SELECT INBOX")
    plain = connect
    command(plain, "p1", "SELECT INBOX")

    command(q, "q3", "STORE 2:3 +FLAGS.SILENT (\\Deleted)")
    expunge = command(q, "q4", "EXPUNGE")
    assert_match(/\A\* VANISHED 2:3\r\n/, expunge)
    assert_match(/\Aq4 OK \[HIGHESTMODSEQ #{highest_modseq}\]/, expunge[/^q4 .*/])

    # The non-QRESYNC observer gets per-sequence EXPUNGE lines instead.
    noop = command(plain, "p2", "NOOP")
    assert_equal 2, noop.scan(/^\* \d+ EXPUNGE\r?$/).size
    refute_match(/VANISHED/, noop)
  end

  test "uid expunge answers highestmodseq code under qresync" do
    2.times { @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil) } # uids 1-2
    c = connect
    command(c, "u1", "ENABLE QRESYNC")
    command(c, "u2", "SELECT INBOX")
    reply = command(c, "u3", "UID EXPUNGE 1")
    assert_match(/\A\* VANISHED 1\r\nu3 OK \[HIGHESTMODSEQ \d+\]/, reply)
  end

  test "expunge without removals or condstore stays plain" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "x1", "SELECT INBOX")
    assert_match(/\Ax2 OK EXPUNGE completed/, command(c, "x2", "EXPUNGE"))
  end

  test "close never carries highestmodseq" do
    # RFC 7162 §3.2.8: CLOSE expunges silently and MUST NOT return
    # HIGHESTMODSEQ in the tagged OK.
    @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil)
    c = connect
    command(c, "c1", "ENABLE QRESYNC")
    command(c, "c2", "SELECT INBOX")
    reply = command(c, "c3", "CLOSE")
    refute_match(/HIGHESTMODSEQ/, reply)
    assert_match(/\Ac3 OK/, reply)
  end

  test "expunged messages are invisible to changedsince and conditional store" do
    2.times { @store.append(@account_id, "INBOX", RAW, [], nil) } # uids 1-2
    c = connect
    command(c, "i1", "ENABLE QRESYNC")
    command(c, "i2", "SELECT INBOX")
    command(c, "i3", "UID STORE 2 +FLAGS.SILENT (\\Deleted)")
    command(c, "i4", "EXPUNGE")
    high = highest_modseq

    refute_match(/\* \d+ FETCH/, command(c, "i5", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE #{high})"))
    reply = command(c, "i6", "UID STORE 2 (UNCHANGEDSINCE #{high}) +FLAGS (label2)")
    refute_match(/MODIFIED/, reply, "expunged uids are not MODIFIED failures")
    refute_match(/\* \d+ FETCH/, reply)
    assert_match(/\Ai6 OK/, reply)
  end

  test "status reflects raised highestmodseq after expunge" do
    2.times { @store.append(@account_id, "INBOX", RAW, [], nil) }
    before = highest_modseq
    c = connect
    command(c, "s1", "SELECT INBOX")
    command(c, "s2", "STORE 1 +FLAGS.SILENT (\\Deleted)")
    command(c, "s3", "EXPUNGE")
    status = command(c, "s4", "STATUS INBOX (MESSAGES HIGHESTMODSEQ)")
    assert_match(/MESSAGES 1/, status)
    assert_operator status[/HIGHESTMODSEQ (\d+)/, 1].to_i, :>, before
  end

  # -- FETCH VANISHED modifier syntax (mox testQresync head) -----------------

  test "vanished modifier syntax rules" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "v1", "ENABLE QRESYNC")
    command(c, "v2", "SELECT INBOX")

    # Non-UID FETCH cannot take VANISHED.
    assert_match(/\Av3 BAD/, command(c, "v3", "FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)"))
    # VANISHED requires CHANGEDSINCE.
    assert_match(/\Av4 BAD/, command(c, "v4", "UID FETCH 1:* (FLAGS) (VANISHED)"))

    # And QRESYNC must have been enabled: CONDSTORE alone is not enough.
    c2 = connect
    command(c2, "w1", "SELECT INBOX (CONDSTORE)")
    assert_match(/\Aw2 BAD/, command(c2, "w2", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)"))
  end

  # -- SELECT QRESYNC parameter validation (mox testQresync) -----------------

  test "select qresync parameter grammar is enforced" do
    c = connect
    command(c, "g0", "ENABLE QRESYNC")
    [
      "SELECT INBOX (QRESYNC 1 1)",                     # args must be parenthesized
      "SELECT INBOX (QRESYNC (0 1))",                   # uidvalidity nonzero
      "SELECT INBOX (QRESYNC (1 0))",                   # modseq nonzero
      "SELECT INBOX (QRESYNC)",                         # two args minimum
      "SELECT INBOX (QRESYNC (1))",                     # two args minimum
      "SELECT INBOX (QRESYNC (1 1 1:*))",               # known-uids: * not allowed
      "SELECT INBOX (QRESYNC (1 1 1:6 (1:* 1:6)))",     # seq-match: * not allowed
      "SELECT INBOX (QRESYNC (1 1 1:6 (1:6 1:*)))",     # seq-match: * not allowed
      "SELECT INBOX (QRESYNC (1 1 1:6 (1 1,2)))",       # seq-match sets equal length
      "SELECT INBOX (QRESYNC (1 1) QRESYNC (1 1))"      # duplicate parameter
    ].each_with_index do |line, i|
      assert_match(/\Ab#{i} BAD/, command(c, "b#{i}", line), "expected BAD for: #{line}")
    end

    # Malformed QRESYNC is BAD even before ENABLE QRESYNC.
    c2 = connect
    assert_match(/\Am1 BAD/, command(c2, "m1", "SELECT INBOX (QRESYNC 1 0)"))
  end

  # -- SELECT QRESYNC catch-up variants (mox testQresync body) ---------------

  # Scenario: uids 1-3 appended, uid 2 expunged, uid 1 flagged. Returns
  # [uidvalidity, modseq-after-appends].
  def build_catchup_scenario
    3.times { @store.append(@account_id, "INBOX", RAW, [], nil) } # modseqs 2,3,4
    after_appends = highest_modseq
    @store.store_flags(inbox_id, [ 2 ], "+", [ "\\Deleted" ])
    @store.expunge(inbox_id)
    @store.store_flags(inbox_id, [ 1 ], "+", [ "\\Flagged" ])
    [ @store.select_mailbox(@account_id, "INBOX")[:uid_validity], after_appends ]
  end

  test "qresync select variants replay the right history" do
    uidvalidity, after_appends = build_catchup_scenario
    high = highest_modseq
    c = connect
    command(c, "y0", "ENABLE QRESYNC")

    # Full catch-up since before anything happened.
    resync = command(c, "y1", "SELECT INBOX (QRESYNC (#{uidvalidity} 1))")
    assert_match(/\* VANISHED \(EARLIER\) 2\r\n/, resync)
    assert_match(/FETCH \(UID 1 FLAGS \([^)]*\\Flagged[^)]*\) MODSEQ \(\d+\)\)/, resync)
    assert_match(/FETCH \(UID 3 FLAGS \(\) MODSEQ \(\d+\)\)/, resync)

    # UIDVALIDITY mismatch: ordinary select, no catch-up at all.
    command(c, "y2", "CLOSE")
    stale = command(c, "y3", "SELECT INBOX (QRESYNC (#{uidvalidity + 1} 1))")
    refute_match(/VANISHED|MODSEQ \(/, stale)

    # known-uids restricts both VANISHED and flag catch-up.
    command(c, "y4", "CLOSE")
    partial = command(c, "y5", "SELECT INBOX (QRESYNC (#{uidvalidity} 1 1:2))")
    assert_match(/\* VANISHED \(EARLIER\) 2\r\n/, partial)
    assert_match(/FETCH \(UID 1 /, partial)
    refute_match(/FETCH \(UID 3 /, partial, "uid 3 is outside known-uids")

    command(c, "y6", "CLOSE")
    only3 = command(c, "y7", "SELECT INBOX (QRESYNC (#{uidvalidity} 1 3))")
    refute_match(/VANISHED/, only3, "uid 2 is outside known-uids")
    assert_match(/FETCH \(UID 3 /, only3)
    refute_match(/FETCH \(UID 1 /, only3)

    # A recent modseq filters out older changes (uid 3 was last touched
    # by its append; the expunge and uid 1's flag came after).
    command(c, "y8", "CLOSE")
    recent = command(c, "y9", "SELECT INBOX (QRESYNC (#{uidvalidity} #{after_appends}))")
    assert_match(/\* VANISHED \(EARLIER\) 2\r\n/, recent)
    assert_match(/FETCH \(UID 1 /, recent)
    refute_match(/FETCH \(UID 3 /, recent)

    # Nothing newer than the current modseq: clean select.
    command(c, "y10", "CLOSE")
    clean = command(c, "y11", "SELECT INBOX (QRESYNC (#{uidvalidity} #{high}))")
    refute_match(/VANISHED|FETCH/, clean)

    # seq-match-data is syntactically accepted; semantics may be ignored
    # (RFC 7162 §3.2.5.2) so the reply matches the known-uids-only form.
    command(c, "y12", "CLOSE")
    seqmatch = command(c, "y13", "SELECT INBOX (QRESYNC (#{uidvalidity} 1 1,3 (1,2 1,3)))")
    assert_match(/\Ay13 OK/, seqmatch[/^y13 .*/])
    assert_match(/FETCH \(UID 1 /, seqmatch)
    assert_match(/FETCH \(UID 3 /, seqmatch)
    refute_match(/VANISHED/, seqmatch, "uid 2 is outside known-uids 1,3")
  end

  # -- tombstone history exhaustion (mox testQresyncHistory) -----------------

  test "vanished earlier survives tombstone pruning" do
    @store = MailOnRails::Imap::Store::Memory.new(tombstone_limit: 2)
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    3.times { @store.append(@account_id, "INBOX", RAW, [], nil) } # uids 1-3
    uidvalidity = @store.select_mailbox(@account_id, "INBOX")[:uid_validity]
    @store.store_flags(inbox_id, [ 1, 3 ], "+", [ "\\Deleted" ])
    @store.expunge(inbox_id)                              # tombstones 1,3
    @store.store_flags(inbox_id, [ 2 ], "+", [ "\\Seen" ])

    c = connect
    command(c, "h1", "ENABLE QRESYNC")
    resync = command(c, "h2", "SELECT INBOX (QRESYNC (#{uidvalidity} 1))")
    assert_match(/\* VANISHED \(EARLIER\) 1,3\r\n/, resync)
    assert_match(/FETCH \(UID 2 FLAGS \([^)]*\\Seen[^)]*\) MODSEQ \(\d+\)\)/, resync)
    command(c, "h3", "CLOSE")

    # A third expunge overflows the 2-entry tombstone limit and prunes
    # the oldest history; VANISHED (EARLIER) must still cover uids 1,3
    # via the never-reused-uids fallback.
    @store.append(@account_id, "INBOX", RAW, [ "\\Deleted" ], nil) # uid 4
    @store.expunge(inbox_id)
    resync = command(c, "h4", "SELECT INBOX (QRESYNC (#{uidvalidity} 1))")
    assert_match(/\* VANISHED \(EARLIER\) 1,3:4\r\n/, resync)

    # UID FETCH VANISHED behaves the same across the pruning boundary.
    high = highest_modseq
    refute_match(/VANISHED/, command(c, "h5", "UID FETCH 1:4 (FLAGS) (CHANGEDSINCE #{high} VANISHED)"))
    replay = command(c, "h6", "UID FETCH 1:4 (FLAGS) (CHANGEDSINCE 1 VANISHED)")
    assert_match(/\* VANISHED \(EARLIER\) 1,3:4\r\n/, replay)
    assert_match(/\* 1 FETCH \(.*UID 2.*MODSEQ \(\d+\)/, replay)
  end

  # -- MOVE under QRESYNC (mox move section) ---------------------------------

  test "move reports vanished to qresync sessions and expunge to others" do
    2.times { @store.append(@account_id, "INBOX", RAW, [], nil) } # uids 1-2
    q = connect
    command(q, "m1", "ENABLE QRESYNC")
    command(q, "m2", "SELECT INBOX")
    plain = connect
    command(plain, "n1", "SELECT INBOX")

    move = command(q, "m3", "UID MOVE 1 Trash")
    assert_match(/\* OK \[COPYUID \d+ 1 \d+\]\r\n\* VANISHED 1\r\n/, move)
    assert_match(/\A\* 1 EXPUNGE\r\n/, command(plain, "n2", "NOOP"))
  end

  # -- COPY gives fresh modseqs in the destination (mox copy section) --------

  test "copied messages get new modseqs in the destination" do
    # Modseq is a per-mailbox sequence: the copy bumps the destination's
    # HIGHESTMODSEQ, not the source's.
    @store.append(@account_id, "INBOX", RAW, [], nil) # uid 1
    trash_before = @store.status(@account_id, "Trash")[:highest_modseq]
    c = connect
    command(c, "c1", "SELECT INBOX (CONDSTORE)")
    command(c, "c2", "UID COPY 1 Trash")
    command(c, "c3", "SELECT Trash")
    assert_operator fetch_modseq(c, "c4", 1), :>, trash_before,
                    "copy must assign a fresh modseq in the destination mailbox"
  end
end

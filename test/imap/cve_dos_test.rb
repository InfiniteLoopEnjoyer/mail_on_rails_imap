# frozen_string_literal: true

require "test_helper"
require "wire_harness"
require "mail_on_rails/imap/mime"

# Resource-exhaustion / crash regressions for the IMAP server, organised by
# the CVE class each guards against. These are boundary probes: they push
# just past the relevant cap (or feed a pathological message) and assert the
# server answers within a generous time budget and the session stays usable
# - never that it enumerates a giant set or recurses into a crash. They are
# deliberately small (no giant mailboxes); a missing bound shows up as a
# blown budget or a dropped session, not a slow test.
#
# Classes covered:
#   1. SEARCH/FETCH/sequence-set resource DoS (the 122-CVE bucket)
#   2. Hostile MIME / BODYSTRUCTURE generation (CVE-2020-12100,
#      CVE-2026-26312, CVE-2008-4907, CVE-2020-25275)
#   3. IDLE command-level abuse (CVE-2020-24386 class)
#   4. COMPRESS=DEFLATE (CVE-2014-8760 class) - structurally not applicable
class CveDosTest < Minitest::Test
  include WireHarness

  Mime = MailOnRails::Imap::Mime

  # A single wall-clock ceiling for every "must stay bounded" assertion. The
  # bounded paths answer in tens of milliseconds; an unbounded one would run
  # for many seconds or exhaust memory first. Well clear of both.
  BUDGET = 5.0

  RAW = "From: sender@remote.test\r\nSubject: dos probe\r\n\r\nbody\r\n"

  # Overrides an ImapServer tuning constant for the block (copied from the
  # pen-test/session-test convention).
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

  # Runs the block, asserting it returns within BUDGET, and hands back its
  # value. The client sockets also carry a timeout so a genuine hang surfaces
  # as an error rather than wedging the suite.
  def within_budget
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    value = yield
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert_operator elapsed, :<, BUDGET, "response was not bounded (took #{elapsed.round(2)}s)"
    value
  end

  def login_select(mailbox: "INBOX", seed: RAW)
    client = connect
    client.timeout = BUDGET + 2
    @store.append(@account_id, mailbox, seed, [], nil) if seed
    assert_match(/\A.*OK/m, command(client, "s1", "SELECT #{mailbox}"))
    client
  end

  # -- Class 1: SEARCH / FETCH / sequence-set resource DoS --------------------

  # A sequence set with a huge comma list is refused outright
  # (MAX_SEQUENCE_CHUNKS): resolving one costs ranges x log(mailbox), so a
  # 20,000-chunk set is an attack, not a client. BAD, promptly, session
  # intact - and a set at the cap still resolves correctly, each message
  # once however many chunks name it.
  def test_massive_comma_sequence_set_is_refused
    client = login_select
    set = Array.new(20_000, "1").join(",")
    reply = within_budget { command(client, "a1", "FETCH #{set} (UID)") }
    assert_match(/\Aa1 BAD/, reply)
    assert_match(/\Aa2 BAD/, command(client, "a2", "UID SEARCH UID #{set}"))
    assert_match(/\Aa3 BAD/, command(client, "a3", "STORE #{set} +FLAGS (\\Seen)"))

    at_cap = Array.new(MailOnRails::ImapServer::MAX_SEQUENCE_CHUNKS, "1").join(",")
    reply = within_budget { command(client, "a4", "FETCH #{at_cap} (UID)") }
    assert_match(/a4 OK/, reply)
    assert_equal 1, reply.scan(/^\* 1 FETCH/).size, "the one message is reported once, not per duplicate"
    command(client, "a9", "LOGOUT")
  end

  # A session over a synthetic 50,000-message snapshot (no store traffic
  # needed: resolution is snapshot-only). A set at the chunk cap resolves
  # well inside a second in both modes...
  def test_sequence_set_resolution_is_logarithmic_in_the_mailbox
    session = MailOnRails::ImapServer::Session.new(nil, @store, { tls: :implicit }, nil)
    session.instance_variable_set(:@uids, (1..50_000).map { |i| i * 2 })
    set = Array.new(MailOnRails::ImapServer::MAX_SEQUENCE_CHUNKS) { |i| "#{i * 97 + 1}:#{i * 97 + 40}" }.join(",")

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    uid_hits = session.send(:resolve_set, set, true)
    seq_hits = session.send(:resolve_set, set, false)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.0
    assert_equal uid_hits.map(&:last), uid_hits.map(&:last).uniq.sort
    assert_equal seq_hits.map(&:first), seq_hits.map(&:first).uniq.sort
    assert_operator uid_hits.length, :>, 0
  end

  # ...and answers exactly what the naive "every uid against every range"
  # resolution would, on random overlapping sets with "*", in both modes.
  def test_sequence_set_resolution_matches_the_naive_implementation
    session = MailOnRails::ImapServer::Session.new(nil, @store, { tls: :implicit }, nil)
    uids = (1..3000).map { |i| i * 3 }
    session.instance_variable_set(:@uids, uids)
    rng = Random.new(20_260_901)
    naive = lambda do |set, uid_mode|
      max = uid_mode ? uids.last : uids.length
      ranges = set.split(",").map do |chunk|
        lo, hi = chunk.split(":", 2)
        lo = lo == "*" ? max : lo.to_i
        hi = hi.nil? ? lo : (hi == "*" ? max : hi.to_i)
        lo, hi = hi, lo if lo > hi
        (lo..hi)
      end
      uids.each_with_index.filter_map do |uid, idx|
        [ idx + 1, uid ] if ranges.any? { |r| r.cover?(uid_mode ? uid : idx + 1) }
      end
    end
    20.times do
      chunks = Array.new(rng.rand(1..40)) do
        a = rng.rand(1..9500)
        case rng.rand(4)
        when 0 then a.to_s
        when 1 then "#{a}:#{rng.rand(1..9500)}"
        when 2 then "#{a}:*"
        else "*"
        end
      end
      set = chunks.join(",")
      [ true, false ].each do |uid_mode|
        assert_equal naive.call(set, uid_mode), session.send(:resolve_set, set, uid_mode), "#{set} uid_mode=#{uid_mode}"
      end
    end
  end

  # FETCH streams its responses in bounded store batches: metadata
  # FETCH_META_BATCH at a time, raw bytes FETCH_RAW_BATCH messages (or
  # FETCH_RAW_BATCH_BYTES) per call - a "download everything" FETCH never
  # holds the mailbox in memory, and the responses stay in mailbox order.
  class BatchProbeStore < MailOnRails::Imap::Store::Memory
    attr_reader :fetches

    def initialize(...)
      super
      @fetches = []
    end

    def fetch(mailbox_id, uids, with_raw)
      @fetches << [ with_raw, uids.dup ]
      super
    end
  end

  def test_fetch_batches_store_calls_and_keeps_response_order
    @store = BatchProbeStore.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    120.times { |i| @store.append(@account_id, "INBOX", "Subject: m#{i}\r\n\r\n#{"x" * 1000}\r\n", [], nil) }
    client = login_select(seed: nil)
    @store.fetches.clear

    reply = within_budget { command(client, "a1", "FETCH 1:* (BODY.PEEK[HEADER])") }
    assert_match(/a1 OK/, reply)
    seqs = reply.scan(/^\* (\d+) FETCH/).flatten.map(&:to_i)
    assert_equal (1..120).to_a, seqs, "responses in mailbox order, each once"
    meta, raw = @store.fetches.partition { |with_raw, _uids| !with_raw }
    assert_equal [ 120 ], meta.map { |_w, uids| uids.length }
    assert_operator raw.length, :>=, 3
    assert raw.all? { |_w, uids| uids.length <= MailOnRails::ImapServer::FETCH_RAW_BATCH }
    assert_equal (1..120).to_a, raw.flat_map { |_w, uids| uids }

    @store.fetches.clear
    assert_match(/a2 OK/, command(client, "a2", "FETCH 1:* (FLAGS RFC822.SIZE)"))
    assert_equal [ [ false, (1..120).to_a ] ], @store.fetches, "metadata-only items make one metadata call"

    # Raw batches are also bounded in bytes, from the metadata sizes.
    @store.fetches.clear
    with_imap_const(:FETCH_RAW_BATCH_BYTES, 2500) do
      assert_match(/a3 OK/, command(client, "a3", "FETCH 1:5 (BODY.PEEK[])"))
    end
    raw = @store.fetches.select { |with_raw, _uids| with_raw }
    assert_equal [ [ 1, 2 ], [ 3, 4 ], [ 5 ] ], raw.map(&:last), "two ~1 KB messages per 2.5 KB batch"
    command(client, "a9", "LOGOUT")
  end

  # -- M11: mailbox names, hierarchy depth, LIST patterns ---------------------

  def test_mailbox_names_are_capped_in_length
    client = login_select(seed: nil)
    max = MailOnRails::ImapServer::MAX_MAILBOX_NAME_BYTES
    assert_match(/\Aa1 OK/, command(client, "a1", "CREATE #{"n" * max}"))
    assert_match(/\Aa2 NO \[CANNOT\]/, command(client, "a2", "CREATE #{"n" * (max + 1)}"))
    assert_match(/\Aa3 NO \[CANNOT\]/, command(client, "a3", "SELECT #{"n" * (max * 3)}"), "over twice the cap is refused before decoding")
    # A UTF-7 name that decodes past the cap is refused after decoding.
    encoded = MailOnRails::Imap::Utf7.encode("é" * 600) # 1200 UTF-8 bytes
    assert_match(/\Aa4 NO \[CANNOT\]/, command(client, "a4", "CREATE #{encoded}"))
    assert_match(/\Aa5 OK/, command(client, "a5", "NOOP"))
    command(client, "a9", "LOGOUT")
  end

  def test_mailbox_hierarchy_depth_is_capped_before_parents_are_created
    client = login_select(seed: nil)
    depth = MailOnRails::ImapServer::MAX_MAILBOX_DEPTH
    ok = (1..depth).map { |i| "d#{i}" }.join("/")
    assert_match(/\Aa1 OK/, command(client, "a1", "CREATE #{ok}"))
    deep = (1..(depth + 1)).map { |i| "e#{i}" }.join("/")
    assert_match(/\Aa2 NO \[CANNOT\]/, command(client, "a2", "CREATE #{deep}"))
    assert_match(/\Aa3 NO \[CANNOT\]/, command(client, "a3", "RENAME d1 #{deep}"))
    listing = command(client, "a4", %(LIST "" "e1*"))
    refute_match(/"e1/, listing, "no intermediate mailbox of the refused name may exist")
    assert_match(/\Aa4 OK/, listing)
    command(client, "a9", "LOGOUT")
  end

  # The pattern is bounded before Regexp compilation (which Regexp.timeout
  # does not cover): length and wildcard count.
  def test_list_pattern_is_capped_before_the_regexp_is_compiled
    client = login_select(seed: nil)
    limit = MailOnRails::ImapServer::MAX_LIST_PATTERN_BYTES
    wildcards = MailOnRails::ImapServer::MAX_LIST_WILDCARDS
    assert_match(/\Aa1 BAD/, within_budget { command(client, "a1", %(LIST "" "#{"%" * 5000}")) })
    assert_match(/\Aa2 BAD/, command(client, "a2", %(LIST "" "#{"x" * (limit + 1)}")))
    assert_match(/\Aa3 BAD/, command(client, "a3", %(LIST "" "#{"%" * (wildcards + 1)}")))
    assert_match(/\Aa4 BAD/, command(client, "a4", %(LSUB "#{"*" * wildcards}" "*")), "reference counts toward the pattern")
    reply = command(client, "a5", %(LIST "" "#{"%" * wildcards}"))
    assert_match(/\* LIST .*"INBOX"/, reply)
    assert_match(/^a5 OK/, reply)
    assert_match(/\Aa6 OK/, command(client, "a6", "NOOP"))
    command(client, "a9", "LOGOUT")
  end

  # LIST over thousands of mailboxes: the CHILDREN attribute is an index
  # lookup per line, not a scan of every other name per line.
  def test_list_over_many_mailboxes_is_linear
    100.times { |p| @store.create_mailbox(@account_id, "m#{p}") }
    3000.times { |i| @store.create_mailbox(@account_id, "m#{i / 30}/c#{i}") }
    client = login_select(seed: nil)
    reply = within_budget { command(client, "a1", %(LIST "" "*")) }
    assert_match(/^a1 OK/, reply)
    assert_equal 3105, reply.scan(/^\* LIST /).size # 5 defaults + 100 parents + 3000 children
    assert_equal 100, reply.scan(/\\HasChildren/).size
    command(client, "a9", "LOGOUT")
  end

  # The MIME parser stops descending once the copies it has made exceed
  # MAX_COPY_FACTOR times the message: a message nested to MAX_DEPTH no
  # longer costs ~2x its size per level.
  def test_mime_parser_bounds_copied_bytes
    raw = nested_multipart(600)
    part = within_budget { Mime.parse(raw) }
    retained = 0
    stack = [ part ]
    until stack.empty?
      node = stack.pop
      retained += node.header_block.bytesize + node.body.bytesize
      stack.concat(node.children.to_a)
      stack << node.embedded if node.embedded
    end
    assert_operator retained, :<=, raw.bytesize * (Mime::MAX_COPY_FACTOR + 2)

    # Ordinary nesting is untouched: mixed > alternative > text parts.
    normal = nested_multipart(3)
    assert Mime.parse(normal).children.first.children.first.children.first.type == "text"
  end

  # UID mode tolerates non-existent UIDs, so bad_seq? cannot reject a giant
  # UID range - the defense is lazy Range cover-checks in resolve_set. A long
  # comma list of full-uint32 ranges must clip to what exists, promptly.
  def test_many_huge_uid_ranges_clip_without_enumeration
    client = login_select
    set = Array.new(500, "1:4294967295").join(",")
    reply = within_budget { command(client, "a1", "UID FETCH #{set} (FLAGS)") }
    assert_match(/a1 OK/, reply)
    assert_equal 1, reply.scan(/^\* \d+ FETCH/).size, "nothing beyond the mailbox is enumerated"
    command(client, "a9", "LOGOUT")
  end

  # A deeply nested OR chain (the Dovecot exponential-SEARCH class) must hit
  # the recursion-depth cap and return BAD, not descend into a
  # SystemStackError that kills the session thread. OR nests one level per
  # operand, so a chain past MAX_SEARCH_DEPTH trips the guard.
  def test_deeply_nested_or_chain_is_rejected_not_fatal
    with_imap_const(:MAX_SEARCH_DEPTH, 8) do
      client = login_select
      chain = ("OR " * 20) + ([ "ALL" ] * 21).join(" ")
      reply = within_budget { command(client, "a1", "SEARCH #{chain}") }
      assert_match(/\Aa1 BAD/, reply, "an over-deep OR chain is a syntax error, not a crash")
      assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"), "session survives")
      command(client, "a9", "LOGOUT")
    end
  end

  # NOT chains recurse the same parser; a long run must also be capped rather
  # than overflow the stack.
  def test_deeply_nested_not_chain_is_rejected_not_fatal
    with_imap_const(:MAX_SEARCH_DEPTH, 8) do
      client = login_select
      chain = ("NOT " * 40) + "ALL"
      reply = within_budget { command(client, "a1", "SEARCH #{chain}") }
      assert_match(/\Aa1 BAD/, reply)
      assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"))
      command(client, "a9", "LOGOUT")
    end
  end

  # -- Class 2: hostile MIME / BODYSTRUCTURE generation -----------------------

  def nested_multipart(depth)
    raw = "Content-Type: text/plain\r\n\r\ninner\r\n"
    depth.times do |i|
      b = "b#{i}"
      raw = "Content-Type: multipart/mixed; boundary=#{b}\r\n\r\n--#{b}\r\n#{raw}\r\n--#{b}--\r\n"
    end
    raw
  end

  def nested_rfc822(depth)
    raw = "Subject: core\r\n\r\ncore body\r\n"
    depth.times { raw = "Content-Type: message/rfc822\r\n\r\n#{raw}" }
    raw
  end

  # The MIME parser caps nesting at MAX_DEPTH: beyond it a container degrades
  # to an opaque leaf, so a message nested hundreds deep is parsed in bounded
  # time and depth (CVE-2020-12100 / CVE-2020-25275 class). Locked in against
  # the parser directly so the cap is asserted, not just the timing.
  def test_mime_parser_caps_nesting_depth
    part = within_budget { Mime.parse(nested_multipart(600)) }
    depth = 0
    while part
      depth += 1
      part = part.multipart? ? part.children&.first : part.embedded
    end
    assert_operator depth, :<=, Mime::MAX_DEPTH + 1, "nesting is capped at MAX_DEPTH"
  end

  # A multipart with far more parts than MAX_PARTS keeps only MAX_PARTS
  # children; the rest fold into the trailing chunk instead of a runaway
  # allocation.
  def test_mime_parser_caps_part_count
    body = "Content-Type: multipart/mixed; boundary=z\r\n\r\n" +
           ("--z\r\nContent-Type: text/plain\r\n\r\nx\r\n" * (Mime::MAX_PARTS + 500)) + "--z--\r\n"
    part = within_budget { Mime.parse(body) }
    assert_operator part.children.size, :<=, Mime::MAX_PARTS, "child count is capped at MAX_PARTS"
  end

  # End to end: APPEND a hundreds-deep multipart, then FETCH the structure
  # items real clients ask for. Each must complete promptly with the session
  # intact - no recursion blowup in BODYSTRUCTURE/ENVELOPE/BODY generation.
  def test_deeply_nested_multipart_append_and_fetch_is_bounded
    client = login_select(seed: nil)
    assert_match(/a1 OK/, append(client, "a1", "INBOX", nested_multipart(600)))
    command(client, "a2", "SELECT INBOX")
    reply = within_budget { command(client, "a3", "FETCH 1 (BODYSTRUCTURE ENVELOPE BODY[1])") }
    assert_match(/a3 OK/, reply)
    assert_match(/\Aa4 OK/, command(client, "a4", "NOOP"))
    command(client, "a9", "LOGOUT")
  end

  # CVE-2026-26312 (Stalwart): malformed nested message/rfc822 parts drove a
  # parser into unbounded following of cyclical references. Our embedded
  # parse is depth-bounded, so a deeply nested message/rfc822 chain must
  # FETCH in bounded time without OOM.
  def test_deeply_nested_message_rfc822_is_bounded
    client = login_select(seed: nil)
    assert_match(/a1 OK/, append(client, "a1", "INBOX", nested_rfc822(600)))
    command(client, "a2", "SELECT INBOX")
    reply = within_budget { command(client, "a3", "FETCH 1 (BODYSTRUCTURE ENVELOPE)") }
    assert_match(/a3 OK/, reply)
    assert_match(/\Aa4 OK/, command(client, "a4", "NOOP"))
    command(client, "a9", "LOGOUT")
  end

  # A message split into far more small parts than MAX_PARTS must still FETCH
  # promptly over the wire (the cap applies inside the session, not only in a
  # unit test).
  def test_thousands_of_small_parts_fetch_is_bounded
    body = "Content-Type: multipart/mixed; boundary=z\r\n\r\n" +
           ("--z\r\nContent-Type: text/plain\r\n\r\nx\r\n" * 4000) + "--z--\r\n"
    client = login_select(seed: nil)
    assert_match(/a1 OK/, append(client, "a1", "INBOX", body))
    command(client, "a2", "SELECT INBOX")
    reply = within_budget { command(client, "a3", "FETCH 1 (BODYSTRUCTURE)") }
    assert_match(/a3 OK/, reply)
    command(client, "a9", "LOGOUT")
  end

  # CVE-2008-4907 (Dovecot): a malformed From address made ENVELOPE
  # generation abort the session. Group syntax, empty groups, and garbled
  # angle brackets must all yield an ENVELOPE (with NIL where an address
  # can't be parsed) and leave the session usable.
  def test_malformed_and_group_addresses_do_not_crash_envelope
    messages = [
      "From: undisclosed-recipients:;\r\nSubject: g0\r\n\r\nbody\r\n",
      "From: A Group: a@x.test, b@y.test;\r\nTo: nobody:;\r\nSubject: g1\r\n\r\nbody\r\n",
      "From: <<<<@@@@>>>>\r\nSubject: g2\r\n\r\nbody\r\n",
      "From: \"unterminated quote\r\nSubject: g3\r\n\r\nbody\r\n"
    ]
    client = login_select(seed: nil)
    messages.each_with_index do |raw, i|
      assert_match(/OK/, append(client, "m#{i}", "INBOX", raw))
    end
    command(client, "a2", "SELECT INBOX")
    reply = within_budget { command(client, "a3", "FETCH 1:* (ENVELOPE)") }
    assert_match(/a3 OK/, reply)
    assert_equal messages.size, reply.scan(/ENVELOPE \(/).size, "every message yields an ENVELOPE"
    refute_match(/ENVELOPE \(.*\(\)/, reply, "empty address lists are NIL, never ()")
    command(client, "a9", "LOGOUT")
  end

  # An unterminated multipart boundary (no closing --boundary--) and garbled
  # Content-Type params must parse to a leaf/opaque structure, not loop or
  # raise; BODYSTRUCTURE still completes.
  def test_unterminated_boundary_and_garbled_params_are_tolerated
    raw = "Content-Type: multipart/mixed; boundary=q; name=\"\\\\; charset==;;\r\n\r\n" \
          "--q\r\nContent-Type: text/plain\r\n\r\nonly part, no close\r\n"
    client = login_select(seed: nil)
    assert_match(/a1 OK/, append(client, "a1", "INBOX", raw))
    command(client, "a2", "SELECT INBOX")
    reply = within_budget { command(client, "a3", "FETCH 1 (BODYSTRUCTURE)") }
    assert_match(/a3 OK/, reply)
    command(client, "a9", "LOGOUT")
  end

  # -- Class 3: IDLE command-level abuse --------------------------------------

  # Enters IDLE, then reads the "+ idling" continuation.
  def start_idle(client, tag)
    client.write("#{tag} IDLE\r\n")
    line = client.gets("\r\n")
    assert_match(/\A\+ /, line, "IDLE answers with a continuation")
  end

  # A garbage line while idling is not DONE: the server answers BAD and ends
  # the IDLE, and the session remains usable (no state confusion, no hang).
  def test_idle_garbage_line_is_rejected_and_session_survives
    client = login_select
    start_idle(client, "i1")
    client.write("this-is-not-done\r\n")
    reply = within_budget { read_until_tagged(client, "i1") }
    assert_match(/\Ai1 BAD/, reply, "non-DONE input during IDLE is BAD")
    assert_match(/\Aa2 OK/, command(client, "a2", "NOOP"), "session usable after a rejected IDLE")
    command(client, "a9", "LOGOUT")
  end

  # Pipelining a fresh command while IDLE is active is the classic IDLE
  # state-confusion: it must be treated as (invalid) IDLE input - BAD - not
  # dispatched as a command against a session that thinks it is idling.
  def test_command_sent_during_idle_is_not_dispatched
    client = login_select
    start_idle(client, "i1")
    client.write("a2 SELECT Sent\r\n")
    reply = within_budget { read_until_tagged(client, "i1") }
    assert_match(/\Ai1 BAD/, reply, "a command during IDLE terminates IDLE with BAD, not a dispatch")
    # The pipelined line was consumed as IDLE input, so INBOX is still the
    # selected mailbox - a UID FETCH resolves against it.
    assert_match(/\Aa3 OK/, command(client, "a3", "NOOP"))
    command(client, "a9", "LOGOUT")
  end

  # DONE remains the one accepted terminator (guards against the rejection
  # above being over-broad).
  def test_idle_done_terminates_cleanly
    client = login_select
    start_idle(client, "i1")
    client.write("DONE\r\n")
    assert_match(/\Ai1 OK/, within_budget { read_until_tagged(client, "i1") })
    command(client, "a9", "LOGOUT")
  end

  # -- Class 4: COMPRESS=DEFLATE (structurally not applicable) -----------------

  # COMPRESS is neither advertised nor implemented, so the CVE-2014-8760
  # class (unencrypted data via compression / decompression-bomb amplifying
  # a stream) cannot arise. Verify it is genuinely absent and cleanly
  # refused rather than half-wired.
  def test_compress_is_not_advertised_and_is_refused
    client = connect
    client.timeout = BUDGET + 2
    caps = command(client, "c1", "CAPABILITY")
    refute_match(/COMPRESS/i, caps, "COMPRESS must not be advertised")
    reply = command(client, "c2", "COMPRESS DEFLATE")
    assert_match(/\Ac2 BAD/, reply, "COMPRESS is refused as an unknown command")
    assert_match(/\Ac3 OK/, command(client, "c3", "NOOP"), "session survives the refusal")
    command(client, "c9", "LOGOUT")
  end
end

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

  # A sequence set with a huge comma list must be answered by lazy range
  # cover-checks, never by materialising every listed number. Thousands of
  # duplicate "1"s fit inside one MAX_LINE command; the reply must still be
  # prompt and correct (the mailbox has one message).
  def test_massive_comma_sequence_set_is_bounded
    client = login_select
    set = Array.new(20_000, "1").join(",")
    reply = within_budget { command(client, "a1", "FETCH #{set} (UID)") }
    assert_match(/a1 OK/, reply)
    assert_equal 1, reply.scan(/^\* 1 FETCH/).size, "the one message is reported once, not per duplicate"
    command(client, "a9", "LOGOUT")
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

# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# Mail is the sender's to write, and SORT, THREAD and SEARCH read its
# headers for every message in the mailbox (audit 2026-11-17).
#
# L17: a Date header with an out-of-range field makes Time.parse and
# Date.parse raise RangeError, which the rescues did not name - one such
# message broke SORT (DATE), THREAD and SEARCH SENT* for its mailbox.
# L16: THREAD=REFERENCES was quadratic in the depth of the tree the
# References chains build - 1000 small messages, 34 s.
class HostileMailTest < Minitest::Test
  include WireHarness

  Server = MailOnRails::ImapServer

  HOSTILE_DATES = [
    "2020-99999999999999999999-01 99999999999999999999:00:00",
    "1 Jan 2020 99999999999999999999:00:00",
    "1 Jan 2020 00:00:99999999999999999999",
    "2020-99999999999999999999-01"
  ].freeze

  def msg(id:, date:, subject: "s", refs: nil)
    lines = [ "Date: #{date}", "From: a@x.test", "Subject: #{subject}", "Message-Id: <#{id}>" ]
    lines << "References: #{refs.map { |r| "<#{r}>" }.join(" ")}" if refs
    "#{lines.join("\r\n")}\r\n\r\nbody\r\n"
  end

  def selected
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def seconds
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  # -- L17 -----------------------------------------------------------------------

  test "a hostile Date header falls back to INTERNALDATE instead of failing the mailbox" do
    day = 86_400
    @store.append(@account_id, "INBOX", msg(id: "new@x", date: "Wed, 3 Jan 2024 10:00:00 +0000"), [], 1_704_275_000)
    HOSTILE_DATES.each_with_index do |date, i|
      # INTERNALDATE 2 Jan 2024: between the two honest messages.
      @store.append(@account_id, "INBOX", msg(id: "bad#{i}@x", date: date, subject: "bad#{i}"), [], 1_704_189_000 + i)
    end
    @store.append(@account_id, "INBOX", msg(id: "old@x", date: "Mon, 1 Jan 2024 10:00:00 +0000"), [], 1_704_275_000 + day)
    c = selected

    assert_match(/^\* SORT 6 2 3 4 5 1\r\n/, command(c, "a1", "SORT (DATE) UTF-8 ALL"))
    assert_match(/^a2 OK THREAD/, command(c, "a2", "THREAD REFERENCES UTF-8 ALL"))
    assert_match(/^a3 OK THREAD/, command(c, "a3", "THREAD ORDEREDSUBJECT UTF-8 ALL"))
    # SENT* keys compare the date as far as it can be read: messages 3
    # and 4 still say "1 Jan 2020" (only their time is out of range);
    # 2 and 5 have no readable date and match no SENT* key.
    assert_match(/^\* SEARCH 1 3 4 6\r\n/, command(c, "a4", "SEARCH SENTSINCE 1-Jan-2020"))
    assert_match(/^\* SEARCH 3 4 6\r\n/, command(c, "a5", "SEARCH SENTBEFORE 2-Jan-2024"))
    assert_match(/^\* SEARCH 1\r\n/, command(c, "a6", "SEARCH SENTON 3-Jan-2024"))
  end

  # -- L16 -----------------------------------------------------------------------

  # The reviewer's mailbox: message k's References extend one long chain
  # of ids by 63 (64 are kept per message), so 1000 messages build a
  # placeholder tree 63,000 deep.
  def chain_entries(count)
    (0...count).map do |k|
      { num: k + 1, uid: k + 1, date: k, message_id: "m#{k}@x", subject: "s#{k}", reply: false,
        references: (k * 63..k * 63 + 63).map { |i| "c#{i}@x" } }
    end
  end

  def bare_session = Server::Session.new(nil, @store, { tls: :implicit }, nil)

  test "a References chain thousands deep threads in linear time" do
    session = bare_session
    threads = nil

    elapsed = seconds { threads = session.send(:references_threads, chain_entries(2_000)) }

    assert_operator elapsed, :<, 5, "took #{elapsed.round(1)}s (it was 30 s for half as many)"
    # Every message hangs off the one chain of ids nobody has; with the
    # placeholders dissolved they are siblings under one root, in order.
    assert_equal "(#{(1..2_000).map { |n| "(#{n})" }.join})", threads.join
  end

  test "the same mailbox over the wire" do
    300.times do |k|
      refs = (k * 63..k * 63 + 63).map { |i| "c#{i}@x" }
      @store.append(@account_id, "INBOX", msg(id: "m#{k}@x", date: "Mon, 1 Jan 2024 10:00:00 +0000", subject: "s#{k}", refs: refs), [], 1_704_189_000 + k)
    end
    c = selected
    reply = nil

    elapsed = seconds { reply = command(c, "t", "THREAD REFERENCES UTF-8 ALL") }

    assert_operator elapsed, :<, 3, "took #{elapsed.round(1)}s"
    assert_equal "* THREAD (#{(1..300).map { |n| "(#{n})" }.join})\r\n", reply.lines.first
  end

  # What the linear path cannot cover - linking roots that already have
  # children under ever deeper nodes - draws on a step budget. Spent, the
  # remaining links are skipped: every message is still in the result,
  # exactly once.
  test "past the loop-check budget THREAD still answers with every message once" do
    entries = []
    # A deep chain, then roots-with-a-child linked under its far end.
    entries << { num: 1, uid: 1, date: 1, message_id: "deep@x", subject: "deep", reply: false,
                 references: (1..60).map { |i| "d#{i}@x" } }
    (2..200).each do |n|
      entries << { num: n, uid: n, date: n, message_id: "kid#{n}@x", subject: "k#{n}", reply: false, references: [ "root#{n}@x" ] }
    end
    (201..210).each do |n|
      entries << { num: n, uid: n, date: n, message_id: "link#{n}@x", subject: "l#{n}", reply: false,
                   references: [ "d60@x" ] + (2..60).map { |r| "root#{r + (n - 201)}@x" } }
    end
    unlimited = bare_session.send(:references_threads, entries.map(&:dup)).join

    limited = with_link_steps(50) { bare_session.send(:references_threads, entries.map(&:dup)).join }

    [ unlimited, limited ].each do |rendered|
      assert_equal (1..210).to_a, rendered.scan(/\d+/).map(&:to_i).sort
      assert_equal rendered.count("("), rendered.count(")")
    end
    refute_equal unlimited, limited, "the budget did cut links short"
  end

  def with_link_steps(steps)
    old = Server::MAX_THREAD_LINK_STEPS
    Server.send(:remove_const, :MAX_THREAD_LINK_STEPS)
    Server.const_set(:MAX_THREAD_LINK_STEPS, steps)
    yield
  ensure
    Server.send(:remove_const, :MAX_THREAD_LINK_STEPS)
    Server.const_set(:MAX_THREAD_LINK_STEPS, old)
  end

  # Merging root threads by subject looked each replaced thread up by a
  # scan of the root list.
  test "thousands of root threads merging by subject stay linear" do
    entries = (1..6_000).map do |n|
      reply = n <= 3_000
      { num: n, uid: n, date: n, message_id: "m#{n}@x", subject: "topic #{reply ? n : n - 3_000}", reply: reply, references: [] }
    end
    threads = nil

    elapsed = seconds { threads = bare_session.send(:references_threads, entries) }

    assert_operator elapsed, :<, 3
    assert_equal 3_000, threads.length
    assert_includes threads, "(3001 1)", "the non-reply roots its subject's thread"
  end
end

# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# RFC 5256 THREAD (REFERENCES and ORDEREDSUBJECT) plus the real RFC 8474
# THREADID that replaced the NIL stub: fetch item, search key, and the
# store-resolved ids that group replies across deliveries.
class ThreadTest < Minitest::Test
  include WireHarness

  def msg(id:, subject:, date:, refs: nil)
    lines = [ "Date: #{date}", "From: a@x.test", "Subject: #{subject}", "Message-Id: <#{id}>" ]
    lines << "References: #{refs.map { |r| "<#{r}>" }.join(" ")}" if refs
    "#{lines.join("\r\n")}\r\n\r\nbody\r\n"
  end

  def append(raw)
    @store.append(@account_id, "INBOX", raw, [], nil)
  end

  def select_inbox
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def thread_response(client, tag, line)
    reply = command(client, tag, line)
    assert_match(/^#{tag} OK/, reply)
    reply[/^\* THREAD (.*)\r\n/, 1]
  end

  test "capability advertises both algorithms" do
    c = connect(login: false)
    assert_match(/THREAD=ORDEREDSUBJECT THREAD=REFERENCES/, command(c, "c1", "CAPABILITY"))
  end

  test "references threads a linear chain" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "r1@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    append msg(id: "r2@x", subject: "Re: hi", date: "Wed, 3 Jan 2024 10:00:00 +0000", refs: %w[root@x r1@x])
    append msg(id: "other@x", subject: "other", date: "Thu, 4 Jan 2024 10:00:00 +0000")
    c = select_inbox

    assert_equal "(1 2 3)(4)", thread_response(c, "t1", "THREAD REFERENCES UTF-8 ALL")
  end

  test "references forks siblings and sorts them by date" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "b@x", subject: "Re: hi", date: "Wed, 3 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    append msg(id: "a@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    c = select_inbox

    assert_equal "(1 (3)(2))", thread_response(c, "t1", "THREAD REFERENCES UTF-8 ALL")
  end

  test "references keeps orphan siblings together under a placeholder" do
    append msg(id: "a@x", subject: "Re: gone", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[ghost@x])
    append msg(id: "b@x", subject: "Re: gone", date: "Mon, 1 Jan 2024 10:00:00 +0000", refs: %w[ghost@x])
    c = select_inbox

    assert_equal "((2)(1))", thread_response(c, "t1", "THREAD REFERENCES UTF-8 ALL")
  end

  test "references merges reference-less replies by base subject" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "r1@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000")
    c = select_inbox

    assert_equal "(1 2)", thread_response(c, "t1", "THREAD REFERENCES UTF-8 ALL")
  end

  test "ordered subject groups by base subject in date order" do
    append msg(id: "a@x", subject: "alpha", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "b@x", subject: "beta", date: "Tue, 2 Jan 2024 10:00:00 +0000")
    append msg(id: "c@x", subject: "Re: alpha", date: "Wed, 3 Jan 2024 10:00:00 +0000")
    c = select_inbox

    assert_equal "(1 3)(2)", thread_response(c, "t1", "THREAD ORDEREDSUBJECT UTF-8 ALL")
  end

  test "uid thread reports uids and search keys filter the set" do
    append("X: y\r\n\r\nplaceholder\r\n").then { |r| @store.store_flags(inbox_id, [ r[:uid] ], "+", [ "\\Deleted" ]) }
    @store.expunge(inbox_id)
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "r1@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    c = select_inbox

    assert_equal "(2 3)", thread_response(c, "u1", "UID THREAD REFERENCES UTF-8 ALL")
    assert_equal "(2)", thread_response(c, "u2", %(UID THREAD REFERENCES UTF-8 SUBJECT "hi" NOT HEADER "references" "root"))
  end

  test "bad algorithm and bad charset are refused" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    c = select_inbox

    assert_match(/\Ab1 BAD/, command(c, "b1", "THREAD BOGUS UTF-8 ALL"))
    assert_match(/\Ab2 NO \[BADCHARSET/, command(c, "b2", "THREAD REFERENCES KOI8-R ALL"))
    assert_match(/\Ab3 BAD/, command(c, "b3", "THREAD REFERENCES UTF-8"))
  end

  # The tree passes (prune, sort, render) walk explicit stacks: a
  # References chain as deep as the mailbox must render as one linear
  # thread without touching the Ruby stack. Entries are built directly -
  # appending tens of thousands of messages is the store's cost, not the
  # algorithm's.
  test "references renders a chain deeper than the Ruby stack" do
    session = MailOnRails::ImapServer::Session.new(nil, @store, { tls: :implicit }, nil)
    depth = 20_000
    entries = (1..depth).map do |i|
      { num: i, uid: i, date: i, message_id: "m#{i}@x", references: i == 1 ? [] : [ "m#{i - 1}@x" ],
        subject: "chain", reply: i > 1 }
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    threads = session.send(:references_threads, entries)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
    assert_equal "(#{(1..depth).to_a.join(" ")})", threads.join

    # Same depth through placeholders: every message references a chain of
    # unknown ids, so pruning has to collapse a deep placeholder spine.
    entries = (1..depth).map do |i|
      { num: i, uid: i, date: i, message_id: "p#{i}@x", references: [ "ghost#{i}@x" ], subject: "s#{i}", reply: false }
    end
    threads = session.send(:references_threads, entries)
    assert_equal depth, threads.length
  end

  # A fork at every level (each message has two replies) exercises the
  # work-stack renderer against the recursive one's exact output shape.
  test "references renders nested forks in RFC 5256 form" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "a@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    append msg(id: "b@x", subject: "Re: hi", date: "Wed, 3 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    append msg(id: "a1@x", subject: "Re: hi", date: "Thu, 4 Jan 2024 10:00:00 +0000", refs: %w[root@x a@x])
    append msg(id: "a2@x", subject: "Re: hi", date: "Fri, 5 Jan 2024 10:00:00 +0000", refs: %w[root@x a@x])
    append msg(id: "b1@x", subject: "Re: hi", date: "Sat, 6 Jan 2024 10:00:00 +0000", refs: %w[root@x b@x])
    c = select_inbox

    assert_equal "(1 (2 (4)(5))(3 6))", thread_response(c, "t1", "THREAD REFERENCES UTF-8 ALL")
  end

  # A References header padded with thousands of ids is trimmed to
  # MAX_THREAD_REFERENCES (oldest and newest kept, so the thread still
  # hangs off its real root and parent) and threads promptly.
  test "a message with thousands of references threads promptly and correctly" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "mid@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    padded = [ "root@x" ] + (1..5000).map { |i| "pad#{i}@x" } + [ "mid@x" ]
    append msg(id: "leaf@x", subject: "Re: hi", date: "Wed, 3 Jan 2024 10:00:00 +0000", refs: padded)
    c = select_inbox

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    threads = thread_response(c, "t1", "THREAD REFERENCES UTF-8 ALL")
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
    assert_equal "(1 2 3)", threads
    assert_match(/\At2 OK/, command(c, "t2", "NOOP"), "session survives")
  end

  # A handler that does overflow the stack (here forced) ends the command
  # with BAD, not the session: SystemStackError is not a StandardError and
  # would otherwise escape handle's rescue.
  test "a stack overflow inside a handler yields BAD and the session survives" do
    session_class = MailOnRails::ImapServer::Session
    session_class.class_eval do
      alias_method :namespace_without_overflow, :namespace
      define_method(:namespace) { |_tag| raise SystemStackError, "stack level too deep" }
    end
    begin
      c = connect
      assert_match(/\Ax1 BAD Internal error/, command(c, "x1", "NAMESPACE"))
      assert_match(/\Ax2 OK/, command(c, "x2", "NOOP"))
    ensure
      session_class.class_eval do
        alias_method :namespace, :namespace_without_overflow
        remove_method :namespace_without_overflow
      end
    end
  end

  test "threadid fetch item and search key use the store's thread ids" do
    append msg(id: "root@x", subject: "hi", date: "Mon, 1 Jan 2024 10:00:00 +0000")
    append msg(id: "r1@x", subject: "Re: hi", date: "Tue, 2 Jan 2024 10:00:00 +0000", refs: %w[root@x])
    append msg(id: "other@x", subject: "other", date: "Wed, 3 Jan 2024 10:00:00 +0000")
    c = select_inbox

    first = command(c, "f1", "FETCH 1 (THREADID)")[/THREADID \(([\w-]+)\)/, 1]
    second = command(c, "f2", "FETCH 2 (THREADID)")[/THREADID \(([\w-]+)\)/, 1]
    third = command(c, "f3", "FETCH 3 (THREADID)")[/THREADID \(([\w-]+)\)/, 1]
    assert first, "THREADID must not be NIL"
    assert_equal first, second, "a reply shares its ancestor's THREADID"
    refute_equal first, third

    reply = command(c, "s1", "SEARCH THREADID #{first}")
    assert_match(/^\* SEARCH 1 2\r\n/, reply)
  end
end

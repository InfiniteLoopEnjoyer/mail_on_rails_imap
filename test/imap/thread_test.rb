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

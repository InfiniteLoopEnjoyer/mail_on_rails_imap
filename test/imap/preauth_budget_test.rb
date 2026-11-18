# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# M8 (audit 2026-11-17): the only bound on an unauthenticated connection
# was an inactivity timeout, which any byte resets - NOOP every 100 s held
# a connection slot for the 24 h session lifetime, and ten addresses with
# ten connections each held all of them. Protocol errors were counted and
# never acted on.
#
# Now: an absolute connect-to-auth deadline (enforced from outside the
# session, so it holds however the peer keeps the read busy), and a
# budget of commands and of protocol errors before authentication.
class PreauthBudgetTest < Minitest::Test
  include WireHarness

  Server = MailOnRails::ImapServer

  def session_spec = { tls: :implicit, trace_capture: true }.merge(@spec || {})

  def seconds
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  def drain(client)
    rest = +""
    while (line = client.gets("\r\n"))
      rest << line
    end
    rest
  rescue IOError, SystemCallError
    rest
  end

  def session = @session_objects.last

  def wait_for_sessions
    @sessions.each { |t| t.join(5) }
  end

  # -- the deadline ------------------------------------------------------------

  test "NOOP keeps the inactivity timeout at bay but not the deadline" do
    @spec = { preauth_deadline: 0.6, preauth_timeout: 0.4 }
    c = connect(login: false)

    elapsed = seconds do
      20.times do |i|
        c.write("n#{i} NOOP\r\n")
        break unless c.gets("\r\n")

        sleep 0.1 # well inside the inactivity timeout, every time
      end
    rescue IOError, SystemCallError
      nil
    end

    assert_operator elapsed, :<, 1.8, "the connection must end at the deadline, not ride on NOOPs"
    wait_for_sessions
    assert_equal "preauth_deadline", session.transcript_capture[:close_reason]
    assert_equal "no_auth", session.idle_reason
  end

  # The deadline has to hold inside a single read too: a command sent a
  # byte at a time never reaches a point "between commands".
  test "a command trickled in one byte at a time does not outlast the deadline" do
    @spec = { preauth_deadline: 0.6, preauth_timeout: 0.4 }
    c = connect(login: false)

    elapsed = seconds do
      40.times do
        c.write("a")
        sleep 0.1
      end
    rescue IOError, SystemCallError
      nil
    end

    assert_operator elapsed, :<, 2.5
    wait_for_sessions
    assert_equal "preauth_deadline", session.send(:capture_reason)
  end

  test "a session that authenticates is released from the deadline" do
    @spec = { preauth_deadline: 0.4 }
    c = connect

    sleep 0.9
    assert_match(/\Aa1 OK/, command(c, "a1", "NOOP"))
    assert_match(/^a2 OK LOGOUT/, command(c, "a2", "LOGOUT"))
    wait_for_sessions
    assert_nil session.transcript_capture, "an ordinary session leaves no capture"
  end

  test "the deadline is two minutes unless a listener says otherwise" do
    assert_equal 120, Server::PREAUTH_DEADLINE
  end

  test "the deadline watcher keeps no thread once nothing is armed" do
    c = connect
    command(c, "a1", "LOGOUT")
    wait_for_sessions
    watch = Server::Session.deadlines

    20.times do
      break if watch.instance_variable_get(:@deadlines).empty? && !watch.instance_variable_get(:@thread)&.alive?

      sleep 0.1
    end
    assert_empty watch.instance_variable_get(:@deadlines)
    refute watch.instance_variable_get(:@thread)&.alive?
  end

  # -- the command budget ------------------------------------------------------

  test "an unauthenticated peer gets a bounded number of commands" do
    c = connect(login: false)
    allowed = Server::MAX_PREAUTH_COMMANDS

    allowed.times { |i| assert_match(/\An#{i} OK/, command(c, "n#{i}", "NOOP"), "command #{i + 1} of #{allowed}") }

    # Said as soon as the last allowed command is answered; no further
    # command is read.
    assert_equal "* BYE Too many commands before authentication\r\n", c.gets("\r\n")
    assert_nil c.gets("\r\n")
    wait_for_sessions
    assert_equal "protocol_abuse", session.transcript_capture[:close_reason]
  end

  test "commands after login are not counted" do
    c = connect
    (Server::MAX_PREAUTH_COMMANDS * 2).times { |i| assert_match(/\An#{i} OK/, command(c, "n#{i}", "NOOP")) }
  end

  test "a login that takes all three attempts and the usual preamble is well inside the budget" do
    c = connect(login: false)
    command(c, "a1", "CAPABILITY")
    command(c, "a2", %(ID ("name" "client")))
    command(c, "a3", "LOGIN #{EMAIL} wrong-1")
    command(c, "a4", "CAPABILITY")
    command(c, "a5", "LOGIN #{EMAIL} wrong-2")
    command(c, "a6", "NOOP")

    assert_match(/\Aa7 OK/, command(c, "a7", "LOGIN #{EMAIL} #{PASSWORD}"))
  end

  # -- the error budget --------------------------------------------------------

  test "protocol errors before authentication end the connection" do
    c = connect(login: false)
    allowed = Server::MAX_PREAUTH_ERRORS

    allowed.times { |i| assert_match(/\Ae#{i} BAD/, command(c, "e#{i}", "BOGUS")) }

    assert_match(/\A\* BYE/, c.gets("\r\n"))
    assert_nil c.gets("\r\n")
  end

  test "syntax errors, refused literals and misplaced UID all count as errors" do
    c = connect(login: false)
    lines = [ %(NOOP "unterminated), "NOOP extra", "UID NOOP", "AUTHENTICATE PLAIN !!!not-base64!!!",
              "LOGIN #{EMAIL} {#{Server::MAX_PREAUTH_LITERAL_BYTES + 1}}" ]
    (lines * 2).each_with_index do |line, i|
      assert_match(/\Ae#{i} (BAD|NO)/, command(c, "e#{i}", line), line)
    end
    assert_equal Server::MAX_PREAUTH_ERRORS, lines.length * 2, "the test spends exactly the budget"

    assert_match(/\A\* BYE/, c.gets("\r\n"))
  end

  test "an authenticated session is not ended by protocol errors" do
    c = connect
    (Server::MAX_PREAUTH_ERRORS * 2).times { |i| assert_match(/\Ae#{i} BAD/, command(c, "e#{i}", "BOGUS")) }

    assert_match(/\Aa1 OK/, command(c, "a1", "NOOP"))
  end
end

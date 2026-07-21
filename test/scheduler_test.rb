# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap/scheduler"

# The fiber scheduler that lets one worker thread serve many sessions.
# Each test runs the scheduler on its own thread (its natural habitat) and
# reports back through a Thread::Queue.
class SchedulerTest < Minitest::Test
  Scheduler = MailOnRails::Imap::Scheduler

  def in_scheduler_thread
    Thread.new do
      Fiber.set_scheduler(Scheduler.new)
      Fiber.schedule { yield }
    end
  end

  test "sleeping fibers run concurrently on one thread" do
    report = Thread::Queue.new
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    thread = in_scheduler_thread do
      3.times { Fiber.schedule { sleep 0.15; report.push(:done) } }
    end
    3.times { report.pop }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    thread.join(5)

    assert_operator elapsed, :<, 0.4, "three 0.15s sleeps should overlap, took #{elapsed.round(3)}s"
  end

  test "queue push from another thread wakes a parked fiber" do
    inbox = Thread::Queue.new
    report = Thread::Queue.new
    thread = in_scheduler_thread { 3.times { report.push(inbox.pop) } }
    feeder = Thread.new { [ 1, 2, 3 ].each { |v| sleep 0.02; inbox.push(v) } }

    assert_equal [ 1, 2, 3 ], 3.times.map { report.pop }
    thread.join(5)
    feeder.join(5)
  end

  test "io timeout raises IO::TimeoutError under the scheduler" do
    r, w = IO.pipe
    report = Thread::Queue.new
    thread = in_scheduler_thread do
      r.timeout = 0.1
      begin
        r.gets
        report.push(:no_timeout)
      rescue IO::TimeoutError
        report.push(:timed_out)
      end
    end

    assert_equal :timed_out, report.pop
    thread.join(5)
    r.close
    w.close
  end

  test "Timeout.timeout is enforced via timeout_after" do
    require "timeout"
    report = Thread::Queue.new
    thread = in_scheduler_thread do
      Timeout.timeout(0.1) { sleep 5 }
      report.push(:no_timeout)
    rescue Timeout::Error
      report.push(:timed_out)
    end

    assert_equal :timed_out, report.pop
    thread.join(5)
  end

  test "one thread serves interleaved socket sessions" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    thread = in_scheduler_thread do
      2.times do
        conn = server.accept
        Fiber.schedule do
          while (line = conn.gets)
            conn.write("echo #{line}")
          end
          conn.close
        end
      end
    end

    clients = Array.new(2) { TCPSocket.new("127.0.0.1", port) }
    # Interleave across both sessions: each round trip only completes if
    # neither session is monopolizing the worker thread.
    3.times do |round|
      clients.each_with_index do |client, i|
        client.write("r#{round}c#{i}\n")

        assert_equal "echo r#{round}c#{i}\n", client.gets
      end
    end
    clients.each(&:close)
    thread.join(5)
    server.close
  end
end

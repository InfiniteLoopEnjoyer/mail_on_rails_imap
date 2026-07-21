# frozen_string_literal: true

module MailOnRails
  module Imap
    # Minimal Fiber::Scheduler (pure Ruby, IO.select-based) that lets one
    # worker thread serve many IMAP sessions concurrently: each session runs
    # in a fiber, and any blocking IO (socket reads, TLS handshakes, DNS,
    # store HTTP calls), sleep, or Queue wait parks the fiber instead of the
    # thread. One scheduler per worker; nothing here is shared across
    # workers, so Ractor isolation holds.
    #
    # Implements the required hooks (fiber, io_wait, kernel_sleep, block,
    # unblock, fiber_interrupt, close) plus timeout_after. unblock is the
    # only cross-thread entry point - it is how another thread's Queue#push
    # wakes a fiber parked in Queue#pop - so it only touches the
    # mutex-guarded ready list and the wake pipe.
    #
    # IO#timeout note: Ruby does not pass an io's own timeout into io_wait
    # (it arrives as nil), so a scheduler that ignores it would silently
    # disable the sessions' idle timeout. io_wait therefore honors
    # io.timeout itself, raising IO::TimeoutError into the waiting fiber -
    # the same error the non-scheduler IO path raises.
    #
    # Usage (see Worker): set as the scheduler on a fresh thread, start the
    # root fiber with Fiber.schedule, and let the thread fall off the end -
    # Ruby then calls #close, which runs the event loop until no fiber is
    # waiting on anything.
    class Scheduler
      # One armed timer. action :wake resumes the fiber with :timeout (the
      # io_wait/block "timed out" signal); an exception class action is
      # raised into the fiber (io.timeout idle limit, timeout_after).
      Timer = Struct.new(:deadline, :fiber, :action, :message)

      def initialize
        @readable = {} # IO => [Fiber]
        @writable = {} # IO => [Fiber]
        @timers = []   # armed Timer records, unordered (small N)
        @blocked = {}  # Fiber => true, parked via #block until #unblock
        @ready = []    # fibers released by cross-thread #unblock
        @lock = Mutex.new
        @wake_r, @wake_w = IO.pipe
      end

      # -- hooks called by Ruby from inside running fibers -------------------

      def fiber(&block)
        f = Fiber.new(blocking: false, &block)
        f.resume # per the scheduler contract: run until the first block
        f
      end

      def io_wait(io, events, timeout)
        fiber = Fiber.current
        @readable[io] = (@readable[io] || []) << fiber if (events & IO::READABLE).nonzero?
        @writable[io] = (@writable[io] || []) << fiber if (events & IO::WRITABLE).nonzero?
        timer =
          if timeout
            arm_timer(timeout, fiber, :wake)
          elsif (idle_limit = io_deadline(io))
            arm_timer(idle_limit, fiber, IO::TimeoutError, "idle timeout on #{io.inspect}")
          end

        result = Fiber.yield
        result == :timeout ? false : events
      ensure
        disarm(fiber, timer)
      end

      def kernel_sleep(duration = nil)
        fiber = Fiber.current
        timer = duration ? arm_timer(duration, fiber, :wake) : nil
        @blocked[fiber] = true unless timer # sleep forever: only #unblock ends it
        Fiber.yield
      ensure
        disarm(fiber, timer)
      end

      # Called by Queue/Mutex/ConditionVariable when a fiber would block.
      # Returns true if unblocked, false on timeout.
      def block(_blocker, timeout = nil)
        fiber = Fiber.current
        @blocked[fiber] = true
        timer = timeout ? arm_timer(timeout, fiber, :wake) : nil
        Fiber.yield != :timeout
      ensure
        disarm(fiber, timer)
      end

      # The one hook that may run on a foreign thread (e.g. Queue#push from
      # an accept thread waking this worker's dispatcher fiber).
      def unblock(_blocker, fiber)
        @lock.synchronize { @ready << fiber }
        begin
          @wake_w.write_nonblock(".")
        rescue IO::WaitWritable, IOError
          nil # pipe full means a wake-up is already pending; closed means shutting down
        end
      end

      # Buffered IO (IO#gets and friends) goes through these on 4.0. They are
      # nominally optional, but Ruby's fallback emulation cannot cope with a
      # socket that was moved in from another Ractor (it trips over
      # Ractor::MovedObject internals), so a worker serving moved sockets
      # needs the real hooks. length is the minimum to read/write; 0 means
      # one non-blocking attempt.
      # Implemented with read_nonblock/write_nonblock plus buffer copies
      # rather than IO::Buffer#read/#write: on 4.0.6 the IO::Buffer syscall
      # path keeps returning EAGAIN inside a non-main Ractor even when
      # select reports the fd readable. Fiber.blocking stops the non-blocking
      # calls from re-entering these hooks; the fd itself stays non-blocking,
      # so the thread can't stall.
      def io_read(io, buffer, length, offset)
        total = 0
        loop do
          result = Fiber.blocking { io.read_nonblock(buffer.size - offset, exception: false) }
          case result
          when :wait_readable
            return -Errno::EAGAIN::Errno if length.zero?

            io_wait(io, IO::READABLE, nil)
          when nil # EOF
            break
          else
            buffer.set_string(result, offset)
            total += result.bytesize
            offset += result.bytesize
            break if total >= length
          end
        end
        total
      rescue SystemCallError => e
        -e.errno
      end

      def io_write(io, buffer, length, offset)
        total = 0
        loop do
          chunk = buffer.get_string(offset, buffer.size - offset)
          result = Fiber.blocking { io.write_nonblock(chunk, exception: false) }
          if result == :wait_writable
            return -Errno::EAGAIN::Errno if length.zero?

            io_wait(io, IO::WRITABLE, nil)
          else
            total += result
            offset += result
            break if total >= length
          end
        end
        total
      rescue SystemCallError => e
        -e.errno
      end

      # Used by Timeout.timeout under a scheduler. The timer is our own
      # record, so nested io waits disarming their timers can't cancel it.
      def timeout_after(duration, exception_class, message)
        fiber = Fiber.current
        timer = arm_timer(duration, fiber, exception_class, message)
        yield duration
      ensure
        @timers.delete(timer)
      end

      # Ruby interrupts a parked fiber through this (Thread#raise/#kill,
      # IO#close racing a reader).
      def fiber_interrupt(fiber, exception)
        fiber.raise(exception) if fiber.alive?
      end

      def close
        run
        @wake_r.close
        @wake_w.close
      end

      private

      def run
        run_once while working?
      end

      def working?
        [ @readable, @writable, @timers, @blocked ].any? { |c| !c.empty? } ||
          @lock.synchronize { !@ready.empty? }
      end

      def run_once
        readers, writers, interval = select_args
        ready_r, ready_w = IO.select(readers, writers, nil, interval)
        drain_wake_pipe if ready_r&.delete(@wake_r)

        wake = @lock.synchronize { @ready.dup.tap { @ready.clear } }
        Array(ready_r).each { |io| wake.concat(@readable[io] || []) }
        Array(ready_w).each { |io| wake.concat(@writable[io] || []) }
        # The waiting? guard drops stale entries (a cross-thread unblock may
        # name a fiber that already moved on); a resume it lets through is at
        # worst a spurious wakeup, which the IO/Queue layers tolerate.
        wake.uniq.each { |f| f.resume(nil) if f.alive? && waiting?(f) }
        fire_timers
      end

      def select_args
        interval = nil
        unless @timers.empty?
          interval = @timers.map(&:deadline).min - now
          interval = 0 if interval.negative?
        end
        [ @readable.keys + [ @wake_r ], @writable.keys, interval ]
      end

      # Due :wake timers resume their fiber with :timeout; due exception
      # timers raise into it. A fiber the wake pass already resumed has
      # disarmed its timers, so it can't be fired twice in one tick.
      def fire_timers
        cutoff = now
        due, @timers = @timers.partition { |t| t.deadline <= cutoff }
        due.each do |t|
          next unless t.fiber.alive?

          t.action == :wake ? t.fiber.resume(:timeout) : t.fiber.raise(t.action, t.message)
        end
      end

      def arm_timer(duration, fiber, action, message = nil)
        Timer.new(now + duration, fiber, action, message).tap { |t| @timers << t }
      end

      # An io's own timeout (IO#timeout) - Session's idle limit.
      def io_deadline(io)
        limit = io.timeout if io.respond_to?(:timeout)
        limit if limit&.positive?
      rescue IOError
        nil
      end

      def waiting?(fiber)
        @blocked.key?(fiber) ||
          @timers.any? { |t| t.fiber == fiber } ||
          @readable.any? { |_, fs| fs.include?(fiber) } ||
          @writable.any? { |_, fs| fs.include?(fiber) }
      end

      def disarm(fiber, timer)
        @timers.delete(timer) if timer
        @blocked.delete(fiber)
        [ @readable, @writable ].each do |set|
          set.each_value { |fs| fs.delete(fiber) }
          set.delete_if { |_, fs| fs.empty? }
        end
      end

      def drain_wake_pipe
        @wake_r.read_nonblock(4096)
      rescue IO::WaitReadable, IOError
        nil
      end

      def now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end

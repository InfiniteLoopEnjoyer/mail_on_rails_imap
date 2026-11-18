# frozen_string_literal: true

module MailOnRails
  module Imap
    # Absolute deadlines for sessions, enforced from outside them.
    #
    # A session can only notice time passing between reads, and a read can
    # be kept busy indefinitely: the socket timeout is an inactivity bound
    # that any byte resets. So a deadline that must hold whatever the peer
    # sends - "authenticate within two minutes of connecting" - is kept
    # here: one thread for the whole process wakes when the next deadline
    # is due and runs that session's expiry block (which closes its
    # socket, raising in the session thread's blocked read).
    #
    # The thread exists only while something is armed.
    class DeadlineWatch
      # Longest sleep between checks; an earlier deadline shortens it.
      TICK = 1.0

      def initialize
        @mutex = Mutex.new
        @deadlines = {}.compare_by_identity
        @thread = nil
      end

      # At monotonic time +at+, call the block once (on the watch thread).
      # One deadline per +key+: arming again replaces it.
      def arm(key, at, &expire)
        @mutex.synchronize do
          @deadlines[key] = [ at, expire ]
          @thread = Thread.new { run } unless @thread&.alive?
        end
      end

      def disarm(key)
        @mutex.synchronize { @deadlines.delete(key) }
      end

      private

      def run
        loop do
          due, pause = @mutex.synchronize do
            now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            due = @deadlines.select { |_key, (at, _expire)| at <= now }
            due.each_key { |key| @deadlines.delete(key) }
            if @deadlines.empty?
              # Decided under the lock, so an arm racing this exit sees a
              # dead thread and starts the next one.
              @thread = nil if due.empty?
              [ due.values, nil ]
            else
              soonest = @deadlines.each_value.map(&:first).min
              [ due.values, (soonest - now).clamp(0.01, TICK) ]
            end
          end
          due.each { |_at, expire| run_expiry(expire) }
          break if pause.nil? && due.empty?

          sleep(pause || 0.01)
        end
      end

      # One session's failing expiry must not end the watch for the rest.
      def run_expiry(expire)
        expire.call
      rescue StandardError
        nil
      end
    end
  end
end

# frozen_string_literal: true

module MailOnRails
  module Imap
    # Caps the number of simultaneously open connections a server will handle,
    # bounding thread and file-descriptor use under a connection flood. Shared
    # by a single server's connection threads; a plain Mutex-guarded counter
    # is sufficient.
    class ConnLimiter
      def initialize(max)
        @max = max
        @count = 0
        @mutex = Mutex.new
      end

      # Tries to reserve a slot. Returns true if acquired, false if at capacity.
      def acquire
        @mutex.synchronize do
          return false if @count >= @max

          @count += 1
          true
        end
      end

      def release
        @mutex.synchronize { @count -= 1 if @count.positive? }
      end
    end
  end
end

# frozen_string_literal: true

require "socket"
require_relative "scheduler"
require_relative "tls"

module MailOnRails
  module Imap
    # Serves many IMAP sessions on one thread: a dispatcher fiber takes
    # incoming connections and starts a session fiber per connection, all
    # multiplexed by Scheduler. Implicit-TLS handshakes happen here too, so
    # the accept loop never blocks on a slow handshake.
    #
    # Two intake modes, one Worker:
    #
    #   Ractor mode (Worker.spawn_ractor): one Worker per core, each inside
    #   its own Ractor for true parallelism. Sockets cross the boundary as
    #   raw fd numbers over a control pipe ("<fd> <spec index>\n" lines) and
    #   are re-wrapped with TCPSocket.for_fd - fds are process-global, and
    #   integers avoid Ractor IO moves entirely (moved IOs misbehave under a
    #   fiber scheduler on Ruby 4.0.6; see scheduler.rb). The worker builds
    #   its own store and TLS context inside the Ractor - neither can be
    #   shared across the boundary - and reports each finished session by
    #   writing a byte to the shared release pipe, which the accept side
    #   turns into ConnLimiter releases.
    #
    #   Thread mode (Worker#serve_queue): same serving core on a plain
    #   thread, fed [socket, spec] pairs through a Thread::Queue and sharing
    #   the caller's store/limiter directly. Used when a store instance is
    #   injected (tests, embedded development) - an in-process store can't
    #   be rebuilt inside a Ractor.
    class Worker
      def initialize(store:, session_class:, tls: nil, on_done: nil)
        @store = store
        @session_class = session_class
        @tls = tls
        @on_done = on_done
      end

      # Thread mode entry point. Runs until the queue is closed.
      def serve_queue(queue)
        serve { queue.pop }
      end

      # Ractor mode entry point. Runs until the control pipe's write end
      # closes. specs must be indexable by the dispatched spec index.
      def serve_pipe(control_r, specs)
        serve do
          line = control_r.gets
          if line
            fd, index = line.split.map { |v| Integer(v) }
            [ TCPSocket.for_fd(fd), specs.fetch(index) ]
          end
        end
      end

      # Spawns a Ractor-mode worker and returns [ractor, control_write_io].
      # All arguments must be shareable: session_class is a Class,
      # specs/tls_material/store_config are deep-frozen data,
      # release_fd/ready_port are an Integer and a Port.
      def self.spawn_ractor(session_class:, specs:, tls_material:, store_config:, release_fd:, ready_port:)
        ractor = Ractor.new(session_class, specs, tls_material, store_config,
                            release_fd, ready_port) do |session_class, specs, tls_material, store_config, release_fd, ready_port|
          # $stdout is ractor-local: it arrives here as a fresh unsynced
          # wrapper of fd 1 (bin/server's boot-time sync doesn't carry
          # over, and STDOUT isn't accessible off the main Ractor), so an
          # unsynced pipe would buffer session log lines for hours.
          $stdout.sync = true
          control_r, control_w = IO.pipe
          ready_port.send(control_w.fileno)

          release = IO.for_fd(release_fd)
          release.autoclose = false # the accept side owns this fd
          release.sync = true

          store = store_config.fetch(:store_class).from_config(store_config[:config] || {})
          tls = tls_material && TLS::ContextProvider.new(tls_material)
          # Explicit constant: self inside a Ractor block is the Ractor.
          Worker.new(store: store, session_class: session_class, tls: tls,
                     on_done: -> { release.write("d") }).serve_pipe(control_r, specs)
          :worker_exit
        end
        [ ractor, IO.for_fd(ready_port.receive) ]
      end

      private

      # The serving core: dispatcher fiber pulls connections from the
      # supplier (which parks the fiber, not the thread, when idle) until it
      # returns nil. Falling off the end lets Ruby run Scheduler#close,
      # which keeps the event loop alive until every session finishes.
      def serve(&supplier)
        Fiber.set_scheduler(Scheduler.new)
        Fiber.schedule do
          loop do
            socket, spec = supplier.call
            break unless socket

            Fiber.schedule { handle(socket, spec) }
          end
        end
      end

      def handle(socket, spec)
        ctx = @tls&.context
        socket = TLS.accept(socket, ctx) if spec[:tls] == :implicit && ctx
        @session_class.new(socket, @store, spec, ctx).run
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
        nil # session logs its own protocol-level errors; this is connection debris
      ensure
        begin
          socket.close
        rescue StandardError
          nil
        end
        @on_done&.call
      end
    end
  end
end

# frozen_string_literal: true

require "socket"
require "etc"
require_relative "conn_limiter"
require_relative "denylist"
require_relative "tls"
require_relative "worker"

module MailOnRails
  module Imap
    # Shared listener scaffolding for the SMTP and IMAP servers: one accept
    # thread per listener spec, a pool of session workers, a connection cap,
    # and TLS material handling. Keeping this in one place means the
    # connection-flood and TLS-accept behavior can't drift apart between the
    # two protocols.
    #
    # Sessions do not run on the accept threads. Each accepted socket is
    # handed to a Worker (fiber-scheduled sessions, see worker.rb):
    #
    #   - Ractor mode: one worker Ractor per core, sockets dispatched as fd
    #     numbers over per-worker control pipes, round-robin. Requires a
    #     store that can be rebuilt inside each Ractor, i.e. one that
    #     implements #worker_config (Store::Http does). Session completions
    #     come back as bytes on a shared release pipe and free ConnLimiter
    #     slots.
    #   - Thread mode: worker threads popping one shared queue. Used when
    #     the store is an injected in-process instance (tests, embedded
    #     development) or when MAIL_ON_RAILS_IMAP_WORKER_MODE=thread.
    #
    # The ConnLimiter always lives on the accept side, so the cap stays
    # exact process-wide in both modes.
    #
    # Subclasses define MAX_CONNECTIONS and the protocol specifics:
    # protocol_name, busy_line (sent when the connection cap is hit),
    # listener_label(spec) and session_class.
    class Server
      # Reap dead peers at the TCP layer (Postal's timings): first probe
      # after 50s idle, then every 10s, gone after 5 unanswered probes -
      # ~100s to reclaim a half-open connection's ConnLimiter slot instead
      # of waiting out the sessions' 1800s idle timeout, which matters even
      # more for IMAP's long-lived connections than it does for SMTP.
      KEEPALIVE_IDLE = 50
      KEEPALIVE_INTERVAL = 10
      KEEPALIVE_PROBES = 5

      def self.run(store, listeners, tls_material, workers: nil)
        new(store, listeners, tls_material, workers: workers).run
      end

      def initialize(store, listeners, tls_material, workers: nil)
        @store = store
        @listeners = listeners
        @tls_material = tls_material
        @limiter = ConnLimiter.new(self.class::MAX_CONNECTIONS)
        @denylist = Denylist.new(ENV["MAIL_ON_RAILS_IMAP_DENYLIST_FILE"])
        @worker_count = [ workers || Integer(ENV.fetch("MAIL_ON_RAILS_IMAP_WORKERS") { Etc.nprocessors }), 1 ].max
        @dispatchers = []
        @round_robin = 0
        @mutex = Mutex.new
      end

      def run
        # Build a context now even in Ractor mode: TLS problems should
        # surface at boot, not on the first connection of each worker.
        tls = @tls_material && TLS::ContextProvider.new(@tls_material)
        mode = worker_mode
        session_specs = build_session_specs
        @dispatchers = mode == :ractor ? spawn_ractor_workers(session_specs) : spawn_thread_workers(tls)

        threads = @listeners.each_with_index.map do |spec, index|
          next if spec[:tls] == :implicit && tls.nil?

          Thread.new(spec, index) { |listener, i| accept_loop(listener, session_specs[i], i) }
        end.compact
        @store.log(:info, "#{protocol_name} listening: #{@listeners.map { |s| listener_label(s) }.join(", ")} " \
                          "(#{@worker_count} #{mode} workers)")
        threads.each(&:join)
      end

      private

      # Ractor mode needs per-Ractor store construction; a store advertises
      # that with #worker_config. Injected instances (Store::Memory, custom
      # embedded stores) fall back to threads, as does an explicit
      # MAIL_ON_RAILS_IMAP_WORKER_MODE=thread override.
      def worker_mode
        return :thread if ENV["MAIL_ON_RAILS_IMAP_WORKER_MODE"] == "thread"

        @store.respond_to?(:worker_config) ? :ractor : :thread
      end

      # The subset of each listener spec a session needs, deep-frozen so it
      # can cross into worker Ractors.
      def build_session_specs
        @listeners.map do |spec|
          Ractor.make_shareable(spec.slice(:host, :port, :tls))
        end
      end

      def spawn_ractor_workers(session_specs)
        release_r, @release_w = IO.pipe
        Thread.new { release_loop(release_r) }
        ready_port = Ractor::Port.new
        store_config = Ractor.make_shareable(@store.worker_config)
        material = @tls_material && Ractor.make_shareable(@tls_material.dup)

        Array.new(@worker_count) do
          _ractor, control_w = Worker.spawn_ractor(
            session_class: session_class, specs: session_specs, tls_material: material,
            store_config: store_config, release_fd: @release_w.fileno, ready_port: ready_port
          )
          control_w.sync = true
          control_w
        end
      end

      def spawn_thread_workers(tls)
        queue = Thread::Queue.new
        @worker_count.times do
          worker = Worker.new(store: @store, session_class: session_class, tls: tls,
                              on_done: -> { @limiter.release })
          Thread.new { worker.serve_queue(queue) }
        end
        [ queue ]
      end

      # Every byte a worker writes is one finished session.
      def release_loop(release_r)
        while (batch = release_r.readpartial(4096))
          batch.bytesize.times { @limiter.release }
        end
      rescue EOFError, IOError
        nil
      end

      def accept_loop(spec, session_spec, spec_index)
        server = spec[:tcp_server] || TCPServer.new(spec[:host], spec[:port])
        loop do
          socket = server.accept
          # Admin-banned addresses (the Rails app's BannedIp) get a bare
          # close before any greeting or limiter slot - a banned scanner
          # earns silence, not a banner. No release needed: nothing was
          # acquired.
          if @denylist.banned?(peer_ip(socket))
            close_quietly(socket)
            next
          end
          tune_keepalive(socket)
          if @limiter.acquire
            dispatch(socket, session_spec, spec_index)
          else
            reject_busy(socket)
          end
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}")
      end

      def dispatch(socket, session_spec, spec_index)
        target = @mutex.synchronize do
          @round_robin += 1
          @dispatchers[@round_robin % @dispatchers.size]
        end
        if target.is_a?(Thread::Queue)
          target.push([ socket, session_spec ])
        else
          # The worker Ractor owns the fd from here; keep our IO object from
          # closing it behind the worker's back when GC collects it.
          socket.autoclose = false
          target.write("#{socket.fileno} #{spec_index}\n")
        end
      rescue StandardError
        @limiter.release
        begin
          socket.close
        rescue StandardError
          nil
        end
      end

      # TCP_KEEP* constants are platform-dependent (macOS has no
      # TCP_KEEPIDLE); missing ones just mean kernel-default timings.
      def tune_keepalive(socket)
        socket.setsockopt(:SOCKET, :KEEPALIVE, true)
        socket.setsockopt(:TCP, :KEEPIDLE, KEEPALIVE_IDLE) if Socket.const_defined?(:TCP_KEEPIDLE)
        socket.setsockopt(:TCP, :KEEPINTVL, KEEPALIVE_INTERVAL) if Socket.const_defined?(:TCP_KEEPINTVL)
        socket.setsockopt(:TCP, :KEEPCNT, KEEPALIVE_PROBES) if Socket.const_defined?(:TCP_KEEPCNT)
      rescue SystemCallError
        nil
      end

      def reject_busy(socket)
        socket.write("#{busy_line}\r\n")
        socket.close
      rescue StandardError
        nil
      end

      # nil rather than "?" on failure so an address we couldn't read can
      # never match a denylist entry (same care as Session#throttle_ip).
      def peer_ip(socket)
        socket.remote_address.ip_address
      rescue StandardError
        nil
      end

      def close_quietly(socket)
        socket.close
      rescue StandardError
        nil
      end
    end
  end
end

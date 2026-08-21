# frozen_string_literal: true

require "socket"
require "timeout"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

module MailOnRails
  module Fuzz
    # Stateful IMAP fuzz harness with pre-auth and post-auth grammars, literal
    # mutations, and account-isolation oracles.
    class Imap < Runner
      ALICE = "fuzz-alice@example.test"
      BOB = "fuzz-bob@example.test"
      PASSWORD = "pw-fuzz-123456"
      ALICE_RAW = "From: s@remote.test\r\nSubject: alice-secret\r\n\r\nalice body\r\n"
      BOB_RAW = "From: s@remote.test\r\nSubject: bob-secret\r\n\r\nbob body\r\n"
      PROFILES = %i[garbage_preauth garbage_postauth stateful_commands literal_flood
                    auth_garbage cross_account_probe].freeze
      # Profiles whose grammar is adversarial by construction: a dropped
      # connection is always a legitimate server response for these.
      GARBAGE_PROFILES = %i[garbage_preauth garbage_postauth auth_garbage literal_flood].freeze

      def initialize(**kwargs)
        super
      end

      def run_round(index)
        @store = fresh_store
        @responses = +""
        @state = fresh_state
        @profile = pick(PROFILES)
        mutator.reset!
        run_profile(@profile)
        check_oracles(index)
      rescue StandardError => e
        if tolerable_io_error?(e)
          check_oracles(index)
        else
          fail(index, @profile || :unknown, "uncaught client error: #{e.class}: #{e.message}")
        end
      end

      # Structured profiles tolerate IO errors only when a mutation actually
      # fired this round; the server may legitimately drop the connection on
      # a mutated line. Clean rounds keep the strict check, and the oracles
      # run either way.
      def tolerable_io_error?(error)
        return false unless GARBAGE_PROFILES.include?(@profile) || mutator.mutated?

        error.is_a?(IOError) || error.is_a?(SystemCallError) || error.is_a?(Timeout::Error)
      end

      private

      def fresh_store
        store = MailOnRails::Imap::Store::Memory.new
        alice_id = store.add_account(email: ALICE, password: PASSWORD)
        bob_id = store.add_account(email: BOB, password: PASSWORD)
        store.append(alice_id, "INBOX", ALICE_RAW, [], nil)
        store.create_mailbox(bob_id, "Bob-Private")
        store.append(bob_id, "Bob-Private", BOB_RAW, [], nil)
        store
      end

      def fresh_state
        { authenticated: false, identity: nil, selected: false, cross_probe: false }
      end

      def run_profile(profile)
        case profile
        when :garbage_preauth then run_garbage(authenticate: false)
        when :garbage_postauth then run_garbage(authenticate: true)
        when :stateful_commands then run_stateful_commands
        when :literal_flood then run_literal_flood
        when :auth_garbage then run_auth_garbage
        when :cross_account_probe then run_cross_account_probe
        end
      end

      def with_client(tls: :implicit, &block)
        server = TCPServer.new("127.0.0.1", 0)
        client = TCPSocket.new("127.0.0.1", server.addr[1])
        client.timeout = config.timeout
        accepted = server.accept
        thread = Thread.new do
          MailOnRails::ImapServer::Session.new(accepted, @store, { tls: tls }, nil).run
        end
        block.call(client)
      ensure
        close_client(client)
        accepted&.close rescue nil
        thread&.join(config.timeout)
        thread&.kill if thread&.alive?
        server&.close
      end

      def close_client(client)
        return unless client

        client.shutdown(Socket::SHUT_RDWR) rescue nil
        client.close rescue nil
      end

      def read_until_tagged(client, tag)
        lines = []
        Timeout.timeout(config.timeout) do
          while (line = client.gets("\r\n"))
            lines << line
            @responses << line
            break if line.start_with?("#{tag} ")
          end
        end
        lines.join
      rescue Timeout::Error
        raise IOError, "timed out waiting for IMAP tagged response"
      end

      def command(client, tag, line)
        client.write("#{tag} #{line}\r\n")
        read_until_tagged(client, tag)
      end

      def login(client, email)
        reply = command(client, mutator.tag, "LOGIN #{email} #{PASSWORD}")
        if reply.include?(" OK ")
          @state[:authenticated] = true
          @state[:identity] = email
        end
        reply
      end

      def run_garbage(authenticate:)
        with_client do |client|
          client.gets("\r\n")
          login(client, ALICE) if authenticate
          @rng.rand(1..8).times do
            tag = mutator.tag
            line = mutator.garbage_line(verbs: Mutator::IMAP_VERBS)
            client.write("#{tag} #{line}\r\n")
            read_until_tagged(client, tag) rescue nil
          end
          command(client, mutator.tag, "LOGOUT") rescue nil
        end
      end

      def run_stateful_commands
        with_client do |client|
          client.gets("\r\n")
          login(client, ALICE)
          verbs = [
            ->(t) { command(client, t, "SELECT #{mutator.maybe('INBOX')}") },
            ->(t) { command(client, t, "FETCH 1:* (FLAGS BODY[HEADER.FIELDS (SUBJECT)])") },
            ->(t) { command(client, t, "SEARCH TEXT #{mutator.maybe('alice')}") },
            ->(t) { command(client, t, "UID STORE 1:* +FLAGS (\\Deleted)") },
            ->(t) { command(client, t, "LIST \"\" \"*\"") }
          ]
          @rng.rand(2..5).times do
            verbs.sample(random: @rng).call(mutator.tag)
          end
          @state[:selected] = @responses.include?("SELECT completed")
          command(client, mutator.tag, "LOGOUT") rescue nil
        end
      end

      def run_literal_flood
        with_client do |client|
          client.gets("\r\n")
          login(client, ALICE)
          tag = mutator.tag
          size = pick([ 64, 128, 256, 1024, 4096, 8192 ])
          payload = mutator.malicious_body
          payload = payload.byteslice(0, size) if payload.bytesize > size
          if @rng.rand < 0.5
            client.write("#{tag} APPEND INBOX {#{size}}\r\n")
            client.write(payload.ljust(size, "X")[0, size])
            client.write("\r\n")
          else
            client.write("#{tag} APPEND INBOX {#{size}+}\r\n#{payload.ljust(size, 'X')[0, size]}\r\n")
          end
          read_until_tagged(client, tag) rescue nil
          command(client, mutator.tag, "LOGOUT") rescue nil
        end
      end

      def run_auth_garbage
        with_client(tls: :implicit) do |client|
          client.gets("\r\n")
          @rng.rand(1..5).times do
            tag = mutator.tag
            initial = if @rng.rand < 0.5
              mutator.garbage_line
            else
              [ "\0#{ALICE}\0#{mutator.maybe(PASSWORD)}" ].pack("m0")
            end
            reply = command(client, tag, "AUTHENTICATE PLAIN #{initial}") rescue nil
            break if reply&.include?(" BYE ")
          end
          command(client, mutator.tag, "LOGOUT") rescue nil
        end
      end

      def run_cross_account_probe
        @state[:cross_probe] = true
        with_client do |client|
          client.gets("\r\n")
          login(client, ALICE)
          [
            "SELECT Bob-Private",
            "STATUS Bob-Private (MESSAGES)",
            "LIST \"\" \"*\"",
            "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])",
            "SEARCH TEXT bob-secret"
          ].each do |line|
            command(client, mutator.tag, line) rescue nil
          end
          command(client, mutator.tag, "LOGOUT") rescue nil
        end
      end

      def check_oracles(round)
        if @responses.match?(/\* BYE /) && @responses.include?("session error")
          fail(round, @profile, "session crashed")
        end

        @responses.each_line do |line|
          next unless line.match?(/\A(?:\* |\w+ (?:OK|NO|BAD))/)

          if line.start_with?("*") || line.match?(/\A\w+ (?:OK|NO|BAD)/)
            next if line.match?(/\A\w+ (?:OK|NO|BAD)/)
            next if line.start_with?("* OK", "* BYE", "* CAPABILITY", "* LIST", "* FLAGS",
                                     "* SEARCH", "* STATUS", "* EXISTS", "* RECENT",
                                     "* FETCH", "* BYE")

            # tagged lines and untagged continuations must look like IMAP
          end
        end

        tagged_lines = @responses.each_line.select { |l| l.match?(/\A\w+ (?:OK|NO|BAD|BYE)/) }
        tagged_lines.each do |line|
          fail(round, @profile, "malformed tagged response", line.strip) unless line.match?(/\A\w+ (?:OK|NO|BAD)/)
        end

        unless @state[:authenticated]
          fail(round, @profile, "pre-auth SELECT succeeded") if @responses.match?(/\A\w+ OK.*SELECT completed/)
          fail(round, @profile, "pre-auth APPEND succeeded") if @responses.match?(/\A\w+ OK.*APPEND completed/)
        end

        if @state[:cross_probe]
          fail(round, @profile, "leaked bob-secret in response") if @responses.include?("bob-secret")
          fail(round, @profile, "listed Bob-Private mailbox") if @responses.include?("Bob-Private")
        end

        if @profile == :garbage_preauth && @state[:authenticated]
          fail(round, @profile, "garbage pre-auth established a session")
        end
      end
    end
  end
end

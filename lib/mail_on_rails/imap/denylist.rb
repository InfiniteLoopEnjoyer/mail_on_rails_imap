# frozen_string_literal: true

require "ipaddr"

module MailOnRails
  module Imap
    # The Rails-managed banned_ips file (one IP or CIDR per line, written
    # atomically on the shared mailconf volume - the same file exim's
    # connect ACL reads). Checked on the accept path for every connection;
    # the file is stat'd at most once per TTL seconds and re-parsed only
    # when its mtime changes, so a ban lands within seconds of the Rails
    # app writing the file, without a stat per connection under load.
    #
    # Fail-soft everywhere, like TLS::ContextProvider: unset path means
    # the feature is off (dev default), a missing file means "no bans", a
    # garbled line is skipped, an unparseable peer address never matches.
    class Denylist
      TTL = 5 # seconds between stat calls

      def initialize(path, ttl: TTL)
        @path = path.to_s.empty? ? nil : path
        @ttl = ttl
        @mutex = Mutex.new
        @networks = []
        @mtime = nil
        @checked_at = nil
      end

      def banned?(ip)
        return false if @path.nil? || ip.nil?

        addr = begin
          IPAddr.new(ip)
        rescue IPAddr::Error
          return false
        end
        current_networks.any? { |net| net.ipv4? == addr.ipv4? && net.include?(addr) }
      end

      private

      def current_networks
        @mutex.synchronize do
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          if @checked_at.nil? || now - @checked_at >= @ttl
            @checked_at = now
            mtime = begin
              File.stat(@path).mtime
            rescue SystemCallError
              nil # missing/unreadable = no bans (exim is the fail-closed layer)
            end
            if mtime != @mtime
              @networks = mtime.nil? ? [] : load_networks
              @mtime = mtime
            end
          end
          @networks
        end
      end

      def load_networks
        File.readlines(@path, chomp: true).filter_map do |line|
          entry = line.strip
          next if entry.empty? || entry.start_with?("#")

          begin
            IPAddr.new(entry)
          rescue IPAddr::Error
            nil
          end
        end
      rescue SystemCallError, IOError
        []
      end
    end
  end
end

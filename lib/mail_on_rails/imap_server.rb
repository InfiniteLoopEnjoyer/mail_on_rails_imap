# frozen_string_literal: true

require "strscan"
require "time"
require "mail_on_rails/imap/server"
require "mail_on_rails/imap/session_helpers"
require "mail_on_rails/imap/utf7"
require "mail_on_rails/imap/version"
require_relative "mime"

module MailOnRails
  # IMAP4rev1 server (RFC 3501 subset), run on a thread by Imap::Daemon -
  # standalone in this repo's container via bin/server, or embedded in a
  # host process in development. Covers what real clients - iOS Mail in
  # particular - need: LOGIN/AUTHENTICATE, LIST/LSUB (with SPECIAL-USE and
  # CHILDREN attributes), SELECT/EXAMINE, STATUS, (UID) FETCH with section
  # fetches, (UID) STORE, (UID) SEARCH, (UID) COPY, (UID) MOVE, APPEND,
  # (UID) EXPUNGE, CLOSE, UNSELECT, NOOP, IDLE, CREATE/DELETE/RENAME,
  # NAMESPACE, ID; mailbox names use modified UTF-7 on the wire (Imap::Utf7).
  # Listens on a plaintext+STARTTLS port and an
  # implicit-TLS port; credentials are refused until the channel is
  # encrypted (LOGINDISABLED advertised in the clear).
  class ImapServer < Imap::Server
    # Base capabilities; STARTTLS/LOGINDISABLED/AUTH are appended per-state.
    BASE_CAPABILITIES = "IMAP4rev1 UIDPLUS LITERAL+ IDLE MOVE UNSELECT NAMESPACE SPECIAL-USE CHILDREN ESEARCH WITHIN CONDSTORE ID"
    FLAGS = "\\Answered \\Flagged \\Deleted \\Seen \\Draft"
    MAX_LITERAL_BYTES = 30 * 1024 * 1024
    # How often an idling session re-checks the store for changes. The
    # store is the source of truth and other writers (delivery through the
    # Rails app, other sessions, possibly other daemon processes) don't
    # share this process, so polling it is the only complete update source.
    IDLE_POLL_SECONDS = Integer(ENV.fetch("MAIL_ON_RAILS_IMAP_IDLE_POLL", 30))
    # Cap on a single (non-literal) command line, so a client can't exhaust
    # memory by sending endless bytes with no CRLF. Bulk data uses {n} IMAP
    # literals, which are bounded separately by MAX_LITERAL_BYTES.
    MAX_LINE = Integer(ENV.fetch("MAIL_ON_RAILS_IMAP_MAX_LINE", 65_536))
    MAX_CONNECTIONS = Integer(ENV.fetch("MAIL_ON_RAILS_IMAP_MAX_CONN", 100))
    MAX_AUTH_ATTEMPTS = 3

    private

    def protocol_name = "IMAP"

    def busy_line = "* BYE Too many connections"

    def listener_label(spec) = "#{spec[:port]}/#{spec[:tls]}"

    def session_class = Session

    # Splits a command line (with literals already inlined as separate
    # elements) into tokens: strings, :lparen and :rparen.
    class Lexer
      attr_reader :tokens

      def initialize(parts)
        @tokens = []
        parts.each do |part|
          if part.is_a?(Array) # [:lit, data]
            @tokens << part[1]
          else
            tokenize(part.chomp("\r\n").sub(/\{\d+\+?\}\z/, ""))
          end
        end
      end

      private

      def tokenize(str)
        s = StringScanner.new(str)
        until s.eos?
          if s.scan(/\s+/)
            next
          elsif s.scan(/\(/)
            @tokens << :lparen
          elsif s.scan(/\)/)
            @tokens << :rparen
          elsif (quoted = s.scan(/"(?:\\.|[^"\\])*"/))
            @tokens << quoted[1..-2].gsub(/\\(.)/, '\1')
          elsif (atom = s.scan(/[^\s()"]+/))
            atom = +atom
            # Bracketed fetch sections may contain spaces and parens:
            # BODY.PEEK[HEADER.FIELDS (DATE SUBJECT)]<0.2048>
            atom << s.scan(/[^\]]*\]/).to_s while atom.count("[") > atom.count("]") && s.check(/[^\]]*\]/)
            atom << s.scan(/<\d+(?:\.\d+)?>/).to_s
            @tokens << atom
          else
            s.getch
          end
        end
      end
    end

    class Session
      include Imap::SessionHelpers

      def initialize(socket, store, spec, tls_ctx)
        @socket = socket
        @store = store
        @spec = spec
        @tls_ctx = tls_ctx
        @tls = spec[:tls] == :implicit
        @account_id = nil
        @auth_attempts = 0
        @selected = nil
        @uids = []
        @flags = {}
        @modseqs = {}
        @highest_modseq = 1
        # Once a client uses any CONDSTORE-enabling construct (SELECT
        # (CONDSTORE), FETCH MODSEQ/CHANGEDSINCE, STORE UNCHANGEDSINCE,
        # SEARCH MODSEQ), MODSEQ rides along in FETCH responses (RFC 7162).
        @condstore = false
        @read_only = false
        @logout = false
      end

      # Capabilities depend on connection state: advertise STARTTLS and
      # LOGINDISABLED until encrypted, then AUTH once it is safe to send
      # credentials.
      def capabilities
        caps = BASE_CAPABILITIES.dup
        if @tls
          caps << " AUTH=PLAIN SASL-IR"
        else
          caps << " STARTTLS" if @tls_ctx
          caps << " LOGINDISABLED"
        end
        caps
      end

      def run
        set_timeout(1800)
        untagged "OK [CAPABILITY #{capabilities}] mail_on_rails ready"
        until @logout
          parts = read_command
          break unless parts

          handle(parts)
        end
      rescue IOError, SystemCallError, IO::TimeoutError, OpenSSL::SSL::SSLError
        # client went away
      rescue StandardError => e
        @store.log(:error, "IMAP session error: #{e.class}: #{e.message} #{e.backtrace&.first}")
      ensure
        begin
          @socket.close
        rescue StandardError
          nil
        end
      end

      private

      # -- transport ---------------------------------------------------------

      # Reads one line, capped at MAX_LINE. Returns nil at EOF; aborts the
      # session on an over-length line rather than draining attacker bytes.
      def read_line
        line = @socket.gets("\r\n", MAX_LINE)
        return nil if line.nil?

        if !line.end_with?("\r\n") && line.bytesize >= MAX_LINE
          untagged "BAD Command line too long"
          raise IOError, "command line too long"
        end
        line
      end

      # Reads one command; IMAP literals ({n}\r\n) are read in full and kept
      # as [:lit, data] elements between the line fragments.
      def read_command
        line = read_line
        return nil unless line

        parts = [ line ]
        while (m = parts.last.match(/\{(\d+)(\+)?\}\r\n\z/))
          size = m[1].to_i
          if size > MAX_LITERAL_BYTES
            return refuse_literal(parts.first, size, non_sync: !m[2].nil?)
          end
          @socket.write("+ OK\r\n") unless m[2] # synchronizing literal
          data = read_exact(size)
          return nil unless data

          parts << [ :lit, data ]
          nxt = read_line
          return nil unless nxt

          parts << nxt
        end
        parts
      end

      def read_exact(size)
        data = +"".b
        while data.bytesize < size
          chunk = @socket.read(size - data.bytesize)
          return nil unless chunk

          data << chunk
        end
        data
      end

      # Refuses an over-size literal without desyncing the stream. For a
      # synchronizing literal the continuation is simply withheld - the
      # client never sends the octets. For LITERAL+ the client sends them
      # regardless, so they (and any further non-sync literals in the same
      # command) must be drained and discarded before the next command.
      def refuse_literal(first_line, size, non_sync:)
        tag = first_line.split(" ", 2).first
        while non_sync
          return nil unless discard_exact(size)

          line = read_line
          return nil unless line

          m = line.match(/\{(\d+)(\+)?\}\r\n\z/)
          break unless m

          size = m[1].to_i
          non_sync = !m[2].nil?
        end
        tagged tag, "NO literal too large"
        read_command
      end

      def discard_exact(size)
        remaining = size
        while remaining.positive?
          chunk = @socket.read([ remaining, 65_536 ].min)
          return false unless chunk

          remaining -= chunk.bytesize
        end
        true
      end

      def untagged(text)
        @socket.write("* #{text}\r\n")
      end

      def tagged(tag, text)
        @socket.write("#{tag} #{text}\r\n")
      end

      # -- dispatch ----------------------------------------------------------

      def handle(parts)
        tokens = Lexer.new(parts).tokens
        tag = tokens.shift
        name = tokens.shift
        return untagged("BAD Empty command") unless tag && name.is_a?(String)

        uid_mode = false
        if name.casecmp?("UID") && tokens.first.is_a?(String)
          uid_mode = true
          name = tokens.shift
        end

        dispatch(tag, name.upcase, tokens, uid_mode)
      rescue IOError, SystemCallError, IO::TimeoutError, OpenSSL::SSL::SSLError
        # Transport failures (including the over-length-line abort) are
        # session-fatal; only command-level errors get a BAD.
        raise
      rescue StandardError => e
        @store.log(:error, "IMAP command error: #{e.class}: #{e.message} #{e.backtrace&.first}")
        tagged tag || "*", "BAD Internal error"
      end

      def dispatch(tag, name, args, uid_mode)
        case name
        when "CAPABILITY"   then capability(tag)
        when "NOOP", "CHECK" then resync; tagged tag, "OK #{name} completed"
        when "LOGOUT"       then untagged "BYE mail_on_rails signing off"; tagged tag, "OK LOGOUT completed"; @logout = true
        when "ID"           then id(tag)
        when "LOGIN"        then login(tag, args)
        when "AUTHENTICATE" then authenticate(tag, args)
        when "STARTTLS"     then starttls(tag)
        when "NAMESPACE"    then require_auth(tag) { namespace(tag) }
        when "LIST"         then require_auth(tag) { list(tag, args, verb: "LIST") }
        when "LSUB"         then require_auth(tag) { list(tag, args, verb: "LSUB") }
        when "SUBSCRIBE", "UNSUBSCRIBE" then require_auth(tag) { tagged tag, "OK #{name} completed" }
        when "CREATE"       then require_auth(tag) { create(tag, args) }
        when "DELETE"       then require_auth(tag) { delete(tag, args) }
        when "RENAME"       then require_auth(tag) { rename(tag, args) }
        when "STATUS"       then require_auth(tag) { status(tag, args) }
        when "SELECT"       then require_auth(tag) { select(tag, args, read_only: false) }
        when "EXAMINE"      then require_auth(tag) { select(tag, args, read_only: true) }
        when "APPEND"       then require_auth(tag) { append(tag, args) }
        when "CLOSE"        then require_selected(tag) { close(tag) }
        when "UNSELECT"     then require_selected(tag) { unselect(tag) }
        when "EXPUNGE"      then require_selected(tag) { expunge(tag, uid_mode ? args : nil) }
        when "FETCH"        then require_selected(tag) { fetch(tag, args, uid_mode) }
        when "STORE"        then require_selected(tag) { store(tag, args, uid_mode) }
        when "COPY"         then require_selected(tag) { copy(tag, args, uid_mode) }
        when "MOVE"         then require_selected(tag) { move(tag, args, uid_mode) }
        when "SEARCH"       then require_selected(tag) { search(tag, args, uid_mode) }
        when "IDLE"         then require_auth(tag) { idle(tag) }
        else tagged tag, "BAD Unknown command #{name}"
        end
      end

      def require_auth(tag)
        return tagged(tag, "NO Not authenticated") unless @account_id

        yield
      end

      def require_selected(tag)
        return tagged(tag, "NO No mailbox selected") unless @selected

        yield
      end

      # -- session commands --------------------------------------------------

      def capability(tag)
        untagged "CAPABILITY #{capabilities}"
        tagged tag, "OK CAPABILITY completed"
      end

      def starttls(tag)
        return tagged(tag, "NO TLS not available") unless @tls_ctx
        return tagged(tag, "NO TLS already active") if @tls

        tagged tag, "OK Begin TLS negotiation now"
        @socket = Imap::TLS.accept(io_for(@socket), @tls_ctx)
        @tls = true
        set_timeout(1800)
        # Discard pre-TLS session state; the client re-authenticates.
        @account_id = nil
        @selected = nil
      rescue OpenSSL::SSL::SSLError => e
        @store.log(:error, "IMAP STARTTLS failed: #{e.message}")
        raise IOError, "TLS handshake failed"
      end

      def tls_required?
        !@tls
      end

      def login(tag, args)
        return tagged(tag, "NO [PRIVACYREQUIRED] STARTTLS required before LOGIN") if tls_required?

        user, pass = args
        complete_login(tag, "LOGIN", user, pass)
      end

      def authenticate(tag, args)
        return tagged(tag, "NO [PRIVACYREQUIRED] STARTTLS required before AUTHENTICATE") if tls_required?

        mechanism, initial = args
        return tagged(tag, "NO Unsupported authentication mechanism") unless mechanism.to_s.casecmp?("PLAIN")

        unless initial
          @socket.write("+ \r\n")
          line = read_line
          return unless line

          initial = line.chomp("\r\n")
          return tagged(tag, "BAD Authentication cancelled") if initial == "*"
        end
        _authzid, user, pass = decode_sasl_plain(initial)
        complete_login(tag, "AUTHENTICATE", user, pass)
      rescue ArgumentError
        tagged tag, "BAD Invalid base64"
      end

      # Shared LOGIN/AUTHENTICATE outcome. Failed attempts are capped like
      # the SMTP server's: past MAX_AUTH_ATTEMPTS the connection is dropped,
      # so a single connection can't brute-force credentials (each attempt
      # costs a bcrypt check).
      def complete_login(tag, verb, user, pass)
        result = @store.authenticate(user.to_s, pass.to_s)
        if result[:account_id]
          @account_id = result[:account_id]
          @store.log(:info, "IMAP login #{result[:email]} (#{peer_ip})")
          tagged tag, "OK [CAPABILITY #{capabilities}] #{verb} completed"
        else
          @auth_attempts += 1
          @store.log(:warn, "IMAP auth failed for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip}, attempt #{@auth_attempts}/#{MAX_AUTH_ATTEMPTS})")
          tagged tag, "NO [AUTHENTICATIONFAILED] Invalid credentials"
          if @auth_attempts >= MAX_AUTH_ATTEMPTS
            untagged "BYE Too many failed authentication attempts"
            @logout = true
          end
        end
      end

      def id(tag)
        untagged %(ID ("name" "mail_on_rails" "version" "#{Imap::VERSION}"))
        tagged tag, "OK ID completed"
      end

      def namespace(tag)
        untagged %(NAMESPACE (("" "/")) NIL NIL)
        tagged tag, "OK NAMESPACE completed"
      end

      # RFC 6154 well-known mailboxes, advertised via SPECIAL-USE
      # attributes so clients auto-map their folders.
      SPECIAL_USE = {
        "Sent" => "\\Sent", "Drafts" => "\\Drafts", "Trash" => "\\Trash", "Junk" => "\\Junk"
      }.freeze

      def list(tag, args, verb:)
        ref, pattern = args
        return tagged(tag, "BAD #{verb} expects 2 arguments") if pattern.nil?

        if pattern.empty?
          untagged %(#{verb} (\\Noselect) "/" "")
        else
          regex = wildcard_regex(Imap::Utf7.decode(ref.to_s + pattern))
          names = mailbox_names
          names.each do |name|
            next unless name.match?(regex)

            untagged %(#{verb} (#{list_attributes(name, names)}) "/" #{Mime.quote(Imap::Utf7.encode(name))})
          end
        end
        tagged tag, "OK #{verb} completed"
      end

      def list_attributes(name, names)
        attrs = [ names.any? { |n| n.start_with?("#{name}/") } ? "\\HasChildren" : "\\HasNoChildren" ]
        attrs << SPECIAL_USE[name] if SPECIAL_USE.key?(name)
        attrs.join(" ")
      end

      def mailbox_names
        result = @store.list_mailboxes(@account_id)
        names = result[:mailboxes] || []
        names.sort_by { |n| [ n == "INBOX" ? 0 : 1, n ] }
      end

      def wildcard_regex(pattern)
        parts = pattern.split(/([*%])/).map do |piece|
          case piece
          when "*" then ".*"
          when "%" then "[^/]*"
          else Regexp.escape(piece)
          end
        end
        Regexp.new("\\A#{parts.join}\\z", Regexp::IGNORECASE)
      end

      def create(tag, args)
        name = Imap::Utf7.decode(args.first.to_s)
        return tagged(tag, "BAD CREATE expects a mailbox name") if name.empty?

        result = @store.create_mailbox(@account_id, name)
        if result[:error]
          tagged tag, "NO CREATE failed: #{result[:error]}"
        else
          tagged tag, "OK CREATE completed"
        end
      end

      def delete(tag, args)
        name = Imap::Utf7.decode(args.first.to_s)
        return tagged(tag, "BAD DELETE expects a mailbox name") if name.empty?
        return tagged(tag, "NO Cannot delete INBOX") if name.casecmp?("INBOX")

        result = @store.delete_mailbox(@account_id, name)
        if result[:error]
          tagged tag, "NO DELETE failed: #{result[:error]}"
        else
          tagged tag, "OK DELETE completed"
        end
      end

      def rename(tag, args)
        from, to = args.first(2).map { |a| Imap::Utf7.decode(a.to_s) }
        return tagged(tag, "BAD RENAME expects two mailbox names") if from.empty? || to.to_s.empty?
        # RFC 3501's special INBOX-rename semantics (move contents, keep
        # INBOX) are not implemented; refusing is safer than surprising.
        return tagged(tag, "NO Cannot rename INBOX") if from.casecmp?("INBOX")

        result = @store.rename_mailbox(@account_id, from, to)
        if result[:error]
          tagged tag, "NO RENAME failed: #{result[:error]}"
        else
          # The selected mailbox keeps its id across a rename; only the
          # name (used by resync) needs updating.
          if @selected && (@selected[:name] == from || @selected[:name].start_with?("#{from}/"))
            @selected[:name] = to + @selected[:name][from.length..]
          end
          tagged tag, "OK RENAME completed"
        end
      end

      def status(tag, args)
        name = Imap::Utf7.decode(args.shift.to_s)
        items = args.select { |a| a.is_a?(String) }.map(&:upcase)
        result = @store.status(@account_id, name)
        return tagged(tag, "NO STATUS failed: no such mailbox") if result[:error]

        values = {
          "MESSAGES" => result[:messages],
          "RECENT" => 0,
          "UNSEEN" => result[:unseen],
          "UIDNEXT" => result[:uid_next],
          "UIDVALIDITY" => result[:uid_validity],
          "HIGHESTMODSEQ" => result[:highest_modseq] || 1
        }
        # HIGHESTMODSEQ is returned only when asked for (RFC 7162).
        items = %w[MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY] if items.empty?
        pairs = items.filter_map { |i| "#{i} #{values[i]}" if values.key?(i) }
        untagged "STATUS #{Mime.quote(Imap::Utf7.encode(name))} (#{pairs.join(" ")})"
        tagged tag, "OK STATUS completed"
      end

      def select(tag, args, read_only:)
        name = Imap::Utf7.decode(args.first.to_s)
        @condstore = true if args.any? { |a| a.is_a?(String) && a.casecmp?("CONDSTORE") }
        result = @store.select_mailbox(@account_id, name)
        if result[:error]
          @selected = nil
          return tagged(tag, "NO SELECT failed: no such mailbox")
        end

        @selected = { mailbox_id: result[:mailbox_id], name: result[:name] }
        @read_only = read_only
        take_snapshot(result)

        untagged "FLAGS (#{FLAGS})"
        untagged "#{@uids.length} EXISTS"
        untagged "0 RECENT"
        if (first_unseen = @uids.index { |uid| !@flags[uid].include?("\\Seen") })
          untagged "OK [UNSEEN #{first_unseen + 1}] First unseen"
        end
        untagged "OK [PERMANENTFLAGS (#{FLAGS} \\*)] Flags permitted"
        untagged "OK [UIDVALIDITY #{result[:uid_validity]}] UIDs valid"
        untagged "OK [UIDNEXT #{result[:uid_next]}] Predicted next UID"
        untagged "OK [HIGHESTMODSEQ #{@highest_modseq}] Highest"
        tagged tag, "OK [#{read_only ? "READ-ONLY" : "READ-WRITE"}] #{read_only ? "EXAMINE" : "SELECT"} completed"
      end

      # Rows are [uid, flags, modseq]; modseq may be absent from a store
      # that predates CONDSTORE, in which case everything reads as 1.
      def take_snapshot(result)
        @uids = result[:messages].map(&:first)
        @flags = result[:messages].to_h { |uid, flags, _modseq| [ uid, flags ] }
        @modseqs = result[:messages].to_h { |uid, _flags, modseq| [ uid, modseq || 1 ] }
        @highest_modseq = result[:highest_modseq] || 1
      end

      def close(tag)
        @store.expunge(@selected[:mailbox_id]) unless @read_only
        drop_snapshot
        tagged tag, "OK CLOSE completed"
      end

      # RFC 3691: like CLOSE but without the implicit expunge.
      def unselect(tag)
        drop_snapshot
        tagged tag, "OK UNSELECT completed"
      end

      def drop_snapshot
        @selected = nil
        @uids = []
        @flags = {}
        @modseqs = {}
      end

      # Plain EXPUNGE removes every \Deleted message; UID EXPUNGE (UIDPLUS,
      # uid_args non-nil) removes only \Deleted messages within the given set.
      def expunge(tag, uid_args = nil)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        uids = nil
        if uid_args
          set = uid_args.first
          return tagged(tag, "BAD UID EXPUNGE expects a sequence set") unless set.is_a?(String)

          uids = resolve_set(set, true).map(&:last)
          return tagged(tag, "OK EXPUNGE completed") if uids.empty?
        end

        result = @store.expunge(@selected[:mailbox_id], uids)
        removed = result[:uids] || []
        @uids.each_with_index.to_a.reverse_each do |uid, idx|
          next unless removed.include?(uid)

          untagged "#{idx + 1} EXPUNGE"
          @flags.delete(uid)
        end
        @uids -= removed
        tagged tag, "OK EXPUNGE completed"
      end

      # -- message sets --------------------------------------------------------

      # Resolves an IMAP sequence set against the current mailbox snapshot.
      # Returns [[seq, uid], ...] in mailbox order.
      def resolve_set(set, uid_mode)
        return [] if @uids.empty?

        max = uid_mode ? @uids.last : @uids.length
        ranges = set.to_s.split(",").filter_map do |chunk|
          lo, hi = chunk.split(":", 2)
          lo = lo == "*" ? max : lo.to_i
          hi = hi.nil? ? lo : (hi == "*" ? max : hi.to_i)
          lo, hi = hi, lo if lo > hi
          (lo..hi)
        end
        result = []
        @uids.each_with_index do |uid, idx|
          value = uid_mode ? uid : idx + 1
          result << [ idx + 1, uid ] if ranges.any? { |r| r.cover?(value) }
        end
        result
      end

      # -- FETCH ---------------------------------------------------------------

      # Deep-frozen (not just the outer hash): session constants must be
      # Ractor-shareable to be readable from worker Ractors.
      FETCH_MACROS = {
        "ALL" => %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE].freeze,
        "FAST" => %w[FLAGS INTERNALDATE RFC822.SIZE].freeze,
        "FULL" => %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY].freeze
      }.freeze

      METADATA_ITEMS = %w[UID FLAGS INTERNALDATE RFC822.SIZE MODSEQ].freeze

      def fetch(tag, args, uid_mode)
        set = args.shift
        return tagged(tag, "BAD FETCH expects a sequence set") unless set.is_a?(String)

        changedsince = extract_changedsince(args)
        items = args.take_while { |a| a != :rparen }.reject { |a| a == :lparen }.map { |a| a.to_s }
        items = items.flat_map { |i| FETCH_MACROS[i.upcase] || [ i ] }
        items << "UID" if uid_mode && items.none? { |i| i.casecmp?("UID") }
        return tagged(tag, "BAD FETCH expects data items") if items.empty?

        @condstore = true if changedsince || items.any? { |i| i.casecmp?("MODSEQ") }
        items << "MODSEQ" if @condstore && items.none? { |i| i.casecmp?("MODSEQ") }

        wanted = resolve_set(set, uid_mode)
        wanted = wanted.select { |_seq, uid| (@modseqs[uid] || 1) > changedsince } if changedsince
        need_raw = items.any? { |i| !METADATA_ITEMS.include?(i.upcase) }
        messages = fetch_messages(wanted.map(&:last), need_raw)
        newly_seen = mark_fetched_seen(items, wanted.filter_map { |_seq, uid| messages[uid] })

        wanted.each do |seq, uid|
          msg = messages[uid] or next
          untagged "#{seq} FETCH (#{fetch_items(msg, items, announce_seen: newly_seen.include?(uid)).join(" ")})"
        end
        tagged tag, "OK FETCH completed"
      end

      # Pulls the RFC 7162 "(CHANGEDSINCE n)" modifier group out of the
      # argument list (it follows the item list) and returns n, or nil.
      def extract_changedsince(args)
        idx = args.index { |a| a.is_a?(String) && a.casecmp?("CHANGEDSINCE") }
        return nil unless idx

        value = args[idx + 1].to_i
        first = idx.positive? && args[idx - 1] == :lparen ? idx - 1 : idx
        last = args[idx + 2] == :rparen ? idx + 2 : idx + 1
        args.slice!(first..last)
        value
      end

      def fetch_messages(uids, with_raw)
        return {} if uids.empty?

        result = @store.fetch(@selected[:mailbox_id], uids, with_raw)
        (result[:messages] || []).to_h { |m| [ m[:uid], m ] }
      end

      # RFC 3501: RFC822, RFC822.TEXT and BODY[...] (without .PEEK)
      # implicitly set \Seen.
      def marks_seen?(items)
        items.any? do |item|
          item.casecmp?("RFC822") || item.casecmp?("RFC822.TEXT") ||
            item.match?(/\ABODY\[.*\](?:<\d+(?:\.\d+)?>)?\z/i)
        end
      end

      # Applies the implicit \Seen from non-PEEK body fetches in one batched
      # store_flags call (a client syncing N bodies would otherwise cost N
      # UPDATEs). Returns the uids whose flags changed.
      def mark_fetched_seen(items, msgs)
        return [] if @read_only || !marks_seen?(items)

        uids = msgs.filter_map { |m| m[:uid] unless (@flags[m[:uid]] || m[:flags]).include?("\\Seen") }
        return [] if uids.empty?

        result = @store.store_flags(@selected[:mailbox_id], uids, "+", [ "\\Seen" ])
        (result[:messages] || []).each do |uid, new_flags, modseq|
          @flags[uid] = new_flags
          @modseqs[uid] = modseq if modseq
        end
        uids
      end

      def fetch_items(msg, items, announce_seen: false)
        parsed = nil
        parse = -> { parsed ||= Mime.parse(msg[:raw]) }
        flags = @flags[msg[:uid]] || msg[:flags]
        out = []

        items.each do |item|
          case item.upcase
          when "UID"           then out << "UID #{msg[:uid]}"
          when "MODSEQ"        then out << "MODSEQ (#{@modseqs[msg[:uid]] || msg[:modseq] || 1})"
          when "FLAGS"         then out << "FLAGS (#{flags.join(" ")})"
          when "INTERNALDATE"  then out << %(INTERNALDATE "#{internal_date(msg)}")
          when "RFC822.SIZE"   then out << "RFC822.SIZE #{msg[:size]}"
          when "ENVELOPE"      then out << "ENVELOPE #{Mime.envelope(parse.call)}"
          when "BODY", "BODYSTRUCTURE" then out << "#{item.upcase} #{Mime.bodystructure(parse.call)}"
          when "RFC822"        then out << "RFC822 #{Mime.literal(msg[:raw])}"
          when "RFC822.HEADER" then out << "RFC822.HEADER #{Mime.literal(parse.call.header_block)}"
          when "RFC822.TEXT"   then out << "RFC822.TEXT #{Mime.literal(parse.call.body)}"
          else
            if (m = item.match(/\ABODY(\.PEEK)?\[(.*)\](?:<(\d+)(?:\.(\d+))?>)?\z/i))
              _peek, section, start, count = m[1], m[2], m[3], m[4]
              data = Mime.section(parse.call, section)
              label = +"BODY[#{section.upcase}]"
              if data && start
                data = data.byteslice(start.to_i, count ? count.to_i : data.bytesize).to_s
                label << "<#{start}>"
              end
              out << "#{label} #{data ? Mime.literal(data) : "NIL"}"
            end
          end
        end

        # Notify the client of the implicit \Seen unless FLAGS was already
        # in the response.
        if announce_seen && items.none? { |i| i.casecmp?("FLAGS") }
          out << "FLAGS (#{flags.join(" ")})"
        end
        out
      end

      def internal_date(msg)
        Time.at(msg[:internal_date]).strftime("%d-%b-%Y %H:%M:%S %z")
      end

      # -- STORE / COPY --------------------------------------------------------

      CANONICAL_FLAGS = {
        "\\seen" => "\\Seen", "\\answered" => "\\Answered", "\\flagged" => "\\Flagged",
        "\\deleted" => "\\Deleted", "\\draft" => "\\Draft"
      }.freeze

      def store(tag, args, uid_mode)
        set = args.shift
        unchangedsince = nil
        # RFC 7162: store-modifier group precedes the item, e.g.
        # STORE 1:* (UNCHANGEDSINCE 620162338) +FLAGS.SILENT (\Deleted)
        if args.first == :lparen && args[1].is_a?(String) && args[1].casecmp?("UNCHANGEDSINCE")
          unchangedsince = args[2].to_i
          args.shift(4)
          @condstore = true
        end
        item = args.shift
        return tagged(tag, "BAD STORE expects a sequence set and item") unless set.is_a?(String) && item.is_a?(String)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        m = item.match(/\A([+-]?)FLAGS(\.SILENT)?\z/i)
        return tagged(tag, "BAD Unknown STORE item #{item}") unless m

        mode = m[1].empty? ? "=" : m[1]
        silent = !m[2].nil?
        flags = args.select { |a| a.is_a?(String) }
                    .map { |f| CANONICAL_FLAGS.fetch(f.downcase, f) }
                    .reject { |f| f == "\\Recent" }

        wanted = resolve_set(set, uid_mode)
        failed = []
        if unchangedsince
          wanted, failed = wanted.partition { |_seq, uid| (@modseqs[uid] || 1) <= unchangedsince }
        end
        return tagged(tag, store_completion(failed, uid_mode)) if wanted.empty?

        result = @store.store_flags(@selected[:mailbox_id], wanted.map(&:last), mode, flags)
        updated = {}
        (result[:messages] || []).each do |uid, new_flags, modseq|
          updated[uid] = new_flags
          @flags[uid] = new_flags
          @modseqs[uid] = modseq if modseq
        end

        unless silent
          wanted.each do |seq, uid|
            next unless updated.key?(uid)

            parts = [ "FLAGS (#{updated[uid].join(" ")})" ]
            parts << "MODSEQ (#{@modseqs[uid] || 1})" if @condstore
            parts << "UID #{uid}" if uid_mode
            untagged "#{seq} FETCH (#{parts.join(" ")})"
          end
        end
        tagged tag, store_completion(failed, uid_mode)
      end

      # RFC 7162: messages skipped by UNCHANGEDSINCE are reported in a
      # MODIFIED response code on the (still OK) tagged completion.
      def store_completion(failed, uid_mode)
        return "OK STORE completed" if failed.empty?

        ids = failed.map { |seq, uid| uid_mode ? uid : seq }
        "OK [MODIFIED #{compress_set(ids)}] Conditional STORE completed"
      end

      def copy(tag, args, uid_mode)
        set, dest = args
        return tagged(tag, "BAD COPY expects a sequence set and mailbox") unless set.is_a?(String) && dest.is_a?(String)

        wanted = resolve_set(set, uid_mode)
        return tagged(tag, "OK COPY completed (nothing to copy)") if wanted.empty?

        result = @store.copy(@selected[:mailbox_id], wanted.map(&:last), Imap::Utf7.decode(dest))
        if result[:error]
          code = result[:code] == :notfound ? "[TRYCREATE] " : ""
          tagged tag, "NO #{code}COPY failed: #{result[:error]}"
        else
          copyuid = "#{result[:uid_validity]} #{result[:src_uids].join(",")} #{result[:dest_uids].join(",")}"
          tagged tag, "OK [COPYUID #{copyuid}] COPY completed"
        end
      end

      # RFC 6851 MOVE: a single atomic store operation, so the message can
      # never exist in both mailboxes (or neither) on a failure.
      def move(tag, args, uid_mode)
        set, dest = args
        return tagged(tag, "BAD MOVE expects a sequence set and mailbox") unless set.is_a?(String) && dest.is_a?(String)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        wanted = resolve_set(set, uid_mode)
        return tagged(tag, "OK MOVE completed (nothing to move)") if wanted.empty?

        result = @store.move(@selected[:mailbox_id], wanted.map(&:last), Imap::Utf7.decode(dest))
        if result[:error]
          code = result[:code] == :notfound ? "[TRYCREATE] " : ""
          return tagged(tag, "NO #{code}MOVE failed: #{result[:error]}")
        end

        # RFC 6851: COPYUID rides an untagged OK and precedes the EXPUNGEs.
        untagged "OK [COPYUID #{result[:uid_validity]} #{result[:src_uids].join(",")} #{result[:dest_uids].join(",")}]"
        moved = result[:src_uids]
        @uids.each_with_index.to_a.reverse_each do |uid, idx|
          next unless moved.include?(uid)

          untagged "#{idx + 1} EXPUNGE"
          @flags.delete(uid)
        end
        @uids -= moved
        tagged tag, "OK MOVE completed"
      end

      # -- SEARCH ----------------------------------------------------------------

      # Matching is byte-oriented, so only ASCII-clean charsets are honest
      # to accept (RFC 3501 requires US-ASCII and UTF-8 support).
      SEARCH_CHARSETS = %w[US-ASCII UTF-8].freeze

      # Raised for malformed search criteria; the message becomes the BAD text.
      class SearchSyntaxError < StandardError; end

      # A compiled search key: raw marks keys that need message bytes
      # (header/body content), so SEARCH can filter on metadata first and
      # fetch raw bytes only for the messages that survive.
      SearchKey = Struct.new(:raw, :fn) do
        def call(seq, msg) = fn.call(seq, msg)
        def raw? = raw
      end

      ESEARCH_OPTIONS = %w[MIN MAX COUNT ALL].freeze

      def search(tag, args, uid_mode)
        criteria = args.dup
        @search_modseq = false
        return_opts = parse_search_return(criteria)
        if criteria.first.is_a?(String) && criteria.first.casecmp?("CHARSET")
          charset = criteria.shift(2)[1].to_s
          unless SEARCH_CHARSETS.any? { |c| charset.casecmp?(c) }
            return tagged(tag, "NO [BADCHARSET (#{SEARCH_CHARSETS.join(" ")})] Charset not supported")
          end
        end

        matchers = []
        matchers << parse_search_key(criteria, uid_mode) until criteria.empty?
        matchers.compact!
        meta_keys, raw_keys = matchers.partition { |k| !k.raw? }

        # Two-phase evaluation: metadata keys (flags, dates, sizes, sets)
        # run against the cheap metadata fetch; message bytes are pulled
        # only for the survivors that content keys still need to inspect.
        all = @uids.each_with_index.map { |uid, idx| [ idx + 1, uid ] }
        messages = fetch_messages(@uids, false)
        hits = all.select do |seq, uid|
          msg = messages[uid]
          msg && meta_keys.all? { |k| k.call(seq, msg) }
        end
        if raw_keys.any? && hits.any?
          raw_messages = fetch_messages(hits.map(&:last), true)
          hits = hits.select do |seq, uid|
            msg = raw_messages[uid]
            msg && raw_keys.all? { |k| k.call(seq, msg) }
          end
        end
        ids = hits.map { |seq, uid| uid_mode ? uid : seq }
        # RFC 7162: a MODSEQ search key adds "(MODSEQ n)" / "MODSEQ n"
        # (highest modseq among the matches) to the response.
        modseq_max = @search_modseq && hits.any? ? hits.map { |_seq, uid| @modseqs[uid] || 1 }.max : nil
        if return_opts
          response = esearch_response(tag, ids, return_opts, uid_mode)
          response << " MODSEQ #{modseq_max}" if modseq_max
          untagged response
        else
          response = +"SEARCH #{ids.join(" ")}".rstrip
          response << " (MODSEQ #{modseq_max})" if modseq_max
          untagged response
        end
        tagged tag, "OK SEARCH completed"
      rescue SearchSyntaxError => e
        tagged tag, "BAD #{e.message}"
      end

      # RFC 4731 "SEARCH RETURN (...)"; nil when absent (classic SEARCH).
      def parse_search_return(criteria)
        return nil unless criteria.first.is_a?(String) && criteria.first.casecmp?("RETURN")

        criteria.shift
        raise SearchSyntaxError, "SEARCH RETURN expects an option list" unless criteria.first == :lparen

        criteria.shift
        opts = []
        until criteria.first == :rparen
          raise SearchSyntaxError, "SEARCH RETURN expects an option list" if criteria.empty?

          opts << criteria.shift.to_s.upcase
        end
        criteria.shift
        unknown = opts - ESEARCH_OPTIONS
        raise SearchSyntaxError, "Unsupported SEARCH RETURN option #{unknown.first}" if unknown.any?

        opts.empty? ? %w[ALL] : opts
      end

      # RFC 4731: MIN/MAX/ALL are omitted when nothing matched; COUNT is
      # always present when requested. The TAG correlator is mandatory.
      def esearch_response(tag, ids, opts, uid_mode)
        parts = []
        parts << "MIN #{ids.min}" if opts.include?("MIN") && ids.any?
        parts << "MAX #{ids.max}" if opts.include?("MAX") && ids.any?
        parts << "COUNT #{ids.size}" if opts.include?("COUNT")
        parts << "ALL #{compress_set(ids)}" if opts.include?("ALL") && ids.any?
        out = +%(ESEARCH (TAG "#{tag}"))
        out << " UID" if uid_mode
        out << " " << parts.join(" ") if parts.any?
        out
      end

      # Collapses sorted ids into RFC sequence-set form: [1,2,3,5] -> "1:3,5".
      def compress_set(ids)
        ids.sort.slice_when { |a, b| b != a + 1 }
           .map { |run| run.size == 1 ? run.first.to_s : "#{run.first}:#{run.last}" }
           .join(",")
      end

      def parse_search_key(toks, uid_mode)
        tok = toks.shift
        return nil if tok.nil?

        if tok == :lparen
          keys = []
          keys << parse_search_key(toks, uid_mode) until toks.empty? || toks.first == :rparen
          toks.shift
          keys.compact!
          return SearchKey.new(keys.any?(&:raw?), ->(seq, msg) { keys.all? { |k| k.call(seq, msg) } })
        end
        return nil unless tok.is_a?(String)

        case tok.upcase
        when "ALL" then meta_key { |_seq, _msg| true }
        when "ANSWERED"   then flag_key("\\Answered")
        when "DELETED"    then flag_key("\\Deleted")
        when "DRAFT"      then flag_key("\\Draft")
        when "FLAGGED"    then flag_key("\\Flagged")
        when "SEEN"       then flag_key("\\Seen")
        when "UNANSWERED" then negate(flag_key("\\Answered"))
        when "UNDELETED"  then negate(flag_key("\\Deleted"))
        when "UNDRAFT"    then negate(flag_key("\\Draft"))
        when "UNFLAGGED"  then negate(flag_key("\\Flagged"))
        when "UNSEEN"     then negate(flag_key("\\Seen"))
        when "RECENT", "NEW" then meta_key { |_seq, _msg| false }
        when "OLD" then meta_key { |_seq, _msg| true }
        when "KEYWORD" then flag_key(toks.shift.to_s)
        when "UNKEYWORD" then negate(flag_key(toks.shift.to_s))
        when "NOT"
          key = parse_search_key(toks, uid_mode)
          raise SearchSyntaxError, "NOT expects a search key" if key.nil?

          negate(key)
        when "OR"
          a = parse_search_key(toks, uid_mode)
          b = parse_search_key(toks, uid_mode)
          raise SearchSyntaxError, "OR expects two search keys" if a.nil? || b.nil?

          SearchKey.new(a.raw? || b.raw?, ->(seq, msg) { a.call(seq, msg) || b.call(seq, msg) })
        when "UID"
          uids = resolve_set(toks.shift.to_s, true).map(&:last)
          meta_key { |_seq, msg| uids.include?(msg[:uid]) }
        when "LARGER"  then min = toks.shift.to_i; meta_key { |_seq, msg| msg[:size] > min }
        when "SMALLER" then max = toks.shift.to_i; meta_key { |_seq, msg| msg[:size] < max }
        when "SINCE"  then date_key(toks.shift) { |msg_day, day| msg_day >= day }
        when "BEFORE" then date_key(toks.shift) { |msg_day, day| msg_day < day }
        when "ON"     then date_key(toks.shift) { |msg_day, day| msg_day == day }
        when "SENTSINCE"  then sent_date_key(toks.shift) { |msg_day, day| msg_day >= day }
        when "SENTBEFORE" then sent_date_key(toks.shift) { |msg_day, day| msg_day < day }
        when "SENTON"     then sent_date_key(toks.shift) { |msg_day, day| msg_day == day }
        when "HEADER"
          name = toks.shift.to_s
          value = toks.shift.to_s
          header_key(name, value)
        when "FROM"    then header_key("from", toks.shift.to_s)
        when "TO"      then header_key("to", toks.shift.to_s)
        when "CC"      then header_key("cc", toks.shift.to_s)
        when "BCC"     then header_key("bcc", toks.shift.to_s)
        when "SUBJECT" then header_key("subject", toks.shift.to_s)
        when "TEXT"
          value = toks.shift.to_s.downcase
          raw_key { |_seq, msg| msg[:raw].to_s.downcase.include?(value) }
        when "BODY"
          # Unlike TEXT, BODY matches the body only, never the header.
          value = toks.shift.to_s.downcase
          raw_key { |_seq, msg| Mime.split_header(msg[:raw].to_s)[1].downcase.include?(value) }
        when "OLDER"   then age_key(toks.shift) { |age, seconds| age >= seconds }
        when "YOUNGER" then age_key(toks.shift) { |age, seconds| age <= seconds }
        when "MODSEQ"
          # Optional entry-name/entry-type prefix ("/flags/\Seen" all) is
          # accepted and ignored - flags share one modseq per message here.
          toks.shift(2) if toks.first.is_a?(String) && !toks.first.match?(/\A\d+\z/)
          value = toks.shift.to_s.to_i
          @condstore = true
          @search_modseq = true
          meta_key { |_seq, msg| (@modseqs[msg[:uid]] || 1) >= value }
        when /\A[\d*][\d,:*]*\z/
          pairs = resolve_set(tok, false)
          seqs = pairs.map(&:first)
          meta_key { |seq, _msg| seqs.include?(seq) }
        else
          raise SearchSyntaxError, "Unknown search key #{tok.upcase}"
        end
      end

      def meta_key(&fn)
        SearchKey.new(false, fn)
      end

      def raw_key(&fn)
        SearchKey.new(true, fn)
      end

      def negate(key)
        return nil if key.nil?

        SearchKey.new(key.raw?, ->(seq, msg) { !key.call(seq, msg) })
      end

      def flag_key(flag)
        meta_key { |_seq, msg| (@flags[msg[:uid]] || msg[:flags]).include?(flag) }
      end

      def date_key(str, &compare)
        day = parse_search_date(str)
        meta_key { |_seq, msg| compare.call(msg[:internal_date] / 86_400, day) }
      end

      # SENTBEFORE/SENTON/SENTSINCE compare against the Date: header
      # (RFC 3501), not INTERNALDATE. Messages without a parseable Date
      # header don't match.
      def sent_date_key(str, &compare)
        day = parse_search_date(str)
        raw_key do |_seq, msg|
          value = Mime.parse_headers(Mime.split_header(msg[:raw].to_s)[0])["date"]&.first
          sent_day = begin
            value && Time.parse(value).to_i / 86_400
          rescue ArgumentError
            nil
          end
          !sent_day.nil? && compare.call(sent_day, day)
        end
      end

      def parse_search_date(str)
        Time.strptime(str.to_s, "%d-%b-%Y").to_i / 86_400
      rescue ArgumentError
        raise SearchSyntaxError, "Invalid date #{str}"
      end

      # RFC 5032 OLDER/YOUNGER: message age in seconds vs INTERNALDATE.
      def age_key(str, &compare)
        seconds = begin
          Integer(str.to_s, 10)
        rescue ArgumentError
          raise SearchSyntaxError, "Invalid interval #{str}"
        end
        now = Time.now.to_i
        meta_key { |_seq, msg| compare.call(now - msg[:internal_date], seconds) }
      end

      def header_key(name, value)
        name = name.downcase
        value = value.downcase
        raw_key do |_seq, msg|
          headers = Mime.parse_headers(Mime.split_header(msg[:raw].to_s)[0])
          headers[name].to_a.any? { |v| v.downcase.include?(value) }
        end
      end

      # -- APPEND ----------------------------------------------------------------

      def append(tag, args)
        name = Imap::Utf7.decode(args.shift.to_s)
        message = args.pop
        return tagged(tag, "BAD APPEND expects a mailbox and message") if name.empty? || !message.is_a?(String)

        flags = []
        date_epoch = nil
        if (open_idx = args.index(:lparen))
          close_idx = args.index(:rparen) || args.length
          flags = args[(open_idx + 1)...close_idx]
                  .select { |a| a.is_a?(String) }
                  .map { |f| CANONICAL_FLAGS.fetch(f.downcase, f) }
                  .reject { |f| f == "\\Recent" }
          args = args[(close_idx + 1)..] || []
        end
        if (date_str = args.find { |a| a.is_a?(String) && a.match?(/\A\s*\d{1,2}-\w{3}-\d{4} /) })
          begin
            date_epoch = Time.strptime(date_str.strip, "%d-%b-%Y %H:%M:%S %z").to_i
          rescue ArgumentError
            date_epoch = nil
          end
        end

        result = @store.append(@account_id, name, message, flags, date_epoch)
        if result[:error]
          code = result[:code] == :notfound ? "[TRYCREATE] " : ""
          tagged tag, "NO #{code}APPEND failed: #{result[:error]}"
        else
          # An APPEND into the selected mailbox must surface as an
          # untagged EXISTS (RFC 3501 §6.3.11) before the tagged OK.
          resync if @selected && @selected[:name].casecmp?(name)
          tagged tag, "OK [APPENDUID #{result[:uid_validity]} #{result[:uid]}] APPEND completed"
        end
      end

      # -- IDLE / resync -----------------------------------------------------------

      # RFC 2177. The session blocks here pushing untagged updates (found
      # by polling resync) until the client sends DONE.
      def idle(tag)
        @socket.write("+ idling\r\n")
        loop do
          if wait_readable(IDLE_POLL_SECONDS)
            line = read_line
            return unless line
            return tagged(tag, "OK IDLE terminated") if line.chomp("\r\n").casecmp?("DONE")

            return tagged(tag, "BAD Expected DONE")
          end
          resync
        end
      end

      # True when input is waiting, false on timeout. TLS can hold
      # decrypted bytes buffered past the raw fd, so check there first.
      def wait_readable(seconds)
        return true if @socket.respond_to?(:pending) && @socket.pending.positive?

        !IO.select([ io_for(@socket) ], nil, nil, seconds).nil?
      end

      # Refreshes the mailbox snapshot (on NOOP/CHECK and from the IDLE
      # loop) so clients learn about newly delivered or externally deleted
      # messages and flag changes made by other sessions.
      def resync
        return unless @selected

        result = @store.select_mailbox(@account_id, @selected[:name])
        return if result[:error]

        old_flags = @flags
        new_uids = result[:messages].map(&:first)
        removed = @uids - new_uids
        added = new_uids - @uids

        @uids.each_with_index.to_a.reverse_each do |uid, idx|
          untagged "#{idx + 1} EXPUNGE" if removed.include?(uid)
        end
        take_snapshot(result)
        untagged "#{@uids.length} EXISTS" if removed.any? || added.any?

        @uids.each_with_index do |uid, idx|
          next unless old_flags.key?(uid) && old_flags[uid].sort != @flags[uid].sort

          untagged "#{idx + 1} FETCH (FLAGS (#{@flags[uid].join(" ")}))"
        end
      end
    end
  end
end

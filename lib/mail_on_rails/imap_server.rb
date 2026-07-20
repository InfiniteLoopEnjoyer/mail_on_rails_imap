# frozen_string_literal: true

require "strscan"
require "time"
require "mail_on_rails/imap/server"
require "mail_on_rails/imap/session_helpers"
require_relative "mime"

module MailOnRails
  # IMAP4rev1 server (RFC 3501 subset), run on a thread by Imap::Daemon -
  # standalone in this repo's container via bin/server, or embedded in a
  # host process in development. Covers what real clients - iOS Mail in particular - need to read a
  # mailbox: LOGIN, LIST/LSUB, SELECT/EXAMINE, STATUS, (UID) FETCH with
  # section fetches, (UID) STORE, (UID) SEARCH, (UID) COPY, APPEND,
  # EXPUNGE, CLOSE, NOOP. Listens on a plaintext+STARTTLS port and an
  # implicit-TLS port; credentials are refused until the channel is
  # encrypted (LOGINDISABLED advertised in the clear).
  class ImapServer < Imap::Server
    # Base capabilities; STARTTLS/LOGINDISABLED/AUTH are appended per-state.
    BASE_CAPABILITIES = "IMAP4rev1 UIDPLUS LITERAL+ ID"
    FLAGS = "\\Answered \\Flagged \\Deleted \\Seen \\Draft"
    MAX_LITERAL_BYTES = 30 * 1024 * 1024
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

    def new_session(socket, spec, ctx)
      Session.new(socket, @store, ctx, spec[:tls] == :implicit)
    end

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

      def initialize(socket, store, tls_ctx, tls_active)
        @socket = socket
        @store = store
        @tls_ctx = tls_ctx
        @tls = tls_active
        @account_id = nil
        @auth_attempts = 0
        @selected = nil
        @uids = []
        @flags = {}
        @read_only = false
        @logout = false
      end

      # Capabilities depend on connection state: advertise STARTTLS and
      # LOGINDISABLED until encrypted, then AUTH once it is safe to send
      # credentials.
      def capabilities
        caps = BASE_CAPABILITIES.dup
        if @tls
          caps << " AUTH=PLAIN"
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
            tag = parts.first.split(" ", 2).first
            tagged tag, "NO literal too large"
            return read_command
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
      rescue StandardError => e
        @store.log(:error, "IMAP command error: #{e.class}: #{e.message} #{e.backtrace&.first}")
        tagged tag || "*", "BAD Internal error"
      end

      def dispatch(tag, name, args, uid_mode)
        case name
        when "CAPABILITY"   then capability(tag)
        when "NOOP", "CHECK" then resync; tagged tag, "OK #{name} completed"
        when "LOGOUT"       then untagged "BYE mail_on_rails signing off"; tagged tag, "OK LOGOUT completed"; @logout = true
        when "ID"           then untagged "ID NIL"; tagged tag, "OK ID completed"
        when "LOGIN"        then login(tag, args)
        when "AUTHENTICATE" then authenticate(tag, args)
        when "STARTTLS"     then starttls(tag)
        when "NAMESPACE"    then require_auth(tag) { namespace(tag) }
        when "LIST"         then require_auth(tag) { list(tag, args, verb: "LIST") }
        when "LSUB"         then require_auth(tag) { list(tag, args, verb: "LSUB") }
        when "SUBSCRIBE", "UNSUBSCRIBE" then require_auth(tag) { tagged tag, "OK #{name} completed" }
        when "CREATE"       then require_auth(tag) { create(tag, args) }
        when "DELETE", "RENAME" then require_auth(tag) { tagged tag, "NO #{name} not supported" }
        when "STATUS"       then require_auth(tag) { status(tag, args) }
        when "SELECT"       then require_auth(tag) { select(tag, args, read_only: false) }
        when "EXAMINE"      then require_auth(tag) { select(tag, args, read_only: true) }
        when "APPEND"       then require_auth(tag) { append(tag, args) }
        when "CLOSE"        then require_selected(tag) { close(tag) }
        when "EXPUNGE"      then require_selected(tag) { expunge(tag) }
        when "FETCH"        then require_selected(tag) { fetch(tag, args, uid_mode) }
        when "STORE"        then require_selected(tag) { store(tag, args, uid_mode) }
        when "COPY"         then require_selected(tag) { copy(tag, args, uid_mode) }
        when "SEARCH"       then require_selected(tag) { search(tag, args, uid_mode) }
        when "IDLE"         then tagged tag, "NO IDLE not supported"
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
          initial = @socket.gets("\r\n").to_s.chomp
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

      def namespace(tag)
        untagged %(NAMESPACE (("" "/")) NIL NIL)
        tagged tag, "OK NAMESPACE completed"
      end

      def list(tag, args, verb:)
        ref, pattern = args
        return tagged(tag, "BAD #{verb} expects 2 arguments") if pattern.nil?

        if pattern.empty?
          untagged %(#{verb} (\\Noselect) "/" "")
        else
          regex = wildcard_regex(ref.to_s + pattern)
          names = mailbox_names
          names.each do |name|
            untagged %(#{verb} (\\HasNoChildren) "/" #{Mime.quote(name)}) if name.match?(regex)
          end
        end
        tagged tag, "OK #{verb} completed"
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
        name = args.first.to_s
        return tagged(tag, "BAD CREATE expects a mailbox name") if name.empty?

        result = @store.create_mailbox(@account_id, name)
        if result[:error]
          tagged tag, "NO CREATE failed: #{result[:error]}"
        else
          tagged tag, "OK CREATE completed"
        end
      end

      def status(tag, args)
        name = args.shift.to_s
        items = args.select { |a| a.is_a?(String) }.map(&:upcase)
        result = @store.status(@account_id, name)
        return tagged(tag, "NO STATUS failed: no such mailbox") if result[:error]

        values = {
          "MESSAGES" => result[:messages],
          "RECENT" => 0,
          "UNSEEN" => result[:unseen],
          "UIDNEXT" => result[:uid_next],
          "UIDVALIDITY" => result[:uid_validity]
        }
        items = values.keys if items.empty?
        pairs = items.filter_map { |i| "#{i} #{values[i]}" if values.key?(i) }
        untagged "STATUS #{Mime.quote(name)} (#{pairs.join(" ")})"
        tagged tag, "OK STATUS completed"
      end

      def select(tag, args, read_only:)
        name = args.first.to_s
        result = @store.select_mailbox(@account_id, name)
        if result[:error]
          @selected = nil
          return tagged(tag, "NO SELECT failed: no such mailbox")
        end

        @selected = { mailbox_id: result[:mailbox_id], name: result[:name] }
        @read_only = read_only
        @uids = result[:messages].map(&:first)
        @flags = result[:messages].to_h { |uid, flags| [ uid, flags ] }

        untagged "FLAGS (#{FLAGS})"
        untagged "#{@uids.length} EXISTS"
        untagged "0 RECENT"
        if (first_unseen = @uids.index { |uid| !@flags[uid].include?("\\Seen") })
          untagged "OK [UNSEEN #{first_unseen + 1}] First unseen"
        end
        untagged "OK [PERMANENTFLAGS (#{FLAGS} \\*)] Flags permitted"
        untagged "OK [UIDVALIDITY #{result[:uid_validity]}] UIDs valid"
        untagged "OK [UIDNEXT #{result[:uid_next]}] Predicted next UID"
        tagged tag, "OK [#{read_only ? "READ-ONLY" : "READ-WRITE"}] #{read_only ? "EXAMINE" : "SELECT"} completed"
      end

      def close(tag)
        @store.expunge(@selected[:mailbox_id]) unless @read_only
        @selected = nil
        @uids = []
        @flags = {}
        tagged tag, "OK CLOSE completed"
      end

      def expunge(tag)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        result = @store.expunge(@selected[:mailbox_id])
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

      FETCH_MACROS = {
        "ALL" => %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE],
        "FAST" => %w[FLAGS INTERNALDATE RFC822.SIZE],
        "FULL" => %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY]
      }.freeze

      METADATA_ITEMS = %w[UID FLAGS INTERNALDATE RFC822.SIZE].freeze

      def fetch(tag, args, uid_mode)
        set = args.shift
        return tagged(tag, "BAD FETCH expects a sequence set") unless set.is_a?(String)

        items = args.take_while { |a| a != :rparen }.reject { |a| a == :lparen }.map { |a| a.to_s }
        items = items.flat_map { |i| FETCH_MACROS[i.upcase] || [ i ] }
        items << "UID" if uid_mode && items.none? { |i| i.casecmp?("UID") }
        return tagged(tag, "BAD FETCH expects data items") if items.empty?

        wanted = resolve_set(set, uid_mode)
        need_raw = items.any? { |i| !METADATA_ITEMS.include?(i.upcase) }
        messages = fetch_messages(wanted.map(&:last), need_raw)
        newly_seen = mark_fetched_seen(items, wanted.filter_map { |_seq, uid| messages[uid] })

        wanted.each do |seq, uid|
          msg = messages[uid] or next
          untagged "#{seq} FETCH (#{fetch_items(msg, items, announce_seen: newly_seen.include?(uid)).join(" ")})"
        end
        tagged tag, "OK FETCH completed"
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
        (result[:messages] || []).each { |uid, new_flags| @flags[uid] = new_flags }
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
        set, item = args.shift(2)
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
        return tagged(tag, "OK STORE completed") if wanted.empty?

        result = @store.store_flags(@selected[:mailbox_id], wanted.map(&:last), mode, flags)
        updated = (result[:messages] || []).to_h { |uid, new_flags| [ uid, new_flags ] }
        updated.each { |uid, new_flags| @flags[uid] = new_flags }

        unless silent
          wanted.each do |seq, uid|
            next unless updated.key?(uid)

            uid_part = uid_mode ? " UID #{uid}" : ""
            untagged "#{seq} FETCH (FLAGS (#{updated[uid].join(" ")})#{uid_part})"
          end
        end
        tagged tag, "OK STORE completed"
      end

      def copy(tag, args, uid_mode)
        set, dest = args
        return tagged(tag, "BAD COPY expects a sequence set and mailbox") unless set.is_a?(String) && dest.is_a?(String)

        wanted = resolve_set(set, uid_mode)
        return tagged(tag, "OK COPY completed (nothing to copy)") if wanted.empty?

        result = @store.copy(@selected[:mailbox_id], wanted.map(&:last), dest)
        if result[:error]
          code = result[:code] == :notfound ? "[TRYCREATE] " : ""
          tagged tag, "NO #{code}COPY failed: #{result[:error]}"
        else
          copyuid = "#{result[:uid_validity]} #{result[:src_uids].join(",")} #{result[:dest_uids].join(",")}"
          tagged tag, "OK [COPYUID #{copyuid}] COPY completed"
        end
      end

      # -- SEARCH ----------------------------------------------------------------

      RAW_SEARCH_KEYS = %w[HEADER FROM TO CC BCC SUBJECT TEXT BODY SENTBEFORE SENTON SENTSINCE].freeze

      def search(tag, args, uid_mode)
        criteria = args.dup
        if criteria.first.is_a?(String) && criteria.first.casecmp?("CHARSET")
          criteria.shift(2)
        end

        need_raw = criteria.any? { |t| t.is_a?(String) && RAW_SEARCH_KEYS.include?(t.upcase) }
        all = @uids.each_with_index.map { |uid, idx| [ idx + 1, uid ] }
        messages = fetch_messages(@uids, need_raw)

        matchers = []
        matchers << parse_search_key(criteria, uid_mode) until criteria.empty?
        matchers.compact!

        hits = all.select do |seq, uid|
          msg = messages[uid]
          msg && matchers.all? { |k| k.call(seq, msg) }
        end
        untagged "SEARCH #{hits.map { |seq, uid| uid_mode ? uid : seq }.join(" ")}".rstrip
        tagged tag, "OK SEARCH completed"
      end

      def parse_search_key(toks, uid_mode)
        tok = toks.shift
        return nil if tok.nil?

        if tok == :lparen
          keys = []
          keys << parse_search_key(toks, uid_mode) until toks.empty? || toks.first == :rparen
          toks.shift
          keys.compact!
          return ->(seq, msg) { keys.all? { |k| k.call(seq, msg) } }
        end
        return nil unless tok.is_a?(String)

        case tok.upcase
        when "ALL" then ->(_seq, _msg) { true }
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
        when "RECENT", "NEW" then ->(_seq, _msg) { false }
        when "OLD" then ->(_seq, _msg) { true }
        when "KEYWORD" then flag_key(toks.shift.to_s)
        when "UNKEYWORD" then negate(flag_key(toks.shift.to_s))
        when "NOT" then negate(parse_search_key(toks, uid_mode))
        when "OR"
          a = parse_search_key(toks, uid_mode)
          b = parse_search_key(toks, uid_mode)
          ->(seq, msg) { (a.nil? || a.call(seq, msg)) || (b.nil? || b.call(seq, msg)) }
        when "UID"
          uids = resolve_set(toks.shift.to_s, true).map(&:last)
          ->(_seq, msg) { uids.include?(msg[:uid]) }
        when "LARGER"  then min = toks.shift.to_i; ->(_seq, msg) { msg[:size] > min }
        when "SMALLER" then max = toks.shift.to_i; ->(_seq, msg) { msg[:size] < max }
        when "SINCE"  then date_key(toks.shift) { |msg_day, day| msg_day >= day }
        when "BEFORE" then date_key(toks.shift) { |msg_day, day| msg_day < day }
        when "ON"     then date_key(toks.shift) { |msg_day, day| msg_day == day }
        when "SENTSINCE"  then date_key(toks.shift) { |msg_day, day| msg_day >= day }
        when "SENTBEFORE" then date_key(toks.shift) { |msg_day, day| msg_day < day }
        when "SENTON"     then date_key(toks.shift) { |msg_day, day| msg_day == day }
        when "HEADER"
          name = toks.shift.to_s
          value = toks.shift.to_s
          header_key(name, value)
        when "FROM"    then header_key("from", toks.shift.to_s)
        when "TO"      then header_key("to", toks.shift.to_s)
        when "CC"      then header_key("cc", toks.shift.to_s)
        when "BCC"     then header_key("bcc", toks.shift.to_s)
        when "SUBJECT" then header_key("subject", toks.shift.to_s)
        when "TEXT", "BODY"
          value = toks.shift.to_s.downcase
          ->(_seq, msg) { msg[:raw].to_s.downcase.include?(value) }
        when /\A[\d*][\d,:*]*\z/
          pairs = resolve_set(tok, false)
          seqs = pairs.map(&:first)
          ->(seq, _msg) { seqs.include?(seq) }
        else
          ->(_seq, _msg) { true } # unknown key: don't filter
        end
      end

      def negate(key)
        return nil if key.nil?

        ->(seq, msg) { !key.call(seq, msg) }
      end

      def flag_key(flag)
        ->(_seq, msg) { (@flags[msg[:uid]] || msg[:flags]).include?(flag) }
      end

      def date_key(str, &compare)
        day = Time.strptime(str.to_s, "%d-%b-%Y").to_i / 86_400
        ->(_seq, msg) { compare.call(msg[:internal_date] / 86_400, day) }
      rescue ArgumentError
        ->(_seq, _msg) { true }
      end

      def header_key(name, value)
        name = name.downcase
        value = value.downcase
        lambda do |_seq, msg|
          headers = Mime.parse_headers(Mime.split_header(msg[:raw].to_s)[0])
          headers[name].to_a.any? { |v| v.downcase.include?(value) }
        end
      end

      # -- APPEND ----------------------------------------------------------------

      def append(tag, args)
        name = args.shift.to_s
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
          tagged tag, "OK [APPENDUID #{result[:uid_validity]} #{result[:uid]}] APPEND completed"
        end
      end

      # -- resync ------------------------------------------------------------------

      # Refreshes the mailbox snapshot on NOOP/CHECK so clients learn about
      # newly delivered or externally deleted messages.
      def resync
        return unless @selected

        result = @store.select_mailbox(@account_id, @selected[:name])
        return if result[:error]

        new_uids = result[:messages].map(&:first)
        removed = @uids - new_uids
        added = new_uids - @uids

        @uids.each_with_index.to_a.reverse_each do |uid, idx|
          untagged "#{idx + 1} EXPUNGE" if removed.include?(uid)
        end
        @uids = new_uids
        @flags = result[:messages].to_h { |uid, flags| [ uid, flags ] }
        untagged "#{@uids.length} EXISTS" if removed.any? || added.any?
      end
    end
  end
end

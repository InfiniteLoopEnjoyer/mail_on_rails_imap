# frozen_string_literal: true

require "strscan"
require "date"
require "time"
require "securerandom"
require "mail_on_rails/scram"
require "mail_on_rails/settings"
require "mail_on_rails/netserv/config"
require "mail_on_rails/netserv/server"
require "mail_on_rails/imap/session_helpers"
require "mail_on_rails/imap/utf7"
require "mail_on_rails/imap/version"
require "mail_on_rails/imap/mime"

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
  class ImapServer < Netserv::Server
    FLAGS = "\\Answered \\Flagged \\Deleted \\Seen \\Draft"
    MAX_LITERAL_BYTES = 30 * 1024 * 1024
    # Before authentication the only literals a client legitimately sends
    # are LOGIN arguments and an AUTHENTICATE initial response - a few
    # hundred bytes. Without a separate cap, one pre-auth LITERAL+ could
    # force the full MAX_LITERAL_BYTES read before any command dispatches.
    MAX_PREAUTH_LITERAL_BYTES = 8 * 1024
    # A single command may chain several literals (e.g. LOGIN with two
    # literal arguments, or a SEARCH with literal strings), but only a
    # handful legitimately. Bound both the number of literals and their
    # combined octets per command so a client can't accumulate unbounded
    # memory in read_command by streaming an endless run of tiny (often
    # LITERAL+) literals before a single command is ever dispatched.
    MAX_COMMAND_LITERALS = 256
    # Guards against a maliciously deep SEARCH key (nested parens / NOT /
    # OR) recursing parse_search_key into a SystemStackError, which - not
    # being a StandardError - would escape the command handler and kill the
    # session thread. A legitimate search nests only a few levels.
    MAX_SEARCH_DEPTH = 64
    # Base capabilities; STARTTLS/LOGINDISABLED/AUTH are appended per-state.
    # APPENDLIMIT=<n> (RFC 7889) advertises one upload limit for every
    # mailbox - the same cap the literal reader enforces.
    # Interpolation defeats the frozen_string_literal magic comment, so
    # freeze explicitly.
    BASE_CAPABILITIES = "IMAP4rev1 UIDPLUS LITERAL+ IDLE MOVE UNSELECT NAMESPACE SPECIAL-USE CHILDREN ESEARCH WITHIN CONDSTORE ENABLE QRESYNC ID LIST-STATUS STATUS=SIZE SEARCHRES OBJECTID SAVEDATE PREVIEW REPLACE SORT THREAD=ORDEREDSUBJECT THREAD=REFERENCES APPENDLIMIT=#{MAX_LITERAL_BYTES}".freeze
    # Cap on a single (non-literal) command line, so a client can't exhaust
    # memory by sending endless bytes with no CRLF. Bulk data uses {n} IMAP
    # literals, which are bounded separately by MAX_LITERAL_BYTES. Boot-only:
    # it sizes read buffers.
    MAX_LINE = Settings.static(:imap_max_line)
    MAX_AUTH_ATTEMPTS = 3
    # Absolute per-connection lifetime (Netserv::Server's reaper), the same
    # slowloris backstop SMTP has. IMAP IDLE is legitimately long-lived
    # (re-issued at most ~every 29 min), so the default cap is generous -
    # 24h, which clients ride out with a transparent reconnect - but
    # finite: a hijacked TCP session or a forgotten client must not stay
    # authenticated for weeks. 0 disables for deployments that need
    # unbounded IDLE. Boot-only: frozen into the listener specs and sizes
    # the reaper sweep.
    SESSION_LIFETIME = Settings.static(:imap_session_seconds)

    # Accept-side anti-abuse limits (see Netserv::Server), mirroring the
    # SMTP server's set: process-wide and per-IP concurrent caps, a lockout
    # after repeated failed LOGIN/AUTHENTICATE attempts (which otherwise
    # cost a bcrypt check each, MAX_AUTH_ATTEMPTS per connection, fresh on
    # every reconnect), and a sliding-window connection rate answered with
    # a pre-greeting tarpit. 0 disables any of them.
    #
    # Read through the settings schema per check, so an admin's change
    # applies to the next connection without a restart. A constant defined
    # on a subclass still wins (the bespoke-test-server seam).
    def max_connections = tunable(:MAX_CONNECTIONS, ImapServer) { Settings[:imap_max_conn] }
    def max_connections_per_ip = tunable(:MAX_CONNECTIONS_PER_IP, ImapServer) { Settings[:imap_max_conn_per_ip] }
    def auth_lockout_failures = tunable(:AUTH_LOCKOUT_FAILURES, ImapServer) { Settings[:imap_auth_lockout_failures] }
    def auth_lockout_seconds = tunable(:AUTH_LOCKOUT_SECONDS, ImapServer) { Settings[:imap_auth_lockout_seconds] }
    def conn_rate_limit = tunable(:CONN_RATE_LIMIT, ImapServer) { Settings[:imap_conn_rate] }
    def conn_rate_window = tunable(:CONN_RATE_WINDOW, ImapServer) { Settings[:imap_conn_rate_window] }

    private

    def protocol_name = "IMAP"

    def busy_line = "* BYE Too many connections"

    def locked_line = "* BYE Too many failed authentication attempts, try later"

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
      include Netserv::HoneypotSession

      # Set by Server when per-IP auth throttling is active: a no-arg
      # callable invoked once per failed authentication attempt, and one
      # answering whether this peer's IP is currently locked out.
      attr_writer :on_auth_failure, :auth_locked

      def initialize(socket, store, spec, tls_ctx)
        @socket = socket
        @store = store
        @spec = spec
        @tls_ctx = tls_ctx
        @tls = spec[:tls] == :implicit
        @trace = spec.fetch(:trace) { Settings[:imap_trace] }
        @trace_capture = spec.fetch(:trace_capture) { Settings[:imap_trace_capture] }
        @close_reason = nil
        @protocol_errors = 0
        @account_id = nil
        @username = nil
        @idling = false
        @on_auth_failure = nil
        @auth_locked = nil
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
        # ENABLE QRESYNC switches expunge reporting from per-sequence
        # EXPUNGE lines to uid-based VANISHED responses (RFC 7162).
        @qresync = false
        @read_only = false
        @logout = false
        # SEARCHRES (RFC 5182): UIDs saved by SEARCH RETURN (SAVE),
        # referenced as "$" in later sequence sets and search keys.
        @saved_search = []
        @honeypot = false
        @honeypot_fired = false
        @honeypot_event_id = nil
      end

      # Honeypot hooks (Netserv::HoneypotSession). IMAP carries no HELO.
      def honeypot_protocol = "imap"
      def honeypot_username = @username
      def honeypot_helo = nil

      # Capabilities depend on connection state: advertise STARTTLS and
      # LOGINDISABLED until encrypted, then AUTH once it is safe to send
      # credentials.
      def capabilities
        caps = BASE_CAPABILITIES.dup
        # QUOTA needs a store that reports usage; the memory and Active
        # Record stores both do, but the capability stays honest either way.
        caps << " QUOTA QUOTA=RES-STORAGE" if @store.respond_to?(:quota)
        if @tls
          # SCRAM ahead of PLAIN: clients commonly pick the first listed
          # mechanism they support, and SCRAM keeps the password itself
          # off the wire even inside TLS. -PLUS only when this connection
          # can actually prove a binding (a real TLS socket).
          caps << " AUTH=SCRAM-SHA-256-PLUS" if Scram.channel_binding?(@socket)
          caps << " AUTH=SCRAM-SHA-256 AUTH=PLAIN SASL-IR"
        else
          caps << " STARTTLS" if @tls_ctx
          caps << " LOGINDISABLED"
        end
        caps
      end

      # Live-state snapshot for the ops UI (Server#connections). Read from
      # the web thread while the session thread runs, so plain values
      # only; a stale read costs nothing worse than a momentarily
      # out-of-date dashboard row.
      def live_info
        state = if @account_id.nil? then "pre-auth"
        elsif @idling then "IDLE #{@selected&.dig(:name)}".strip
        elsif @selected then "SELECT #{@selected[:name]}"
        else "authenticated"
        end
        { user: @username, state: state, tls: @tls }
      end

      # The transcript to persist for this session, or nil - the same
      # rules as the SMTP session's (see SmtpServer::Session): opt-in
      # (imap_trace_capture), only abnormally ended sessions, never
      # honeypot sessions (their transcript lands in the HoneypotEvent).
      # The buffer is redacted at the tap (LOGIN/AUTHENTICATE arguments,
      # challenge responses) and literals never enter it. Called by
      # Server#report_closed on the dying connection thread.
      def transcript_capture
        return nil unless @trace_capture && !honeypot_fired?
        return nil unless (reason = capture_reason)

        text = honeypot_transcript.to_s
        { transcript: text, close_reason: reason } unless text.empty?
      end

      def run
        set_timeout(session_timeout)
        untagged "OK [CAPABILITY #{capabilities}] #{honeypot_banner || "IMAP server ready"}"
        until @logout
          parts = read_command
          break unless parts

          handle(parts)
        end
        # EOF without LOGOUT; capture_reason deliberately ignores a bare
        # eof (scanners and sloppy clients produce them constantly), but
        # a session that also tripped errors keeps its dialogue.
        @close_reason = "eof" unless @logout
      rescue IO::TimeoutError
        # Idle far past the command timeout without a LOGOUT - the client
        # was abandoned rather than closed. One line per half-hour of dead
        # connection is cheap; silence would hide a client that never got
        # a reply it was waiting for.
        @close_reason = "timeout"
        @store.log(:info, "IMAP session idle timeout#{@username && " for #{@username}"} (#{peer_ip})")
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError => e
        # The peer vanished mid-session. Routine for mobile clients, so
        # :info - but never silent, or a reply lost in flight (and the
        # client-side resync it forces) leaves no server-side witness.
        # read_line pre-sets "protocol_abuse" before its over-length
        # abort; anything else here is the peer (or its network) going
        # away.
        @close_reason ||= "connection_lost"
        @store.log(:info, "IMAP connection lost#{@username && " for #{@username}"}: #{e.class}: #{e.message} (#{peer_ip})")
      rescue StandardError => e
        @close_reason = "session_error"
        @store.log(:error, "IMAP session error: #{e.class}: #{e.message} #{e.backtrace&.first}")
      ensure
        begin
          @socket.close
        rescue StandardError
          nil
        end
      end

      private

      # Why this session's transcript is worth keeping, or nil for a
      # session with nothing to diagnose (same policy as SMTP): a close
      # reason always wins; a cleanly closed session still qualifies when
      # the peer tripped protocol errors or failed every authentication
      # attempt. A bare EOF without LOGOUT stays nil deliberately.
      def capture_reason
        return @close_reason if @close_reason && @close_reason != "eof"
        return "protocol_errors" if @protocol_errors.positive?
        return "auth_failed" if @auth_attempts.positive? && @account_id.nil?

        nil
      end

      # Overridable via spec so tests can exercise the timeout close
      # reason without waiting out a real client's half hour.
      def session_timeout
        @spec[:timeout] || 1800
      end

      # -- transport ---------------------------------------------------------

      # Reads one line, capped at MAX_LINE. Returns nil at EOF; aborts the
      # session on an over-length line rather than draining attacker bytes.
      def read_line
        line = @socket.gets("\r\n", MAX_LINE)
        return nil if line.nil?

        if !line.end_with?("\r\n") && line.bytesize >= MAX_LINE
          untagged "BAD Command line too long"
          @close_reason = "protocol_abuse" # before the raise; run's rescue keeps it
          raise IOError, "command line too long"
        end
        line
      end

      # Reads one command; IMAP literals ({n}\r\n) are read in full and kept
      # as [:lit, data] elements between the line fragments. Loops (rather
      # than recursing) past refused literals: Ruby has no tail-call
      # elimination, so a client streaming oversize literals must not grow
      # the session-thread stack per refusal.
      def read_command
        loop do
          parts = read_one_command
          return parts unless parts == :refused
        end
      end

      def read_one_command
        line = read_line
        return nil unless line

        parts = [ line ]
        literal_count = 0
        literal_octets = 0
        while (m = parts.last.match(/\{(\d+)(\+)?\}\r\n\z/))
          size = m[1].to_i
          non_sync = !m[2].nil?
          literal_count += 1
          literal_octets += size
          # A single over-size literal, too many literals in one command, or
          # too many octets in aggregate: all refuse the same way, draining
          # any LITERAL+ payload so the stream stays framed.
          limit = @account_id ? MAX_LITERAL_BYTES : [ MAX_PREAUTH_LITERAL_BYTES, MAX_LITERAL_BYTES ].min
          if size > limit || literal_count > MAX_COMMAND_LITERALS ||
             literal_octets > limit
            # Except pre-auth LITERAL+: there the drain that keeps the
            # stream framed is itself the forced read being refused, so
            # hang up instead - nothing legitimate is lost, no real
            # client sends large literals before authenticating.
            if !@account_id && non_sync
              tagged parts.first.split(" ", 2).first.to_s, "NO [TOOBIG] literal too large before authentication"
              untagged "BYE Goodbye"
              return nil
            end
            return refuse_literal(parts.first, size, non_sync: non_sync)
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
      # Returns :refused so read_command's loop moves on to the next
      # command, or nil at EOF.
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
        # RFC 7889/4469: over-limit uploads get the TOOBIG response code
        # so clients report "too large" instead of retrying.
        tagged tag, "NO [TOOBIG] literal too large"
        :refused
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
        honeypot_transcript.outbound("* #{text}")
        trace("=>", "* #{text}")
        @socket.write("* #{text}\r\n")
      end

      def tagged(tag, text)
        honeypot_transcript.outbound("#{tag} #{text}")
        trace("=>", "#{tag} #{text}")
        @socket.write("#{tag} #{text}\r\n")
      end

      # One traced protocol line, opt-in via imap_trace (resolved at session
      # start, like smtp_trace: new connections). FETCH responses embed whole
      # message literals, so lines are flattened and truncated - the trace is
      # for protocol flow, not message content. Logged at :info because that
      # is production's default log level and the setting is the opt-in.
      def trace(direction, line)
        return unless @trace

        flat = line.gsub(/\r?\n/, '\n')
        flat = "#{flat[0, 400]}... (#{line.bytesize} bytes)" if flat.size > 400
        @store.log(:info, "IMAP #{direction} #{flat} (#{peer_ip})")
      end

      # Redacts credentials from a command line before it enters the honeypot
      # transcript - the same no-password policy the SMTP tracer keeps. LOGIN's
      # user and password both go (parsing a quoted/literal username safely is
      # not worth the risk of leaking the password beside it); AUTHENTICATE
      # keeps its mechanism but drops any initial response. Everything else is
      # recorded verbatim - it is the intel.
      def redact_imap(line)
        case line
        when /\A(\S+)\s+(LOGIN)\b/i
          "#{Regexp.last_match(1)} #{Regexp.last_match(2).upcase} [redacted]"
        when /\A(\S+)\s+(AUTHENTICATE)\s+(\S+)(.*)/i
          rest = Regexp.last_match(4).to_s.strip.empty? ? "" : " [redacted]"
          "#{Regexp.last_match(1)} #{Regexp.last_match(2).upcase} #{Regexp.last_match(3)}#{rest}"
        else
          line
        end
      end

      # -- dispatch ----------------------------------------------------------

      def handle(parts)
        # The command line only (literals - message data - stay out of the
        # transcript). LOGIN/AUTHENTICATE arguments are redacted; a literal
        # password never reaches here anyway, it arrives as a [:lit, data] part.
        raw = parts.first.to_s.chomp
        redacted = redact_imap(raw)
        honeypot_transcript.inbound(redacted)
        trace("<=", redacted)
        # Exploit-probe payloads are recognised and refused, never dispatched.
        if (signature = Netserv::ProbeSignatures.match(raw))
          trigger_honeypot("exploit_probe", signature: signature)
          return tagged(raw[/\A\S+/] || "*", "BAD Unknown command")
        end

        tokens = Lexer.new(parts).tokens
        tag = tokens.shift
        name = tokens.shift
        unless tag && name.is_a?(String)
          @protocol_errors += 1
          return untagged("BAD Empty command")
        end

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
        when "LOGOUT"       then untagged "BYE Logging out"; tagged tag, "OK LOGOUT completed"; @logout = true
        when "ID"           then id(tag)
        when "LOGIN"        then login(tag, args)
        when "AUTHENTICATE" then authenticate(tag, args)
        when "STARTTLS"     then starttls(tag)
        when "NAMESPACE"    then require_auth(tag) { namespace(tag) }
        when "ENABLE"       then require_auth(tag) { enable(tag, args) }
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
        when "REPLACE"      then require_selected(tag) { replace(tag, args, uid_mode) }
        when "CLOSE"        then require_selected(tag) { close(tag) }
        when "UNSELECT"     then require_selected(tag) { unselect(tag) }
        when "EXPUNGE"      then require_selected(tag) { expunge(tag, args, uid_mode) }
        when "FETCH"        then require_selected(tag) { fetch(tag, args, uid_mode) }
        when "STORE"        then require_selected(tag) { store(tag, args, uid_mode) }
        when "COPY"         then require_selected(tag) { copy(tag, args, uid_mode) }
        when "MOVE"         then require_selected(tag) { move(tag, args, uid_mode) }
        when "SEARCH"       then require_selected(tag) { search(tag, args, uid_mode) }
        when "SORT"         then require_selected(tag) { sort(tag, args, uid_mode) }
        when "THREAD"       then require_selected(tag) { thread(tag, args, uid_mode) }
        when "GETQUOTA", "GETQUOTAROOT", "SETQUOTA"
          return tagged(tag, "BAD Unknown command #{name}") unless @store.respond_to?(:quota)

          require_auth(tag) do
            case name
            when "GETQUOTA" then getquota(tag, args)
            when "GETQUOTAROOT" then getquotaroot(tag, args)
            else tagged tag, "NO [NOPERM] Quotas are administered in the web UI"
            end
          end
        when "IDLE"         then require_auth(tag) { idle(tag) }
        else
          @protocol_errors += 1
          tagged tag, "BAD Unknown command #{name}"
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

      # Maps a store error onto the IMAP response code (RFC 5530) the
      # client uses to distinguish "create the mailbox and retry" from
      # "free up space".
      def error_response_code(result)
        case result[:code]
        when :notfound then "[TRYCREATE] "
        when :overquota then "[OVERQUOTA] "
        when :unavailable then "[UNAVAILABLE] "
        else ""
        end
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
        # Plaintext bytes pipelined behind STARTTLS must never be executed
        # as post-handshake commands (the CVE-2011-0411 class). They are
        # dropped here because the new SSLSocket reads the fd directly,
        # while anything read_line over-read sits in the old IO's buffer and
        # dies with it. Anything that gives the session a buffered reader
        # spanning the TLS swap reintroduces the injection - keep the
        # pre-TLS buffer unreachable from here on.
        @socket = Netserv::Tls.accept(io_for(@socket), @tls_ctx)
        @tls = true
        set_timeout(session_timeout)
        # Discard pre-TLS session state; the client re-authenticates.
        @account_id = nil
        @username = nil
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
        return if reject_reauth(tag, "LOGIN")

        user, pass = args
        complete_login(tag, "LOGIN", user, pass)
      end

      # RFC 3501 §6.2: LOGIN/AUTHENTICATE are only valid in the not-
      # authenticated state. Beyond the letter of the spec this is an
      # isolation guard: complete_login only replaces @account_id, so a
      # second login would leave the *previous* account's @selected
      # mailbox_id in place and serve its mail to the new identity.
      def reject_reauth(tag, verb)
        return false unless @account_id

        tagged tag, "BAD #{verb} not permitted in authenticated state"
        true
      end

      def authenticate(tag, args)
        return tagged(tag, "NO [PRIVACYREQUIRED] STARTTLS required before AUTHENTICATE") if tls_required?
        return if reject_reauth(tag, "AUTHENTICATE")

        mechanism, initial = args
        case mechanism.to_s.upcase
        when "PLAIN" then authenticate_plain(tag, initial)
        when "SCRAM-SHA-256" then authenticate_scram(tag, initial)
        when "SCRAM-SHA-256-PLUS"
          if Scram.channel_binding?(@socket)
            authenticate_scram(tag, initial, plus: true)
          else
            tagged(tag, "NO Unsupported authentication mechanism")
          end
        else tagged(tag, "NO Unsupported authentication mechanism")
        end
      rescue Imap::SessionHelpers::InvalidBase64
        # Only base64 the *client* sent. Anything else that raises in here
        # is ours, and belongs in the generic handler's "BAD Internal
        # error" with a logged backtrace - not blamed on the client.
        tagged tag, "BAD Invalid base64"
      end

      def authenticate_plain(tag, initial)
        initial = sasl_challenge(tag, "") { return } if initial.nil?
        return if initial.nil?

        _authzid, user, pass = decode_sasl_plain(initial)
        complete_login(tag, "AUTHENTICATE", user, pass)
      end

      # Sends a SASL continuation and reads the client's base64 reply.
      # Yields (to abort the command) on connection loss; returns nil after
      # answering a "*" cancellation.
      def sasl_challenge(tag, data)
        # The server-first challenge carries SCRAM salt/iterations and the
        # client reply carries a credential proof - both are verifier material,
        # so the transcript keeps only placeholders (a "*" cancel is recorded).
        honeypot_transcript.outbound("+ [redacted]")
        @socket.write("+ #{data}\r\n")
        line = read_line
        yield unless line

        text = line.chomp("\r\n")
        honeypot_transcript.inbound(text == "*" ? "*" : "[redacted]")
        return cancel_auth(tag) if text == "*"

        text
      end

      # A "*" cancellation still costs a per-connection attempt. Otherwise a
      # client could loop AUTHENTICATE/cancel without bound, and for SCRAM
      # each loop first drives a store credential lookup (line ordering in
      # authenticate_scram) that the throttle never sees - it only trips on
      # *recorded* failures. Counting the cancel here caps the loop at
      # MAX_AUTH_ATTEMPTS and hangs the connection up like a real failure.
      def cancel_auth(tag)
        @auth_attempts += 1
        tagged tag, "BAD Authentication cancelled"
        disconnect_if_attempts_exhausted
        nil
      end

      # Server side of SCRAM-SHA-256 (RFC 5802/7677) and, over real TLS,
      # SCRAM-SHA-256-PLUS with tls-exporter / tls-server-end-point
      # channel binding (RFC 9266 / 5929). The store supplies only
      # verifier material (StoredKey/ServerKey) - the password itself
      # never travels on this path.
      def authenticate_scram(tag, initial, plus: false)
        client_first = initial || (sasl_challenge(tag, "") { return } or return)
        gs2, bare, cb_type, cb_declined = Scram.split_gs2(decode_base64(client_first))
        return tagged(tag, "BAD Malformed SCRAM message") if gs2.nil?

        cb_data = nil
        if plus
          # -PLUS is only ever dispatched with channel binding available;
          # the gs2 header must then name a type this connection can prove.
          return tagged(tag, "BAD Channel binding required for SCRAM-SHA-256-PLUS") unless cb_type

          cb_data = Scram.channel_binding_data(@socket, cb_type)
          return tagged(tag, "NO Unsupported channel binding type #{cb_type}") unless cb_data
        elsif cb_type
          message = Scram.channel_binding?(@socket) ? "NO Channel binding requires SCRAM-SHA-256-PLUS" : "NO Channel binding not supported"
          return tagged(tag, message)
        elsif cb_declined && Scram.channel_binding?(@socket)
          # RFC 5802 §6: "y" claims the server never advertised -PLUS.
          # This one does, so the claim can only mean the advertisement
          # was stripped - fail rather than complete a downgraded exchange.
          return tagged(tag, "NO Channel binding downgrade detected")
        end

        attrs = scram_attrs(bare)
        user = attrs["n"].to_s.gsub("=2C", ",").gsub("=3D", "=")
        cnonce = attrs["r"].to_s
        return tagged(tag, "BAD Malformed SCRAM message") if user.empty? || cnonce.empty?

        return if ip_lockout_refusal(tag, "AUTHENTICATE", user)

        creds = @store.scram_credentials(user, ip: throttle_ip)
        return auth_throttled(tag, "AUTHENTICATE", user, creds[:retry_after]) if creds[:throttled]

        if creds[:error]
          # :notfound is a real credential miss (unknown account, or one
          # whose password predates SCRAM derivation); anything else is the
          # store being unreachable.
          return store_unavailable(tag, "AUTHENTICATE") unless creds[:code] == :notfound

          return scram_failure(tag, user)
        end

        nonce = cnonce + SecureRandom.alphanumeric(24)
        server_first = "r=#{nonce},s=#{creds[:salt_base64]},i=#{creds[:iterations]}"
        reply = sasl_challenge(tag, [ server_first ].pack("m0")) { return } or return

        client_final = decode_base64(reply)
        final_attrs = scram_attrs(client_final)
        proof = decode_base64(final_attrs["p"])
        without_proof = client_final[/\A(.*),p=[^,]*\z/m, 1].to_s
        auth_message = "#{bare},#{server_first},#{without_proof}"

        # Store-supplied, so deliberately not wrapped: a verifier that
        # won't decode is a server fault, not the client's bad base64.
        # c= carries gs2-header + raw cb data (RFC 5802 §5.1), so a bound
        # exchange only verifies against this TLS connection's own
        # binding - a MITM relaying the exchange has a different one.
        stored_key = creds[:stored_key_base64].unpack1("m0")
        unless final_attrs["r"] == nonce &&
               final_attrs["c"] == [ gs2.b + cb_data.to_s.b ].pack("m0") &&
               Scram.valid_proof?(stored_key, auth_message, proof)
          return scram_failure(tag, user)
        end

        server_key = creds[:server_key_base64].unpack1("m0")
        verifier = "v=#{[ Scram.server_signature(server_key, auth_message) ].pack("m0")}"
        empty = sasl_challenge(tag, [ verifier ].pack("m0")) { return } or return
        return tagged(tag, "BAD Unexpected final client response") unless empty.empty?

        @account_id = creds[:account_id]
        @username = creds[:email]
        @store.log(:info, "IMAP login #{creds[:email]} (#{peer_ip}, SCRAM#{"-PLUS" if plus})")
        honeypot_login! if creds[:honeypot]
        tagged tag, "OK [CAPABILITY #{capabilities}] AUTHENTICATE completed"
      end

      def scram_attrs(message)
        message.split(",").filter_map { |part| [ part[0], part[2..] ] if part[1] == "=" }.to_h
      end

      # A SCRAM attempt the daemon rejected on its own: the proof is checked
      # here against verifier material, so the store never sees the failure
      # and has to be told, or SCRAM would be an unthrottled way around the
      # LOGIN throttle.
      def scram_failure(tag, user)
        @store.record_auth_failure(user.to_s, ip: throttle_ip)
        auth_failure(tag, user)
      end

      # Shared failed-auth accounting for LOGIN/AUTHENTICATE paths that
      # don't go through the store's password check. Reported to the
      # accept-side per-IP throttle before the reply is written, so a
      # lockout is in force by the time the client can react to the NO -
      # same ordering as the SMTP session. Store-throttled and store-error
      # outcomes never come through here: the credentials were not checked,
      # so they must not count toward the lockout.
      def auth_failure(tag, user)
        @auth_attempts += 1
        @on_auth_failure&.call
        @store.log(:warn, "IMAP auth failed for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip}, attempt #{@auth_attempts}/#{MAX_AUTH_ATTEMPTS})")
        tagged tag, "NO [AUTHENTICATIONFAILED] Invalid credentials"
        disconnect_if_attempts_exhausted
      end

      # The store is refusing attempts for this address or account (see the
      # contract's throttling section). Answered with UNAVAILABLE, not
      # AUTHENTICATIONFAILED: the credentials were never checked, and a
      # client told its password is wrong re-prompts the user for one that
      # is probably fine. It still burns a per-connection attempt, so a
      # throttled client is hung up on rather than left spinning.
      def auth_throttled(tag, verb, user, retry_after)
        @auth_attempts += 1
        @store.log(:warn, "IMAP #{verb} throttled for #{user.to_s.empty? ? "(empty)" : user} " \
                          "(#{peer_ip}), #{retry_after}s remaining")
        tagged tag, "NO [UNAVAILABLE] Too many authentication failures, try again later"
        disconnect_if_attempts_exhausted
      end

      # The accept-side per-IP lockout, re-checked at each attempt: it is
      # otherwise enforced only on NEW connections, so sessions already
      # open when the IP locked would keep their full attempt budget -
      # each guess still costing a store credential check. Accounted like
      # auth_throttled (the credentials are never checked, so the lockout
      # is not extended, but the attempt burns per-connection budget so a
      # locked peer is hung up on rather than left spinning).
      def ip_lockout_refusal(tag, verb, user)
        return false unless @auth_locked&.call

        @auth_attempts += 1
        @store.log(:warn, "IMAP #{verb} refused for #{user.to_s.empty? ? "(empty)" : user}: IP locked out (#{peer_ip})")
        tagged tag, "NO [UNAVAILABLE] Too many authentication failures, try again later"
        disconnect_if_attempts_exhausted
        true
      end

      def disconnect_if_attempts_exhausted
        return if @auth_attempts < MAX_AUTH_ATTEMPTS

        untagged "BYE Too many failed authentication attempts"
        @logout = true
      end

      # The address the throttle counts against. peer_ip degrades to "?"
      # when the socket can't answer; that is a log placeholder, not an
      # address, and must not become a throttle key of its own.
      def throttle_ip
        ip = peer_ip
        ip == "?" ? nil : ip
      end

      # Shared LOGIN/AUTHENTICATE outcome. Failed attempts are capped like
      # the SMTP server's: past MAX_AUTH_ATTEMPTS the connection is dropped,
      # so a single connection can't brute-force credentials (each attempt
      # costs a bcrypt check).
      def complete_login(tag, verb, user, pass)
        return if ip_lockout_refusal(tag, verb, user)

        result = @store.authenticate(user.to_s, pass.to_s, ip: throttle_ip)
        if result[:account_id]
          @account_id = result[:account_id]
          @username = result[:email]
          @store.log(:info, "IMAP login #{result[:email]} (#{peer_ip})")
          # A login against a canary can only be an attacker: record it and ban
          # the source, but let them in so we observe what they FETCH/SEARCH.
          honeypot_login! if result[:honeypot]
          tagged tag, "OK [CAPABILITY #{capabilities}] #{verb} completed"
        elsif result[:throttled]
          auth_throttled(tag, verb, user, result[:retry_after])
        elsif result[:error]
          store_unavailable(tag, verb)
        else
          auth_failure(tag, user)
        end
      end

      # A store error during authentication means the app is unreachable,
      # not that the credentials are wrong. Answer with a temporary failure
      # (RFC 5530 UNAVAILABLE) so clients keep the saved password and retry
      # quietly instead of re-prompting the user, and don't count it toward
      # MAX_AUTH_ATTEMPTS.
      def store_unavailable(tag, verb)
        @store.log(:warn, "#{verb} temporary failure (#{peer_ip}): store unreachable")
        tagged tag, "NO [UNAVAILABLE] Temporary server error, try again later"
      end

      def id(tag)
        if honeypot_banner
          untagged %(ID ("name" "#{honeypot_banner}"))
        else
          # NIL rather than name+version: the ID response is otherwise a
          # free fingerprint for scanners (RFC 2971 allows NIL).
          untagged "ID NIL"
        end
        tagged tag, "OK ID completed"
      end

      def namespace(tag)
        untagged %(NAMESPACE (("" "/")) NIL NIL)
        tagged tag, "OK NAMESPACE completed"
      end

      # RFC 5161. Only extensions that change server behavior are
      # enableable; QRESYNC implies CONDSTORE (RFC 7162).
      def enable(tag, args)
        requested = args.select { |a| a.is_a?(String) }.map(&:upcase)
        enabled = requested & %w[CONDSTORE QRESYNC]
        @condstore = true if enabled.any?
        @qresync = true if enabled.include?("QRESYNC")
        untagged "ENABLED#{enabled.empty? ? "" : " #{enabled.join(" ")}"}"
        tagged tag, "OK ENABLE completed"
      end

      # RFC 6154 well-known mailboxes, advertised via SPECIAL-USE
      # attributes so clients auto-map their folders.
      SPECIAL_USE = {
        "Sent" => "\\Sent", "Drafts" => "\\Drafts", "Trash" => "\\Trash", "Junk" => "\\Junk"
      }.freeze

      def list(tag, args, verb:)
        # RFC 5258 selection options before the reference. SPECIAL-USE is
        # the only one supported (RFC 6154 makes it mandatory with the
        # capability advertised): limit the listing to the special-use
        # mailboxes.
        special_only = false
        if verb == "LIST" && args.first == :lparen
          args.shift
          until args.first == :rparen
            option = args.shift
            unless option.is_a?(String) && option.casecmp?("SPECIAL-USE")
              return tagged(tag, "BAD Unknown LIST selection option #{option}")
            end

            special_only = true
          end
          args.shift
        end

        ref, pattern = args.shift(2)
        return tagged(tag, "BAD #{verb} expects 2 arguments") if pattern.nil?

        status_items = nil
        if args.first.is_a?(String) && args.first.casecmp?("RETURN")
          return tagged(tag, "BAD #{verb} does not take RETURN options") unless verb == "LIST"

          status_items = parse_list_return(args)
          return tagged(tag, "BAD #{status_items}") if status_items.is_a?(String)
        end

        if pattern.empty?
          untagged %(#{verb} (\\Noselect) "/" "")
        else
          regex = wildcard_regex(Imap::Utf7.decode(ref.to_s + pattern))
          names = mailbox_names
          names.each do |name|
            next unless name.match?(regex)
            next if special_only && !SPECIAL_USE.key?(name)

            untagged %(#{verb} (#{list_attributes(name, names)}) "/" #{Imap::Mime.quote(Imap::Utf7.encode(name))})
            emit_status(name, status_items) if status_items
          end
        end
        tagged tag, "OK #{verb} completed"
      end

      # Parses "RETURN (STATUS (attrs...))" (RFC 5819) off the LIST
      # argument list. Returns the STATUS attribute names, nil when the
      # RETURN list is empty, or a String error for a BAD reply - unknown
      # return options must be rejected, not ignored (RFC 5258 §3).
      # SPECIAL-USE (RFC 6154 §4, what iOS Mail sends) is accepted as a
      # no-op: list_attributes already puts the special-use flags on every
      # LIST response.
      def parse_list_return(args)
        args.shift # RETURN
        return "LIST RETURN expects an option list" unless args.shift == :lparen

        items = nil
        until args.first == :rparen
          option = args.shift
          return "LIST RETURN expects an option list" if option.nil?

          if option.is_a?(String) && option.casecmp?("SPECIAL-USE")
            next
          elsif option.is_a?(String) && option.casecmp?("STATUS") && args.first == :lparen
            args.shift
            items = []
            items << args.shift.to_s.upcase until args.first == :rparen || args.empty?
            args.shift
            return "STATUS expects at least one attribute" if items.empty?
            if (unknown = items.find { |i| !STATUS_ATTRS.include?(i) })
              return "Unknown STATUS attribute #{unknown}"
            end
          else
            return "Unknown LIST RETURN option #{option}"
          end
        end
        items
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
        name = mailbox_name_arg(tag, args.first, "CREATE") or return

        # A trailing hierarchy separator only declares the intent to
        # create children under the name (RFC 3501 §6.3.3).
        name = name.chomp("/")
        create_missing_parents(name)
        result = @store.create_mailbox(@account_id, name)
        if result[:error]
          tagged tag, "NO #{result[:code] == :exists ? "[ALREADYEXISTS] " : ""}CREATE failed: #{result[:error]}"
        else
          # RFC 8474: the new mailbox's object id rides the tagged OK.
          code = result[:mailbox_object_id] ? "[MAILBOXID (#{result[:mailbox_object_id]})] " : ""
          tagged tag, "OK #{code}CREATE completed"
        end
      end

      # BAD for names no client should ever send (control characters);
      # a plain error string for structurally invalid hierarchy.
      def mailbox_name_error(name)
        return "BAD Mailbox name contains control characters" if name.match?(/[\x00-\x1f\x7f]/)
        return "invalid mailbox name" if name.start_with?("/") || name.include?("//")

        nil
      end

      # Shared gate for every command that takes a client-supplied mailbox
      # name: 7-bit on the wire, decoded from modified UTF-7, then the
      # same structural validation CREATE enforces - a name planted with
      # control bytes via the store or admin API must not be addressable
      # from any command. Replies and returns nil when the name is
      # unusable, else returns the decoded name.
      def mailbox_name_arg(tag, arg, command)
        unless arg.to_s.ascii_only?
          tagged tag, "BAD Mailbox name must be 7-bit (modified UTF-7)"
          return nil
        end

        name = Imap::Utf7.decode(arg.to_s)
        if name.empty?
          tagged tag, "BAD #{command} expects a mailbox name"
          return nil
        end
        if (error = mailbox_name_error(name))
          tagged tag, error.start_with?("BAD") ? error : "NO #{command} failed: #{error}"
          return nil
        end
        name
      end

      # RFC 3501 §6.3.3/§6.3.5: a name with hierarchy separators SHOULD
      # cause any missing superior names to be created too.
      def create_missing_parents(name)
        existing = mailbox_names
        prefix = +""
        name.split("/")[0..-2].each do |component|
          prefix << "/" unless prefix.empty?
          prefix << component
          @store.create_mailbox(@account_id, prefix.dup) unless existing.include?(prefix)
        end
      end

      def delete(tag, args)
        name = mailbox_name_arg(tag, args.first, "DELETE") or return
        return tagged(tag, "NO Cannot delete INBOX") if name.casecmp?("INBOX")

        result = @store.delete_mailbox(@account_id, name)
        if result[:error]
          tagged tag, "NO #{result[:code] == :notfound ? "[NONEXISTENT] " : ""}DELETE failed: #{result[:error]}"
        else
          tagged tag, "OK DELETE completed"
        end
      end

      def rename(tag, args)
        from = mailbox_name_arg(tag, args.first, "RENAME") or return
        to = mailbox_name_arg(tag, args[1], "RENAME") or return
        return rename_inbox(tag, to) if from.casecmp?("INBOX")

        create_missing_parents(to)
        result = @store.rename_mailbox(@account_id, from, to)
        if result[:error]
          code = { exists: "[ALREADYEXISTS] ", notfound: "[NONEXISTENT] " }[result[:code]] || ""
          tagged tag, "NO #{code}RENAME failed: #{result[:error]}"
        else
          # The selected mailbox keeps its id across a rename; only the
          # name (used by resync) needs updating.
          if @selected && (@selected[:name] == from || @selected[:name].start_with?("#{from}/"))
            @selected[:name] = to + @selected[:name][from.length..]
          end
          tagged tag, "OK RENAME completed"
        end
      end

      # RFC 3501 §6.3.5: renaming INBOX is special - its messages move to
      # a newly created mailbox while INBOX itself (and any children)
      # remain in place. Sessions with INBOX selected learn about the
      # moved messages through their next resync.
      def rename_inbox(tag, to)
        if to.casecmp?("INBOX") || mailbox_names.include?(to)
          return tagged(tag, "NO [ALREADYEXISTS] RENAME failed: mailbox exists")
        end

        create_missing_parents(to)
        result = @store.create_mailbox(@account_id, to)
        return tagged(tag, "NO [ALREADYEXISTS] RENAME failed: #{result[:error]}") if result[:error]

        inbox = @store.select_mailbox(@account_id, "INBOX")
        uids = inbox[:messages].map(&:first)
        @store.move(inbox[:mailbox_id], uids, to) if uids.any?
        tagged tag, "OK RENAME completed"
      end

      STATUS_ATTRS = %w[MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY HIGHESTMODSEQ SIZE APPENDLIMIT MAILBOXID].freeze

      def status(tag, args)
        name = mailbox_name_arg(tag, args.shift, "STATUS") or return
        # The attribute list is mandatory and non-empty per the grammar,
        # and unknown attributes are BAD, not silently skipped.
        return tagged(tag, "BAD STATUS expects a mailbox and attribute list") if args.first != :lparen

        items = args.select { |a| a.is_a?(String) }.map(&:upcase)
        return tagged(tag, "BAD STATUS expects at least one attribute") if items.empty?
        if (unknown = items.find { |i| !STATUS_ATTRS.include?(i) })
          return tagged(tag, "BAD Unknown STATUS attribute #{unknown}")
        end

        return tagged(tag, "NO [NONEXISTENT] STATUS failed: no such mailbox") unless emit_status(name, items)

        tagged tag, "OK STATUS completed"
      end

      # Sends the untagged STATUS line for +name+; false when the mailbox
      # doesn't exist. Shared between STATUS and LIST RETURN (STATUS ...)
      # (RFC 5819). STATUS (HIGHESTMODSEQ) in either form is a CONDSTORE
      # enabling command (RFC 7162 §3.1).
      def emit_status(name, items)
        @condstore = true if items.include?("HIGHESTMODSEQ")
        result = @store.status(@account_id, name)
        return false if result[:error]

        values = {
          "MESSAGES" => result[:messages],
          "RECENT" => 0,
          "UNSEEN" => result[:unseen],
          "UIDNEXT" => result[:uid_next],
          "UIDVALIDITY" => result[:uid_validity],
          "HIGHESTMODSEQ" => result[:highest_modseq] || 1,
          "SIZE" => result[:size] || 0,
          "APPENDLIMIT" => MAX_LITERAL_BYTES,
          "MAILBOXID" => "(#{result[:mailbox_object_id]})"
        }
        pairs = items.map { |i| "#{i} #{values[i]}" }
        untagged "STATUS #{Imap::Mime.quote(Imap::Utf7.encode(name))} (#{pairs.join(" ")})"
        true
      end

      def select(tag, args, read_only:)
        name = mailbox_name_arg(tag, args.first, read_only ? "EXAMINE" : "SELECT") or return

        @condstore = true if args.any? { |a| a.is_a?(String) && a.casecmp?("CONDSTORE") }
        qresync = parse_qresync_param(args)
        return tagged(tag, "BAD #{qresync}") if qresync.is_a?(String)
        return tagged(tag, "BAD QRESYNC parameter requires ENABLE QRESYNC") if qresync && !@qresync

        was_selected = !@selected.nil?
        result = @store.select_mailbox(@account_id, name)
        if result[:error]
          @selected = nil
          return tagged(tag, "NO SELECT failed: no such mailbox")
        end

        # RFC 7162 §3.2.11: QRESYNC sessions are told the previous mailbox
        # is closed before any responses for the new one.
        untagged "OK [CLOSED] Previous mailbox closed" if was_selected && @qresync

        @selected = { mailbox_id: result[:mailbox_id], name: result[:name] }
        @read_only = read_only
        # RFC 5182: a successful SELECT/EXAMINE resets the search result.
        @saved_search = []
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
        untagged "OK [MAILBOXID (#{result[:mailbox_object_id]})] Ok" if result[:mailbox_object_id]
        qresync_catch_up(qresync, result) if qresync
        tagged tag, "OK [#{read_only ? "READ-ONLY" : "READ-WRITE"}] #{read_only ? "EXAMINE" : "SELECT"} completed"
      end

      # Extracts "QRESYNC (uidvalidity modseq [known-uids [(seq-match)]])"
      # from the SELECT parameter list. Returns nil when absent, a params
      # hash when valid, or a String error message (for a BAD reply) when
      # malformed per the RFC 7162 grammar: both leading numbers nonzero,
      # no "*" anywhere, seq-match-data two equal-length sets.
      def parse_qresync_param(args)
        idx = args.index { |a| a.is_a?(String) && a.casecmp?("QRESYNC") }
        return nil unless idx
        return "Duplicate QRESYNC parameter" if args[(idx + 1)..].any? { |a| a.is_a?(String) && a.casecmp?("QRESYNC") }
        return "QRESYNC expects (uidvalidity modseq [known-uids [seq-match-data]])" unless args[idx + 1] == :lparen

        rest = args[(idx + 2)..]
        values = rest.take_while { |a| a != :rparen && a != :lparen }
        unless values[0].to_s.match?(/\A[1-9]\d*\z/) && values[1].to_s.match?(/\A[1-9]\d*\z/)
          return "QRESYNC uidvalidity and modseq must be nonzero numbers"
        end
        return "QRESYNC takes at most four arguments" if values.length > 3

        known = values[2]
        if known && !known.match?(/\A\d[\d,:]*\z/)
          return "QRESYNC known-uids must be a uid-set without *"
        end

        if (error = validate_seq_match_data(rest))
          return error
        end

        { uid_validity: values[0].to_i, modseq: values[1].to_i, known_uids: known }
      end

      # Syntax-checks the optional seq-match-data "(known-seqs known-uids)".
      # Its semantics are an optimization the server is free to ignore
      # (RFC 7162 §3.2.5.2), but malformed data must still be rejected.
      def validate_seq_match_data(rest)
        inner_at = rest.index(:lparen)
        return nil unless inner_at && inner_at < rest.index(:rparen).to_i

        inner = rest[(inner_at + 1)..].take_while { |a| a != :rparen }
        return "QRESYNC seq-match-data expects two sequence sets" unless inner.length == 2
        unless inner.all? { |s| s.is_a?(String) && s.match?(/\A\d[\d,:]*\z/) }
          return "QRESYNC seq-match-data sets cannot contain *"
        end

        sizes = inner.map { |s| parse_ranges(s, 0).sum(&:size) }
        return "QRESYNC seq-match-data sets must be the same length" unless sizes.first == sizes.last

        nil
      end

      # The QRESYNC fast-resync: VANISHED (EARLIER) for expunges the
      # client missed, then FLAGS catch-up for messages changed since its
      # last known modseq. Skipped entirely on a UIDVALIDITY mismatch -
      # the client must do a full resync then.
      def qresync_catch_up(qresync, result)
        return unless qresync[:uid_validity] == result[:uid_validity]

        known = qresync[:known_uids] && parse_ranges(qresync[:known_uids], result[:uid_next] - 1)
        vanished = @store.expunged_since(@selected[:mailbox_id], qresync[:modseq])[:uids] || []
        vanished = vanished.select { |uid| known.any? { |r| r.cover?(uid) } } if known
        untagged "VANISHED (EARLIER) #{compress_set(vanished)}" if vanished.any?

        @uids.each_with_index do |uid, idx|
          next unless (@modseqs[uid] || 1) > qresync[:modseq]
          next if known && known.none? { |r| r.cover?(uid) }

          untagged "#{idx + 1} FETCH (UID #{uid} FLAGS (#{@flags[uid].join(" ")}) MODSEQ (#{@modseqs[uid]}))"
        end
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

      # Plain EXPUNGE removes every \Deleted message; UID EXPUNGE (UIDPLUS)
      # removes only \Deleted messages within the given set.
      def expunge(tag, args, uid_mode)
        return tagged(tag, "BAD EXPUNGE takes no arguments") if !uid_mode && args.any?
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        uids = nil
        if uid_mode
          set = args.first
          return tagged(tag, "BAD UID EXPUNGE expects a sequence set") unless set.is_a?(String) && args.length == 1

          uids = resolve_set(set, true).map(&:last)
          return tagged(tag, "OK EXPUNGE completed") if uids.empty?
        end

        result = @store.expunge(@selected[:mailbox_id], uids)
        removed = result[:uids] || []
        report_removed(removed)
        @highest_modseq = result[:highest_modseq] if result[:highest_modseq]
        # RFC 7162 §3.2.7/§3.2.9: when something was expunged, the tagged
        # OK carries the updated HIGHESTMODSEQ (a MUST once QRESYNC is
        # enabled, optional but recommended for plain CONDSTORE).
        if @condstore && removed.any?
          tagged tag, "OK [HIGHESTMODSEQ #{@highest_modseq}] EXPUNGE completed"
        else
          tagged tag, "OK EXPUNGE completed"
        end
      end

      # Announces removals as either per-sequence EXPUNGE lines (highest
      # first, so earlier lines don't renumber later ones) or a single
      # uid-based VANISHED response once QRESYNC is enabled (RFC 7162).
      def report_removed(removed)
        return if removed.empty?

        if @qresync
          untagged "VANISHED #{compress_set(removed)}"
        else
          @uids.each_with_index.to_a.reverse_each do |uid, idx|
            untagged "#{idx + 1} EXPUNGE" if removed.include?(uid)
          end
        end
        removed.each { |uid| @flags.delete(uid); @modseqs.delete(uid) }
        @uids -= removed
      end

      # -- message sets --------------------------------------------------------

      # Resolves an IMAP sequence set against the current mailbox snapshot.
      # Returns [[seq, uid], ...] in mailbox order.
      def parse_ranges(set, max)
        set.to_s.split(",").filter_map do |chunk|
          lo, hi = chunk.split(":", 2)
          lo = lo == "*" ? max : lo.to_i
          hi = hi.nil? ? lo : (hi == "*" ? max : hi.to_i)
          lo, hi = hi, lo if lo > hi
          (lo..hi)
        end
      end

      def resolve_set(set, uid_mode)
        return [] if @uids.empty?

        # "$" is the whole sequence set (RFC 5182); expunged messages
        # drop out naturally because only current uids resolve.
        if set == "$"
          return @uids.each_with_index.filter_map { |uid, idx| [ idx + 1, uid ] if @saved_search.include?(uid) }
        end

        ranges = parse_ranges(set, uid_mode ? @uids.last : @uids.length)
        result = []
        @uids.each_with_index do |uid, idx|
          value = uid_mode ? uid : idx + 1
          result << [ idx + 1, uid ] if ranges.any? { |r| r.cover?(value) }
        end
        result
      end

      # -- FETCH ---------------------------------------------------------------

      # Deep-frozen (not just the outer hash): shared read-only by every
      # connection thread.
      FETCH_MACROS = {
        "ALL" => %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE].freeze,
        "FAST" => %w[FLAGS INTERNALDATE RFC822.SIZE].freeze,
        "FULL" => %w[FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY].freeze
      }.freeze

      METADATA_ITEMS = %w[UID FLAGS INTERNALDATE RFC822.SIZE MODSEQ EMAILID THREADID SAVEDATE].freeze

      FETCH_ITEM_ATOMS = %w[UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY
                            BODYSTRUCTURE RFC822 RFC822.HEADER RFC822.TEXT MODSEQ
                            EMAILID THREADID SAVEDATE PREVIEW].freeze

      # Validates a FETCH data item: a known atom, or BODY[.PEEK][section]
      # with an optional <origin.count> partial (count mandatory and
      # nonzero per the RFC 3501 grammar). Items can arrive as literals,
      # so the string may carry any byte - control bytes (CR/LF included)
      # are rejected outright, since the section is later echoed on the
      # untagged FETCH line and must not be able to forge extra lines.
      def valid_fetch_item?(item)
        return false if item.match?(/[\x00-\x1f\x7f]/)
        return true if FETCH_ITEM_ATOMS.include?(item.upcase)

        m = item.match(/\ABODY(?:\.PEEK)?\[(.*)\](<(\d+)(?:\.(\d+))?>)?\z/i) or return false
        return false if m[2] && (m[4].nil? || m[4].to_i.zero?)

        valid_fetch_section?(m[1])
      end

      # Section grammar: optional dotted part numbers, then nothing or
      # HEADER / TEXT / MIME (MIME only after a part number) /
      # HEADER.FIELDS[.NOT] with a non-empty header list (single SP
      # separators only - the label echo relies on this being canonical).
      def valid_fetch_section?(spec)
        numbers, rest = spec.match(/\A((?:\d+\.)*\d+)?\.?(.*)\z/).captures
        return true if rest.to_s.empty?

        case rest.upcase
        when "HEADER", "TEXT" then true
        when "MIME" then !numbers.nil?
        else rest.match?(/\AHEADER\.FIELDS(?:\.NOT)? \([^\s()][^()]*\)\z/i)
        end
      end

      # RFC 9051 (seq-number): a numeric message sequence number beyond
      # the number of messages in the mailbox gets a tagged BAD. Chunks
      # containing "*" clamp to the mailbox instead of failing.
      def bad_seq?(set, uid_mode)
        return false if uid_mode || set.to_s == "$"

        set.to_s.split(",").any? do |chunk|
          next false if chunk.include?("*")

          chunk.split(":", 2).any? { |n| n.to_i < 1 || n.to_i > @uids.length }
        end
      end

      def fetch(tag, args, uid_mode)
        set = args.shift
        return tagged(tag, "BAD FETCH expects a sequence set") unless set.is_a?(String)
        return tagged(tag, "BAD Message sequence number out of range") if bad_seq?(set, uid_mode)

        changedsince, vanished = extract_fetch_modifiers(args)
        if vanished && !(uid_mode && changedsince && @qresync)
          return tagged(tag, "BAD VANISHED requires UID FETCH with CHANGEDSINCE after ENABLE QRESYNC")
        end
        if (preview_error = collapse_preview_modifier(args))
          return tagged(tag, "BAD #{preview_error}")
        end

        # Macros are only valid as a single bare word, never inside a
        # parenthesized item list (RFC 3501 grammar).
        parenthesized = args.first == :lparen
        items = args.take_while { |a| a != :rparen }.reject { |a| a == :lparen }.map { |a| a.to_s }
        if !parenthesized && items.length == 1 && FETCH_MACROS.key?(items.first.upcase)
          items = FETCH_MACROS[items.first.upcase].dup
        end
        items << "UID" if uid_mode && items.none? { |i| i.casecmp?("UID") }
        return tagged(tag, "BAD FETCH expects data items") if items.empty?
        if (bad = items.find { |i| !valid_fetch_item?(i) })
          return tagged(tag, "BAD Unknown FETCH item #{bad}")
        end

        @condstore = true if changedsince || items.any? { |i| i.casecmp?("MODSEQ") }
        items << "MODSEQ" if @condstore && items.none? { |i| i.casecmp?("MODSEQ") }

        if vanished
          gone = @store.expunged_since(@selected[:mailbox_id], changedsince)[:uids] || []
          ranges = parse_ranges(set, @uids.last || 0)
          gone = gone.select { |uid| ranges.any? { |r| r.cover?(uid) } }
          untagged "VANISHED (EARLIER) #{compress_set(gone)}" if gone.any?
        end

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

      # Pulls the RFC 7162 "(CHANGEDSINCE n [VANISHED])" modifier group
      # out of the argument list (it follows the item list); returns
      # [n, vanished?] or [nil, false]. A VANISHED without CHANGEDSINCE
      # still extracts (as [nil, true]) so fetch can reject it with BAD.
      def extract_fetch_modifiers(args)
        idx = args.index { |a| a.is_a?(String) && (a.casecmp?("CHANGEDSINCE") || a.casecmp?("VANISHED")) }
        return [ nil, false ] unless idx

        first = args[0..idx].rindex(:lparen) || idx
        last = args[(idx + 1)..].index(:rparen)
        last = last ? idx + 1 + last : idx + 1
        group = args.slice!(first..last)
        cs = group.index { |a| a.is_a?(String) && a.casecmp?("CHANGEDSINCE") }
        value = cs && group[cs + 1].is_a?(String) ? group[cs + 1].to_i : nil
        [ value, group.any? { |a| a.is_a?(String) && a.casecmp?("VANISHED") } ]
      end

      # Collapses "PREVIEW (LAZY)" to a plain PREVIEW item - LAZY only
      # permits skipping generation, and we always generate (RFC 8970).
      # Returns an error string for any other modifier.
      def collapse_preview_modifier(args)
        idx = args.index { |a| a.is_a?(String) && a.casecmp?("PREVIEW") }
        return nil unless idx && args[idx + 1] == :lparen

        mod = args[idx + 2]
        unless mod.is_a?(String) && mod.casecmp?("LAZY") && args[idx + 3] == :rparen
          return "Unknown PREVIEW modifier"
        end

        args.slice!((idx + 1)..(idx + 3))
        nil
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
        parse = -> { parsed ||= Imap::Mime.parse(msg[:raw]) }
        flags = @flags[msg[:uid]] || msg[:flags]
        out = []

        items.each do |item|
          case item.upcase
          when "UID"           then out << "UID #{msg[:uid]}"
          when "MODSEQ"        then out << "MODSEQ (#{@modseqs[msg[:uid]] || msg[:modseq] || 1})"
          when "FLAGS"         then out << "FLAGS (#{flags.join(" ")})"
          when "INTERNALDATE"  then out << %(INTERNALDATE "#{internal_date(msg)}")
          when "RFC822.SIZE"   then out << "RFC822.SIZE #{msg[:size]}"
          when "ENVELOPE"      then out << "ENVELOPE #{Imap::Mime.envelope(parse.call)}"
          when "BODY" then out << "BODY #{Imap::Mime.bodystructure(parse.call)}"
          when "BODYSTRUCTURE" then out << "BODYSTRUCTURE #{Imap::Mime.bodystructure(parse.call, extended: true)}"
          when "EMAILID"       then out << "EMAILID (#{msg[:email_id]})" if msg[:email_id]
          when "THREADID"      then out << (msg[:thread_id] ? "THREADID (#{msg[:thread_id]})" : "THREADID NIL")
          when "SAVEDATE"
            out << (msg[:saved_date] ? %(SAVEDATE "#{Time.at(msg[:saved_date]).strftime("%d-%b-%Y %H:%M:%S %z")}") : "SAVEDATE NIL")
          when "PREVIEW"       then out << "PREVIEW #{Imap::Mime.quote(Imap::Mime.preview(parse.call))}"
          when "RFC822"        then out << "RFC822 #{Imap::Mime.literal(msg[:raw])}"
          when "RFC822.HEADER" then out << "RFC822.HEADER #{Imap::Mime.literal(parse.call.header_block)}"
          when "RFC822.TEXT"   then out << "RFC822.TEXT #{Imap::Mime.literal(parse.call.body)}"
          else
            if (m = item.match(/\ABODY(\.PEEK)?\[(.*)\](?:<(\d+)(?:\.(\d+))?>)?\z/i))
              _peek, section, start, count = m[1], m[2], m[3], m[4]
              data = Imap::Mime.section(parse.call, section)
              label = +"BODY[#{section.upcase}]"
              if data && start
                data = data.byteslice(start.to_i, count ? count.to_i : data.bytesize).to_s
                label << "<#{start}>"
              end
              out << "#{label} #{data ? Imap::Mime.literal(data) : "NIL"}"
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

      # Canonicalizes system-flag spellings and dedupes case-insensitively
      # (flags are atoms). Returns nil if the list names a "\" flag the
      # server doesn't define - clients cannot invent system flags.
      def parse_flag_list(raw)
        flags = raw.map { |f| CANONICAL_FLAGS.fetch(f.downcase, f) }
        return nil if flags.any? { |f| f.start_with?("\\") && !CANONICAL_FLAGS.value?(f) }

        flags.uniq(&:downcase)
      end

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
        return tagged(tag, "BAD Message sequence number out of range") if bad_seq?(set, uid_mode)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        m = item.match(/\A([+-]?)FLAGS(\.SILENT)?\z/i)
        return tagged(tag, "BAD Unknown STORE item #{item}") unless m

        mode = m[1].empty? ? "=" : m[1]
        silent = !m[2].nil?
        # Grammar: a flag list "()" (possibly empty) or one-or-more bare
        # flag atoms - no flag argument at all is BAD.
        return tagged(tag, "BAD STORE expects a flag list") if args.none? { |a| a == :lparen || a.is_a?(String) }

        flags = parse_flag_list(args.select { |a| a.is_a?(String) })
        return tagged(tag, "BAD Unknown system flag") if flags.nil?

        flags = flags.reject { |f| f == "\\Recent" }

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
        return tagged(tag, "BAD Message sequence number out of range") if bad_seq?(set, uid_mode)

        dest_name = mailbox_name_arg(tag, dest, "COPY") or return
        wanted = resolve_set(set, uid_mode)
        return tagged(tag, "OK COPY completed (nothing to copy)") if wanted.empty?

        result = @store.copy(@selected[:mailbox_id], wanted.map(&:last), dest_name)
        if result[:error]
          tagged tag, "NO #{error_response_code(result)}COPY failed: #{result[:error]}"
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
        return tagged(tag, "BAD Message sequence number out of range") if bad_seq?(set, uid_mode)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        dest_name = mailbox_name_arg(tag, dest, "MOVE") or return
        wanted = resolve_set(set, uid_mode)
        return tagged(tag, "OK MOVE completed (nothing to move)") if wanted.empty?

        result = @store.move(@selected[:mailbox_id], wanted.map(&:last), dest_name)
        if result[:error]
          return tagged(tag, "NO #{error_response_code(result)}MOVE failed: #{result[:error]}")
        end

        # RFC 6851: COPYUID rides an untagged OK and precedes the EXPUNGEs.
        untagged "OK [COPYUID #{result[:uid_validity]} #{result[:src_uids].join(",")} #{result[:dest_uids].join(",")}]"
        report_removed(result[:src_uids])
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

      ESEARCH_OPTIONS = %w[MIN MAX COUNT ALL SAVE].freeze

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

        hits = search_hits(criteria, uid_mode)
        save_search_result(hits, return_opts) if return_opts&.include?("SAVE")

        ids = hits.map { |seq, uid| uid_mode ? uid : seq }
        # RFC 7162: a MODSEQ search key adds "(MODSEQ n)" / "MODSEQ n"
        # (highest modseq among the matches) to the response.
        modseq_max = @search_modseq && hits.any? ? hits.map { |_seq, uid| @modseqs[uid] || 1 }.max : nil
        if return_opts
          display_opts = return_opts - [ "SAVE" ]
          return tagged(tag, "OK SEARCH completed") if display_opts.empty?

          response = esearch_response(tag, ids, display_opts, uid_mode)
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

      SORT_KEYS = %w[ARRIVAL CC DATE FROM SIZE SUBJECT TO].freeze
      RAW_SORT_KEYS = %w[CC DATE FROM SUBJECT TO].freeze

      # RFC 5256 SORT: "(criteria) charset search-keys". Matches like
      # SEARCH, then orders by the criteria in turn (REVERSE flips the
      # single following criterion), final tiebreak ascending sequence.
      def sort(tag, args, uid_mode)
        criteria = parse_sort_criteria(args)
        return tagged(tag, "BAD #{criteria}") if criteria.is_a?(String)

        charset = args.shift
        unless charset.is_a?(String) && SEARCH_CHARSETS.any? { |c| charset.casecmp?(c) }
          return tagged(tag, "NO [BADCHARSET (#{SEARCH_CHARSETS.join(" ")})] Charset not supported")
        end
        return tagged(tag, "BAD SORT expects search criteria") if args.empty?

        @search_modseq = false
        hits = search_hits(args, uid_mode)
        need_raw = criteria.any? { |key, _rev| RAW_SORT_KEYS.include?(key) }
        messages = fetch_messages(hits.map(&:last), need_raw)

        keyed = hits.map { |seq, uid| [ seq, uid, sort_values(messages[uid], criteria) ] }
        sorted = keyed.sort do |a, b|
          order = 0
          criteria.each_with_index do |(_key, reverse), i|
            order = a[2][i] <=> b[2][i]
            order = -order if reverse
            break unless order.zero?
          end
          order.zero? ? a[0] <=> b[0] : order
        end

        ids = sorted.map { |seq, uid, _values| uid_mode ? uid : seq }
        untagged +"SORT #{ids.join(" ")}".rstrip
        tagged tag, "OK SORT completed"
      rescue SearchSyntaxError => e
        tagged tag, "BAD #{e.message}"
      end

      # Returns [[KEY, reverse?], ...] or an error String.
      def parse_sort_criteria(args)
        return "SORT expects a criteria list" unless args.shift == :lparen

        criteria = []
        reverse = false
        loop do
          token = args.shift
          return "SORT expects a criteria list" if token.nil?
          break if token == :rparen

          name = token.to_s.upcase
          if name == "REVERSE"
            reverse = true
          elsif SORT_KEYS.include?(name)
            criteria << [ name, reverse ]
            reverse = false
          else
            return "Unknown SORT criterion #{name}"
          end
        end
        return "SORT expects at least one criterion" if criteria.empty?
        return "REVERSE expects a following criterion" if reverse

        criteria
      end

      # One comparable value per criterion. Address criteria use the
      # addr-mailbox (localpart) of the first address; DATE falls back to
      # INTERNALDATE when the Date header is missing or unparseable.
      def sort_values(msg, criteria)
        headers = nil
        read_header = lambda do |name|
          headers ||= Imap::Mime.parse_headers(Imap::Mime.split_header(msg[:raw].to_s)[0])
          headers[name]&.first.to_s
        end

        criteria.map do |key, _reverse|
          case key
          when "ARRIVAL" then msg[:internal_date]
          when "SIZE"    then msg[:size]
          when "DATE"
            begin
              Time.parse(read_header.call("date")).to_i
            rescue ArgumentError, TypeError
              msg[:internal_date]
            end
          when "FROM" then first_addr_mailbox(read_header.call("from"))
          when "TO"   then first_addr_mailbox(read_header.call("to"))
          when "CC"   then first_addr_mailbox(read_header.call("cc"))
          when "SUBJECT" then base_subject(read_header.call("subject"))
          end
        end
      end

      def first_addr_mailbox(value)
        Imap::Mime.parse_addresses(value).first&.at(1).to_s.downcase
      end

      # RFC 5256 §2.1 base subject, simplified: strip trailing "(fwd)"
      # and leading re:/fw:/fwd: markers (with optional [blah]) until
      # stable. Case-insensitive by downcasing.
      def base_subject(subject)
        s = subject.to_s.gsub(/\s+/, " ").strip.downcase
        loop do
          before = s
          s = s.sub(/\s*\(fwd\)\s*\z/, "")
          s = s.sub(/\A\s*(?:re|fwd?)\s*(?:\[[^\]]*\])?\s*:\s*/, "")
          break if s == before
        end
        s
      end

      # -- THREAD (RFC 5256) -------------------------------------------------------

      THREAD_ALGORITHMS = %w[ORDEREDSUBJECT REFERENCES].freeze

      # RFC 5256 THREAD: "<algorithm> <charset> <search keys>". Matches
      # like SEARCH, then arranges the matches into conversation trees.
      def thread(tag, args, uid_mode)
        algorithm = args.shift.to_s.upcase
        return tagged(tag, "BAD Unknown THREAD algorithm #{algorithm}") unless THREAD_ALGORITHMS.include?(algorithm)

        charset = args.shift
        unless charset.is_a?(String) && SEARCH_CHARSETS.any? { |c| charset.casecmp?(c) }
          return tagged(tag, "NO [BADCHARSET (#{SEARCH_CHARSETS.join(" ")})] Charset not supported")
        end
        return tagged(tag, "BAD THREAD expects search criteria") if args.empty?

        @search_modseq = false
        hits = search_hits(args, uid_mode)
        messages = fetch_messages(hits.map(&:last), true)
        entries = hits.filter_map do |seq, uid|
          (msg = messages[uid]) && thread_entry(seq, uid, msg, uid_mode)
        end

        threads = algorithm == "REFERENCES" ? references_threads(entries) : ordered_subject_threads(entries)
        untagged "THREAD #{threads.join}".rstrip
        tagged tag, "OK THREAD completed"
      rescue SearchSyntaxError => e
        tagged tag, "BAD #{e.message}"
      end

      # The facts threading needs about one matched message, read off its
      # headers: ancestry (References, falling back to In-Reply-To), base
      # subject, and the sent date (INTERNALDATE when unparseable, as in
      # SORT).
      def thread_entry(seq, uid, msg, uid_mode)
        headers = Imap::Mime.parse_headers(Imap::Mime.split_header(msg[:raw].to_s)[0])
        subject = headers["subject"]&.first.to_s
        references = header_msg_ids(headers, "references")
        references = header_msg_ids(headers, "in-reply-to").first(1) if references.empty?
        date = begin
          Time.parse(headers["date"]&.first.to_s).to_i
        rescue ArgumentError, TypeError
          msg[:internal_date]
        end
        { num: uid_mode ? uid : seq, uid: uid, date: date,
          message_id: header_msg_ids(headers, "message-id").first,
          references: references,
          subject: base_subject(subject),
          # A re:/fwd: prefix marks a reply for the subject-merge step
          # (the non-reply wins a merged thread's root).
          reply: base_subject(subject) != subject.gsub(/\s+/, " ").strip.downcase }
      end

      def header_msg_ids(headers, name)
        headers[name].to_a.flat_map { |v| v.scan(/<([^>]+)>/) }.flatten
      end

      # ORDEREDSUBJECT ("poor man's threading"): one linear thread per
      # base subject, messages ordered by sent date, threads by their
      # first message's date.
      def ordered_subject_threads(entries)
        groups = entries.group_by { |e| e[:subject] }.values
        groups.each { |group| group.sort_by! { |e| [ e[:date], e[:uid] ] } }
        groups.sort_by { |group| [ group.first[:date], group.first[:uid] ] }
              .map { |group| "(#{group.map { |e| e[:num] }.join(" ")})" }
      end

      # REFERENCES (the JWZ algorithm as RFC 5256 specifies it): build the
      # ancestry forest from References chains - creating placeholder
      # containers for referenced messages outside the result set - then
      # prune the placeholders, merge root threads sharing a base subject,
      # sort siblings by date, and render.
      def references_threads(entries)
        containers = Hash.new { |h, k| h[k] = { entry: nil, children: [], parent: nil } }
        entries.each do |entry|
          id = entry[:message_id] || "no-id-#{entry[:uid]}"
          id = "#{id}-dup-#{entry[:uid]}" if containers[id][:entry]
          container = containers[id]
          container[:entry] = entry

          # Link each adjacent pair of the References chain, never
          # re-parenting an already-linked container and never
          # introducing a loop.
          previous = nil
          entry[:references].each do |ref|
            node = containers[ref]
            if previous && !node.equal?(previous) && node[:parent].nil? && !thread_ancestor?(node, previous)
              adopt(previous, node)
            end
            previous = node
          end
          # The message's own parent is its last reference, overriding
          # any speculative link an earlier chain made (unless that
          # would loop).
          if previous && !previous.equal?(container) && !thread_ancestor?(container, previous)
            container[:parent]&.dig(:children)&.delete(container)
            adopt(previous, container)
          end
        end

        roots = prune_placeholders(containers.values.select { |c| c[:parent].nil? })
        roots = merge_threads_by_subject(roots)
        sort_threads(roots)
        roots.map { |root| render_thread(root) }
      end

      def adopt(parent, child)
        child[:parent] = parent
        parent[:children] << child
      end

      # True when +node+ is +other+ or one of its ancestors.
      def thread_ancestor?(node, other)
        while other
          return true if other.equal?(node)

          other = other[:parent]
        end
        false
      end

      # JWZ step 2: drop placeholders for messages outside the result
      # set, promoting their children - except that a placeholder at the
      # root keeps a multi-child sibling group together (it renders as
      # "((a)(b))").
      def prune_placeholders(nodes, root: true)
        nodes.flat_map do |node|
          node[:children] = prune_placeholders(node[:children], root: false)
          if node[:entry]
            [ node ]
          elsif node[:children].empty?
            []
          elsif !root || node[:children].size == 1
            node[:children].each { |c| c[:parent] = node[:parent] }
            node[:children]
          else
            [ node ]
          end
        end
      end

      # RFC 5256 step 4: root threads sharing a base subject merge into
      # one - under the placeholder if either is one, under the
      # non-reply if exactly one message lacks a re:/fwd: prefix, and
      # under a fresh placeholder when neither is clearly the parent.
      def merge_threads_by_subject(roots)
        table = {}
        merged = []
        replace = lambda do |old, new, subject|
          merged[merged.index { |n| n.equal?(old) }] = new
          table[subject] = new
        end

        roots.each do |root|
          subject = thread_subject(root)
          other = table[subject] unless subject.empty?
          if other.nil?
            table[subject] = root unless subject.empty?
            merged << root
          elsif other[:entry].nil? && root[:entry].nil?
            root[:children].each { |c| adopt(other, c) }
          elsif other[:entry].nil?
            adopt(other, root)
          elsif root[:entry].nil?
            replace.call(other, root, subject)
            adopt(root, other)
          elsif other[:entry][:reply] && !root[:entry][:reply]
            replace.call(other, root, subject)
            adopt(root, other)
          elsif root[:entry][:reply] && !other[:entry][:reply]
            adopt(other, root)
          else
            placeholder = { entry: nil, children: [], parent: nil }
            replace.call(other, placeholder, subject)
            adopt(placeholder, other)
            adopt(placeholder, root)
          end
        end
        merged
      end

      # The base subject a thread is known by: its message's, or the
      # first descendant's for a placeholder.
      def thread_subject(node)
        node = node[:children].first until node.nil? || node[:entry]
        node ? node[:entry][:subject] : ""
      end

      # RFC 5256 steps 5-6: siblings sort by sent date (mailbox order as
      # the tiebreak), recursively; the root set sorts the same way, a
      # placeholder counting as its first (sorted) child.
      def sort_threads(nodes)
        nodes.each { |node| sort_threads(node[:children]) }
        nodes.sort_by! { |node| thread_sort_key(node) }
      end

      def thread_sort_key(node)
        node = node[:children].first while node[:entry].nil?
        [ node[:entry][:date], node[:entry][:uid] ]
      end

      # RFC 5256 rendering: a linear descent stays in one list
      # ("(2 3 4)"); a fork nests each branch ("(2 (3)(4))"); a
      # parentless sibling group opens with a nested thread ("((3)(4))").
      def render_thread(node)
        parts = []
        while node
          parts << node[:entry][:num].to_s if node[:entry]
          case node[:children].size
          when 0 then node = nil
          when 1 then node = node[:children].first
          else
            parts << node[:children].map { |child| render_thread(child) }.join
            node = nil
          end
        end
        "(#{parts.join(" ")})"
      end

      # Evaluates search-key tokens against the current snapshot and
      # returns matching [seq, uid] pairs in mailbox order. Two-phase:
      # metadata keys (flags, dates, sizes, sets) run against the cheap
      # metadata fetch; message bytes are pulled only for survivors that
      # content keys still need. Raises SearchSyntaxError on bad keys.
      def search_hits(criteria, uid_mode)
        matchers = []
        matchers << parse_search_key(criteria, uid_mode) until criteria.empty?
        matchers.compact!
        meta_keys, raw_keys = matchers.partition { |k| !k.raw? }

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
        hits
      end

      # RFC 5182: SAVE stores the matched UIDs as the "$" variable. When
      # combined with only MIN and/or MAX, just those messages are saved;
      # any other combination (or SAVE alone) saves the full result.
      def save_search_result(hits, opts)
        uids = hits.map(&:last) # ascending: mailbox order
        @saved_search =
          if (opts - %w[SAVE MIN MAX]).empty? && opts.intersect?(%w[MIN MAX])
            [ (uids.min if opts.include?("MIN")), (uids.max if opts.include?("MAX")) ].compact.uniq
          else
            uids
          end
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

      def parse_search_key(toks, uid_mode, depth = 0)
        raise SearchSyntaxError, "SEARCH key nested too deeply" if depth > MAX_SEARCH_DEPTH

        tok = toks.shift
        return nil if tok.nil?

        if tok == :lparen
          keys = []
          keys << parse_search_key(toks, uid_mode, depth + 1) until toks.empty? || toks.first == :rparen
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
          key = parse_search_key(toks, uid_mode, depth + 1)
          raise SearchSyntaxError, "NOT expects a search key" if key.nil?

          negate(key)
        when "OR"
          a = parse_search_key(toks, uid_mode, depth + 1)
          b = parse_search_key(toks, uid_mode, depth + 1)
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
        when "TEXT" then content_key(toks.shift.to_s, "text")
        when "BODY"
          # Unlike TEXT, BODY matches the body only, never the header.
          content_key(toks.shift.to_s, "body")
        when "OLDER"   then age_key(toks.shift) { |age, seconds| age >= seconds }
        when "YOUNGER" then age_key(toks.shift) { |age, seconds| age <= seconds }
        when "SAVEDBEFORE" then saved_date_key(toks.shift) { |saved, day| saved < day }
        when "SAVEDON"     then saved_date_key(toks.shift) { |saved, day| saved == day }
        when "SAVEDSINCE"  then saved_date_key(toks.shift) { |saved, day| saved >= day }
        when "EMAILID"
          value = toks.shift.to_s
          meta_key { |_seq, msg| msg[:email_id] == value }
        when "THREADID"
          value = toks.shift.to_s
          meta_key { |_seq, msg| msg[:thread_id] == value }
        when "MODSEQ"
          # Optional entry-name/entry-type prefix ("/flags/\Seen" all) is
          # accepted and ignored - flags share one modseq per message here.
          toks.shift(2) if toks.first.is_a?(String) && !toks.first.match?(/\A\d+\z/)
          value = toks.shift.to_s.to_i
          @condstore = true
          @search_modseq = true
          meta_key { |_seq, msg| (@modseqs[msg[:uid]] || 1) >= value }
        when "$"
          # SEARCHRES: the saved search result as a search key.
          meta_key { |_seq, msg| @saved_search.include?(msg[:uid]) }
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

      # Flags are grammar atoms and therefore case-insensitive (RFC 9051
      # formal-syntax rules): KEYWORD Custom1 matches a stored "custom1".
      def flag_key(flag)
        meta_key { |_seq, msg| (@flags[msg[:uid]] || msg[:flags]).any? { |f| f.casecmp?(flag) } }
      end

      def date_key(str, &compare)
        day = parse_search_date(str)
        meta_key { |_seq, msg| compare.call(Time.at(msg[:internal_date]).utc.to_date, day) }
      end

      # SENTBEFORE/SENTON/SENTSINCE compare against the Date: header
      # (RFC 3501), not INTERNALDATE, "disregarding time and timezone":
      # the date is taken as written in the header, never shifted to UTC.
      # Messages without a parseable Date header don't match.
      def sent_date_key(str, &compare)
        day = parse_search_date(str)
        raw_key do |_seq, msg|
          value = Imap::Mime.parse_headers(Imap::Mime.split_header(msg[:raw].to_s)[0])["date"]&.first
          sent_day = begin
            value && Date.parse(value)
          rescue ArgumentError, TypeError
            nil
          end
          !sent_day.nil? && compare.call(sent_day, day)
        end
      end

      def parse_search_date(str)
        Date.strptime(str.to_s, "%d-%b-%Y")
      rescue ArgumentError
        raise SearchSyntaxError, "Invalid date #{str}"
      end

      # SAVEDBEFORE/SAVEDON/SAVEDSINCE (RFC 8514) compare the date the
      # message entered the mailbox, disregarding time and timezone.
      def saved_date_key(str, &compare)
        day = parse_search_date(str)
        meta_key { |_seq, msg| msg[:saved_date] && compare.call(Time.at(msg[:saved_date]).to_date, day) }
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
          headers = Imap::Mime.parse_headers(Imap::Mime.split_header(msg[:raw].to_s)[0])
          headers[name].to_a.any? { |v| v.downcase.include?(value) }
        end
      end

      # TEXT/BODY. Pushed down to the store's indexed search when it offers
      # one (search_text in the store contract; word-level matching), so
      # the common "search my mail" case never ships raw bytes up to this
      # process. Queries an FTS index can't express (no word characters -
      # bare punctuation, the empty string) and stores without search_text
      # take the RFC-exact substring scan instead. A store search that
      # fails matches nothing, same as a failed fetch in search_hits.
      def content_key(value, scope)
        return substring_key(value, scope) unless @store.respond_to?(:search_text) && value.match?(/[[:alnum:]]/)

        uids = nil
        meta_key do |_seq, msg|
          uids ||= @store.search_text(@selected[:mailbox_id], value, scope)[:uids] || []
          uids.include?(msg[:uid])
        end
      end

      # RFC 3501 TEXT/BODY semantics: case-insensitive substring over the
      # raw message (scope "text") or its body section (scope "body").
      def substring_key(value, scope)
        value = value.downcase
        raw_key do |_seq, msg|
          haystack = msg[:raw].to_s
          haystack = Imap::Mime.split_header(haystack)[1] if scope == "body"
          haystack.downcase.include?(value)
        end
      end

      # -- QUOTA (RFC 2087 / RFC 9208) ---------------------------------------------

      # One quota root per account, named "" - every mailbox belongs to
      # it. Only the STORAGE resource exists, and SETQUOTA is refused:
      # quotas are the operator's to set, not the mail client's.

      def getquota(tag, args)
        root = args.shift
        return tagged(tag, "BAD GETQUOTA expects a quota root") unless root.is_a?(String)
        return tagged(tag, "NO No such quota root") unless root.empty?

        untagged %(QUOTA "" #{quota_resources})
        tagged tag, "OK GETQUOTA completed"
      end

      def getquotaroot(tag, args)
        name = mailbox_name_arg(tag, args.shift, "GETQUOTAROOT") or return
        return tagged(tag, "NO [NONEXISTENT] No such mailbox") if @store.status(@account_id, name)[:error]

        untagged %(QUOTAROOT #{Imap::Mime.quote(Imap::Utf7.encode(name))} "")
        untagged %(QUOTA "" #{quota_resources})
        tagged tag, "OK GETQUOTAROOT completed"
      end

      # STORAGE counts units of 1024 octets (RFC 2087), usage rounded up
      # so a nonzero byte count never reads as zero. An account without a
      # configured limit reports no resources - the root exists, nothing
      # is limited.
      def quota_resources
        result = @store.quota(@account_id)
        return "()" unless result[:limit_bytes]

        "(STORAGE #{(result[:used_bytes].to_i + 1023) / 1024} #{(result[:limit_bytes].to_i + 1023) / 1024})"
      end

      # -- APPEND ----------------------------------------------------------------

      def append(tag, args)
        name = mailbox_name_arg(tag, args.shift, "APPEND") or return
        message = args.pop
        return tagged(tag, "BAD APPEND expects a mailbox and message") unless message.is_a?(String)

        flags, date_epoch = parse_append_args(args)
        return tagged(tag, "BAD #{flags}") if flags.is_a?(String)

        result = @store.append(@account_id, name, message, flags, date_epoch)
        if result[:error]
          tagged tag, "NO #{error_response_code(result)}APPEND failed: #{result[:error]}"
        else
          # An APPEND into the selected mailbox must surface as an
          # untagged EXISTS (RFC 3501 §6.3.11) before the tagged OK.
          resync if @selected && @selected[:name].casecmp?(name)
          tagged tag, "OK [APPENDUID #{result[:uid_validity]} #{result[:uid]}] APPEND completed"
        end
      end

      # Parses APPEND's optional "(flags)" and date-time arguments (shared
      # with REPLACE). Returns [flags, date_epoch] or an error String -
      # junk or extra literals (unadvertised MULTIAPPEND) are errors.
      def parse_append_args(args)
        flags = []
        date_epoch = nil
        if (open_idx = args.index(:lparen))
          close_idx = args.index(:rparen) || args.length
          flags = parse_flag_list(args[(open_idx + 1)...close_idx].select { |a| a.is_a?(String) })
          return "Unknown system flag" if flags.nil?

          flags = flags.reject { |f| f == "\\Recent" }
          args = args[(close_idx + 1)..] || []
        end
        if (date_str = args.shift)
          date_epoch = begin
            Time.strptime(date_str.to_s.strip, "%d-%b-%Y %H:%M:%S %z").to_i
          rescue ArgumentError
            return "Invalid APPEND date-time"
          end
        end
        return "Unexpected extra APPEND arguments" if args.any?

        [ flags, date_epoch ]
      end

      # RFC 8508 REPLACE: append the new message to the named mailbox and
      # remove the identified one from the selected mailbox, presented to
      # the client as one action (append first - the original MUST
      # survive a failed append).
      def replace(tag, args, uid_mode)
        return tagged(tag, "NO Mailbox is read-only") if @read_only

        id = args.shift
        return tagged(tag, "BAD REPLACE expects a single message id") unless id.is_a?(String) && id.match?(/\A\d+\z/)
        return tagged(tag, "BAD Message sequence number out of range") if bad_seq?(id, uid_mode)

        target = resolve_set(id, uid_mode)
        return tagged(tag, "NO No such message") unless target.length == 1

        name = mailbox_name_arg(tag, args.shift, "REPLACE") or return
        message = args.pop
        return tagged(tag, "BAD REPLACE expects a mailbox and message") unless message.is_a?(String)

        flags, date_epoch = parse_append_args(args)
        return tagged(tag, "BAD #{flags}") if flags.is_a?(String)

        result = @store.append(@account_id, name, message, flags, date_epoch)
        if result[:error]
          return tagged(tag, "NO #{error_response_code(result)}REPLACE failed: #{result[:error]}")
        end

        untagged "OK [APPENDUID #{result[:uid_validity]} #{result[:uid]}] Replacement ready"

        uid = target.first.last
        @store.store_flags(@selected[:mailbox_id], [ uid ], "+", [ "\\Deleted" ])
        expunged = @store.expunge(@selected[:mailbox_id], [ uid ])
        @highest_modseq = expunged[:highest_modseq] if expunged[:highest_modseq]
        if @selected[:name].casecmp?(name)
          resync # one pass reports both the EXISTS and the removal
        else
          report_removed(expunged[:uids] || [])
        end
        tagged tag, "OK REPLACE completed"
      end

      # -- IDLE / resync -----------------------------------------------------------

      # How often an idling session re-checks the store for changes. The
      # store is the source of truth and other writers (delivery through
      # the Rails app, other sessions, possibly other daemon processes)
      # don't share this process, so polling it is the only complete
      # update source. Read per iteration through the settings schema, so
      # retuning applies even to IDLEs already in flight; a constant set
      # on the server class wins (the test seam - tests need sub-second
      # polls the integer schema can't express).
      def idle_poll_seconds
        if ImapServer.const_defined?(:IDLE_POLL_SECONDS, false)
          ImapServer.const_get(:IDLE_POLL_SECONDS, false)
        else
          Settings[:imap_idle_poll]
        end
      end

      # RFC 2177. The session blocks here pushing untagged updates (found
      # by polling resync) until the client sends DONE.
      def idle(tag)
        @idling = true
        @socket.write("+ idling\r\n")
        loop do
          if wait_readable(idle_poll_seconds)
            line = read_line
            return unless line
            return tagged(tag, "OK IDLE terminated") if line.chomp("\r\n").casecmp?("DONE")

            return tagged(tag, "BAD Expected DONE")
          end
          resync
        end
      ensure
        @idling = false
      end

      # True when input is waiting, false on timeout. TLS can hold
      # decrypted bytes buffered past the raw fd, so check there first.
      def wait_readable(seconds)
        return true if @socket.respond_to?(:pending) && @socket.pending.positive?

        !io_for(@socket).wait_readable(seconds).nil?
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

        if @qresync
          untagged "VANISHED #{compress_set(removed)}" if removed.any?
        else
          @uids.each_with_index.to_a.reverse_each do |uid, idx|
            untagged "#{idx + 1} EXPUNGE" if removed.include?(uid)
          end
        end
        take_snapshot(result)
        untagged "#{@uids.length} EXISTS" if removed.any? || added.any?

        @uids.each_with_index do |uid, idx|
          next unless old_flags.key?(uid) && old_flags[uid].sort != @flags[uid].sort

          # RFC 7162: CONDSTORE-aware sessions get MODSEQ in every
          # unsolicited FETCH; QRESYNC sessions additionally get the UID.
          parts = []
          parts << "UID #{uid}" if @qresync
          parts << "FLAGS (#{@flags[uid].join(" ")})"
          parts << "MODSEQ (#{@modseqs[uid] || 1})" if @condstore
          untagged "#{idx + 1} FETCH (#{parts.join(" ")})"
        end
      end
    end
  end
end

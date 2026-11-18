# frozen_string_literal: true

require "strscan"

module MailOnRails
  module Imap
    # Minimal MIME parser and IMAP data-item formatter.
    #
    # This runs on the IMAP server's connection threads and is deliberately
    # pure Ruby over binary strings - untrusted messages are parsed without
    # touching ActiveRecord or the Mail gem. It covers the subset of RFC 3501
    # FETCH data items real clients (iOS Mail in particular) ask for:
    # ENVELOPE, BODYSTRUCTURE, and BODY[...] sections.
    module Mime
      Part = Struct.new(:header_block, :headers, :body, :type, :subtype,
                        :params, :children, :embedded, keyword_init: true) do
        def multipart? = type == "multipart"
        def message_rfc822? = type == "message" && subtype == "rfc822"
        def encoding = headers["content-transfer-encoding"]&.first || "7bit"
        def size = body.bytesize
        def line_count = body.count("\n")
        def raw = header_block + body
      end

      module_function

      # Bounds on how much structure we will build from an untrusted message.
      # A crafted message with thousands of nested multipart boundaries could
      # otherwise blow the stack or exhaust memory inside the IMAP server.
      # Past these limits a container degrades to an opaque leaf part, which is
      # acceptable output for a malicious message.
      MAX_DEPTH = 20
      MAX_PARTS = 1000
      # Every nesting level copies its body into the child parts (the
      # container splits it, the child re-slices it), so a message nested
      # to MAX_DEPTH would hold ~2x its size per level. The parse stops
      # descending once the copies made exceed this multiple of the
      # top-level message; real mail is two or three levels deep.
      MAX_COPY_FACTOR = 8

      def parse(raw, depth: 0, budget: nil)
        raw = raw.to_s.b
        budget ||= { parts: MAX_PARTS, bytes: raw.bytesize * MAX_COPY_FACTOR }
        budget[:bytes] -= raw.bytesize if depth.positive?
        header_block, body = split_header(raw)
        headers = parse_headers(header_block)
        type, subtype, params = parse_content_type(headers["content-type"]&.first)
        part = Part.new(header_block: header_block, headers: headers, body: body,
                        type: type, subtype: subtype, params: params)

        return part unless depth < MAX_DEPTH && budget[:parts].positive? && budget[:bytes].positive?

        if part.multipart? && params["boundary"]
          budget[:bytes] -= body.bytesize # the split's own copy
          chunks = split_multipart(body, params["boundary"], budget[:parts])
          budget[:parts] -= chunks.size
          part.children = chunks.map { |chunk| parse(chunk, depth: depth + 1, budget: budget) }
          part.children = nil if part.children.empty?
        elsif part.message_rfc822?
          budget[:parts] -= 1
          part.embedded = parse(body, depth: depth + 1, budget: budget)
        end
        part
      end

      # Returns [header block including the delimiting blank line, body].
      # A message (or MIME part) may have no headers at all, in which case
      # it opens directly with the blank line (RFC 2046 §5.1: "a blank line
      # ... means no header fields were given").
      def split_header(raw)
        if (m = raw.match(/\A\r?\n/))
          [ raw[0...m.end(0)], raw[m.end(0)..] || (+"").b ]
        elsif (m = raw.match(/\r?\n\r?\n/))
          [ raw[0...m.end(0)], raw[m.end(0)..] || (+"").b ]
        else
          [ raw, (+"").b ]
        end
      end

      def parse_headers(header_block)
        headers = {}
        current = nil
        header_block.each_line do |line|
          stripped = line.chomp
          break if stripped.empty?

          if line.start_with?(" ", "\t")
            current << " " << stripped.strip if current
          elsif (idx = stripped.index(":"))
            name = stripped[0...idx].strip.downcase
            current = +stripped[(idx + 1)..].to_s.strip
            (headers[name] ||= []) << current
          end
        end
        headers
      end

      def parse_content_type(value)
        return [ "text", "plain", { "charset" => "us-ascii" } ] if value.nil? || value.strip.empty?

        mime = value.split(";", 2).first.to_s.strip.downcase
        type, subtype = mime.split("/", 2)
        params = {}
        value.split(";", 2)[1].to_s.scan(/([\w-]+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^;\s]+))/) do |name, quoted, token|
          params[name.downcase] = quoted ? quoted.gsub(/\\(.)/, '\1') : token
        end
        type = "text" if type.nil? || type.empty?
        subtype = "plain" if subtype.nil? || subtype.empty?
        [ type, subtype, params ]
      rescue StandardError
        [ "text", "plain", {} ]
      end

      # Splits a multipart body at its boundary lines into at most +limit+
      # chunks (nil: unbounded). The limit is enforced while scanning, not
      # by trimming afterwards: a body that is nothing but delimiter lines
      # ("--b\r\n" repeated, a few MiB via APPEND or SMTP) would otherwise
      # allocate a chunk string per line - hundreds of MB and seconds of
      # CPU on every BODYSTRUCTURE - before parse dropped the excess.
      # Everything past the last allowed delimiter is discarded, which is
      # what trimming did.
      def split_multipart(body, boundary, limit = nil)
        delim = "--#{boundary}"
        close = "#{delim}--"
        chunks = []
        current = nil
        body.each_line do |line|
          # Only a line that opens with the delimiter can be one; the
          # trailing-whitespace strip is skipped for every other line.
          marker = line.start_with?(delim) ? line.chomp.rstrip : nil
          if marker == delim
            chunks << current if current
            current = nil
            break if limit && chunks.size >= limit

            current = +"".b
          elsif marker == close
            chunks << current if current
            current = nil
          elsif current
            current << line
          end
        end
        chunks << current if current # tolerate a missing close delimiter
        chunks.map { |c| c.sub(/\r?\n\z/, "") }
      end

      # -- BODY[<section>] ----------------------------------------------------

      # Returns the octets for an IMAP section spec ("", "HEADER", "TEXT",
      # "HEADER.FIELDS (A B)", "1.2", "2.MIME", "2.HEADER", ...) or nil.
      def section(part, spec)
        spec = spec.to_s.strip
        return part.raw if spec.empty?

        numbers = []
        rest = spec
        while (m = rest.match(/\A(\d+)\.?/))
          numbers << m[1].to_i
          rest = rest[m.end(0)..]
        end
        target = dig_part(part, numbers)
        return nil unless target

        case rest.upcase
        when ""
          numbers.empty? ? target.raw : target.body
        when "MIME"
          numbers.empty? ? nil : target.header_block
        when "HEADER"
          message_of(target, numbers)&.header_block
        when "TEXT"
          message_of(target, numbers)&.body
        when /\AHEADER\.FIELDS(\.NOT)?\s*\(([^)]*)\)\z/i
          negate = !Regexp.last_match(1).nil?
          names = Regexp.last_match(2).split(/\s+/).map { |n| n.delete('"') }
          msg = message_of(target, numbers)
          msg && header_fields(msg.header_block, names, negate: negate)
        end
      end

      # HEADER/TEXT apply to the message itself at the top level, or to an
      # embedded message/rfc822 when addressed through a part number.
      def message_of(target, numbers)
        return target if numbers.empty?

        target.message_rfc822? ? target.embedded : nil
      end

      # Part numbers count from 1 (RFC 3501 §6.4.5); "0" names nothing,
      # and must not read as Ruby's last-element index.
      def dig_part(part, numbers)
        numbers.inject(part) do |cur, n|
          # No message has more than MAX_PARTS parts, and a number past a
          # machine word is a RangeError as an array index.
          return nil unless cur && n.positive? && n <= MAX_PARTS

          cur = cur.embedded if cur.message_rfc822?
          if cur.multipart?
            cur.children.to_a[n - 1]
          elsif n == 1
            cur
          end
        end
      end

      def header_fields(header_block, names, negate: false)
        # A Set: the name list is the client's and is checked per header line.
        wanted = names.to_set(&:downcase)
        out = +"".b
        keep = false
        header_block.each_line do |line|
          break if line.chomp.empty?

          unless line.start_with?(" ", "\t")
            name = line[/\A[^:]+/].to_s.strip.downcase
            keep = wanted.include?(name) ^ negate
          end
          out << line if keep
        end
        out << "\r\n"
      end

      # -- BODYSTRUCTURE / ENVELOPE -------------------------------------------

      # BODY is the plain form; BODYSTRUCTURE (extended: true) appends the
      # RFC 3501 extension data - body-fld-md5/dsp/lang/loc for single
      # parts, body-fld-param/dsp/lang/loc for multiparts. Clients use the
      # disposition data to list attachments without downloading bodies.
      def bodystructure(part, extended: false)
        if part.multipart? && part.children
          fields = [ "#{part.children.map { |c| bodystructure(c, extended: extended) }.join} #{quote(part.subtype.upcase)}" ]
          fields << params_list(part.params) << disposition(part) << language(part) << location(part) if extended
          "(#{fields.join(" ")})"
        else
          fields = [
            quote(part.type.upcase),
            quote(part.subtype.upcase),
            params_list(part.params),
            nstring(part.headers["content-id"]&.first),
            nstring(part.headers["content-description"]&.first),
            quote(part.encoding.upcase),
            part.size.to_s
          ]
          if part.message_rfc822? && part.embedded
            fields << envelope(part.embedded) << bodystructure(part.embedded, extended: extended) << part.line_count.to_s
          elsif part.type == "text"
            fields << part.line_count.to_s
          end
          if extended
            fields << nstring(part.headers["content-md5"]&.first)
            fields << disposition(part) << language(part) << location(part)
          end
          "(#{fields.join(" ")})"
        end
      end

      # body-fld-dsp: ("inline"/"attachment" (params)) or NIL.
      def disposition(part)
        value = part.headers["content-disposition"]&.first
        return "NIL" if value.nil? || value.strip.empty?

        type = value.split(";", 2).first.to_s.strip
        params = {}
        value.split(";", 2)[1].to_s.scan(/([\w-]+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^;\s]+))/) do |name, quoted, token|
          params[name.downcase] = quoted ? quoted.gsub(/\\(.)/, '\1') : token
        end
        "(#{quote(type.upcase)} #{params.empty? ? "NIL" : params_list(params)})"
      end

      # body-fld-lang: NIL, a single language tag, or a parenthesized list.
      def language(part)
        value = part.headers["content-language"]&.first
        return "NIL" if value.nil? || value.strip.empty?

        langs = value.split(",").map(&:strip).reject(&:empty?)
        langs.length == 1 ? quote(langs.first) : "(#{langs.map { |l| quote(l) }.join(" ")})"
      end

      def location(part)
        nstring(part.headers["content-location"]&.first)
      end

      def params_list(params)
        return "NIL" if params.nil? || params.empty?

        "(#{params.flat_map { |k, v| [ quote(k.upcase), quote(v.to_s) ] }.join(" ")})"
      end

      # Sender and Reply-To default to From (RFC 3501 §7.4.2); the From
      # list is built once and reused, not parsed again for each.
      def envelope(part)
        h = part.headers
        from = address_list(h["from"]&.first)
        "(#{[
          nstring(h["date"]&.first),
          nstring(h["subject"]&.first),
          from,
          h["sender"] ? address_list(h["sender"].first) : from,
          h["reply-to"] ? address_list(h["reply-to"].first) : from,
          address_list(h["to"]&.first),
          address_list(h["cc"]&.first),
          address_list(h["bcc"]&.first),
          nstring(h["in-reply-to"]&.first),
          nstring(h["message-id"]&.first)
        ].join(" ")})"
      end

      def address_list(value)
        addrs = parse_addresses(value)
        return "NIL" if addrs.empty?

        "(#{addrs.map { |name, mbox, host| "(#{nstring(name)} NIL #{nstring(mbox)} #{nstring(host)})" }.join})"
      end

      # How much of an address header ENVELOPE (and SORT FROM/TO/CC) will
      # read. The header is whatever the sender wrote - SMTP bounds only
      # the line length and the message - and megabytes of folded
      # addresses used to cost seconds of CPU per FETCH and an 8x larger
      # response. Mail to hundreds of visible recipients exists; the
      # envelope then lists the first MAX_ADDRESSES, and a client that
      # wants them all reads the header itself.
      MAX_ADDRESS_HEADER_BYTES = 64 * 1024
      MAX_ADDRESSES = 256
      # One address with its display name. Longer "addresses" are not
      # addresses, and are skipped rather than matched.
      MAX_ADDRESS_BYTES = 1024

      # [[display name or nil, mailbox, host], ...] for an address header.
      # Linear in the (capped) header: one scanner pass to split, one
      # anchored look at each piece.
      def parse_addresses(value)
        return [] if value.nil?

        value = value.b
        value = value.byteslice(0, MAX_ADDRESS_HEADER_BYTES) if value.bytesize > MAX_ADDRESS_HEADER_BYTES
        return [] if value.strip.empty?

        addresses = []
        split_on_commas(value) do |token|
          address = parse_address(token.strip)
          addresses << address if address
          break if addresses.length >= MAX_ADDRESSES
        end
        addresses
      end

      # "Display Name <local@host>" (the name optionally one quoted
      # string), or a bare local@host with optional angle brackets.
      def parse_address(token)
        return nil if token.empty? || token.bytesize > MAX_ADDRESS_BYTES

        if token.end_with?(">") && (found = angle_address(token))
          name, open, at = found
          [ (name unless name.empty?), token[(open + 1)...at], token[(at + 1)..-2] ]
        elsif (m = token.match(/\A<?([^@\s<>]+)@([^\s<>]+?)>?\z/))
          [ nil, m[1], m[2] ]
        end
      end

      # [name, index of "<", index of "@"] for a token ending in
      # "<local@host>", or nil. The angle address holds no ">" or
      # whitespace, so it opens after the last of those; a quoted name
      # directly in front of it is taken whole, otherwise the first "<"
      # with a mailbox behind it is the one. (A lazy regexp found the same
      # position by trying every prefix - quadratic in a long name with no
      # address behind it.)
      def angle_address(token)
        floor = token.rindex(/[>\s]/, -2) || -1
        if token.start_with?('"') && (close = token.index('"', 1))
          open = token.index(/\S/, close + 1)
          if open && open > floor && token[open] == "<" && (at = mailbox_end(token, open))
            return [ token[1...close], open, at ]
          end
        end

        open = token.index("<", floor + 1)
        open = token.index("<", open + 1) while open && token[open + 1] == "@"
        at = open && mailbox_end(token, open)
        [ token[0...open].rstrip, open, at ] if at
      end

      # The "@" that ends a non-empty mailbox opening at +open+ and has a
      # host after it.
      def mailbox_end(token, open)
        return nil if token[open + 1] == "@"

        at = token.index("@", open + 1)
        at if at && at < token.length - 2
      end

      # Yields the pieces of +value+ between top-level commas: a comma
      # inside a quoted string or an angle address does not split.
      def split_on_commas(value)
        scanner = StringScanner.new(value)
        start = 0
        quoted = false
        depth = 0
        while scanner.skip_until(/[",<>]/n)
          case value.getbyte(scanner.pos - 1)
          when 0x22 then quoted = !quoted
          when 0x3c then depth += 1 unless quoted
          when 0x3e then depth -= 1 if depth.positive? && !quoted
          else
            next if quoted || depth.positive?

            yield value.byteslice(start, scanner.pos - 1 - start)
            start = scanner.pos
          end
        end
        yield value.byteslice(start..).to_s
      end

      # -- PREVIEW (RFC 8970) --------------------------------------------------

      PREVIEW_MAX_CHARS = 200
      PREVIEW_MAX_OCTETS = 256
      # How much of the (still transfer-encoded) text part a preview is
      # made from: 200 characters of output never need the megabytes a
      # body can run to decoded, tag-stripped and transcoded.
      PREVIEW_SOURCE_BYTES = 64 * 1024

      # A short plain-text rendition of the message body for list views:
      # the first text part (multipart/alternative lists plain before html,
      # so plain wins), transfer-decoded, tags stripped for html, charset
      # coerced to UTF-8, whitespace collapsed, then capped at 200 chars /
      # 256 octets per the RFC. Always valid UTF-8, whatever the message
      # declares or contains: everything up to the transcode works on
      # bytes, and the transcode replaces what it cannot read.
      def preview(part)
        target = first_text_part(part)
        return "" unless target

        text = decode_transfer_encoding(target, PREVIEW_SOURCE_BYTES)
        text = text.gsub(/<[^>]*>/n, " ") if target.subtype == "html"
        text = to_utf8(text, target.params["charset"] || "US-ASCII")
        text = text.gsub(/\s+/, " ").strip[0, PREVIEW_MAX_CHARS]
        text = text[0..-2] while text.bytesize > PREVIEW_MAX_OCTETS
        text
      end

      # +bytes+ read as +charset+ and transcoded to UTF-8; as UTF-8 itself
      # when the charset is unknown, unconvertible, or not a name at all
      # (the header is the sender's). Invalid sequences become U+FFFD.
      def to_utf8(bytes, charset)
        text = begin
          bytes.dup.force_encoding(charset).encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
        rescue StandardError
          bytes.dup.force_encoding(Encoding::UTF_8)
        end
        text.scrub
      end

      def first_text_part(part)
        part = part.embedded if part.message_rfc822? && part.embedded
        if part.multipart? && part.children
          part.children.each do |child|
            found = first_text_part(child)
            return found if found
          end
          nil
        elsif part.type == "text"
          part
        end
      end

      # The first +limit+ octets of the part's body, transfer-decoded, as
      # a binary string. Rebuilt from its bytes: unpack("M") can hand
      # back a string flagged 7-bit that holds 8-bit bytes (a stray "="
      # before one), and every later validity check - scrub included -
      # trusts that flag, so the bad byte would surface only as an
      # exception in whichever string method looked first.
      def decode_transfer_encoding(part, limit)
        body = part.body.byteslice(0, limit)
        decoded =
          case part.encoding.downcase
          when "base64" then body.unpack1("m").to_s
          when "quoted-printable" then body.unpack1("M").to_s
          else body
          end
        decoded.unpack("C*").pack("C*")
      end

      # -- IMAP string encoding ------------------------------------------------

      def nstring(str)
        str.nil? ? "NIL" : quote(str)
      end

      def quote(str)
        str = str.to_s
        if str.match?(/[\r\n]/) || !str.ascii_only? || str.bytesize > 512
          literal(str)
        else
          %("#{str.gsub(/["\\]/) { |c| "\\#{c}" }}")
        end
      end

      def literal(str)
        "{#{str.bytesize}}\r\n#{str}"
      end
    end
  end
end

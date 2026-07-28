# frozen_string_literal: true

module MailOnRails
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

    def parse(raw, depth: 0, budget: nil)
      budget ||= { parts: MAX_PARTS }
      raw = raw.to_s.dup.force_encoding(Encoding::BINARY)
      header_block, body = split_header(raw)
      headers = parse_headers(header_block)
      type, subtype, params = parse_content_type(headers["content-type"]&.first)
      part = Part.new(header_block: header_block, headers: headers, body: body,
                      type: type, subtype: subtype, params: params)

      return part unless depth < MAX_DEPTH && budget[:parts].positive?

      if part.multipart? && params["boundary"]
        chunks = split_multipart(body, params["boundary"]).first(budget[:parts])
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

    def split_multipart(body, boundary)
      delim = "--#{boundary}"
      chunks = []
      current = nil
      body.each_line do |line|
        marker = line.chomp.rstrip
        if marker == delim
          chunks << current if current
          current = +"".b
        elsif marker == "#{delim}--"
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

    def dig_part(part, numbers)
      numbers.inject(part) do |cur, n|
        return nil unless cur

        cur = cur.embedded if cur.message_rfc822?
        if cur.multipart?
          cur.children.to_a[n - 1]
        elsif n == 1
          cur
        end
      end
    end

    def header_fields(header_block, names, negate: false)
      wanted = names.map(&:downcase)
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

    def envelope(part)
      h = part.headers
      from = h["from"]&.first
      "(#{[
        nstring(h["date"]&.first),
        nstring(h["subject"]&.first),
        address_list(from),
        address_list(h["sender"]&.first || from),
        address_list(h["reply-to"]&.first || from),
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

    def parse_addresses(value)
      return [] if value.nil? || value.strip.empty?

      split_on_commas(value).filter_map do |token|
        token = token.strip
        if (m = token.match(/\A(?:"([^"]*)"|(.*?))\s*<([^>@\s]+)@([^>\s]+)>\z/m))
          name = m[1] || m[2]
          name = nil if name&.empty?
          [ name, m[3], m[4] ]
        elsif (m = token.match(/\A<?([^@\s<>]+)@([^\s<>]+?)>?\z/))
          [ nil, m[1], m[2] ]
        end
      end
    end

    def split_on_commas(value)
      tokens = []
      current = +""
      quoted = false
      depth = 0
      value.each_char do |ch|
        case ch
        when '"' then quoted = !quoted
        when "<" then depth += 1 unless quoted
        when ">" then depth -= 1 if depth.positive? && !quoted
        when ","
          unless quoted || depth.positive?
            tokens << current
            current = +""
            next
          end
        end
        current << ch
      end
      tokens << current
    end

    # -- PREVIEW (RFC 8970) --------------------------------------------------

    PREVIEW_MAX_CHARS = 200
    PREVIEW_MAX_OCTETS = 256

    # A short plain-text rendition of the message body for list views:
    # the first text part (multipart/alternative lists plain before html,
    # so plain wins), transfer-decoded, tags stripped for html, charset
    # coerced to UTF-8, whitespace collapsed, then capped at 200 chars /
    # 256 octets per the RFC.
    def preview(part)
      target = first_text_part(part)
      return "" unless target

      text = decode_transfer_encoding(target)
      text = text.gsub(/<[^>]*>/, " ") if target.subtype == "html"
      charset = target.params["charset"] || "US-ASCII"
      text = begin
        text.force_encoding(charset).encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
      rescue StandardError
        text.dup.force_encoding(Encoding::UTF_8)
      end
      text = text.scrub.gsub(/\s+/, " ").strip[0, PREVIEW_MAX_CHARS]
      text = text[0..-2] while text.bytesize > PREVIEW_MAX_OCTETS
      text
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

    def decode_transfer_encoding(part)
      case part.encoding.downcase
      when "base64" then part.body.unpack1("m").to_s
      when "quoted-printable" then part.body.unpack1("M").to_s
      else part.body.dup
      end
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

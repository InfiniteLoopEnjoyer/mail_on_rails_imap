# frozen_string_literal: true

module MailOnRails
  module Imap
    # Modified UTF-7 mailbox-name encoding (RFC 3501 §5.1.3): non-ASCII
    # runs become "&<base64 of UTF-16BE, '/' as ','>-" and a literal "&"
    # becomes "&-". Store names are UTF-8; only the wire uses this form.
    module Utf7
      module_function

      def encode(name)
        utf8 = name.to_s.dup.force_encoding(Encoding::UTF_8)
        return name.to_s unless utf8.valid_encoding?

        utf8.gsub(/&|[^\x20-\x7e]+/) do |chunk|
          if chunk == "&"
            "&-"
          else
            b64 = [ chunk.encode(Encoding::UTF_16BE).b ].pack("m0").delete("=").tr("/", ",")
            "&#{b64}-"
          end
        end
      end

      def decode(name)
        name.to_s.gsub(/&([A-Za-z0-9+,]*)-/) do
          seg = Regexp.last_match(1)
          if seg.empty?
            "&"
          else
            b64 = seg.tr(",", "/")
            b64 += "=" * ((4 - b64.length % 4) % 4)
            b64.unpack1("m").force_encoding(Encoding::UTF_16BE).encode(Encoding::UTF_8)
          end
        end
      rescue StandardError
        name.to_s
      end
    end
  end
end

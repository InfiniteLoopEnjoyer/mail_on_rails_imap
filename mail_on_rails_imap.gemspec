# frozen_string_literal: true

require_relative "lib/mail_on_rails/imap/version"

Gem::Specification.new do |spec|
  spec.name = "mail_on_rails_imap"
  spec.version = MailOnRails::Imap::VERSION
  spec.summary = "Standalone IMAP4rev1 server (RFC 3501 subset) with pluggable stores"
  spec.description = "The mailbox-access commands real clients need (LOGIN, LIST, " \
                     "SELECT, UID FETCH/STORE/SEARCH/COPY, APPEND, EXPUNGE) over " \
                     "STARTTLS or implicit TLS, including MIME BODYSTRUCTURE. " \
                     "Persistence goes through any store satisfying the " \
                     "IMAP store contract."
  spec.authors = [ "Tayden Miller" ]
  spec.homepage = "https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.4"

  spec.files = Dir["lib/**/*.rb"] + %w[LICENSE README.md]
  spec.require_paths = [ "lib" ]
end

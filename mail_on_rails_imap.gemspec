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

  # logger stopped being a default gem in Ruby 4.0, so `require "logger"`
  # (daemon.rb, store/http.rb) raises LoadError under bundler unless it is
  # declared. In the Rails app the dependency comes in through Rails; the
  # standalone container has nothing else pulling it, so bin/server used to
  # crash-loop on boot.
  spec.add_dependency "logger"
end

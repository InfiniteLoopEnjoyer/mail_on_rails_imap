# frozen_string_literal: true

require_relative "lib/mail_on_rails/imap/version"

Gem::Specification.new do |spec|
  spec.name = "mail_on_rails_imap"
  spec.version = MailOnRails::Imap::VERSION
  spec.summary = "The IMAP server for mail_on_rails: IMAP and IMAPS listeners"
  spec.description = "An IMAP4rev1 server (RFC 3501 subset with STARTTLS, SCRAM-SHA-256(-PLUS), " \
                     "IDLE, CONDSTORE/QRESYNC, MOVE, SORT/THREAD, SPECIAL-USE, QUOTA, " \
                     "APPENDLIMIT) that serves mail from the mail_on_rails models gem's tables. " \
                     "Runs inside a Rails app's Puma process (plugin :mail_on_rails) or " \
                     "standalone (bin/mail_server --protocols imap), with or without the SMTP " \
                     "gem and the admin UI - an operator can fill the tables themselves."
  spec.authors = [ "Tayden Miller" ]
  spec.homepage = "https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage
  }

  spec.files = Dir["lib/**/*", "MIT-LICENSE", "README.md"]
  spec.require_paths = [ "lib" ]

  # The models, migrations, settings schema, listener scaffolding
  # (Netserv), SCRAM primitives, runtime and Puma plugin all live in the
  # core gem. Bump the two together.
  spec.add_dependency "mail_on_rails", ">= 0.1.0"
end

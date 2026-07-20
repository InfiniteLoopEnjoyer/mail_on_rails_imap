# frozen_string_literal: true

# The mail_on_rails_imap gem: a standalone IMAP4rev1 server (RFC 3501 subset)
# with its own listener scaffolding, TLS, and MIME handling - no shared
# runtime dependency on the SMTP gem. Persistence goes through any object
# satisfying the IMAP store contract (MailOnRails::Imap::Store::Contracts).
require_relative "imap/version"
require_relative "imap/server"
require_relative "imap/store/http"
require_relative "imap_server"

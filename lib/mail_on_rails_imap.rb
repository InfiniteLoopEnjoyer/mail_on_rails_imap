# frozen_string_literal: true

# Bundler's autorequire target (`gem "mail_on_rails_imap"`): loading the
# IMAP protocol gem registers IMAP with the core runtime, which is what
# lets `plugin :mail_on_rails` and bin/mail_server serve it.
require "mail_on_rails/imap"

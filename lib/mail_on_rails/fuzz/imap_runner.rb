# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../..", __dir__) unless $LOAD_PATH.include?(File.expand_path("../../..", __dir__))

require "mail_on_rails/fuzz/config"
require "mail_on_rails/fuzz/mutator"
require "mail_on_rails/fuzz/runner"
require "mail_on_rails/fuzz/imap"

MailOnRails::Fuzz::Imap.new.run!

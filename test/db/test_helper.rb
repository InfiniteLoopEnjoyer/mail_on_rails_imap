# frozen_string_literal: true

# Harness for the Active Record store suite: boots Active Record (no Rails
# application) through the core gem's test harness, which loads the models
# and runs every core migration - see MailOnRails::Testing::Database. The
# adapter comes from DATABASE_URL; without one, a throwaway SQLite file.
require "bundler/setup"
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

ENV.delete("DATABASE_URL") if ENV["DATABASE_URL"].to_s.strip.empty?

require "minitest/autorun"
require "mail_on_rails/testing/database"
require "mail_on_rails/imap"

MailOnRails::Testing::Database.setup!(sqlite_path: File.expand_path("../../tmp/db_suite.sqlite3", __dir__))

module Minitest
  class Test
    def self.test(name, &block)
      define_method("test_#{name.gsub(/\W+/, '_')}", &block)
    end

    def assert_not(object, message = nil)
      refute object, message
    end
  end
end

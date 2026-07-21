# frozen_string_literal: true

# Standalone harness: nothing from Rails or the host app is loaded here.
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

# Worker Ractors and the scheduler's IO::Buffer use are experimental APIs;
# the warnings are expected and drown real test output.
Warning[:experimental] = false

require "minitest/autorun"

# Minimal stand-in for the Rails-style `test "..."` declaration so suites
# read like Rails ones without pulling in ActiveSupport.
module Minitest
  class Test
    def self.test(name, &block)
      define_method("test_#{name.gsub(/\W+/, '_')}", &block)
    end

    # ActiveSupport::TestCase spelling.
    def assert_not(object, message = nil)
      refute object, message
    end
  end
end

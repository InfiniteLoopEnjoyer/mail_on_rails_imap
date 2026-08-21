# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/fuzz/config"
require "mail_on_rails/fuzz/mutator"
require "mail_on_rails/fuzz/runner"
require "mail_on_rails/fuzz/imap"

# CI smoke: a handful of fuzz rounds must pass the security oracles. Deep
# runs use bin/rails fuzz:imap with a higher FUZZ_ROUNDS.
class ImapFuzzSmokeTest < Minitest::Test
  def test_stateful_fuzz_rounds_pass_security_oracles
    fuzzer = MailOnRails::Fuzz::Imap.new(rounds: 15, seed: 0xBEEF)
    failures = fuzzer.run
    assert_empty failures, failures.map { |f| "round #{f.round} #{f.profile}: #{f.message}" }.join("\n")
  end
end

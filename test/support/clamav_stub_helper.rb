# frozen_string_literal: true

require "mail_on_rails/clamav_scanner"

# Swaps MailOnRails::ClamavScanner's module functions for the block's
# duration (minitest/mock ships as a separate gem under Minitest 6), then
# restores the originals. `scan:` takes a Result or a callable; pass a
# raising callable to assert a path must NOT scan.
module ClamavStubHelper
  def with_scanner(enabled:, scan: nil)
    singleton = MailOnRails::ClamavScanner.singleton_class
    original_enabled = MailOnRails::ClamavScanner.method(:enabled?)
    original_scan = MailOnRails::ClamavScanner.method(:scan)
    singleton.define_method(:enabled?) { enabled }
    singleton.define_method(:scan) { |raw| scan.respond_to?(:call) ? scan.call(raw) : scan }
    yield
  ensure
    singleton.define_method(:enabled?, original_enabled)
    singleton.define_method(:scan, original_scan)
  end
end

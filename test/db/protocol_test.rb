# frozen_string_literal: true

require_relative "test_helper"

# The IMAP runtime adapter: registered with the core runtime on load, and
# its production boot guard - the self-signed TLS fallback is
# development-only, so a production boot without explicit cert material
# must refuse to start.
class ImapProtocolTest < Minitest::Test
  TLS_ENV = %w[MAIL_ON_RAILS_TLS_CERT MAIL_ON_RAILS_TLS_KEY].freeze

  def with_tls_env(values)
    previous = TLS_ENV.to_h { |name| [ name, ENV[name] ] }
    TLS_ENV.each { |name| values[name] ? ENV[name] = values[name] : ENV.delete(name) }
    yield
  ensure
    previous.each { |name, value| value ? ENV[name] = value : ENV.delete(name) }
  end

  test "requiring the gem registers :imap with the runtime" do
    assert MailOnRails::Runtime.registered?(:imap)
    assert_equal MailOnRails::Imap::Protocol, MailOnRails::Runtime.adapter(:imap)
  end

  # Inside module Imap, a bare `Store` is Imap::Store (the memory store's
  # namespace) - the adapter must reach the Active Record backend by its
  # full name or the production boot dies with a NameError.
  test "start hands the daemon the Active Record store, stamped with source imap" do
    captured = nil
    original = MailOnRails::Imap::Daemon.method(:start)
    MailOnRails::Imap::Daemon.define_singleton_method(:start) { |store:, **| captured = store; :handle }
    begin
      assert_equal :handle, MailOnRails::Imap::Protocol.start(logger: MailOnRails.logger, tls_dir: nil)
    ensure
      MailOnRails::Imap::Daemon.define_singleton_method(:start, original)
    end
    assert_instance_of MailOnRails::Store::WithSource, captured
    assert_respond_to captured, :select_mailbox
  end

  test "a boot without explicit TLS material raises, naming the pair" do
    with_tls_env({}) do
      error = assert_raises(RuntimeError) { MailOnRails::Imap::Protocol.require_explicit_tls! }
      assert_match(/MAIL_ON_RAILS_TLS_CERT/, error.message)
    end
  end

  test "explicit material satisfies the guard" do
    with_tls_env("MAIL_ON_RAILS_TLS_CERT" => "/x/cert.pem", "MAIL_ON_RAILS_TLS_KEY" => "/x/key.pem") do
      assert_nil MailOnRails::Imap::Protocol.preflight!
    end
  end
end

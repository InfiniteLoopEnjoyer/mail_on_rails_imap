# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "logger"
require "stringio"
require "mail_on_rails/netserv/tls"
require "mail_on_rails/imap/daemon"

# Boot-time TLS material resolution, mirroring the SMTP twin. Explicitly
# configured cert/key paths that fail to load must be fatal: a mail host
# that silently degrades to plaintext-only looks healthy while dropping
# the IMAPS listener and (since LOGINDISABLED holds until the channel is
# encrypted) refusing every login. The self-signed development path stays
# forgiving.
class ImapTlsMaterialTest < Minitest::Test
  TLS = MailOnRails::Netserv::Tls
  ENV_KEYS = %w[MAIL_ON_RAILS_TLS_CERT MAIL_ON_RAILS_TLS_KEY].freeze

  def setup
    @saved_env = ENV_KEYS.to_h { |k| [ k, ENV.delete(k) ] }
  end

  def teardown
    @saved_env.each { |k, v| v ? ENV[k] = v : ENV.delete(k) }
  end

  def null_logger
    Logger.new(IO::NULL)
  end

  # Writes a freshly generated self-signed cert/key pair into a tmpdir.
  def with_valid_pems
    Dir.mktmpdir do |dir|
      pems = TLS.generate_self_signed
      cert = File.join(dir, "cert.pem")
      key = File.join(dir, "key.pem")
      File.write(cert, pems[:cert])
      File.write(key, pems[:key])
      yield cert, key, dir
    end
  end

  test "explicit cert and key paths load and are returned as path material" do
    with_valid_pems do |cert, key, _dir|
      ENV["MAIL_ON_RAILS_TLS_CERT"] = cert
      ENV["MAIL_ON_RAILS_TLS_KEY"] = key

      assert_equal({ cert_path: cert, key_path: key }, TLS.for(:imap).material(logger: null_logger))
    end
  end

  test "explicit paths that do not exist are fatal" do
    ENV["MAIL_ON_RAILS_TLS_CERT"] = "/nonexistent/fullchain.pem"
    ENV["MAIL_ON_RAILS_TLS_KEY"] = "/nonexistent/privkey.pem"

    error = assert_raises(TLS::Error) { TLS.for(:imap).material(logger: null_logger) }
    assert_match(/fullchain\.pem/, error.message, "the message must name the bad path")
  end

  test "explicit paths with unusable contents are fatal" do
    with_valid_pems do |_cert, key, dir|
      garbage = File.join(dir, "garbage.pem")
      File.write(garbage, "not a pem")
      ENV["MAIL_ON_RAILS_TLS_CERT"] = garbage
      ENV["MAIL_ON_RAILS_TLS_KEY"] = key

      assert_raises(TLS::Error) { TLS.for(:imap).material(logger: null_logger) }
    end
  end

  test "a cert paired with the wrong key is fatal" do
    with_valid_pems do |cert, _key, dir|
      other_key = File.join(dir, "other.key")
      File.write(other_key, TLS.generate_self_signed[:key])
      ENV["MAIL_ON_RAILS_TLS_CERT"] = cert
      ENV["MAIL_ON_RAILS_TLS_KEY"] = other_key

      assert_raises(TLS::Error) { TLS.for(:imap).material(logger: null_logger) }
    end
  end

  test "setting only one of cert or key is fatal, not a silent self-signed fallback" do
    ENV["MAIL_ON_RAILS_TLS_CERT"] = "/some/fullchain.pem"

    error = assert_raises(TLS::Error) { TLS.for(:imap).material(logger: null_logger) }
    assert_match(/set together/, error.message)
  end

  test "generated self-signed certs are leaf certs, not CAs" do
    cert = OpenSSL::X509::Certificate.new(TLS.generate_self_signed[:cert])
    extensions = cert.extensions.to_h { |ext| [ ext.oid, ext ] }

    assert_equal "CA:FALSE", extensions.fetch("basicConstraints").value
    assert extensions.fetch("basicConstraints").critical?
    refute_match(/Certificate Sign/i, extensions.fetch("keyUsage").value)
    assert_match(/Server Authentication|serverAuth/i, extensions.fetch("extendedKeyUsage").value)
    assert extensions.key?("subjectKeyIdentifier")
  end

  test "self-signed dev path stays forgiving and returns nil on failure" do
    assert_nil TLS.for(:imap).material(dir: nil, logger: null_logger)
  end

  test "self-signed dev path still provisions inline pems" do
    Dir.mktmpdir do |dir|
      material = TLS.for(:imap).material(dir: dir, logger: null_logger)

      assert material[:cert] && material[:key], "expected inline PEM material"
      assert_path_exists File.join(dir, "selfsigned.crt")
    end
  end

  test "daemon refuses to start on broken explicit TLS config" do
    ENV["MAIL_ON_RAILS_TLS_CERT"] = "/nonexistent/fullchain.pem"
    ENV["MAIL_ON_RAILS_TLS_KEY"] = "/nonexistent/privkey.pem"
    logs = StringIO.new

    error = assert_raises(MailOnRails::Netserv::Tls::Error) do
      MailOnRails::Imap::Daemon.start(store: nil, logger: Logger.new(logs))
    end

    assert_match(/fullchain\.pem/, error.message, "the error must name the bad path")
  end
end

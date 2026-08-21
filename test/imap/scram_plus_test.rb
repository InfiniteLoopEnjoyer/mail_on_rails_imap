# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/imap_server"
require "mail_on_rails/scram"
require "mail_on_rails/imap/store/memory"

# SCRAM-SHA-256-PLUS channel binding (RFC 5802 §6, RFC 5929, RFC 9266)
# over a real TLS upgrade. scram_session_test.rb covers the unbound
# exchange on plain sockets; everything channel binding adds - the -PLUS
# advertisement, binding proof, downgrade detection - needs the actual
# SSLSocket and lives here.
class ScramPlusTest < Minitest::Test
  Scram = MailOnRails::Scram

  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  # One self-signed pair for the whole suite; generating RSA keys per test
  # dominates the runtime otherwise.
  def self.tls_context
    @tls_context ||= MailOnRails::Netserv::Tls.context(MailOnRails::Netserv::Tls.generate_self_signed)
  end

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # A session upgraded to real TLS via STARTTLS; returns the client-side
  # SSLSocket, ready to authenticate.
  def tls_session
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    thread = Thread.new do
      MailOnRails::ImapServer::Session.new(session_socket, @store, { tls: :starttls }, self.class.tls_context).run
    end
    @cleanup << -> { client.close }
    @cleanup << -> { thread.join(5) }
    @cleanup << -> { server.close }
    client.gets("\r\n") # greeting
    client.write("s1 STARTTLS\r\n")
    client.gets("\r\n")

    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(client, ctx)
    tls.sync_close = true
    tls.connect
    tls
  end

  # Client-side channel-binding bytes, mirroring what the server derives.
  def client_cb_data(tls, type)
    case type
    when "tls-server-end-point"
      cert = tls.peer_cert
      OpenSSL::Digest.digest("SHA256", cert.to_der)
    when "tls-exporter"
      tls.export_keying_material("EXPORTER-Channel-Binding", 32, "")
    end
  end

  def read_until_tagged(client, tag)
    lines = []
    while (line = client.gets("\r\n"))
      lines << line
      break if line.start_with?("#{tag} ")
    end
    lines.join
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    read_until_tagged(client, tag)
  end

  def finish(client, tag, line)
    return line.to_s if line.nil? || line.start_with?("#{tag} ")

    line + read_until_tagged(client, tag)
  end

  def b64(str) = [ str ].pack("m0")
  def unb64(str) = str.unpack1("m0")

  # Full client side of the exchange. mechanism/gs2/cb_data let each test
  # pick a binding (or deliberately mismatch one).
  def authenticate(client, tag, mechanism: "SCRAM-SHA-256-PLUS", gs2: "p=tls-server-end-point,,",
                   cb_data: nil, password: PASSWORD, user: EMAIL, cnonce: "clientnonce123")
    bare = "n=#{user},r=#{cnonce}"
    client.write("#{tag} AUTHENTICATE #{mechanism} #{b64(gs2 + bare)}\r\n")
    line = client.gets("\r\n")
    return finish(client, tag, line) unless line.start_with?("+ ")

    server_first = unb64(line[2..].chomp("\r\n"))
    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    creds = Scram.derive(password, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)

    without_proof = "c=#{b64(gs2.b + cb_data.to_s.b)},r=#{attrs["r"]}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    proof = client_proof(password, creds, auth_message)

    client.write("#{b64("#{without_proof},p=#{b64(proof)}")}\r\n")
    line = client.gets("\r\n")
    return finish(client, tag, line) unless line.to_s.start_with?("+ ")

    client.write("\r\n")
    [ line, read_until_tagged(client, tag) ].join
  end

  def client_proof(password, creds, auth_message)
    salted = OpenSSL::KDF.pbkdf2_hmac(password, salt: creds[:salt], iterations: creds[:iterations],
                                      length: 32, hash: "SHA256")
    client_key = Scram.hmac(salted, "Client Key")
    Scram.xor(client_key, Scram.hmac(Scram.h(client_key), auth_message))
  end

  # -- advertisement ---------------------------------------------------------

  test "tls capabilities advertise scram-plus and list scram before plain" do
    client = tls_session
    caps = command(client, "a1", "CAPABILITY")

    assert_match(/AUTH=SCRAM-SHA-256-PLUS/, caps)
    scram = caps.index("AUTH=SCRAM-SHA-256 ")
    plain = caps.index("AUTH=PLAIN")

    assert scram && plain && scram < plain,
           "SCRAM must be listed before PLAIN so mechanism-order clients keep the password off the wire (#{caps.inspect})"
  end

  # -- bound authentication --------------------------------------------------

  test "scram-plus with tls-server-end-point authenticates" do
    client = tls_session
    cb = client_cb_data(client, "tls-server-end-point")

    assert_match(/^a1 OK \[CAPABILITY/, authenticate(client, "a1", cb_data: cb))
    assert_match(/^\* \d+ EXISTS/, command(client, "a2", "SELECT INBOX"))
  end

  test "scram-plus with tls-exporter authenticates" do
    client = tls_session
    # RFC 9266 defines tls-exporter over the TLS 1.3 exporter; the suite's
    # context negotiates 1.3 against a modern OpenSSL.
    assert_equal "TLSv1.3", client.ssl_version
    cb = client_cb_data(client, "tls-exporter")

    assert_match(/^a1 OK \[CAPABILITY/,
                 authenticate(client, "a1", gs2: "p=tls-exporter,,", cb_data: cb))
  end

  # -- binding verification --------------------------------------------------

  # The MITM case: a relayed exchange carries the *other* connection's
  # binding in c=, so the proof must not verify here.
  test "scram-plus with wrong channel binding data is rejected" do
    client = tls_session
    wrong = "x" * 32

    assert_match(/^a1 NO \[AUTHENTICATIONFAILED\]/, authenticate(client, "a1", cb_data: wrong))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  test "scram-plus with an unsupported binding type is refused" do
    client = tls_session
    reply = authenticate(client, "a1", gs2: "p=tls-unique,,", cb_data: "irrelevant")

    assert_match(/^a1 NO Unsupported channel binding type/, reply)
  end

  test "scram-plus without a p= header is bad" do
    client = tls_session
    reply = authenticate(client, "a1", gs2: "n,,")

    assert_match(/^a1 BAD Channel binding required/, reply)
  end

  # -- downgrade detection ---------------------------------------------------

  # RFC 5802 §6: "y" means the client supports channel binding but saw no
  # -PLUS advertised. This server advertises it, so "y" can only mean the
  # advertisement was stripped by an intermediary.
  test "a y gs2 flag over tls is rejected as a downgrade" do
    client = tls_session
    reply = authenticate(client, "a1", mechanism: "SCRAM-SHA-256", gs2: "y,,")

    assert_match(/^a1 NO Channel binding downgrade detected/, reply)
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  test "a p= header with the non-plus mechanism is refused" do
    client = tls_session
    reply = authenticate(client, "a1", mechanism: "SCRAM-SHA-256",
                         gs2: "p=tls-server-end-point,,",
                         cb_data: client_cb_data(client, "tls-server-end-point"))

    assert_match(/^a1 NO Channel binding requires SCRAM-SHA-256-PLUS/, reply)
  end

  # A client with no channel-binding support at all ("n") keeps working:
  # requiring -PLUS outright would strand every current mail client.
  test "unbound scram still authenticates over tls" do
    client = tls_session

    assert_match(/^a1 OK/, authenticate(client, "a1", mechanism: "SCRAM-SHA-256", gs2: "n,,"))
  end
end

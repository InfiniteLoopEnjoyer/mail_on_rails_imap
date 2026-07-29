# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/scram"
require "mail_on_rails/imap/store/memory"

# The SCRAM-SHA-256 AUTHENTICATE exchange as the session drives it over the
# wire. scram_test.rb pins the crypto against the RFC 7677 vectors; this
# suite covers the parts of RFC 5802 §5 the session itself is responsible
# for - nonce echo, channel-binding handling, and the rule that no failure
# path may leave the session authenticated.
class ScramSessionTest < Minitest::Test
  Scram = MailOnRails::Imap::Scram

  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  # Sessions are built as an implicit-TLS listener would, so AUTHENTICATE
  # is permitted on this (plain) loopback socket.
  def session
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.addr[1])
    client.timeout = 5
    session_socket = server.accept
    thread = Thread.new do
      MailOnRails::ImapServer::Session.new(session_socket, @store, { tls: :implicit }, nil).run
    end
    @cleanup << -> { client.close }
    @cleanup << -> { thread.join(5) }
    @cleanup << -> { server.close }
    client.gets("\r\n") # greeting
    client
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

  # Completes a response that has already had its first line read: a
  # refusal arrives as the tagged line itself, anything else still needs
  # draining up to the tag.
  def finish(client, tag, line)
    return line.to_s if line.nil? || line.start_with?("#{tag} ")

    line + read_until_tagged(client, tag)
  end

  # Everything the server sends before it hangs up.
  def drain(client)
    rest = +""
    rest << client.gets("\r\n").to_s while !client.eof?
    rest
  rescue IOError, SystemCallError
    rest
  end

  def b64(str) = [ str ].pack("m0")
  def unb64(str) = str.unpack1("m0")

  # Sends client-first and returns the parsed server-first attributes, or
  # the server's tagged/errored line when it refuses to continue.
  def begin_exchange(client, tag, gs2: "n,,", user: EMAIL, cnonce: "clientnonce123")
    bare = "n=#{user},r=#{cnonce}"
    client.write("#{tag} AUTHENTICATE SCRAM-SHA-256 #{b64(gs2 + bare)}\r\n")
    line = client.gets("\r\n")
    return [ nil, bare, line ] unless line.start_with?("+ ")

    server_first = unb64(line[2..].chomp("\r\n"))
    [ server_first, bare, line ]
  end

  # Full client side of the exchange. Overrides let each test corrupt
  # exactly one field of client-final.
  def authenticate(client, tag, password: PASSWORD, gs2: "n,,", user: EMAIL,
                   cnonce: "clientnonce123", nonce_override: nil, cbind_override: nil)
    server_first, bare, raw = begin_exchange(client, tag, gs2: gs2, user: user, cnonce: cnonce)
    return finish(client, tag, raw) unless server_first

    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    nonce = nonce_override || attrs["r"]
    creds = Scram.derive(password, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)

    without_proof = "c=#{cbind_override || b64(gs2)},r=#{nonce}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    proof = client_proof(password, creds, auth_message)

    client.write("#{b64("#{without_proof},p=#{b64(proof)}")}\r\n")
    line = client.gets("\r\n")
    return finish(client, tag, line) unless line.to_s.start_with?("+ ")

    # Server-final carries v=<server signature>; answer with the empty
    # client response RFC 5802 requires.
    client.write("\r\n")
    [ line, read_until_tagged(client, tag) ].join
  end

  # ClientProof = ClientKey XOR HMAC(StoredKey, AuthMessage).
  def client_proof(password, creds, auth_message)
    salted = OpenSSL::KDF.pbkdf2_hmac(password, salt: creds[:salt], iterations: creds[:iterations],
                                      length: 32, hash: "SHA256")
    client_key = Scram.hmac(salted, "Client Key")
    Scram.xor(client_key, Scram.hmac(Scram.h(client_key), auth_message))
  end

  # -- the happy path --------------------------------------------------------

  test "scram authenticates and binds the session to the account" do
    client = session
    assert_match(/^a1 OK \[CAPABILITY/, authenticate(client, "a1"))
    assert_match(/^\* 0 EXISTS|^\* \d+ EXISTS/, command(client, "a2", "SELECT INBOX"))
  end

  test "server final carries a verifiable server signature" do
    client = session
    server_first, bare, = begin_exchange(client, "a1")
    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    creds = Scram.derive(PASSWORD, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)

    without_proof = "c=#{b64("n,,")},r=#{attrs["r"]}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    proof = client_proof(PASSWORD, creds, auth_message)
    client.write("#{b64("#{without_proof},p=#{b64(proof)}")}\r\n")

    final = client.gets("\r\n")
    assert_match(/\A\+ /, final)
    verifier = unb64(final[2..].chomp("\r\n"))
    expected = b64(Scram.server_signature(creds[:server_key], auth_message))
    assert_equal "v=#{expected}", verifier
  end

  # -- failure paths ---------------------------------------------------------

  # The client must echo the server's full nonce; a client-chosen nonce
  # would let a MITM replay a captured proof under a nonce it controls.
  test "a client final that does not echo the server nonce is rejected" do
    client = session
    reply = authenticate(client, "a1", nonce_override: "clientnonce123attackerchosen")
    assert_match(/^a1 NO \[AUTHENTICATIONFAILED\]/, reply)
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  # c= must repeat the gs2 header verbatim, so a downgrade of the header
  # between client-first and client-final cannot go unnoticed.
  test "a client final with a mismatched channel binding value is rejected" do
    client = session
    reply = authenticate(client, "a1", cbind_override: b64("y,,"))
    assert_match(/^a1 NO \[AUTHENTICATIONFAILED\]/, reply)
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  test "a wrong password produces a bad proof and does not authenticate" do
    client = session
    reply = authenticate(client, "a1", password: "wrong-password")
    assert_match(/^a1 NO \[AUTHENTICATIONFAILED\]/, reply)
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  test "an unknown account fails without revealing that it is unknown" do
    client = session
    reply = authenticate(client, "a1", user: "nobody@example.test")
    assert_match(/^a1 NO \[AUTHENTICATIONFAILED\]/, reply)
    # Same response code as a wrong password: no user enumeration.
    refute_match(/no such|unknown|notfound/i, reply)
  end

  # A client demanding channel binding ("p=") must be told the server has
  # none, not silently downgraded to an unbound exchange.
  test "a client demanding channel binding is refused" do
    client = session
    reply = authenticate(client, "a1", gs2: "p=tls-unique,,")
    assert_match(/^a1 NO Channel binding not supported/, reply)
  end

  # "y,," means the client saw no channel-binding support advertised. The
  # server has none, so this is the honest case and must succeed.
  test "a client that saw no channel binding support authenticates normally" do
    client = session
    assert_match(/^a1 OK/, authenticate(client, "a1", gs2: "y,,"))
  end

  test "a malformed scram message is bad" do
    client = session
    # No n= (empty username) and no r=.
    client.write("a1 AUTHENTICATE SCRAM-SHA-256 #{b64("n,,n=,r=")}\r\n")
    assert_match(/\Aa1 BAD Malformed SCRAM message/, read_until_tagged(client, "a1"))
  end

  test "invalid base64 in the initial response is bad" do
    client = session
    assert_match(/\Aa1 BAD Invalid base64/, command(client, "a1", "AUTHENTICATE SCRAM-SHA-256 !!!not-base64!!!"))
  end

  test "invalid base64 in the client final response is bad" do
    client = session
    begin_exchange(client, "a1")
    client.write("!!!not-base64!!!\r\n")
    assert_match(/\Aa1 BAD Invalid base64/, read_until_tagged(client, "a1"))
  end

  test "invalid base64 in the proof is bad" do
    client = session
    server_first, = begin_exchange(client, "a1")
    nonce = server_first.split(",").find { |p| p.start_with?("r=") }[2..]
    client.write("#{b64("c=#{b64("n,,")},r=#{nonce},p=!!!not-base64!!!")}\r\n")
    assert_match(/\Aa1 BAD Invalid base64/, read_until_tagged(client, "a1"))
  end

  # A store that misbehaves is a server fault. It must not be reported as
  # the client's bad base64 - a blanket ArgumentError rescue around the
  # exchange used to do exactly that, hiding real errors behind a message
  # blaming whoever was trying to log in.
  class BrokenScramStore < MailOnRails::Imap::Store::Memory
    def scram_credentials(email, ip: nil)
      super.merge(stored_key_base64: "!!!not-base64!!!")
    end
  end

  test "a store error is an internal error, not invalid base64" do
    @store = BrokenScramStore.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)

    client = session
    reply = authenticate(client, "a1")
    assert_match(/\Aa1 BAD Internal error/, reply)
    refute_match(/Invalid base64/, reply)
  end

  # Same point from the other side: an ArgumentError raised anywhere in the
  # exchange that isn't a client base64 decode must surface as an internal
  # error too.
  class RaisingScramStore < MailOnRails::Imap::Store::Memory
    def scram_credentials(email, ip: nil)
      raise ArgumentError, "wrong number of arguments"
    end
  end

  test "an unrelated argument error is an internal error, not invalid base64" do
    @store = RaisingScramStore.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)

    client = session
    reply = authenticate(client, "a1")
    assert_match(/\Aa1 BAD Internal error/, reply)
    refute_match(/Invalid base64/, reply)
  end

  test "an unsupported mechanism is refused" do
    client = session
    assert_match(/\Aa1 NO Unsupported authentication mechanism/,
                 command(client, "a1", "AUTHENTICATE SCRAM-SHA-1"))
  end

  test "cancelling the exchange is not an authentication" do
    client = session
    client.write("a1 AUTHENTICATE SCRAM-SHA-256\r\n")
    assert_match(/\A\+ /, client.gets("\r\n"))
    client.write("*\r\n")
    assert_match(/\Aa1 BAD Authentication cancelled/, read_until_tagged(client, "a1"))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", "SELECT INBOX"))
  end

  # -- replay ----------------------------------------------------------------

  # The server nonce is fresh per exchange, so a client-final captured from
  # one session is worthless in the next: its proof is over the old
  # AuthMessage and its r= echoes the old nonce.
  test "a captured client final cannot be replayed into a new session" do
    first = session
    server_first, bare, = begin_exchange(first, "a1")
    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    creds = Scram.derive(PASSWORD, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)
    without_proof = "c=#{b64("n,,")},r=#{attrs["r"]}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    captured = b64("#{without_proof},p=#{b64(client_proof(PASSWORD, creds, auth_message))}")

    # It works once, on the session it was made for.
    first.write("#{captured}\r\n")
    assert_match(/\A\+ /, first.gets("\r\n"))

    # Replayed into a fresh exchange it is rejected: different server nonce.
    second = session
    second_first, = begin_exchange(second, "b1")
    refute_equal server_first, second_first, "server nonce must be fresh per exchange"

    second.write("#{captured}\r\n")
    assert_match(/^b1 NO \[AUTHENTICATIONFAILED\]/, read_until_tagged(second, "b1"))
    assert_match(/\Ab2 NO Not authenticated/, command(second, "b2", "SELECT INBOX"))
  end

  # -- attempt accounting ----------------------------------------------------

  # SCRAM failures never reach the store's password check, so they are
  # counted by the session's own auth_failure path. Past the cap the
  # connection is dropped, exactly as for LOGIN.
  test "scram failures count toward the auth attempt cap and drop the connection" do
    client = session
    (MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS - 1).times do |i|
      assert_match(/^f#{i} NO \[AUTHENTICATIONFAILED\]/, authenticate(client, "f#{i}", password: "wrong"))
    end

    final = authenticate(client, "flast", password: "wrong")
    assert_match(/^flast NO \[AUTHENTICATIONFAILED\]/, final)
    assert_match(/\* BYE Too many failed authentication attempts/, drain(client))
  end
end

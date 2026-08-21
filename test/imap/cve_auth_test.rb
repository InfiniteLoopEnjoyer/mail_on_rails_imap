# frozen_string_literal: true

require "test_helper"
require "socket"
require "openssl"
require "mail_on_rails/scram"
require "wire_harness"

# Regression tests against known IMAP CVE classes, driven over the wire the
# way wire_harness runs a real loopback session against the memory store.
#
# Classes covered here (scenarios already pinned elsewhere are not repeated):
#   - authentication bypass / state-machine confusion
#       (CVE-2011-3372, CVE-2006-6423, CVE-2020-1xxxx PREAUTH class):
#       authenticated-state commands before login, aborted SASL exchanges.
#       Re-auth-after-login and TLS gating live in cross_account_isolation_test
#       and starttls_test; pre-auth SELECT/FETCH/SEARCH/APPEND/IDLE in pen_test.
#   - user enumeration (CVE-2026-40193 / CVE-2008-1275 class): LOGIN and
#       AUTHENTICATE failures must be byte-identical for an unknown account and
#       a wrong password, and the SCRAM decoy must not leak an i= oracle.
#   - SASL / base64 robustness (CVE-2003-1177, CVE-2007-0887, CVE-2008-6984
#       class): malformed base64, misplaced/absent NULs in PLAIN, and binary
#       garbage in SCRAM must all fail closed under the attempt cap, never crash.
#
# The certificate-validation CVE class (CVE-2011-4318, CVE-2013-0308, ...) is
# not applicable: the IMAP code is only ever a TLS *server* (the sole
# OpenSSL::SSL::SSLSocket construction is Netserv::Tls.accept, server side). It
# never opens an outbound TLS connection, so there is no peer certificate for
# it to validate. See the final report for the evidence.
class ImapCveAuthTest < Minitest::Test
  include WireHarness

  Scram = MailOnRails::Scram

  UNKNOWN = "nobody@example.test"

  # -- class: authentication bypass / state-machine confusion ----------------

  # RFC 3501 §6.3/§6.4: authenticated-state commands must be refused before a
  # LOGIN/AUTHENTICATE succeeds. pen_test already covers SELECT/APPEND/FETCH/
  # SEARCH/IDLE; this pins the rest of the surface that goes through
  # require_auth, and asserts none of them is silently tolerated.
  def test_pre_auth_authenticated_state_commands_are_all_refused
    client = connect(login: false)
    commands = [
      %(LIST "" "*"), %(LSUB "" "*"), "STATUS INBOX (MESSAGES)",
      "CREATE Foo", "DELETE Foo", "RENAME Foo Bar", "EXAMINE INBOX",
      "NAMESPACE", "ENABLE CONDSTORE"
    ]
    commands.each_with_index do |cmd, i|
      reply = command(client, "p#{i}", cmd)
      assert_match(/\Ap#{i} (NO|BAD)/, reply, "#{cmd.inspect} must be refused before authentication")
    end
    # And the session is genuinely still unauthenticated afterwards.
    assert_match(/\Az NO Not authenticated/, command(client, "z", %(LIST "" "*")))
  end

  # Commands guarded by require_selected (STORE/COPY/MOVE/EXPUNGE/CLOSE) have
  # no selected mailbox pre-auth, so they too must refuse rather than act.
  def test_pre_auth_mailbox_commands_are_refused
    client = connect(login: false)
    %w[STORE COPY MOVE EXPUNGE CLOSE].each_with_index do |name, i|
      args = name == "STORE" ? "1 +FLAGS (\\Seen)" : name == "COPY" || name == "MOVE" ? "1 Bar" : ""
      reply = command(client, "s#{i}", "#{name} #{args}".strip)
      assert_match(/\As#{i} NO/, reply, "#{name} must be refused with no mailbox/auth")
    end
  end

  # The greeting is an ordinary "* OK", never a "* PREAUTH": a server that
  # pre-authenticates the connection (the Fetchmail/Thunderbird/Mutt PREAUTH
  # class, CVE-2021-39272 / CVE-2020-12398 / CVE-2020-14093) would let a
  # man-in-the-middle skip both TLS and the credential check. This server has
  # no PREAUTH code path at all; pin that it cannot regress into one.
  def test_greeting_is_never_preauth
    client = connect(login: false)
    # connect already consumed the greeting; open a raw one to read it.
    raw = TCPSocket.new("127.0.0.1", @listener.addr[1])
    @clients << raw
    greeting = raw.gets("\r\n")
    assert_match(/\A\* OK /, greeting)
    refute_match(/\APREAUTH/i, greeting.sub(/\A\* /, ""))
    # A pre-auth command is still refused, proving the greeting granted nothing.
    assert_match(/\Ag NO Not authenticated/, command(raw, "g", "SELECT INBOX"))
    client.close
  end

  # RFC 3501 §6.2.2: a client may abort an AUTHENTICATE exchange by sending a
  # bare "*". The session must reset cleanly - not authenticated, still usable
  # for a subsequent successful login - and must not have leaked an
  # authenticated state. Mirrors the SCRAM cancel test for the PLAIN path.
  def test_aborted_authenticate_plain_resets_cleanly
    client = connect(login: false)
    client.write("a1 AUTHENTICATE PLAIN\r\n")
    assert_match(/\A\+ /, client.gets("\r\n"), "server should send a SASL continuation")
    client.write("*\r\n")
    assert_match(/\Aa1 BAD Authentication cancelled/, read_until_tagged(client, "a1"))
    # Not authenticated by the aborted exchange...
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", %(LIST "" "*")))
    # ...and a real login on the same connection still works.
    assert_match(/\Aa3 OK/, command(client, "a3", "LOGIN #{EMAIL} #{PASSWORD}"))
  end

  # -- class: user enumeration -----------------------------------------------

  # The LOGIN failure for an unknown account and for a wrong password on a
  # real account must be byte-identical (tag aside) and carry no textual hint
  # of which case it was. A differing reply is a username oracle.
  def test_login_failure_is_identical_for_unknown_user_and_wrong_password
    unknown = strip_tag(login_attempt(UNKNOWN, PASSWORD))
    wrong   = strip_tag(login_attempt(EMAIL, "wrong-password"))
    assert_match(/\ANO \[AUTHENTICATIONFAILED\]/, unknown)
    assert_equal unknown, wrong, "the NO must not reveal whether the account exists"
    refute_match(/no such|unknown|not found|no account/i, unknown)
  end

  def test_authenticate_plain_failure_is_identical_for_unknown_user_and_wrong_password
    unknown = strip_tag(plain_attempt(UNKNOWN, PASSWORD))
    wrong   = strip_tag(plain_attempt(EMAIL, "wrong-password"))
    assert_match(/\ANO \[AUTHENTICATIONFAILED\]/, unknown)
    assert_equal unknown, wrong
  end

  # The same for a full SCRAM exchange: an unknown account is served decoy
  # verifier material so it still reaches the proof stage, and the proof
  # failure is reported identically to a wrong password on a real account.
  def test_scram_failure_is_identical_for_unknown_user_and_wrong_password
    unknown = strip_tag(scram_full_attempt(user: UNKNOWN, password: PASSWORD))
    wrong   = strip_tag(scram_full_attempt(user: EMAIL, password: "wrong-password"))
    assert_match(/NO \[AUTHENTICATIONFAILED\]/, unknown)
    assert_equal unknown, wrong
  end

  # SCRAM's server-first hands out salt and iteration count before any proof.
  # A real account serves the cost its credential was derived under; the decoy
  # must advertise the same iteration count, or i= becomes an existence oracle
  # (the caveat documented in Scram.decoy_credentials). scram_session_test
  # already pins that the decoy salt is stable; this pins i= parity with a real
  # account.
  def test_scram_decoy_iteration_count_matches_a_real_account
    unknown_i = scram_server_first(UNKNOWN)["i"]
    known_i   = scram_server_first(EMAIL)["i"]
    assert_operator unknown_i.to_i, :>=, 4096, "decoy must advertise a realistic iteration count"
    assert_equal known_i, unknown_i, "a differing i= for unknown accounts is a username oracle"
  end

  # -- class: SASL / base64 robustness ---------------------------------------

  # CVE-2003-1177 / CVE-2007-0887 class: garbage where base64 is expected must
  # be rejected as bad input, never decoded into a credential or crashed on.
  def test_authenticate_plain_with_non_base64_initial_response_is_bad
    client = connect(login: false)
    assert_match(/\Aa1 BAD Invalid base64/,
                 command(client, "a1", "AUTHENTICATE PLAIN !!!not-base64!!!"))
    # Session survives and is still unauthenticated.
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", %(LIST "" "*")))
  end

  # SASL PLAIN is base64("authzid\0authcid\0password"). A token with no NUL at
  # all (CVE-2008-6984 base64-confusion class) must fail closed as a bad
  # credential, not be mistaken for a username=password match.
  def test_authenticate_plain_without_nul_separators_fails_closed
    client = connect(login: false)
    token = [ EMAIL ].pack("m0") # valid base64, but no NULs
    assert_match(/\Aa1 NO \[AUTHENTICATIONFAILED\]/, command(client, "a1", "AUTHENTICATE PLAIN #{token}"))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", %(LIST "" "*")))
  end

  # One NUL only: authcid present but no password field. Must fail closed
  # (an empty/absent password is never a pass-through, the CVE-2013-6796 shape).
  def test_authenticate_plain_with_missing_password_field_fails_closed
    client = connect(login: false)
    token = [ "\0#{EMAIL}" ].pack("m0")
    assert_match(/\Aa1 NO \[AUTHENTICATIONFAILED\]/, command(client, "a1", "AUTHENTICATE PLAIN #{token}"))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", %(LIST "" "*")))
  end

  # A NUL embedded inside the password field (only the first two NULs are
  # separators) must not corrupt parsing into a match - it is simply a wrong
  # password, and the session stays unauthenticated and usable.
  def test_authenticate_plain_with_embedded_nul_in_password_fails_closed
    client = connect(login: false)
    token = [ "\0#{EMAIL}\0#{PASSWORD}\0extra" ].pack("m0")
    assert_match(/\Aa1 NO \[AUTHENTICATIONFAILED\]/, command(client, "a1", "AUTHENTICATE PLAIN #{token}"))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", %(LIST "" "*")))
  end

  # Binary garbage that is valid base64 but not a SCRAM client-first message
  # must be rejected as malformed, without crashing the session thread.
  def test_binary_garbage_scram_client_first_is_rejected_not_fatal
    client = connect(login: false)
    garbage = [ "\x00\x01\x02\xffnot-scram\x00".b ].pack("m0")
    assert_match(/\Aa1 BAD Malformed SCRAM message/,
                 command(client, "a1", "AUTHENTICATE SCRAM-SHA-256 #{garbage}"))
    assert_match(/\Aa2 NO Not authenticated/, command(client, "a2", %(LIST "" "*")))
  end

  # Repeated malformed AUTHENTICATE attempts must fail closed each time and,
  # at the per-connection cap, drop the connection rather than spin or crash.
  def test_repeated_malformed_auth_hits_the_attempt_cap_and_drops
    client = connect(login: false)
    cap = MailOnRails::ImapServer::MAX_AUTH_ATTEMPTS
    (cap - 1).times do |i|
      # Each undecodable PLAIN token counts as one failed attempt.
      token = [ "\0#{UNKNOWN}\0wrong#{i}" ].pack("m0")
      assert_match(/\Am#{i} NO \[AUTHENTICATIONFAILED\]/, command(client, "m#{i}", "AUTHENTICATE PLAIN #{token}"))
    end
    last = [ "\0#{UNKNOWN}\0nope" ].pack("m0")
    final = command(client, "mlast", "AUTHENTICATE PLAIN #{last}")
    assert_match(/mlast NO \[AUTHENTICATIONFAILED\]/, final)
    assert_match(/\* BYE Too many failed authentication attempts/, drain(client))
  end

  private

  # Strips the leading "tag " so replies from different connections compare
  # by content, not by the arbitrary tag.
  def strip_tag(line) = line.to_s.sub(/\A\S+ /, "")

  def login_attempt(user, pass)
    client = connect(login: false)
    command(client, "a1", "LOGIN #{user} #{pass}")
  end

  def plain_attempt(user, pass)
    client = connect(login: false)
    token = [ "\0#{user}\0#{pass}" ].pack("m0")
    command(client, "a1", "AUTHENTICATE PLAIN #{token}")
  end

  # Everything the server sends before it hangs up (used after the cap drop).
  def drain(client)
    rest = +""
    rest << client.gets("\r\n").to_s while !client.eof?
    rest
  rescue IOError, SystemCallError
    rest
  end

  def b64(str) = [ str ].pack("m0")
  def unb64(str) = str.unpack1("m0")

  # Opens a fresh session, sends SCRAM client-first for +user+, and returns
  # the parsed server-first attributes (r=, s=, i=); the exchange is cancelled.
  def scram_server_first(user)
    client = connect(login: false)
    bare = "n=#{user},r=clientnonce123"
    client.write("a1 AUTHENTICATE SCRAM-SHA-256 #{b64("n,,#{bare}")}\r\n")
    line = client.gets("\r\n")
    assert_match(/\A\+ /, line, "expected a server-first challenge for #{user}")
    attrs = unb64(line[2..].chomp("\r\n")).split(",").to_h { |p| [ p[0], p[2..] ] }
    client.write("*\r\n")
    read_until_tagged(client, "a1")
    attrs
  end

  # Runs a full (failing) SCRAM exchange and returns the final tagged line.
  # The proof is computed from +password+ against the server-advertised
  # salt/iterations, so a wrong password or an unknown account (decoy keys)
  # both fail at proof verification.
  def scram_full_attempt(user:, password:)
    client = connect(login: false)
    gs2 = "n,,"
    bare = "n=#{user},r=clientnonce123"
    client.write("a1 AUTHENTICATE SCRAM-SHA-256 #{b64(gs2 + bare)}\r\n")
    line = client.gets("\r\n")
    return finish_line(client, "a1", line) unless line.start_with?("+ ")

    server_first = unb64(line[2..].chomp("\r\n"))
    attrs = server_first.split(",").to_h { |p| [ p[0], p[2..] ] }
    creds = Scram.derive(password, salt: unb64(attrs["s"]), iterations: attrs["i"].to_i)
    without_proof = "c=#{b64(gs2)},r=#{attrs["r"]}"
    auth_message = "#{bare},#{server_first},#{without_proof}"
    proof = client_proof(password, creds, auth_message)
    client.write("#{b64("#{without_proof},p=#{b64(proof)}")}\r\n")
    reply = client.gets("\r\n")
    finish_line(client, "a1", reply)
  end

  def finish_line(client, tag, line)
    return line.to_s if line.nil? || line.start_with?("#{tag} ")

    line + read_until_tagged(client, tag)
  end

  def client_proof(password, creds, auth_message)
    salted = OpenSSL::KDF.pbkdf2_hmac(password, salt: creds[:salt], iterations: creds[:iterations],
                                      length: 32, hash: "SHA256")
    client_key = Scram.hmac(salted, "Client Key")
    Scram.xor(client_key, Scram.hmac(Scram.h(client_key), auth_message))
  end
end

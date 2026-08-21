require "test_helper"
require "wire_harness"

# QUOTA (RFC 2087 / RFC 9208): a single account-wide quota root named "",
# STORAGE as the only resource (units of 1024 octets), and NO [OVERQUOTA]
# refusals on APPEND/COPY once the account is full. SETQUOTA is always
# refused - limits are administered in the web UI.
class QuotaTest < Minitest::Test
  include WireHarness

  RAW = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"

  test "capability advertises QUOTA and the STORAGE resource" do
    c = connect(login: false)
    caps = command(c, "c1", "CAPABILITY")
    assert_match(/\bQUOTA\b/, caps)
    assert_match(/\bQUOTA=RES-STORAGE\b/, caps)
  end

  test "quota commands require authentication" do
    c = connect(login: false)
    assert_match(/\Aq1 NO Not authenticated/, command(c, "q1", %(GETQUOTA "")))
  end

  test "getquotaroot names the account root and reports no resources without a limit" do
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    response = command(c, "q1", "GETQUOTAROOT INBOX")
    assert_match(/^\* QUOTAROOT "INBOX" ""\r\n/, response)
    assert_match(/^\* QUOTA "" \(\)\r\n/, response)
    assert_match(/\Aq2 NO \[NONEXISTENT\]/, command(c, "q2", "GETQUOTAROOT Nope"))
  end

  test "getquota reports storage in units of 1024 octets rounded up" do
    @store.set_quota(@account_id, 1_048_576) # 1 MiB = 1024 units
    @store.append(@account_id, "INBOX", RAW, [], nil) # 37 bytes -> 1 unit
    c = connect
    response = command(c, "q1", %(GETQUOTA ""))
    assert_match(/^\* QUOTA "" \(STORAGE 1 1024\)\r\n/, response)
    assert_match(/^q1 OK/, response.lines.last)

    assert_match(/\Aq2 NO No such quota root/, command(c, "q2", %(GETQUOTA "Nope")))
    assert_match(/\Aq3 BAD/, command(c, "q3", "GETQUOTA"))
  end

  test "setquota is refused" do
    c = connect
    assert_match(/\Aq1 NO \[NOPERM\]/, command(c, "q1", %(SETQUOTA "" (STORAGE 512))))
  end

  test "append over quota returns NO with OVERQUOTA" do
    @store.set_quota(@account_id, RAW.bytesize)
    c = connect
    assert_match(/\Aa1 OK/, append(c, "a1", "INBOX", RAW).lines.last)
    assert_match(/\Aa2 NO \[OVERQUOTA\]/, append(c, "a2", "INBOX", RAW).lines.last)
  end

  test "copy over quota returns NO with OVERQUOTA but move still works" do
    @store.set_quota(@account_id, RAW.bytesize)
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "s1", "SELECT INBOX")
    assert_match(/\Ac1 NO \[OVERQUOTA\]/, command(c, "c1", "COPY 1 Trash").lines.last)
    assert_match(/^m1 OK/, command(c, "m1", "MOVE 1 Trash").lines.last,
                 "a full account must still be able to file mail away")
  end
end

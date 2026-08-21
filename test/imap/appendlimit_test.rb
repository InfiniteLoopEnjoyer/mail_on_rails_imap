require "test_helper"
require "wire_harness"

# APPENDLIMIT (RFC 7889): the fixed-limit capability form, the STATUS
# attribute, and the TOOBIG refusal (the refusal mechanics themselves are
# covered by the oversize-literal tests in imap_session_test.rb).
class AppendlimitTest < Minitest::Test
  include WireHarness

  test "capability advertises the fixed append limit" do
    c = connect(login: false)
    limit = MailOnRails::ImapServer::MAX_LITERAL_BYTES
    assert_match(/\bAPPENDLIMIT=#{limit}\b/, command(c, "c1", "CAPABILITY"))
  end

  test "status reports the append limit" do
    c = connect
    limit = MailOnRails::ImapServer::MAX_LITERAL_BYTES
    assert_match(/\* STATUS "INBOX" \(APPENDLIMIT #{limit}\)/, command(c, "s1", "STATUS INBOX (APPENDLIMIT)"))
  end
end

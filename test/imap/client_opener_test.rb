# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# Real-client opening sequences, replayed verbatim and asserted BAD-free.
#
# Born from a production incident (2026-08-13): the server advertised
# SPECIAL-USE but LIST rejected the RFC 6154 return option, and iOS Mail
# opens every sync with exactly that option - so iPhones got no folder
# list at all and looped forever. Every extension had its own passing
# test; what nothing checked was the full contract of an advertised
# capability, or a real client's opener end to end. These do both.
class ClientOpenerTest < Minitest::Test
  include WireHarness

  RAW = "From: sender@remote.test\r\nSubject: hi\r\n\r\nbody line\r\n"

  # The tagged replies a client actually keys on: none may be BAD or NO.
  def assert_all_ok(replies)
    replies.each do |(line, reply)|
      status = reply[/^\S+ (OK|NO|BAD)/, 1]
      assert_equal "OK", status, "#{line.inspect} answered:\n#{reply}"
    end
  end

  # iOS 26 Mail (com.apple.email.maild), captured from a live trace of an
  # iPhone syncing against this server. Tags and argument shapes are
  # verbatim; the AUTHENTICATE initial response is SASL-IR (also what the
  # phone sends).
  test "the iOS Mail opener completes without a single BAD" do
    3.times { @store.append(@account_id, "INBOX", RAW, [], nil) }
    client = connect(login: false)
    replies = []
    run = ->(tag, line) { replies << [ line, command(client, tag, line) ] }

    ir = [ "\0#{EMAIL}\0#{PASSWORD}" ].pack("m0")
    run.call("B1", "AUTHENTICATE PLAIN #{ir}")
    run.call("B2", %(ID ("name" "com.apple.email.maild" "version" "3864.600.51.2.1" "os" "iOS" "os-version" "26.5 (23F77)" "vendor" "Apple Inc" "event" NIL)))
    run.call("B3", "NAMESPACE")
    run.call("B4", %(LIST "" "*" RETURN (STATUS (MESSAGES UIDNEXT UIDVALIDITY UNSEEN HIGHESTMODSEQ) SPECIAL-USE)))
    run.call("C5", %(SELECT "INBOX" (CONDSTORE)))
    run.call("D35", "UID SEARCH RETURN (ALL) UID 1:*")
    run.call("C19", "UID FETCH 1:3 (UID BODY.PEEK[]<0.393216>)")
    assert_all_ok(replies)

    # The folder list must carry the special-use flags - this is what lets
    # the client map Sent instead of inventing "Sent Messages".
    list_reply = replies.find { |line, _| line.start_with?("LIST") }.last
    assert_match(/\* LIST \([^)]*\\Sent\) "\/" "Sent"/, list_reply)
    assert_match(/\* STATUS "Sent" /, list_reply)

    # The opener parks in IDLE; the server must accept and release it.
    client.write("D6 IDLE\r\n")
    assert_match(/\A\+ /, client.gets("\r\n"), "IDLE must answer with a continuation")
    client.write("DONE\r\n")
    assert_match(/\AD6 OK/, read_until_tagged(client, "D6"))
  end

  # Every advertised capability is a public contract: clients key their
  # entire behavior off this string, and an advertised-but-partial
  # extension fails WORSE than an absent one (see the class comment).
  # This pin makes editing the list a deliberate act: on a mismatch,
  # first cover the new capability's full contract - its commands,
  # arguments, options, return options, and response codes - with wire
  # tests, then update the pin.
  test "the advertised capability list is pinned to conformance coverage" do
    expected = %w[
      IMAP4rev1 UIDPLUS LITERAL+ IDLE MOVE UNSELECT NAMESPACE SPECIAL-USE
      CHILDREN ESEARCH WITHIN CONDSTORE ENABLE QRESYNC ID LIST-STATUS
      STATUS=SIZE SEARCHRES OBJECTID SAVEDATE PREVIEW REPLACE SORT
      THREAD=ORDEREDSUBJECT THREAD=REFERENCES
    ]
    advertised = MailOnRails::ImapServer::BASE_CAPABILITIES.split
                   .reject { |token| token.start_with?("APPENDLIMIT=") } # numeric, pinned by appendlimit_test

    assert_equal expected.sort, advertised.sort,
                 "BASE_CAPABILITIES changed. Each advertised capability is a contract " \
                 "clients rely on wholesale - add wire conformance tests for the new " \
                 "capability's complete surface before updating this pin."
  end
end

# frozen_string_literal: true

require "test_helper"
require "wire_harness"

# TEXT/BODY pushdown wiring: when the store offers search_text the
# session must resolve content keys store-side without ever fetching raw
# bytes; queries an index can't express (no word characters) and stores
# without search_text take the session's own substring scan. Substring
# *semantics* are audited in search_audit_test.rb - the memory store's
# search_text is RFC-exact, so those runs exercise the pushdown path too.
class SearchPushdownTest < Minitest::Test
  include WireHarness

  # Memory store that records pushdown calls and raw fetches.
  class ProbeStore < MailOnRails::Imap::Store::Memory
    attr_reader :search_text_calls

    def initialize(...)
      super
      @search_text_calls = []
      @raw_fetches = 0
    end

    def search_text(mailbox_id, query, scope)
      @search_text_calls << [ query, scope ]
      super
    end

    def fetch(mailbox_id, uids, with_raw)
      @raw_fetches += 1 if with_raw
      super
    end

    def raw_fetches = @raw_fetches
  end

  RAW = "From: fred@example.test\r\nSubject: afternoon meeting\r\n\r\nthe kumquat budget?\r\n"

  def swap_store(store)
    @store = store
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
  end

  def seed_and_select
    @store.append(@account_id, "INBOX", RAW, [], nil)
    c = connect
    command(c, "s0", "SELECT INBOX")
    c
  end

  def search_hits(client, tag, criteria)
    command(client, tag, "SEARCH #{criteria}")[/^\* SEARCH ?([\d ]*)/, 1].to_s.split.map(&:to_i)
  end

  test "TEXT and BODY push down to search_text without fetching raw bytes" do
    swap_store(ProbeStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "p1", %(TEXT "kumquat"))
    assert_equal [ 1 ], search_hits(c, "p2", %(BODY "kumquat"))
    # BODY never matches header-only text; the scope must reach the store.
    assert_equal [], search_hits(c, "p3", %(BODY "afternoon"))

    assert_equal [ [ "kumquat", "text" ], [ "kumquat", "body" ], [ "afternoon", "body" ] ],
                 @store.search_text_calls
    assert_equal 0, @store.raw_fetches, "pushdown must not ship raw bytes to the session"
  end

  test "queries without word characters take the substring scan instead" do
    swap_store(ProbeStore.new)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "q1", %(TEXT "?"))
    assert_equal [ 1 ], search_hits(c, "q2", %(TEXT ""))
    assert_equal [], search_hits(c, "q3", %(BODY "!"))

    assert_empty @store.search_text_calls, "an FTS index can't answer these"
    assert_operator @store.raw_fetches, :>, 0
  end

  test "a store without search_text falls back to the substring scan" do
    store = MailOnRails::Imap::Store::Memory.new
    store.singleton_class.send(:undef_method, :search_text)
    swap_store(store)
    c = seed_and_select

    assert_equal [ 1 ], search_hits(c, "f1", %(TEXT "kumquat"))
    assert_equal [ 1 ], search_hits(c, "f2", %(BODY "umqua")) # substring, RFC-exact
    assert_equal [], search_hits(c, "f3", %(BODY "afternoon"))
  end
end

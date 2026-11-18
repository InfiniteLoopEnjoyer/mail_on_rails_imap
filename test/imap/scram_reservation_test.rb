# frozen_string_literal: true

require_relative "scram_session_test"

# A SCRAM exchange is adjudicated here, not in the store, so the store's
# count-before-the-verdict (a reservation, Store::Base#scram_credentials
# with reserve: true) only works if the session plays its part: ask for
# the reservation, hand it back when the proof verifies, report it as
# already counted when the proof does not, and leave it standing when the
# client walks away. Without that, parallel exchanges all pass the
# throttle check before any failure lands.
class ScramReservationTest < ScramSessionTest
  # Drop the inherited cases: this file adds its own on the same helpers.
  ScramSessionTest.instance_methods(false).grep(/\Atest_/).each { |name| undef_method(name) }

  # The memory store plus the optional reservation methods, recording
  # how the session used them.
  class ReservingStore < MailOnRails::Imap::Store::Memory
    attr_reader :calls

    def initialize(...)
      super
      @calls = []
    end

    def scram_credentials(email, ip: nil, reserve: false)
      @calls << [ :lookup, reserve ]
      material = super(email, ip: ip)
      reserve ? material.merge(reservation: [ :hold, email ]) : material
    end

    def record_auth_failure(email, ip: nil, source: nil, reservation: nil)
      @calls << [ :failure, reservation ]
      {}
    end

    def record_auth_success(email, reservation: nil)
      @calls << [ :success, email, reservation ]
      {}
    end
  end

  def setup
    super
    @store = ReservingStore.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)
  end

  test "a verified proof gives the reservation back" do
    assert_match(/^a1 OK /, authenticate(session, "a1"))

    assert_equal [ [ :lookup, true ], [ :success, EMAIL, [ :hold, EMAIL ] ] ], @store.calls
  end

  test "a bad proof is reported with its reservation, so the store does not count it twice" do
    assert_match(/^a1 NO /, authenticate(session, "a1", password: "wrong-password"))

    assert_equal [ [ :lookup, true ], [ :failure, [ :hold, EMAIL ] ] ], @store.calls
  end

  test "an undecodable client-final is reported with its reservation" do
    client = session
    server_first, = begin_exchange(client, "a1")
    assert server_first
    client.write("!!!not-base64!!!\r\n")
    assert_match(/\Aa1 BAD Invalid base64/, read_until_tagged(client, "a1"))

    assert_equal [ [ :lookup, true ], [ :failure, [ :hold, EMAIL ] ] ], @store.calls
  end

  test "an exchange cancelled after the challenge keeps its reservation" do
    client = session
    server_first, = begin_exchange(client, "a1")
    assert server_first
    client.write("*\r\n")
    read_until_tagged(client, "a1")

    assert_equal [ :lookup, true ], @store.calls.first
    refute(@store.calls.any? { |call| call.first == :success }, "a cancelled exchange is never refunded")
  end

  test "a store without record_auth_success is asked the old way" do
    @store = MailOnRails::Imap::Store::Memory.new
    @account_id = @store.add_account(email: EMAIL, password: PASSWORD)

    assert_match(/^a1 OK /, authenticate(session, "a1"))
  end
end

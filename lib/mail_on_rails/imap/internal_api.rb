# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module MailOnRails
  module Imap
    # HTTP client for the host app's private IMAP API - authentication plus
    # one endpoint per store operation. With this, the IMAP daemon needs no
    # database connection.
    #
    # Non-2xx responses raise InternalApi::Error carrying a store-contract
    # error code; connection failures raise their own exceptions. The store
    # turns both into error envelopes (see Store::Contracts).
    class InternalApi
      class Error < StandardError
        attr_reader :code

        def initialize(message, code: :internal)
          super(message)
          @code = code
        end
      end

      OPEN_TIMEOUT = 5
      READ_TIMEOUT = 60 # fetches ship whole messages back

      # Connections are kept alive and pooled: a TLS handshake per store
      # call is what made IMAP feel slow, and handshake stalls under host
      # memory pressure were surfacing as login failures. Net::HTTP
      # re-validates a pooled connection itself - past keep_alive_timeout
      # it reconnects before sending rather than risking a request on a
      # socket the proxy already closed.
      KEEP_ALIVE_TIMEOUT = 15
      POOL_SIZE = 4 # retained connections; bursts open extra, shed on checkin

      def initialize(url: default_url, password: default_password)
        @base = URI(url.to_s.chomp("/"))
        @password = password
        @pool = []
        @pool_lock = Mutex.new
      end

      # => { account_id:, email: } (both nil on bad credentials), or
      # { throttled: true, retry_after: } when the app is refusing attempts
      # for this ip/account (see the app's AuthThrottle). +ip+ is the mail
      # client's address, which the app counts against.
      def authenticate(email, password, ip: nil)
        response = post_json("authenticate", email: email, password: password, ip: ip)
        result = { account_id: response["account_id"], email: response["email"] }
        result.merge!(throttled: true, retry_after: response["retry_after"]) if response["throttled"]
        result
      end

      # One IMAP store operation (see Store::Http); the endpoint delegates
      # to the host app's store. Returns the store-contract result with
      # symbol keys, symbol error codes, and raw bytes decoded.
      def imap_op(op, payload)
        request = Net::HTTP::Post.new("#{@base.path}/imap/#{op}")
        request.content_type = "application/json"
        request.body = JSON.generate(payload)

        response = perform(request)
        raise Error.new("imap/#{op} failed: #{response.code}") unless response.is_a?(Net::HTTPSuccess)

        self.class.decode_store_result(JSON.parse(response.body, symbolize_names: true))
      end

      # Undoes the JSON framing of a store result: error codes back to
      # symbols, base64-framed raw message bytes back to binary. Public so a
      # host app's test harness can drive the same endpoints through Rack.
      def self.decode_store_result(result)
        result[:code] = result[:code].to_sym if result[:code]
        if result[:messages].is_a?(Array)
          result[:messages].each do |message|
            next unless message.is_a?(Hash) && message.key?(:raw_base64)

            message[:raw] = message.delete(:raw_base64).unpack1("m0")
          end
        end
        result
      end

      private

      def post_json(endpoint, payload)
        request = Net::HTTP::Post.new("#{@base.path}/#{endpoint}")
        request.content_type = "application/json"
        request.body = JSON.generate(payload)

        response = perform(request)
        raise Error.new("#{endpoint} failed: #{response.code}") unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body)
      end

      def perform(request)
        # The basic-auth username is fixed by the app's controller.
        request.basic_auth("mail_on_rails", @password.to_s)
        http = checkout
        begin
          response = http.request(request)
        rescue StandardError
          discard(http)
          raise
        end
        checkin(http)
        response
      end

      # Sessions are fibers multiplexed on one thread per worker (see
      # Imap::Worker), so a Mutex is enough: a contested checkout parks
      # the fiber. The lock only guards the pool array - connections are
      # opened and used outside it, so slow requests don't serialize.
      def checkout
        @pool_lock.synchronize { @pool.pop } || connect
      end

      def checkin(http)
        surplus = @pool_lock.synchronize { @pool.size < POOL_SIZE ? (@pool.push(http); nil) : http }
        discard(surplus) if surplus
      end

      def discard(http)
        http.finish
      rescue StandardError
        nil
      end

      def connect
        http = Net::HTTP.new(@base.host, @base.port)
        http.use_ssl = @base.scheme == "https"
        http.open_timeout = OPEN_TIMEOUT
        http.read_timeout = READ_TIMEOUT
        http.keep_alive_timeout = KEEP_ALIVE_TIMEOUT
        http.start
      end

      def default_url
        ENV.fetch("MAIL_ON_RAILS_INTERNAL_API_URL") { "http://127.0.0.1:3000/mail_on_rails/internal" }
      end

      # The host app's internal API password, handed to this daemon as an
      # environment secret.
      def default_password
        ENV["MAIL_ON_RAILS_INTERNAL_API_PASSWORD"]
      end
    end
  end
end

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

      def initialize(url: default_url, password: default_password)
        @base = URI(url.to_s.chomp("/"))
        @password = password
      end

      # => { account_id:, email: } (both nil on bad credentials)
      def authenticate(email, password)
        response = post_json("authenticate", email: email, password: password)
        { account_id: response["account_id"], email: response["email"] }
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
        Net::HTTP.start(@base.host, @base.port, use_ssl: @base.scheme == "https",
                        open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT) do |http|
          http.request(request)
        end
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

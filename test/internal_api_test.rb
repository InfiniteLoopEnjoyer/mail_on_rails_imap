# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap/internal_api"

# Exercises the HTTP client against a minimal keep-alive HTTP/1.1 server.
# Connection reuse is what keeps IMAP responsive - a fresh TCP+TLS
# handshake per store call was the daemon's main latency source - so the
# suite pins it: sequential calls share one connection, and the pool
# degrades cleanly when the server refuses to keep connections open.
class InternalApiTest < Minitest::Test
  def setup
    @server = TCPServer.new("127.0.0.1", 0)
    @lock = Mutex.new
    @connections = 0
    @requests = 0
    @close_after_response = false
    @acceptor = Thread.new { accept_loop }
  end

  def teardown
    @server.close
    @acceptor.join(2)
  end

  def api
    MailOnRails::Imap::InternalApi.new(
      url: "http://127.0.0.1:#{@server.addr[1]}/mail_on_rails/internal", password: "secret"
    )
  end

  def counts
    @lock.synchronize { { connections: @connections, requests: @requests } }
  end

  def test_sequential_calls_reuse_one_connection
    client = api
    3.times do
      assert_equal 1, client.authenticate("user@example.test", "pw")[:account_id]
    end
    assert_equal({ connections: 1, requests: 3 }, counts)
  end

  def test_calls_still_succeed_when_the_server_closes_after_each_response
    @close_after_response = true
    client = api
    2.times do
      assert_equal 1, client.authenticate("user@example.test", "pw")[:account_id]
    end
    assert_equal 2, counts[:requests]
  end

  private

  def accept_loop
    loop do
      socket = begin
        @server.accept
      rescue IOError, SystemCallError
        break
      end
      @lock.synchronize { @connections += 1 }
      Thread.new(socket) { |s| serve(s) }
    end
  end

  # Just enough HTTP/1.1 to answer InternalApi's POSTs: read headers, read
  # the Content-Length body, reply with a fixed JSON credential result.
  def serve(socket)
    while socket.gets("\r\n")
      length = 0
      while (line = socket.gets("\r\n")) && line != "\r\n"
        length = Integer(line.split(":", 2).last.strip) if line.downcase.start_with?("content-length")
      end
      socket.read(length)
      @lock.synchronize { @requests += 1 }

      body = '{"account_id":1,"email":"user@example.test"}'
      connection = @close_after_response ? "Connection: close\r\n" : ""
      socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" \
                   "Content-Length: #{body.bytesize}\r\n#{connection}\r\n#{body}")
      break if @close_after_response
    end
  rescue IOError, SystemCallError
    nil
  ensure
    begin
      socket.close
    rescue StandardError
      nil
    end
  end
end

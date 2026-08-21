require "test_helper"
require "logger"
require "stringio"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# A dropped or timed-out IMAP connection must leave a log line rather than
# vanish in the run loop's rescue. Driven through a scripted socket so the
# transport failure is deterministic.
class ImapConnectionLossTest < Minitest::Test
  class FakeSocket
    def initialize(reads: [])
      @reads = reads
    end

    def gets(_sep, _limit)
      step = @reads.shift
      raise step if step.is_a?(Class) && step <= Exception

      step
    end

    def write(bytes) = bytes.bytesize

    def close = nil
  end

  def setup
    @logs = StringIO.new
    @store = MailOnRails::Imap::Store::Memory.new(logger: Logger.new(@logs, level: Logger::INFO))
  end

  def run_session(socket)
    MailOnRails::ImapServer::Session.new(socket, @store, { tls: :implicit }, nil).run
  end

  test "peer reset logs at info" do
    run_session(FakeSocket.new(reads: [ Errno::ECONNRESET ]))

    assert_match(/INFO.*IMAP connection lost: Errno::ECONNRESET/, @logs.string)
  end

  test "idle timeout logs at info" do
    run_session(FakeSocket.new(reads: [ IO::TimeoutError ]))

    assert_match(/INFO.*IMAP session idle timeout/, @logs.string)
  end
end

# frozen_string_literal: true

require_relative "test_helper"
require "logger"
require "stringio"

# The Mailbox model validates folder names for every writer, and its rules
# go beyond what the IMAP session checks before calling the store: edge
# whitespace, and a child that its parent's rename would push past the
# length or depth bound. A CREATE or RENAME the model refuses is the
# client's request being declined - NO [CANNOT], like the names the
# session declines itself - not a store fault answered "temporary server
# error" with an error-level log line.
class ImapBackendMailboxNameTest < MailOnRails::Testing::Database::TestCase
  PASSWORD = "a-long-test-password"

  def backend = @backend ||= MailOnRails::Store::ImapBackend.new

  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "names-#{SecureRandom.hex(4)}@example.test",
                                                   password: PASSWORD)
  end

  def names = account.mailboxes.order(:name).pluck(:name)

  # Everything the core logger and the store log receive inside the block.
  def captured_log
    io = StringIO.new
    original = MailOnRails.logger
    MailOnRails.logger = Logger.new(io)
    yield
    io.string
  ensure
    MailOnRails.logger = original
  end

  def with_wire_session
    account
    server, client = UNIXSocket.pair
    session = MailOnRails::ImapServer::Session.new(server, backend, { tls: :implicit }, nil)
    thread = Thread.new { session.run }
    client.timeout = 10
    client.gets("\r\n")
    assert_match(/\Al0 OK/, command(client, "l0", "LOGIN #{account.email} #{PASSWORD}"))
    yield client
  ensure
    client&.close
    thread&.join(5)
  end

  def command(client, tag, line)
    client.write("#{tag} #{line}\r\n")
    lines = []
    while (reply = client.gets("\r\n"))
      lines << reply
      break if reply.start_with?("#{tag} ")
    end
    lines.join
  end

  test "creating a name with trailing whitespace is declined, not a store error" do
    before = names
    result = nil
    log = captured_log { result = backend.create_mailbox(account.id, "Projects ") }

    assert_equal :cannot, result[:code]
    assert_equal "invalid mailbox name (must not start or end with whitespace)", result[:error]
    assert_equal before, names
    refute_match(/ERROR|store error|RecordInvalid/, log)
  end

  test "renaming to a name the model refuses is declined" do
    backend.create_mailbox(account.id, "Projects")
    result = nil
    log = captured_log { result = backend.rename_mailbox(account.id, "Projects", " Projects") }

    assert_equal :cannot, result[:code]
    assert_includes names, "Projects"
    refute_match(/ERROR|store error/, log)
  end

  # The new parent name is fine on its own; it is the child, renamed with
  # it, that would no longer be addressable. Nothing may be half-renamed.
  test "renaming a parent whose child would end up with an invalid name changes nothing" do
    limit = MailOnRails::Mailbox::MAX_NAME_BYTES
    child = "A/#{"c" * (limit - 10)}"
    backend.create_mailbox(account.id, "A")
    backend.create_mailbox(account.id, "A/keep")
    assert_nil backend.create_mailbox(account.id, child)[:error]
    before = names
    longer = "B" * 100 # valid itself; the long child under it would be over the byte limit

    result = nil
    log = captured_log { result = backend.rename_mailbox(account.id, "A", longer) }

    assert_equal :cannot, result[:code]
    assert_match(/\Ainvalid mailbox name \(is too long/, result[:error])
    assert_equal before, names, "the parent and its other children keep their names"
    refute_match(/ERROR|store error/, log)

    # And a rename that leaves every child valid still goes through.
    assert_equal({}, backend.rename_mailbox(account.id, "A", "Z"))
    assert_equal [ "Z", "Z/#{"c" * (limit - 10)}", "Z/keep" ], names.grep(/\AZ/)
    assert_empty names.grep(/\AA/)
  end

  test "a child pushed past the depth bound by its parent's rename is declined too" do
    depth = MailOnRails::Mailbox::MAX_DEPTH
    deep_child = "A/#{([ "l" ] * (depth - 2)).join("/")}" # depth - 2 separators under A: allowed
    backend.create_mailbox(account.id, "A")
    assert_nil backend.create_mailbox(account.id, deep_child)[:error]

    result = backend.rename_mailbox(account.id, "A", "x/y/z") # two more levels for every child

    assert_equal :cannot, result[:code]
    assert_includes names, deep_child
  end

  test "a name that only collides is still reported as existing" do
    backend.create_mailbox(account.id, "Projects")

    assert_equal :exists, backend.create_mailbox(account.id, "Projects")[:code]
  end

  test "on the wire: NO [CANNOT], no temporary-failure reply, no error log, session intact" do
    log = captured_log do
      with_wire_session do |client|
        assert_equal "a1 NO [CANNOT] CREATE failed: invalid mailbox name (must not start or end with whitespace)\r\n",
                     command(client, "a1", %(CREATE "Projects "))
        assert_match(/\Aa2 OK/, command(client, "a2", "CREATE Projects"))
        assert_equal "a3 NO [CANNOT] RENAME failed: invalid mailbox name (must not start or end with whitespace)\r\n",
                     command(client, "a3", %(RENAME Projects "Work "))
        list = command(client, "a4", %(LIST "" "*"))
        assert_match(/"Projects"\r\n/, list)
        refute_match(/Work/, list)
      end
    end

    refute_match(/ERROR|store error|failed in the store/, log)
  end
end

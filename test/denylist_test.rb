# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "fileutils"
require "mail_on_rails/imap/denylist"

# The banned_ips file reader: matching, fail-soft parsing, and the
# mtime-driven reload contract (see Denylist).
class DenylistTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @path = File.join(@dir, "banned_ips")
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  # ttl 0 stats on every call, so tests never wait out the throttle.
  def denylist(ttl: 0)
    MailOnRails::Imap::Denylist.new(@path, ttl: ttl)
  end

  def write(content, mtime: nil)
    File.write(@path, content)
    File.utime(File.atime(@path), mtime, @path) if mtime
  end

  test "disabled without a path" do
    assert_not MailOnRails::Imap::Denylist.new(nil).banned?("203.0.113.7")
    assert_not MailOnRails::Imap::Denylist.new("").banned?("203.0.113.7")
  end

  test "a missing file means no bans" do
    assert_not denylist.banned?("203.0.113.7")
  end

  test "matches exact addresses and CIDR ranges" do
    write("203.0.113.7\n198.51.100.0/24\n")
    list = denylist

    assert list.banned?("203.0.113.7")
    assert list.banned?("198.51.100.200")
    assert_not list.banned?("203.0.113.8")
    assert_not list.banned?("192.0.2.1")
  end

  test "matches IPv6 ranges, and IPv4 entries never match IPv6 peers" do
    write("2001:db8::/32\n0.0.0.0/8\n")
    list = denylist

    assert list.banned?("2001:db8::1")
    assert_not list.banned?("::1")
  end

  test "comments, blanks and garbage lines are skipped" do
    write("# comment\n\nnot-an-ip\n203.0.113.7\n")
    list = denylist

    assert list.banned?("203.0.113.7")
    assert_not list.banned?("192.0.2.1")
  end

  test "an unreadable peer address never matches" do
    write("0.0.0.0/8\n")
    list = denylist

    assert_not list.banned?(nil)
    assert_not list.banned?("?")
  end

  test "reloads when the file's mtime changes" do
    write("203.0.113.7\n")
    list = denylist
    assert list.banned?("203.0.113.7")

    write("192.0.2.1\n", mtime: Time.now + 10)
    assert_not list.banned?("203.0.113.7")
    assert list.banned?("192.0.2.1")
  end

  test "a deleted file empties the list" do
    write("203.0.113.7\n")
    list = denylist
    assert list.banned?("203.0.113.7")

    File.unlink(@path)
    assert_not list.banned?("203.0.113.7")
  end

  test "the stat is throttled to the ttl" do
    write("203.0.113.7\n")
    list = denylist(ttl: 600)
    assert list.banned?("203.0.113.7")

    write("192.0.2.1\n", mtime: Time.now + 10)
    # Within the ttl the old list keeps serving; no stat, no reload.
    assert list.banned?("203.0.113.7")
    assert_not list.banned?("192.0.2.1")
  end
end

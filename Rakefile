# frozen_string_literal: true

require "bundler/gem_tasks"

# Both suites run in a clean ruby subprocess with the bundle on the load
# path (the core gem is a bundled dependency): the wire suite is Rails-free
# and defines a minimal `test "..."` shim that would collide with
# ActiveSupport::TestCase; the db suite boots Active Record (no Rails app).
namespace :test do
  {
    wire: "test/imap",
    db: "test/db"
  }.each do |task_name, dir|
    desc "Run the #{task_name} suite (#{dir})"
    task task_name do
      command = [
        RbConfig.ruby, "-rbundler/setup", "-Ilib", "-Itest/support", "-I#{dir}",
        "-e", %(Dir.glob("#{dir}/**/*_test.rb").sort.each { |f| require File.expand_path(f) })
      ]
      system(*command, exception: true)
    end
  end
end

desc "Run the wire suite and the store suite"
task test: [ "test:wire", "test:db" ]

task default: :test

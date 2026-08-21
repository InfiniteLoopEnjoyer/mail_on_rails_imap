# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# The core gem (models, migrations, settings, netserv, runtime). Consumers
# pin it in their own Gemfile; for local development against a checkout:
#   bundle config set --local local.mail_on_rails /path/to/mail_on_rails
gem "mail_on_rails", github: "InfiniteLoopEnjoyer/mail_on_rails", branch: "main"

group :development, :test do
  # The AR-backed store suite runs on SQLite; the adapter matrix lives in
  # the core gem's CI.
  gem "sqlite3"
  gem "debug", platforms: %i[ mri windows ], require: "debug/prelude"
  gem "rubocop-rails-omakase", require: false
  gem "bundler-audit", require: false
end

source "https://rubygems.org"

# Runtime dependencies live in the gemspec (none - the gem is stdlib-only).
gemspec

group :development do
  gem "minitest"

  # Tests only: the strict reference IMAP client (integration tests drive
  # the server with it) and the oracle for the UTF-7 codec tests.
  gem "net-imap", require: false

  # Deploy this daemon as a Docker container (config/deploy.yml). Kamal
  # brings dotenv, which the deploy config uses to load .env for secrets.
  gem "kamal", require: false
  gem "dotenv", require: false

  # Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
  gem "rubocop-rails-omakase", require: false

  # Scans the bundle for gems with known CVEs (`bundle exec bundler-audit check --update`).
  gem "bundler-audit", require: false
end

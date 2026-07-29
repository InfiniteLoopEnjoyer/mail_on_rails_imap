# syntax=docker/dockerfile:1
# check=error=true

# Production image for the mail_on_rails_imap daemon (see config/deploy.yml).
# No Rails, no database - just the Ruby IMAP listeners talking HTTP to the
# host app. Build and run by hand with:
# docker build -t mail_on_rails_imap .
# docker run -d -p 143:1143 -p 993:1993 mail_on_rails_imap

# Matches the app image's Ruby (see .ruby-version); the gemspec floor is 3.4.
# Digest-pinned so builds can't silently pick up whatever the tag points at;
# Dependabot (docker ecosystem) PRs tag and digest bumps.
FROM docker.io/library/ruby:4.0.6-slim@sha256:abd7528c4df35d151e2643d5efb845e442a26e36a4babc6459bee508619137a2 AS base

WORKDIR /imap

ENV BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development"

# Throw-away build stage to drop bundler's caches and the compiler
# toolchain (json is the one C-extension gem - it is in the bundle to
# override the CVE-affected default gem, see the gemspec).
FROM base AS build

RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# The gemspec is the Gemfile's dependency source and loads version.rb.
COPY Gemfile Gemfile.lock mail_on_rails_imap.gemspec ./
COPY lib/mail_on_rails/imap/version.rb lib/mail_on_rails/imap/version.rb

RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache

COPY . .

# Final stage
FROM base

# The bundle carries a fixed json (>= 2.19.2); remove the base image's
# stale default gem (json 2.18.0, CVE-2026-33210) - spec AND stdlib copies,
# since plain `require "json"` outside bundler loads the stdlib file
# straight off $LOAD_PATH and would silently get 2.18.0.
RUN rm /usr/local/lib/ruby/gems/*/specifications/default/json-*.gemspec && \
    rm -rf /usr/local/lib/ruby/[0-9]*/json.rb /usr/local/lib/ruby/[0-9]*/json \
           /usr/local/lib/ruby/[0-9]*/*-linux*/json

# Run and own only the runtime files as a non-root user for security (which
# is also why the in-container listener ports stay >1024).
RUN groupadd --system --gid 1000 imap && \
    useradd imap --uid 1000 --gid 1000 --create-home --shell /bin/bash
USER 1000:1000

COPY --chown=imap:imap --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --chown=imap:imap --from=build /imap /imap

EXPOSE 1143 1993
CMD ["bin/server"]
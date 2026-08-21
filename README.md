# mail_on_rails_imap

[![CI](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap/actions/workflows/ci.yml)
[![Security](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap/actions/workflows/security.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap/actions/workflows/security.yml)
[![Lint](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap/actions/workflows/lint.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](MIT-LICENSE)

The IMAP server for [mail_on_rails](https://github.com/InfiniteLoopEnjoyer/mail_on_rails):
an IMAP4rev1 server (143 STARTTLS / 993 IMAPS) that serves mail from the
core gem's tables. RFC 3501 subset with LOGINDISABLED-until-TLS, AUTH
PLAIN and SCRAM-SHA-256(-PLUS), IDLE, CONDSTORE/QRESYNC, MOVE, UIDPLUS,
SORT/THREAD, ESEARCH/SEARCHRES, SPECIAL-USE, QUOTA, APPENDLIMIT, OBJECTID,
SAVEDATE, PREVIEW, LIST-STATUS, and per-IP connection caps, tarpits and
auth lockouts (the core gem's `Netserv` scaffolding). Tested against real
clients (iOS Mail in particular).

The three pieces of the stack:

| Gem | Owns |
|---|---|
| [`mail_on_rails`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails) (core) | models, migrations, jobs, mailroom, outbound delivery, settings schema, listener scaffolding, SCRAM primitives, runtime, Puma plugin, CLI |
| [`mail_on_rails_smtp`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp) | the SMTP server and its Active Record store |
| **`mail_on_rails_imap`** (this gem) | the IMAP server and its Active Record store |

Add only the protocol gems you want. A Rails app with core + this gem is
an IMAP server with no SMTP and no admin UI - your own code (or another
process) writes the `mail_on_rails_*` tables (domains, email accounts,
mailboxes, messages) and IMAP serves them. The companion
[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)
app is the full product (webmail + admin UI + both protocols), deployed
as web / smtp / imap containers from one image.

## Installation

```ruby
# Gemfile
gem "mail_on_rails",      git: "https://github.com/InfiniteLoopEnjoyer/mail_on_rails.git",      branch: "main"
gem "mail_on_rails_imap", git: "https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap.git", branch: "main"
```

```sh
bin/rails generate mail_on_rails:install   # bin/mail_server + initializer (core gem)
bin/rails db:migrate
```

Requiring the gem (Bundler does it for you) registers IMAP with
`MailOnRails::Runtime`; that is what makes it "installed".

## Running

**Standalone** (its own process or container - the production shape):

```sh
bin/mail_server --protocols imap          # binds 1143/1993 (>1024: the container runs unprivileged)
bin/mail_server check --protocols imap    # validate settings/TLS/ports without binding
```

**Inside the web process** (one container for everything):

```ruby
# config/puma.rb
plugin :mail_on_rails
```

```sh
MAIL_ON_RAILS_SERVERS=imap bin/rails server     # or "smtp,imap", or 0 for UI only
```

Unset, development serves every installed protocol and other environments
serve none in-process (run `bin/mail_server`). `config.mail_on_rails.protocols`
is the initializer equivalent.

**Solid Queue is required** for anything beyond serving the tables. A
`bin/mail_server` process runs no job worker; the core gem's
maintenance (`prune!` of history/throttles/transcripts, DKIM rotation,
report sending) and the jobs IMAP sessions enqueue (honeypot and IP
enrichment) are Active Jobs driven by the host's recurring schedule -
the reference is
[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)'s
`config/recurring.yml` on a Solid Queue supervisor against the same
database. If the same deployment also accepts mail (the SMTP gem), the
worker is what routes and delivers it - see that gem's README. A
standalone mode that runs Solid Queue inside `bin/mail_server` is on the
todo list.

## Configuration

Everything is a setting in the core gem's schema (`MailOnRails::Settings`,
`imap_*` names; see its `docs/settings.md`), layered
`default < ENV < initializer < database`. The essentials:

| Setting | ENV | Default |
|---|---|---|
| `imap_host`, `imap_port`, `imaps_port` | `MAIL_ON_RAILS_HOST`, `MAIL_ON_RAILS_IMAP_PORT`, `MAIL_ON_RAILS_IMAPS_PORT` | `0.0.0.0`, 1143, 1993 |
| `imap_tls_cert`, `imap_tls_key` | `MAIL_ON_RAILS_TLS_CERT`, `MAIL_ON_RAILS_TLS_KEY` | self-signed in development; **required in production** |
| `imap_idle_poll`, `imap_session_seconds`, `imap_max_conn`, `imap_max_conn_per_ip`, ... | `MAIL_ON_RAILS_IMAP_IDLE_POLL`, ... | see schema |
| `imap_append_fail_closed` | `MAIL_ON_RAILS_IMAP_APPEND_FAIL_CLOSED` | true (APPEND defers when the virus scanner is down) |

## Layout

```
lib/mail_on_rails/imap.rb              entry: registers MailOnRails::Imap::Protocol with the runtime
lib/mail_on_rails/imap_server.rb       the server (sessions, commands, extensions)
lib/mail_on_rails/imap/daemon.rb       listener specs + TLS material -> a running server
lib/mail_on_rails/imap/{mime,utf7,session_helpers}.rb
lib/mail_on_rails/imap/store/          the store contract (executable) and the memory store
lib/mail_on_rails/store/imap_backend.rb the Active Record store (core models)
lib/mail_on_rails/fuzz/imap*.rb        fuzz harness
test/imap                              wire/session/CVE/client suites (Rails-free)
test/db                                the AR store against the contract (SQLite)
```

The server never touches Active Record or Rails directly: it talks to an
injected store (`docs/store_contract.md` in the core gem). Its live
connections, lockouts and heartbeat are projected into the core gem's ops
tables by `Netserv::OpsSync`, which is how the admin UI shows them from
another container.

## Testing

```sh
bundle exec rake test          # wire + store suites
bundle exec rake test:wire     # Rails-free
bundle exec rake test:db       # DATABASE_URL or SQLite
FUZZ_ROUNDS=25 bundle exec ruby -Ilib lib/mail_on_rails/fuzz/imap_runner.rb
```

For local development against a core checkout:
`bundle config set --local local.mail_on_rails /path/to/mail_on_rails`.

## License

MIT - see [MIT-LICENSE](MIT-LICENSE).

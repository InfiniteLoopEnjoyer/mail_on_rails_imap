# mail_on_rails_imap

A standalone IMAP4rev1 server (RFC 3501 subset): the mailbox-access
commands real clients need (LOGIN, LIST, SELECT, UID FETCH/STORE/SEARCH/
COPY, APPEND, EXPUNGE) over STARTTLS or implicit TLS, including MIME
BODYSTRUCTURE. Designed as the mailbox-access frontend for a Rails app.

The daemon holds **no database credentials and no Rails**: every store
operation is an HTTP call to the host app's private API (one round-trip
per IMAP store call - chatty, accepted for the isolation). If the app is
down, sessions report temporary failures and clients retry.

Persistence is pluggable: any store satisfying the contract can back the
server. `Store::Memory` is the dependency-free reference implementation,
`Store::Http` the production client, and `Store::Contracts` the
executable (Minitest) spec a custom store must pass.

## Concurrency architecture

Sessions are served by a pool of **worker Ractors** (one per core by
default), each running a single thread whose hand-rolled
**fiber scheduler** (`Imap::Scheduler`, pure Ruby over `IO.select`)
multiplexes every session on that worker: socket reads, TLS handshakes,
and store HTTP calls park a fiber, never the thread. Accept threads stay
in the main Ractor with the exact process-wide `ConnLimiter`; accepted
sockets cross to workers as **raw fd numbers over a control pipe** (fds
are process-global, and integer messages sidestep Ractor IO moves, which
Ruby 4.0.6 does not handle reliably under a scheduler - probes documented
in `scheduler.rb`/`worker.rb`). Finished sessions are reported back as
single bytes on a shared release pipe.

Ractor mode engages when the store can be rebuilt inside each worker
(`Store::Http` can - it is an env-configured HTTP client). An injected
store instance (tests, embedded development) falls back to the same
worker/scheduler core on plain threads, so both modes exercise identical
session code. Requires Ruby >= 4.0 in Ractor mode; Ractors are still
formally experimental there.

Companion repos:
[mail_on_rails](https://github.com/InfiniteLoopEnjoyer/mail_on_rails)
(the host Rails app — persistence, internal API, and web UI) and
[mail_on_rails_smtp](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp)
(the SMTP server).

## Layout

- `lib/mail_on_rails/imap/` - the gem: listener scaffolding
  (`Server`/`ConnLimiter`/`TLS`), the serving core (`Worker` sessions on a
  hand-rolled fiber `Scheduler`, one worker Ractor per core in
  production), the IMAP session (`ImapServer`), MIME parsing, and stores
  (`Store::Memory` reference implementation, `Store::Http` production
  client, `Store::Contracts` executable contract suite).
- `lib/mail_on_rails/imap/daemon.rb` - env-driven runtime; also embeddable
  in a host process (e.g. inside Puma in development, passing your own
  store and logger).
- `bin/server` - foreground entrypoint the container runs.
- `config/deploy.yml` - Kamal service definition.

## Host app requirements

`Store::Http` expects the host Rails app to expose a private internal API
behind basic auth: `POST authenticate` plus one `POST imap/<op>` endpoint
per store operation (see `InternalApi` for the exact request/response
shapes). Raw message bytes are base64-framed in both directions so
arbitrary binary survives JSON.

## Configuration (environment)

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAIL_ON_RAILS_INTERNAL_API_URL` | `http://127.0.0.1:3000/mail_on_rails/internal` | App's private API |
| `MAIL_ON_RAILS_INTERNAL_API_PASSWORD` | - | Basic-auth password for it |
| `MAIL_ON_RAILS_HOST` | `0.0.0.0` | Bind address |
| `MAIL_ON_RAILS_IMAP_PORT` / `_IMAPS_PORT` | `1143` / `1993` | Listener ports |
| `MAIL_ON_RAILS_TLS_CERT` / `_TLS_KEY` | - | PEM paths (else self-signed under `MAIL_ON_RAILS_TLS_DIR`, default `storage/tls`) |
| `MAIL_ON_RAILS_IMAP_MAX_CONN` | `100` | Connection cap |
| `MAIL_ON_RAILS_IMAP_MAX_LINE` | `65536` | Command-line length cap |
| `MAIL_ON_RAILS_IMAP_WORKERS` | CPU cores | Session worker count |
| `MAIL_ON_RAILS_IMAP_WORKER_MODE` | auto | `thread` forces thread workers (no Ractors) |

## Test / run

    bundle install
    bin/test        # Rails-free suite (loopback sessions, contracts)
    bin/server      # foreground daemon

## Deploy

    bin/kamal deploy -d prod

`config/deploy.yml` is a generic template. Put your real infrastructure
(hosts, registry, domains) in a gitignored destination overlay -
`config/deploy.prod.yml` - and deploy with `-d prod`. Secrets come from
the gitignored `.env` (see `.kamal/secrets-common`); the value must
match the host app's internal API password.

## License

MIT - see [LICENSE](LICENSE).

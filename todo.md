# IMAP daemon todo

Running list of improvements. The original gap list (vs RIMS + net-imap,
2026-07-27) was completed and removed. Rule: every item lands with tests.

- [ ] **Auth cache for reconnect storms** — iOS opens ~5 fresh connections per
      folder refresh and LOGINs on each; every LOGIN costs a bcrypt check in
      the app (~300 ms idle, ~1 s when they land concurrently on the 1-vCPU
      droplet — measured 4.3 s of a 10 s refresh). Cache a successful check
      briefly (e.g. SHA-256 of email+password → account, 60–120 s TTL,
      per-worker in the daemon) so a refresh costs one bcrypt, not five.
      TTL bounds staleness after a password change; a cached entry must never
      outlive MAX_AUTH_ATTEMPTS accounting for *failed* attempts (only cache
      successes).

- [x] **Plain-HTTP internal API** — DONE 2026-07-28 (app 000d99a alias, imap
      env flip, exim followed the same day) — drop TLS on the daemon→app hop (verified
      2026-07-28: `assume_ssl = true` means a direct `http://<container>:80`
      call reaches the internal controller, 401 not 301, so no app code
      change). Needs a stable `--network-alias` on the app's kamal role +
      `MAIL_ON_RAILS_INTERNAL_API_URL=http://<alias>/mail_on_rails/internal`.
      Decouples IMAP from kamal-proxy uptime and public-cert renewals.
      Traffic stays on the host-local docker bridge. Deploy app (alias)
      first, then the daemon env; exim's INTERNAL_API_URL can follow.

- [ ] (optional, later) true SQL pushdown — a store `search` op could skip
      the metadata fetch, but with two-phase evaluation the remaining win is
      small; revisit only if metadata volume becomes a problem

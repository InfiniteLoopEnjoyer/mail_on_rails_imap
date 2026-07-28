# IMAP server gap list (vs RIMS + net-imap client expectations)

Source: comparative scan of this repo, y10k/rims, and ruby/net-imap (2026-07-27).
Rule: every item lands with tests.

## Tier 0 — correctness bugs (advertised behavior that's wrong) — DONE 2026-07-27

- [x] **UID EXPUNGE honors its sequence set** — store contract now
      `expunge(mailbox_id, uids = nil)` across memory store, http store,
      internal API, Rails `ImapBackend`, contracts suite.
- [x] **Over-size literal desync** — `refuse_literal` drains non-sync payloads
      (bounded chunks) and withholds the continuation for sync literals.
- [x] **Unbounded AUTHENTICATE continuation read** — goes through `read_line`
      (MAX_LINE cap); transport errors are now session-fatal in `handle` too.
- [x] **Response-format strictness** — audit found mime.rb already correct
      (ENVELOPE NIL, text line counts, quoted INTERNALDATE, sync literals only);
      locked in by test/mime_format_test.rb + net-imap integration tests.
- [x] **SEARCH fixes** — `SENT*` matches the `Date:` header; unknown key /
      bad date → tagged `BAD` (SearchSyntaxError); CHARSET validated with
      `NO [BADCHARSET (US-ASCII UTF-8)]`; OR/NOT require operands.

## Tier 1 — features clients actually use — DONE 2026-07-27

- [x] **IDLE** — implemented as server-side resync polling
      (`IDLE_POLL_SECONDS`, default 30s, env-tunable) rather than a RIMS-style
      in-process bus: the store is the source of truth and new delivery happens
      in the Rails process, so an in-process bus would miss the main event.
      resync now also reports flag changes (`FETCH (FLAGS ...)`) alongside
      EXPUNGE (reverse order) + EXISTS. DONE answered immediately.
- [x] **DELETE / RENAME** — store ops `delete_mailbox` / `rename_mailbox`
      (renames children in the `/` hierarchy); INBOX refused in the session.
      INBOX-rename RFC semantics deliberately not implemented (refused).
- [x] **MOVE / UID MOVE** — atomic `move` store op; untagged
      `OK [COPYUID ...]` precedes the EXPUNGEs per RFC 6851.
- [x] **UNSELECT** — done.
- [x] **Modified UTF-7 mailbox names** — hand-rolled `Imap::Utf7`
      (dependency-free), tested against `Net::IMAP.encode_utf7/decode_utf7`
      as oracle; applied on every inbound name and LIST/STATUS output.
- [x] **LIST attributes** — real `\HasChildren`/`\HasNoChildren` + SPECIAL-USE
      attrs on Sent/Drafts/Trash/Junk.
- [x] **Capability housekeeping** — now advertises
      `IMAP4rev1 UIDPLUS LITERAL+ IDLE MOVE UNSELECT NAMESPACE SPECIAL-USE
      CHILDREN ID` (+ `AUTH=PLAIN SASL-IR` once encrypted); ID returns real
      server identity.

## Tier 2 — later

- [x] ESEARCH `RETURN (MIN MAX COUNT ALL)` with `(TAG "...")` correlator,
      `RETURN ()` = ALL, MIN/MAX/ALL omitted on empty results — DONE 2026-07-27,
      advertised, verified through net-imap's ESearchResult
- [x] `TEXT` vs `BODY` differentiated (BODY excludes headers) — DONE 2026-07-27
- [x] OLDER/YOUNGER (RFC 5032) — DONE 2026-07-27, `WITHIN` advertised
- [x] Keyword flags end-to-end tests (STORE/FETCH/SEARCH KEYWORD round trip)
- [x] Bonus fix found by testing: APPEND into the selected mailbox now
      announces untagged EXISTS before the tagged OK (RFC 3501 §6.3.11)
- [x] CONDSTORE (RFC 7162) — DONE 2026-07-27: per-mailbox highest_modseq +
      per-message modseq in every store layer (Rails migration
      20260727220000, Mailbox#claim_modseq!, EmailMessage hooks on
      create/flag-update/destroy); SELECT (CONDSTORE) + HIGHESTMODSEQ,
      FETCH MODSEQ / CHANGEDSINCE, STORE UNCHANGEDSINCE + [MODIFIED],
      SEARCH MODSEQ with (MODSEQ n) response, STATUS HIGHESTMODSEQ
      (requested-only). Verified via net-imap's condstore:/changedsince:/
      unchangedsince: APIs.
- [x] QRESYNC (RFC 7162) — DONE 2026-07-27: expunge tombstones (uid+modseq,
      1000/mailbox, pruning raises tombstone_floor; below the floor
      expunged_since over-reports with every-missing-uid, which is correct
      since uids are never reused). ENABLE (RFC 5161) with ENABLED response;
      SELECT (QRESYNC (uidvalidity modseq [known-uids])) emits VANISHED
      (EARLIER) + FLAGS/MODSEQ catch-up, skipped on UIDVALIDITY mismatch;
      OK [CLOSED] on mailbox switch; EXPUNGE/MOVE/resync report uid-based
      VANISHED instead of EXPUNGE once enabled; UID FETCH (CHANGEDSINCE n
      VANISHED). Rails: expunged_messages table + mailboxes.tombstone_floor
      (migration 20260727230000), EmailMessage#record_tombstone.
- [x] AUTH=SCRAM-SHA-256 — DONE 2026-07-27: Imap::Scram crypto module
      (pinned to RFC 7677 test vectors), scram_credentials store op
      (verifier material only, never the password), full server exchange
      in the session (gs2 parsing, channel binding refused, nonce/proof/
      c= verification, server signature, MAX_AUTH_ATTEMPTS accounting).
      Rails derives salt/iterations/StoredKey/ServerKey at password-set
      time (migration 20260728000000, keys encrypted at rest).
      NOTE: pre-existing accounts can't use SCRAM until their next
      password change (bcrypt digests can't be converted); they keep
      working via AUTH=PLAIN over TLS.
- [x] SEARCH raw-fetch elimination — two-phase evaluation (2026-07-27):
      keys are compiled as SearchKey(raw?, fn); metadata keys (flags, dates,
      sizes, sets, OLDER/YOUNGER) filter first against a metadata-only fetch,
      then message bytes are pulled ONLY for survivors that content keys
      (HEADER/FROM/SUBJECT/TEXT/BODY/SENT*) still need. A flags-only search
      never touches raw bytes at all.
- [ ] (optional, later) true SQL pushdown — a store `search` op could also
      skip the metadata fetch, but with two-phase evaluation the remaining
      win is small; revisit only if metadata volume becomes a problem

## Testing strategy

- [x] Integration tests driving the server with net-imap as the client
      (test/net_imap_client_test.rb): AUTHENTICATE PLAIN w/ SASL-IR, LIST attrs,
      ENVELOPE/BODYSTRUCTURE/section/partial fetches, SEARCH, UID MOVE,
      UID EXPUNGE, IDLE round trip — all through net-imap's strict parser
- [x] Protocol tests added for: oversize literals (sync + LITERAL+ drain),
      SEARCH keys (BADCHARSET, unknown key, SENT* vs Date header), UTF-7
      round trips, IDLE, MOVE/UNSELECT/DELETE/RENAME, ID, capability string,
      ENVELOPE/BODYSTRUCTURE shape (test/mime_format_test.rb)
- [x] Multi-literal commands (LOGIN with two sync literals), APPEND with
      flags + INTERNALDATE, `*`/`1:*` sets against an empty mailbox,
      keyword-flag persistence — covered 2026-07-27

## Anti-patterns seen in RIMS — do NOT copy

- reversed ranges (`5:1`) matching nothing (normalize instead)
- partial fetch past EOF returning `NIL` (RFC says empty string)
- quote helper that doesn't escape backslashes
- `UNSEEN` resp-code carrying a count (must be first-unseen sequence number)
- flags shared across copies of a message in different mailboxes

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

- [ ] CONDSTORE/QRESYNC (needs modseq column in Rails store) — only after IDLE
- [ ] ESEARCH `RETURN (MIN MAX COUNT ALL)` — must include `(TAG "...")` correlator
- [ ] AUTH=SCRAM-SHA-256
- [ ] SEARCH quality: differentiate `TEXT` vs `BODY` (BODY excludes headers);
      push flag/date/size keys down into SQL via a store `search` op
- [ ] Keyword flags end-to-end tests (advertised `PERMANENTFLAGS \*` — verify persistence)
- [ ] OLDER/YOUNGER (RFC 5032)

## Testing strategy

- [x] Integration tests driving the server with net-imap as the client
      (test/net_imap_client_test.rb): AUTHENTICATE PLAIN w/ SASL-IR, LIST attrs,
      ENVELOPE/BODYSTRUCTURE/section/partial fetches, SEARCH, UID MOVE,
      UID EXPUNGE, IDLE round trip — all through net-imap's strict parser
- [x] Protocol tests added for: oversize literals (sync + LITERAL+ drain),
      SEARCH keys (BADCHARSET, unknown key, SENT* vs Date header), UTF-7
      round trips, IDLE, MOVE/UNSELECT/DELETE/RENAME, ID, capability string,
      ENVELOPE/BODYSTRUCTURE shape (test/mime_format_test.rb)
- [ ] Still uncovered: multi-literal commands, sequence-set edge cases
      (reversed ranges, `*` in empty mailbox), APPEND with flags+date parsing
      edge cases, keyword-flag persistence

## Anti-patterns seen in RIMS — do NOT copy

- reversed ranges (`5:1`) matching nothing (normalize instead)
- partial fetch past EOF returning `NIL` (RFC says empty string)
- quote helper that doesn't escape backslashes
- `UNSEEN` resp-code carrying a count (must be first-unseen sequence number)
- flags shared across copies of a message in different mailboxes

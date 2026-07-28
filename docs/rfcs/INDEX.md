# IMAP RFC reference texts

The `.txt` files in this directory are gitignored. Refetch with:

```sh
cd docs/rfcs
for n in 3501 9051 7162 4549 4959 5819 8438 5182 8474 8970 7889 8514 8508 5256 \
         2177 4315 6851 3691 2342 6154 3348 4731 5032 5161 7888 2971; do
  curl -sf -O "https://www.rfc-editor.org/rfc/rfc$n.txt"
done
```

## Core

| RFC | Title / role |
|-----|--------------|
| 3501 | IMAP4rev1 — the baseline we implement and advertise |
| 9051 | IMAP4rev2 — corrected rewrite; better prose for the same behavior |
| 7162 | CONDSTORE / QRESYNC (implemented) |
| 4549 | Client synchronization practices (informational — what clients actually do) |

## Extensions we already advertise

| RFC | Capability |
|-----|------------|
| 2177 | IDLE |
| 4315 | UIDPLUS |
| 7888 | LITERAL+ / LITERAL- |
| 6851 | MOVE |
| 3691 | UNSELECT |
| 2342 | NAMESPACE |
| 6154 | SPECIAL-USE |
| 3348 | CHILDREN |
| 4731 | ESEARCH |
| 5032 | WITHIN |
| 5161 | ENABLE |
| 2971 | ID |

## Gap extensions (planned, roughly by value)

| RFC | Capability |
|-----|------------|
| 4959 | SASL-IR |
| 5819 | LIST-STATUS |
| 8438 | STATUS=SIZE |
| 5182 | SEARCHRES |
| 8474 | OBJECTID |
| 8970 | PREVIEW |
| 7889 | APPENDLIMIT |
| 8514 | SAVEDATE |
| 8508 | REPLACE |
| 5256 | SORT / THREAD |

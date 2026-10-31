# Moving the meter and the pending batch off GitHub

Status: built behind a flag, off by default. `WITNESS_USAGE_STORE=postgres` turns it on.
Code: `lib/_usage_store.js`. Table: `supabase/migrations/2026_10_31_usage_docs.sql`.
Tests: `test/usage_store_postgres.test.js`.

## The problem

Every accepted pin wrote to GitHub four times:

| write | repo | why |
|---|---|---|
| `pins/<ns>/<seq>.json` | public pins repo | the record itself |
| `pins/<ns>/latest.json` | public pins repo | the pointer to it |
| `usage/<key hash>/<month>.json` | private usage repo | the free tier meter (`lib/_meter.js`) |
| `pending/open_batch.json` | private usage repo | the open Merkle batch, when the shadow run is on (`lib/_pending.js`) |

The two private writes are bookkeeping. Nobody outside reads them, they are
not evidence of anything, and they cost a commit each: the same rate budget,
the same latency, and the same compare and swap loop that already struggles
under bursts (`lib/_pending.js` notes the contents API gives no read your
writes across instances). The meter's file is also hot: every pin by one key
rewrites the same file, so a busy key races itself.

## The change

The meter's usage file, the open batch and the seal claim (`lib/_claim.js`,
which goes through the same two functions as the batch) move into one table,
`usage_docs`, in the Postgres database the account path already uses. Same
`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, same PostgREST over `fetch`,
no new dependency, no new secret.

One row per document, keyed by the path the file had:

```
usage_docs(path text primary key, doc jsonb, version bigint, note text, updated_at timestamptz)
```

The callers did not change. `lib/_meter.js` and `lib/_pending.js` each kept
their GitHub read and write exactly as they were, and gained one line at the
top of each: when the flag says postgres, hand the call to `lib/_usage_store.js`.
That works because the new store keeps the whole contract the callers lean on:

* `read(path)` answers `{json, sha}` or `null`. `null` only for a row that is
  verifiably absent. Anything else throws with `err.unreadable`, so a database
  outage is never "nothing used this month".
* `write(path, obj, sha)` with no sha creates if absent; a duplicate path is
  the lost race and sets `err.conflict`. With a sha it updates only if
  unchanged; zero rows matched is the lost race and sets `err.conflict`.

In Postgres the sha is the row's version counter, written `pg:<n>`. The update
is `PATCH ... ?path=eq.p&version=eq.n` setting `version = n + 1`. Postgres
locks the row for the update, so of two writers holding version n exactly one
matches. This is the same arbiter the GitHub sha was, and unlike the contents
API it is read your writes on every instance.

## Writes per pin, counted

Measured in `test/usage_store_postgres.test.js` on the existing GitHub store
fake (`test/helpers/mock_store.js`) and a new PostgREST fake
(`test/helpers/mock_postgrest.js`), over pins on a namespace past its first
pin (the first pin also binds the deadline owner, one public write, either way):

| per pin | flag off (before) | flag on (after) |
|---|---|---|
| public GitHub writes | 2 | 2 |
| private GitHub writes | 2 (1 with the shadow run off) | 0 |
| database writes | 0 | 2 (1 with the shadow run off) |

A pin now costs only its public writes on GitHub. The public record is the
same with the flag on or off; a test compares the two byte for byte, clock
aside.

Reads: the meter still reads once per pin, now from the database. The first
pin by a key in a month also makes one GitHub read (the cutover check below);
for a month that started after the cutover that read is a 404.

## The cutover

Turning the flag on in the middle of a month must not hand every key its
free pins back. So a miss in the table falls back once to the GitHub file
(a read, never a write there) and adopts it with a create. Two instances
adopting at once: one create wins, the loser re-reads the winning row. If
the GitHub read itself fails, the read throws and the pin is refused, rather
than counted from zero. An open batch on GitHub is adopted the same way, with
its leaves, and seals from the database. The old files are left in the
private repo untouched.

Turning the flag back off is not symmetric: counts made in the database stay
there and the GitHub files are where they were at cutover. Rolling back mid
month means copying the month's rows back by hand first. Rolling back at a
month boundary costs nothing for the meter. Seal the open batch before
rolling back.

All instances should change together: a redeploy with the new value, not a
mix of old and new instances writing both stores.

## Failure behaviour

| case | result |
|---|---|
| flag on, database down | meter refuses, pin answers 502, nothing public written |
| flag on, `SUPABASE_URL` or the key missing | same 502, never a silent fallback to GitHub |
| `WITNESS_USAGE_STORE` set to anything but github or postgres | same 502 |
| a row we cannot version, or a meter count we cannot read | refused, row left as it was |
| a GitHub sha handed to the database store | refused, not written |
| database down for the sealer | `pending_head_unreadable`, nothing written |
| database down for a shadow leaf | the pin stands, the miss is logged, as before |

The service role key goes in request headers only. Tests check it appears in
no error, no return value and no log line, and that the meter's key hash path
never reaches a 502 body.

## What did not move, on purpose

* `lib/_balance.js`, credits and the credit ledger. That is billing, and
  another branch owns billing. A pin paid from credits, past the free cap,
  still writes the private repo for the decrement.
* `lib/_keys.js`, issued keys. Not per pin.
* The public pins repo. Nothing about it changed.

## Turning it on

1. Apply `supabase/migrations/2026_10_31_usage_docs.sql` to the account database.
2. Set `WITNESS_USAGE_STORE=postgres` on the Vercel project and on the sealer's
   environment (`tools/seal_batch.js`, `tools/reconcile_batches.js`), with
   `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.
3. Redeploy. The first pin by each key adopts its GitHub count.

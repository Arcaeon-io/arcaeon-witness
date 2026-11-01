# Everything a namespace pinned, as one bundle

`tools/export_namespace.js` gathers every record one namespace holds in the public pins repo into one file, and `tools/verify_namespace_bundle.js` checks that file offline. For a person who wants to keep, or hand to someone else, the whole witnessed history of their log.

```
node tools/export_namespace.js --clone <clone of the pins repo> --namespace acme-prod \
     --checkpoint checkpoints/2026-10-31.txt --out acme-prod.bundle.json
node tools/verify_namespace_bundle.js acme-prod.bundle.json --key "<the witness's published verifier key, below>"
```

## What the bundle holds

For every numbered record `pins/<namespace>/<seq>.json` that the checkpoint covers: its committed bytes, the commit that introduced it, its place in the log, and an inclusion proof into the checkpoint. Then the envelope of every entry of the log up to the checkpoint's size (its path, its file's SHA-256 and the commit that introduced it). Then the checkpoint itself, as published, with its signatures; the paths of records written after that checkpoint (listed, not proven); and the paths of the namespace's conflict observations under the checkpoint, with any later ones listed apart.

Know what you hand over: because the envelopes name every entry of the log, the bundle lists every other namespace's name, how many records it has, the file names of its observations (which are timestamps), and the commit of each entry. No record bytes of any other namespace are in it, only those paths, digests and commits.

The log is built from the clone exactly as `tools/publish_checkpoint.js` builds it. The export is refused unless the checkpoint given has the very root the clone gives at its size, so every record in the bundle is a leaf of the published log and not of some other history. A namespace with no record under the checkpoint yet is refused too: export again after the next checkpoint. It writes only the one output file, never over an existing one.

## Why the bundle is whole

Inclusion proofs show that each record given is in the log. They cannot show that none was left out: a bundle with its last records cut off would prove just as well. So the bundle also carries every entry's envelope up to the checkpoint's size. The check rebuilds the signed root from them; if one envelope is dropped, added or changed, the root comes out different and the answer is BROKEN. With the envelopes proven to be the whole log, the check reads off every path of this namespace among them, and the bundle must hold each of those records, the first through the last. A record cut from the start, the middle or the end is `missing_record`; a bundle with no records at all is the same.

## What the check says

One word and its exit code, as `tools/follow.js` answers:

| word | exit | means |
|---|---|---|
| VERIFIED | 0 | only with `--key`: the checkpoint is this witness's log (its origin) and carries a good signature by the key; the envelopes give its root; the bundle holds every record of this namespace that the log holds under that checkpoint, the last one too; each is in the log byte for byte; they run 1, 2, 3 with none missing; each names this namespace and its own seq; every observation listed is one in the log under the checkpoint; the head never went backward, and the same rows never carried another chain |
| BROKEN | 1 | any of that fails, named: `log_envelopes`, `not_in_checkpoint`, `missing_record`, `observation_missing`, `observation_unknown`, `path`, `record_mismatch`, `went_backward`, `chain_changed`, `tree_size`, or a signature by the key that fails |
| COULD NOT LOOK | 2 | the file or the checkpoint cannot be read, the checkpoint is of another log (`unknown_origin`), the bundle carries no envelopes, the log holds no record of the namespace under the checkpoint, no key was given, or the checkpoint carries no signature by the key; and `unsigned`, below |

Unsigned: `--allow-unsigned` without a key runs every other check, and a bundle that fails one is still BROKEN. One that passes them all is COULD NOT LOOK `unsigned`, exit 2, never VERIFIED. Without a signature nothing ties the checkpoint to the witness: anyone can cut the last records off, drop their envelopes, rebuild the root and write a new checkpoint for it, and every other check passes. `tools/follow.js` marks the same case UNSIGNED.

## What it does not say

That the log is the one everybody else sees: compare checkpoints with others, or run `tools/monitor.js`. Anything about records written after the checkpoint, which the bundle only lists until the next checkpoint covers them. Signed receipts are not in the bundle; `/api/verify` answers with each record's receipt when receipts are on.

## Which key

Any key can be given with `--key`. A person who makes a log and a key of their own gets VERIFIED for that log under that key, so a VERIFIED by itself says nothing about the witness. The check therefore says which key it was: one of the witness's published verifier keys (pinned in `tools/verify_namespace_bundle.js` as `PUBLISHED_VERIFIER_KEYS`, the same list as `docs/LOGTREE_KEY_RUNBOOK.md` and `log/checkpoints/KEYS.md` in the pins repo, compared by name, key hash and public key bytes), or "the key you supplied, which is not one the witness publishes". The witness's current key is:

```
arcaeon.io/witness-log/2026-09-22+09765dec+AdKhx0P0WL2jig0oBbA5OC4I/Yu7dyiA54ju7lcMgQ07
```

## An exhibit: that each record is unchanged since the checkpoint was signed

```
node tools/verify_namespace_bundle.js acme-prod.bundle.json --key "<the witness's published verifier key>" --exhibit acme-prod.exhibit.txt
```

With `--exhibit`, and only when the answer is VERIFIED under one of the witness's published keys, the check also writes a plain text exhibit beside the bundle. It holds:

- the namespace, the bundle file's name and SHA-256, and the time of the check;
- the signed checkpoint: origin, size, root and the witness's published verifier key;
- every record checked, with its rows, chain, its place in the log and its commit;
- what the check proves; apart from that, what the witness says (the time in each record's own `pinned_at` field); what the check does not prove; and how to check it again.

What it proves: each record is, byte for byte, an entry of the log of size N whose checkpoint the witness's published key signed, so each record is unchanged since that checkpoint was signed; and these are all the namespace's records under that checkpoint. The checkpoint carries no time, so the exhibit proves nothing about when it was signed or when any record was received. The time each record gives in its `pinned_at` field is printed under "What the witness says": it is the witness's own statement, not something the check proves. It does not say that a court or anyone else will accept it, and it says so.

Every line is built from what the check itself read and proved. The only values taken from the records are their rows, chain and `pinned_at`, and the exhibit is written only when each chain is 8 to 64 hex characters (the shape `lib/_store.js` enforces on a pin) and each `pinned_at` is an ISO time as the witness writes it (`2026-10-31T08:00:00.000Z`); the origin is this witness's log, as the check requires. So a bundle cannot carry words of its own into the exhibit. The file is written only where nothing is yet. BROKEN, COULD NOT LOOK (a check run with `--allow-unsigned` among them), a key that is not one the witness publishes, or a chain or `pinned_at` of another shape writes no exhibit, and says so naming `exhibit`, `key`, `chain` or `pinned_at`.

Hand over the bundle and the exhibit together: the SHA-256 in the exhibit names the bundle exactly, and anyone can run the same check on it and get the same answer.

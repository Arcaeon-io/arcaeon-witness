# Everything a namespace pinned, as one bundle

`tools/export_namespace.js` gathers every record one namespace holds in the public pins repo into one file, and `tools/verify_namespace_bundle.js` checks that file offline. For a person who wants to keep, or hand to someone else, the whole witnessed history of their log.

```
node tools/export_namespace.js --clone <clone of the pins repo> --namespace acme-prod \
     --checkpoint checkpoints/2026-10-31.txt --out acme-prod.bundle.json
node tools/verify_namespace_bundle.js acme-prod.bundle.json --key "<the log's verifier key>"
```

## What the bundle holds

For every numbered record `pins/<namespace>/<seq>.json` that the checkpoint covers: its committed bytes, the commit that introduced it, its place in the log, and an inclusion proof into the checkpoint. Then the checkpoint itself, as published, with its signatures; the paths of records written after that checkpoint (listed, not proven); and the paths of the namespace's conflict observations.

The log is built from the clone exactly as `tools/publish_checkpoint.js` builds it. The export is refused unless the checkpoint given has the very root the clone gives at its size, so every record in the bundle is a leaf of the published log and not of some other history. It writes only the one output file, never over an existing one.

## What the check says

One word and its exit code, as `tools/follow.js` answers:

| word | exit | means |
|---|---|---|
| VERIFIED | 0 | every record is in the log under the signed checkpoint; the records run 1, 2, 3 with none missing; each names this namespace and its own seq; the head never went backward, and the same rows never carried another chain |
| BROKEN | 1 | any of that fails, named: `not_in_checkpoint`, `missing_record`, `path`, `record_mismatch`, `went_backward`, `chain_changed`, `tree_size`, or a signature by the key that fails |
| COULD NOT LOOK | 2 | the file or the checkpoint cannot be read, no key was given, or the checkpoint carries no signature by the key |

## What it does not say

That the log is the one everybody else sees: compare checkpoints with others, or run `tools/monitor.js`. Anything about records written after the checkpoint, which the bundle only lists until the next checkpoint covers them. Signed receipts are not in the bundle; `/api/verify` answers with each record's receipt when receipts are on.

## A court ready exhibit

```
node tools/verify_namespace_bundle.js acme-prod.bundle.json --key "<the log's verifier key>" --exhibit acme-prod.exhibit.txt
```

With `--exhibit`, and only when the answer is VERIFIED under a key given with `--key`, the check also writes a plain text exhibit beside the bundle. It holds:

- the namespace, the bundle file's name and SHA-256, and the time of the check;
- the signed checkpoint: origin, size, root and the verifier key;
- every record checked, with its rows, chain, the witness's time and its place in the log;
- what the check proves, what it does not, and how to check it again.

Every line is built from what the check itself read and proved; nothing is copied from text inside the bundle, so a bundle cannot carry words of its own into the exhibit. The file is written only where nothing is yet. BROKEN, COULD NOT LOOK, or a check run with `--allow-unsigned` writes no exhibit, and says so naming `exhibit`.

Hand over the bundle and the exhibit together: the SHA-256 in the exhibit names the bundle exactly, and anyone can run the same check on it and get the same answer.

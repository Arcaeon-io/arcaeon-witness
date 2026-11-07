# Witness log signing key: runbook

The witness log's checkpoints (`lib/_checkpoint.js`) are C2SP-style signed notes. One Ed25519 key signs them. This page says where that key lives, how it gets there, how it is rotated, and where its public half is published so a stranger can check a signature.

Owner's decision (2026-09-22): **the signer key lives on Vercel, as an environment variable on the witness project.** The daily checkpoint job (`bridge/arcaeon/logtree_checkpoint.py` in the operator's machine, scheduled task `velouria-logtree-checkpoint`) signs with the same key, so the operator's machine holds a second copy in a local file. That is two places. It is stated here rather than hidden.

## The names

| thing | value |
|---|---|
| env var the signer lives in | `WITNESS_LOG_SIGNER_KEY` (what `tools/publish_checkpoint.js --key-env` is given) |
| signer format | `PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 \|\| 32-byte seed)>`, one line, no newline |
| verifier (public) format | `<name>+<8 hex>+<base64(0x01 \|\| 32-byte public key)>` |
| current key name | `arcaeon.io/witness-log/2026-09-22` |
| current verifier | `arcaeon.io/witness-log/2026-09-22+09765dec+AdKhx0P0WL2jig0oBbA5OC4I/Yu7dyiA54ju7lcMgQ07` |
| local signer file | `C:\Users\USER\.arcaeon\witness-log.signer.key` (outside every repository; `*.signer.key` is also in `.gitignore`) |
| Vercel project | `arcaeon-witness`, `prj_A06c9220XDkqUt9PrKBJZ1YBNwPO`, team `team_buKMBUUmpIrIkNbm6J16bJp9` |

## 1. Minting a key

```
node tools/logtree_keygen.js --out C:\Users\USER\.arcaeon\witness-log.signer.key --name arcaeon.io/witness-log/<YYYY-MM-DD>
```

It prints the verifier and the env var name, and nothing else. The signer goes to `--out` only, created exclusively (an existing file is refused, never overwritten), mode 0600, and on Windows restricted by `icacls` to the current user. Before it reports success it signs a throwaway note with the file and verifies it with the printed verifier; if that fails the file is deleted and the tool exits 2.

## 2. Putting the signer on Vercel (the helm does this)

Through the REST API, so the value never sits in shell history or on a command line. The body is built from the file by a short script, and the token is read from the environment:

```
POST https://api.vercel.com/v10/projects/prj_A06c9220XDkqUt9PrKBJZ1YBNwPO/env?teamId=team_buKMBUUmpIrIkNbm6J16bJp9
Authorization: Bearer $VERCEL_TOKEN
Content-Type: application/json

{"key": "WITNESS_LOG_SIGNER_KEY",
 "value": "<the file's contents, exactly>",
 "type": "encrypted",
 "target": ["production"]}
```

For example, in Python:

```python
import json, os, urllib.request
val = open(r"C:\Users\USER\.arcaeon\witness-log.signer.key", encoding="utf-8").read()
assert val.startswith("PRIVATE+KEY+") and "\n" not in val
req = urllib.request.Request(
    "https://api.vercel.com/v10/projects/prj_A06c9220XDkqUt9PrKBJZ1YBNwPO/env?teamId=team_buKMBUUmpIrIkNbm6J16bJp9",
    method="POST",
    data=json.dumps({"key": "WITNESS_LOG_SIGNER_KEY", "value": val, "type": "encrypted", "target": ["production"]}).encode(),
    headers={"Authorization": "Bearer " + os.environ["VERCEL_TOKEN"], "Content-Type": "application/json"})
r = urllib.request.urlopen(req, timeout=30)
print(r.status, json.loads(r.read()).get("created", {}).get("key"))   # never print the value
```

Read-back: `GET /v9/projects/{id}/env?teamId=...` lists the variable by key, type and target without its value. Check that `WITNESS_LOG_SIGNER_KEY` appears once, `type` `encrypted`, `target` `["production"]`. If a variable of that name already exists, the POST fails with a conflict; do not use `upsert=true` for this key. Replacing a signing key is a rotation (section 4), not an overwrite.

Env changes take effect on the NEXT deployment. Nothing in the deployed witness reads this variable yet (the daily job runs on the operator's machine, because `api/` is at its 12-function cap); it is there so that per-seal checkpoints (design A8) can sign server-side without a second key.

Choosing `encrypted` and not `sensitive` is deliberate and has a cost: an `encrypted` value can be read back by anyone holding a Vercel token for the team (the dashboard and `vercel env pull` both decrypt it). A `sensitive` value cannot be read back at all, which is stronger, but then Vercel cannot serve as the recovery copy if the local file is lost. The owner's instruction named `encrypted`. If the local file is the recovery copy of record, `sensitive` is the better type; that is his call.

## 3. The local copy the daily job uses

`bridge/arcaeon/logtree_checkpoint.py` resolves the signer in this order and never logs it:

1. `WITNESS_LOG_SIGNER_KEY` already set in the process environment;
2. otherwise the file named by `WITNESS_LOG_SIGNER_KEY_FILE` in velouria's `.env`, default `C:\Users\USER\.arcaeon\witness-log.signer.key`.

It passes the value to `node tools/publish_checkpoint.js` through the child's environment only (`--key-env WITNESS_LOG_SIGNER_KEY`). With `--write` it refuses to publish unsigned. The file and the Vercel value must be the same key; the job checks every signature it makes against the verifier in `bridge/arcaeon/logtree_verifier_key.txt` before committing anything, so a mismatched local key fails closed rather than publishing a checkpoint no one can verify.

### Every UTC day, even when nothing was added (2026-11-07)

2026-11-05 has no checkpoint. The machine was up that day (the 10:15 UTC anchor and the tips commits every six hours landed), but at the 09:45 UTC run the log held the same 109 records as on 11/04, because the 11/04 anchor was never stamped and no pin had landed since. 2026-09-24 and 2026-10-23 have no checkpoint for the same reason: on a quiet day the only new record is the previous day's anchor, which lands at 10:15 UTC, after the 09:45 UTC run, so a missing anchor leaves the next run with nothing new. The job wrote nothing on those days and said nothing. That rule is in `bridge/arcaeon/logtree_checkpoint.py` on the operator's machine, not in this repository.

From now on:

1. The job publishes a checkpoint every UTC day, also when the size is unchanged. A checkpoint at the same size is true ("nothing was added"), its proof from the day before is empty, and `publish_checkpoint.js` reports `size_unchanged: true`. The skip in `logtree_checkpoint.py` must go; that is a change on the operator's machine, which this repository cannot make.
2. `publish_checkpoint.js` names every missed day from the clone's own `log/checkpoints/` (a `MISSED DAY` line on stderr, `missed_days` in the summary) and writes `gaps/<date>.json` for days no earlier gap record named. The job publishes it as `log/gaps/<date>.json` beside the checkpoint, in the same run.
3. A missed day is never filled in. The tool refuses a `--date` on or before the newest published checkpoint, or before the UTC day of the tree commit.
4. `/api/status.json` carries `witness_log`, which goes red (and the board degraded) when a finished UTC day has neither a checkpoint nor a gap record naming it (`missing_days`), or when no checkpoint has had an outside cosignature for over 36 hours (`outside_cosignature`). See `lib/_witness_log_health.js`.

## 4. Rotation

A key is never replaced in place. Rotation is a new key with a new, dated name:

1. `node tools/logtree_keygen.js --out C:\Users\USER\.arcaeon\witness-log-<new date>.signer.key --name arcaeon.io/witness-log/<new date>`.
2. Add the new verifier to `log/checkpoints/KEYS.md` in the pins repo as a new line under "Keys", with its first-use date. The old line stays, marked with its last-use date. (KEYS.md is written by the job's first run and by hand after that; it is the one file under `log/` that is appended to, and only appended to.)
3. For an overlap period, sign with BOTH keys: a signed note may carry more than one signature line (`signCheckpoint` appends a line when the note is already signed), and checkers ignore lines for keys they were not given (the C2SP "ignore unknown signatures" rule, implemented in `verifyCheckpointSignature` and `follow.js`). A stranger holding only the old key keeps verifying through the overlap.
4. Replace the Vercel value: delete the old variable (`DELETE /v9/projects/{id}/env/{envId}`) and POST the new one, in that order, then update `bridge/arcaeon/logtree_verifier_key.txt` and point `WITNESS_LOG_SIGNER_KEY_FILE` at the new file.
5. The witness README's "Witness log" section names the current key and lists retired ones.

**Old checkpoints stay verifiable by the old public key forever.** Nothing is re-signed. A checkpoint's signature line names the key that made it; the old verifier stays published in KEYS.md and in the README. A checker walking history uses the old key for old checkpoints and the new key for new ones. A consistency proof does not depend on any key, so the chain of proofs is unbroken across a rotation.

**If the key leaks:** rotate as above, and add a line to KEYS.md stating the date from which the old key must not be trusted. A leaked key can sign a forged checkpoint; it cannot make a forged checkpoint consistent with the real ones that strangers already hold, and the daily Bitcoin anchor already covers every checkpoint committed before the leak.

## 5. Where the public key is published

- **`log/checkpoints/KEYS.md` in the public pins repo** (`dan8433-user/arcaeon-witness-pins`), written by the daily job on its first `--write` run from `bridge/arcaeon/logtree_verifier_key.txt`. Being in the pins repo, it is covered by the daily OTS anchor from the next 03:15 run.
- **The witness README**, section "Witness log".

Two places on purpose: the README is served from one repository and the key file from another, so replacing the key silently needs both changed. Neither is independent of the operator, which is the split-view limit the design states (A9 item 2).

## What this key does NOT do

It proves that the operator's key signed a checkpoint. It does not prove the checkpoint is the only one the operator signed for that size (split view), it does not prove anything recorded is true, and it proves nothing about records the operator accepted and has not yet checkpointed.

# The checkpoint monitor

`tools/monitor.js` is for anyone who wants to watch this witness's public log over time. `tools/follow.js` checks one pair of checkpoints and the proof between them; the monitor keeps what it has seen in a state file and, on every run, checks every checkpoint published since against the last one it kept.

```
node tools/monitor.js --state monitor.json --key "<the log's verifier key>" --since 2026-10-01
node tools/monitor.js --state monitor.json --key "<the log's verifier key>"          # every later run, from a timer
node tools/monitor.js --state monitor.json --key "..." --source <url> --source <mirror url>
```

A source is a base URL serving `checkpoints/<day>.txt` and `proofs/<day>-consistency.json`, the files `tools/publish_checkpoint.js` writes; the default is the public pins repo. The monitor needs nothing but Node, this file, `tools/follow.js` and the log's public verifier key.

## What it reports

One word, and the exit code:

| word | exit | means |
|---|---|---|
| VERIFIED | 0 | every new checkpoint extends the last one kept, unaltered, and is signed by the key given |
| BROKEN | 1 | evidence against the log, named: `rollback`, `split`, `changed`, or what follow.js finds |
| COULD NOT LOOK | 2 | a source could not be read, a proof is missing, or a signature cannot be attributed |

- `rollback`: a checkpoint smaller than one already seen.
- `split`: the same size with another root; a checkpoint naming another log; or two sources serving different checkpoints for one day.
- `changed`: a checkpoint already kept now reads differently. A signature line added to it later is not a change: only the note text counts.
- A proof that does not hold, or a signature line by the key that does not verify, is BROKEN as follow.js says.
- A proof that starts from a checkpoint the monitor never kept is COULD NOT LOOK: it proves nothing about the one kept.

The state file moves forward only on VERIFIED. On BROKEN or COULD NOT LOOK it is left exactly as it was, so the next run checks the same step again and a finding never goes away by itself. A first run that does not end VERIFIED writes no state file.

## What it does not see

It watches the checkpoints, not the pins: a pin refused at the door, or anything before the first checkpoint it kept, is outside it. Comparing two sources catches a split only between those two; a split shown to someone else is caught only when monitors compare their state files, or by a cosigning witness. It looks at most 400 days in one run.

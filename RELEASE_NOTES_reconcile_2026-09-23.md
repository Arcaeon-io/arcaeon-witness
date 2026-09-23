# Release notes — arcaeon-witness, the hosted completeness verdict (`/api/reconcile`, `/reconcile`), 2026-09-23

Branch `reconcile-endpoint-2026-09-23`, cut from `release-candidate-2026-09-23b` at `9bbf79a` (release three's tip). Worktree `C:/Users/USER/arcaeon-witness-reconcile`. Local only: nothing pushed, nothing deployed, no Vercel env written, no key minted.

## What it is

`POST /api/reconcile` takes two tapes, the agent side's and the tool side's, in the exact `arcaeon-tape/1` format `arcaeon-ledger reconcile` reads, and answers with the same verdict that command prints: **MATCHED n of n**, **MISSING at k**, **ALTERED at k**, or **COULD NOT LOOK**, with the counts, every finding, the first divergence as the headline, and reconcile.py's limits. A signed receipt comes back beside it. `GET /reconcile` is a small static page (same style as `completeness.html`) where a person pastes or picks the two tapes and sees the answer, the legend and the limits.

- **Input.** `application/json` `{"agent_tape": "<text>", "tool_tape": "<text>"}`, or `agent_tape_b64` / `tool_tape_b64` when the exact bytes matter (BOM, CRLF, invalid UTF-8). Or `multipart/form-data` with parts `agent_tape` and `tool_tape`. The agent tape is the adapter's `--tape`; the tool tape is arcaeon-receipt call_proxy's `--tape` (the proxy-side ledger slice) or the adapter with `--side tool`. As in reconcile.py, each tape's side is read from its own rows.
- **Caps.** 1,000,000 bytes per tape (decoded), 3,000,000 bytes per request (Vercel's own ceiling is 4.5 MB, so the typed refusal is reached before the platform's). Over either: `413` with `error_code` `tape_too_large` / `too_large` and `cap_bytes`, before any comparison.
- **Refusals are typed, never a 500.** `malformed_json`, `malformed_body`, `missing_tape`, `malformed_field`, `malformed_base64`, `ambiguous_tape`, `unknown_field`, `pins_not_supported`, `malformed_multipart`, `duplicate_field`, `too_many_parts`, `unsupported_media_type` (415), `method_not_allowed` (405), `rate_limited` (429). A refusal carries no verdict. COULD NOT LOOK is an answer, so it is a 200.
- **Nothing kept.** The tapes live in memory for the one request. No store read or write, no network call, no log line with tape content (a test replaces `fetch` with a thrower and captures the console).
- **Rate limit.** One unit of the same per-IP limiter `/api/verify` uses (naive, per warm instance).
- **Routing.** `api/` is at the Hobby 12-function cap, so there is no new function. `vercel.json` rewrites `/api/reconcile` to `/api/verify?op=reconcile` and `/reconcile` to `/api/verify?op=reconcile-page`; `api/verify.js` dispatches both before its GET-only CORS helper, as it already does `?op=stamp`. Nothing else in `verify.js` changed. No cross-origin POST is opened; the page is same-origin.

### Port, not shell-out (and why)

The Python is ported to Node (`lib/_reconcile_tapes.js`), not called. Vercel's Node runtime does not promise a Python interpreter, and a second (Python) function is not available under the 12-function cap. A port is only honest if it is held to the reference, so it is held three ways:

1. **Fixture conformance** (`test/reconcile_conformance.test.js`, 493 cases in `test/fixtures/reconcile/cases.json`). Every expected answer was written by the real `arcaeon_ledger.reconcile` (arcaeon-ledger 0.8.0, the `release-ledger-0.8.0` checkout) by `test/fixtures/reconcile/make_fixtures.py`. The port's dict, under `json.dumps(d, sort_keys=True, ensure_ascii=True, separators=(",", ":"))`, must be the same string. Sources: **156 cross-repo cases** (every tape the receipt repo's `tests/test_call_proxy_tape.py` and the ledger repo's `adapter/test_http_forward.py` and `adapter/test_tape.py` leave behind, harvested with pytest `--basetemp`: the adapter agent tape against call_proxy's tool tape, FIFO duplicate ids, invalid ids including `true`, a 202 answered later, a 202 never answered, gzip/deflate answers, and those suites' own break arms); **21** of the ledger's own reconcile cases (every one that takes two tapes and no pin); **96 edge** cases (floats, NaN/Infinity, 30-digit ints, the 4300-digit int limit, lone surrogates, duplicate keys, BOM, CRLF, lone CR, seven invalid-UTF-8 sequences re-chained so they verify only if the port replaces bytes exactly as CPython does, Python-only whitespace, a float/boolean/string/zero/huge `idx`); **220 seeded fuzz** cases. The fixture records the LF sha256 of `reconcile.py` and `arcaeon_ledger/__init__.py`, and the test refuses a fixture made from other sources than the port names.
2. **The same check through the endpoint**: every fixture pair posted to the handler, the `verdict` field compared byte for byte.
3. **A live differential** (`test/reconcile_live_python.test.js`): 150 fresh byte-level mutations of the cross-repo tapes, judged by reconcile.py in a subprocess. Skips, saying why, when no Python or no matching ledger checkout is present. Run here with six seeds (900 cases): all agree.

"FIFO id pairing, the invalid-id rule, the boolean-id rule and 202/gzip parity" are rules of the **recorders** (the adapter's observer and call_proxy), applied when a tape is written. reconcile.py never sees an rpc id pairing; it reads the tapes those rules produced. So they are covered here the only way they can be: the harvested cross-repo tapes were written under exactly those rules, and reconcile.py's verdict on them is the fixture. What reconcile.py itself checks, the port checks: `idx` must be an integer and not a boolean (a JSON `true`, `1.0` or `"1"` is not a call index: COULD NOT LOOK), `rpc_id` is outside both digests (a renumbered id still matches, stated in a test), an `invalid_id` row has `resp: null` and pairs only with the same on the other tape.

**Mutation runs** (each a one-line change to the port, run, then restored; the file is byte-identical to the committed one): strip a BOM like `TextDecoder` does by default: 2 tests fail. `String#trim` instead of `str.strip()`: 4 fail. No 4300-digit int limit: 2 fail. No duplicate-key check: 3 fail. Read `1.0` as an integer: 5 fail.

### Where the port does not follow reconcile.py

- **Three inputs make reconcile.py raise instead of answering** (found building this; reported, not fixed, because the reference is a released package in another repo). (1) A line whose strict read finds a duplicate key and whose plain read then fails (`{"a":1,"a":2} x`): `verify_file` calls `_loads` again inside its `except DuplicateKeyError` and the `JSONDecodeError` escapes. (2) A row that verifies but is wrapped in whitespace `str.strip()` removes and `json.loads` does not (`\x0b \x0c \x1c-\x1f \x85 \xa0 U+2028 U+3000`): `_load`'s second read raises. (3) A row nested past CPython's C recursion guard reaching `_peek_side`, which catches `ValueError` and not `RecursionError`. For each, the port answers **COULD NOT LOOK** and says the reference raises there. Nine fixture cases pin (1) and (2).
- **Nesting deeper than 512** is COULD NOT LOOK here. CPython's limit is a C-stack guard that moves with platform and version (measured 16,912 nested arrays, 14,310 nested objects on Python 3.14.3 / Windows); no fixed number reproduces it, and a tape row is flat. One fixture case pins it.
- **Pins are not accepted.** `--pin` stays in the CLI and in `completeness.html`. Its refusal messages are CPython's `JSONDecodeError` text and `repr()` of arbitrary values, and a pin submitted to a public service is only as good as its submitter. A request carrying `pin` / `pins` / `pin_b64` is refused `pins_not_supported`, not silently ignored.

## The receipt

`lib/_reconcile_receipt.js`. The claim, verbatim and signed: **"These two tapes, as submitted, compared like this at this time."** It binds `sha256:raw-bytes:v1` of each tape's bytes exactly as received (and their sizes), the method (reconcile.py rules, `js-port`, port version, the reference's source hashes), the verdict word, call, side, matched count, counts, finding and could-not-look counts, exit code, the `sha256:json-c14n:v1` digest of the whole verdict document returned beside it, and `compared_at`. `does_not_claim` is inside the signed bytes: the service saw only the bytes submitted; an operator-owned tape is not an outside witness; nothing about calls neither recorder saw; no witness pin checked; the tapes are not kept. The receipt holds no tape content (a test checks that no request or response digest from a row appears in it).

- **Signing** reuses the witness's key shape: one Ed25519 key in the `lib/_checkpoint.js` signer-string format, read from **`WITNESS_RECONCILE_SIGNER_KEY`**, public half carried in the receipt as the verifier string; preimage is the check-record rule (json-c14n:v1 of the receipt minus `sig`). It is its own key: the receipt never signs with `WITNESS_LOG_SIGNER_KEY` (a test pins that), so "the witness log says" and "this service compared two uploads" cannot be confused.
- **Without the key** the receipt goes out with `sig: null`, `signer: null` and `unsigned_reason`; the verdict is unchanged. A badly formed key is named, never echoed.
- **Verification**: `verifyReceiptText(text, verifier)` takes the receipt or the whole saved answer (the page saves the response bytes as they arrived), refuses `bad_signature`, `unknown_signer`, `malformed_signature`, `unsigned`, `not_a_reconcile_receipt`, and `verdict_does_not_match_receipt` when the verdict beside a good receipt was edited.
- A verdict that quotes a tape's lone surrogate cannot be json-c14n encoded (strict UTF-8, as `arcaeon_ledger.artefact._canon_json`); the receipt then carries `verdict_digest: null` and a `verdict_digest_note`, and is still signed over everything else.

## Claims it makes and does not make

Makes: these two byte strings, compared under reconcile.py 0.8.0's rules (no pin), at `compared_at`, give this verdict; the port gives reconcile.py's answer on every case it has been shown (1,393 cases counting the live runs) and says COULD NOT LOOK where reconcile.py raises.

Does not make: that either tape is true or complete; that the tapes are independent (MATCHED between two tapes one party wrote is consistency, not independence); anything about calls neither recorder saw; that the tapes were not cut in agreement (no pin); that the service keeps anything; that the port equals reconcile.py on inputs it has not been shown.

## Files

- `lib/_reconcile_tapes.js` — the port (verify_file strict + reconcile, no pins), Python-faithful JSON read/write, the serializations.
- `lib/_reconcile_receipt.js` — receipt build, sign, verify.
- `lib/_reconcile_http.js` — the two handlers, body reading, caps, typed refusals.
- `lib/_reconcile_page.js` — the page, as a constant string (always in the bundle; no file read at request time). Renders with `textContent` only.
- `api/verify.js` — the `?op=reconcile` / `?op=reconcile-page` dispatch (15 lines). `vercel.json` — two rewrites.
- `test/reconcile_conformance.test.js` (10), `test/reconcile_endpoint.test.js` (39), `test/reconcile_receipt.test.js` (8), `test/reconcile_live_python.test.js` (1); `test/fixtures/reconcile/make_fixtures.py` and `cases.json` (2.2 MB; regenerate with the command in the script's docstring).

`npm test`: **776 tests, 776 pass, 0 fail, 0 skipped** (718 + 58), in the worktree. From a `git archive` export (the deploy shape): 774 pass, 1 skip, 1 fail. The fail is release three's known one (`test/logtree_keygen.test.js` runs `git check-ignore`, which exits 128 outside a repository); the skip is the live Python differential, which finds no ledger checkout beside an export and says so. Break arms in the suite: an always-MATCHED reconcile (caught on every non-green fixture case, directly and through the endpoint), one that files ALTERED as MISSING, a JSON.parse-style float `idx`, a forged call index (not re-chained: ALTERED at that line; re-chained: MISSING/ALTERED from the index walk), a boolean or float index, a one-sided `invalid_id`, a truncated tape (rows cut: MISSING; torn line: ALTERED), plus the stated limits (renumbered rpc id and both tapes cut together still MATCH).

## Before deploying

1. **Mint the receipt key** (optional; without it receipts go out unsigned and say so). Same tool and discipline as the log key (`docs/LOGTREE_KEY_RUNBOOK.md` section 1), a new name and file:
   `node tools/logtree_keygen.js --out C:\Users\USER\.arcaeon\witness-reconcile.signer.key --name arcaeon.io/witness-reconcile/2026-09-23`
   The tool prints `WITNESS_LOG_SIGNER_KEY` as the env name because that constant is the log key's; for this key the name is **`WITNESS_RECONCILE_SIGNER_KEY`**. Publish the printed verifier somewhere a stranger can find it (the runbook's "current verifier" table, or beside `OPERATOR_KEYS.json`); until then a receipt's signature proves only "whoever holds this key", not "Arcaeon's witness".
2. **Env write** (only if step 1 was done), the runbook's section 2 shape, `type: "encrypted"`, `target: ["production"]`, value = the file's contents, token from the environment, never on a command line:
   `POST https://api.vercel.com/v10/projects/prj_A06c9220XDkqUt9PrKBJZ1YBNwPO/env?teamId=team_buKMBUUmpIrIkNbm6J16bJp9` with `{"key": "WITNESS_RECONCILE_SIGNER_KEY", "value": "<file contents>", "type": "encrypted", "target": ["production"]}`. Read back with `GET /v9/projects/{id}/env?teamId=...`: the key appears once, encrypted, production. Write it immediately before the deploy.
3. **Order against release three.** This branch sits on `9bbf79a`. If release three is not live yet, deploy it first as its own release (its notes and read-backs), then this; or deploy this alone and run both read-back lists. Do not skip release three's read-backs because this tree carries them.

## Deploy (same as release three's; one command, when Daniel says go)

```bash
OUT=C:/Users/USER/velouria/bridge/tmp/witness_release_reconcile_2026-09-23
mkdir -p "$OUT" && git -C C:/Users/USER/arcaeon-witness-reconcile archive reconcile-endpoint-2026-09-23 | tar -x -C "$OUT"
mkdir -p "$OUT/.vercel" && cp C:/Users/USER/arcaeon-witness/.vercel/project.json "$OUT/.vercel/project.json"
```

With `VERCEL_TOKEN` in the environment:

```
npx.cmd --yes vercel@59.25.0 deploy --cwd C:/Users/USER/velouria/bridge/tmp/witness_release_reconcile_2026-09-23 --prod --yes --scope arcaeon --archive=tgz
```

(Not prepared here: the export directory was not made, so it cannot drift from the branch.)

## Rollback

To the deployment that is production immediately before this one. Read its id before deploying (`npx.cmd --yes vercel@59.25.0 ls arcaeon-witness --scope arcaeon`, or the dashboard): release three's deployment if it went live, else `dpl_6uYScywM` (`8242bfa`, per release three's notes). `npx.cmd --yes vercel@59.25.0 rollback <id> --scope arcaeon`. Nothing here writes to any store, so a rollback orphans nothing. The signer variable can stay; nothing else reads it. Cheaper partial rollback: none is needed for a bad page alone, but removing the two rewrites would require a deploy, so roll back instead.

## Post-deploy read-back

Release three's list first (its items 1 to 6 hold unchanged: this release touches no store path, no status code and no field of `/api/verify`). Then:

1. `GET https://witness.arcaeon.io/reconcile` is **200**, `text/html`, title `Two Tapes Verdict`, and the page carries the four answers and "An operator-owned tape is not an outside witness."
2. `POST https://witness.arcaeon.io/api/reconcile` with `{"agent_tape_b64": ..., "tool_tape_b64": ...}` from the fixture case `receipt-test_call_proxy_tape/test_cross_repo_adapter_tape_a0: agent vs tool` answers **200**, `verdict.summary` `MATCHED 5 of 5`, and `receipt.tapes.tape_a.digest` equals the sha256 of the bytes sent. The fixture case `receipt-test_call_proxy_tape/test_cross_repo_answer_changed0: agent vs tool` answers `ALTERED at call 2`.
3. The receipt from 2 verifies: `node -e 'const r=require("./lib/_reconcile_receipt.js");console.log(r.verifyReceiptText(require("fs").readFileSync("answer.json","utf8"), "<published verifier>"))'` prints `ok: true` (or, with no key configured, `reason: "unsigned"` and `unsigned_reason` naming `WITNESS_RECONCILE_SIGNER_KEY`).
4. `POST /api/reconcile` with `{"agent_tape": ""}` is **400** `missing_tape`; `GET /api/reconcile` is **405**.
5. The same two files as **multipart** (`curl -F agent_tape=@agent.tape.jsonl -F tool_tape=@tool.tape.jsonl`) answers the same verdict as 2. See "unconfirmed" below; if this is `400 missing_tape` or `malformed_multipart`, the JSON path still works and the page uses JSON only, so it is not a rollback trigger.
6. A body over 3 MB is **413** `too_large` from this service, not the platform's `FUNCTION_PAYLOAD_TOO_LARGE`.
7. `/api/verify` on a live namespace's current head is unchanged (release three's item 3).

If 1, 2, 4 or 7 fails, roll back first and diagnose after.

## What I could not confirm

- **Multipart on Vercel.** The handler reads the raw stream when the platform has not parsed the body. Whether the Vercel Node runtime leaves a `multipart/form-data` stream readable on a function whose `bodyParser` is on (it is, for `?op=bulk`) was not tested against the platform. The page does not depend on it (it posts JSON, base64 for picked files). Read-back 5 settles it.
- **The platform's own body limit** is taken from Vercel's documentation (4.5 MB), not measured; the 3 MB cap sits under it.
- **Deploy state of release three** and so the exact rollback id; no token was used.
- **Unicode-version drift** in one message: a duplicate-key break names the key with Python's `repr()`, whose "printable" test uses CPython's Unicode database; the port uses V8's. They could differ only for a code point assigned in a Unicode version one side has and the other lacks.
- **CPU time on the platform.** Two 1 MB tapes that share nothing took about 4.6 s here (the lookahead in reconcile.py's alignment is quadratic, and the port keeps it rather than change the rule); the function's `maxDuration` is 30 s. Not measured on Vercel.
- The three reconcile.py crash inputs are reported here only; no issue was filed in the ledger repo.

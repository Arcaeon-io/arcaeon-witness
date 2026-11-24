# Reading Sigstore's verifier next to ours (2026-11-22)

**What was read:** `@sigstore/verify` 4.1.3, the published npm package from
github.com/sigstore/sigstore-js (Apache-2.0). Only two files were read, and
none of the package's code was run:
- `dist/tlog/checkpoint.js`, which reads and verifies a Rekor checkpoint, a signed note in the same layout as our witness log's checkpoint;
- `dist/tlog/merkle.js`, which checks an RFC 6962 inclusion proof against that checkpoint.

**What it was compared with:**
- `lib/_checkpoint.js` and `tools/follow.js` (our checkpoint reader and the stranger's checker);
- `lib/_logtree.js` (RFC 9162 inclusion and consistency);
- `lib/_merkle.js` (batch tree inclusion).

The C2SP specification pages could not be read from the build machine: the session's network refuses that host. Nothing below about C2SP comes from those pages.

## What they do better

1. **Proof arithmetic that is right at any size.** They parse the tree size and the leaf index as BigInt and walk the proof in BigInt. We walked ours with JavaScript's bitwise operators (`>>=`, `&`), which cut every value to a 32-bit signed integer. But our checkpoint reader accepts a size of up to 15 digits. That caused three failures on `main`, each now a test:
   - valid proofs for trees past 2^31 − 1 leaves were refused;
   - an old size of 2^32 made `tools/follow.js` loop forever: `fn = first − 1` read as −1, and `−1 >> 1` is −1;
   - in `lib/_merkle.js`, a claimed `tree_size` of 2^31 + 1 stopped the walk after one step, so an empty path "proved" that a leaf was the root of the tree. It was reported with `tree_size_bound: false`, so a caller that also checks the published root record would still refuse it.
2. **A parse error is an error, not a crash.** Their code comments say the size and index are "attacker-controlled" and parsed before any signature is checked, and they wrap `BigInt()` so bad input becomes a named verification error. Ours does the same with regex checks before parsing. Both are fine; theirs states the reason in the code, which ours now does too.

## What we do better

1. **Signature lines are read strictly.** They find signature lines anywhere in the text after the blank line, with a global regex, and ignore everything else there. We refuse a note with any line there that is not a signature line, or with signature bytes that are not exactly 4 + 64 bytes in canonical base64.
2. **The origin is checked.** Their `verifyCheckpoint` never compares the checkpoint's origin line with the log it expects; it trusts that a signature by a known key is enough. `tools/follow.js` refuses an unknown origin (COULD NOT LOOK) and checkpoints whose origins disagree.
3. **Key matching is exact.** They match a signature to a log by the key hint and by the signer name being a substring of the log's URL. We match the exact key name and the C2SP key hash (sha256 of name, newline, algorithm byte and public key).
4. **"No signature for this key" is kept apart from "bad signature".** They return one boolean. We return two named reasons, and a checker can tell COULD NOT LOOK from BROKEN.

## The one change made for us, with its tests

Every proof walk now uses plain division (`x % 2`, `Math.floor(x / 2)`) and a power-of-two loop in place of bitwise operators. Every size and index must be a safe integer (below 2^53); larger values are refused as `malformed_proof` instead of being walked. The change covers:
- `lib/_logtree.js` `verifyInclusion` and `verifyConsistency`;
- `tools/follow.js` `verifyConsistency`;
- `lib/_merkle.js` `verifyInclusion`.

The tests are:
- `test/proof_large_trees.test.js` (27). It uses hand-written RFC 9162 proofs at 2^31, 2^32, 2^40 and 2^52 leaves: valid proofs pass, wrong roots and short paths are refused, and the forged empty batch path is refused. Sizes past 2^53 − 1 are refused.
- `test/proof_no_hang.test.js` (3). Each checker runs in a child process with a 5 second limit. On `main` all three time out.

The proofs this witness publishes today are far below 2^31 leaves, so no published result changes. What changes is that a checker handed a large or crafted size now gives an answer, and the right one.

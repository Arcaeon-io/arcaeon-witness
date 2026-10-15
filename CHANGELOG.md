# Changelog — arcaeon-witness

## 2026-10-15: Unit R-ABf: the fixes for R-AB (branch `case-protocol-2026-10-10`, NOT deployed)

- **Commits.** 0408ca1 (tests and code) and this entry's commit (the defect list and its ledger, the gap tests, the change log).
- **B1 (the blocker; the architect's ruling: the order changes, not the sentence).** The page (`renderCase`), the sealer (`anchorCase`) and the reference read the projected registration files (`projectedRegistrations`) before they judge a root single party and before the sealed check, as the reveal already did.
  - A root that does not agree with its files, such as a `key_fp` written over while the file holds another key, reads `case_record_inconsistent` on each: the page 503, the sealer `refused`, the reference 503 codes only.
  - A single-key root whose file could not be read is could-not-look. The page is 503, in the one-sentence shape: "A registration file this case projects could not be read when this page was read, so nothing is asserted about this case; this is not a no.", then `<code>could_not_look</code>` and the two links. The sealer answers `could_not_look`, the reference 503.
  - Only a root that agrees with its files gets the 200 single-party page.
  - The reference now reads the files for the operator's row too, and the role's proof is checked against what it read.
  - `sealedRecordReason` alone still answers `single_party` first: it reads no file, and its callers read the files before it.
  - The page now reads the registration files for a VERDICT that does not verify too; `case_item2d` FIX 1's list of reads says so.
- **M1 (the runner).** A run is caught only when the suite exits non-zero AND a test failed.
  - A suite killed at its timeout is recorded `timeout`. One that exits non-zero, or is killed, with no failing test is `error` (it did not start, say). The table prints each as such and never as caught.
  - Nothing was run again: no run in the committed ledgers (`test/must_fail/r_ab.ledger.json`) is recorded caught with no failing test (each caught run there has 2 or more), and a test reads every committed ledger to say so.
- **M2 (a named commit definitely off the published branch).** `off`, set and until now read by nothing, is read.
  - **Set:** in `lib/_case_seal.js` `namedDocumentOf`, at two returns: the branch read's (`off: !on.unknown && !on.not_found`, true for a commit ahead of or diverged from the branch) and a document read that failed (`off: false`).
  - **Read:** in `signedUnderReason`, its one reader, which now answers `document_off_branch` (reason `commit_not_on_branch`) for it: a known refusal.
  - No body code existed for this state: the page showed the reason `commit_not_on_branch` under `document_unavailable`, at 503. So `document_off_branch` is new, and it is no new state.
  - Through the one reader:
    - the reference: 409 `document_off_branch`, codes only (`case_id`, `reason`);
    - the page: the same page at 200, worded off the branch by the code (it was worded by the reason, which a 404 also carries);
    - the sealer: `refused` (`document_off_branch`), no longer `could_not_look`;
    - the withdrawn root's answer (`unconfirmedWithdrawal`): 409 with words, `UNSEALED_WORDS.document_off_branch`;
    - the marker repair (`repairWithdrawn`): not repaired, logged;
    - a reference row (`judgeReferenceRow`): invalid, not unreadable;
    - `verifyRefusalReceipt` and `tools/check_refusal_receipt.js`: reason `document_off_branch`.
  - A read that failed, a 404 commit among them, stays `document_unavailable` and 503 everywhere.
  - Not changed: `confirmSealingDocument`, for the deployment's own commit, still answers 503 `document_unavailable` with reason `commit_not_on_branch`; a redeploy, not a re-send, finishes it. The pin's own `commit_off_branch` was already a definite `pin_commit_mismatch`.
- **Minors.**
  - **m-a:** the reference's `single_party` is 409 codes only, `{case_id}`, as the reveal's.
  - **m-b:** `UNSEALED_WORDS.document_unavailable` is still reached, by the withdrawn root's could-not-look (`unconfirmedWithdrawal`), so it stays; a test shows it.
  - **m-c:** `projectionBar` is no longer handed the key id. Planting it back changes nothing observable, so no defect was planted for it.
  - **m-d:** a defect's file must be a relative path inside the repository (no absolute path, no `..` segment), checked before anything is planted. An interrupt (SIGINT, SIGTERM) removes the copies, the planted file with them, and kills the suite.
  - **m-e:** a re-seed that catches a defect its earlier runs did not records `caught_by`: the failing tests named MUST-FAIL GAP, or all failing tests when none is. The table prints that record (the names as the runner stored them, at most 160 characters each); the operator's `--gap` option is gone. The table reads the R-AB ledger's older form the same way.
  - **m-f:** the single-party sentence stands.
- **Found while testing the runner, and fixed.**
  - A runner started from inside a test inherited `NODE_TEST_CONTEXT`, and its `node --test` then exited at once with its tests unrun, which would have recorded every defect survived. The suite now runs without it.
  - Killing the suite killed only `node --test`, not its test processes. The suite now runs in its own process group, killed whole on timeout and on interrupt.
  - `--suite` names the test files (`test/*.test.js` unless given). `test/must_fail/slow_suite.fixture.js` is a one-minute suite the interrupt tests hand it.
- **Line counts.** `lib/_case_page.js` 723 to 754, `lib/_case_http.js` 2432 to 2449, `lib/_case_seal.js` 2313 to 2322, `test/must_fail/run.js` 150 to 241.
- **Tests.**
  - New, `test/case_rab.test.js` (R-ABf: 8, and 2 gap tests). On a118c94, 6 of the 8 fail; 2 pass by design: a 404 commit stays a could-not-look, and m-b shows the words are still reached.
  - New, `test/must_fail_runner.test.js` (7, and 1 gap test). On a118c94, 6 of the 7 fail; the committed-ledger check passes there by design (it is M1's "say so").
  - Rewritten to the ruling, each failing on a118c94:
    - R-AB 2 (a written-over `key_fp` reads `case_record_inconsistent`);
    - R-AB 6's VERDICT part (a single-key VERDICT that agrees with its files; this one passes on a118c94 too, which read such a root single party as well);
    - P31;
    - the FIX A forged VERDICT;
    - H07 (codes only);
    - `case_item2d` FIX 1 (the files are read);
    - the off-branch expectations in `case_rn`, `case_rn2` and `case_trust_root` (ANCESTRY and R-I2 m4: `document_off_branch`, the page at 200).
- **The must-fail pass** (the repository's runner; dates from the ledger, `test/must_fail/r_abf.ledger.json`). 26 defects were planted over the lines R-ABf changed, each alone with the whole suite run: `lib/_case_page.js` 7, `lib/_case_seal.js` 3, `lib/_case_http.js` 7, `test/must_fail/run.js` 9.
  - The reader's own defects were among them: PG1, SE1 and HT1 (judge before read), SE2 (`off` read by nothing) and RN1 (caught on any non-zero exit).
  - 21 were caught. Of the 5 that survived, 4 are caught by gap tests and were re-seeded the same day (PG4, PG6, RN8, RN9). One is equivalent:
    - RN3, the absolute-path check removed. The inside-the-repository check that follows refuses every absolute path itself, so the explicit check changes nothing. It stays because it names the rule.
  - During the RN9 re-seed, the interrupt test without the pid check left one fixture process. It ended within its minute.

  | id | file | planted defect | first run | last re-seeded and caught |
  |---|---|---|---|---|
  | PG1 | `lib/_case_page.js` | B1: the page judges single party before it reads the files (the reader's defect) | caught (7 failing) | 2026-10-15 |
  | PG2 | `lib/_case_page.js` | B1: a single-key root whose file could not be read gets the single-party page | caught (2 failing) | 2026-10-15 |
  | PG3 | `lib/_case_page.js` | B1: the could-not-look page at 200 | caught (2 failing) | 2026-10-15 |
  | PG4 | `lib/_case_page.js` | B1: the could-not-look sentence altered | survived; caught on re-seed by MUST-FAIL GAP (PG4): the could-not-look sentence for a single-key root whose file could not be read, exactly | 2026-10-15 |
  | PG5 | `lib/_case_page.js` | M2: the off-branch page at 503 | caught (5 failing) | 2026-10-15 |
  | PG6 | `lib/_case_page.js` | M2: a 404 commit's page worded as off the branch | survived; caught on re-seed by MUST-FAIL GAP (PG6): a named commit the repository does not have (404) is worded as a read that failed, 'try again', never as off the published branch | 2026-10-15 |
  | PG7 | `lib/_case_page.js` | M2: the off-branch page worded as a read that failed | caught (5 failing) | 2026-10-15 |
  | SE1 | `lib/_case_seal.js` | B1: the sealer judges single party before it reads the files (the reader's defect) | caught (6 failing) | 2026-10-15 |
  | SE2 | `lib/_case_seal.js` | M2: off read by nothing (the reader's defect) | caught (9 failing) | 2026-10-15 |
  | SE3 | `lib/_case_seal.js` | M2: every named read that failed answered off-branch | caught (22 failing) | 2026-10-15 |
  | HT1 | `lib/_case_http.js` | B1: the reference judges single party before it reads the files (the reader's defect) | caught (5 failing) | 2026-10-15 |
  | HT2 | `lib/_case_http.js` | B1: the operator's reference reads no file | caught (2 failing) | 2026-10-15 |
  | HT3 | `lib/_case_http.js` | M2: the reference's off-branch at 503 | caught (2 failing) | 2026-10-15 |
  | HT4 | `lib/_case_http.js` | M2: the reference's off-branch with a sentence | caught (2 failing) | 2026-10-15 |
  | HT5 | `lib/_case_http.js` | M2: the reference's off-branch branch gone | caught (2 failing) | 2026-10-15 |
  | HT6 | `lib/_case_http.js` | m-a: the reference's single_party with a sentence | caught (3 failing) | 2026-10-15 |
  | HT7 | `lib/_case_http.js` | M2: no words for document_off_branch in the withdrawn root's answer | caught (2 failing) | 2026-10-15 |
  | RN1 | `test/must_fail/run.js` | M1: caught on any non-zero exit (the reader's defect) | caught (1 failing) | 2026-10-15 |
  | RN2 | `test/must_fail/run.js` | M1: a timeout classified by its exit | caught (1 failing) | 2026-10-15 |
  | RN3 | `test/must_fail/run.js` | m-d: an absolute path accepted | survived | never |
  | RN4 | `test/must_fail/run.js` | m-d: a '..' path accepted | caught (1 failing) | 2026-10-15 |
  | RN5 | `test/must_fail/run.js` | m-d: an interrupt leaves the copies | caught (1 failing) | 2026-10-15 |
  | RN6 | `test/must_fail/run.js` | m-e: a re-seed's catch records no gap test | caught (1 failing) | 2026-10-15 |
  | RN7 | `test/must_fail/run.js` | m-e: the table prints every failing test, not the record's gap test | caught (2 failing) | 2026-10-15 |
  | RN8 | `test/must_fail/run.js` | found in testing: the suite inherits NODE_TEST_CONTEXT | survived; caught on re-seed by MUST-FAIL GAP (RN8, RN9): a runner started with NODE_TEST_CONTEXT set (as from a test) still runs its suite, and an interrupt kills the suite's test processes,  | 2026-10-15 |
  | RN9 | `test/must_fail/run.js` | found in testing: the suite's test processes outlive a kill | survived; caught on re-seed by MUST-FAIL GAP (RN8, RN9): a runner started with NODE_TEST_CONTEXT set (as from a test) still runs its suite, and an interrupt kills the suite's test processes,  | 2026-10-15 |

- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1514 tests, 1507 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1508 pass, 1 skipped.
- **UNSURE.**
  - The could-not-look page for a single-key root whose file could not be read is new copy: its sentence is mine, its heading is COULD NOT LOOK, and its code is `could_not_look`.
  - A 404 named commit (a read that failed) is now worded on the page as could-not-look, "try again". Until now it was worded as off the published branch, since it carries the same reason. R-I2 m4's off-branch words now apply only to `document_off_branch`.
  - The off-branch page at 200 keeps its words, heading COULD NOT LOOK and "says neither that the sealed record verifies nor that it does not". Only its status changed.
  - The sealer lists `document_off_branch` under `refused`. Like every refused case, it is still read again on later passes while it has no pin.
  - M1: `error` is a result the ruling did not name; it is never a catch.
  - m-d: "restore the copy on SIGINT" is read as removing the copies, which takes the planted file with them, and killing the suite's process group.
  - m-e: a gap test is known by its name's prefix, MUST-FAIL GAP.
  - The reference reads the projected files before its sealed check for every request, which is one more read per operator row.

## 2026-10-14: Unit R-AB: parties are told apart by public key (key_fp), never by key id (branch `case-protocol-2026-10-10`, NOT deployed)

- **Commits.** 851e77b (tests, code, red-team record) and this entry's commit (the runner, the defect list and its ledger, the gap test, the change log).
- **The brief.** Built from the architect's message (v2, against c5770ce); `unit_R_AB.txt`, which it names for the original intent, is not in this session, and the message overrides it where they differ.
- **1. key_fp.** A case root's per-role entry carries `key_fp`: the lowercase hex sha256 of the 32 raw Ed25519 public-key bytes the registration file's verifier carries (`lib/_case.js` `keyFpOf`).
  - It is computed when the root projects the file (`caseEntry`). The registration file carries none, and the claim is unchanged.
  - It is in `CASE_ENTRY_FIELDS` only, so it is required in a COMMITTED or VERDICT root and in a withdrawal record's kept projection. An entry without it is `missing_field` at `commitments.<role>.key_fp` (the readers' `case_missing_field`); one not 64 lowercase hex is `malformed_field`.
  - The projection reader (`projectedRegistrations`) checks it against the projected file's verifier. A root whose `key_fp` is not the file's does not agree with itself: `projection_differs_from_file`, `case_record_inconsistent`.
- **2. Every key comparison is by key_fp.**
  - Registration (`projectionBar`): before the write, which now passes the verifier (it passed only the key id), and at the projection.
  - `singleParty`, read by the reveal, the seal, the sealed check (`sealedRecordReason`'s first step), the sealer and the page.
  - One public key under two names (two key ids) is one key. Two public keys that share a key id (the T12 pair, `test/fixtures/key_id_collision.json`) are two keys: they register both roles and seal.
- **3. 409 `same_key_both_roles`, codes only.**
  - Refused before the write, the body is exactly `{ok: false, error_code, case_id, role, other_role}`.
  - Refused at the projection, after a race, it also carries the registration's own path, sha256, `received_at` and `registration_recorded`, the data the projection refusals already carry.
  - Neither names a key id. `single_party` is only the reading of a stored case.
- **4.** A re-send under the same public key in another name stays 409 `role_already_committed`. The claim hash is the party-supplied fields' as before.
- **5.** A WITHDRAWN record is never single party, even when its kept projection shares a `key_fp`.
- **6. The single-party page** is the one-sentence shape of the inconsistent page, at 200, under the heading SINGLE PARTY. It shows the sentence "One key signs the registrations of both roles of this case; this page shows nothing else from it.", then `<code>single_party</code>` and the case file's two links. It shows no key id, label, status, time, verdict, registration or limits, before or after the deadline.
- **7.** The sealed page gets no new copy. A test asserts it makes no claim about key identity, and that no library file says "two keys, never two parties".
- **8. The record.**
  - `test/case_redteam.test.js`'s header marks §2A NARROWED.
  - The §2A test's name now says so. The "A + B DECISION" test is rewritten to the new page. Five FIX A tests whose names said "key id" (or named the one key id) are renamed, and the forged VERDICT shares a `key_fp`.
  - Comments corrected: `lib/_case.js` ONE KEY PER ROLE ("one key id is one key" is gone); `lib/_case_http.js` ONE KEY PER ROLE, the reveal's step 2, THE REFERENCE ROW, and the registration's "a withdrawn root holds no projection" (untrue since R-L5); `lib/_case_seal.js` SINGLE PARTY and the seal's message; `lib/_case_page.js` SINGLE PARTY.
- **Carry-over (a).** The sealer's withdrawn-marker repair (`repairWithdrawn`, handed the sealer's key document) reads the withdrawal record through `signedUnderReason`. A record that does not verify, or whose named document cannot be read, is logged and left with nothing written. The next pass reads it again; the report lists it under `terminal` as before, with no new state.
- **Carry-over (b).** The reference answers a sealed case whose named document cannot be read with 503 `document_unavailable`, codes only (`case_id`, `reason`). A document that reads and refuses the record stays 409 (`signature_invalid`, `signer_unlisted`, `signer_revoked` and the rest).
- **The R-RVf3 reader's small items.**
  - **m1.** `UNSEALED_WORDS.signer_revoked` holds R-REVf's words, "one of the keys it is signed with is listed as revoked in the key document this service carries", so the 5a answer no longer prints the bare code.
  - **m2.** A test drives the refusal receipt and the retried withdrawal through a moment the document cannot be read (`forceRawFailure`): both answer 503, and both re-sends finish.
  - **m3.** A test drives a version-3 row whose named document cannot be read: unreadable, neither counted nor invalid.
  - **m4.** R-RVf3's planted-defect sentence is corrected.
  - **m5.** A test re-signs the case over a receipt alteration the binding sees: `verdict_unbound`, `receipt_time_mismatch`, as without. The R-SIG and R-RVf3 lines cite it.
- **The runner and the date column** (the new standing line). The planted-defect runner is now in the repository, `test/must_fail/run.js`.
  - A defects file (`test/must_fail/r_ab.json`) lists each defect as `{id, file, find, replace, what}`. The runner plants each alone in a copy of the tree under the system's temporary directory, runs the whole suite, and removes the copies.
  - It records every run, with its UTC date, in the file's ledger (`test/must_fail/r_ab.ledger.json`).
  - `--table` prints the must-fail table from the ledger. The column "last re-seeded and caught" is the date of the latest run that caught the defect, or "never". A defect that survived its first run and was caught after its gap test shows that re-run's date.
  - A survivor is re-seeded against the whole suite, not against its gap test alone.
- **Line counts.** `lib/_case.js` 1466 to 1489, `lib/_case_http.js` 2420 to 2432, `lib/_case_page.js` 733 to 723, `lib/_case_seal.js` 2302 to 2313.
- **Tests.**
  - New, `test/case_rab.test.js` (21: 20 and a gap test). On e06fa88 (this unit's parent), 15 fail as they should; 5 pass by design: 4 (a behaviour kept), 7 (no new copy), m2 and m3 (R-RVf3's code; the tests were missing), and m5 (a citation). On c5770ce, 17 fail and 3 pass: 4, 7 and m5.
  - Rewritten for the rule:
    - `case_redteam`: the FIX A tests and A + B DECISION;
    - `case_fix_mutation_gaps` P03/P04, `case_rj2` P31 and `case_rl4c` P06 (each asserted the old page's status, deadline or registration links);
    - `case_signed_under` DOCUMENT UNAVAILABLE and H09 (the reference's 409 is now 503, codes only).
  - Fixtures that build entries by hand, or compare a root's entry with the file's, gain `key_fp` (`case_protocol`, `case_rl4`, `case_rl4c`).
- **The must-fail pass.** 27 defects were planted over the lines R-AB changed, each alone with the whole suite run: `lib/_case.js` 8, `lib/_case_http.js` 9, `lib/_case_seal.js` 5, `lib/_case_page.js` 5.
  - The reader's own defects were among them: K06 (single party by key id), H01 (registration by key id), H07 and H09 (the reference's 409).
  - 26 were caught. K07, the guard that two entries without `key_fp` are not one key, survived. No reader reaches it, since every reader validates the record first, but `singleParty` is exported; a gap test catches it, re-seeded the same day.
  - "N failing" counts distinct failing test names (the body-audit test, which runs the case suites again, counts once). Earlier tables counted output lines.

  | id | file | planted defect | first run | last re-seeded and caught |
  |---|---|---|---|---|
  | K01 | `lib/_case.js` | 1: key_fp not an entry field | caught (517 failing) | 2026-10-14 |
  | K02 | `lib/_case.js` | 1: key_fp's form not checked | caught (2 failing) | 2026-10-14 |
  | K03 | `lib/_case.js` | 1: key_fp over the verifier string, not the public key | caught (9 failing) | 2026-10-14 |
  | K04 | `lib/_case.js` | 2: key_fp over the name and the public key | caught (9 failing) | 2026-10-14 |
  | K05 | `lib/_case.js` | 1: the entry's key_fp from the key id | caught (472 failing) | 2026-10-14 |
  | K06 | `lib/_case.js` | 2: single party by key id (the reader's defect) | caught (8 failing) | 2026-10-14 |
  | K07 | `lib/_case.js` | 2: two entries without key_fp read as one key | survived; caught by the gap test MUST-FAIL GAP (K07) | 2026-10-14 |
  | K08 | `lib/_case.js` | 5: a WITHDRAWN record read as single party | caught (2 failing) | 2026-10-14 |
  | H01 | `lib/_case_http.js` | 2: registration compares key ids (the reader's defect) | caught (9 failing) | 2026-10-14 |
  | H02 | `lib/_case_http.js` | 3: same_key_both_roles with a sentence | caught (6 failing) | 2026-10-14 |
  | H03 | `lib/_case_http.js` | 3: same_key_both_roles names the requester's key id | caught (6 failing) | 2026-10-14 |
  | H04 | `lib/_case_http.js` | 2: the pre-write check without the verifier | caught (4 failing) | 2026-10-14 |
  | H05 | `lib/_case_http.js` | 3: the reveal's single_party names a key id | caught (2 failing) | 2026-10-14 |
  | H06 | `lib/_case_http.js` | m1: no words for signer_revoked | caught (2 failing) | 2026-10-14 |
  | H07 | `lib/_case_http.js` | (b): the reference's could-not-look answered 409 | caught (5 failing) | 2026-10-14 |
  | H08 | `lib/_case_http.js` | (b): the 503 with a sentence | caught (5 failing) | 2026-10-14 |
  | H09 | `lib/_case_http.js` | (b): the could-not-look branch gone (the 409 as before) | caught (5 failing) | 2026-10-14 |
  | S01 | `lib/_case_seal.js` | 1: the projection reader does not check key_fp against the file | caught (2 failing) | 2026-10-14 |
  | S02 | `lib/_case_seal.js` | (a): the marker repaired without the record verifying | caught (2 failing) | 2026-10-14 |
  | S03 | `lib/_case_seal.js` | (a): a could-not-look repaired | caught (2 failing) | 2026-10-14 |
  | S04 | `lib/_case_seal.js` | (a): the sealer's key document not handed to the repair | caught (7 failing) | 2026-10-14 |
  | S05 | `lib/_case_seal.js` | (a): the refusal not logged | caught (2 failing) | 2026-10-14 |
  | P01 | `lib/_case_page.js` | 6: the page names a key id | caught (3 failing) | 2026-10-14 |
  | P02 | `lib/_case_page.js` | 6: the sentence claims who holds the key | caught (2 failing) | 2026-10-14 |
  | P03 | `lib/_case_page.js` | 6: the page at 503 | caught (6 failing) | 2026-10-14 |
  | P04 | `lib/_case_page.js` | 6: no single_party code | caught (3 failing) | 2026-10-14 |
  | P05 | `lib/_case_page.js` | 6: the single-party page not shown (the case read on) | caught (9 failing) | 2026-10-14 |

- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1496 tests, 1489 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1490 pass, 1 skipped.
- **UNSURE.**
  - `key_fp` is the sha256 of the 32 raw public-key bytes, not of the verifier string or of `0x01 || public key`.
  - "Fails the schema (named reason)" is read as `missing_field` naming `commitments.<role>.key_fp`; no new code.
  - The projection reader's `key_fp` check against the file was not asked for. It follows from "computed from the registration file's verifier", and it is what makes a forged `key_fp` a record that does not agree with itself.
  - Two public keys that share a key id now register and seal as two keys. A reader of the record sees the same key id under both roles.
  - The reveal's 409 `single_party` is codes only too (it named role a's key id as "the one key"); the brief names only `same_key_both_roles`.
  - Item 6: "codes-only body" is read as the page's panel carrying only the code and the links, as the inconsistent page does. The heading stays SINGLE PARTY: it is a reading, at 200, not a could-not-look. The sentence's wording is mine.
  - Item 8: "rename the moved tests (:447-448, :576-588)" is read as the §2A test and the A + B DECISION test. Five more FIX A tests whose names said "key id" are renamed too.
  - The standing line asks for each test to fail on c5770ce. Items 4 and 7 keep a behaviour and m5 cites one, so those three cannot fail there; they are listed above.
  - The runner is in `test/must_fail/`, not `tools/`, whose files the suite scans for words a test harness uses. Earlier units' defect lists were never in the repository, and their tables carry no date column; the standing line reads "from here".

## 2026-10-14: Unit R-RVf3: the OPEN expiry sentence, T12, the readers' minors, fail-closed withdrawn roots (branch `case-protocol-2026-10-10`, NOT deployed)

- **Commits.** 5d4774e (tests, code, fixture) and this entry's commit (the gap tests, the change log).
- **1. The EXPIRED page for an OPEN root** (the architect's ruling, confirming the reader's fix). An OPEN case past its deadline prints only "No joint reveal is sealed to this case, and the deadline has passed by this service's clock." The reveal refuses a root that is not COMMITTED, and a root never moves back from COMMITTED to OPEN, so the second sentence's limit does not apply to it.
  - A COMMITTED case past its deadline prints both sentences, as built. The heading stays EXPIRED for both.
  - `lib/_case_page.js` now has two constants, `EXPIRED_SENTENCE` (the first sentence) and `EXPIRED_PENDING_SENTENCE` (the second). Each comment block now heads its own constant: the registration file's comment had sat above the EXPIRED block, away from its own constant.
- **2. T12 is not equivalent.** A key id is the key's name plus the first 4 bytes of SHA-256(name, "\n", 0x01, public key), so two keys under one name sharing an id need only a birthday search.
  - `test/fixtures/key_id_collision.js` derives key i's Ed25519 seed from SHA-256(seed tag + i) and stops at the first key id already seen. It found `arcaeon.io/case-test/key-id-collision+60178041` at keys 5466 and 9628, after 9,629 keys, in about a second.
  - The pair, with the seed tag, the counters and how it was found, is `test/fixtures/key_id_collision.json`. The test re-derives both keys from their counters, so the fixture is the script's output.
  - The test signs a record with each key under a document that lists that key. Each verifies under its own document and reads `signer_unlisted` (`case_key_not_listed`) when the current document lists the other key under the same id.
  - R-SIG's table row and summary are corrected in place.
- **3. R-SIG's UNSURE line on an altered receipt was wrong** and is corrected in place, with the Tests bullet that said the same. What the code does:
  - The sealed check reads the receipt's binding first (`checkSealedReceipt`).
  - An alteration the binding sees reads `verdict_unbound`, re-signed or not (`case_item2d` "FIX 1 (planted)", not re-signed; unit R-AB's test m5 drives both).
  - An alteration it does not see, with the case not re-signed, reads `signature_invalid` (`case_fix_mutation_gaps` S10).
  - With the case re-signed, it reads `verdict_unbound`, `receipt_bad_signature` (S12).

  The check that verifies a receipt "under its own carried verifier" is `storableReceipt`'s, at seal time (`lib/_case_seal.js` near line 789). `checkSealedReceipt` verifies no signature; on a stored case the receipt's signature is checked last, under the named document's reconcile entry.
- **4. The readers' minors.**
  - **a.** `stamp_rewritten`'s sentence is now "the stamp for this hash is not the bytes recorded at the oldest commit that touched it, or is absent there, and is not taken as this commitment's stamp." It is one sentence for both cases (the bytes differ, or no file is there), and the code is unchanged.
  - **b.** The schema no longer refuses a VERDICT whose `registered_at` is later than its `revealed_at` (`lib/_case.js` `checkFull`). The order of registration and reveal is judged on the root the reveal read, COMMITTED. A registration that arrived after the reveal and was projected before the reveal read the case used to fail the seal build, 500 `seal_build_failed`; it now seals. No `registered_at <= compared_at` check was added (UNSURE).
  - **c.** R-REVf's UNSURE item on the reference's "so this case takes no reference row" is removed: ruled as built. No code change.
  - **d.** R-L5's record-level note in place of the brief's test-4 page line is confirmed as built. No change.
  - **e.** The replay and held-file paths call `readStamp` without its history (`lib/_case_http.js` near lines 1307 and 1351; 1281 and 1325 before this unit), so the bytes check at the stamp's oldest commit runs only on a registration's first write. The architect confirmed that is sufficient.
- **5. The R-SIG reader's three.** Each turned out to be a few lines, so all three are built.
  - **a. Fail closed on a WITHDRAWN root.** Before a refusal receipt is signed, and before a retried withdrawal is answered (and its marker written again), the withdrawal record goes through `signedUnderReason` (`unconfirmedWithdrawal`, 7 lines and a comment, called from `withdrawnRefusal` and `retriedWithdrawal`).
    - A could-not-look answers 503 `document_unavailable`.
    - Any other answer is 409 with the reader's code: `signature_invalid` for a bad signature.
    - The sentence is "the case reads WITHDRAWN, but its withdrawal record is not confirmed (REASON): " followed by the reference's existing words for that code, and the request's tail. The body carries `status: "WITHDRAWN"` and `reason`.
    - The check comes after the role's proof, so a non-party is still 404 `not_a_party`, and nothing is signed or written before it.
  - **b.** The reference's pre-write judge (`judgeReferenceRow` on the row it built) that could not read the row's named document now answers 503 `document_unavailable` with codes only (`error_code`, `case_id`, `reason`; no sentence, as R-L4e's code-only body). Any other refusal of that judge stays 500 `internal_error` with its sentence.
  - **c.** A `note_version` 3 row is checked as a row, its own sentence aside, and gets its `row_note_v3` reading last, so that `judgeReferenceRow` can verify its signature. One that verifies reads `row_note_v3`; one that does not reads `signature_invalid`; one whose named document cannot be read is unreadable (no test drove this until unit R-AB's m3). None is counted. A version-3 row whose other fields do not read as a row's reads by its form (`reference_missing_field`, say).
- **Line counts.** `lib/_case.js` 1461 to 1466, `lib/_case_http.js` 2393 to 2420, `lib/_case_page.js` 726 to 733, `lib/_case_seal.js` 2299 to 2302.
- **Tests.**
  - New, `test/case_rrvf.test.js` (3):
    - 1, the OPEN page, with the COMMITTED one unchanged;
    - 4a, both cases;
    - 4b, a registration projected under the reveal, on one clock: arrival, registration 2 s later, comparison 5 s later. It fails before this unit with 500 `seal_build_failed`.
  - New, `test/case_rsig.test.js` (5 and 3 gap tests):
    - T12;
    - 5a, the refusal receipt: a bad signature, a could-not-look, and a control;
    - 5a, the retried withdrawal: the same two, no marker and nothing written, and a control;
    - 5b, the document taken away after the sealed check, then the re-send;
    - 5c;
    - the gap tests W11, B05 and V01 (below).
  - The 5a, 5b, 5c and 4b tests each failed on the code before this unit, as the reader described.
  - Rewritten:
    - `case_mutation_gaps` C38, which asserted the dropped ordering check;
    - `case_rj2` B2, whose version-3 row was not signed for its own bytes and is now signed.
- **The must-fail pass.** 30 defects were planted, each alone with the whole suite run: 29 over the lines R-RVf3 changed (`lib/_case_page.js` 5, `lib/_case_http.js` 17, `lib/_case.js` 5, `lib/_case_seal.js` 2), and T12, on a line R-SIG changed, planted again against its new test. (Corrected by unit R-AB: this sentence said `lib/_case_http.js` 18, which summed to 31, and counted T12 among R-RVf3's lines.) Among them were the reader's own: R01 (4b's old check restored) and B01 (5b's 500). 27 were caught, and the 3 that survived are each caught by a gap test in `test/case_rsig.test.js`:
  - W11: the 5a bodies without `reason`;
  - B05: every refusal of the pre-write judge answered 503. The gap test drives a row dated before the seal, which must stay 500;
  - V01: a version-3 row's reading given before its other fields, so that a version-3 row with no `signed_under` read `row_note_v3`. The gap test asserts `reference_missing_field`.

  | id | file | planted defect | result |
  |---|---|---|---|
  | P01 | `lib/_case_page.js` | 1: an OPEN root prints both sentences | caught (2 failing) |
  | P02 | `lib/_case_page.js` | 1: a COMMITTED root prints the first sentence only | caught (10 failing) |
  | P03 | `lib/_case_page.js` | 1: the condition inverted | caught (10 failing) |
  | P04 | `lib/_case_page.js` | 1: the second sentence altered | caught (10 failing) |
  | P05 | `lib/_case_page.js` | 1: the first sentence altered | caught (10 failing) |
  | A01 | `lib/_case_http.js` | 4a: the old sentence | caught (2 failing) |
  | R01 | `lib/_case.js` | 4b: the registered_at > revealed_at refusal restored (the reader's defect) | caught (4 failing) |
  | W01 | `lib/_case_http.js` | 5a: the record never refused | caught (4 failing) |
  | W02 | `lib/_case_http.js` | 5a: the refusal receipt signed without the check | caught (2 failing) |
  | W03 | `lib/_case_http.js` | 5a: the retried withdrawal answered without the check | caught (2 failing) |
  | W04 | `lib/_case_http.js` | 5a: the marker written before the check | caught (2 failing) |
  | W05 | `lib/_case_http.js` | 5a: a could-not-look answered 409 | caught (4 failing) |
  | W06 | `lib/_case_http.js` | 5a: a bad signature answered 503 | caught (4 failing) |
  | W07 | `lib/_case_http.js` | 5a: one code for every answer | caught (4 failing) |
  | W08 | `lib/_case_http.js` | 5a: the caller ignores the refusal | caught (2 failing) |
  | W09 | `lib/_case_http.js` | 5a: the record read in the reconcile role | caught (31 failing) |
  | W10 | `lib/_case_http.js` | 5a: the deployment's document handed to the reader ignored | caught (31 failing) |
  | W11 | `lib/_case_http.js` | 5a: no reason in the body | survived; caught by the gap test (W11) |
  | B01 | `lib/_case_http.js` | 5b: a could-not-look answered 500 (the reader's defect) | caught (2 failing) |
  | B02 | `lib/_case_http.js` | 5b: the 500's sentence printed | caught (2 failing) |
  | B03 | `lib/_case_http.js` | 5b: status 500 | caught (2 failing) |
  | B04 | `lib/_case_http.js` | 5b: code internal_error | caught (2 failing) |
  | B05 | `lib/_case_http.js` | 5b: every refusal of the judge answered 503 | survived; caught by the gap test (B05) |
  | V01 | `lib/_case.js` | 5c: a version-3 row's reading before its other fields | survived; caught by the gap test (V01) |
  | V02 | `lib/_case.js` | 5c: a version-3 row must carry the version-4 sentence | caught (6 failing) |
  | V03 | `lib/_case.js` | 5c: a version-3 row accepted as a row | caught (8 failing) |
  | V04 | `lib/_case.js` | 5c: a version-3 row is malformed_field | caught (8 failing) |
  | V05 | `lib/_case_seal.js` | 5c: a version-3 row's signature not verified | caught (2 failing) |
  | V06 | `lib/_case_seal.js` | 5c: a version-3 row that fails verification keeps row_note_v3 | caught (2 failing) |
  | T12 | `lib/_case_seal.js` | 2: the current document's verifier not compared (R-SIG's T12) | caught (2 failing) |

- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1475 tests, 1468 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1469 pass, 1 skipped.
- **UNSURE.**
  - 4b: no ordering check stays. `registered_at` and `compared_at` come from two requests' clocks, possibly on two instances, so a `registered_at <= compared_at` check could fail the seal build under clock skew as the old one did.
  - 4a: one sentence serves both cases, since the ruling's words ("or is absent there") cover both.
  - 5a: a WITHDRAWN root whose signer the current document does not list, or lists revoked, answers 409 `signer_unlisted` or `signer_revoked`, the reader's own codes, not `signature_invalid`. Each fails closed.
  - 5a: the sealer's marker repair (`lib/_case_seal.js` `repairWithdrawn`) still acts on a WITHDRAWN root after `judgeCase` only. The ruling names the refusal receipt and the retried withdrawal, so it is not changed here. (Built by unit R-AB, carry-over (a).)
  - 5b: "codes only" is read as R-L4e's code-only body, with no sentence.
  - 5c: a version-3 row's `anchor_note` is not checked against any sentence; only its presence is required, as for every row field.
  - Seen, not changed: the reference answers a sealed case whose named document cannot be read with 409 `document_unavailable` (`lib/_case_http.js`, the sealed check), not a 503. (Changed by unit R-AB, carry-over (b): 503, codes only.)

## 2026-10-14: Unit R-RVf2: the EXPIRED page's sentence, as ruled (branch `case-protocol-2026-10-10`, NOT deployed)

- **Commits.** 0ee71e0 (tests and the sentence) and this entry's commit.
- **The ruling** (the architect's, correcting the sentence R-RVf kept). The page reads one root. It learns only three things: the root is not sealed, no seal is recorded, and the deadline has passed by this service's clock. Arrival is known only to the reveal's compare-and-swap, so "received" is not the page's to say. The EXPIRED page's sentence (`lib/_case_page.js` `EXPIRED_SENTENCE`) is now exactly: "No joint reveal is sealed to this case, and the deadline has passed by this service's clock. A reveal that arrived before the deadline still seals the case whenever its sealing lands, and this page cannot tell whether one is pending." It replaces "No joint reveal was received before the deadline, by this service's clock, so the case reads EXPIRED."
  - The heading stays EXPIRED.
  - The sentence after it, "Expiry is read, not written, and implies no actor.", is kept.
  - No new state, field, marker or write. The verdict page is unchanged.
  - R-RVf's entry, which says the EXPIRED sentence was unchanged, stands as the record of that unit.
  - `lib/_case_page.js` goes from 719 lines to 726 (the constant and its comment).
- **Tests** (`test/case_rrvf.test.js`, 4 new). For a COMMITTED case past its deadline, the page prints the sentence exactly under `<h1>Case: EXPIRED</h1>`, in three states:
  - a reveal in flight: arrived before the deadline, the page read before its seal lands, and the seal then landing;
  - a timely reveal whose seal write failed: the root unchanged;
  - no reveal ever.

  In each, the page read writes nothing, and neither the old sentence nor "received before the deadline" appears. A fourth test checks that the old sentence is in no `lib/` or `tools/` file and not in the README. The R-RVf tests on the old sentence now assert the new one, escaped as the page prints it.
- **The must-fail pass.** 4 defects were planted in `lib/_case_page.js`, each alone with the whole suite run, and all 4 were caught:

  | id | planted defect | result |
  |---|---|---|
  | E01 | the old sentence printed | caught (10 failing) |
  | E02 | the sentence names no limit of the page | caught (9 failing) |
  | E03 | the sentence not escaped | caught (9 failing) |
  | E04 | the first clause claims a receipt | caught (9 failing) |
- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1464 tests, 1457 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1458 pass, 1 skipped.
- **UNSURE.** The ruling replaces "the sentence". The page's second sentence, "Expiry is read, not written, and implies no actor.", says nothing about arrival, so it is kept.

## 2026-10-14: Unit R-L5f: the reader's blocker on R-L5 (branch `case-protocol-2026-10-10`, NOT deployed)

- **Commits.** 2bc85f5 (tests, code, README) and this entry's commit (the gap tests, the change log).
- **B1.** The withdrawal reads the case root before it takes the case lock, and its root write is a compare-and-swap on that read. Since R-L5 the record it builds keeps the root's `commitments`.
  - When the compare-and-swap loses, the store reads the root again and hands that read to the withdrawal's rebuild hook (`lib/_store.js` `putFile`).
  - The record is written again only when both roles' entries on that read are the ones the record carries: their json-c14n:v1 bytes equal (`sameEntry`), and a null equals only a null.
  - Otherwise nothing is written, and the withdrawal answers the existing 503 `store_error` (`reason: case_kept_changing`), which a re-send finishes. The re-send reads the root as it then stands, and builds and signs the record from it.
  - A seal, an expiry or another withdrawal found on the re-read is refused as before.
  - The 503's sentence is now "the case changed while this request tried to write; nothing was written to the case record. Send it again." It said "kept changing", which one projection landing does not show. Its code is unchanged.
  - The README's Withdrawal section gains one sentence: "A registration projected between a withdrawal's read of the case and its write makes the withdrawal write nothing and answer 503 `store_error`; sent again, it keeps the new registration."
  - A fix of the same gap, found during R-SIG, rebuilt and re-signed the record inside the compare-and-swap. It was a local commit, never pushed, and was dropped for this ruling.
- **M1.** Since R-L5 a withdrawal record must carry `commitments`. A record in the form written before R-L5 (and, before R-SIG, without `signed_under`) is refused by the schema: `missing_field` at `commitments`. Every reader then reads it as `case_record_unreadable`, reason `case_missing_field`, and never as a withdrawal. Nothing is deployed, so no such record exists. A test plants one, signed with the case key, and checks:
  - the schema;
  - a withdrawal sent again (503 `case_record_unreadable`);
  - the refusal receipt (none is issued);
  - the page (no withdrawn page; it names `case_missing_field`).

  The test passes on the code before this unit: M1 asked for the test, not for a change.
- **M2.** R-L5's entry carried its survivors and its UNSURE list. It now carries the full table of its 17 planted defects as well.
- **The five minors.** Not folded in: the reader's report is not in this session. Please paste them; each that is one or two lines goes into the next commit.
- **R-SIG's entry corrected.** `lib/_case_http.js` went from 2367 lines to 2378 in R-SIG, not 2387: the count was taken while the dropped local commit was in the tree.
- **Tests** (`test/case_rl5.test.js`, 6 new):
  - B1, the brief's test: a projection landing under the withdrawal. The withdrawal answers 503 and writes nothing (the root as the projection left it; no marker). The re-send answers 201 with b's entry kept and the record's signature verifying. Role b's own refusal receipt is then a 409 `case_withdrawn` naming b's commitment, and `verifyRefusalReceipt` holds. It fails on the code before this unit: 201, and the stale record with b's entry null.
  - B1's control: a root that moved with both entries unchanged takes the built record.
  - M1 (above).
  - The README sentence.
  - Gap tests F03 and F05/F06 (below).
  - Rewritten:
    - `case_item2c` WITHDRAWAL RACE (3), which asserted the old behaviour (201 over the moved projection). It now asserts 503, nothing written, and the re-send keeping b's entry.
    - `case_rl2` M2's sentence.
- **The must-fail pass.** 8 defects were planted over the lines R-L5f changed (`lib/_case_http.js` 7, the README 1), each alone with the whole suite run. 5 were caught, among them F01, the defect the reader named (the stale record written): it fails the B1 test and `case_item2c`'s race. The 3 that survived are each caught by a gap test in `test/case_rl5.test.js`:
  - F03: only role b's entry compared. The gap test projects role a under role b's withdrawal.
  - F05 and F06: two non-null entries always the same, or compared by their commitment only. No path of this service changes a projected entry once it is written, so the gap test plants a root whose entry differs in `stamped_at` alone.

  | id | file | planted defect | result |
  |---|---|---|---|
  | F01 | `lib/_case_http.js` | B1 as reported: the stale record is written over a moved projection | caught (4 failing) |
  | F02 | `lib/_case_http.js` | only role a's entry compared | caught (4 failing) |
  | F03 | `lib/_case_http.js` | only role b's entry compared | survived; caught by the gap test (F03) |
  | F04 | `lib/_case_http.js` | a null entry matches anything | caught (4 failing) |
  | F05 | `lib/_case_http.js` | two entries always match | survived; caught by the gap test (F05, F06) |
  | F06 | `lib/_case_http.js` | entries compared by commitment only | survived; caught by the gap test (F05, F06) |
  | F07 | `lib/_case_http.js` | the 503's sentence says kept changing | caught (4 failing) |
  | F08 | README | the README sentence | caught (2 failing) |

- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1460 tests, 1453 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1454 pass, 1 skipped.
- **UNSURE.**
  - "Re-read once": the comparison runs on the store's own read after the lost write. When it refuses, the handler reads the root once more to say what the case now is (R-L2 M2's existing path), so a refused withdrawal reads the root twice after its write.
  - The 503 keeps its code, `case_kept_changing`; only its sentence changed.
  - The README sentence was not asked for; it says only what the code does.
  - Entries are compared whole, not by commitment alone; see F05/F06.

## 2026-10-14: Unit R-SIG: signed_under on every signed record; one reader; no unsigned records (branch `case-protocol-2026-10-10`, NOT deployed)

- **Commits.** 490aa02 (the unit: tests, code, README, key document) and this entry's commit (the gap tests, the change log, and a test temp-file fix, below).
- **The architect's rulings.**
  - Rule 5 reads "note_version must equal 4". A row at version 3, never issued, reads `row_note_v3` and is not rewritten. Any other version, or none, is `malformed_field`.
  - `case_signature_invalid` is now `signature_invalid`, everywhere.
  - `withdrawal.reason` is optional and absent when not given.
  - Rule 11's sentence is printed as written.
- **Rule 1.** `signed_under` is exactly `{document_sha256, document_commit}` (`lib/_case.js` `SIGNED_UNDER_FIELDS`, `checkSignedUnder`). It is required on all four signed records: the sealed case, the withdrawal record, the reference row and the refusal receipt. `retrieved_at` is gone, and a record carrying it is `unknown_field`. An OPEN or COMMITTED root carrying `signed_under` is `status_inconsistent`.
- **Rule 2: one reader.** `signedUnderReason(rec, role, doc)` in `lib/_case_seal.js` checks, in order:
  1. the named document (`namedDocumentOf`): its commit on the published branch, and the document there the one `signed_under.document_sha256` names;
  2. `signed_by` listed active in `role` there;
  3. the signature over the record minus `sig`;
  4. the current document `doc` listing the key in `role` with the same verifier (else `signer_unlisted`), not revoked (else `signer_revoked`, R-REV's answer, called as it was).

  It answers `valid_under_document`, `signature_invalid`, `signer_unlisted`, `signer_revoked` or `document_unavailable`, each with a reason. Its callers:
  - `sealedRecordReason`: single party, then the receipt's binding, then `signedUnderReason(rec, "case")`, then the reconcile receipt under the same named document in role `reconcile`, then the current document's listing of the reconcile key;
  - `judgeReferenceRow`, now async (`liveRecords` and the reference handler await it): the row's form, then `signedUnderReason(row, "case")`. A row whose named document could not be read is counted unreadable, never invalid;
  - the withdrawn page's "signed by" cell (`withdrawalSignedByHtml`): `signedUnderReason(root, "case")`;
  - `verifyRefusalReceipt` and `tools/check_refusal_receipt.js`: the form (`refusalReceiptFormReason`), then `signedUnderReason(rec, "reconcile")`. The tool's offline mode passes the supplied file as the named document (`{named}`), and the reader then skips the branch read and the current-document step. The tool still never prints `ok: true` offline.
- **Rule 3.** The withdrawal and the reference confirm their document as the reveal does (`sealingDocument`, then `confirmSealingDocument`, through one helper, `signingDocument`). If it is not confirmed they answer 503 `document_unavailable`, write nothing, and the sentence ends with the request's "wrote nothing" tail. The withdrawal confirms after the role's proof and before loading its signer. The reference confirms before the sealed check.
- **Rule 4.**
  - `signRecord` throws without a signer: "signRecord: no signer (CODE); no record is written unsigned".
  - `sig_reason` is null on every signed record. On an OPEN or COMMITTED root it is exactly `UNSEALED_SIG_REASON`; any other value is `malformed_field`, and null is `sig_reason_missing`.
  - `sig` must be a non-empty string on a VERDICT, a WITHDRAWN record and a reference row (else `malformed_field`), and on a refusal receipt (its form: `malformed_field`).
  - `row_unsigned` is gone.
- **Rule 5 (ruled).** `note_version` 4. A row at version 3 reads `row_note_v3`; any other version, or none, is `malformed_field`. `row_note_v1` and `row_note_v2` are gone. `REFERENCE_ANCHOR_NOTE` is unchanged.
- **Rule 6.** A stored reconcile receipt inside a seal carries a non-empty `sig` (else `malformed_field` at `verdict.sig`) and no `unsigned_reason` (else `malformed_field`). `RECEIPT_OPTIONAL` is `["verdict_digest_note"]`.
- **Rule 7.** `validateWithdrawBody` and `withdrawnRecord` record a reason only when the request names one. The withdrawn page's reason cell reads "No reason was given." when there is none. `DEFAULT_WITHDRAWAL_REASON` and the "written before Design N" sentence are gone.
- **Rule 8.** `appended_by` is `preimage:a`, `preimage:b` or `operator`. The page prints "appended on presentation of role a's commitment preimage" or "appended with the operator key".
- **Rule 9.** The refusal receipt's `reason` is `case_withdrawn`. The 409's sentence no longer speaks of consent: "the case was withdrawn, so this reveal is refused and its tapes are never decoded or hashed; nothing was compared, and nothing about the tapes is kept. ..."
- **Rule 10.** One case-root judge, `judgeCase(got, caseId)`, exported from `lib/_case_seal.js`. It is used by the handlers in `lib/_case_http.js` (7 calls; the handler's own copy is removed), the sealer (`anchorCase`, `repairWithdrawn`) and the page (`handleCasePage`).
- **Rule 11 (ruled).** The registrations panel and the README carry exactly: "A registration file is signed by the registering party over the case, role and commitment; its registered_at, stamp_commit and stamped_at are the service's unsigned arrival note until a seal copies them into signed bytes."
- **Rule 12.** The key document's `description` now names every signed record and its key, in the brief's three sentences. The rest of the description is unchanged.
- **Signatures checked against a key document, before this unit** (`lib/_case_seal.js` unless named):
  - `publishedSignatureReason`: reference rows (through `judgeReferenceRow`) and the withdrawn page (`lib/_case_page.js` `signedByHtml`), under the CURRENT document;
  - `sealedRecordReason`: the seal and its receipt, under the named document;
  - `verifyRefusalReceipt`: its own named-document code;
  - `checkStoredReceipt` with `receiptSignerReason`: a receipt under a given verifier (no production caller);
  - `tools/check_refusal_receipt.js` `offline`: its own verification against the supplied file.
- **After:** `signedUnderReason`, for all four records and the tool's offline mode. `sealedRecordReason` also checks the embedded receipt, under the same named document `signedUnderReason` read and in role `reconcile`.
  - Not against a key document, and unchanged: the seal-time checks of the receipt this request's own signer just produced (`checkReceipt`, `storableReceipt`), and a registration's party signature (`lib/_case.js`).
  - `signatureReason` stays as the primitive (one verifier, one record), and `signedUnderReason` is its one caller.
- **Removed**, with line counts:
  - `lib/_case_seal.js`, 2326 lines to 2299:
    - `publishedSignatureReason` (10 lines);
    - `checkStoredReceipt` (7) and `receiptSignerReason` (7), with `RECEIPT_UNSIGNED_REASONS` (1), and their exports;
    - signRecord's unsigned branch;
    - `verifyRefusalReceipt`'s own named-document code;
    - the `document_unrecorded` answer;
    - `row_note_v1`/`row_note_v2` handling;
    - `retrieved_at` in every writer.
  - `lib/_case_http.js`, 2367 to 2378. It grows by `signingDocument` and the two confirmations. Removed:
    - its own `judgeCase` (8);
    - `withoutSigReason` (4) and the "stored unsigned" note;
    - `UNSEALED_WORDS.document_unrecorded`;
    - the consent clause.
  - `lib/_case_page.js`, 710 to 719. Removed:
    - `signedByHtml` (10);
    - the `unsigned: ...` cells;
    - the `retrieved_at` cell;
    - `UNVERIFIED_CHECKS.document_unrecorded`;
    - the "written before Design N" sentence.
  - `lib/_case.js`, 1438 to 1461. It grows by `checkSig`, `checkSignedBy` and `checkSignedUnder`. Removed:
    - `DEFAULT_WITHDRAWAL_REASON` and its export;
    - `row_note_v1` and `row_note_v2` from `CODES`;
    - `retrieved_at`.
  - `tools/check_refusal_receipt.js`, 78 to 72: its own crypto, and the `crypto` and `canonicalBytes` requires.
  - Tests deleted (2): `case_signed_under`'s two DOCUMENT UNRECORDED tests (33 lines), with their helper `unrecordedCase`.
- **The four records as they now stand** (every one signed by `signRecord`: `signed_by` a key id, `sig` base64 Ed25519 over the json-c14n:v1 bytes of the record minus `sig`, `sig_reason` null; `signed_under` `{document_sha256: 64 hex, document_commit: 40 hex}`):
  - **Sealed case** (`cases/<case_id>.json`, status VERDICT), signed with the case key: `v, case_id, protocol_version, policy_version, scope_digest, party_a, party_b, opened_at, deadline, commitments {a, b}, reveals {a, b}, verdict` (the signed reconcile receipt: `kind, v, claim, tapes, method, verdict, verdict_digest, compared_at, does_not_claim, signer, sig`, optionally `verdict_digest_note`; never `unsigned_reason`), `records, cross_reference, status, withdrawal: null, limits, signed_under, signed_by, sig, sig_reason`.
  - **Withdrawal record** (the same path, status WITHDRAWN), signed with the case key: `v, case_id, protocol_version, status, opened_at, commitments {a, b}` (the root's projection as it stood; the withdrawing role's entry not null), `withdrawal {by_role, at, salt_sha256, reason?}` (`reason`, only when given, is `party_choice`, `deadline` or `other`), `limits, signed_under, signed_by, sig, sig_reason`.
  - **Reference row** (`cases/<case_id>/references/<seq>.json`), signed with the case key: `kind: "case_reference", v: 1, case_id, seq, cross_reference {operator, reference, url}, recorded_at, appended_by` (`preimage:a`, `preimage:b` or `operator`), `anchor_note` (`REFERENCE_ANCHOR_NOTE`), `note_version: 4, signed_under, signed_by, sig, sig_reason`.
  - **Refusal receipt** (in the 409 body; written nowhere), signed with the reconcile key: `kind: "comparison_refused", v: 1, case_id, at, reason: "case_withdrawn", role, commitment_sha256, signed_under, signed_by, sig, sig_reason`.
- **Tests.**
  - New, `test/case_rsig.test.js`: the brief's 1 to 12, plus 8 more:
    - one reader;
    - one case-root judge;
    - `signature_invalid` everywhere;
    - the stored receipt must be signed;
    - `sig_reason` only on OPEN or COMMITTED roots;
    - rule 11;
    - rule 12;
    - no `unsigned:` page cell.

    Also nine must-fail gap tests (below). 29 tests in all.
  - Rewritten in about 30 files, for the new forms:
    - planted records carry `signed_under` with two fields and are signed;
    - `signature_invalid`;
    - `preimage:a`;
    - `case_withdrawn`;
    - no default reason;
    - `note_version` 4;
    - writers given a deployment the document is confirmed for (`test/helpers/key_document.js` `KD.deployedFor`);
    - a receipt altered in a field the receipt binding does not read, without re-signing the case, reads `signature_invalid` (the case signature is checked after the binding), so those receipt tests re-sign the case. (Corrected by unit R-RVf3: this line said the case signature is checked first.)
- **A test's temp file.** `test/response_bodies.test.js` wrote its audit file (about 18 MB, every body the case suites drive) to a fresh temp directory on every run and never removed it, so every suite run and every planted-defect run left one behind. It now removes the directory after the read. Nothing else in the test changes.
- **The R-L5 gap found during this unit** (a registration projected between a withdrawal's read and its write was missing from the kept projection) is not built here. The reader's B1 on R-L5 ruled its fix, and it is built as R-L5f.
- **The must-fail pass.** 75 defects were planted over the lines R-SIG changed, each alone with the whole suite run: `lib/_case.js` 19, `lib/_case_seal.js` 33, `lib/_case_http.js` 7, `lib/_case_page.js` 10, the tool 2, the README 3, the key document 1. 63 were caught. Of the 12 that survived, 11 are each caught by a gap test in `test/case_rsig.test.js` (9 tests), and 1, T12, was called equivalent here. It is not (corrected by unit R-RVf3):
  - T12, the current document's verifier not compared beside its key id. This entry said one key id under two verifiers needs a 32-bit collision that no test can build. A 32-bit collision is a birthday search of about 2^16 keys, done once offline. Unit R-RVf3 keeps such a pair as a test fixture, and its test catches T12.

  The table:

  | id | file | planted defect | result |
  |---|---|---|---|
  | G01 | `lib/_case.js` | rule: a signed record with sig null is accepted by the schema | caught (2 failing) |
  | G02 | `lib/_case.js` | rule: a signed record may carry a sig_reason | caught (4 failing) |
  | G03 | `lib/_case.js` | rule: an open case may carry any sig_reason | caught (2 failing) |
  | G04 | `lib/_case.js` | an unsigned case with sig_reason null reads malformed_field, not sig_reason_missing | caught (4 failing) |
  | G05 | `lib/_case.js` | signed_by need not be a key id | caught (2 failing) |
  | G06 | `lib/_case.js` | withdrawn: signed_under's shape not checked | caught (2 failing) |
  | G07 | `lib/_case.js` | a stored receipt with sig null is accepted | survived; caught by the gap test (G07) |
  | G08 | `lib/_case.js` | a stored receipt may say unsigned_reason | caught (2 failing) |
  | G09 | `lib/_case.js` | a VERDICT without signed_under reads malformed_field, not missing_field | caught (4 failing) |
  | G10 | `lib/_case.js` | an open case may carry signed_under | caught (2 failing) |
  | G11 | `lib/_case.js` | signed_under may carry other fields (retrieved_at) | caught (4 failing) |
  | G12 | `lib/_case.js` | signed_under's field list keeps retrieved_at (required) | caught (356 failing) |
  | G13 | `lib/_case.js` | the withdrawal reason defaults to party_choice | caught (6 failing) |
  | G14 | `lib/_case.js` | a version-3 row reads malformed_field | caught (6 failing) |
  | G15 | `lib/_case.js` | note_version 5 accepted | caught (4 failing) |
  | G16 | `lib/_case.js` | a row without note_version reads missing_field | caught (6 failing) |
  | G17 | `lib/_case.js` | appended_by role:a accepted | caught (2 failing) |
  | G18 | `lib/_case.js` | row: signed_under's shape not checked | caught (2 failing) |
  | G19 | `lib/_case.js` | row: sig not checked by the schema | caught (2 failing) |
  | T01 | `lib/_case_seal.js` | signRecord returns an unsigned record with no signer | caught (10 failing) |
  | T02 | `lib/_case_seal.js` | the binding accepts a receipt with sig null | survived; caught by the gap test (T02) |
  | T03 | `lib/_case_seal.js` | a receipt may carry unsigned_reason | caught (2 failing) |
  | T04 | `lib/_case_seal.js` | offline: the supplied document's sha256 not checked | caught (2 failing) |
  | T05 | `lib/_case_seal.js` | the named document's revoked key verifies | caught (6 failing) |
  | T06 | `lib/_case_seal.js` | a key in another role verifies | caught (8 failing) |
  | T07 | `lib/_case_seal.js` | the signature itself is not checked | caught (13 failing) |
  | T08 | `lib/_case_seal.js` | offline runs the current-document step | caught (6 failing) |
  | T09 | `lib/_case_seal.js` | an unreadable current document holds | caught (11 failing) |
  | T10 | `lib/_case_seal.js` | a key not in the current document holds | caught (15 failing) |
  | T11 | `lib/_case_seal.js` | a key revoked in the current document holds | caught (21 failing) |
  | T12 | `lib/_case_seal.js` | the current document's verifier not compared | survived; not equivalent: caught by unit R-RVf3's test "R-RVf3 2 (T12)" (corrected) |
  | T13 | `lib/_case_seal.js` | could-not-look read as signature_invalid | caught (16 failing) |
  | T14 | `lib/_case_seal.js` | the seal goes on to the receipt when the case signature fails | caught (15 failing) |
  | T15 | `lib/_case_seal.js` | a revoked reconcile key in the named document signs the receipt | caught (2 failing) |
  | T16 | `lib/_case_seal.js` | a case key may sign the receipt | caught (2 failing) |
  | T17 | `lib/_case_seal.js` | the receipt's signature not verified | caught (4 failing) |
  | T18 | `lib/_case_seal.js` | an unlisted reconcile key holds | caught (6 failing) |
  | T19 | `lib/_case_seal.js` | a revoked reconcile key holds | caught (11 failing) |
  | T20 | `lib/_case_seal.js` | judgeCase: a root at another case's path holds | caught (2 failing) |
  | T21 | `lib/_case_seal.js` | withdrawnRecord writes a default reason | caught (7 failing) |
  | T22 | `lib/_case_seal.js` | the receipt's reason is consent_withdrawn | caught (7 failing) |
  | T23 | `lib/_case_seal.js` | receipt form: signed_under may carry other fields | caught (4 failing) |
  | T24 | `lib/_case_seal.js` | receipt form: a missing signed_under field reads malformed_field | survived; caught by the gap test (T24) |
  | T25 | `lib/_case_seal.js` | receipt form: an unsigned receipt passes the form | caught (4 failing) |
  | T26 | `lib/_case_seal.js` | verifyRefusalReceipt drops the detail | caught (8 failing) |
  | T27 | `lib/_case_seal.js` | a version-3 row reads reference_row_note_v3 | caught (2 failing) |
  | T28 | `lib/_case_seal.js` | a row's signature is not read | caught (7 failing) |
  | T29 | `lib/_case_seal.js` | a row whose document could not be read is invalid | survived; caught by the gap test (T29, T30) |
  | T30 | `lib/_case_seal.js` | liveRecords: an unavailable row counted invalid | survived; caught by the gap test (T29, T30) |
  | T31 | `lib/_case_seal.js` | an invalid row without a detail carries detail undefined/null | caught (8 failing) |
  | T32 | `lib/_case_seal.js` | the refusal receipt read in role case | caught (9 failing) |
  | T33 | `lib/_case_seal.js` | the answer carries a third field | caught (4 failing) |
  | U01 | `lib/_case_http.js` | a writer signs under an unconfirmed document | caught (2 failing) |
  | U02 | `lib/_case_http.js` | the withdrawal does not confirm its document | caught (2 failing) |
  | U03 | `lib/_case_http.js` | the reference does not confirm its document | caught (4 failing) |
  | U04 | `lib/_case_http.js` | appended_by names the other role | caught (6 failing) |
  | U08 | `lib/_case_http.js` | the answer's signature_invalid words | survived; caught by the gap test (U08) |
  | U09 | `lib/_case_http.js` | the receipt message speaks of consent | survived; caught by the gap test (U09) |
  | U10 | `lib/_case_http.js` | the 503 names no reason | caught (2 failing) |
  | V01 | `lib/_case_page.js` | rule 11: the page's registration-file sentence | caught (2 failing) |
  | V02 | `lib/_case_page.js` | an invalid withdrawal signature shown as verified | caught (6 failing) |
  | V03 | `lib/_case_page.js` | could-not-look shown as not confirmed with a code | survived; caught by the gap test (V03, V10) |
  | V04 | `lib/_case_page.js` | the page names no code | caught (4 failing) |
  | V05 | `lib/_case_page.js` | the page names a default reason | caught (6 failing) |
  | V06 | `lib/_case_page.js` | an open case's signed-by cell | caught (2 failing) |
  | V07 | `lib/_case_page.js` | a preimage row read as the operator's | caught (2 failing) |
  | V08 | `lib/_case_page.js` | the invalid-row note drops the detail | caught (2 failing) |
  | V09 | `lib/_case_page.js` | the unverified page has no words for signature_invalid | survived; caught by the gap test (V09) |
  | V10 | `lib/_case_page.js` | the verified cell names no commit | survived; caught by the gap test (V03, V10) |
  | K01 | the tool | the tool reads the receipt in role case | caught (6 failing) |
  | K02 | the tool | the tool skips the form | caught (2 failing) |
  | R01 | README | rule 11: the README sentence | caught (2 failing) |
  | R02 | README | README: the receipt's reason | caught (2 failing) |
  | R03 | README | README: the no-reason sentence | survived; caught by the gap test (R03) |
  | D01 | key document | the key document's description of signed_under | caught (2 failing) |

- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1454 tests, 1447 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1448 pass, 1 skipped.
- **UNSURE.**
  - `sig_reason` stays on signed records as null, not removed, so that every record has one field list and the form check is one rule.
  - A key that the named document lists but not as active reads `signature_invalid` with reason `signer_not_active`. The revoked answer (`signer_revoked`, `key_revoked`) is the current document's, as R-REV built it.
  - (Corrected by unit R-RVf3; this line said the case signature is checked first, so that an altered receipt reads `signature_invalid`, not `verdict_unbound`. That is wrong.) The sealed check reads the receipt's binding first (`checkSealedReceipt`, its form and its binding to the case; it verifies no signature). An alteration the binding sees reads `verdict_unbound` with the binding's reason, whether or not the case was re-signed (`case_item2d` "FIX 1 (planted)": `compared_at` altered, `receipt_time_mismatch`, not re-signed; unit R-AB's test m5 drives both). An alteration it does not see, with the case not re-signed, reads `signature_invalid`, the case's own signature being checked next (`case_fix_mutation_gaps` S10). With the case re-signed, the receipt's own signature is checked last and reads `verdict_unbound`, `receipt_bad_signature` (S12).
  - `receipt_unsigned` is kept as the seal's code for a receipt signer the named document does not list as an active reconcile key (`unknown_signer`, `signer_not_active`).
  - A named commit that is not on the published branch is `document_unavailable` with reason `commit_not_on_branch` (could-not-look), as the seal read it before. It is not a separate code.
  - The reference confirms its document before its sealed check, so a raw host that is down answers 503 `document_unavailable`, not 409. The withdrawal confirms its document after the role's proof and before its signer.
  - A receipt without a signature, inside a stored seal, is refused by the case schema (`malformed_field`). At the seal it is `receipt_unknown_field`, because `unsigned_reason` is no longer a receipt field.
  - `publishedEntry` stays exported, with no `lib/` caller.
  - The page's "signed by" row for an OPEN or COMMITTED case prints `UNSEALED_SIG_REASON`, the fixed sentence the root carries.
  - A reference row whose named document could not be read counts as unreadable, never invalid: like a row whose read failed, it leaves the live count not established when no valid row is read.
  - No record written before this unit exists anywhere (nothing is deployed), so no reader keeps a path for one: a sealed case, row or withdrawal record without `signed_under`, or a row at version 1 or 2, is refused by its schema.

## 2026-10-14: Unit R-L5: the withdrawal record keeps the root's projection; a withdrawn case's readers read no file or history (branch `case-protocol-2026-10-10`, NOT deployed)

R-L5's first commit precedes unit R-RVf on the branch: the architect's R-RVf rulings were built next, as ordered. This entry and R-L5's gap tests follow R-RVf.

- **The architect's rulings.**
  - The DAMAGED removal was already done (R-L4b, R-L4e), so that part of the unit is dropped.
  - `key_fp` belongs on the WITHDRAWN projection this unit shapes. The projection is the root's entries exactly as they stood, checked against the same entry fields as the root's (`CASE_ENTRY_FIELDS`), so when R-AB adds `key_fp` to an entry, the withdrawal record carries it with no change here. This unit does not add `key_fp`: `key_id` versus `key_fp` is R-AB's.
- **Rule 1.** `WITHDRAWN_FIELDS` gains `commitments`. `withdrawnRecord` copies the case root's `commitments` as they stand when the withdrawal is written, including an OPEN case's null for a role not registered, inside the signed record: the record's signature covers them. There is no `party_a` and no `party_b`.
  - `checkWithdrawn` holds the projection to: an object with exactly `a` and `b`; each null or a whole case entry (`checkCommitmentEntry`, with a 64-hex `registration_sha256` and `claim_sha256`); the role that withdrew not null (else `status_inconsistent` at `commitments.<role>`); and one commitment never in both roles (`duplicate_commitment`).
  - A WITHDRAWN record is never single party: `singleParty` does not read a WITHDRAWN record's commitments.
- **Rule 2.** Every reader of a withdrawn case takes standing from the kept projection, and nothing orders a file against the withdrawal by commit.
  - The refusal receipt (`withdrawnRefusal`) checks the requester's opening against `commitments[role]`. It reads no registration file and no history.
  - A retried withdrawal (`retriedWithdrawal`) proves the opening against the same projection, and also reads no registration file and no history.
  - The page: decided here, the "written, never confirmed" line is not printed. The page cannot see a file the record does not project without listing the directory, and the listing was removed in unit R-L. R-L4's rule also holds that the page neither lists nor links an unprojected file, and R-L4c keyed the paths by claim. The page prints `WITHDRAWN_REGISTRATIONS_NOTE`, now: "The registration files of this case, if any, remain in the public record of the pins repository. This withdrawal record keeps the registrations the case root projected when it was withdrawn; a registration file it does not project does not stand: no reader counts it."
  - The README says the same in a new paragraph under "Withdrawal".
- **Rule 3 (no DAMAGED).** Already done. R-L4b made it 503 `case_record_inconsistent` for every handler. R-L4e gave the page its one sentence: "The stored record for this case does not agree with itself. Nothing is asserted about this case while that is so." The brief's rule 3 sentence predates R-L4e's ruling and was not brought back. Test 5 is a guard.
- **Rule 4.** Already done: a missing withdrawn marker is written by `anchorPending`'s terminal branch (through `repairWithdrawn`, which nothing else calls). Test 6 is a guard.
- **What R-L4 had already done** (read in the code, not assumed):
  - `withdrawalCommitOf` and `registrationAgainstWithdrawal` are in no `lib/` file: R-L4 replaced them with `rootBeforeWithdrawal`, which this unit removes.
  - `repairWithdrawn`'s rotating windows, the markerless scan and `WITHDRAWN_REPAIR_READS` are in no `lib/` file.
  - No DAMAGED state, reason or page branch exists.
  - The `case_rj3` table has no row ordering a file against a withdrawal, so no row was removed.
  - The README's "The sealer's window" describes the window of cases a sealer run reads (`rotatingWindow`), which remains, and R-N4 R6's test requires the README to say so. It is not the withdrawn repair windows, so it is kept.
- **Removed**, with line counts:
  - `lib/_case_seal.js` (2343 lines to 2323): `rootBeforeWithdrawal` and `WITHDRAWAL_COMMIT_READS` (23 lines with their comment) and the export.
  - `lib/_case_http.js` (2349 to 2332):
    - from `withdrawnRefusal`: the read of the root before the withdrawal, its 503 `store_unreachable` ("the case root before the withdrawal could not be read"), and the projection read with its refusal;
    - from `retriedWithdrawal`: the same reads, its 503 `store_unreachable` ("The case is withdrawn. This request could not finish checking it. Send the same withdrawal again.") and its `case_record_inconsistent` refusal;
    - the caller's line for that refusal.
  - `lib/_case.js` grows (1415 to 1438) with the projection's check. `lib/_case_page.js` changes one comment. The README grows (950 to 957) by the paragraph.
  - Tests deleted: 3 tests (37 lines) of the removed reads: `case_rl4` H55 and S06/S07/S09, and `case_rn4` f4.
  - Arms removed: `case_rn` H13 and H17 (H19 stays); the 503 half of `case_rn3` H21; and the "again: withdrawn, registration unread" arm of `case_rn4`'s R1 sweep, which now drives 26 arms.
- **Rewritten.**
  - The planted WITHDRAWN records carry `commitments`: `case_item2c` FIX 6; `case_mutation_gaps`; `case_protocol` TEST 3, ITEM 2A and SCHEMA; `case_reveal` TEST 6.
  - `case_item2c` TEST 10: the record keeps the root's commitments, and no labels.
  - `case_protocol` SCHEMA: a withdrawn record's `commitments` is no longer `unknown_field`, and one without them is refused.
  - `test/case_redteam.test.js` GPT-5.6 §2B: DECIDED (unit R-L5). The record identifies the commitments and not the parties' labels, and the test asserts that, so there is no new todo and `case_rn` T1's count is unchanged.
- **Tests.** New, `test/case_rl5.test.js` (12):
  - the brief's 1, with 1b (an OPEN case keeps its one entry) and 1c (the schema);
  - 2, 3 and 4;
  - 5 and 6, guards;
  - the removal test;
  - three gap tests (below).

  Test 4 fails before this unit (the withdrawal record kept no commitments), so it is not a guard.
- **The must-fail pass.** 17 defects were planted over the lines R-L5 changed (`lib/_case.js` 9, `lib/_case_seal.js` 3, `lib/_case_http.js` 4, the README 1), each alone with the whole suite run. 9 were caught. The 8 that survived are each caught by a gap test in `test/case_rl5.test.js`:
  - L04: the projection not required to be an object;
  - L05: a key beside `a` and `b` accepted;
  - L06: a role missing from the projection;
  - L07: an entry not checked as a whole entry;
  - L08: an entry's `registration_sha256` or `claim_sha256` not held to 64 hex;
  - L10: one commitment in both roles;
  - L11: a withdrawn record whose two entries name one key read as single party;
  - L17: the README's paragraph.

  The table (added by unit R-L5f, M2):

  | id | file | planted defect | result |
  |---|---|---|---|
  | L01 | `lib/_case.js` | rule 1: commitments not a WITHDRAWN field | caught (83 failing) |
  | L02 | `lib/_case_seal.js` | rule 1: the withdrawal record drops the projection | caught (75 failing) |
  | L03 | `lib/_case_seal.js` | rule 1: only the withdrawer's entry kept | caught (19 failing) |
  | L04 | `lib/_case.js` | schema: no object check | survived; caught by the gap test (L04, L05, L06, L07, L08, L10) |
  | L05 | `lib/_case.js` | schema: extra keys in commitments accepted | survived; caught by the gap test (L04, L05, L06, L07, L08, L10) |
  | L06 | `lib/_case.js` | schema: a role missing from commitments | survived; caught by the gap test (L04, L05, L06, L07, L08, L10) |
  | L07 | `lib/_case.js` | schema: entries not checked | survived; caught by the gap test (L04, L05, L06, L07, L08, L10) |
  | L08 | `lib/_case.js` | schema: the projection's sha256 and claim not checked | survived; caught by the gap test (L04, L05, L06, L07, L08, L10) |
  | L09 | `lib/_case.js` | schema: the withdrawer's entry may be null | caught (2 failing) |
  | L10 | `lib/_case.js` | schema: one commitment in both roles | survived; caught by the gap test (L04, L05, L06, L07, L08, L10) |
  | L11 | `lib/_case.js` | a withdrawn record read as single party | survived; caught by the gap test (L11) |
  | L12 | `lib/_case_http.js` | rule 2: the receipt reads the other role's entry | caught (18 failing) |
  | L13 | `lib/_case_http.js` | rule 2: no entry is not not-a-party | caught (4 failing) |
  | L14 | `lib/_case_http.js` | rule 2: the retry proves against nothing | caught (10 failing) |
  | L15 | `lib/_case_http.js` | rule 2: the retry proves nothing beyond the salt | caught (2 failing) |
  | L16 | `lib/_case_seal.js` | the note's sentence | caught (2 failing) |
  | L17 | README | the README's paragraph | survived; caught by the gap test (L17) |

- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1427 tests, 1420 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1421 pass, 1 skipped. The counts include R-RVf.
- **UNSURE.**
  - The page's "written, never confirmed" line (the brief's rule 2 and test 4) is not printed, for the reasons above; the note states the rule instead.
  - The README's "The sealer's window" section is kept (above).
  - `key_fp` is not added (above).
  - A withdrawn record whose two entries name one key can only be planted, since registration refuses a second role under the first role's key (`same_key_both_roles`). Such a record reads WITHDRAWN.
  - `case_rn`'s R07 gap test still plants a WITHDRAWN record with no `commitments`, which no longer validates. The run never reads it, since its marker is present, and the test passes; it was left as it is.

## 2026-10-14: Unit R-RVf: the architect's rulings on R-RV's second read (branch `case-protocol-2026-10-10`, NOT deployed)

R-RV's second reader found two blockers and two majors; the architect ruled on each, and this unit builds them. The seal itself is unchanged: one compare-and-swap on the sha read, no 201 for a seal the root does not hold, no double seal.

- **B1, option (a).** `revealed_at` is this service's clock when the joint reveal arrived, read before any port call (`lib/_case_http.js`: the seal's `revealedAt` is the arrival read). `signed_under.retrieved_at` and a cross-reference's `recorded_at`, which the seal takes from the same value, are that time too. `compared_at` is the clock after the port returns, as R-RV built it. The deadline is judged on the arrival time and on nothing else: a reveal that arrived before the deadline seals even when its comparison and its compare-and-swap land after it. The receipt check (`lib/_case_seal.js` `receiptBinding`) binds `revealed_at <= compared_at`, not equality, at the seal and on a stored case: a `compared_at` earlier than `revealed_at`, or not a UTC-seconds string, is `receipt_time_mismatch`. The page's "revealed at" and the comment at THE SEALED OBJECT ("revealed_at is this service's clock when the request arrived") mean that time again (M3). The EXPIRED sentence is unchanged. A re-send is a new arrival, judged on its own time. Decided here: the pin's `pinned_at` stays the clock after the port (the pin is written after the seal).
- **B2.** A stamp path whose history is longer than this service reads (10 pages of 100) is 409 `commits_beyond_bound`, no longer 503 `stamp_history_unreadable`: "the stamp's commit history is longer than this service reads (1000 commits), so the oldest commit that touched it is not known. Draw a new salt, compute a new commitment, stamp it with size 272 and register that hash. Nothing was registered." The body is `{ok: false, error_code, error, commitment_sha256}`: the `reason` field it carried is now the code. Nothing is written. A new salt gives a new commitment and a new stamp, which can register.
- **M1.** After the walk, the stamp is read at the oldest commit that touched it (`lib/_store.js` `getRawFileAt`, the contents API at that commit, bound for the stamps repository in `lib/_stamp_store.js` with `getRawFile`), and its bytes must equal the current file's bytes. The record, and with it `stamped_at` and the size, is then taken from those bytes. Bytes that differ, or no file at that commit, are 409 `stamp_rewritten`: "the stamp for this hash is not the bytes the oldest commit that touched it wrote, so it was changed after it was written and is not taken as this commitment's stamp." followed by the same "Draw a new salt" sentences. Nothing is recorded, no state is added, and the case root is unchanged. A read at the oldest commit that fails is the existing 503 `stamp_store_unreachable`. The current read is now of the raw bytes; a stamp file that is not JSON is still the 503 `stamp_store_unreachable` it was. A registration makes one more request: the stamp at its oldest commit. `test/helpers/mock_store.js` serves a contents read at a commit.
- **M2.** The registrations panel's first sentence is now exactly: "Before registration the commitment's stamp must already be in the stamps repository; this service records the oldest commit that touched it for metering, and this page does not treat that commit or its date as evidence of when the commitment was made." (`lib/_case_page.js` `STAMP_SENTENCE`). It no longer says "stamped first as a public, dated commit". The "stamp commit X (stamped T)" line stays.
- **R-RV's entry** keeps its ruling (b) and ruling (c) lines and its deadline UNSURE as the record of what was built then, each marked superseded by this unit.
- Line counts: `lib/_case_http.js` 2332 to 2367, `lib/_case_seal.js` 2323 to 2326, `lib/_case_page.js` 704 to 710, `lib/_store.js` 925 to 942, `lib/_stamp_store.js` 171 to 183. Nothing was removed but the replaced lines.
- **Tests.**
  - New, `test/case_rrvf.test.js` (14). The brief's tests:
    - B1, five: a reveal arriving half a second before the deadline whose comparison lands after it answers 201 and seals; the binding accepts an earlier or equal `revealed_at` and refuses a later one, on a stored case and at the seal; the page's "revealed at" is the arrival time; the EXPIRED sentence prints only when no reveal arrived in time; a re-send after the deadline is judged on its own arrival.
    - B2, one.
    - M1, four: equal bytes read at the oldest commit; differing bytes, and the same record in other bytes; a listing cut at a page boundary; exactly ten full pages.
    - M2, one.

    Three of them pass on the code before this unit, so they are guards: the EXPIRED sentence, the re-send, and the page-boundary listing. The other three tests are gap tests (below).
  - Rewritten:
    - `case_rrv`: ruling (c)'s test (revealed_at is the arrival time); the deadline edge at its line 499 (now 201, sealed); V19's title; V28 (409 `commits_beyond_bound`).
    - The planted `compared_at` in `case_item2b`, `case_item2d` and `case_reveal` (two each) is now one second before the reveal, not after it, since a later one now binds.
    - `case_rl4c` R-L4d d3 asserts the ruled sentence.
- **The must-fail pass.** 26 defects were planted, each alone with the whole suite run: `lib/_case_http.js` 15, `lib/_case_seal.js` 5, `lib/_case_page.js` 4, `lib/_store.js` 2. One of them, the page's "revealed at" printing `compared_at`, is on a line this unit did not change, planted for the B1 page test. 20 were caught. Of the 6 that survived, 5 are each caught by a gap test in `test/case_rrvf.test.js`, and 1 is equivalent:
  - W05: the binding without the UTC-seconds check, where a `compared_at` that does not parse passed;
  - W06: the binding without the type check, where an array holding a time string passed;
  - W15: no null check on the read at the oldest commit, where a 404 there threw;
  - W25: `getRawFileAt` throwing on a 404 rather than answering null;
  - W20: a failed read at the oldest commit answered as `stamp_rewritten`;
  - W19 (equivalent): the record taken from the current read rather than from the bytes at the oldest commit. The two are equal by then.
- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1424 tests, 1417 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1418 pass, 1 skipped. The counts include R-L5's first commit, which precedes this unit on the branch.
- **UNSURE.**
  - A `compared_at` earlier than `revealed_at` keeps the reason `receipt_time_mismatch`; no new reason was added.
  - The two 409s carry `commitment_sha256`, as `stamp_size_mismatch` does.
  - "The case is not opened" (ruling M1) is read as: the case root is unchanged and no registration file is written. Registration does not open a case, and a refused stamp leaves the case as it was.
  - `signed_under.retrieved_at` and the seal's cross-reference `recorded_at` follow `revealed_at` to the arrival time; the pin's `pinned_at` stays the clock after the port. The ruling names only `revealed_at` and `compared_at`.
  - No file at the oldest commit is read as a rewritten stamp (409), not as a read that failed.
  - Nothing bounds how much later than `revealed_at` a `compared_at` may be.

## 2026-10-14: Unit R-REVf: the architect's rulings on R-REV's two majors, and the minors (branch `case-protocol-2026-10-10`, NOT deployed)

- **One sentence for either key (ruling 1, option c).** Under SIGNED BY A REVOKED KEY the page prints exactly: "One of the keys this case is signed with (KEY_ID) is listed as revoked in the key document this service carries (commit V), so this page does not show its verdict, whenever it was signed." KEY_ID is the revoked key; when both are revoked it is the case key (`signed_by`), printed once. No role word is printed. The verdict is withheld when only the reconcile key is revoked: the receipt carries the verdict.
- **The reference's refusal uses the same words.** 409 `signer_revoked`: "One of the keys this case is signed with (KEY_ID) is listed as revoked in the key document this service carries (commit V), so this case takes no reference row, whenever it was signed; no row was written." Decided here: the clause after "so" says what the reference does instead of what the page does, and V is the full commit (a JSON body carries no link), or "not known to this deployment".
- **KEY_DATES_NOTE (ruling 2)** reads exactly: "A key is judged by its status in the named document and in the key document this service carries; it counts as active only when both list it active."
- **V (ruling 3).** "(commit not known to this deployment)" stands in place of "(commit V)" when the deployment does not know its commit: the page read the carried document, and the missing commit does not change what it lists. On the page V is shown as its first 12 characters, linked to the key document at the full commit; that is kept.
- **One reason code.** `case_key_revoked` and `reconcile_key_revoked` are one code, `key_revoked`, for either key. `sealedRecordReason` answers `{code: "signer_revoked", reason: "key_revoked", key_id}`, and the reference's body carries `reason: "key_revoked"` and `key_id`, with no role word. R-REV's entry is corrected where it named the two reasons.
- **The minors.** `tools/preview_dry_run.js` says of a revoked key "one of the keys it is signed with (KEY_ID) is listed as revoked in the key document this checkout carries, so it is not shown as holding, whenever it was signed"; it said the record does not hold "under the key document it names". The comments that still described the removed marker machinery (in `fetchNamedDocument`'s note and in `test/helpers/mock_store.js`) are gone. The reference's old sentence for a revoked key (`UNSEALED_WORDS.signer_revoked`) is removed with its one use.
- **Tests.** New, `test/case_rrevf.test.js` (8): the page sentence exactly for only the case key, only the reconcile key, and both (the case key's id, printed once), each with the verdict withheld, the full commit in the link, no role word, and the commit-not-known form; KEY_DATES_NOTE exactly; the sealed check's `key_revoked` with `key_id` for either key; the reference's 409 (`key_revoked`, `key_id`, the words, no role word, no row); the preview tool's words; no comment describing the marker machinery and no role-named reason anywhere in `lib/`, `tools/` or the mock. `test/response_bodies.test.js` now fails if `case_key_revoked` or `reconcile_key_revoked` appears in any response body the case suites drive, and checks that the reference's `signer_revoked` bodies say `key_revoked`. Updated: `case_rrev`, `case_trust_root`, `case_rj` and `case_rl` (the new reason, sentence and note).
- **The must-fail pass.** 13 defects were planted over the lines R-REVf changed (`lib/_case_seal.js` 2, `lib/_case_page.js` 4, `lib/_case_http.js` 5, `tools/preview_dry_run.js` 2), each alone with the whole suite run. 12 were caught. F12 (the reference reading V from the bundled document rather than the one passed) is equivalent: the document passed has already read in the sealed check, and V is the deployment's commit either way.
- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1404 tests, 1397 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1398 pass, 1 skipped.
- **UNSURE.** None. Its one item, the reference's sentence after "so" ("this case takes no reference row"), was ruled as built by unit R-RVf3 (it claims less than the ruling's words and says nothing false) and is removed.

## 2026-10-14: Unit R-RV: the reveal is one compare-and-swap; no stamp re-check; no legacy stamp form (branch `case-protocol-2026-10-10`, NOT deployed)

- **The one write (rule 1).** The joint reveal writes the case root once: the VERDICT seal, by compare-and-swap on the blob sha of the COMMITTED root it read at the start. Nothing is written before it. A successful reveal, counted by a request spy, makes these requests in order:
  1. GET the case root `cases/<case_id>.json` (its blob sha is the swap's);
  2. GET role a's registration file, then role b's (the root's projection, each checked against the sha256 it carries);
  3. GET compare `main...<commit>` in this repository (the deployment's commit on the published branch; kept for the instance once on);
  4. GET the key document at that commit from the raw host (kept once its sha256 matches);
  5. PUT the case root (the seal), over the blob sha read in 1;
  6. then the pin, a separate file: GET and create `pins/case/<case_id>/00000001.json`.
  No stamp is read. A reveal that fails reads the same and writes nothing.
- **Failures write nothing (rule 2).** Each keeps its code and status, and the case stays exactly as it was read: the comparison raising is 500 `comparison_failed`, a receipt that fails its own check (or cannot be held in a record) 500 `receipt_check_failed`, a verdict a JSON record cannot hold 422 `verdict_not_sealable`, a sealed case the schema refuses 500 `seal_build_failed`. Decided here: the body's `error_code` is that code (three of them answered `internal_error` before, with the code only in the trace). The server log line is `[case] reveal: case <case_id>, <code>`: no tape, hash or salt. The body keeps a receipt check's `reason`.
- **A lost compare-and-swap (rule 3)** reads the root once more: VERDICT is 409 `not_committed`; WITHDRAWN is 409 `case_withdrawn`, "The case was withdrawn before this reveal could seal it. Nothing was recorded, and this response carries no verdict.", with no verdict, receipt or tape digest in the body; anything else, a root still COMMITTED or a read that fails, is 503 `case_seal_failed` with rule 4's text (the architect's ruling a: `case_moved` is cut, no new code).
- **A seal write that throws (rule 4)** is 503 `case_seal_failed`: "The case may not have been sealed. Nothing was pinned. Send the same reveal again: it seals the case, or answers that it is already sealed." Ruling (d): the text never says "anchored"; it says nothing was pinned. Decided here: rule 4's two sentences are printed as the brief wrote them, with the ruling's "Nothing was pinned." between them. R-PIN's change log line that said no answer said "anchored" is corrected: the reveal's 503 still did until this unit.
- **No `reveal_attempted` (rule 5).** A withdrawal of a COMMITTED case is never refused because a reveal was tried; a failed reveal leaves a clean COMMITTED case its parties can send again or withdraw.
- **No stamp at the reveal (rule 6).** The seal's `stamp_commit` and `stamped_at` are the projected registration's. `stamp_commit` is required: a null, the item-one form, is `malformed_field` in a registration record and in a commitment entry. The page's "no stamp commit recorded" branch, unreachable now, is removed.
- **Ruling (b), at registration.** A stamp path touched by more than one commit is no longer refused `stamp_history_ambiguous`: the registration records the oldest commit that touched it. Every page of the path's history is walked (`stampHistory`, following the Link header's next page, and past a full page with none named), at most 10 pages of 100; a longer history leaves the oldest unknown, 503 `stamp_history_unreadable` (`commits_beyond_bound`). `lib/_store.js` and `lib/_stamp_store.js` gain `listCommitsPage` for the stamps repository. (Superseded in part by unit R-RVf: a history past the bound is 409 `commits_beyond_bound`, ruling B2, and the stamp is held to the bytes its oldest commit wrote, ruling M1.)
- **Ruling (c).** `compared_at` is this service's clock read after the port returns (`lib/_reconcile_http.js` `compare` reads `opts.clock()` after the port). The reveal takes that one read for every time the seal and its pin record: `revealed_at`, `compared_at`, `signed_under.retrieved_at`, a cross-reference's `recorded_at`, the pin's `pinned_at`. The deadline is judged, and a refusal receipt dated, by the clock when the request arrived. The receipt's signed sentence (`claim`) is unchanged. (Superseded by unit R-RVf, ruling B1: `revealed_at`, `signed_under.retrieved_at` and a cross-reference's `recorded_at` are the arrival time again; only `compared_at` and the pin's `pinned_at` are the read after the port.)
- **The page.** The COMMITTED page no longer says that a reveal sent again seals the case. Its sentence claims less: "Both roles are registered. A case is sealed only by one request carrying both reveals and both tapes, received before the deadline."
- **The README** says the reveal writes the root once and a failed reveal writes nothing, and no longer counts a reveal attempt among what a withdrawal can lose to. The change log's Fix E entry and its E1 line are kept as the record of what was built then, each marked superseded by this unit, rather than deleted.
- **Removed**, with line counts (comment blocks included):
  - `lib/_case.js` (1564 lines to 1415): the two-phase comment and the constants `REVEAL_ATTEMPT_FIELDS`, `REVEAL_FAILURE_FIELDS`, `REVEAL_EVENTS`, `REVEAL_FAILURE_REASONS` (22), `reveal_attempts` from `OPTIONAL_TOP_LEVEL_FIELDS`, `checkRevealAttempts` and `revealInputSha256` (57), the case log: `CASE_EVENT_KIND`, `CASE_EVENT_FIELDS`, `CASE_EVENTS`, `GIT_COMMIT` (its one user) and `validateCaseEvent` (54), `caseLogDir` and `caseLogPath` (9), the `stamp_commit: null` allowance, and their exports.
  - `lib/_case_http.js` (2417 to 2344): step 2a with `commitment_history_missing` and step 2b, the stamp re-read at the reveal (25), the attempt write with `reveal_attempt_unwritten` and the failure recorder (48), `recordRevealFailure` (14), `movedRefusal` (15; `sealLostRefusal` takes the lost swap), the `reveal_attempted` refusal in the withdrawal (11) and its rebuild clause, `readStamp`'s reveal-only branch, and `stamp_history_ambiguous`.
  - `lib/_case_seal.js`: `reveal_incomplete` in `anchorCase` and in the sealer's report.
  - `lib/_case_page.js` (719 to 697): `revealAttemptHtml` (20) and the null stamp-commit branch.
  - Tests: 20 tests (413 lines) of the removed machinery: `case_consent` 11, `case_rn` 5, `case_item2b`, `case_mutation_gaps`, `case_rn3` and `case_rn4` one each; with them the dead helpers they used. No state-table row was a reveal-attempt row.
- **The minors from the small-three read** (their own commit, "minors from the small-three read"): the debug print in `test/case_rl4c.test.js` is deleted; the status page says pin files counts the case files whose pin file the tree lists "and no withdrawal marker", as the code does; the case row's counts are named for what is counted, `pin_files` and `withdrawal_markers` (in `caseAnchorSummary` and `/status.json`'s `case_anchors`, which said `pinned` and `withdrawn`); R-PINf's entry gives both environments' counts; the README says `case_commit` is, for the reveal, the commit its write of the sealed case file answered with, and for the sealer's run the commit it read back.
- **Tests.**
  - New, `test/case_rrv.test.js` (24): the brief's ten (test 4, the same reveal re-sent after a transient failure seals, passes before this unit too: a guard); rule 3 with ruling (a); rule 2's log line; ruling (b) twice (three commits, and a history past its first page); ruling (c), and its deadline edge (below); the sealer's `not_sealed` with no reason; and seven gap tests (below).
  - Rewritten: `case_consent` (E11 and E12 now answer the codes and write nothing; E05 is the seal's own write), `case_item2b` FIX 1, `case_protocol` (ITEM 2A is ruling (b)), `case_reveal` (the receipt check's code, the one PUT, the key set, the swapped reveals), `case_rl2` L4, `case_rn2` m4 (rule 3's words), `case_rn3` H11-H15 and `case_rn4`'s sweep (no reveal-attempt arms).
  - `test/case_redteam.test.js`: GPT-5.6 §1.3 ("the system has run the comparison but leaves only a normal COMMITTED case") is todo again, DECIDED (unit R-RV): a failed root write leaves the case as it was read, on purpose. `case_rn` T1 counts five todos.
- **The must-fail pass.** 34 defects were planted over the lines R-RV changed (`lib/_case_http.js` 26, `lib/_case.js` 2, `lib/_case_seal.js` 1, `lib/_case_page.js` 1, `lib/_reconcile_http.js` 2, `lib/_store.js` 1, the README 1), each alone with the whole suite run. 27 were caught. The 7 that survived are each caught by a gap test in `test/case_rrv.test.js`:
  - V09: a receipt that cannot be held for a reason other than an integer past 2^53 - 1 answering `internal_error`;
  - V12: a seal write that throws a conflict read as a failed write rather than a lost swap (the gap test lands a withdrawal first: 409 `case_withdrawn`, not 503);
  - V19: the pin dated by the arrival clock rather than the read after the port;
  - V25: ruling (b)'s walk stopping at a full page whose answer names no next page;
  - V26: the walk asking for the page after the last rather than the one the Link header names;
  - V28: a stamp history past the bound not refused (the walk's null then throws);
  - V37: the README's sentence on the one write.
- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1396 tests, 1389 pass, 2 skipped, 0 fail, 5 todo, three runs. Where one of them runs (the reader's environment): 1390 pass, 1 skipped. The counts include the minors' commit.
- **UNSURE.**
  - Ruling (c) and the deadline: the seal's times are the read after the port returns, the deadline is judged at arrival, and the schema requires `revealed_at` before the deadline. A reveal received less than a second before the deadline whose comparison ends at or after it builds a seal the schema refuses: 500 `seal_build_failed`, nothing written, and by then the case reads EXPIRED. A test pins this. The alternatives (date the seal at arrival, against the ruling; or a new refusal) were not taken. (Superseded by unit R-RVf, ruling B1, option a: the seal is dated at arrival, and this reveal seals.)
  - Rule 2's codes: the brief names `comparison_failed`, `receipt_check_failed` and `seal_build_failed` as the existing codes; they were the trace's failure reasons, and the response said `internal_error`. The response now carries the named code.
  - The withdrawal answers 201 when it writes (the brief's test 2 says 200); 200 is its answer to a retry. The tests assert 201.
  - The stamp history walk is bounded at 10 pages (1,000 commits); past it the registration is refused rather than read in part.
  - "Nothing was pinned." speaks of this request; a sealer run may pin a seal whose write did land.

## 2026-10-14: Unit R-REV: no revocation by commit order; a key is active or revoked (branch `case-protocol-2026-10-10`, NOT deployed)

- **The reversal, confirmed (the architect's ruling, option b).** The marker walk and the "signed before revoked" holding are removed. A seal whose signature verifies under the document it names is read against the CURRENT document, the one this service carries (`PUBLISHED_KEYS`): each key that signed it listed active in its role is `valid_under_document`; listed revoked is `signer_revoked`, whenever it signed; absent is `signer_unlisted`. No order, pin or marker is read. `signer_since_revoked` and `pin_unavailable` no longer exist. When both keys are listed revoked, the case key is named (it is checked first).
- **What each state shows (the seal read-states).**
  - `valid_under_document`: 200, the verdict, as before.
  - `signer_revoked` (`{code, reason, key_id}`, the reason `case_key_revoked` or `reconcile_key_revoked`; corrected by unit R-REVf: one reason, `key_revoked`, for either key, with `key_id`): 200, SIGNED BY A REVOKED KEY, with exactly one sentence under the heading: "The key that signed this case (KEY_ID) is listed as revoked in the key document this service carries (commit V), so this page does not show its verdict, whenever it was signed." V is the commit `sealingDocument` reports, linked to the document at that commit; a deployment whose commit is not set or not 40 hex prints "not known to this deployment" in its place. KEY_ID is the revoked key. The sealer does not pin it: `anchorCase` answers `{ok: false, code: "not_sealed", status, reason: "signer_revoked"}`. The reference refuses it 409 `signer_revoked`: "the case reads VERDICT, and a key that signed it is listed as revoked in the key document this service carries, whenever it signed (<reason>), so it is not treated as a sealed case; no row was written".
  - `signer_unlisted`, `case_signature_invalid`, `receipt_unsigned`, `verdict_unbound`, `document_unrecorded`: 200, SEALED RECORD DOES NOT VERIFY, as before. Its notice now states the current document's one rule ("Each key that signed it must also be listed in its role in the current key document; a key that is not makes the record signer_unlisted."); the revocation sentence and the `signer_revoked` row of the check names are gone.
  - `document_unavailable`: 503 COULD NOT LOOK, as before. For a current document that does not read, the row naming it now says "the current key document this deployment carries, which lists each key in its role as active or revoked". It said "which says whether a key was since revoked or is still listed", an order this unit removes.
  - `single_party`: the single-party page, as before (it is read before the sealed check).
- **Statuses.** A key document entry's status is exactly `active` or `revoked`. `checkKeyDocument` refuses any other status (`malformed_field` at `keys[i].status`), refuses `revoked_since` (`unknown_field`), and holds `status_meaning` to exactly the two statuses. `since` stays. A rotated-out key stays listed active with a note that it no longer signs (rule 5). The case key's entry in the document a case names, when not active, is `case_signature_invalid` `signer_revoked` (it was `signer_not_active` for a retired one). The receipt check's `signer_not_active` reason is unchanged.
- **The key document** (`public/.well-known/arcaeon/case-signing-keys.json`, `updated` 2026-10-14). `description` and `matching` are unchanged.
  - `status_meaning.active`: "currently used for signing in its role; trusted" → "Listed for its role. A record this key signed verifies under a document that lists it active."
  - `status_meaning.retired`: removed.
  - `status_meaning.revoked`: the marker paragraph → "Its private half is believed exposed. A record this key signed is not shown as holding, whenever it was signed: this document does not order a signature against a revocation."
  - `rotation`: the move to retired, `revoked_since`, the marker and its tool, the revoking commit and the legacy-pin sentence are removed. It now reads: "Rotation adds a new key with status active. The previous key stays listed active with a note that it no longer signs, so the records it signed keep verifying. A key is marked revoked only if its private half is believed exposed. Dates in this document are information and are not enforced. A reader holds a record to the document it names, at a commit on this repository's published branch, and each key that signed it must also be listed here, in its role, when the record is read. The service signs only with a key listed here as active in its role, and before it seals it confirms that this document is the one at the commit it names."
- **Removed**, by name, with line counts (comment blocks included):
  - `lib/_case_seal.js` (2631 lines to 2346): `revocationOrder` (32), `notPinnedReason` (12), `pinnedBefore` and its cache `pinOrder` (22), `keyFingerprint`, `revocationMarkerPath`, `revocationMarkerFor`, `validateRevocationMarker` and the marker constants `REVOCATION_MARKER_KIND`, `REVOCATION_MARKER_FIELDS`, `REVOCATIONS_DIR` (33), `checkRevocationMarker` (23), `revocationMarkerOf` with `MARKER_CANDIDATES_READ` and the `markers` cache (84), `markersWithoutRevocation` with `REVOCATION_MARKER_RE` (28); the `signer_since_revoked` and `pin_unavailable` branches of `sealedRecordReason`; `retired` in `CASE_KEY_STATUSES`; `revoked_since` in the optional entry fields, its checks and `ISO_DATE`; the sealer's `marker_without_revocation` and `markers_unread` report; their exports and cache clearing.
  - `lib/_case_page.js` (750 to 719): `revokedSinceBanner` (17), `pinCouldNotLookPage` (21), the `signer_since_revoked` path in `renderCase` and the verdict panels, the `signer_revoked` row of `UNVERIFIED_CHECKS` and the notice's revocation sentence.
  - `lib/_case_http.js`: the reference's `pin_unavailable` branch (the file's length is unchanged: the `signer_revoked` branch takes its place).
  - `tools/record_key_revocation.js` (158 lines), and `tools/preview_dry_run.js`'s `pin_unavailable` branch (4).
  - The README's marker paragraphs (the 5,000-commit bound, "A key once shown revoked by a valid marker stays revoked", the tool's mentions); a new section, "A revoked key", says what the code does and ends: "Revocation marker files (`revocations/<fingerprint>.json`) already in a repository are left in place and ignored: no code reads or writes them." Nothing in a pins repository is deleted.
  - Tests: 47 tests (850 lines) that tested the removed machinery: `case_trust_root` 32, `case_rn` 5, `case_rj3` 4 (F4 and its three gap tests), `case_rl` 3, `case_signed_under` 2, `case_rn2` 1. None of the state table's rows was a revocation row, so the table is unchanged. The dead revoke helpers in `case_rn`, `case_rn2`, `case_rn3`, `case_rn4`, `case_trust_root` and `case_signed_under` are removed.
- **Not touched, as ruled:** `signatureReason`, `namedDocumentOf`, `fetchNamedDocument` (two of its comment lines still name the marker reads it once served; left, see UNSURE), `commitOnBranch`, `signed_under`'s fields, the key document's `description`, `pinState` (only its callers were removed), and the reveal.
- **Tests.**
  - New, `test/case_rrev.test.js` (16): the brief's seven; the sealer's `not_sealed`; the reconcile key revoked (and no `lib/` file names `signer_since_revoked` or `pin_unavailable`); the key document's prose and the README sentence; the current-document row on the could-not-look page; KEY_DATES_NOTE; and four gap tests (below). Test 3 (a planted marker changes nothing) and the KEY_DATES_NOTE test pass on the code before this unit too: they are guards.
  - Rewritten to the two statuses and the one rule: `case_trust_root` (10), `case_signed_under` (6), `case_item2c` (2), `case_rn` and `case_rn2` (a retired reconcile key is now a revoked one; `case_rn2`'s full-page walk now walks a pin file's history, the walk that remains), `case_commits` (EVERY COMMIT IS A LINK: V is the carried document's commit), `case_rj`, `case_consent`, `mint_case_key`, `preview_dry_run`.
  - `test/case_redteam.test.js`: GPT-5.6 §1.4 / §3.3 / §6.4 ("A later edit changing a key ... to revoked makes old sealed cases fail") is todo again, DECIDED (unit R-REV). Its assertion that such a case still verifies fails; the page it shows is SIGNED BY A REVOKED KEY, not SEALED RECORD DOES NOT VERIFY. `case_rn` T1 counts four todos.
- **The must-fail pass.** 37 defects were planted over the lines R-REV changed (`lib/_case_seal.js` 17, `lib/_case_page.js` 11, `lib/_case_http.js` 5, the key document 3, the README 1), each alone with the whole suite run. 28 were caught. The 9 that survived:
  - R06 (both keys revoked, the reconcile key named first): caught by a gap test; the case key is named.
  - R10 (no `role` in the `signer_revoked` answer): nothing read the field, and the reason already named the role, so the field is removed rather than tested. The answer is `{code, reason, key_id}`. (Corrected by unit R-REVf: the reason no longer names a role; it is `key_revoked` for either key, and `key_id` says which key.)
  - R15, R16, R17 (`status_meaning` taking a third status, one status, or something that is not an object, where `null` threw): caught by a gap test; each is `malformed_field` at `status_meaning`, never a throw.
  - P06 (the page naming the case key when the reconcile key is the revoked one) and P11 (the page's `<title>` saying VERDICT): caught by gap tests.
  - R07 (`=== "revoked"` read as `!== "active"`) and P09 (V read from the bundled document rather than the one passed): equivalent. A key document holds only the two statuses, and the document passed is one the sealed check has already read, whose commit is the deployment's either way.
- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1391 tests, 1385 pass, 2 skipped, 0 fail, 4 todo, three runs. Where one of them runs (the reader's environment): 1386 pass, 1 skipped.
- **UNSURE.**
  - V when the deployment does not know its commit: the sentence prints "not known to this deployment" in place of the link. The ruling names V as the commit `sealingDocument` reports and does not say what to print when it reports none.
  - Both keys revoked: the case key is named.
  - `fetchNamedDocument`'s comment still mentions the marker's check and the marker tool's walk as reads it keeps by commit. The function was not to be touched; the comment is stale.
  - `tools/preview_dry_run.js` says of `signer_revoked` and `signer_unlisted` (current-document answers) "its sealed record does not hold under the key document it names"; that wording is older than this unit and was left.
  - The receipt check keeps the reason `signer_not_active` for a reconcile key the named document lists revoked, where the case key's check now says `signer_revoked`.
  - `sealedPanels` keeps its `answer` parameter, now unused.

## 2026-10-14: Unit R-PINf: two follow-ups from R-PIN's reader (branch `case-protocol-2026-10-10`, NOT deployed)

- **f1: an empty re-read after a create conflict is not a conflict.** `pinChain` answered `conflict` when the store refused the pin's create with a conflict and the read after it found no file. A store that answers 409 on every attempt gives up with a conflict although no pin was created, and the reveal then answered 201 with `pin: "conflict"` and no pin file. That branch now answers `commit_unrecorded` (`store_conflict`); a retry may pin. R-PIN's entry is corrected: its reason for leaving S12 was wrong. The new test forces a 409 on every attempt the store makes (`PUT_RETRY.maxAttempts`, 4): with three, as the reader put it, the fourth attempt lands and the pin is written.
- **f2, the minors.**
  - The fixed timestamp sentence is printed directly under the pin line, in the pin's own cell, after a line break. It was printed after the whole table. Still printed once.
  - A pin that `pinChain` finds already written is held as the page holds it. It is read at the commit that wrote it, and the case file is read at the `case_commit` it names (`pinState`). Only then is it `pinned`, naming the commit that wrote it (it named none). Otherwise the answer is the state read: `pin_commit_mismatch` with the commit, `conflict`, `could_not_look`, or `commit_unrecorded` (`pin_not_found`) when the file is gone on the second read. The sealer's report and the reveal's answer carry that state.
  - The stale comment in `revocationOrder` (a legacy pin as `case_not_pinned`, the next pin) is removed. The function is otherwise untouched: unit R-REV removes it.
  - Claiming less:
    - The status page's case columns are now "pin files" and "withdrawal markers", and its sentences say they count the paths the tree lists: "pin files counts the case files whose pin file, `pins/case/<case_id>/00000001.json`, the tree lists; whether a pin holds its case, only the case's own page reads." It no longer says "is pinned by its own pin" or "Pinned means". The JSON keys are unchanged.
    - `ANCHOR_NOTE`, in the reveal's answer and on the status page, now reads "A sealed case's pin, when it has one, is pins/case/<case_id>/00000001.json, written once by this service. It is its own record, not a log-tree leaf: ...". It no longer says "A case is pinned by ...", which read as true of every case.
    - The README says a sealed case has at most one pin (not exactly one), that `case_commit` is the commit its writer read back and that a reader holds the case file at it, and that this service writes nothing else under a case's pin namespace (not that nothing else is ever written there).
  - The test counts. R-PIN's entry gave this environment's counts, where both environment-dependent tests skip (R-L4d (a)); the reader's three runs, 1404 pass with 1 skipped, ran one of them. R-PIN's counts line now gives both.
- **Tests.** In `test/case_rpin.test.js`: f1 (the reveal, and `pinChain` itself); the sentence in the pin's cell, once; a found pin held as the page holds it (`pin_commit_mismatch` with its commit, and `pinned` with the commit that wrote it); the status page's and the README's words; and one gap test. Updated: the state table's cell reader (`case_rj3`: the sentence is read from the pin cell), the status tests in `case_commits` (S01, S02) and `case_item2b`, and the note's words in `case_item2b`.
- **The must-fail pass.** 12 defects were planted over the lines R-PINf changed in `lib/_case_seal.js`, `lib/_case_page.js` and `api/status.js`, each alone with the whole suite run. 10 were caught. F06 (a found pin's mismatch naming no commit) is caught by an assertion added to the found-pin test. F05 (a pin gone on the second read answering `not_pinned`) is caught by a new gap test whose second read of the pin file answers 404.
- Counts, as `npm test` prints them here (both environment-dependent tests skip, R-L4d (a)): 1422 tests, 1417 pass, 2 skipped, 0 fail, 3 todo, three runs. Where one of them runs (the reader's environment): 1418 pass, 1 skipped.

## 2026-10-14: Unit R-L4e: an inconsistent case record says one sentence, and its 503 carries only the code (branch `case-protocol-2026-10-10`, NOT deployed)

- **The page.** The could-not-look page for `case_record_inconsistent` no longer has the heading "This case's record could not be read as one consistent record", or R-L4b's sentence. Its one sentence is: "The stored record for this case does not agree with itself. Nothing is asserted about this case while that is so." Under it are the code `case_record_inconsistent` and the links to the case file and its history. Decided here: the limits panel is no longer printed on this page, since its lines are prose and the ruling allows one sentence; the code and the two links are not prose and stay.
- **The 503 body.** At every handler (the registration, the reveal, the withdrawal and its retry, the reference) the body is exactly `{"ok": false, "error_code": "case_record_inconsistent"}`: no sentence, no reason code, no role, no case id. `lib/_case_http.js` `refuse` answers a refusal whose message is empty with its code alone; `inconsistentRefusal` is the one place that builds this refusal. The reveal's stamp re-check, which answered the same code with the reason `stamp_differs_from_registration`, uses it too. Unit R-RV removes that check.
- **The reasons.** `registration_file_differs`, `registration_file_missing` and `projection_differs_from_file` go to the operator log, one line naming the case, the role and the reason: `[case] case_record_inconsistent: case <id>, role <r>, <reason>`. The page logs the same line, prefixed `page:`. The sealer's refused record keeps `{case_id, code, role, reason}`.
- **Tests.**
  - New, in `test/case_rl4b.test.js`: for each of the three reasons, the page prints exactly the sentence (its panels' text is the sentence, the code and the two links), has no heading below its title, and logs the reason; the body is exactly the one code at the registration, the reveal and the withdrawal; and the reasons appear in the operator log and in the sealer's refused record.
  - `test/response_bodies.test.js` now fails if any response body any case suite drives for this state carries anything beside the code.
  - `test/case_rj3.test.js` gains the state's three rows (one per reason: 503, the sentence, no registration row, the reason not on the page).
  - Updated: the tests that read the role, the reason or the sentence from this state's body (`case_rl4b`, `case_rl4` including its H03 gap test, now read from the log, `case_rl4c` S04 and S05, now read from `projectedRegistrations`, `case_reveal`, `case_mutation_gaps` H36 and H41, `case_rn`, `case_rn4`, `case_fix_mutation_gaps`).
- **The README** sentence now says the body is the code alone, where the reason goes, and the page's one sentence.
- **The must-fail pass.** 15 defects were planted over the lines R-L4e changed in `lib/_case_http.js` and `lib/_case_page.js`, each alone with the whole suite run. 12 were caught. The 3 that survived are caught by log checks added to the page test (E13 and E15: the page's log line missing, or naming no reason) and to H41 (E09: the stamp reason misnamed in the log).
- Counts, as `npm test` prints them: 1417 tests, 1412 pass, 2 skipped, 0 fail, 3 todo, three runs.

## 2026-10-14: Unit R-L4d: three follow-ups from the second reader's pass over R-L4c (branch `case-protocol-2026-10-10`, NOT deployed)

- **d1: the lost compare-and-swap that answers 200.** A new test in `test/case_rl4c.test.js` runs two identical sends that overlap. The first writes the claim file and reaches its compare-and-swap. The second finds that file and reaches its own, held until the first has answered. The first answers 201 (`projected: ["a"]`). The second loses its swap, reads the root once more (one read by the handler, counted), finds the file's own sha256 projected, and answers 200 `existing: true` with nothing projected by it. The answer is 200 only for the send that did not write the file: a send that wrote it answers 201 even when another send projected it (`existing` is "this request did not create the file"). Two defects were planted on that branch, each with the whole suite run: answering 409 `role_already_committed` (D1a) and skipping the re-read (D1b). Both are caught by this test. D1a is also caught by `case_rl4`'s gap test for H23 and H29 (and the response-bodies run), and D1b by ten other tests, so the branch was covered before this test as well.
- **d2: the late refusal.** 409 `late_commitment` for a written file now says "the case's deadline has passed, and the registration file written for this request was not confirmed when this request read the case". It no longer says "was never confirmed; it has no standing". The constant is checked by its tests in `case_rl4` and `case_rl4c`. No state-table row carries this sentence: `test/case_rj3.test.js`'s tables hold the pin states and the page's registration words, and neither contains it.
- **d3: the registrations panel.** "Each role registered one commitment hash" is now "Each role registers one commitment hash" on every page that shows the panel, OPEN and COMMITTED included. It was changed rather than cut: it states the rule (the root projects at most one claim per role), which holds on every page, and its second half explains the stamp links the panel shows.
- **(a) The skipped count.** Neither count is wrong. Two tests skip by environment: `case_item2b`'s check of the case key configured where the suite runs (skipped when `WITNESS_CASE_SIGNER_KEY` is not set) and `reconcile_live_python`'s live differential (skipped without an arcaeon-ledger checkout, `ARCAEON_LEDGER_REPO`). This environment has neither, so the entries say 2 skipped. A run with one of them set skips 1, as the reader's did (1549 tests, 1547 pass, 1 skipped, 1 todo, against 2 skipped and 1546 pass here).
- **(b) The README's list of files updated in place: complete.** Every write into the pins repository from this repository's code was checked: `lib/_store.js` `putFile` and its callers in `lib/`, `api/` and `tools/`. All other direct PUTs (`lib/_pending.js`, `_balance.js`, `_keys.js`, `_meter.js`) go to the private usage repository, and `tools/ceiling_probe.js` refuses the live pins repository. The only writes that replace an existing pins file are the case root (by compare-and-swap, as the README says) and the namespace pin pointers `pins/<namespace>/latest.json` (`api/pin.js`: the pin, the heartbeat and the self-heal). Everything else is created once: the namespace records, observations, batch leaves and roots, deadline-owner bindings, the case files and markers, and the one case pin. The daily anchor files are written by the anchoring job, which is outside this repository; the README names the one in-place change it makes, the `.ots` upgrade. Nothing was added.
- **The must-fail pass.** 6 defects were planted, each alone with the whole suite run: D1a and D1b on d1's branch, two on d2's sentence (the old words; no "when"), two on d3's (the past tense; the sentence cut). All 6 were caught, none survived.
- Counts, as `npm test` prints them: 1411 tests, 1406 pass, 2 skipped, 0 fail, 3 todo.

## 2026-10-13: Unit R-PIN: one pin per case, written once; nothing reads or claims an anchor (branch `case-protocol-2026-10-10`, NOT deployed)

- **The brief, built as written.** A sealed case has exactly one pin, `pins/case/<case_id>/00000001.json`, created once (by the reveal, or by the sealer when the reveal's pin write failed). There is no `latest.json` and no next pin. `case_commit` is required: a pin without it reads `unreadable` (`case_seal_missing_field`). `lib/_case_seal.js` `pinState` replaces `anchorState` and has six answers: `pinned`, `not_pinned`, `pin_commit_mismatch`, `conflict`, `unreadable`, `could_not_look`. The page's pin line is "Pinned at commit P (the pins repository's commit time, T)", and the architect's sentence is printed once under it: "Daily anchor records and their OpenTimestamps proofs are in `anchors/` in the pins repository; this page does not check them, and you can check one yourself by running `ots verify` on the proof file beside the record." No page, answer or status row says "anchored" (corrected by unit R-RV: the reveal's 503 `case_seal_failed` still said "nothing was anchored" until then; it now says nothing was pinned).
- **The reference.** It reads no pin and no anchor. The codes `case_not_pinned` and `anchor_conflict` are gone, and its answer names no row commit (`row_commit`, `row_commit_note`). Reference rows carry `note_version: 4`: "This row has no pin of its own. It is recorded by the pins-repository commit that writes it, and no anchoring is asserted here." Versions 2 and 3 are recorded as never issued (`row_note_v2`, `row_note_v3`).
- **The sealer and the status row.** The sealer's candidates are the case roots with no pin file and no withdrawn marker (`caseTreeIndex(...).candidates`); a pinned root is not read again. `caseAnchorSummary` has no `pending` count, and the status page drops its pending column. The page cache is gone: every page view reads.
- **Preview files.** Files a preview pins repository holds from before this release under a case's pin namespace (`latest.json`, and `0000000N.json` for N above 1) are ignored: one README sentence says so.
- **Left as they were, as ruled:** `sealedRecordReason`; `revocationOrder` (its one call renamed to `pinState`; its reason `case_not_pinned` for a pin that is not pinned stays); `handleCaseReveal`; `reveal_attempts`; the signatures; the reference quota; the `anchors/` and `revocations/` files.
- **Reads, counted by a request spy on a sealed case:**
  - A case page: 10 GETs before (1 when the page cache answered); 9 now, on every view. A page after one reference row: 7, since the files read at a commit are kept for the instance as before.
  - A reference request: 10 GETs before, 7 now.
- **Removed.**
  - `lib/_case_seal.js` (3180 lines to 2614): `anchorState` (52 lines), `dailyAnchorOf` (93), `nextPin` (74), `listedByIndex` (26), `listedReferences` (24), `nextPinRecord` (24), `referenceCommitStates` (23), `strayPin` (13), `movePointer` (10), `listedIndexOf` (6), `dayBefore` (4), `pinAt` (3), and the constants `ANCHORS_DIR`, `ANCHOR_RECORD_RE`, `ANCHOR_TEXT_RE`, `ANCHOR_RECORD_READS`, `CASE_PIN_LATEST_RE` (now `CASE_PIN_RE`) and `PIN_WALK_READS`; `pinPaths(...).latest`; the conflict words for the pointer and the anchored head; the sealer's `sealable`, `commits_recorded` and `rows_unrecorded`.
  - `lib/_case_page.js` (975 to 748): `anchorHtml` (57), `caseCommitHtml` (29), `rowCommitHtml` (23), `anchorRecordWords` (16), `ROW_NOT_READ` (9), `definitePage` (7), `keepPage` (5), `anchorNoteFor` (4), `untilOf` (3), `withReadAt` (3), `ROW_ANCHOR`, `ROW_NOT_DEFINITE`, `PAGE_CACHE_MS`, `PAGE_CACHE_MAX`, `pageCache`, and the `definite`/`until` fields.
  - `lib/_case_http.js`: `pinCouldNotLook` (7) and the pin gate at the reference's step 1c.
  - `lib/_verdict.js`: `listedByOk` (14), `referenceCommitsOk` (13), `CASE_SEAL_OPTIONAL`, `CASE_SEAL_MAX_SEQ`.
  - `lib/_status_json.js`: `pending` and `pending_meaning`.
- **The state table** (`test/case_rj3.test.js`, THE TABLE): 149 rows before (31 of `anchorState`, 3 of its chain and no-lookup forms, 28 of `dailyAnchorOf`, 58 of the row reader, 29 of `servedAtCommit`); 47 now (29 of `pinState` reading the pin, 16 of `servedAtCommit` for the case file at the commit its pin names, 2 of `pinState` given a chain).
- **Tests.**
  - New: `test/case_rpin.test.js`, 10 tests of the brief, each failing at 50a570e, and 7 gap tests below.
  - Deleted, as tests of removed machinery: 61 tests, 973 lines. By file: `case_commits` 18 (347 lines), `case_rj3` 10 (127), `case_rj2` 10 (139), `case_rl` 9 (123), `case_rj` 6 (91), `case_consent` 3 (57), `case_rl2` 2 (26), `case_rn` 2 (27), `case_item2c` 1 (36). And 102 rows of the state table.
  - Updated to the one pin: `case_commits`, `case_consent`, `case_fix_mutation_gaps`, `case_item2b`, `case_item2c`, `case_item2d`, `case_mutation_gaps`, `case_redteam`, `case_reveal`, `case_rj`, `case_rj2`, `case_rj3`, `case_rl`, `case_rl2`, `case_rl4`, `case_rl4b`, `case_rl4c`, `case_rn`, `case_rn2`, `case_rn3`, `case_rn4`, `case_signed_under`, `case_trust_root`, `preview_dry_run`.
  - The red-team file: GPT-5.6 §1.2 (a reference before the case is anchored) and §5 (a row storing its write commit) are todo again, marked DECIDED (unit R-PIN). §3.4's test now holds that nothing says anchored, and that pinned is said only after the pin is read at its commit and the case file at `case_commit`.
- **The must-fail pass.** 65 defects were planted over the lines R-PIN changed in `lib/_case_seal.js`, `lib/_case_page.js`, `lib/_case.js`, `lib/_case_http.js`, `lib/_verdict.js`, `tools/preview_dry_run.js` and `api/status.js` at ad1e5d2, each alone with the whole suite run. 55 were caught and 10 survived. Eight gap tests catch 9 of them: S02, S10, S24, S25, S29, P02, P03, A02 and T04. Left:
  - S12: after a create-only pin write that conflicted, a read that finds no file answered `conflict` (as before this unit). The reason first given here for leaving it, that this read never comes back empty since nothing is deleted, was wrong: a store that answers the create with 409 on every attempt gives up with a conflict although no pin file was created, and the reveal then answered 201 with `pin: "conflict"` and no pin. Unit R-PINf (f1) fixes it: that branch is `commit_unrecorded` (`store_conflict`).
- Counts, as `npm test` prints them:
  - 50a570e: 1553 tests, 1550 pass, 2 skipped, 0 fail, 1 todo.
  - ad1e5d2: 1400 tests, 1395 pass, 2 skipped, 0 fail, 3 todo (1553 − 61 deleted − 102 table rows + 10 new).
  - The gap tests and this entry: 1408 tests, 1403 pass, 2 skipped, 0 fail, 3 todo (bare `node --test`: 1415, 1410). These are this environment's counts, where both environment-dependent tests skip. Where one of them runs, as in the reader's three runs, the same tree gives 1404 pass and 1 skipped (unit R-L4d, (a)).

## 2026-10-13: Unit R-L4b: the DAMAGED state is cut; an inconsistent case record is 503 case_record_inconsistent (branch `case-protocol-2026-10-10`, NOT deployed)

- **The architect's ruling, built as written.** "A projected entry whose file is missing or does not hash to the projected sha256 is answered 503 `case_record_inconsistent` by every handler, and the page shows the could-not-look page with that reason and the sentence: 'A registration file does not match the hash this case records for it; this page shows nothing from this case until it does.' The case cannot seal and is never pinned; nothing is written, nothing is deleted." The substance of R-L4's rule 4 stands (never silently resolved, never sealed, never pinned); only the named state goes, since `case_record_inconsistent` already names the condition. This also closes the second reader's B3, whose words were DAMAGED's.
- **What changed.** `lib/_case_seal.js` `projectedRegistrations` answers `inconsistent` (reasons `registration_file_missing`, `registration_file_differs`, `projection_differs_from_file`). The commit path, the reveal, the withdrawal and its retry, and the reference answer 503 `case_record_inconsistent` with the role and the reason. The sealer reports such a case under `refused`, with its role. The case page is the could-not-look page (503, never kept): `case_record_inconsistent`, the sentence, and the links to the case file and its history, and nothing else from the case.
- **Removed.** `damagedWords` and the sealer's `damaged` list (`lib/_case_seal.js`); `damagedPage` (`lib/_case_page.js`); the code `case_damaged` and the status `DAMAGED` (`lib/_case_http.js`). `test/case_rj3.test.js`'s state table had no DAMAGED rows, so none were removed there.
- **Tests.** New: `test/case_rl4b.test.js`, 4 tests, each failing at ffce92e. Updated by design (DAMAGED's 409 to the 503): `case_rl4` (the rule test, the reasons gap test, H55, the page gap test), `case_fix_mutation_gaps`, `case_mutation_gaps` (H36), `case_reveal`, `case_rn`, `case_rn4`. None deleted.
- **The must-fail pass.** 18 defects planted over every line R-L4b changed in `lib/_case_http.js`, `lib/_case_seal.js` and `lib/_case_page.js` at 1a01395, each alone with the whole suite run: 18 caught, none survived.
- Counts, as `npm test` prints them: 1a01395 and this entry: 1553 tests, 1550 pass, 2 skipped, 0 fail, 1 todo (bare `node --test`: 1560, 1557).

## 2026-10-13: Unit R-L4c: the second reader's fixes to R-L4; a registration file is keyed by its claim (branch `case-protocol-2026-10-10`, NOT deployed)

The second reader's pass over R-L4 at 2b05ee7 found the structural fault ended, four sentences false in reachable states, and one design gap. The architect's ruling on c4 replaced c4 as first sent and trimmed c2; it is built as ruled.

- **c1 (B1): the projection is looked at first.** A registration the case root already projects is answered 200 `existing: true` with the projected values whatever the case's state since, at the commit path's first read and at its confirming read. Only a file the root does not project gets the withdrawn, sealed or expired answer. Two identical sends that overlap while the case is sealed between them are both answered 200. A withdrawn root holds no projection, so a re-send after a withdrawal is still refused; the WITHDRAWN root keeping its projection is unit R-L5 (c5).
- **c2 (B2): the server clock before the compare-and-swap.** The projection is refused 409 `late_commitment` when the server clock read just before its compare-and-swap is past the deadline, never by the clock the request arrived by. The page half of c2 went with the architect's ruling on c4: the page prints no claim file, and the words "cannot acquire it" are printed nowhere (the late refusal now says "...was never confirmed; it has no standing").
- **c3 (B4): the public property, scoped.** The README now says: "No file that belongs to a case is ever deleted. A case's registration files, reference rows, withdrawal record and seal are written once and never changed. The case root is the one case file that is updated, and only by a compare-and-swap that every reader can follow in the repository's history." One sentence after it names the files updated in place outside any case: the daily anchor proofs, and the pin pointers (each namespace's `latest.json`, and a case's `pins/case/<case_id>/latest.json`). The R-L4 entry below quotes the earlier, repository-wide sentence; it no longer stands.
- **c4 (M1), as the architect ruled: THE CLAIM.**
  - A registration file is a claim at `registrations/<case_id>/<role>/<claim>.json`, create-only. The claim is the sha256 of the json-c14n:v1 bytes of the fields a party supplies (case id, role, commitment, verifier, key id, signature): `lib/_case.js` `PARTY_SUPPLIED_FIELDS`, `claimSha256`, and `partySuppliedDiffers` moved there. The root's entry carries `claim_sha256`, so every reader finds the projected file's path from the root alone. `registration_exists` is removed: the same registration sent again is the same claim and finds its own file.
  - A file is written only when the root as read shows the case open, the role unprojected, before the deadline, and able to take it. A role the root projects for another claim is 409 `role_already_committed`, naming `projected_sha256`, and nothing is written.
  - The tie rule is the compare-and-swap on the root: one that loses is never retried (no rebuild); the root, read once more, is the answer: 200 `existing: true` when it projects this file, 409 `role_already_committed` naming the projected sha256 when it projects another, the refusal its state gives, or 503 `registration_unconfirmed` (the file is written; send it again).
  - No cap on claim files per role: the per-IP limiter is the only bound, and a file written under it never stands once the role is decided.
  - Every answer after a file is written names its path, `registration_path`. A file at the claim's path that does not hold the claim (only a plant can be there) is 503 `registration_record_unreadable`, never projected.
  - The page neither reads, lists, counts nor links a claim file the root does not project: such a role reads "no registration is confirmed for this role". The WITHDRAWN and EXPIRED pages show no registration rows; their status word is the terminal state. The presence read is gone.
- **Decided here (small things):** the root's entry names the claim (`claim_sha256`) rather than the path; the claim covers the key id beside the verifier it is derived from; the commit path's re-read of the root under the case lock still checks only for a withdrawal before the write; the WITHDRAWN and EXPIRED pages print no per-role words.
- **Tests.**
  - New: `test/case_rl4c.test.js`, 15 tests of c1 to c4 and 4 gap tests. On 2b05ee7 the 5 tests of c1, c2 and c3 fail; on 94edea5, 9 of the 10 tests of c4 fail. The tenth (a withdrawn, sealed or expired case writes no file) already held.
  - `test/case_rj3.test.js`'s registration-file table keeps its 7 rows, now in three states: projected, not confirmed ("no registration is confirmed for this role"), and no rows (WITHDRAWN and EXPIRED).
  - Deleted: the 2 tests of `registration_exists` in `test/case_rl4.test.js`.
  - Updated by design: `case_rl4` (the overlapping-send assertion c1 replaced, the page words, the planted-file test, the paths), `case_protocol` (the tie rule: a lost compare-and-swap answers 503 and is projected on the re-send, never rebuilt), `case_fix_mutation_gaps` (H05), `case_rn2` (m10, T05), `case_consent`, `case_reveal`, `case_item2b`, `case_rn`, `case_rn3`, `case_rn4`, `case_rj3`, `preview_dry_run`. The test helper `test/helpers/case_registration.js` finds claim files (`recordPath`, `claimPath`, `dirOf`, `filesOf`, `pathOf`).
- **The must-fail pass.** 56 defects were planted over every line R-L4c changed in `lib/_case.js`, `lib/_case_http.js`, `lib/_case_seal.js` and `lib/_case_page.js` at 8f8d319, each alone with the whole suite run: 46 caught, 10 survived. Four gap tests catch 8 of them (K22, K23, H08, H18, H27, S04, S05, P06). Left:
  - S02: a could-not-look answer without the file's path. The path is carried and never printed.
  - P05: the damaged page's link to the file's history. Unit R-L4b, next, removes that page.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/`):
  - 94edea5 (c1, c2, c3): 1537 tests, 1534 pass, 2 skipped, 0 fail, 1 todo.
  - 8f8d319 (c4): 1545 tests, 1542 pass, 2 skipped, 0 fail, 1 todo.
  - The gap tests and this entry: 1549 tests, 1546 pass, 2 skipped, 0 fail, 1 todo (bare: 1556, 1553).

## 2026-10-13: Unit R-L4: nothing is ever deleted; a registration file is a claim until the case root projects it (branch `case-protocol-2026-10-10`, NOT deployed)

- **Taken out before release.** The removal and repair-note machinery added in units R-L, R-L2 and R-L3 (the unwind of an unconfirmed registration, the signed repair notes, the sealer's completion of recorded removals, the "condemned" file, and the one pins-repository deletion in `lib/_case_unregister.js`) was taken out before release. Four review rounds each found one more reader of a registration file that the unwind could delete after the service had answered 200 for it, and the fault was the rule, not the readers: a 503 must leave the repository where a re-send can finish, never where something must be reversed.
- **The rule.**
  - A registration file is a claim, inert until the case root projects it. The root's entry for a role carries `registration_sha256`, the sha256 of the file's bytes (`lib/_case.js` THE PROJECTION, `caseEntry`).
  - The commit path projects only after a fresh read of the root (the confirming read) shows no withdrawal and no seal, before the deadline, by a compare-and-swap on the root (`projectRegistration`). The case lock stays as a courtesy that serializes writers; the compare-and-swap is the guard.
  - If the confirming read or the projection fails, nothing more is written: 503 `registration_unconfirmed`, "the registration file is written and is not yet confirmed; send the same registration again".
  - The same registration is the same fields a party supplies: case id, role, commitment, the registering key (verifier and key id) and its signature, compared by one helper (`partySuppliedDiffers`), never the file's bytes. Sent again, it finds the file and projects that file as it is, with its own sha256 and registered_at. The lost create-only race is the same case. A file whose party-supplied fields differ is 409 `registration_exists`, naming its sha256 and the field (`differs`). This is the architect's correction to rule 3, applied in this unit.
  - Every reader takes registrations from the root's projection alone and checks each file against it (`lib/_case_seal.js` `projectedRegistrations`). This covers the commit path, the reveal and its refusal receipt, the withdrawal and its retry, the reference, the sealer and the case page. A projected file that is missing, is not the file projected, or does not hold the entry is DAMAGED: 409 `case_damaged`, its own page, never sealed and never pinned. The sealer's index and the status counts read no registration file.
  - A file written after its case's withdrawal is 409 `case_withdrawn` and stays, inert. The refusal receipt and a retried withdrawal take the commitment from the root version the withdrawal wrote over (`rootBeforeWithdrawal`).
  - The case page says of a file the root does not project "written, not confirmed". Once the case is sealed or past its deadline it says "written, never confirmed; this file has no standing and cannot acquire it". On a withdrawn case it says "written; the case is withdrawn, so this file has no standing and cannot acquire it". These rows are in `test/case_rj3.test.js`'s registration-file table.
  - The README states the public property verbatim: "No file in the pins repository is ever deleted. ..." (since scoped to a case's own files by unit R-L4c, c3, above). Files under `removals/` in a preview repository are ignored.
- **The reveal (rule 7).** It writes nothing but the case root before its VERDICT. Its first write, the reveal attempt, is itself a compare-and-swap over the root it read. The VERDICT is a compare-and-swap over the attempt. A projection or a withdrawal that lands in between makes the next write lose, and the reveal answers from the new state. The pin comes after the VERDICT.
- **Removed.**
  - From `lib/_case_seal.js`: `repairNote`, `repairNotePath`, `repairNotePathV1`, `notePathOf`, `repairNoteFormReason`, `verifyRepairNote`, `noteVerdict`, `NOTE_UNREAD_REASONS`, `REPAIR_NOTE_*`, `REPAIR_REASONS`, `REPAIR_NOTES_DIR`, `CREATE_ONLY_RULE`, `sealedWithRegistration`, `registrationsStanding`, `standingOfCase`, `removeRegistration`, `caseRemovals`, `REMOVAL_WALK_READS`, `completeRemovals`, `removalsToComplete`, `withdrawalCommitOf`, `registrationAgainstWithdrawal`, `WITHDRAWN_REPAIR_READS`, and the sealer's three repair windows.
  - From `lib/_case_http.js`: `readRegistrations`, `standingUnread`, `project`, `projectFiles`, `judgeRegistration`, `registrationOnFile`, `unwindRegistration`, `unwoundWords` and `UNCONFIRMED_NOTED`.
  - From `lib/_case_page.js`: the Removals panel (`removalsPanel`, `noteRow`, `REMOVED_ROWS`, `NOTE_STATE_WORDS`, `removalsDefinite`).
  - `lib/_case_unregister.js` and its test, `test/case_rl3.test.js`, and every test of the removed machinery.
- **Tests.**
  - New: `test/case_rl4.test.js`, 15 tests of the rule and the correction, plus 7 registration-file rows in `test/case_rj3.test.js`.
  - On 85d90a2 the 11 rule tests fail, and so do the 4 table rows of the new states; the 3 table rows of unchanged states pass. On 0a49538, 3 of the correction's 4 tests fail. The later-clock re-send already projected the original file there.
  - Deleted: 92 tests of the removed machinery: 30 in `case_rl3`, 23 in `case_rl`, 21 in `case_rl2`, 7 in `case_rn`, 4 in `case_consent`, 3 in `case_rn2`, 3 in `case_mutation_gaps` and 1 in `no_delete_record`.
  - Updated by design: `case_protocol`, `case_fix_mutation_gaps`, `case_mutation_gaps`, `case_redteam`, `case_reveal`, `case_item2b`, `case_item2c`, `case_rn`, `case_rn2`, `case_rn4`, `case_commits`, `no_delete_record`. The single-party fixtures are now written by hand: the second projection under one key is refused.
- **The must-fail pass, and the gap-test commit** (3edb973).
  - 107 defects were planted over every line R-L4 changed in `lib/_case_http.js`, `lib/_case_seal.js`, `lib/_case_page.js`, `lib/_case.js` and `lib/_store.js` at 0a49538, and 18 more over the correction's lines at f39038e, each alone with the whole suite run. None timed out.
  - The first batch: 63 caught, 44 survived. 15 gap tests catch 35 of them.
  - The second batch: 11 caught, 7 survived. The gap tests catch 4 of them.
  - Left as equivalent or unreachable through the service:
    - H15, H16, H17: the confirming read's own-role checks. One path holds one file, and step 2 already checked the projection against it.
    - H18, H49: the confirming read's deadline. It uses the request's clock, which step 5a already checked.
    - H31: a root the rebuild found unprojectable reading projectable at the next read. Statuses never regress, and projections are never removed.
    - H59: the receipt taking the other role's entry. The preimage binds the role.
    - T01: `fileText` without its newline. Every write and every hash use the one function.
    - X04, X05: the signature and the key id in the comparison. A valid record with the same fields and verifier has both.
    - X18: an unparsed file read as `{}`. It is refused as a record, as `null` is.
    - H47: a line replaced by the correction; X14 covers it.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - 0a49538 (R-L4): 1513 tests, 1510 pass, 2 skipped, 0 fail, 1 todo.
  - f39038e (the correction): 1517 tests, 1514 pass, 2 skipped, 0 fail, 1 todo.
  - 3edb973 (gap tests): 1532 tests, 1529 pass, 2 skipped, 0 fail, 1 todo. A bare `node --test`: 1539 and 1536.
  - The change log commit changes no test, and the final tip prints what 3edb973 prints.

## 2026-10-13: Unit R-L3: a registration file under a verified repair note never stands, sending it again writes it fresh, and the anchor's last early returns are misses (branch `case-protocol-2026-10-10`, NOT deployed)

- **The blocker.** R-L2's own rule let the sealer delete a registration the service had answered 200 for. The registration was written, the read after the write failed, a repair note (`registration_unconfirmed`) was written, and the removal failed; the 503 said to send the registration again. The re-send took the file still at the path as the registration and answered 200 `existing: true`. The sealer's next run then completed the recorded removal, and the case carried a commitment whose file was gone.
- **THE CONDEMNED FILE.** A registration file for which a current-form repair note stands and verifies, naming that exact file (its path, its blob and the commit that created it), never stands as a registration, for any reader or any handler.
  - One helper decides it, `registrationsStanding` in `lib/_case_seal.js` (`standingOfCase` reads the files first). Every reader calls it: `readRegistrations` in `lib/_case_http.js` (the commit path and its projection, the reveal, the withdrawal and the reference), the sealer's sealable index and the case page.
  - A note that definitely does not verify condemns nothing. A note that could not be listed, read or checked now, or a file whose creating commit could not be read, is could-not-look: 503 `could_not_look`, naming the role and the reason, and nothing changes.
- **Rule 1, the replay.** A registration sent again while a condemned file is at its role's path completes the recorded removal under the case lock (the note stands, so no second note is written), after reading the case again under the lock. It then registers afresh as a new write, with a new creating commit and every check, the deadline included. The answer is 200 with `existing: false` and `earlier_removed: true`.
  - A removal that cannot be completed is 503 `removal_incomplete`, and nothing changes.
  - Past the deadline the fresh registration is 409 `late_commitment`: "the earlier registration was removed under a repair note and the deadline has passed; no commitment can be registered to it now".
- **Rule 2, every reader.** A condemned file reads as absent. A case is not COMMITTED and cannot reveal while either role's only file is condemned. The reveal answers 409 `not_committed`, naming the role and the note. The other role's registration does not project the file. The case page shows a case its object calls COMMITTED as OPEN and says why in the role's row. The sealer counts the case in `not_standing`, not among its candidates, and a case whose notes could not be checked is in `pending` with its reason.
- **Rule 3.** The 503 after a failed read-after-write, once a note is written, says: "The registration was written and could not be confirmed, so a removal of it was recorded. Send the same registration again; it will be written fresh."
- **Rule 4, completion under the lock.** `completeRemovals` takes the case lock for each case it acts on, reads the case and the files again under it, and removes nothing if the case reads sealed or the file is no longer the noted one. A busy lock is reported as `case_busy`. The sealer passes its run's clock as the lock's lease clock.
  - The reveal does not take the case lock. The race is closed by rule 2: the reveal treats a condemned file as absent, so it cannot seal with the file being removed.
- **Rule 5.** The README's removals section states the rule in two sentences.
- **Follow-ups.**
  - (a) In `dailyAnchorOf`, the three remaining early returns are misses: a branch answer that is unknown, the record's commits unreadable, and the record at its commit unreadable. The records after them are read, so a proven conflict in a later record is still found and still refuses a row.
  - (b) In the removals history walk, a 404 at a commit the path's own commit list names is a removal only right after a commit where the file was read. Any other such 404, or a walk that ends contradicting what is at the path now, is a history the host has not shown yet. The page says the history of that path could not be read, each note naming it says what is at its path could not be read, and the page is not kept.
  - (c) An old-form note names its file by its bytes. It marks as recorded only the oldest removal of a file with those bytes, not every removal on its path.
  - (d) A withdrawal whose write kept losing says "nothing was written to the case record", since the lock record was written.
- **Tests.**
  - New: `test/case_rl3.test.js`, 14 tests, plus one in `test/case_rj3.test.js` for (a). On b22b763 all 15 fail.
  - Updated by design: `case_rl` (H13: the rule 3 words, and the file removed) and `case_rl2` (M2: the kept-changing words; H04-H07: the rule 3 words).
- **The must-fail pass, and the gap-test commit** (89eaa37).
  - 109 defects were planted, one at a time, over every line R-L3 changed in `lib/_case_seal.js`, `lib/_case_http.js` and `lib/_case_page.js`, with the whole suite run against each. The unit's own tests caught 61, and none timed out.
  - The 48 that survived, by place:
    - the sealer's index: could-not-look, a noted case with no condemned file, the counts, role b, the run's clock and the candidates (S02, S04-S06, S08, S09, S31);
    - the helper: role b, its listing, the creating commit and its reason, the note's read, each field check, a note that does not verify, its `standing` answer, its reasons, and the reads it skips (S10, S11, S13-S15, S17-S22, S24, S25, S27, S29, S32, S33);
    - the old-form match (C02, C03) and completion's default clock (L10);
    - the handlers: role b, the could-not-look words, the projection's rebuild, the replay's lock and re-read, `earlier_removed`, the reveal's code and note, the withdrawal's and the reference's reads, and the no-note words (H04, H06, H07, H12, H13, H21, H22, H24, H27, H28, H30, H33);
    - the page: its could-not-look rows, the note's link, the panel shown with only an unread history, the kept page, the not-sealed words, the title and role b (P01-P03, P05, P07, P14-P17).
  - 16 gap tests in `test/case_rl3.test.js` catch 46 of them.
  - Two are left as equivalent. S18 drops the note's version check and S19 its case check. A note at a file's note path in another version, or of another case, already fails the note's own form check, so it never verifies.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - f85663a (R-L3): 1571 tests, 1568 pass, 2 skipped, 0 fail, 1 todo.
  - 89eaa37 (gap tests): 1587 tests, 1584 pass, 2 skipped, 0 fail, 1 todo. A bare `node --test`: 1594 and 1591.
  - The change log commit changes no test, and the final tip prints what 89eaa37 prints.

## 2026-10-13: Unit R-L2: a repair note records a removal decided, the page says what it read, notes keyed on the file, and a row refused only on a proven anchor conflict (branch `case-protocol-2026-10-10`, NOT deployed)

- **B1, a note records a removal decided.** A repair note is described everywhere as "a removal of this file was recorded for <reason>", never as a removal made.
  - The case page's Removals panel says, for each note, what it read at the note's path: the same file still there ("a repair note is written; the removal has not been made"), another file there ("removed; another file is at that path now"), nothing there ("removed"), or the same file under a case that sealed with it ("a repair note was written and the removal was not made; the registration stood and the case sealed").
  - The sealer completes every recorded removal whose file is still at its path, for every reason, without a second note (`completeRemovals`, a window of the cases holding a note; `removals_completed` in its answer). A registration that stood while its case sealed with it is never removed, and nothing is removed under a VERDICT. The README says so.
- **B2, three outcomes for a removed file.** A file the page reads as removed is "removed without a record" only when no note is there. A note whose check could not look (the document it names or the current document unreadable, or the note itself) says "its repair note could not be verified when this page was read", is no finding, and keeps the page out of the cache. A note that definitely does not verify says so, with its reason. The page reads a registration path's files from its history: the commits touching it and the file at each.
- **M1, a note keyed on the file.** A note is kept at `removals/<case_id>/<sha256 of removed_path, removed_blob_sha and created_in_commit, a newline between>.json` and records `created_in_commit` (`v: 2`). A second removal on the same path gets its own note, and a byte-identical file created by a later commit is another file: no note of the earlier file removes it. Notes of the form before (`v: 1`, keyed on the path alone) are read and labelled as the old form, and nothing acts on them.
- **M2.** After a withdrawal's write kept losing, the 503 says "the case kept changing while this request tried to write; nothing was written. Send it again." (`case_kept_changing`) when the case read fine and can still be withdrawn; "what it is now could not be read" (`case_moved`) is said only when that read failed or read no case.
- **M3.** A case holds at most 500 reference rows (`MAX_REFERENCE_ROWS`); the 501st is 409 `row_limit`, and the eight-digit `references_full` it replaces could not be reached. The comment beside the constant gives the arithmetic: a pin at the cap is under 35 KB, against the contents API's 1 MB inline limit that `lib/_store.js` `getFile` reads through.
- **M4.** In `dailyAnchorOf`, a head whose compare is not_found and a record whose newest commit names another head, or no head (`anchor_record_names_no_head`, with its own words), are misses: the records after them are read. A reference row is refused only on a proven anchor conflict (409 `anchor_conflict`); the 503 `anchor_unreadable` and its words are gone, and the case page's anchor cell is unchanged.
- **The minors.**
  - The L2 test inspects the sealed case, its receipt and the reveal's answer: every key id they name, past the service's own keys, is one of the two that registered in that case, and no key id of another case in the same store appears.
  - L4: a withdrawal that loses to a reveal attempt, or to another withdrawal, writes nothing to the pins repository and removes nothing.
  - A next pin written after a walk that did not reach a legacy chain's start says an earlier pin may list its rows too.
  - The one removal (`lib/_case_unregister.js`) needs the file's creating commit, reads the note kept for that file, checks its signature itself, and checks that the file at the path is the one that commit created.
- **Tests.**
  - New: `test/case_rl2.test.js`, 14 tests. On c7ccdb2, 13 fail; the L4 test passes, the behaviour already held.
  - `test/case_rj3.test.js`: a table row (`anchor_record_names_no_head`) and two M4 tests; the table's anchor rows expect the row taken (201); the R-L H36 gap test is deleted, the 503 it pinned being gone. On c7ccdb2, 23 fail.
  - Updated by design: `case_rl` (its race learns the note's path after the write; notes in v 2; the panel and refusal words; the L2 test), `case_consent`, `case_rn2`, `case_signed_under` (P13 counts pin histories only), `no_delete_record`.
- **The must-fail pass, and the gap-test commit** (ec87459).
  - 114 defects were planted, one at a time, over every line R-L2 changed in `lib/_case_seal.js`, `lib/_case_http.js`, `lib/_case_page.js` and `lib/_case_unregister.js`, with the whole suite run against each. The unit's own tests caught 76, and none timed out.
  - The 38 that survived, by place:
    - the note's form by its version (S09-S11) and `sealedWithRegistration` (S17-S19);
    - the removal's creating commit when none is given, and its read-back (S22-S25, S27);
    - the walk of a path's history (S31-S34, S39) and the match of a removal to its note (S44, S45);
    - completion's reports and guards (S50-S54, S56, S57, S59);
    - the index pin's `auth_note` (S72), and the creating commit the sealer and the commit path hand the removal (S75, H01);
    - the commit path's refusals in full (H04-H07);
    - the unread note's row and the kept page (P05, P13, P14);
    - the removal guard's version check and its commits read (U02, U06).
  - 12 gap tests in `test/case_rl2.test.js` catch 35 of them.
  - Three are left as equivalent. S31: a path with one commit and no file now yields no removal either way. S56: the sealed branch returns before the line it changes. P14: a removal whose note could not be verified always has an unverified or unread note, which the kept-page check already refuses.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - 0ccad6d (R-L2): 1544 tests, 1541 pass, 2 skipped, 0 fail, 1 todo.
  - ec87459 (gap tests): 1556 tests, 1553 pass, 2 skipped, 0 fail, 1 todo. A bare `node --test`: 1563 and 1560.
  - The change log commit changes no test, and the final tip prints what ec87459 prints.

## 2026-10-13: Unit R-L: the withdrawn-tape listing removed, a signed note for every removal, and a pin chain that always advances; and eight follow-ups to R-J3 (branch `case-protocol-2026-10-10`, NOT deployed)

- **The listing, removed (L1, L7).** The withdrawn-tape listing introduced in unit R-N was removed before release. A list keyed on a tape digest was a permanent, one-sided way for a stranger to stop a published tape from ever being compared here, one changed byte evaded it, and the service cannot recall bytes a counterparty already holds.
  - Gone: the `withdrawn_commitments/` writer and its read-back (`writeWithdrawnCommitment`, `tapeWithdrawn`, `withdrawnCommitmentPath`); the listing-first order and the listing's refusals in the withdrawal handler; the `consent_withdrawn` and `consent_unreadable` gates at `?op=reconcile` and at the reveal (`LISTED_WORDS`); the `withdrawn_commitment`, `withdrawn_commitment_note` and `tape_listed` fields; the README's listing paragraphs; the case page's "unless a tape in it has since been listed as withdrawn"; the listing's tests and the red-team todo about a stranger listing a published digest.
  - The withdrawal proves the role, takes the lock, writes the signed withdrawal record, writes the marker and answers. A request that wrote nothing ends "This request wrote nothing."
  - Files under `withdrawn_commitments/` from before this change are ignored: no code reads or writes them, and none deletes them.
- **The public claim (L2).** The README's withdrawal section, the WITHDRAWN case page and the withdrawal's answer (`withdrawal_note`) say: "Withdrawal before the reveal closes that case; it does not recall a tape a counterparty already holds, and no verdict ever binds a key that did not sign in the case that produced it." A test holds a verdict to the key ids that signed in its own case.
- **A signed note for every removal (L3).** A registration removed by the commit path or the sealer's repair is removed only after a create-only repair note, `removals/<case_id>/<sha256 of the removed path>.json`, signed under the one signature rule, is written and read back. No note, no removal. A removal that fails leaves the note, and the next repair completes it without a second note. The case page lists a case's notes, each verified under the key document it names, and says when a registration file reads removed with no valid note. The README states the rule: the pins repository is create-only except for removals that carry a signed repair note.
- **The withdrawal race (L4).** A withdrawal that took effect leaves its signed record in every interleaving, the lease race included. A withdrawal that lost (sealed, attempted, expired, or withdrawn first) writes nothing to the pins repository and removes nothing, and says so.
- **The pin chain always advances (L5).** A pin carries `listed_by`, the index of every row a pin of the chain lists, so the next pin reads the pointer's index and the rows no pin lists yet, not the chain from pin 1. A case at pin 40 gets pin 41, and the reads it takes do not grow with the pin count. A chain written before the index is walked within the old bound once; rows the walk did not reach are listed again, and the next pin carries the index. A reference row is never refused for a pin count.
- **Two sentences (L6).** Revocation (README and the key document's `revoked` meaning): "A key once shown revoked by a valid marker stays revoked. If the marker file is later removed, the answer is that the marker cannot be read, never that the key is trusted again." The case page, beside the key document it names: "Dates in a key document are shown for information and are not enforced; a key is judged by its status in the named document."
- **Follow-ups to R-J3 (g1-g8), the first commit.** `anchor_record_changed` says the record was read and named a different head (g1). A daily anchor record whose head the repository does not show no longer holds the cases behind it (g2). The case-commit cell of `case_commit_not_shown` says what was read (g3). "Not shown by the repository" is one wording, and "yet" only for `could_not_look` (g4). A pin commit list longer than this service reads, or empty, has its own reason and words (g5). The preview tool says `pin_unavailable` as could-not-look (g6). The anchor record's own commit is said as that (g7). The (state, reason) table in `test/case_rj3.test.js` now has 148 rows, and the R-J3 line that said "every pair" says what the table covers (g8).
- **Tests.** New: `test/case_rl.test.js`, 25 tests; on the follow-ups commit 24 fail, and the one that passes holds a verdict to its own case's key ids, which was already so. Deleted: every test of the listing, and the red-team todo about a stranger listing a published digest. Updated by design: the tests whose fixtures went through the listing or a removal (`case_consent`, `case_item2c`, `case_redteam`, `case_rn`, `case_rn2`, `case_rn3`, `case_rn4`, `no_delete_record`, `reconcile_endpoint`, `response_bodies`).
- **The must-fail pass, and the gap-test commit** (1535f38).
  - 185 defects were planted, one at a time, over every line the follow-ups and R-L changed in `lib/_case_seal.js`, `lib/_case_http.js`, `lib/_case_page.js`, `lib/_verdict.js`, `lib/_case_unregister.js` and `tools/preview_dry_run.js`, with the whole suite run against each. The unit's own tests caught 105, and none timed out.
  - The 80 that survived, by place:
    - the index reader and the next pin (L5): a failed, absent or foreign pin's reason, the wanted-row filter, a walk that stops, and the pin's `auth_note`;
    - the marker read again from the cache (L6), and the first miss kept over later ones (g2), with an unread record passed over;
    - the repair note (L3): every form check, every verifier check, every guard before the note is written, the read-back, the verification before the removal, two of the sealer's three paths passing the run's key, and the removal guard's field checks;
    - the page's removals (L3): what it says when a read failed, a note at the wrong name or of another case, a file still there, a role never registered, the rule, the panel on OPEN and EXPIRED pages, and that a page whose removals could not be read is never kept;
    - the answers: the C2 refusal's words and `repair_note`, the withdrawal's `withdrawal_note` and `preimage_note`, the `reason` field of `anchor_unreadable`, and the revoked-key could-not-look page for a history longer than this service reads (g5).
  - 25 gap tests (21 in `test/case_rl.test.js`, 4 in `test/case_rj3.test.js`) catch 78 of them.
  - Two are left as equivalent, both in `lib/_verdict.js` `listedByOk`. V03 drops "an index on the seal's own pin": every entry there already fails the pin range. V04 drops "an entry that is not an object": no JSON value that is not an object has both keys.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - 9e35cd7 (the follow-ups): 1494 tests, 1490 pass, 2 skipped, 0 fail, 2 todo.
  - 39caaae (R-L): 1503 tests, 1500 pass, 2 skipped, 0 fail, 1 todo. The todo removed is the red-team question about a stranger listing a published digest.
  - 1535f38 (gap tests): 1528 tests, 1525 pass, 2 skipped, 0 fail, 1 todo. A bare `node --test`: 1535 and 1532.
  - The change log commit changes no test, and the final tip prints what 1535f38 prints.

## 2026-10-13: Unit R-J3: every pin, anchor, case-commit and row cell, and every refusal about a pin, anchor, commit or row, says only what was read, by state and reason (branch `case-protocol-2026-10-10`, NOT deployed)

- **The rule.** Every cell on the case page, and every refusal about a pin, anchor, commit or row, says only what was read, by state and reason. No cell states the absence of something read as present, and no reason names a cause the code did not establish.
- **The (state, reason) table** (`test/case_rj3.test.js`, `TABLE`). It covers one fixture for each reason that `anchorState`, `dailyAnchorOf`, `servedAtCommit` and the row reader (`referenceCommitStates`, with the walk down the pins) name, in 62 rows. Each read is tried with one HTTP failure (503; 404 where the reader treats it apart). The pointer is tried with one seal-judge reason (`case_seal_unknown_field`). The row reader's `not_read` is shown under one case state (`no_case_commit`). Other HTTP codes, judge reasons and case states were not asserted until unit R-L (g8) added rows for them. (Corrected in unit R-L: this line said "every pair".) Each row gives the sentence for the pin cell, the anchor cell, the case-commit cell, the note under them, the row's commit cell and the reference's answer.
  - Each row is a test, run against a fixture that makes the pair.
  - Every test first asserts the pair as its reader returns it, then every cell and the answer, word for word.
  - Two pairs come only from `anchorState` given a chain (`tools/preview_dry_run.js`), and one only from the revocation order's lookup with no anchor read. Their cells are asserted from the page's own cell functions. The reference never meets them.
- **BL1, the pin cell** (`pinnedHtml`). It says "no pin of this case's chain" only where the pointer was read and holds no pin of this chain (`pointer_holds_another_chain`).
  - Where the pointer was read and holds the chain, the cell says "a pin of this case's chain was read; the case is not shown as pinned or anchored (reason)". This covers `no_case_commit`, every conflict at the pin's commit or a daily anchor head, every mismatch, and every `could_not_look` past the pointer.
  - No pin pointer present: "not pinned yet: no pin pointer is present under this case's namespace (not_pinned)".
  - A pointer that is not a case seal record: "a record is present at this case's pin pointer and cannot be read as a case seal record (reason)".
  - A pointer that could not be read: "not known when this page was read: the pin pointer could not be read (pin_pointer_unreadable)".
- **BL2, another chain or not a pin** (`notHeldAtCommit`, which replaces `heldAtCommit`).
  - `*_holds_another_chain` is said only when the record passes the seal judge at the seal's seq and its chain differs.
  - A record that fails the judge or has another seq is `pin_at_its_commit_not_a_pin` or `anchored_head_not_a_pin`: "the record at this case's pin path, ... is not a pin record for this case". That holds even when the record carries this case's chain.
  - `pointer_holds_another_chain` is unchanged.
- **F1.** No later pin is stated as fact. Not pinned: "the case is sealed and not yet pinned (not_pinned) ... A later sealer run may pin it." No case commit: "A later sealer run may record that commit in a next pin of the case." The cause "it was pinned before every write named its own commit" is gone. So is the stale comment in `lib/_case_http.js`.
- **F2.** `*_commit_not_found` says "the pins repository does not show that commit". Every mismatch ends "so the case is not shown as pinned or anchored", and "Never pinned, never anchored" is gone. Behaviour is unchanged.
- **F3.** A raw 404 for the pin at a daily anchor record's head counts as "a head from before the pin" only once the commits API shows the repository has that head.
  - If the repository does not show the head, the anchor is `could_not_look` (`anchor_head_not_shown`).
  - If that read fails, it is `could_not_look` (`anchor_head_exists_<reason>`).
- **F4.** Under a key the current document lists as revoked, a pin that could not be read is `pin_unavailable`: neither `signer_revoked` nor `signer_since_revoked`. It gives:
  - on the page, the could-not-look page (503), naming the revoked key and the pin's state, never "SEALED RECORD DOES NOT VERIFY";
  - at the reference, 503 `could_not_look`;
  - for the sealer, `could_not_look`.
  - A pointer read that is not a case seal record stays `signer_revoked` (`pin_unreadable:<reason>`).
- **F5.** A pin that could not be read answers a reference 503 `could_not_look`: "could not look; this is not a refusal of the row. Try again." It no longer answers 409 `case_not_pinned`.
  - The 409 `case_not_pinned` text now says "a reference row is appended only to a case that reads pinned or anchored", with no "once the operator's sealer run has pinned the case".
  - The 503 `anchor_unreadable` says which: "whether a daily anchor record conflicts with its pin could not be read", or "the head a daily anchor record names is not shown by the repository yet". It no longer says "its daily anchor records could not be read" for a read that did not fail.
- **F6.** For the `*_commit_not_shown` reasons the anchor and row cells say "the commit it names is not shown by the repository yet". Every other `could_not_look` names the read that failed: the pin record's commit, the pin record at its commit, the file at the commit, whether the commit exists, or whether it is on the published branch. The head a daily anchor record names, when not shown, is said as that.
- **F8.** A page kept again moves to the newest place in the cache's eviction order (`keepPage`).
- **F9.** The case-commit cell says "not known when this page was read (reason)" only when a read failed. Otherwise it says what was read:
  - no pointer to name it;
  - a pin that names none;
  - the commit its pin names and the mismatch;
  - a pointer holding another chain;
  - a conflict at the pin's commit, where the case file was not read;
  - a daily anchor head's conflict, where the case file read at the commit its pin names is this case;
  - a pointer that is not a case seal record.
- **The row cell, by the same rule.**
  - A row of a case not shown pinned is `not_read`, with the case's state and reason. The old `could_not_look (pin_not_held)` named a cause that was not established.
  - A walk that stops on a record it read is `not_read`: `pin_below_absent`, `pin_below_not_a_pin` (it was `pin_unreadable`), or `pins_not_read` ("the pointer and 20 below it").
  - `could_not_look` is said of a row only when a read failed.
  - A `not_read` row keeps its page out of the cache. A case with rows whose pin names no case commit is therefore no longer cached.
- **The note** under the cells names the state and its reason.
- **Tests.**
  - New: `test/case_rj3.test.js`, 68 tests: the 62 table rows plus BL1, BL2, F1/F2, F4, F8 and the uncached `not_read` page. On 8a88212 59 fail; the 9 that pass are the unchanged pinned, anchored, recorded and mismatched-row sentences and the table's own BL1 check.
  - Updated by design:
    - the page phrases in `test/case_commits.test.js`, `case_item2c`, `case_rj`, `case_rj2` and `case_signed_under`;
    - C01's seq-2 record, now `pin_at_its_commit_not_a_pin`;
    - the walk's reasons;
    - the reference's could-not-look answer in `case_consent`;
    - R-I2 m2's revoked-key pin read in `case_trust_root`, now `pin_unavailable`.
  - One fixture changed: in `case_commits`, a daily anchor record naming a head the mock dropped when it re-seeded a path is removed before the control. A real repository keeps its commits, and since F3 a head it does not show is `could_not_look`.
- **The must-fail pass, and the gap-test commit** (cd4feb3).
  - 86 defects were planted, one at a time, over every line R-J3 changed in `lib/_case_seal.js`, `lib/_case_page.js` and `lib/_case_http.js`, with the whole suite run against each. The unit's own tests caught 82, and none timed out.
  - The 4 that survived:
    - S04: the revoked-key answer without its revoked keys;
    - P38: the could-not-look page without the revoked key;
    - P42: the could-not-look page without its pin row;
    - P24: a `not_read` row whose reason the page has no words for, printed as "undefined".
  - Two gap tests in `test/case_rj3.test.js` catch all four. None is left as equivalent.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - 13536f0 (R-J3): 1403 tests, 1399 pass, 2 skipped, 0 fail, 2 todo.
  - cd4feb3 (gap tests): 1405 tests, 1401 pass, 2 skipped, 0 fail, 2 todo. A bare `node --test`: 1412 and 1408.
  - The change log commit changes no test, and the final tip prints what cd4feb3 prints.

## 2026-10-13: Unit R-J2: the row sentence claims no future pin, conflicts and mismatches worded by reason, a commit not shown yet is could_not_look, and the page cache keeps only definite pages (branch `case-protocol-2026-10-10`, NOT deployed)

- **B2, the blocker: the signed row sentence, version 3** (an architect decision; `lib/_case.js`, `lib/_case_seal.js`, `lib/_case_http.js`, `lib/_case_page.js`, README).
  - `REFERENCE_ANCHOR_NOTE` is "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case may list that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here."
  - `note_version` is 3. Version 2 was never issued, and the code comment, the README (a new section, "A reference row's sentence") and this change log say so.
  - A row with `note_version` 2 is `row_note_v2`; a row with none is `row_note_v1`, reported by what it lacks. Neither is counted.
  - The 201 body's `row_commit_note` no longer states a future pin.
  - The page says a row is "recorded by commit X" and "listed by pin N" only where it read that pin, shows each row's anchor state as "not computed", and never calls a row anchored. A row no pin lists says no pin read lists it.
  - Rows are not refused for a case whose pin chain cannot advance, and the pin walk is untouched.
- **B1, the blocker: a conflict is worded by its reason** (`conflictWords`). On the page and in the reference's 409 `anchor_conflict`, "holds another chain" is said only for `pointer_holds_another_chain`, `pin_at_its_commit_holds_another_chain` and `anchored_head_holds_another_chain`:
  - `anchored_head_off_branch` says the daily anchor record names a head that is not on the published branch;
  - `anchored_head_not_json` and `pin_at_its_commit_not_json` say the record there could not be read as a pin.
- **M1.** A commit the host does not show on the branch yet (`commitOnBranch` answering not_found) is `could_not_look`: `case_commit_not_shown` and `reference_commit_not_shown`, and `anchor_head_not_shown` for a head. A definite off-branch answer stays a mismatch or a conflict.
- **M2, the page cache.**
  - A page is kept only when every state on it was read with a definite answer: no `could_not_look` and no `pin_commit_mismatch` anywhere. A page that does not verify is never kept.
  - An unsealed case's entry ends at its deadline.
  - Every view reads the case root first, and is answered from the cache only for the same root blob.
  - Every case page prints "read at <UTC time>", and "on this request" is now "when this page was read".
- **Minors.**
  - **n1.** The row link names the row's commit once the row reads recorded.
  - **n2.** The sealer's row read-back uses `servedAtCommit`, so its reason is `reference_at_commit_differs`.
  - **n3.** The general anchor sentence is printed only beside a case that reads pinned or anchored; otherwise the page says what it read.
  - **n4.** `tools/preview_dry_run.js` says the anchor's proof is not checked by it.
  - **n5.** Given a chain the case served does not have, `anchorState` answers `case_served_differs` before any read at the commit.
  - **n6, n7.** The mismatch sentences say "in canonical form (json-c14n:v1)" and are worded by reason. An off-branch commit, or one the repository does not have, is not called "that commit of the pins repository's branch".
  - **n8.** This entry, and the corrected J1, J5 and J6 lines in the R-J entry below.
- **Tests.**
  - New: `test/case_rj2.test.js`, 12 tests, each failing before the change.
  - Updated by design:
    - the page phrases in `test/case_commits.test.js`, `case_item2c`, `case_item2d`, `case_mutation_gaps`, `case_signed_under` and `case_trust_root`;
    - the J1 tests and the cache read counts in `test/case_rj.test.js`;
    - the sealer's row read-back reason.
- **The must-fail pass, and the gap-test commit** (74644f9).
  - 56 defects were planted, one at a time, over every line R-J2 changed, with the whole suite run against each. The unit's own tests caught 43.
  - The 13 that survived:
    - S04: the sealer's row read failure read as a mismatch;
    - S07: n5's mismatch without its commit;
    - S12: the default conflict words;
    - P16: the anchor sentence beside an anchored case;
    - P18, P19, P21, P22, P23, P30: the cache keeping a page with a pin, rows or a row not read definitely, or one that does not verify;
    - P25: a sealed page held to the deadline;
    - P31: a single-party page past its deadline;
    - P32: a withdrawn page never kept.
  - Seven gap tests in `test/case_rj2.test.js` catch all 13. None is left as equivalent.
  - They also found a defect in the cache: a withdrawn or expired page has no deadline cap, `Math.min` with `undefined` gave NaN, and those pages were never kept. A missing cap now means none.
  - That fix and the `mismatchWords` export are two more defects planted (X01, X02), both caught.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - b1b58cf (R-J2): 1328 tests, 1324 pass, 2 skipped, 0 fail, 2 todo.
  - 74644f9 (gap tests): 1335 tests, 1331 pass, 2 skipped, 0 fail, 2 todo. A bare `node --test`: 1342 and 1338.
  - The change log commit changes no test, and the final tip prints what 74644f9 prints.

## 2026-10-13: Unit R-J: the row sentence, what "anchored" claims, a wrong commit is a mismatch, and the case checked by bytes; and seven follow-ups to R-N4 (branch `case-protocol-2026-10-10`, NOT deployed)

- **The follow-ups to R-N4** (17c7cf9, the unit's first commit).
  - **f1.** A withdrawal whose case lock could not be read or written answers `case_lock_unreachable` with "This request wrote nothing to the case record. Try again shortly." A lock write that failed may have landed. Other handlers' words are unchanged.
  - **f2, f3** (README):
    - the tape is refused "usually as 409 `consent_withdrawn`"; an earlier check can refuse first (a sealed case's reveal is `not_committed`), and a listing that cannot be read is 503 `consent_unreadable`;
    - a WITHDRAWN case whose listing is missing leaves the tape "not refused on account of this case".
  - **f4.** The withdrawer's retry whose registration read fails is 503 `store_unreachable`: "The case is withdrawn. This request could not finish checking it. Send the same withdrawal again." It is no longer the final-sounding 409.
  - **f5.** The R-N4 entry names which refusals carry the tail.
  - **f6.** A `reveal_attempts` list with no attempt event cannot throw: `reveal_attempted`, with `reveal_attempt_at: null`.
  - **f7.** A test drives a WITHDRAWN case whose listing is missing:
    - `?op=reconcile` compares the tape;
    - the other role's request does not repair the listing;
    - the withdrawer's retry writes it, and the tape is then refused.
- **J1, the blocker: the row's sentence, version 2** (`lib/_case.js`, `lib/_case_seal.js`). (Corrected in unit R-J2, B2: version 2 was never issued. It stated a future event, "listed by the case's next pin", as fact, and R-J2 replaced it with version 3 before any row was written under it.)
  - `REFERENCE_ANCHOR_NOTE` was "This row has no pin of its own. It is recorded by the pins-repository commit that writes it and listed by the case's next pin; it is anchored only when that pin is."
  - Rows carried `note_version: 2`. The judge accepted only version 2; a row without `note_version` was `row_note_v1`.
  - The 201 body's `anchor_note` and `row_commit_note` agreed with each other, and both stated the next pin as fact.
- **J2.** "anchored" claims what is checked. The anchor state carries `proof: "unchecked"`. The page says "a daily anchor record in this repository names a head that holds this pin; this page does not check the OpenTimestamps proof." `ANCHOR_NOTE`, the seal module's header and the README say the same.
- **J3, J4, J6: one standard for the case and its rows** (`servedAtCommit`).
  - The record served must be the file at the commit a pin names, byte for byte in json-c14n:v1, signature included (`sameRecord`), on the pins repository's branch (`commitOnBranch`).
  - Each of these is `pin_commit_mismatch`:
    - other bytes, or no JSON;
    - a file absent at the commit;
    - a commit the repository does not have (its existence read once from the commits API, `store.commitExists`; only GitHub's 422 reads as "no such commit");
    - a commit off the branch.
  - Only a read that failed is `could_not_look`.
  - `anchorState` takes the case served; given a chain, it reads the case from the branch and serves it only when it has that chain.
  - The page's "the case file" link names `case_commit` once the case reads pinned or anchored.
  - An anchor head off the branch is an anchor conflict. (Corrected in unit R-J2, M1: a commit the host does not show on the branch yet is `could_not_look`, never a mismatch or a conflict.)
- **J5.** Non-JSON at a pin's oldest commit, or at the head a daily anchor record names, is `conflict`. A reference refuses every anchor conflict as 409 `anchor_conflict`. (Corrected in unit R-J2, B1: until then the page and the 409 said every conflict "holds another chain"; since then each is worded by its reason.)
- **J7.** A 200 case page is kept per case for sixty seconds per instance, by the page's clock and for the same key document; at most 500 cases. The per-IP limiter runs first.
- **J8.** `case_not_anchored` is `case_not_pinned`.
- **Tests.**
  - New: `test/case_rj.test.js`, 9 tests, each failing before the change, and five tests in `test/case_rn4.test.js` for the follow-ups (f7 pins behaviour that already held).
  - The mock store answers `GET /repos/<repo>/commits/<sha>`.
  - Updated by design:
    - THE VERIFIER test, inverted: a commit that does not exist is a mismatch;
    - the anchor words, `proof: "unchecked"`, and the reason `case_at_commit_differs`;
    - the row note words;
    - `case_not_pinned`;
    - I1's forced compare failure, which now names the order compare;
    - every test page view clears the page cache first.
- **The must-fail pass, and the gap-test commit** (8dd6ff9).
  - 63 defects were planted, one at a time, over every line the unit's two commits changed (the follow-ups and R-J), with the whole suite run against each. The unit's own tests caught 45.
  - The 18 that survived:
    - A03: a `note_version` other than 2;
    - B06, B07: the commit-existence cache;
    - B18: a row's failed read shown as a mismatch;
    - B23: a head whose branch read fails;
    - B25, B26: the branch's case served whatever its chain, and its failed read;
    - B29, C04, D07: a reader handing anchorState a chain instead of the case it holds (one more read of the case file);
    - C01: an anchor conflict refused only when it is another chain;
    - D04 to D06: the case commit row's words and the case file link;
    - D09 to D12: the cache's key document, clock, status and bound.
  - Ten gap tests in `test/case_rj.test.js` catch all 18. None is left as equivalent.
- Counts, as `npm test` prints them (a bare `node --test` adds the 7 files in `test/helpers/` to tests and to passes):
  - 17c7cf9 (follow-ups): 1297 tests, 1293 pass, 2 skipped, 0 fail, 2 todo.
  - fbaa2f0 (R-J): 1306 tests, 1302 pass, 2 skipped, 0 fail, 2 todo.
  - 8dd6ff9 (gap tests): 1316 tests, 1312 pass, 2 skipped, 0 fail, 2 todo. A bare `node --test`: 1323 and 1319.
  - The change log commit changes no test, and the final tip prints what 8dd6ff9 prints.

## 2026-10-13: Unit R-N4: the withdrawal says only what this request did, and the listing's README holds in every state (branch `case-protocol-2026-10-10`, NOT deployed)

- **R1, the blocker: the words** (`lib/_case_http.js`).
  - No answer from the withdrawal handler says "nothing was withdrawn", or claims the state of the listing, unless this request confirmed it.
  - The refusals that end with "This request wrote nothing. A tape digest listed by an earlier withdrawal request stays listed." are those of the case read, the standing (sealed, withdrawn, attempted, expired, on a first request and on a second), the registration files, the proof, the signer, the record, and the lock when busy or unreadable. The plain 400, 404 and 405, the listing's own refusal, the refusals after a confirmed listing, and the retry whose listing is unconfirmed do not carry it. (Corrected after R-N4, f5. Since f1, the lock that could not be read or written ends "This request wrote nothing to the case record. Try again shortly.")
  - The shared readers and `lockRefusal` put that tail after a full stop (`withTail`). Every other handler's words are unchanged.
  - A listing that cannot be confirmed (its write failed, or only its read-back) says "The tape listing could not be confirmed, so this request went no further. Send the same withdrawal again."
  - No listing read is added before the role is proven.
- **R2.** The README's "A withdrawn tape's listing" is rewritten so every sentence holds in every state:
  - when a listing stands without a withdrawn case, with examples;
  - that sending the same withdrawal again finishes it only if the case can still be withdrawn;
  - that a WITHDRAWN case whose listing is missing is repaired only by the withdrawer sending the withdrawal again, and until then the tape is not refused;
  - that a listing only ever refuses.
- **R3.** A root write that throws: "The withdrawal record may not have been written. Your tape digest is already listed, so this service will not compare that tape. Send the same withdrawal again to finish or to confirm."
- **R4** (`tools/check_refusal_receipt.js`).
  - The exported `offline()` answers `{signature_ok, reason}`, never a key named `ok`.
  - The CLI prints `signature_reason`, and `"unreadable"` for an input it cannot read.
  - The assertions on `bad_signature` and `document_sha256_mismatch` are restored on the new shape.
- **R5, the counts.**
  - `npm test` runs `node --test "test/*.test.js"`. A bare `node --test` also finds the 7 files in `test/helpers/`: `case_registration.js`, `check_fixtures.js`, `http_mocks.js`, `key_document.js`, `mock_store.js`, `stripe_sign.js` and `vercel_preview.js`. It reports each as one passing test, so it prints 7 more tests and 7 more passes, and nothing else differs.
  - That is the second reader's 1293 at 5e24fec, where `npm test` prints 1286. It is also their 1278 at 18ae018, where `npm test` prints 1271.
  - One line per commit, as `npm test` prints it (a bare `node --test` adds 7 to tests and to passes; measured at 5e24fec and a250335):
    - 92f17ad (R-N3): 1280 tests, 1276 pass, 2 skipped, 0 fail, 2 todo.
    - 2a547be (R-N3 gap tests): 1286 tests, 1282 pass, 2 skipped, 0 fail, 2 todo.
    - 5e24fec (R-N3 change log): 1286 tests, 1282 pass, 2 skipped, 0 fail, 2 todo. A bare `node --test`: 1293 and 1289.
    - f314c84 (R-N4): 1290 tests, 1286 pass, 2 skipped, 0 fail, 2 todo.
    - a250335 (R-N4 gap tests): 1292 tests, 1288 pass, 2 skipped, 0 fail, 2 todo. A bare `node --test`: 1299 and 1295.
    - The R-N4 change log commit changes no test, and the final tip prints what a250335 prints.
- **R6.** The window comment and a new README section, "The sealer's window", state the counts: with 30 entries, 5 a run, an hourly run reads every entry within 12 runs and a daily run within 28, from any start time. No change in behaviour.
  - The numbers are the first count of runs that leaves no gap longer than 5/30 of a turn, worked out exactly.
  - The test finds a start that needs all 12, and one that needs all 28, and checks 3,000 sampled starts.
- **R7.** "withdrawn by another request".
- **Tests.**
  - New: `test/case_rn4.test.js`, 4 tests, each failing before the change:
    - R1 (b): the listing lands, a reveal seals first, and the same withdrawal is sent again;
    - R1 (a): the listing lands, the root write fails, the deadline passes, and the same withdrawal is sent again;
    - the sweep: 31 refusals, first request and second, none saying "nothing was withdrawn", and none that confirmed no listing claiming one;
    - R6.
  - Updated by design: the tool assertions in `test/case_rn2.test.js` and `test/case_rn3.test.js`, and the R3 and R7 words in `test/case_rn3.test.js`.
- **The must-fail pass, and the gap-test commit** (a250335).
  - 36 defects were planted, one at a time, over every line R-N4 changed, with the whole suite run against each. The unit's own tests caught 30.
  - The 6 that survived:
    - W03 to W07: the full stop applied to every handler's tail, or another handler's joiner changed;
    - W14: the listing's refusal without its `case_id`.
  - Two gap tests in `test/case_rn4.test.js` catch all 6. None is left as equivalent.
  - The comment-only change in `lib/_case_seal.js` and the README were not mutated.

## 2026-10-13: Unit R-N3: plain words once the tape is listed, a partial offline receipt check, listed_at, and a window no fixed period holds still (branch `case-protocol-2026-10-10`, NOT deployed)

- **N1, the BLOCKER: the words after the listing** (`lib/_case_http.js`, `lib/_reconcile_http.js`, `lib/_case_page.js`, README).
  - Since R-N2 B1 the listing is written before the withdrawal record. A listing can therefore stand with no withdrawn case: the root write fails after it, or a reveal that passed the listing check seals first.
  - The listing's 409 `consent_withdrawn` now says "A party that committed to this tape digest in a case has withdrawn that case, or asked to. This service does not compare a tape so listed.", at `?op=reconcile` and at the reveal.
  - Every withdrawal refusal sent after the listing is confirmed says so, and carries `tape_listed: true`. None says "nothing was withdrawn".
    - A root write that fails, and a case that moved (`reason: "case_moved"`), are 503 `store_error`: "The withdrawal record was not written. Your tape digest is already listed, so this service will not compare that tape. Send the same withdrawal again to finish."
    - A reveal that sealed first is 409 `case_sealed`: "This case sealed before the withdrawal could land, so it stays a public verdict. Your tape digest is listed, so this service will not compare that tape again."
    - Another withdrawal or a reveal attempt that landed first is refused by its own code. The words say the record was not written, why, and that the tape is listed.
  - The page of a reveal attempt that did not complete says the same reveal seals it "unless a tape in it has since been listed as withdrawn".
  - The README section "A withdrawn tape's listing" says when a listing stands without a withdrawn case, and that it only ever refuses.
- **N2.** A retry on a WITHDRAWN case whose listing cannot be confirmed is 503 `withdrawn_commitment_unconfirmed`: "The case is withdrawn. The tape listing could not be confirmed this time. Send the same withdrawal again."
- **N3, the offline receipt check is partial** (`tools/check_refusal_receipt.js`).
  - With `--document` the tool prints `{ok: false, reason: "offline_partial", signature_ok, not_checked}` and exits 3, whatever it found. Only the online check prints `ok: true` and exits 0.
  - The header and the README say the offline check proves the signature against the document you supplied, and nothing about whether that document is the published one.
  - `main` is exported for the tests.
- **N4.** The listing holds `{listed_at}`, the time it was first written. A retry that writes a missing listing writes the retry's time, so `listed_at` can differ from the withdrawal's own time. The README says so.
- **N6, the sealer's window** (`lib/_case_seal.js` `rotatingWindow`, THE WINDOW'S START).
  - The start is derived from the run's full timestamp, turned by the golden ratio. No fixed run period reads the same slice forever.
  - The old start stood still under hourly runs with 12 or 30 candidates, five a run.
  - The cost: runs a minute apart no longer read each candidate within exactly ceil(n / max) runs. Measured over lists of up to 300 entries, they do within twice that. A period whose turn falls near a fraction with a small denominator moves slowly, and the comment says so.
  - The SEALER window test's run bound is now 2 × ceil(3 / 1), by design.
- **N7.** This entry, and the corrected counts and must-fail commits in the R-N2 entry below.
- **N8, the body audit** (`test/response_bodies.test.js`, `test/helpers/http_mocks.js`).
  - The audit records every status, 2xx included, with the handler that sent it, and asserts that the child run passed.
  - Each of the four named bodies is tied to the handler that sends it, not to its code alone.
  - A retried withdrawal's 200 drops a stored unsigned record's `sig_reason` (`withdrawalAnswer`). A signed record is shown whole.
- **Also.** Tests show that a multipart reveal goes through the listing gate, and that the 409 `consent_withdrawn` bodies carry no receipt field.
- **Not in this unit: N5 stays open.** A removal commit on a marker path makes the marker unreadable for good (R-N2 m1, below).
- **Tests.**
  - New: `test/case_rn3.test.js`, 9 tests, each failing before the change.
  - Updated by design:
    - `listed_at` in `test/case_rn.test.js` and `test/case_rn2.test.js`;
    - the listing's words and the tool's exit 3 in `test/case_rn2.test.js`;
    - the SEALER window bound in `test/case_item2b.test.js`;
    - the audit in `test/response_bodies.test.js`.
- Suite at 92f17ad: 1280 tests, 1276 pass, the 2 environment skips, 0 fail, 2 todo.
- **The must-fail pass, and the gap-test commit** (2a547be).
  - 50 defects were planted, one at a time, over every line R-N3 changed, with the whole suite run against each. The unit's own tests caught 33.
  - The 17 that survived:
    - H06, H07, H08: the `case_moved` 503's words, reason and `tape_listed`;
    - H11 to H15: a lost root write's standing, its listed sentence, and the `case_withdrawn`, `reveal_attempted` and `expired` words;
    - H21: the retry's 503 without its `case_id`;
    - P02: the clause on the page of an attempt with no recorded completion;
    - S02, S03, S04, S07: G made even, a clock that is not finite or not whole, the minute only;
    - T05, T06, T09: an unreadable receipt read as `signature_ok: true`, a truthy online `ok`, `--document` before the receipt.
  - Six gap tests in `test/case_rn3.test.js` catch all 17. None is left as equivalent.
  - H23 and H24, R-N2's B08 and B09 on the line R-N3 rewrote, are caught by the N2 test.
  - The harness runs the suite in a copy without `.git`, as in every earlier pass. There the same tests run, but 3 more of them skip because they need a repository: 5 skips, not 2 (measured at d0a7342 and 18ae018).
- At 2a547be, with the gap tests: 1286 tests, 1282 pass, the 2 environment skips, 0 fail, 2 todo.

## 2026-10-13: Unit R-N2: fixes from the second reader's pass over R-N (branch `case-protocol-2026-10-10`, NOT deployed)

- **B1, the withdrawn-tape listing fails closed** (`lib/_case_http.js`, `lib/_case_seal.js`).
  - The withdrawal writes the listing FIRST, under the case lock, before the root write. If the listing cannot be confirmed, the answer is 503 `withdrawn_commitment_unconfirmed` and nothing else is written. A listing left by a withdrawal that then does not land only refuses, and the retry is idempotent.
  - The marker and the listing are create-only writes that read the path back (`createOnly`). Four 409s of branch-ref contention on an absent path are a failure, never "existing".
  - The note that `?op=reconcile` refuses the tape is printed only with a confirmed listing.
  - A retried withdrawal also confirms the listing, or answers 503.
- **B2, every body carries a code.** The reveal's and `?op=reconcile`'s `signer_unavailable`, the reveal's `document_unavailable`, `operator_key_not_configured`, `key_required` and the could-not-look page no longer name a variable.
  - The loaders carry codes: `reconcile_key_unset`, `reconcile_key_unparseable`, `reconcile_key_unpublished`, `carried_document_unreadable`, `deploy_commit_unknown` and `deploy_commit_malformed`. The reasons go to the server log.
  - One test, `test/response_bodies.test.js`, re-runs the case and reconcile suites with a body audit (`test/helpers/http_mocks.js`, `ARCAEON_BODY_AUDIT`) and reads every refusal body they drive for an environment-style name.
- **M1, the joint reveal is gated by the listing.** Once each tape's digest is known, before the attempt, both digests are read. Either one listed is 409 `consent_withdrawn`, with nothing written; a read that fails is 503 `consent_unreadable`.
- **M2, the words.** The listing's 409 says exactly "A party that committed to this tape digest in a case has withdrawn that case. This service does not compare a tape so listed.", at `?op=reconcile` and at the reveal. A red-team todo names the open question: a digest already published in a sealed case can still be listed by a stranger.
- **M3.** The sealer also walks cases with one registration file, no marker and no pin, in a bounded window, and writes the marker of one whose root reads WITHDRAWN.
- **The minor findings, m1 to m10.**
  - **m1.** A marker candidate still skipped on a 404 after its second read makes the answer `revocation_marker_unreadable`, and so does a walk that ends with such a skip and no valid marker. A commit that removed the marker file therefore leaves the path unreadable.
  - **m2.** `commitOnBranch` keeps only an "on" answer; off is read again.
  - **m3.** The commit walk goes on after a full page whether or not the host names a next page. This applies to the reader and to the marker tool, and the README bound now reads "5,000 commits or more".
  - **m4.** The lease race answers "Refused. A withdrawal landed while this reveal was in progress. Nothing computed from the tapes is kept."
  - **m5.** The copy says the tapes are never decoded or hashed.
  - **m6.**
    - `verifyRefusalReceipt` reads the named document with the seal's reader (`namedDocumentOf`). A commit definitely off the published branch is `document_not_on_branch`.
    - The README has a "Checking a refusal receipt" section.
    - `tools/check_refusal_receipt.js` (61 lines) checks a receipt, offline with `--document`.
  - **m7.** The page labels an unsigned withdrawal record "withdrawal record, unsigned: not a record" and never prints its `sig_reason`. The case reads WITHDRAWN and the refusal does not depend on the signature.
  - **m8.** The WITHDRAWN page sentence.
  - **m9.** This change log's counts, the gap-test commits, and the attempt count on COMMITTED cases only.
  - **m10.** `registration_recorded` is the file's real state on the projection path and on the abandoned branch: null when it could not be read.
- **Tests.**
  - New: `test/case_rn2.test.js` (12 tests) and `test/response_bodies.test.js` (1 test), each failing before the change, and the M2 todo.
  - Updated by design: the trust-root n1/M03/n4 assertions (m1, m2), the race words (m4), the off-branch reason (m6), the B2 body assertions (`test/case_redteam.test.js`, `test/case_item2b.test.js`, `test/case_item2d.test.js`), and the tests that withdraw one case and then reveal another with the same fixture tapes, which now forget the listing first.
- Suite 1248 -> 1262 tests at d0a7342, 0 fail, 2 todo. Here: 1258 pass and the 2 environment skips. (Checked again in unit R-N3, N7: that is what the suite prints at d0a7342 in a git checkout.)
- **The must-fail pass, and the gap-test commit** (18ae018; listed in unit R-N3, N7).
  - d0a7342 and 18ae018 were pushed before this pass finished. 18ae018 was drafted ahead of its results.
  - 65 defects were planted, one at a time, over every line R-N2 changed, with the whole suite run against each. The unit's own tests caught 44.
  - The gap tests in 18ae018 (9 tests) caught 18 of the 21 that survived: B01, B03, B05, C03, C11, L07, L08, M08, R02, R04, R10, R11, R13, R15, T01, T03, T05 and T07.
  - B08 and B09 survived 18ae018: a retry whose listing fails, ignored or answered 200. Unit R-N3 rewrote that line (N2). Its N2 test and gap tests catch both on the new code (H23, H24 in the R-N3 entry).
  - M09 survives: the walk of one-registration cases also taking pinned ones. The service writes a pin only for a sealed case, which holds both registration files, so the two differ only for a pin planted by someone with write access to the pins repository. Such a case is then walked by the mutant and not by the code. No test pins that down, and R-N3 does not change the line.
  - At 18ae018 `npm test` prints 1271 tests: 1267 pass, the 2 environment skips, 0 fail, 2 todo. The second reader's 1278 and 1274 are a bare `node --test`, which also counts the 7 files in `test/helpers/` as passing tests (corrected in unit R-N4, R5).

## 2026-10-13: Unit R-N: one signature rule everywhere, the refusal receipt made real, the reconcile bypass closed, and the withdrawal lease made honest (branch `case-protocol-2026-10-10`, NOT deployed)

- **N1, the BLOCKER: one signature rule everywhere** (`lib/_case_seal.js`, `lib/_case_http.js`). Seals, reference rows, withdrawal records and refusal receipts are each signed or not written.
  - A refusal receipt is signed by the reconcile key, or it is not issued. With no reconcile signer the answer is 503 `signer_unavailable`, with no receipt and no 409 claiming one.
  - A withdrawal or a reference row without a case key is 503 `signer_unavailable`, and nothing is written.
  - The new refusals (receipt, withdrawal, row) name no environment variable: the server log has the reason. (Corrected in unit R-N2: four older bodies still did, the reveal's and `?op=reconcile`'s `signer_unavailable`, the reveal's `document_unavailable` and `operator_key_not_configured`; R-N2 B2 made every body carry a code.)
  - An unsigned row is not a record. `judgeReferenceRow` reads `sig: null` as `row_unsigned`, `liveRecords` does not count it, and the page does not say "two records" for it.
  - `publishedSignatureReason` filters by key role: a reconcile key never verifies a row, and a case key never verifies a receipt.
- **N2, the reconcile bypass closed** (`lib/_reconcile_http.js`).
  - The withdrawal records the withdrawer's tape digest at `withdrawn_commitments/<sha256 of the digest's 32 bytes>.json` in the pins repository, holding only `{withdrawn_at}`.
  - `?op=reconcile` reads that path for each tape, one read per tape. Either tape listed is 409 `consent_withdrawn`, naming no case and issuing no receipt. A read that fails is 503 `consent_unreadable`.
- **N3, the refusal reads one opening.**
  - The reveal body takes an optional `role`. On a withdrawn case only `reveals[role]` is read: the other role's entry is never read and never hashed.
  - The opening must recompute that role's registration, written before the withdrawal.
  - The receipt names the role, the commitment and `signed_under`. `verifyRefusalReceipt` is now async and checks the receipt under the named document the way a seal is checked.
  - Anything else is 404 `not_a_party`, with no receipt.
- **N4, the lease race in true words.**
  - When the attempt's CAS loses to a withdrawal, the answer says "refused; the tapes were read before the withdrawal landed and the hashes are discarded". No hash is written and no receipt is issued.
  - The commit's lost race writes no case log event: the removal's commit message names the reason. The case log stays as a format, unused.
- **C1, a registration never stands after a withdrawal.**
  - Every reader treats one under a WITHDRAWN case as not standing.
  - `registration_recorded` reports the file's real state.
  - The sealer has a withdrawn path (`repairWithdrawn`, `withdrawn_repaired` in its report). It rewrites a withdrawn marker that failed. It removes a registration file whose creating commit comes after the withdrawal's commit, decided by one compare read in the pins repository. Registrations from before the withdrawal stay.
- **C2.** A failed read of the case after the registration's write unwinds the registration: 503 `registration_unconfirmed`.
- **C3, the lease clock.**
  - The clock is read at each lock attempt, and a lease expires 30 s after its own acquisition. `opts.clock` lets tests drive the clock.
  - A retried withdrawal (the same role and preimage) is 200 with `existing: true`, and writes again a marker or withdrawn commitment that failed.
- **E1, `reveal_attempts`** (`lib/_case.js`). An append-only list of `{event: "attempt", commitments, input_sha256, at}` and `{event: "failure", reason, at}` entries replaces `reveal_attempt` and `reveal_failure`, which were never deployed. (Removed by unit R-RV: no case records a reveal attempt.)
  - It is part of the sealed base: a VERDICT keeps it inside its signed bytes.
  - A VERDICT's last entry is the attempt that sealed it, and its input hash is the sealed reveals'.
  - The page says how many attempts there were, on a COMMITTED case only: a sealed case's page does not show them. (Corrected in unit R-N2, m9.)
- **D1.** A reference reads the daily anchor records. A head holding another chain for the pin is 409 `anchor_conflict`. An anchor lookup that could not look is 503 `anchor_unreadable`.
- **T1.** The two §2B todos are plain assertions: A's reveal, naming its role, is 409 `case_withdrawn`, and the redacted root identifies neither party nor commitment. The §4 cost todo stays.
- **Tests.**
  - New: `test/case_rn.test.js`, 20 tests, each failing before the change.
  - Updated by design in the consent, item 2b/2c/2d, reveal, signed-under, red-team, fix-gap and reconcile-endpoint suites. The reconcile endpoint's suite now runs on the mock store, since `?op=reconcile` reads it.
  - Removed: the two case-log gap tests (L30/L31, L35-L38), whose code is gone.
- Suite 1209 -> 1227 tests at 2675ea0, 0 fail, 1 todo. Here: 1224 pass and the 2 environment skips.
- **The must-fail pass, and the gap-test commits** (bc99662, b7ae479; corrected in unit R-N2, m9). 132 defects were planted, one at a time, over every line R-N changed, with the whole suite run against each. The unit's own tests caught 96. Twenty-one gap tests in `test/case_rn.test.js` caught 35 of the 36 that survived. The one left, C05, is equivalent: an opening that is not hex never recomputes the registered commitment, so the answer is 404 `not_a_party` either way. With the gap tests: 1248 tests, 1245 pass and the 2 environment skips, 0 fail, 1 todo.

## 2026-10-13: Unit R-N, commit 1: the follow-ups from the second reader's pass over R-I2 (branch `case-protocol-2026-10-10`, NOT deployed)

- **n1, a 404 is not proof** (`lib/_case_seal.js` `revocationMarkerOf`). A candidate skipped on a 404 might be the real R, read before the host had it. That covers nothing on the raw host at that commit, and a revoking commit that the branch's compare does not show (`commitOnBranch` now marks that answer `not_found`). When a marker is found after any such skip, each skipped candidate is read once more. Unless every one skips again, the answer is `revocation_marker_unreadable`, and a marker found after such a skip is never kept.
- **n2, the walk follows the Link header** (`lib/_store.js` `listCommitsPage`). A page shorter than `per_page` is no longer taken as the last. The reader (`allCommitsOf`) and the marker tool both follow `rel="next"`. A next page that does not move forward is a read that failed, never a loop.
- **n3.** A sentence in the README's `KEY_DOCUMENT_BRANCH` section: a marker path forced past 5,000 commits reads `revocation_marker_unreadable` for good, and this bound is accepted.
- **n4, the walk's cost.**
  - At most `MARKER_CANDIDATES_READ` = 200 candidate reads per key per request, second reads included; one more is `revocation_marker_unreadable`.
  - A compare answer that is off the branch, or not before, is kept for the instance. A 404 is read again.
  - A key document read by its commit with nothing to match is kept for the instance, apart from the reads held to a sha256 (I5 unchanged).
- **n5, the banner** says the key document lists the key as revoked **at** its commit W, not "from": the reader checks the document at W only.
- **n6.** `pinned_at_or_after_revocation` is answered only when the compare shows that order (ahead or identical). A 404 or a diverged compare is `order_not_shown`. The marker tool's header comment and the R-I2 change-log line are corrected.
- **n7.** The bound test asserts that the refusal names no revoking commit at all.
- **The dry run's usage.** `node tools/preview_dry_run.js --help` prints the `KEY_DOCUMENT_BRANCH` lines (now a test, which runs it).
- Suite 1198 -> 1209 tests, 0 fail, 3 todo. Here: 1204 pass and the 2 environment skips.

## 2026-10-13: Unit R-I2, the must-fail pass over the lines it changed, and the tests that close its gaps (branch `case-protocol-2026-10-10`, NOT deployed)

- **The pass.** One pass over only the lines unit R-I2 changed. Mutants went into `lib/_case_seal.js`, `lib/_case_page.js`, `lib/_case_http.js`, `lib/_store.js`, `tools/record_key_revocation.js`, `tools/preview_dry_run.js`, `README.md` and the key document's notes. 62 defects were planted one at a time, with the whole suite run against each.
- **The result.** The unit's own tests caught 51. Six new tests in `test/case_trust_root.test.js` close 8 of the 11 that survived.
- **The 3 left are equivalent:**
  - **P10:** the off-branch wording applied to the current document too. A current document that does not read never has the reason `commit_not_on_branch`.
  - **S04:** a fallback reason that is never needed. Every non-pinned state `anchorState` answers carries a reason string.
  - **ST01:** a branch-read 404 that throws instead. The caller reads a throw and a 404 alike, as a branch that is not there.
- **What the new tests pin:**
  - the could-not-look headings (a commit off the branch, the current document);
  - `pin_unreadable` with the judge's reason for a pointer that is not a pin;
  - the pin token on the branch read;
  - one commits read for a short history;
  - a commit that removed the marker read as nothing there;
  - a numbered record with no commit read as could_not_look, not a crash;
  - the tool's printed usage;
  - the notes' "pinned before it" and "no later write moves it" sentences.
- Suite 1192 -> 1198 tests, 0 fail, 3 todo. Here: 1193 pass and the 2 environment skips.

## 2026-10-13: Unit R-I2: fixes from the second reader's pass over R-I (branch `case-protocol-2026-10-10`, NOT deployed)

- **B1, R past the first page** (`lib/_case_seal.js`).
  - **The defect.** The reader took R from one page of the marker path's commits, the newest 100. With 100 and more rewrites of the marker after a forged case was pinned, R moved after it, and the forged case held.
  - **The fix.** The reader now walks every page (`allCommitsOf`, at most `COMMIT_LIST_PAGES` = 50 pages of 100). Past the bound it answers `revocation_marker_unreadable`, which is `signer_revoked`. `commitsOf`, the pins-repository read Design J's commits use, pages the same way.
- **M1, R is the first VALID marker.**
  - R is the oldest commit on the path at which the file reads as a valid marker for the key: `checkRevocationMarker`, the reader's whole check, including the revoking commit on the published branch and the document there listing the key revoked.
  - Content that is not a valid marker is skipped; a commit that removed the file reads as nothing there.
  - An earlier valid marker always wins, so no later write moves R.
  - A read that fails before the first valid marker is found answers unreadable, never a later commit.
  - With none valid it is `revocation_marker_invalid`.
  - `tools/record_key_revocation.js` runs the same check on the marker it would write, against the readers' published branch (`KEY_DOCUMENT_BRANCH` of its shell), and refuses one a reader would reject: `marker_rejected`, nothing written.
- **M2, the banner says what is proven** (`lib/_case_page.js`). "The case file was written at commit P, before this key's revocation was recorded in the pins repository at commit R. The key document lists the key as revoked from its commit W." P links to the case_commit, R to the marker's commit, and W to the document at the marker's `revoked_in_commit`. "Pinned before the revocation" is gone from the page and the notes. (Corrected in unit R-N, n6: the reason code `pinned_at_or_after_revocation` stayed, and it was also answered when the compare showed no order; since R-N it is answered only when the compare shows that order, and a 404 or diverged compare is `order_not_shown`.)
- **The minor findings, m1 to m7.**
  - **m1, the notes on retired keys.** A retired key still verifies seals under a document where it was active, with no commit order, and a key suspected of compromise must be revoked, not retired. "Pinned before it" is defined as the case-file commit the pin records.
  - **m2, the pin's state in the reason.** A case under a revoked key whose pin is not pinned says why: `case_not_pinned`, `pin_commit_mismatch`, or `pin_unreadable:<reason>`.
  - **m3, the DOES NOT VERIFY notice** has one sentence each for `signer_unlisted` and `signer_revoked`.
  - **m4, a compare 404.** It is off the branch only when the branch exists: one branch read, kept once it does (`store.branchExists`). A branch that does not exist, or a failed branch read, is `branch_unreadable`. The could-not-look page for a commit off the branch says so, and does not say "try again".
  - **m5, KEY_DOCUMENT_BRANCH is documented** in both tools' usage and in a README section.
  - **m6, the mock** keeps a path's history when asked (`seed(..., {keepHistory: true})`), and answers branch reads.
  - **m7, the notes on legacy pins.** A legacy pin with no case_commit under a revoked key reads case_not_pinned and cannot be upgraded.
- **The flake.** `test/preview_dry_run.test.js` clears the seal module's caches before each test. Its TIMEOUTS test now gives each case its own clocks, the other one 30s out, so the idle timer and the deadline cannot fire in the other order under load. The failure did not reproduce here: 4 runs of the old file beside a full parallel suite each passed 26/26.
- **Tests.**
  - `test/case_trust_root.test.js` +10, and M3's test rewritten to 105 later commits with a case pinned between R and them. At 5517ea8, 13 tests failed. The m6 test passed there: it guards that the reader keeps reading at R.
  - **By design:** the banner wording (`case_signed_under`, `case_redteam`, `case_commits`), and two `commitOnBranch` assertions for a branch that does not exist (now `branch_unreadable`).
- Suite 1182 -> 1192 tests, 0 fail, 3 todo. Here: 1187 pass and the 2 environment skips.

## 2026-10-13: Unit R-I, the must-fail pass over the lines it changed, and the tests that close its gaps (branch `case-protocol-2026-10-10`, NOT deployed)

- **The pass.** One pass over the lines unit R-I changed: `lib/_case_seal.js`, `lib/_case_http.js`, `lib/_case_page.js`, `lib/_store.js`, `tools/record_key_revocation.js`, `tools/preview_dry_run.js` and the key document's notes. 114 defects were planted one at a time, with the whole suite run against each.
- **The result.** The unit's own tests caught 62. Of the 52 that survived, 48 are caught by the 13 tests added here: 12 in `test/case_trust_root.test.js` and 1 in `test/preview_dry_run.test.js`.
- **The 4 left are equivalent:**
  - **S07, K13 and T08** match an entry by key id while dropping the verifier comparison. `checkKeyDocument` already requires a key id to be its verifier's name and 32-bit hash, so another verifier under the same key id needs a hash collision.
  - **PD02** is the dry run's "current document could not be read" line. By the time (e) runs the sealed check, the current document is the one the case names (an earlier check requires its sha256), so that branch cannot be reached there.
- **What the new tests pin:**
  - `commitOnBranch`: an answer with no known status, an unusable branch name and a non-commit (no read), a kept answer per repository and branch, the pin token on the read, the pins repository's own default branch;
  - the reveal refusing a failed branch read by its reason, and reading its document once per instance;
  - `KEY_DOCUMENT_BRANCH` naming the branch;
  - a case key listed only as a reconcile key;
  - the pin commit in a `signer_revoked` answer;
  - the order kept;
  - P equal to R (signer_revoked);
  - R as the commit that wrote the marker;
  - each marker form refused (version, fingerprint, off-branch or other-role revoking commit, unreadable revoking document or branch, not JSON);
  - the marker schema's reasons;
  - the sealer run's marker report (wrong path, invalid, unreadable);
  - the words for signer_unlisted and signer_revoked;
  - the tool's refusals (existing marker in a dry run, a racing writer, store error, unlisted key, each failed read) and its walk over every page, in the key's own role;
  - the dry run reading a mismatched or off-branch bundle as BROKEN.
- Suite 1169 -> 1182 tests, 0 fail, 3 todo. Here: 1177 pass and the 2 environment skips.

## 2026-10-13: Unit R-I: the key document's trust root, revocation by commit order, and the sealer reading what it names (branch `case-protocol-2026-10-10`, NOT deployed)

- **Why.** A second-model review of Design I at 7041aa8 found:
  - **B1:** revocation was decided on service-written dates, so a signer revoked before sealing could read as holding;
  - **B2:** the reveal never read the document it names;
  - **M1:** a key absent from the current document read valid, and any commit the raw host serves could be named;
  - **minors:** the cache took any parseable document (m1); the could-not-look page always blamed the named document (m2); the "revoking commit" shown was the reader's own deployment (m3).
- **I1, revocation by commit order** (`lib/_case_seal.js` THE TRUST ROOT).
  - **Dates are display only.** `retrieved_at`, `since` and `revoked_since` are never compared; a key is active in the named document by its status.
  - **Why a marker.** A pin is a pins-repository commit and the key document is a witness-repository file, and git orders commits only within one repository. So a key the current document lists as revoked is ordered by a **revocation marker** in the pins repository: `revocations/<fingerprint>.json`, `{kind: "key-revocation", v: 1, key_id, key_fingerprint, revoked_in_commit}`.
  - **The marker is read as it names.** At its own commit R, with the key id and fingerprint held to the key, and the document at `revoked_in_commit` (on the published branch) listing the key revoked.
  - **The answer.**
    - The case's pin commit P strictly before R (`compare/<R>...<P>` behind) is `signer_since_revoked`: it holds, and the page banner says "revoked in commit R, after this case was pinned in commit P", both linked.
    - Anything else is `signer_revoked`: P at or after R, no pin, no marker, a marker or an order that cannot be read. It does not hold: no verdict, no pin, 409 on reference.
  - **A marker alone never revokes.** One whose key the current document does not list as revoked is ignored, and the sealer's run reports it as `marker_without_revocation`.
- **The marker tool** (`tools/record_key_revocation.js`, new). It writes the marker create-only. It finds `revoked_in_commit` by walking the key document's commits on the branch, oldest first. It refuses an existing marker (`marker_exists`) and a key not listed as revoked (`not_revoked`), and with no `--write` it is a dry run.
- **I2, the sealer reads what it names** (`lib/_case_http.js` step 5b2, `confirmSealingDocument`). Before anything is written, the reveal reads the document at its own commit and compares it with the bundle. A commit off the published branch, an unreadable document, or a different one is 503 `document_unavailable`, and no attempt is written.
- **I3, the current document lists both keys.** A signer absent from the current document, in its role and with the same verifier, is `signer_unlisted`: no verdict, no pin, 409 on reference.
- **Ancestry** (`commitOnBranch(commit, {repo, branch})`, exported for Design J's commits). A named document commit must be on `KEY_DOCUMENT_BRANCH` (default `main`): one compare read, identical or behind, kept once on. Anything else is `document_unavailable`.
- **I5.**
  - A fetched document is cached only after its hash matches.
  - `document_unavailable` names `document: "named" | "current"`, and the page heading and the dry-run line say which.
  - `current_commit` is gone: the revoking commit shown is R.
- **I4.**
  - The key document's notes now state the rules (revoked: cases pinned before the revoking commit keep their verdict under a banner, cases pinned at or after it do not verify; the reconcile key is listed here with role reconcile; the marker; the "never provisioned" sentence deleted). Its shape is unchanged.
  - `checkKeyDocument` refuses one public key listed twice across roles (`duplicate_public_key`).
  - `loadCaseSigner` refuses a case key the document lists as a reconcile key (`case_key_is_other_key`).
- **Smaller changes.**
  - `lib/_store.js`: `compareCommits`, and `listCommits` paging.
  - The preview dry run reads 503 `document_unavailable` (bundled_document_differs, commit_not_on_branch) as BROKEN.
- **Tests.**
  - **New:** `test/case_trust_root.test.js`, 18 tests, each run first against the unchanged code and failing there.
  - **Inverted, as the brief asked:** `case_signed_under` "the current document does not decide", and the red-team FIX B control (a document the sealer named does not make a stranger's reconcile key valid).
  - **Rewritten to commit order:**
    - the since-revoked tests (answer, page, verdict word, S32);
    - the date-based named-document test, now by status;
    - red-team §1.4, now with a marker;
    - `case_commits` every-commit-is-a-link.
  - **Fixtures adapted:**
    - readers that read under a document without the test keys now hand it one that lists them (`case_mutation_gaps`, `case_item2c`, `case_item2d`);
    - four tests that read after the reveal's cached read now clear the cache first;
    - the dry run's unreadable-document case now refuses at the reveal.
- Suite 1151 -> 1169 tests, 0 fail, 3 todo. Here: 1164 pass and the 2 environment skips.

## 2026-10-12: The must-fail pass over this unit (fixes C, D, E, Design N, the one signature rule), the tests that close its gaps, and two defects it found (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The pass.** 148 defects were planted one at a time in the code this unit added or changed: `lib/_case_http.js`, `lib/_case.js`, `lib/_case_seal.js`, `lib/_case_page.js`, `lib/_case_unregister.js` and `tools/preview_dry_run.js`. The whole suite ran against each one. The unit's own tests caught 99. 21 new tests in `test/case_consent.test.js` close the 49 that survived, except E15, which is equivalent: the receipt check reads only the case's `policy_version`, which the case with and without its attempt share.
- **Two defects the survivors pointed at, each fixed with its test first** (`lib/_case_http.js`):
  - **The case log** (L38's survivor). `appendCaseEvent` reported success when the store abandoned its write. That happens when, after a branch-ref retry, the path is found taken by another request's event. It answered that other event's path and wrote nothing of its own. An abandoned write now takes the next seq, and nothing is ever written over another event.
  - **The commit under the lock** (L39's survivor). A case record that read again under the lock but was missing or not a valid case record was taken as "not withdrawn", and the registration was written. It is now refused 503 `case_record_unreadable` and nothing is registered: a commit that cannot tell whether the case was withdrawn writes nothing.
- **The mock store's DELETE** (`test/helpers/mock_store.js`) now behaves as the contents API does. It removes a file only at the blob sha the request names: 404 with no file, 409 for another sha. It answers the removal's commit and logs each removal (`deleteLog`), so a test can see the request the one deletion makes.
- **What the new tests pin**:
  - the lock record's forms, waits and refusals;
  - the lock's path and holder;
  - the removal request (DELETE, blob sha, branch, token) and its commit;
  - the log event's commit, from the write's answer or the history;
  - a refused removal;
  - the log's seq rules;
  - `anchorState`'s `not_looked_up`;
  - each recorded failure reason;
  - an abandoned failure write;
  - the attempt sha read back;
  - a withdrawal meeting an attempt;
  - the attempt's input-hash formula and schema;
  - the refusal receipt checker's every reason;
  - an unsigned seal under an unfetchable document;
  - a legacy withdrawal page.
- Suite 1130 -> 1151 tests, 0 fail, 3 todo. Here: 1146 pass and the 2 environment skips.

## 2026-10-12: One signature rule: verifyCase is deleted, an unsigned seal never verifies, and the reveal seals only signed (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The two flagged items.** `verifyCase` checked a case under a verifier its caller chose and passed an unsigned receipt; THE SEALED CHECK (`sealedRecordReason`) is the check every reader runs. A seal with `sig: null` read `valid_under_document`.
- **verifyCase is deleted** (`lib/_case_seal.js`). It had no caller outside the tests. The tests that used it now run the sealed check under the document the case names, or `signatureReason` for a bare signature question.
- **An unsigned seal never verifies.** `sealedRecordReason` reads a VERDICT with `sig: null` as `case_signature_invalid`, reason `unsigned_seal`, under any document, before the named document is fetched. So the sealer pins nothing for it, a reference to it is refused, and the case page shows no verdict.
- **The reveal seals only signed** (`lib/_case_http.js`). Without a case key the document it carries lists (`loadCaseSigner`), the reveal refuses 503 `case_signer_unavailable` with the signer's code as `reason`, before the attempt is written or anything is compared, the way it refuses without a reconcile signer. **(Beyond the literal ask; see the report.)**
- **The preview dry run** (`tools/preview_dry_run.js`) reads that 503 as BROKEN: the published case signer is not installed, so the preview seals nothing.
- **What is unchanged.** Unsigned reference rows and unsigned withdrawal records still read valid and unsigned: the rule is about seals. `signCase` still writes `sig: null` with `sig_reason` when it has no key; nothing writes that as a seal any more.
- **Tests.**
  - `test/case_consent.test.js` +3: verifyCase defined, exported or called nowhere in lib/, api/ or tools/; an unsigned seal reads `case_signature_invalid` (`unsigned_seal`), the sealer pins nothing, a reference is refused and the page shows no verdict; the reveal's 503 for each missing-signer code, with nothing written.
  - Updated by design: tests that sealed unsigned through the reveal now expect the 503, or build the unsigned record the seal module's way (`case_item2b` FIX 2 and SIGNED_BY, `case_item2c` FIX 1, FIX 2 and the page, `case_item2d`, `case_reveal` TEST 9, `preview_dry_run` (e)); fixtures that sealed without the log key now carry it so the case key can be shown apart (`case_budgets`, `case_mutation_gaps`).
- Suite 1127 -> 1130 tests, 0 fail, 3 todo. Here: 1125 pass and the 2 environment skips.

## 2026-10-12: Design N: a withdrawal's reason, a joint reveal after it refused before its tapes are read, and a signed refusal receipt (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **(1) THE REASON** (`lib/_case.js`). The withdrawal event gains `reason` beside `by_role` and `at`.
  - It is a code from the request's optional `reason`: `party_choice` | `deadline` | `other`, and `party_choice` when none is named. Any other value is 400 `malformed_field` (`reason`), and nothing is withdrawn.
  - It sits inside the record's signed bytes.
  - The withdrawn page shows the code.
  - A record from before, with no reason, still reads.
- **(2) THE REFUSAL BEFORE THE TAPES** (`lib/_case_http.js`).
  - The reveal now reads only its case fields first.
  - A joint reveal that arrives after a withdrawal is refused 409 `case_withdrawn` before the tapes are decoded or hashed: tapes that would not even decode are refused the same way.
  - Nothing about the tapes is stored or logged.
  - The tapes are decoded once the case is known to take a reveal.
  - The request body itself is read, since it carries the case id.
- **(3) THE REFUSAL RECEIPT** (`lib/_case_seal.js`).
  - **What it is.** The refusing answer carries `refusal_receipt`: `{kind: "comparison_refused", v: 1, case_id, at, reason: "consent_not_jointly_held"}`, signed with the case key under the key document the deployment carries (`signed_by` and `sig`, or `sig: null` with `sig_reason`, as a seal is).
  - **Checking it.** The requester may show it to anyone. `verifyRefusalReceipt(rec, doc)` checks exact fields, the fixed values, and a signature by a key the document lists as a case key, not revoked.
  - **What it changes.** It is written nowhere: the public case record and page do not change.
  - **The race.** A withdrawal that lands under the reveal's attempt write (FIX E) is refused the same way, with a receipt, and nothing is compared.
- **Tests.**
  - `test/case_consent.test.js` +4: the reason (default, each code, refusals, signed, on the page); the refusal before the tapes (never decoded, nothing in the answer or the logs, nothing stored); the receipt (fields, verified, each forgery refused, unsigned without a listed key, record and page unchanged); the race.
  - GPT-5.6 §2B's two tests stay todo, now noted as decided: the design keeps the refusal, and their assertions ask for a seal.
  - TEST 10 expects the default reason in the withdrawal.
- Suite 1123 -> 1127 tests, 0 fail, 3 todo. Here: 1122 pass and the 2 environment skips.

## 2026-10-12: Red-team fix E: the two-phase reveal; a comparison that ran always leaves its trace (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Superseded by unit R-RV (2026-10-14).** The reveal now writes the case root once, the seal, and a failed reveal writes nothing. Nothing below about reveal attempts, `reveal_attempted`, `reveal_incomplete` or `reveal_attempt_unwritten` holds now; the entry stays as the record of what was built then.
- **The defect (GPT-5.6 §1.3).** "The system has run the comparison but leaves only a normal COMMITTED case": a reveal whose root write failed after the comparison left the record byte-identical to the COMMITTED case.
- **THE TWO-PHASE REVEAL** (`lib/_case.js`, `lib/_case_http.js`). Before it compares anything, the reveal writes `reveal_attempt` into the COMMITTED case, a CAS over the case as read. The attempt is `{commitments: {a, b}, input_sha256, at}`:
  - `commitments`: the two registered commitment hashes;
  - `input_sha256`: the sha256 of the json-c14n:v1 comparison input, `{kind: "case-reveal-input", v: 1, case_id, policy_version, tape_a_sha256, tape_b_sha256}` (`C.revealInputSha256`);
  - `at`: the service clock.
- **Then one of two things.** The root write, a CAS over the attempt as written, replaces the record with the sealed case (VERDICT, which carries neither field). Or the record stays COMMITTED with the attempt and `reveal_failure: {reason, at}`. The reasons are `comparison_failed`, `receipt_check_failed`, `verdict_not_sealable`, `seal_build_failed` and `case_seal_failed`. The answer says whether the failure write landed (`reveal_failure_recorded`).
- **When nothing is written.**
  - An attempt that cannot be written compares nothing: 503 `reveal_attempt_unwritten`.
  - A case that moved under the attempt is refused by what it now is.
  - The reconcile signer is now checked before the attempt, so a reveal that cannot compare records nothing.
- **The schema.** Only a COMMITTED case carries the fields. The attempt names the case's own commitments, a failure stands only beside an attempt, and fields are exact.
- **The sealer** reports a COMMITTED case with an attempt as `not_sealed`, reason `reveal_incomplete`, and lists it in `reveal_incomplete`, never as a clean COMMITTED.
- **The page** says a reveal was attempted at T and did not complete (reason, at), or does not record that it completed. It does not show the input hash.
- **The same reveal sent again seals.** The new attempt replaces the old one and its failure.
- **A case with a reveal attempt is not withdrawn by one role:** 409 `reveal_attempted`. A withdrawal would erase the trace.
- **Tests.**
  - `test/case_consent.test.js` +5:
    - the attempt is in the record when the comparison runs;
    - a failed root write leaves the attempt and the failure, and the sealer reports reveal_incomplete, and the page says so, and the retry seals;
    - an unwritable attempt compares nothing;
    - failures recorded by reason;
    - the withdrawal refused;
    - the schema.
  - The §1.3 red-team test loses its todo and keeps its named assertion. Its fixture now fails the case file's second PUT (the seal's; the first is the attempt).
  - Four tests that counted the reveal's case writes, failed the first one, or listed a VERDICT's optional fields were updated by design.
- Suite 1118 -> 1123 tests, 0 fail, 4 -> 3 todo. Here: 1118 pass and the 2 environment skips.

## 2026-10-12: Red-team fix D: a reference row only to a case that is pinned or anchored (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The defect (GPT-5.6 §1.2).** "A reference may be appended before the case anchor exists": a role's reference to a sealed case whose pin was not written was 201.
- **The fix.** `?op=case-reference` reads the case's pin state (`lib/_case_seal.js` `anchorState`, Design J's words) after the sealed check and before anything is spent or written.
  - Pinned (anchored implies it) takes a row.
  - Any other state is 409 `case_not_anchored`, with `state` and `reason` in the body so the caller can retry once the operator's sealer run has pinned the case. The other states are `commit_unrecorded`, `could_not_look`, `pin_commit_mismatch`, `conflict` and `unreadable`.
  - No row is written and no unit of the reference quota is taken.
- **No anchor lookup.** A row needs pinned only, so the check reads no daily anchor record: `anchorState(..., {anchor: false})` stops at pinned, with `anchor: {not_looked_up: true}`.
- **Tests.**
  - `test/case_consent.test.js` +2: an unpinned case refused, then 201 once pinned; each other state refused with it, and no anchor record read.
  - The §1.2 red-team test loses its todo and keeps its named assertion.
  - Three tests that appended a row to a case never pinned now pin it first, or plant the row (C18, which needs a row on an unpinned case). One of them re-points its pin at the case file's commit, because re-seeding drops a path's history in the mock.
- Suite 1116 -> 1118 tests, 0 fail, 5 -> 4 todo. Here: 1112 pass and the 2 environment skips.

## 2026-10-12: Red-team fix C: a registration file never stands after a withdrawal (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The defect (GPT-5.6 §1.1 / §6.2).** "A commitment can land after withdrawal ... the registration file remains written": a commit that read OPEN wrote its registration file after a withdrawal landed, and only its projection answered case_withdrawn.
- **THE CASE LOCK** (`lib/_case_http.js`).
  - **Where it lives.** The registration write and the withdrawal's root write take one per-case lock: a lease in the PRIVATE usage repository, `case_locks/<case_id>.json`.
  - **How it is taken.** Through the store's conditional writes (lib/_claim.js's discipline). It is held `CASE_LOCK_TTL_SECONDS` (30) and released by its holder.
  - **When it cannot be taken.** A live lock held by another request is waited on three times, then 503 `case_busy`. One that cannot be read is 503 `case_lock_unreachable`; one present and unreadable is 503 `case_lock_unreadable`. Nothing is written in any of them.
- **Under the lock the commit reads the case again.** On WITHDRAWN it writes nothing: 409 case_withdrawn, `registration_recorded: false`, `received_at` (the registered_at it would have recorded).
- **After its write, still under the lock, it reads the case once more.** A lease that ran out can be taken over, so a withdrawal may land in between: the race lost after the write. Inside the same critical section:
  - the registration is removed (`lib/_case_unregister.js`, the pins repository's one deletion, which refuses every path but a registration file; the removal is itself a commit);
  - a case log event `commit_after_withdrawal` is appended, so the attempt is not invisible: 409 with `registration_removed` and `log_event`.
- **THE CASE LOG** (`lib/_case.js`): `cases/<case_id>/log/<seq>.json`, create-only, exactly `{kind: "case-event", v, case_id, seq, event, at, role, commitment_sha256, registered_at, registration_commit, withdrawal_at}`.
- A registration written before the withdrawal stands, as design decision 3 says.
- **`test/no_delete_record.test.js`.** The new module is the one named exception to "no DELETE against the pin repo". A new test holds it to registration files only, before any request is made.
- **Tests.**
  - `test/case_consent.test.js` (new, 5): the withdrawal seen under the lock; the race lost after the write (removed and logged); a live lock (case_busy), with an expired one taken over; a lock that cannot be read; the event's schema.
  - The §1.1 red-team test loses its todo and keeps its named assertion.
  - Its sibling keeps the registered_at-before-withdrawal check, now read from the refusal's `received_at` since no file is created.
  - Three interleaving tests move their interleave point to just before the lock is taken (the lock now orders those writes), or count pins-repository writes only.
- Suite 1110 -> 1116 tests, 0 fail, 6 -> 5 todo. Here: 1109 pass and the 2 environment skips.

## 2026-10-12: Design J, step 5: the must-fail pass, 108 planted defects, 107 caught, 1 equivalent (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- 108 defects planted one at a time in the code Design J added or changed, with the whole suite run against each. The harness is not committed.

  | file | planted | caught by steps 1-4 | closed by these tests | equivalent |
  |---|---|---|---|---|
  | `lib/_case_seal.js` | 64 | 47 | A03, A11, A12, B03, C01, C02, C03, C04, C05, C06, C08, C13, C14, C17, C18, C21, C23 | |
  | `lib/_case_page.js` | 15 | 12 | P03, P07, P15 | |
  | `lib/_verdict.js` | 8 | 8 | | |
  | `lib/_case_http.js` | 6 | 5 | | H06 |
  | `tools/preview_dry_run.js` | 5 | 3 | T03, T05 | |
  | `lib/_status_json.js` | 1 | 1 | | |
  | `api/status.js` | 2 | 0 | S01, S02 | |
  | `test/helpers/mock_store.js` | 7 | 7 | | |
  | total | 108 | 83 | 24 | 1 |

  `lib/_status_data.js` changed only in a comment, so nothing was planted there.
- **The 24 are caught now.** Rerun against the new tests, all 24 are killed.
  - C06 (an older pin's listing overriding a newer one) survived the first gap test: one row stops the walk at the newer pin. The test now has two rows, so the walk goes on, and C06 is killed.
- **What the new tests hold.**
  - A record from the day before the pin's day anchors it.
  - The record's commit is the newest touching it, and the record at that commit must name the same head.
  - A case commit holding no JSON is pin_commit_mismatch.
  - A numbered record is held to its own seq, and an orphan saying another is never adopted.
  - The walk down the pins stops at the rows it needs and reads at most `PIN_WALK_READS`.
  - A pin below the pointer that is not the case's stops the walk, and the newer pin's listing of a row wins.
  - Twenty-one rows are listed over two runs.
  - A pointer moved meanwhile is not counted written, and the next run adopts the record.
  - A row of an unpinned case is commit_unrecorded.
  - A row holding no JSON at its commit is not listed.
  - The page says when the anchor could not be looked up, and never shows a mismatched case commit as the case's.
  - The status row's pinned column.
  - The dry run's (f) waiting and could-not-look lines.
- **H06 is equivalent.** It logs a pinned seal as a failure: a server log line that no answer and no record carries.
- **Tests.** `test/case_commits.test.js` +12, `test/preview_dry_run.test.js` +2.
- Suite 1096 -> 1110 tests, 0 fail, 6 todo. Here: 1102 pass and the 2 environment skips.

## 2026-10-12: Design J, step 4: every commit on the case page is a link into the public repository it is a commit of (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- Steps 1 to 3 already render every commit they add as a link. This step adds the test that holds the page to it.
- **The sweep.** On the page, every 40-hex commit appears only as a link: in its href, or as a link's own text, never bare. Every commit link points into the repository it is a commit of:
  - the pins repository: the case file, the pin, the daily anchor record and the head it names, a row;
  - the stamps repository: the registrations' stamp commits;
  - this repository: the key document the case names, and the revoking document's commit.
- **The states covered.**
  - a sealed, anchored case with a recorded row;
  - the same case under a document that revokes its key since (the banner);
  - `pin_commit_mismatch`, and a row's `pin_commit_mismatch`;
  - the key document's could-not-look page;
  - `commit_unrecorded`;
  - a case registered and not revealed.
- No code changed in this step.
- **Tests.** `test/case_commits.test.js` +2.
- Suite 1094 -> 1096 tests, 0 fail, 6 todo. Here: 1088 pass and the 2 environment skips.

## 2026-10-12: Design J, step 3: a reference row's answer names its commit, and the case's next pin lists it (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The defect (GPT-5.6 §5).** The commit that wrote a reference row appeared neither in the row nor in the answer.
- **THE ROW'S TWO WRITES** (`lib/_case_seal.js`). The row is written first, and its 201 answer names `row_commit`, the commit its write answered with (null when that answer named none), with `row_commit_note`.
- **The second phase is the case's NEXT PIN** (`nextPin`, run by the sealer's pass for every pinned case). It:
  - lists the rows no pin of the case lists yet (at most `REFERENCE_ROW_READS` a run);
  - reads each row's commit back (the newest touching it) and the row AT that commit;
  - writes `pins/case/<id>/<seq + 1>.json`, a case_seal record with the case's chain, its `case_commit` and `reference_commits: [{seq, commit}]`;
  - moves the pointer to it, only from the record it was read at. The record is create-only, and an orphan from a lost pointer write is adopted.
- **Rows it cannot record.** A row whose read-back finds another row is not listed (`rows_unrecorded`, `pin_commit_mismatch`). One that cannot be read waits for the next run.
- **What this gives.** A row read without its pin has its commit in its answer, and a row read with its pin has it in two places. A pin from before that names no case commit gets one the same way, recorded in the next pin.
- **The run's report** gains `rows_unrecorded`. `commits_recorded` names every next pin, with its `reference_commits`.
- **The judge** (`judgeCaseSeal`).
  - seq is 1 (the seal's own pin) up to 99999999.
  - From seq 2 on, `case_commit` is required.
  - `reference_commits`, when present, is a non-empty list of exactly `{seq, commit}` in ascending seq. Anything else is refused by name.
  - The seal's own pin stays seq 1, and pinned and anchored are said of it. Every next pin carries the case's chain, so the pointer always does.
- **The page** (`referenceCommitStates`). Each reference row shown names the commit that wrote it, as the case's pins list it and read at it ("written at commit <link> (listed in pin N)"). Otherwise it says `commit_unrecorded`, `pin_commit_mismatch` (naming the pin and the commit) or `could_not_look`. The pins below the pointer are read at most `PIN_WALK_READS` (20).
- **Tests.**
  - `test/case_commits.test.js` +5:
    - the row's commit in its answer and then in the next pin (two places), with a later row in the pin after;
    - **the crash between the phases for a row** (the answer lost): the row is never rewritten, and the next run lists it;
    - **a row swapped during the read-back** is not listed, and a pin listing another row's commit is pin_commit_mismatch for that row;
    - a pin from before gets its case commit in the next pin;
    - the next pin's judge.
  - The §5 red-team test loses its todo and keeps its named assertion. The case_seal judge table's wrong seqs are now 0, "1" and 100000000 (seq 2 is a next pin).
  - The six todos left each still fail at their own named assertion.
- Suite 1089 -> 1094 tests, 0 fail, 7 -> 6 todo. Here: 1086 pass and the 2 environment skips.

## 2026-10-12: Design J, step 2: the pin records the commit that wrote the sealed case, and every reader checks the case file at it (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The defect (GPT-5.6 §3.2).** The commit that wrote a sealed case appeared neither in the case nor in its pin.
- **THE PIN IS THE SECOND PHASE** (`lib/_case_seal.js` TWO WRITES). The pin records `case_commit`, the commit the pins repository assigned to the write of the sealed case file. The case file cannot name the commit that writes it; the pin, written after it and already read by the page, does.
  - **The reveal** takes the commit from the case write's own answer (GitHub's `{commit: {sha}}`) and carries it as `case_commit`. With none, it writes no pin.
  - **The pin judge** (`lib/_verdict.js` `judgeCaseSeal`) accepts `case_commit`, 40 lowercase hex, and refuses anything else by name. It is absent only from a pin written before.
- **commit_unrecorded.** A write whose second phase has not completed reads `commit_unrecorded`, a could-not-look class answer like `document_unrecorded`: never pinned, never anchored. That covers no pin (`not_pinned`), and a pin from before that names no commit (`no_case_commit`).
  - The reveal answers `pin: "commit_unrecorded"` where it said `pending`.
  - The page says so in words.
- **The retry** (`anchorCase`, `caseCommitOf`). The sealer's next run:
  - reads the commit back (the newest commit touching the case file);
  - reads the case file AT that commit from the public pins repository;
  - pins only when that file's chain is the chain it pins. Otherwise it is `pin_commit_mismatch` (refused, nothing written), and a read that fails is `could_not_look`.
- **Nothing is backfilled.** The case file is never written again, and the run's report names each commit it recorded (`commits_recorded: [{case_id, pin_seq, case_commit}]`).
- A pin from before that names no commit is reported `pending` (`no_case_commit`); step 3's next pin records it.
- **The verifier never trusts case_commit as an id.** `anchorState`, and `anchorCase` for a pin it finds, read the case file at the commit the pin names and require its chain to be the pin's.
  - Another case there is `pin_commit_mismatch`: never pinned, never anchored, whatever a daily anchor record says.
  - A file it could not read there is `could_not_look`.
- **The page.** The anchor row says `commit_unrecorded` or `pin_commit_mismatch` (naming the commit, linked). A new "case commit" row names the commit, linked, for a pinned or anchored case.
- **Tests.**
  - `test/case_commits.test.js` +5:
    - the two writes;
    - the verifier (a commit holding another case, a commit not served, a read that fails);
    - commit_unrecorded (no pin, a pin with no case commit, with a daily anchor record present);
    - **the crash between the phases**: the pin write fails, and separately the case write's answer is lost. The page says commit_unrecorded, the case file is untouched, and the next run records the commit, read back and checked;
    - **the swapped file**: the file is swapped while the sealer reads its commit back, so the retry pins nothing and reports pin_commit_mismatch. A pin that names the swapped file's commit is pin_commit_mismatch to every reader, with a daily anchor record present.
  - The §3.2 red-team test loses its todo and keeps its named assertion. The §1.2 todo's fixture line now reads `commit_unrecorded`, so it still fails at its own named assertion.
  - `test/helpers/mock_store.js`: `dropCommitFromAnswer`.
- Suite 1084 -> 1089 tests, 0 fail, 8 -> 7 todo. Here: 1080 pass and the 2 environment skips.

## 2026-10-12: Design J, step 1: pinned, anchored or could_not_look; anchored only with a daily anchor record and its commit (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **The defect (GPT-5.6 §3.4 / §5).** `anchorState` answered "anchored" after reading `pins/case/<id>/latest.json` and nothing else, so "anchored" meant only "a pin file exists".
- **THE ANCHOR WORDS** (`lib/_case_seal.js` `anchorState`). A reader says one of three words, each only after the reads it names:
  - **pinned**: the pointer holds the case's chain, and so does the numbered record read AT the commit that wrote it (its oldest commit), which is named with its commit time;
  - **anchored**: pinned, and a daily anchor record `anchors/<date>-head.txt` names a head of the pins repository at which the numbered record holds the chain. The record's own commit is read and named, and the record at that commit names the same head;
  - **could_not_look**: a read failed, no claim.
- A pinned case whose anchor could not be looked up stays pinned and says so (`anchor: {could_not_look}`). The other answers are `pending`, `conflict` and `unreadable`. A conflict now includes a numbered record that held another chain at the commit that wrote it, and a head a record names that holds another chain.
- **How the files are read.**
  - Files at a commit are read from the public pins repository on the raw host, with no credentials. Answered reads are cached, failed ones are not.
  - Records are looked up from the day before the pin's commit, oldest first, at most `ANCHOR_RECORD_READS` (3).
  - The OpenTimestamps proof is not checked here.
- **Every place that said anchored after reading only the pin now says pinned:**
  - `pinChain` (`pinned`, with `pin_commit` when it wrote the record);
  - the reveal's answer (`pin: "pinned"`, `pin_commit`);
  - the sealer's report (`newly_pinned`, was `anchored`);
  - the status row (`pinned`, was `anchored`, in the data, the JSON and the page);
  - the case page (the anchor and pin rows);
  - `ANCHOR_NOTE`;
  - the dry run's (f).
- **The case page.**
  - anchored names the record (linked at the commit that wrote it), that commit and the head, each a link.
  - pinned says no daily anchor record read holds the pin yet.
  - could_not_look says what could not be read and claims nothing.
- **`test/helpers/mock_store.js`.**
  - The raw host serves a pins-repository file at any of its commits, as git would.
  - Commit shas are unique across the process.
  - New: `seedText`, `headOf`, `forceGetFailure`, and a `match` for `forceRawFailure`.
- **Tests.**
  - `test/case_commits.test.js` (new, 8): pinned; anchored; a head that predates the pin, and the read bound; could_not_look at each read; conflicts at the pin's commit and in an anchored head; the writers' words; the page; the note.
  - The §3.4 red-team test loses its todo and keeps its named assertion. It now plants a daily anchor record; the line that recorded the defect (only the pointer read) is gone.
  - Tests that expected the old words were updated by design.
- Suite 1076 -> 1084 tests, 0 fail, 9 -> 8 todo. Here: 1074 pass and the 2 environment skips.

## 2026-10-12: The page says two keys, never two parties (decision on the A + B report; branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- Two key ids prove two keys, not two holders. The single-party page's status line now reads "not shown as a case between two keys", and the page header comment says the same. No page state says "two parties".
- **Tests.** `test/case_redteam.test.js` +1: the single-party page says "two keys", and neither it nor a sealed page says "two parties". Must-fail: 2 planted in `lib/_case_page.js` (the old words back; the clause dropped), 2 caught.
- Suite 1059 -> 1060 tests, 0 fail, 11 todo. Here: 1047 pass and the 2 environment skips.

## 2026-10-12: Design I, the must-fail pass: 84 planted defects, 83 caught, 1 equivalent (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- 84 defects planted one at a time in the code Design I added or changed, with the whole suite run against each. The harness is not committed.

  | file | planted | caught by steps 1-5 | closed by these tests | equivalent |
  |---|---|---|---|---|
  | `lib/_case.js` | 9 | 8 | K06 | |
  | `lib/_reconcile_http.js` | 2 | 2 | | |
  | `lib/_case_http.js` | 9 | 7 | H09 | H08 |
  | `lib/_case_seal.js` | 42 | 38 | S21, S24, S32, S44 | |
  | `lib/_case_page.js` | 15 | 13 | P03, P13 | |
  | `lib/_sealer.js` | 1 | 0 | L01 | |
  | `tools/preview_dry_run.js` | 6 | 4 | T06, T07 | |
  | total | 84 | 72 | 11 | 1 |

  `lib/_reconcile_receipt.js` changed only in comments, so nothing was planted there.
- **The 11 survivors are caught now.** Rerun against the new tests, each fails exactly the test written for it.
  - **K06**: a `signed_under` missing a field is `missing_field`.
  - **H09**: the reference's 409 `document_unavailable` says the document could not be read, and that this is not a no.
  - **S21, S24**: a key counts only in its own role in the named document.
  - **S32**: a reader commit that is not 40 hex is not named as the revoking commit; the page says it is not known.
  - **S44**: `checkStoredReceipt` with no verifier given refuses every signed receipt, even where the environment names one.
  - **P03**: the page names the commit that wrote the numbered pin record, the oldest touching it.
  - **P13**: a case not pinned yet reads no pin-commit history.
  - **L01**: `anchorCases` reads the document it is handed; an unreadable one is `could_not_look`, not a pin.
  - **T06, T07**: the dry run's (f) is COULD NOT LOOK when the pass could not read the document this run's case names, and its summary counts it.
- **H08 is equivalent.** `?op=case-reference` not passing its own commit to the sealed check changes nothing it does: it reads only an answer's code and reason. `current_commit` appears only in `signer_since_revoked`, which the reference accepts without reading further.
- **Tests.** `test/case_signed_under.test.js` +8, `test/preview_dry_run.test.js` +1.
- Suite 1050 -> 1059 tests, 0 fail, 11 todo. Here: 1046 pass and the 2 environment skips.

## 2026-10-12: Design I, step 5: a seal that names no key document is document_unrecorded, never valid (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- A stored VERDICT with no `signed_under` (a seal from before Design I) reads as `document_unrecorded` (reason `no_signed_under`), signed or not, under any current document, readable or not. It is never `valid_under_document`, and no document is fetched for it.
  - **The page** shows the does-not-verify state, naming the check in words: "the key document: the record names none it was sealed under, so it cannot be held to one".
  - **`anchorCase`** refuses it and pins nothing (`anchorPending` lists it under `refused`).
  - **`?op=case-reference`** refuses it 409 `document_unrecorded`, saying that it names no key document it was signed under.
- The does-not-verify page's own sentence now says a sealed record is shown only when it names its key document and verifies under that document, read at its commit. The case-signature check's words say "the key document the case names".
- **Tests.** `test/case_signed_under.test.js` +2: `document_unrecorded` under every current document, signed or unsigned, with nothing fetched; and the page, the sealer and the reference.
- Suite 1048 -> 1050 tests, 0 fail, 11 todo. Here: 1037 pass and the 2 environment skips.

## 2026-10-12: Design I, step 4: the three key-document red-team claims are fixed (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- `test/case_redteam.test.js`: the three tests quoting GPT-5.6 §1.4 and §3.3 lose their `todo` and keep their named assertions.
  - **"A later edit changing a key ... to revoked"**: "a case sealed while its key was active still verifies, and its page shows its verdict, after a later document revokes the key". The answer is `signer_since_revoked` (a holding answer), and the page shows the verdict and the dated banner.
  - **"a later document can introduce a verifier"**: "the verdict on stored bytes does not change with the document alone". A case signed by a key its named document does not list stays `case_signature_invalid` (`signer_unpublished`) under a later document that lists it.
  - **"No sealed case records the key-document hash, Git commit, or retrieval time"**: "the sealed case names the key document it was signed under". `signed_under` now records the sha256 of the document's json-c14n:v1 form, the commit and the retrieval time.
  - The first two now await the asynchronous check (Design I, step 2), and their documents list the reconcile key as a reconcile entry.
- The file's header lists them under FIXED SINCE. The other 11 confirmed claims still fail at their own named assertions.
- Suite 1048 tests, 0 fail, 11 todo. Here: 1035 pass and the 2 environment skips.

## 2026-10-12: Design I, step 3: the case page names the document a case was sealed under and the commit that pinned it (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **A sealed case's page** (`lib/_case_page.js`, THE DOCUMENT AND THE PIN), in its "Anchor and signature" panel:
  - **key document**: "sealed under document <sha256, 16 hex> at commit <W>", the commit linked to the document at that commit in this public repository. `retrieved_at` is shown as "service clock, unverified": the public time bound is the commit's time, never the service's clock;
  - **pin**: "pinned at commit <P>, <date> (the pins repository's commit time)", for the commit that wrote the case's numbered pin record. It is read once the case is anchored, says "not pinned yet" before that, and says so when that commit cannot be read on the request;
  - **signed by**: the key id, and that the signature verified under the key document the case names. It no longer checks the CURRENT document.
- **`signer_since_revoked`** shows the verdict with a dated banner: "Revoked since this case was sealed", which key (case or reconcile), revoked since when, and the revoking document's commit. That commit is this deployment's own `VERCEL_GIT_COMMIT_SHA`, linked, or "its commit is not known here".
- **The verdict word never changes on a later document**: dropping, retiring or revoking either key, or adding keys, leaves the sealed word.
- The withdrawn page and the open and committed panels keep their wording.
- **Tests.**
  - `test/case_signed_under.test.js` +4: the document and the pin named; not pinned yet, and a pin commit that cannot be read; the dated banner for either key, with the reader's commit known or not; the verdict word unchanged under five later documents.
  - The 2c page test cites the document at its commit and says the signature verified under it (by design).
  - Suite 1044 -> 1048 tests, 0 fail, 14 todo. Here: 1032 pass and the 2 environment skips.

## 2026-10-12: Design I, step 2: a sealed case is held to the document it names, never to the current one (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **THE SEALED CHECK** (`lib/_case_seal.js` `sealedRecordReason`) is now asynchronous. It reads the key document the case names, `signed_under.document_commit`, from this public repository (`raw.githubusercontent.com`, no credentials) via `fetchNamedDocument`. A commit's file never changes, so an answered read is kept for the life of the instance; a failed one is not. Under that document, both keys must have been active at `retrieved_at` (listed from that day or before, and active or revoked only from a later day), and both signatures must verify. The answers:
  - `valid_under_document`, with the three `signed_under` fields;
  - `signer_since_revoked`: valid under the named document, but the CURRENT document (the reader's bundled copy) marks a key revoked. It carries `revoked: [{role, key_id, revoked_since}]` and `current_commit`, the reader's own `VERCEL_GIT_COMMIT_SHA`, or null when unknown. The case stays sealed;
  - `document_unavailable`: the named commit cannot be fetched (404, 5xx, network, not JSON), or the current document does not read. Could-not-look: never a yes and never a no;
  - `case_signature_invalid`:
    - the case key was already revoked in the named document at `retrieved_at` (`signer_revoked`);
    - it was retired, or listed from a later day (`signer_not_active`);
    - it was not listed (`signer_unpublished`);
    - the signature does not verify;
    - the bytes at the named commit are not the document named (`document_sha256_mismatch`), or are not a key document (`named_document_unreadable`);
  - `receipt_unsigned`: the receipt key is not a reconcile entry of the named document (`unknown_signer`), or not active then (`signer_not_active`);
  - `document_unrecorded` for a seal with no `signed_under`; step 5 covers it in every reader;
  - `single_party` and `verdict_unbound` as before.
  - `sealHolds` names the two holding answers. A later document can never make a formerly unverifiable stored signature verify: the named document alone decides validity.
- **The reconcile verifier is no longer the reader's environment.** `WITNESS_RECONCILE_VERIFIER` is only the private-side pointer to which published entry is the service's, read by the dry run. `checkStoredReceipt` holds a receipt to a verifier its caller gives, and with none refuses every signed one.
- **Callers** (consuming the new answers only):
  - `anchorCase` pins on `valid_under_document` and `signer_since_revoked`. On `document_unavailable` it does nothing and answers `could_not_look`; `anchorPending` lists it in a new `could_not_look` field and the next run tries again. Anything else is refused.
  - `?op=case-reference` takes a row on the two holding answers, and otherwise refuses 409 with the answer's code and reason (`document_unavailable`, `document_unrecorded`, and the rest as before).
  - The case page shows a VERDICT on the two holding answers. On `document_unavailable` it is a COULD NOT LOOK page (HTTP 503: the commit it names and why, no verdict, no does-not-verify state). Anything else is the does-not-verify state. Step 3 adds what the page says about the document and the pin.
  - `lib/_sealer.js` `anchorCases` takes no verifier.
- **`tools/preview_dry_run.js`.**
  - (e) holds the seal to this checkout's document: a seal under another is BROKEN.
  - (e) holds the receipt's signer to the `WITNESS_RECONCILE_VERIFIER` pointer: another key is BROKEN, none is COULD NOT LOOK.
  - (e) requires `valid_under_document`; a named document it cannot read is COULD NOT LOOK.
  - (f) needs no verifier, and says COULD NOT LOOK when the pass could not read the sealed case's named document.
- **Tests.**
  - `test/case_signed_under.test.js` +9. Valid under the named document, fetched once with no credentials. The current document does not decide. Signer since revoked, still anchored and still referenced. Revoked, retired or later-listed in the named document. A later document never makes an unlisted key verify, for the case key or the receipt key. `document_unavailable` across the sealed check, the sealer, the reference and the page, and the next run pins once it can read. Other bytes at the commit. The cache. An unreadable current document.
  - Expectations changed by design. Every reader of the old synchronous check now awaits it. The 2c and 2d arms in which the CURRENT document decided (an unlisted, revoked or unreadable current document) now say what Design I says. The 2c page through the real dispatch now shows the verdict, not DOES NOT VERIFY. The FIX B tests about readers' environments now show the environment does not decide.
  - The two §1.4 red-team todos fail earlier now; step 4 rewrites them.
  - Suite 1035 -> 1044 tests, 0 fail, 14 todo. Here: 1028 pass and the 2 environment skips.

## 2026-10-12: Design I, step 1: a sealed case records the key document it was signed under (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** GPT-5.6's red-team review, §1.4 and §3.3, CONFIRMED by `test/case_redteam.test.js`: the verdict on a sealed case changed when the public key document changed, and no sealed case recorded which document it was signed under. Design I fixes that in five steps; this is the first.
- **The key document's entries gain a role** (`lib/_case_seal.js`, SIGNED UNDER ONE DOCUMENT): `role` is "case" or "reconcile", and absent means case. A revoked entry carries `revoked_since` (an ISO date) beside `status: revoked`; no other entry carries one.
  - A key signs only in its role. The case key must be an active case entry (`loadCaseSigner`). The reconcile key must be an active reconcile entry (`loadReconcileSigner`, new) of the document the deployment carries.
  - Without one, `?op=reconcile` and the reveal refuse 503 `signer_unavailable` and compare nothing. The committed document lists no reconcile key yet, so that is the production state until the real entry is minted by hand.
  - The committed document is unchanged: its one entry has no role, so it is the case key it was.
- **`signed_under`** (`lib/_case.js`, the one optional top-level field): `{document_sha256, document_commit, retrieved_at}`, inside the signed bytes, on a VERDICT only.
  - `document_sha256` is the sha256 of the json-c14n:v1 form of the document the sealer carried.
  - `document_commit` is the sealing deployment's own commit, `VERCEL_GIT_COMMIT_SHA`. The repository is public, and the bundled document is the document at that commit (`sealingDocument`).
  - `retrieved_at` is the reveal's service time: unverified.
  - One document commit binds the case key that signed the seal and the reconcile key that signed its receipt. `sealCase` refuses to build a seal without it.
  - A VERDICT without it still reads; step 5 reads it as `document_unrecorded`.
- **The reveal** refuses 503 `document_unavailable` before anything is compared when its document does not read or its commit is not a 40-hex id. Nothing is compared or written.
- **Tests.**
  - `test/case_signed_under.test.js` (new, 7): the roles and `revoked_since`; a key signs only in its role; reconcile fails closed, including the committed document through the real dispatch; `signed_under` names the sealer's document and is covered by the signature and the chain; the schema; the reveal's `document_unavailable`; `sealCase` without it.
  - `test/helpers/key_document.js` (new) builds entries and documents, and serves a document from the public repository at a commit derived from it (sha1 of its json-c14n bytes), so the commit a deployment names always holds the document it carries.
  - `test/helpers/mock_store.js` serves raw files at a commit (`seedRaw`), as `raw.githubusercontent.com` does.
  - Every sealing test's document lists the reconcile key, every reveal runs on a deployment built at its document's commit, and the hand-built seals carry `signed_under`.
  - Expectations changed by design:
    - a reveal under the committed document now refuses (`document_unavailable` with no commit, `signer_unavailable` with one), where it sealed unsigned before. The 2a dispatch test, a 2c test and the dry run's CLI tests say so; the dry run reads that 503 as COULD NOT LOOK;
    - unsigned seals in the tests come from a document without the case key;
    - `test/reconcile_endpoint.test.js` sends its POSTs to `handleReconcile` with a document that lists its signer.
  - The red-team test "No sealed case records the key-document hash" now passes, still under its `todo` until step 4.
  - Suite 1028 -> 1035 tests, 0 fail, 14 todo. Here: 1019 pass and the 2 environment skips.

## 2026-10-12: red-team fix B, a receipt is the service's: a stored reconcile receipt holds only when the service's reconcile signer signed it, and no signer means no comparison (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** GPT-5.6's red-team review, §3.1, CONFIRMED by `test/case_redteam.test.js`: a sealed case built from a receipt no comparison produced, unsigned, passed `sealedRecordReason`. Its page showed MATCHED and "The service ran its recorded comparison once". A stored receipt was checked under the verifier it carried itself, so a receipt signed by any key, or by none, passed.
- **The rule (`lib/_case_seal.js`, A RECEIPT IS THE SERVICE'S).** A stored receipt holds only with a signature by the service's reconcile signer over its canonical bytes.
  - `checkStoredReceipt` answers `receipt_unsigned` when the receipt is unsigned, signed under another verifier, or read where no verifier is known.
  - THE SEALED CHECK (`sealedRecordReason`) answers `{code: "receipt_unsigned", reason}`, the reason one of `unsigned`, `unknown_signer` or `no_reconcile_verifier`.
  - A receipt that names the service's verifier but whose signature does not verify was altered after signing. That stays `verdict_unbound`, `receipt_bad_signature`, as before.
  - The seal-time `checkReceipt` refuses no signer, or an unsigned receipt, as `receipt_unsigned` (before, an unsigned receipt matched to a keyless deployment passed).
- **Who refuses such a case.**
  - The case page shows SEALED RECORD DOES NOT VERIFY, naming the check ("the receipt's signer") with code `receipt_unsigned` and the reason.
  - `anchorCase` refuses it (`refused`, code `receipt_unsigned`) and pins nothing.
  - `?op=case-reference` refuses it 409 `receipt_unsigned`.
  - A case whose receipt the service's signer signed shows and anchors as before.
- **The service's verifier** (`lib/_reconcile_receipt.js` `expectedVerifier`) is read from the reader's environment, in this order:
  1. the public half of `WITNESS_RECONCILE_SIGNER_KEY` (on the deployment, so the page and the reference need no new setting);
  2. else `WITNESS_RECONCILE_VERIFIER` (new): the verifier string alone, for a reader that holds no signer key, such as the operator's sealer run (`tools/seal_batch.js`) and the dry run.
  - Neither, or neither parsing, is no verifier, and every receipt is refused. The case page and the reference read their deployment's environment. `anchorCase`, `anchorPending` and `lib/_sealer.js` `anchorCases` take a `receiptVerifier` and read the process environment without one.
- **Fail closed (`lib/_reconcile_http.js`, NO SIGNER, NO RECEIPT).** With `WITNESS_RECONCILE_SIGNER_KEY` absent or unreadable:
  - `?op=reconcile` refuses 503 `signer_unavailable`, with no verdict and no receipt, before the tapes are compared;
  - the joint reveal refuses the same way (it runs the same `compare`): nothing compared, nothing sealed.
  - The service never hands out an unsigned receipt. `signReceipt` can still write the unsigned form when handed no signer, since a reader must recognise one; no path of the service hands it none.
- **`tools/preview_dry_run.js`.** (e) and (f) hold the receipt to the reconcile verifier read from this machine's environment (`WITNESS_RECONCILE_VERIFIER`, public). A receipt signed by another key is BROKEN `receipt_unsigned`. With no verifier known, (e) and (f) are COULD NOT LOOK and say so.
- **For the owner.**
  - The deployment must hold `WITNESS_RECONCILE_SIGNER_KEY`, or `?op=reconcile` and every reveal answer 503.
  - The machine that runs `tools/seal_batch.js` or the dry run needs `WITNESS_RECONCILE_VERIFIER` set to that key's public verifier, or the sealer refuses every sealed case and the dry run cannot look.
  - Only one verifier is held at a time: rotating the reconcile key would make cases sealed under the old key read `unknown_signer`.
- **Tests.**
  - `test/case_redteam.test.js`: the §3.1 test loses its `todo` and keeps its named assertion. Its page assertions now say SEALED RECORD DOES NOT VERIFY with `receipt_unsigned` and no MATCHED.
  - Beside it, 4 tests of the fix: 503 `signer_unavailable` from `?op=reconcile` for an absent, empty or unparseable signer, with the port never run; the same from the reveal, nothing written; a receipt signed by the wrong key refused by the sealed check, the page, `anchorCase`, `anchorPending` and the reference; and the readers (no verifier refuses everything; the signer key or the public verifier each name it).
  - The other 14 confirmed claims still fail at their own named assertions.
  - Test environments now carry a throwaway reconcile signer where the real dispatch runs, and the public verifier where readers run:
    - `test/reconcile_endpoint.test.js`;
    - one 2a reveal through `api/verify.js`;
    - the dry run's stand-in;
    - the case test files.
  - Expectations changed by design: the 2b separation test's environment with no reconcile signer now gets 503 from the reveal, so its unsigned-seal half runs with the log key unset instead; the seal-time check's two unsigned arms read `receipt_unsigned`.
  - `test/preview_dry_run.test.js` +1: the wrong verifier, none, and the right one.
  - `test/case_fix_mutation_gaps.test.js` +4: a must-fail pass (harness not committed) planted 34 defects in fix B's code. 28 were caught by the tests above. Of the 6 that survived, 5 are closed there and one is equivalent (S11, named in the file). Final: 34 planted, 33 caught, 1 equivalent.
  - Suite 1019 -> 1028 tests, 0 fail, 14 todo. Here: 1012 pass and the 2 environment skips.

## 2026-10-12: red-team fix A, one key per role: a case one key registered both roles of is never sealed (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** GPT-5.6's red-team review, §2A, CONFIRMED by `test/case_redteam.test.js`: one requester opened a case naming another party's label, registered both roles and revealed. The page then showed a sealed verdict naming the other party. Registration was keyless, so nothing told the two roles apart.
- **The rule (`lib/_case.js`, ONE KEY PER ROLE).** The two roles of a case are registered by two distinct key ids.
  - `?op=case-commit` takes `{case_id, role, commitment_sha256, verifier, sig}`. `verifier` is an Ed25519 verifier string in `lib/_checkpoint.js`'s shape. `sig` is that key's signature over the json-c14n:v1 bytes of `{kind: "case-registration-signature", v: 1, case_id, role, commitment_sha256}` (`registrationSigningBytes`; `signRegistration` makes one from a signer string).
  - The key id is the verifier's first two segments, `<name>+<8 hex>`.
  - A malformed verifier or sig is 400 `malformed_field`. A signature the verifier does not confirm is 403 `registration_unauthorized`, checked before anything is read.
  - A new registration whose key id is the other role's registered key id is 409 `same_key_both_roles`, and nothing is written. The other role's registration FILE counts, not only the case object.
  - The same commitment under another key for a role already registered is `role_already_committed`, never a replay.
  - The registration file keeps `key_id`, `verifier` and `sig` (a reader of the file re-checks the signature); the case's commitment entry keeps `key_id`.
  - The commitment is unchanged: the same preimage, the same 272 bytes, the same hash.
- **A case whose two commitments share a key id** (two registrations that raced past the check, each first write wins per role, or a record no build wrote) is single party (`C.singleParty`) and never reaches sealed:
  - the joint reveal refuses it, 409 `single_party`, and compares nothing;
  - `sealCase` refuses to build one;
  - THE SEALED CHECK (`sealedRecordReason`) answers `{code: "single_party", reason: "same_key_both_roles"}` for a stored VERDICT that is one, first, so `?op=case-reference` refuses it 409 `single_party`;
  - `anchorCase` answers `not_sealed`, reason `single_party`, for one read as COMMITTED or VERDICT, and pins nothing. `anchorPending` counts it in `not_sealed` and lists it in a new `single_party` field;
  - the case page shows SINGLE PARTY: the id, the stored status, the one key id, the opening and registration times, the record links and the four limits. It names no label (one would name a party that registered nothing), and shows no verdict, records, cross-reference or anchor, even for a VERDICT.
- **The limit, said in the code.** Two key ids show two keys, not two holders: one holder can make a second key. What the rule removes is the one-key case, and the use of a key the registrant does not hold.
- **Records stored before this change** carry no key. The schema now refuses them, so their page answers "Could not look" (503) and the commit and reveal paths answer `registration_record_unreadable`. None exists outside the tests and the preview's store.
- **`tools/preview_dry_run.js`.** It registers each role under its own throwaway registration key, made for the run and held in memory. Only the verifier and the signature are sent.
- **Tests.**
  - `test/case_redteam.test.js`: the §2A test loses its `todo` and keeps its named assertion. Its one key holder's second registration is now 409 `same_key_both_roles`.
  - Beside it, 8 tests of the fix: the refusal both ways; two distinct keys still seal; a raced single-party case refused by the reveal, reported `not_sealed: single_party` by the sealer, and shown as single party naming no label; a forged single-party VERDICT signed by the case key refused by the page, the sealed check, the sealer and the reference; the 403 and the 400s; another key for a registered role.
  - Every test that registers now signs through `test/helpers/case_registration.js`, one throwaway key per role.
  - The other 15 confirmed claims still fail at their own named assertions.
  - `test/case_fix_mutation_gaps.test.js` (new): a must-fail pass (harness not committed) planted 37 defects in fix A's code. 18 were caught by the tests above. Of the 19 that survived, 18 are closed there and one is equivalent (A18, named in the file). Two more were planted after and are caught: A16, and A19, a key name longer than a key id holds (180 characters), which reading the diff found answering a 500. It is now a 400 `malformed_field`. Final: 39 planted (`lib/_case.js` 19, `lib/_case_http.js` 8, `lib/_case_seal.js` 5, `lib/_case_page.js` 5, `tools/preview_dry_run.js` 2), 38 caught, 1 equivalent.
  - Suite 997 -> 1019 tests, 0 fail, 15 todo. Here: 1002 pass and the 2 environment skips.

## 2026-10-10: .gitattributes: LF everywhere, so every deployer serves the same bytes (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** On the owner's Windows checkout (`core.autocrlf true`), the working copy of `public/.well-known/arcaeon/case-signing-keys.json` is CRLF (sha256 `b6d11ab5...`), while the git blob is LF (sha256 `c17f497f...`, 2055 bytes). A prebuilt deploy uploads the working copy, so one made on Windows would serve other bytes than one made on Linux. Check (a), which compares the served bytes with the local file, would call both byte-identical.
- **The fix.** A tracked `.gitattributes` at the root: `* text=auto eol=lf`. Every blob and every working copy is LF on every OS.
  - There are no binary rules: every tracked file is text (`git ls-files --eol`: 165 files, all `i/lf`; js, md, json, py, ps1, one svg, .gitignore).
  - `git add --renormalize .` staged no change but `.gitattributes` itself.
  - On Windows, the two `.ps1` scripts now check out LF too.
- **Tests.** `test/deploy_shape.test.js` +3, all reading raw bytes, never normalized text:
  - every file under `public/` has no 0x0D byte in this working copy (the bytes a prebuilt deploy uploads), and `.gitattributes` holds the rule. A stale CRLF working copy fails, naming the refresh: delete `public/` and run `git checkout -- public`;
  - every file under `public/` has no 0x0D byte in its blob, both in HEAD and in the index, read with `git cat-file blob` (no filters), and `text=auto` and `eol=lf` apply to it. This one skips by design outside a git checkout;
  - a break arm: a CRLF blob written with `hash-object --no-filters` into a scratch repository still shows its 0x0D through `git cat-file`, a raw read of a CRLF file shows its CR, and `readText` would hide it.
  - A must-fail check on scratch clones (harness not committed) planted 3 defects one at a time: a CRLF working copy, a CR in a staged blob, and the rule removed. All 3 were caught. The refresh command was run on a CRLF copy: the key document went from 2077 bytes back to 2055, sha256 `c17f497f...`.
  - Suite 941 -> 944 tests, 0 fail. Here: 942 pass and the 2 environment skips.
- **For an existing Windows checkout.** A pull does not rewrite files it does not change, so the three `public/` files stay CRLF until they are refreshed. The working-copy test says so until then.

## 2026-10-10: tests read text files line-ending-blind (CRLF checkouts) (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** On the owner's Windows checkout (`core.autocrlf true`, 785 CR bytes in README.md), `test/deploy_shape.test.js` read "the README lists []". JavaScript's `/m` counts a lone `\r` as a line end, so the "Deploy shape" heading split did match. The list's lines then kept their `\r`, and none matched `/^- `...`$/`.
- **The fix.** Every text file a test reads for line-anchored or line-split matching is normalized right after `readFileSync` with `.replace(/\r\n/g, "\n")`:
  - in `test/deploy_shape.test.js`, through one reader, `readText`, for the README and the page sources;
  - in the three other tests that split a source file into lines: `test/case_item2b.test.js` (the seal header), `test/case_item2d.test.js` (`_case_http.js` code lines) and `test/merkle_batching.test.js` (`_batch.js` code lines). These three already tolerated a trailing `\r`, so this is prevention.
  - The other `/m` regexes in `test/` match captured process output, not file contents. `test/logtree_keygen.test.js` already splits on `/\r?\n/`. No code outside `test/` changed.
- **Tests.**
  - `test/deploy_shape.test.js` +1. The planted arm writes the README with CRLF line ends to disk and reads it through `readText`: the same served list, and the whole shape holds. A must-fail arm reads the same bytes without normalizing and gets the Windows failure verbatim, `the README lists []`.
  - On a scratch copy with all 163 text files converted to CRLF: the previous commit fails exactly that one test, and this tree passes the suite. There are 3 skips there, the third being the `.gitignore` test, which skips by design outside a git checkout.
  - Suite 940 -> 941 tests, 0 fail. Here: 939 pass and the 2 environment skips.

## 2026-10-10: the deploy shape, declared: public/ is the output directory (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** The owner read the real deployments' file trees through the Vercel API. Production went out PREBUILT with no static file at all (1 source file, 12 functions), so it answers 404 for `/.well-known/arcaeon/snapshot-keys.json` and would answer 404 for the case key document. The first preview uploaded the raw tree and serves 148 static files, `lib/`, `test/` and `CHANGELOG.md` among them. A local `vercel build` of the previous commit puts the same 148 files in `.vercel/output/static` (reproduced here with Vercel CLI 63.1.2 on a scratch copy). The shape depended on who deployed, and nothing in the repository declared it.
- **The declaration.**
  - `vercel.json` sets `"outputDirectory": "public"`. The domain serves `public/<path>` at `/<path>` and nothing else statically.
  - `public/` holds exactly `.well-known/arcaeon/case-signing-keys.json`, `favicon.svg` and `PRACTICES.md`, each moved with `git mv` so its history follows. The key document's contents are unchanged.
  - `PRACTICES.md` moved too because readers fetch it from the domain: the `/status` footer links `/PRACTICES.md` ("the standing challenge to break this"), and the brand-mark test named it with `/favicon.svg` as the root files a deployment serves. Production, with no static files, already answers 404 for that link today.
  - `/.well-known/arcaeon/snapshot-keys.json` is not in this repository, nor anywhere in its history, so nothing was moved or created for it. The README says so.
- **The readers.**
  - `lib/_case_seal.js` loads the document from `public/.well-known/arcaeon/case-signing-keys.json` (`CASE_KEYS_FILE`, new). `CASE_KEYS_DOC` stays the served path, the name every message, `sig_reason` and the case page use, so no stored or served wording changes.
  - The three functions whose require graph reaches it, `api/verify.js`, `api/status.js` and `api/badge.js`, name `public/.well-known/**` in `vercel.json` `includeFiles`.
  - In the scratch build, those three bundles carry the committed file through `filePathMap` with `includeFiles`. Without it, the `require()` trace copies the same file in, so `includeFiles` is the declared second fence.
  - `api/` stays at 12 functions.
- **The tools.** Check (a) of `tools/preview_dry_run.js` compares the served document with `public/.well-known/arcaeon/case-signing-keys.json`, and so do (e) and (f) and their evidence lines. `tools/mint_case_key.js` names that file as the one to edit.
- **README "Deploy shape".** How to deploy (`vercel pull`, `vercel build`, `vercel deploy --prebuilt`; `--prod` on both build and deploy for production only) and the exact list of what the domain serves statically.
- **The scratch build of this tree.** `.vercel/output/static` holds exactly the three files, and there are 12 functions. This is the check the owner's own local build repeats.
- **Tests.**
  - `test/deploy_shape.test.js` (new, 2). It checks the declaration: `outputDirectory`; `public/`'s exact files and none left at the root; `includeFiles` on every function whose require graph reaches the document and on no other; every root-relative static link in the pages served; the README's list equal to `public/`; `api/` at 12. Eight break arms, each named.
  - The stand-in serves static files from `vercel.json`'s `outputDirectory`. `rawTree: true` is the first preview's shape; there, (g) and now (a) read BROKEN, since the document sits at `/public/.well-known/...`.
  - Expectations changed by design: the 2b KEY DOCUMENT test and the brand-mark FAVICON test asserted that no `public/` directory exists; they now assert the declared shape. Other tests read the committed file at its new path, and the dry run's evidence names it. The exit-code test's "only (g) BROKEN" arm plants one served `README.md` instead of the raw tree.
  - Suite 938 -> 940 tests, 0 fail. Here: 938 pass and the 2 environment skips.

## 2026-10-10: the preview dry run, after its first real run: no bypass cookie; a note on root files served on the preview (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** The owner ran the dry run against a protected preview deployment of this branch. The bypass worked and the functions answered. On the first request, though, `x-vercel-set-bypass-cookie: true` drew Vercel's cookie handshake: a 307 whose `location` is the same URL. So (a) read COULD NOT LOOK (HTTP 307, neither the file nor a 404). With only `x-vercel-protection-bypass`, the key document came back 200 `application/json`, 2055 bytes, with the committed file's sha256.
- **The fix.** `tools/preview_dry_run.js` sends only `x-vercel-protection-bypass`, on every request, and never `x-vercel-set-bypass-cookie`. This supersedes the 3a entry's line that the first request carries it.
- **Tests.**
  - The stand-in (`test/helpers/vercel_preview.js`) mimics the handshake: a request that passes protection and carries `x-vercel-set-bypass-cookie` gets a 307 to its own URL with a bypass cookie, never the page.
  - The right-bypass test now asserts that no request carries the cookie header, and that the handshake is live: with the header, 307 to self; with the bypass alone, the document.
  - A must-fail check on a scratch copy (harness not committed) restored the old behaviour, the cookie asked on the first request, and separately on every request. Both were caught, the first with the real run's own symptom: (a) HTTP 307, neither the file nor a 404.
  - Suite 938 tests, 0 fail. Here: 936 pass and the 2 environment skips.
- **Note, no code yet: root files served on the preview.** The same run's (g) found 131 of its 134 root paths (lib/, tools/, test/, README.md, package.json) served 200 on the preview. Production answers 404 for the same paths. The owner is finding what differs in the production checkout before deciding anything. Until then, (g) reads BROKEN on the preview, as it should.

## 2026-10-10: the case protocol, item 3b follow-up: tests that took the committed key document for "a document without the case key" (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** `faab41b` lists the production case key's public entry (`case-2026-10+295a9a61`, active) in `.well-known/arcaeon/case-signing-keys.json`. Two 2c tests used the committed document as a document with no key, and failed. No code changed, and the key document is untouched.
- **`test/case_item2c.test.js`** (no test renamed or removed):
  - FIX 2 (GPT's planted test) seals against an injected copy of the committed document with `keys: []` (`NO_KEYS_DOC`), the same property as before: three valid, distinct keys and a document without the case key seal UNSIGNED, `key_unpublished`.
  - FIX 4 checks the unknown-field refusal on that same injected document. Its committed-document half now asserts that the committed document passes with exactly one entry, active, whose `key_id` is `case-2026-10+295a9a61` and whose verifier is the file's own and names that key id.
- **`test/preview_dry_run.test.js`.** The two child-process runs still expect (e) BROKEN, and now name the reason: the seal is unsigned (`case_key_unset`). The committed document lists the production key, but its private half is in no tree, so the stand-in cannot sign with it.
- **Tests.** A must-fail check on a scratch copy (harness not committed) planted 3 defects one at a time: publication not enforced, an unknown top-level field accepted, and the checker dropping its entries. The reworked tests caught all 3. Suite 938 tests, 0 fail. Here: 936 pass and the 2 environment skips.

## 2026-10-10: the case protocol, item 3a: three holes in the preview dry run, after the outside review of c0ef907 (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Fix 1: (e) requires a signed seal the published key confirms.** A 201 VERDICT is BROKEN, never VERIFIED, when:
  - the sealed case's `signed_by` or `sig` is missing or null (the line says "the published case signer is not installed", with the `sig_reason`);
  - the case is not a valid record;
  - it fails `lib/_case_seal.js` `sealedRecordReason` against this checkout's key document (the receipt binding, then the signature under the entry `signed_by` names);
  - that entry is not `active`;
  - or the answer's `chain` is not 64 hex, or is not the sealed case's own `caseChain`.

  Item 3b exists to show the published signer is installed, so an unsigned seal is a failure. Until 3b lists the key, (e) against a deployment of this checkout is BROKEN, and the CLI tests now expect that.
- **Fix 2: (g) reads any answer but a 404 as BROKEN.** That includes a 2xx, a 301/302/307/308 (with its `location`) and a 403, each listed with its path. Only a request that got no answer at all is COULD NOT LOOK.
- **Fix 3: (f) counts an anchor only for the reveal's chain.** The reveal's chain must be 64 hex, and the pin record's `chain` must equal it. An anchored state under any other chain is BROKEN.
- **Timeouts.** Each request has three clocks: the request's socket before an answer starts, `res.setTimeout` once one has (a server that stalls mid-body), and a deadline of four idle periods on the whole exchange (an answer that trickles in forever).
- **The key document is the checkout's.** (e) and (f) judge against this checkout's `.well-known/arcaeon/case-signing-keys.json`, and (f) hands it to `anchorCases`. `run({keyDocument})` lets a test hand another, the rule `lib/_case_seal.js` keeps; the CLI never does.
- **Tests.**
  - The stand-in gains `signer: {env, keyDocument}`, a deployment with the case key installed and listed, and `answers`, a fixed answer or a dropped connection per path. In-process runs seal with a throwaway key listed active in a copy of the committed document.
  - `test/preview_dry_run.test.js` 18 -> 21:
    - fix 1: the planted 201 VERDICT with `sig` and `signed_by` null; a deployment with no signer; a key the document does not list, or lists retired; and the answer altered (`signed_by` or `sig` missing, `sig` invalid, `chain` not hex, missing or another);
    - fix 3: an anchored state under another chain;
    - the three clocks: a stall, a trickle and silence, each ended by its own clock, with a 5-second guard so a missing clock fails rather than hangs.
  - Fix 2's arms join the (g) test: 301, 302, 307, 308 and 403 each BROKEN with its path; dropped connections alone COULD NOT LOOK.
  - Expectations changed: the plain-401 test's (g) is now BROKEN (a 401 is an answer), and the CLI runs' (e) is BROKEN (the committed document lists no key).
  - A must-fail pass on a scratch copy (harness not committed) planted 15 defects one at a time; all 15 were caught.
  - Suite 935 -> 938 tests, 0 fail. Here: 936 pass and the 2 environment skips.

## 2026-10-10: the case protocol, item 3a: the case-key mint and the preview dry run (branch `case-protocol-2026-10-10`, local only, NOT deployed, no key minted, nothing published)

- **Why.** Item three provisions the case key and promotes a preview. Before either, the key needs a tool that never shows its private half, and the preview needs one run that says what it does before anything is promoted. Nothing under `api/` changed (still 12 functions).
- **`tools/mint_case_key.js`** `--out <path ending in .signer.key> [--name] [--note]`.
  - It mints one Ed25519 key in the signer-string shape `loadCaseSigner` reads, `PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 || seed)>`.
  - The private half is written create-only, mode 0600, to `--out` and nowhere else. An existing path is refused (exit 2) and left untouched.
  - stdout is only the document entry `{key_id, verifier, since, note, status: "active"}`; progress goes to stderr.
  - The entry is `keyDocumentEntry` of `loadCaseSigner`'s `key_unpublished` answer against the committed document. Before printing, the tool checks three things, or removes the file and refuses: the entry passes `checkKeyDocument` inside the committed document; `loadCaseSigner` loads the key once that document lists it; and the key's signature verifies under the printed verifier. Throwaway log and reconcile keys stand in for the separation rule; the real ones are never read.
  - It follows `tools/logtree_keygen.js`: the `.signer.key` suffix `.gitignore` covers, header-as-help, exit 0/1/2, Windows icacls.
- **`tools/preview_dry_run.js`** `--base <origin> --key <issued key> [--bypass <secret>] [--operator-key <k>] [--pin-token <t>] [--exhaust-quota]`. Seven checks in order, one line each, VERIFIED / BROKEN / COULD NOT LOOK with the evidence:
  - (a) the key document is served byte-identical to the checkout's (sha256);
  - (b) `/case/:case_id` from this checkout's `vercel.json` delivers the page of a case the run opened (200 text/html, the id, `Case: OPEN`);
  - (c) case-open with the key is 201; with `--exhaust-quota`, opens 1-20 are 201 and the 21st is 429 `open_quota_exceeded`. Without the flag the line is COULD NOT LOOK. The per-IP limiter's `rate_limited`, or a refusal before the 21st (the key opened earlier today), is COULD NOT LOOK, never VERIFIED;
  - (d) role a's commitment is stamped, then registered at once; the registration's `stamp_commit` must be the commit the stamp answered;
  - (e) role b is stamped and registered, then the joint reveal goes out chunked with no content-length and must be 201 VERDICT;
  - (f) the sealer's case pass (`lib/_sealer.js` `anchorCases`) runs only with `--pin-token`. The store `GITHUB_PIN_REPO` names must first show the case opened on the preview. The pass must report nothing refused, in conflict or unreadable, and the sealed case must be anchored under the reveal's chain;
  - (g) README.md, package.json, package-lock.json and every file under lib/, tools/ and test/ must answer 404.
  - Exit 0 all VERIFIED, 2 any BROKEN, 3 any COULD NOT LOOK (3 wins), 1 usage.
  - The issued key goes only to case-open and the two stamps. `--operator-key` (`WITNESS_CASE_OPERATOR_KEY`) is accepted and never sent, because no check calls `case-reference`. The pin token is set for the pass alone and put back. Every line is scrubbed of all four secrets: the key, the bypass, the operator key and the pin token.
- **A protected preview** (follow-up). The project's previews sit behind Vercel Authentication, so an unauthenticated request gets a 401 SSO page.
  - `--bypass <secret>`, or `VERCEL_AUTOMATION_BYPASS_SECRET` when the flag is absent (an empty variable is no bypass), is sent as `x-vercel-protection-bypass` on every request to the preview. The first request also carries `x-vercel-set-bypass-cookie: true`.
  - The first request is (a)'s GET. When it answers 401 with Vercel's SSO page, nothing more is asked or written and every check is COULD NOT LOOK, exit 3. The reason is `protected preview, no bypass given`, or `protected preview, the bypass given was refused` when one was sent.
  - Vercel's page is told by a link to `vercel.com/sso-api`, a `_vercel_sso_nonce` cookie, or the title "Authentication Required" served by Vercel. That recognition is modelled on Vercel's page, not taken from a live one. Any other 401 is left to the checks, as before.
- **Tests.**
  - `test/mint_case_key.test.js` (new, 5).
  - `test/preview_dry_run.test.js` (new, 18) runs the tool over HTTP against `test/helpers/vercel_preview.js` (new): an in-process server running this checkout's `api/*.js` over the mock store, with Vercel's filesystem-then-rewrites order, its JSON body parser, and Vercel Authentication with an automation bypass secret.
    - Each check is planted both ways, VERIFIED and BROKEN, plus its COULD NOT LOOK cases.
    - Protection is planted both ways. With the right secret the checks run, every request carries the secret, and only the first asks for the cookie. With a wrong or missing secret, every check is COULD NOT LOOK after one request. A plain 401 is still judged per check.
    - The CLI runs as a child process: against the stand-in, against a closed port, and against the protected stand-in with the secret from the environment, with the flag over the environment, and with none.
    - What only a live preview can answer stays the dry run's: Vercel's own parser and static serving, its real SSO page and bypass, and GitHub's read-after-write.
  - Must-fail passes on a scratch copy (harness not committed), one defect at a time:
    - First pass: 34 defects, 33 caught. The one left is an equivalent mutant: the mint's explicit `checkKeyDocument` line is repeated inside `loadCaseSigner`, so removing it alone changes nothing.
    - Bypass pass: 12 defects, 11 caught. The one left is equivalent too: `run` already treats an empty bypass as none.
  - Suite 912 -> 935 tests, 0 fail. Here: 933 pass and the 2 skips 2d names (`KEY DOCUMENT, THIS ENVIRONMENT`, and `LIVE DIFFERENTIAL`, which needs an arcaeon-ledger checkout).

## 2026-10-10: the case protocol, item 2d: a fix pass after the code review of 2c: the sealed check on the reference and the page, no count from a truncated read, the operator's own key, the open quota on a fresh day (no fix needed), a partial conflict count (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** A code review of 2c raised five points. Four were real and are fixed here. The fifth, about the open quota, did not reproduce: its planted test passes on the 2c code, so that code is unchanged.
- **Fix 1: the reference and the page run the full sealed check.** One routine, `lib/_case_seal.js` `sealedRecordReason`, now holds every stored VERDICT to the same check before anything treats it as sealed.
  - It checks the receipt binding (`checkStoredReceipt`; a failure is `verdict_unbound`).
  - Then, if the case is signed, it checks the case's signature under the verifier its `signed_by` names in the key document (`publishedSignatureReason`; a failure is `case_signature_invalid`). An unsigned seal passes, as before.
  - `anchorCase` now calls the same routine instead of running its own two steps, with the same codes.
  - `?op=case-reference` refuses a record that fails with a 409 named by those same two codes plus a `reason`. The check runs before the proof is read and before any row is built, so nothing is written.
  - The case page shows a new state, SEALED RECORD DOES NOT VERIFY, instead of a verdict. It shows the id, the stored status, the failed check and its reason, the key the record names, links to the case file and its history, and the four limits. It shows no verdict word, records, cross-reference, anchor, labels or registrations, and reads no pin or reference row.
- **Fix 2: `liveRecords` never states a count from a truncated read.**
  - The count is 2 as soon as the seal carries its `cross_reference` or one valid row is read.
  - It is 1 only when every listed row was read and judged and none is valid.
  - When the read ends without a valid row and some listed row was not seen (left past the 20-row window, or a row whose read failed), the answer is `indeterminate: true` and `records: null`.
  - A failed row read is now listed in `unreadable` and is no longer counted as an invalid row (`row_unreadable`).
  - The page says "the live count could not be established on this request". Its `recordsWords` throws on anything but 1 or 2, so a null can never fall through to "one record".
  - `?op=case-reference` answers `records_live: null` in that case.
- **Fix 3: the operator's own key.** The operator path for references reads `WITNESS_CASE_OPERATOR_KEY` (`OPERATOR_KEY_ENV`) and never `WITNESS_ADMIN_KEY`. With it unset, the code does what it did before, now documented: a request with no role proof and no bearer is 401 `reference_unauthorized` (the missing bearer is checked first), and one with a bearer is 503 `operator_key_not_configured`. The refusal names the new variable. Deploying the operator path needs `WITNESS_CASE_OPERATOR_KEY` set; until then, no bearer can append as the operator.
- **Fix 4: no change.** The review said `takeOpenQuota` passes the `getFile` wrapper or null into `judgeCounter` and throws on a fresh day. The test was planted first: the first open of a UTC day for a key that has never opened, through the real read path. It passes on the 2c code.
  - `getFile` returns null for a 404, and `judgeCounter` mints a verified empty with value 0 for it.
  - The present `{json, sha}` wrapper is the shape `judgeCounter` reads.
  - The CAS rebuild hook was tested with both shapes (the counter moved, the counter gone).
- **Fix 5: the conflict count carries `partial`.** `lib/_status_data.js` returns `obsPartial`: true when the tree came back truncated, false when it came back whole, null when there is no count.
  - `/status` says "Partial" in the conflict panel.
  - `/api/status.json` carries `conflict_observations.partial` and says so in its `note`.
  - Like the case row's flag, it feeds no verdict.
- **Tests.**
  - `test/case_item2d.test.js` (new, 5): fix 1 with both planted records through both operations; fix 2 with twenty invalid rows then a valid one, plus controls; fix 3 unset and set, through the handler and through the real `verify.js` dispatch; fix 4 planted first; fix 5 on the page and in the JSON.
  - Existing tests, fixtures: `test/case_item2c.test.js` sets the operator's key as `WITNESS_CASE_OPERATOR_KEY` and deletes it from the environment at the top.
  - Existing tests, one expectation changed by fix 1: the 2c page test's real-dispatch arm read a test-key-signed case against the committed key document, which lists no key. It now expects the does-not-verify state (`signer_unpublished`) instead of the verdict with "not listed in the key document". Its verdict assertions moved to the arm whose document lists the key, and an unsigned seal now carries the "verdict through the real dispatch" check. No test was renamed or removed.
  - A must-fail pass on a scratch copy (harness not committed) made 11 mutations, one at a time, across fixes 1, 2, 3 and 5. Each was caught by its own fix's test and by no other.
  - Suite 907 -> 912 tests, 0 fail. Where this was run: 905 -> 910 pass and 2 skips, the named `KEY DOCUMENT, THIS ENVIRONMENT` skip and `LIVE DIFFERENTIAL`, which needs an arcaeon-ledger checkout. Where that checkout is present (the 2c entry's 906 pass, 1 named skip), the expected figure is 911 pass and 1 named skip; that was not run here.

## 2026-10-10: the case protocol, item 2c: six fixes, authorized withdrawal, the reference row, the per-key open quota, the public case page (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** The GPT-5.6 and Gemini 3.1 Pro reviews of 2b found six holes, all accepted (velouria `projects/arcaeon/CASE_PROTOCOL_DESIGN_2026-10-10.md`, "After item 2b"). Withdrawal, the addendum, the open quota and the page were the rest of item two.
- **Fix 1: the anchor retry checks the case's own signature.** `anchorCase` verifies a signed stored case under the verifier its `signed_by` names in the key document before it pins. The entry must be listed and not revoked (a retired key's cases stay trusted). A replaced `sig` is refused `case_signature_invalid`, and no pin is written. An unsigned seal is still pinned.
- **Fix 2: signing fails closed unless the key is published.** `lib/_case_seal.js` loads `.well-known/arcaeon/case-signing-keys.json` with `require()` when it loads, so the function bundle carries it, and freezes it. After the separation rules, the case key must be an ACTIVE entry holding exactly its verifier. Otherwise the seal is unsigned with `key_unpublished`. The document lists no key, so every seal is unsigned until item three mints one.
- **Fix 3: the status row reads nothing but the tree.** `caseAnchorSummary` counts from paths alone: case files, anchored (both registrations and a pin pointer), pending (both registrations, no pin, no withdrawn marker), and withdrawn. It fetches no case file and no pin. `lib/_store.js` `getTree` now carries GitHub's `truncated` flag as a non-enumerable property of the array it returns, and a truncated tree makes the row `partial` on `/status` and in `/api/status.json`. The row's `sealed`, `conflict`, `unreadable`, `read` and `unread` fields are gone.
- **Fix 4.** `checkKeyDocument` refuses an unknown top-level field (`unknown_field`).
- **Fix 5: pinned cases stay in the sealer's window.** The sealer's rotating window includes pinned cases. Their `latest.json` is judged with the `case_seal` judge, and a squatter or an unreadable pin is reported (`conflict`, `unreadable`), including a pin under a case that is not sealed. Nothing is written over.
- **Fix 6: terminal states are skipped.** A case with the marker `cases/<id>/withdrawn` is not considered, by the tree alone. A root read as WITHDRAWN, or as OPEN or COMMITTED past its deadline, is skipped and reported as `terminal`.
- **`POST ?op=case-withdraw`** `{case_id, role, tape_sha256, salt}`.
  - The role proves itself by its commitment preimage. The commitment is recomputed under the named role and must equal the registration file; otherwise 403 `withdraw_unauthorized`.
  - The case is refused if it is VERDICT (`case_sealed`), already WITHDRAWN (`case_withdrawn`), or past its deadline (`expired`).
  - The case object is replaced by the redacted record `{v, case_id, protocol_version, status, opened_at, withdrawal: {by_role, at, salt_sha256}, limits, signed_by, sig, sig_reason}`, signed with the case key or unsigned with its reason. No label and no commitment. `salt_sha256` is the only trace of the preimage kept.
  - Then the marker `cases/<id>/withdrawn` is written, create-only.
  - The CAS on the root decides a race with a reveal; the loser answers 409 (`case_withdrawn` or `case_sealed`). Tested both ways, for real.
  - Registration files stay, public, and the answer says so in words.
- **`POST ?op=case-reference`** `{case_id, cross_reference, role?, tape_sha256?, salt?}`.
  - It writes a create-only signed row, `cases/<id>/references/<8-digit seq>.json`, of record type `case_reference`, with its own judge (`judgeReferenceRow`). The row has no pin of its own and says in words that its anchor is the pins-repository commit and the daily head anchor.
  - Only a sealed case takes a row.
  - The row is appended by a registered role proving itself with its preimage, or by the operator's key (`Authorization: Bearer <WITNESS_ADMIN_KEY>`, compared in constant time). The row records which (`appended_by`).
  - The sealed case's `records` never changes. `liveRecords` derives the live count: 2 when the seal carries a cross_reference or a valid row exists.
  - A row that lands first at the next seq is never written over; the append moves on.
- **The open quota.** Twenty opens per key per UTC day; the twenty-first is 429 `open_quota_exceeded`, with `retry-after` until 00:00 UTC, and writes nothing.
  - The count is a store record in the private usage repository, `case_opens/<sha256 of the key>/<day>.json`, created or updated through the CAS. It is not a per-instance Map.
  - An unreadable counter is 503 `open_quota_unreadable`, never zero.
  - A duplicate opening is refused `case_exists` by a read before the quota is taken, so it spends nothing.
- **The page.** `GET /case/<case_id>`: a `vercel.json` rewrite to `/api/verify?op=case-page&case_id=:case_id`, rendered by the new `lib/_case_page.js` (no thirteenth function).
  - It shows exactly the design's list: the status, the protocol and policy versions, both labels with "Labels are recorded, not verified", the registration times with the derived stamp-commit and registration-record links, the reveal time, the verdict word and the first divergence, and records in words (sealed and live).
  - It also shows the cross-reference, the anchor state computed from the pin ("sealed, not yet anchored" when it is absent), the four limits, and `signed_by` looked up in the key document, which it links.
  - A WITHDRAWN case shows the redacted record and the sentence about its registrations. An EXPIRED case shows the opening and the word.
  - It never shows a tape, a tape hash, a salt, a salt hash or the scope digest. Every value is escaped, the page has no script, and its CSP allows none.
- **Shared.** One signing routine for every record the case key signs (`signRecord`), and one signature check against the document (`publishedSignatureReason`). `admit` returns the resolved open key, which is held in memory only.
- **Tests.**
  - `test/case_item2c.test.js` (new, 18): the six fixes with GPT's two planted tests; design test 10; the withdrawal proof and nothing-kept checks; the race both ways; design test 11; invalid rows; refusals; create-only seqs; the quota; every status of the page; and nothing secret on any page.
  - Existing tests, fixtures: `KEYS_DOC` handed to the seal, the retry and the sealer; the WITHDRAWN fixtures moved to the new redacted form.
  - Existing tests, expectations changed where 2c's rules change the behaviour: the status row (fix 3), the sealer's second run (fix 5), and the dispatched op list. Three of those tests were renamed.
  - A must-fail pass on a scratch copy (harness not committed) planted 37 defects one at a time. The case suites caught all 37.
  - Suite 889 -> 907 tests: 906 pass, 1 named skip, 0 fail.

## 2026-10-10: the case protocol, item 2b: three fixes, the readers, the case_seal record type, signed_by and the key document, the sealer trigger, the key on case-open and the deadline horizon (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** GPT-5.6's code review of 2a found three holes and named four departures to settle before any deploy (velouria `projects/arcaeon/CASE_PROTOCOL_DESIGN_2026-10-10.md`, "After item 2a"). Decisions 5 and 12 were still unbuilt. Withdrawal, the addendum and the page are item 2c.
- **Fix 1: the anchor retry checks the receipt.** `anchorCase` runs the full sealed-receipt check before it pins: the receipt's binding to the reveals, `compared_at` and policy (`checkSealedReceipt`), and a signed receipt's signature under the verifier it carries. A schema-valid VERDICT that fails is refused `verdict_unbound`, and no pin is written.
- **Fix 2: signer separation fails closed.** `WITNESS_CASE_SIGNER_KEY` is used only when it can be shown different from both `WITNESS_LOG_SIGNER_KEY` and `WITNESS_RECONCILE_SIGNER_KEY`: each must be present and parse, and both its verifier string and its key bytes must differ from the case key's. If either is absent or unparseable, the seal goes out unsigned with `key_separation_unverifiable`. A case key that is one of them is `case_key_is_other_key`, even under another name. `sig_reason` now reads `This case is sealed and not signed (<code>): <why>.`
- **Fix 3.** A registration with `stamp_commit: null` cannot reveal. The answer is 409 `commitment_history_missing`; nothing is written and reconcile never runs.
- **The readers.**
  - `/status` and `/api/status.json` no longer list `pins/case` as a namespace. Case anchors get their own row (sealed, anchored, pending, conflict or unreadable), counted from the tree the page already reads, at most 100 case files a render (it says when it read fewer). The row feeds no verdict.
  - `lib/_store.js` `validatePin` reserves the bare namespace `case`, so `pins/case/` holds case seals only.
  - `lib/_logtree.js` is unchanged; a sealed case adds no leaf. The reveal's answer carries `anchor_note`, and `lib/_case_seal.js`'s header says it too: a case pin is anchored by the pins-repository commit and the daily anchor of the repository head, not as a log-tree leaf.
- **The `case_seal` record type.** `lib/_verdict.js` `judgeCaseSeal` takes exactly {namespace, rows: 3, chain, pinned_at, seq: 1, record_kind: "case_seal", auth_level: "case-seal", auth_note}. No cadence field is allowed, and each refusal has its own name. The seal's pin path reads through it. The generic `judgePin` refuses a case seal, by its kind or by its namespace.
- **`signed_by` and the key document.**
  - Every full case object carries `signed_by`, the signing key's id `<name>+<8 hex>`. It is set when the case is signed, inside the signed bytes, and is null when unsigned. Open and committed cases carry null. The schema refuses a signed case without it, or an unsigned one with it. `verifyCase` refuses a verifier that is not the key `signed_by` names (`signer_mismatch`).
  - The verifier is published at `.well-known/arcaeon/case-signing-keys.json`, a static file at the project root (the snapshot keys' pattern and schema, `arcaeon-signing-keys/1`), entries {key_id, verifier, since, note, status}. It lists no key yet: no case-signing key has been provisioned.
- **The trigger.** `lib/_sealer.js` `sealOnce` (the operator's `tools/seal_batch.js`) ends every run with `lib/_case_seal.js` `anchorPending`. One tree read lists the cases that hold both registration files and no pin pointer, and `anchorCase` runs for each. A run reads at most 25 cases, and the window moves on each minute. The pass is idempotent and never changes the chain. Its report is the receipt's `cases` field, and it does not change the exit code. No public `?op` writes a pin.
- **The two rules.** `?op=case-open` requires a bearer key, resolved by the stamp's own `resolveKey` (env keys, then the issued-key store). It costs no credits. No key is 401 `key_required`; an unknown or revoked key is 401 `key_invalid`; an unreadable key store is 503 `key_store_unreachable`. The case records nothing about the key. A deadline more than 30 days after `opened_at` is refused `deadline_too_far`; exactly 30 days is accepted.
- **Tests.**
  - `test/case_item2b.test.js` (new, 17): 16 pass and 1 is a named skip. The skip runs only where `WITNESS_CASE_SIGNER_KEY` is set and checks that key is in the document.
  - Existing tests: three fixtures changed in `test/case_reveal.test.js` and one in `test/case_protocol.test.js`, with no expectation changed: the open key, the log key in the signing env, `signed_by: null` on a hand-unsigned copy, and a well-formed squatter.
  - A must-fail pass on a scratch copy (harness not committed) planted 30 defects one at a time. The case suites caught all 30, each by the test written for it.
  - Suite 872 -> 889 tests: 888 pass, 1 skipped, 0 fail. All 872 earlier names still pass.

## 2026-10-10: the case protocol, item 2a: the joint reveal, the reconcile run, the seal, and commits-for-path (branch `case-protocol-2026-10-10`, local only, NOT deployed, nothing published)

- **Why.** Item one left a case that two parties can open and commit to, and no way to compare their tapes under it. The design (velouria `projects/arcaeon/CASE_PROTOCOL_DESIGN_2026-10-10.md`, "The joint reveal and its refusals", the decisions after the item-one build, and "After the fix pass") has one request carry both reveals and both tapes. The service checks them against the public registrations, runs the existing reconcile once, and seals the case in that request. This entry is unit 2a. Withdrawal, the addendum and the page are 2b.
- **`POST ?op=case-reveal`** (`lib/_case_http.js`, one dispatch line in `api/verify.js`; `api/` stays at 12). The body is `{case_id, reveals: {a: {tape_sha256, salt}, b: {...}}, cross_reference?}` plus the two tapes as `?op=reconcile` takes them: JSON text, base64 or multipart parts, read by that endpoint's own code. The tapes are named by role (`tape_a`, `tape_b`), not by side. The checks run in this order:
  1. The case status: WITHDRAWN is `case_withdrawn`; at or past the deadline by the service clock is `expired`; anything other than COMMITTED is `not_committed`.
  2. The registration files are the authority, and the case object must agree with them (`case_record_inconsistent`, 503). Each registration must still rest on its stamp as registered: size 272, one commit, the same `stamped_at` and commit.
  3. Each commitment is recomputed under the role it was registered to (`commitment_mismatch`).
  4. Each tape's sha256 must equal the committed one (`tape_substituted`).
  5. The case's bound `policy_version` must be the port version this build runs (`policy_unavailable`). A case is never compared under another version.

  Then reconcile runs once (`compare`, the call `?op=reconcile` makes), its receipt is checked deeply, and the case is sealed. Every refusal in that list is a typed 4xx, or a 503 for the store. A refusal carries no verdict, writes nothing and never runs reconcile. All times come from one read of the service clock.
- **The seal** (`lib/_case_seal.js`, new). The case is written as status VERDICT, with `reveals` ({tape_sha256, salt_sha256, revealed_at}; the salt is kept only as the sha256 of its 32 bytes), `verdict` (the receipt in full) and `records` (2 only with a `cross_reference`, which is recorded at the service clock). It is signed under the `lib/_check_record.js` rule (Ed25519 over json-c14n:v1 of the case minus `sig`) with its own key, `WITNESS_CASE_SIGNER_KEY`. That key uses the same signer-string shape as the reconcile signer. It is never the log key or the receipt key; either one, when present, is refused and the case is sealed unsigned. With no usable key, the case is sealed with `sig: null` and a `sig_reason`. The case file comes first and is authoritative. The pin comes second: `{namespace: "case/<case_id>", rows: 3, chain}`, where chain is the sha256 of those same signed bytes. It is written through the store paths `api/pin.js` writes (`pins/case/<case_id>/00000001.json`, then `latest.json`), not over HTTP, so no bearer, meter or credit is involved. If the pin fails after the case write, the case stands and the answer is `pin: "pending"`, computed from the pin's absence and never stored. `anchorCase(case_id)` retries from the stored case file, so a retry cannot change the chain. A different chain already under the namespace is never written over. The sealed object has no `anchor` field and never changes after sealing.
- **The receipt deep check.** Before sealing, the receipt must have exactly the receipt's fields. Its kind, claim and non-claims must be verbatim, and its method block must be this build's own, with a port version equal to the case's `policy_version`. Each received-tape digest must be the tape hash committed for its role. The verdict block and digest must be the comparison's own. `compared_at` must be the reveal's time. When `WITNESS_RECONCILE_SIGNER_KEY` is set, the signature must verify. A receipt that fails is a 500 with nothing sealed. A call index past 2^53 - 1 cannot be stored in JSON without changing the signed bytes and is refused `verdict_not_sealable` (422). The index walk keeps it far below that on any tape that fits the cap.
- **Commits-for-path.** `lib/_store.js` `listCommits(path, opts, target)` (bound by `forTarget`, exposed by `lib/_stamp_store.js`): `GET /repos/{repo}/commits?path=&sha=<branch>&per_page=`. Registration now fills `stamp_commit` from the stamp's history. More than one commit is `stamp_history_ambiguous` (409). An unreadable or empty history is a 503 and nothing is written. A registration never records `null` now.
- **Item 1b's leftovers.**
  - The same registration replayed (same hash, same role) is a 200 that completes or confirms. Either party's replay repairs both projections. Only a different hash is `role_already_committed`.
  - A case WITHDRAWN under a registration's case write is a typed 409 `case_withdrawn`, not a TypeError.
  - The retry that completes a registration rechecks the stamp record and its size.
  - Two new tests: the status rule, and a rebuild that actually writes.
- **Shared, not copied.** `lib/_reconcile_http.js` exports `readFields`, `tapeFrom` and `compare`, and `handleReconcile` is now built from them. Its answers are unchanged, and every reconcile suite passes as before. `lib/_reconcile_receipt.js` exports `methodBlock`. The reconcile port and stamp billing are untouched, and no dependency was added.
- **Mock.** `test/helpers/mock_store.js` serves `GET /repos/<repo>/commits?path=`, newest first. Every PUT and DELETE is one commit, with a 40-hex sha (formerly `commit-N`). `seed()` gives its path exactly one commit, and `addCommit()` and `forceCommitsFailure()` plant the rest.
- **Tests.**
  - `test/case_reveal.test.js` (new, 17): design tests 6, 7, 8, 9 and 12; the reveal halves of 4 and 5; `policy_unavailable`; the receipt deep check on tampered receipts; the stamp-size reveal path; multipart; the race between two reveals.
  - `test/case_protocol.test.js` (+8, now 35): commits-for-path, `stamp_history_ambiguous`, and the 1b leftovers. Two item-one tests changed their bodies but not their names: the same-hash replay is now 200, and `stamp_commit` is filled.
  - A must-fail pass on a scratch copy (harness not committed) planted 32 defects one at a time; the case suites went red on all 32.
  - Suite 847 -> 872 pass, 0 fail. All 847 earlier names still pass.
- **Not settled here, for 2b.**
  - The witness log's leaf table (`pins/<ns>/<seq>.json`, one level deep) does not include `pins/case/<id>/`.
  - The status page lists every directory under `pins/` as a namespace, so it would read `pins/case` as one.
  - Nothing yet triggers `anchorCase` in production.
  - A reader needs the published case verifier: the case object has no field for it, and the reveal's answer carries it as `sealed_by`.

## 2026-10-10: the case protocol, wiring item one: the case schema, the commitment format, registration (branch `case-protocol-2026-10-10` from `reconcile-endpoint-2026-09-23`, local only, NOT deployed, nothing published)

- **Why.** Two parties who want their agent tape and tool tape compared need each tape fixed before either sees the other's. The design (velouria `projects/arcaeon/CASE_PROTOCOL_DESIGN_2026-10-10.md`, version 2, after the Gemini 3.1 Pro and GPT-5.6 Terra Pro pass) has each party stamp a commitment and register it to a case under its role, first write wins, before one joint reveal. This item builds the case object, the two hashing rules and the registration. The joint reveal, the seal, withdrawal and the page are item two (design tests 6 to 12).
- **`lib/_case.js` (new, no I/O).** The arcaeon-case/1 schema (the design's table; unknown fields refused; `sig: null` needs a `sig_reason`; a stored EXPIRED refused, since expiry is computed on read; WITHDRAWN is the redacted form only). `case_id` = sha256 of json-c14n:v1 over {protocol_version, policy_version, scope_digest, party_a, party_b, opened_at}. Parties are sorted by label, then side, by code point (Python's str order, which differs from JavaScript's `<` on astral characters). A tie on both is refused. opened_at goes to UTC and the fraction is truncated. The deadline is not in the id. `commitment` = sha256 of json-c14n:v1 over {case_id, role, tape_sha256, salt, protocol_version}, with no manifest hash. It is always 272 bytes. Labels holding a lone surrogate or a control character are refused, so Node and Python cannot encode them differently. Every refusal is a typed `CaseError` (`code`, `field`).
- **`lib/_case_http.js` (new) + two dispatch lines in `api/verify.js`.** `POST ?op=case-open` writes `cases/<case_id>.json` (OPEN) in the pins repository, create-only. The same opening twice is `case_exists`. The answer says `parties_reordered` when role a is not the party the caller listed first. `POST ?op=case-commit` takes {case_id, role, commitment_sha256} and nothing else. It reads the stamp through the stamp read path (stamps repository only) and takes `stamped_at` from that record. It writes `cases/<case_id>/commit_<role>.json` create-only and projects it into the case (COMMITTED when both roles are in). Refusals: `role_already_committed`, `late_commitment`, `no_commitment`, `bad_role`, `case_not_open`, `commitment_registered_to_other_role`, `unknown_field` for any caller-sent stamp field, plus typed 503s for an unreadable store or record. Never a 500 for a bad request. The registration file is the authority. If the case update fails after it lands, the answer is `case_update_failed` with `registration_recorded: true`, and re-sending the same registration completes it. `api/` stays at 12 files and `vercel.json` is unchanged.
- **Departures, stated.** `stamp_commit` is `null` in every registration: the stored stamp record does not carry its commit, and the contents read returns only a blob sha, so there is no commit to read from the fetched record. A caller's `stamped_at` is refused (`unknown_field`) rather than ignored, the house rule. Registration cannot see the role inside a commitment hash. It refuses one hash on both roles, and the reveal (item two) recomputes under the registered role.
- **Tests.** `test/case_protocol.test.js` (23): design tests 1, 2, 3, 4, 5 and 13, plus schema refusals. `test/fixtures/case/c14n_cases.json` holds canonical bytes written by arcaeon_ledger's own `_canon_json` (`test/fixtures/case/make_fixtures.py`, `py -B`, ledger checkout untouched): 5 case-id cases over 24 inputs and 4 commitments. Node matches byte for byte. Break arms in the tests: caller order, UTF-16 sort, skipped time normalization, manifest hash, unsorted JSON. A must-fail pass on a scratch copy (harness not committed) planted 17 defects one at a time and caught all 17. Suite 820 -> 843 pass, 0 fail.
- **Item 1b, 2026-10-10: the fix pass after the two code reviews (Gemini 3.1 Pro, GPT-5.6), four holes and four tests, nothing else.** (1) Every case update rebuilds `commitments` from both registration files (`commit_a.json`, `commit_b.json`, read through the same store), and so does the race-rebuild hook. A case whose role-b file landed but whose projection failed becomes COMMITTED when role a registers, with no retry by b. (2) The fetched stamp record must say `size: 272` (`COMMITMENT_BYTES_LENGTH`). Any other size, or none, is refused `stamp_size_mismatch` (409) and nothing is written. A party that stamped its tape hash instead of its commitment bytes stamped the wrong thing, and the size is the cheapest tell (a tell, not a proof; the reveal's recomputation is the proof). (3) `readJsonBody` also caps a body that arrives already parsed (Vercel parses application/json): its JSON.stringify form in UTF-8 bytes, the same 413 `too_large`. (4) `applyRegistration` only moves OPEN to COMMITTED and never computes a status from the commitments. Other statuses were already refused `case_not_open`. Tests: four, titled ITEM 1B, each with a MUST-FAIL ARM. On scratch copies, each fix reverted alone failed its own test and no other. Fix 4 has no test of its own (none was asked for); a direct check showed the old computation turning COMMITTED back into OPEN. Suite 843 -> 847 pass, 0 fail; all 843 earlier names still pass.

## 2026-09-25: batch lane H, B077 to B080 (branch reconcile-endpoint-2026-09-23, local only, NOT deployed)

- **B077.** test/logtree_keygen.test.js skips the .gitignore check outside a git checkout and prints why; in a checkout it runs as before.
- **B078.** README says the credit packs are sold (listed, checkout works, no real purchase yet). The welcome email and the fulfil page name the Stripe receipt link as how a lost key is recovered. Render only, no sender wired.
- **B079.** lib/_ratelimit.js counts in a shared store (Vercel KV or Upstash REST, chosen by env) instead of per instance; memory store is the test stub and the fallback. check() is async and every call site awaits it. Shared counting is off in production until the KV env vars are set.
- **B080.** Status data carries one line per observed conflict, what it was and how it resolved; /status and /api/status.json print the same sentences.
- **Tests.** node --test "test/*.test.js": 820/820.

## 2026-09-23 (late night): the battery plants a record each fence must refuse (branch `reconcile-endpoint-2026-09-23`, local only, NOT deployed, nothing published)

- **Why.** The battery line says a check is DEFINED and was CALLED. Neither can see a check that ran and saw nothing: a fence whose refusal is removed is still defined, still called, and on a clean day every record passes it anyway (a correspondent measured the class as "0 of 17 probes noticed a guard removed"). This is the third guard, promised publicly for 2026-09-24.
- **`lib/_battery_plants.js` (new).** Every run builds, in memory, one PLANTED BAD record per fence and one PLANTED GOOD record, signed with two throwaway Ed25519 keys made for that run (neither is stored, neither is in any OPERATOR_KEYS). The seven plants follow the seven real fences: a byte order mark (`check_byte_order_mark`), a malformed JSON body (`check_json`), a `rerun` naming a drive (`check_rerun_portable`), a body edited after signing (`check_record_verifies`, bad_signature), a name saying broken over a body saying VERIFIED (`check_path_result`), a record filed under another namespace (`check_record_path`), a key nobody declared (`check_key_declared`). Each bad plant is judged by its own fence called directly, not by the chain, because a later fence often refuses the same record for another reason and would hide the removal (verifyCheckRecord also refuses a non-portable rerun). A plant counts as caught only when its fence refuses with that fence's own reason. The good plant goes through the whole chain in order and must pass every fence. A fence with no plant, or a plant whose fence is gone, is missed too. The module has no file access: plants never enter the publish set, the dry-run list, the checks/ store or the --dir the daily task writes into; the header says so.
- **`tools/publish_self_checks.js`.** Every run prints `plants: P planted, Q caught, R missed [fence names]` on stderr directly after the battery line, including refused days and days with no records. R > 0 prints `REFUSED: plants: <fence>: plant <name> ...` naming the fence and the plant, and the run exits 2, nothing published, before any token read or network call. The red word stays REFUSED; no new verdict word. `--break-plants [FENCE]` (default `check_record_verifies`) swaps that fence for a blind one of the same name for the real records and the plants alike: the battery line stays green, the plants line goes red. Record format, refusal reasons and the order of the fences are unchanged.
- **Not planted:** an oversize body and a stale timestamp. The publisher has no size fence and no staleness fence (fence 1 refuses only future-dated records), so there is nothing to plant against; adding either fence would now require adding its plant.
- **Real dry run** (8 records for 2026-09-23, operator keys from the pins checkout): clean `battery: 7 defined, 7 called, 0 orphaned []` / `plants: 8 planted, 8 caught, 0 missed []`, exit 0; with `--break-plants` `plants: 8 planted, 7 caught, 1 missed [check_record_verifies]` and `REFUSED: plants: check_record_verifies: plant bad_signature passed (expected refusal bad_signature); ...`, exit 2, nothing listed.
- **Tests:** `test/battery_plants.test.js` (13, same file in both witness trees): one plant per fence; all caught on a clean battery; each of the seven fences blinded in turn misses exactly its own plant; a wrong-reason refusal is not a catch; coverage both ways; clean CLI run with the plants line directly after the battery line; the `--break-plants` arm (default and named fence); the good plant refused by a fence broken to refuse everything; the no-records day; line order with both break arms on; plants absent from the dry-run list and bytes, the plan and the --dir; the vocabulary. Suite 796 pass (785 before the battery guard came over from the other tree, see the cherry-picked "battery says when it was not there" entry below) -> 809 pass, 0 fail. Break arms on the guard itself: plants that always report ok fail 7; counting every bad plant as caught fails 6. Shared files byte-identical to the release-candidate tree: `tools/publish_self_checks.js`, `lib/_battery_plants.js`, `test/battery_plants.test.js` (and `lib/_battery_inventory.js`, `test/battery_inventory.test.js` from the cherry-pick).

## 2026-09-23 (night): the locked Arcaeon mark on every witness page (branch `reconcile-endpoint-2026-09-23`, local only, NOT deployed, nothing published)

- **Why.** The mark inventory (velouria `bridge/tmp/MARK_EVERYWHERE_INVENTORY_2026-09-23.md`) found no witness page carrying the mark: `lib/_page.js` said there was "no logo asset" and fell back to a text wordmark, and the reconcile page had no branding at all. arcaeon.io got the locked C2 mark the same day; this is the witness half.
- **`lib/_brand_mark.js` (new).** The one copy of the mark here: `markSvg(px, ground)`, `headerMark(ground)` (30 px), `footerMark(ground)` (20 px plus "arcaeon.io"), `FAVICON_LINK`. Geometry is `brand/arcaeon_mark_C2.svg` exactly (gold #e0a73c outer stroke 9, inner stroke 6.5, #e8eef3 on dark and #13233A on light, miter joins, square caps). Grounds `dark`, `light`, `dark-auto`, `light-auto`: the auto ones flip the inner chevron with the page's own colour-scheme media query. Twin of arcaeon.io's `brand_mark.py`.
- **Pages.** the /status page, the navy shell every fulfill and balance page renders through (`lib/_page.js` `pageShell`), and the /reconcile page (`lib/_reconcile_page.js`; the mark and the favicon link go in by placeholder slots filled at module load, because the page literal must hold no template syntax; it had no wordmark, so it gains a small uppercase "Arcaeon" one beside the mark): header mark 30 px beside the wordmark, footer mark 20 px plus "arcaeon.io", and `<link rel="icon" type="image/svg+xml" href="/favicon.svg">` in the head. The shell keeps its `<div class="wordmark">Arcaeon</div>` byte for byte, now inside a centred row with the mark.
- **`favicon.svg` (new, deployment root).** A byte copy of arcaeon.io's favicon: the mark on navy #13233A with 20 percent rounded corners. It sits at the root, next to PRACTICES.md, and not in a `public/` folder on purpose: with no framework preset Vercel would take a `public/` folder as the whole output directory and stop serving the root files (/PRACTICES.md is served from the root today). The new test pins that no `public/` exists.
- **Not changed:** no JSON, no API response, no verdict text, no vocabulary word. The welcome email (`lib/_welcome_email.js`) is not branded: it is an email, not a served page, and mail clients such as Gmail strip inline SVG.
- **Tests:** `test/brand_mark.test.js` (new, same file in both witness trees): the helper's geometry on each ground; favicon.svg's rect and paths; and every served HTML page carries the outer and inner mark paths exactly twice (header + footer), one 30 px and one 20 px mark in that order, "arcaeon.io" in the footer, and the favicon link exactly once, in the head. Suite 778 pass -> 785 pass, 0 fail.

## 2026-09-23 (evening): the audit headline says COULD NOT LOOK, the badge's spelling (branch `reconcile-endpoint-2026-09-23`, local only, NOT deployed)

- **Why.** The Fable audit's item 1 example: on one status page the badge for a namespace the render did not fully read said COULD NOT LOOK while the headline above it said "N not fully read." One page, two spellings for one fact.
- **`lib/_audit_status.js`**: one constant, `COULD_NOT_LOOK_WORD = "COULD NOT LOOK"`, now feeds the badge (both branches), the headline count ("2 COULD NOT LOOK.") and the superseded line; exported. The JSON twin's machine values (`state: "NOT_FULLY_READ"`, `badge: "NOT FULLY READ"`, `counts.not_fully_read`) are frozen wire values and did not move.
- **`tools/publish_self_checks.js`**: the refusal line on stderr prints `COULD NOT LOOK:` with spaces, like every other tool; `err.outcome` keeps its hyphenated internal value.
- **Tests:** `audit_status_page.test.js` headline pin moved to "2 COULD NOT LOOK." with the old spelling asserted absent, plus one new test that the headline and the badge (partial and no-data) carry the same words and that `NOT_FULLY_READ` is unchanged; `audit_reader_newest.test.js` also asserts no COULD NOT LOOK count when nothing was left unread.

## 2026-09-23 — reconcile port tracks the hardened reconcile.py (branch `reconcile-endpoint-2026-09-23`, local only, NOT deployed)

- **Why.** arcaeon-ledger `reconcile-hardening-2026-09-23` (a31402f) made reconcile.py answer COULD NOT LOOK on the three inputs it used to raise on, with the cause in brackets, and bounded nesting at 512. The port must say the same bytes.
- **`lib/_reconcile_tapes.js`**: `REFERENCE.reconcile_sha256` -> `42e8231b...a918`; a `cannotRead` pre-pass mirroring `_cannot_read` (nesting counted before the parser's stop, whole line after a 4300-digit int; duplicate key that does not parse); the three messages in the Python's words; `peekSide` skips any unreadable line.
- **Fixture**: `make_fixtures.py` pins the hardened file and drops `python_raises`/`port_expect`; 517 cases, 10 expected answers changed (9 former raises, `nested_522_both`). Conformance test drops the "reference implementation raises" assertion. `npm test` 777/777; live differential green on 6 seeds.

## 2026-09-23 — the hosted completeness verdict: `POST /api/reconcile` and the `/reconcile` page (branch `reconcile-endpoint-2026-09-23` from `9bbf79a`, local only, NOT deployed)

- **`lib/_reconcile_tapes.js`**: a Node port of `arcaeon_ledger.reconcile` (arcaeon-ledger 0.8.0) and the strict `verify_file` it rests on, with Python-faithful reading (errors="replace" decoding with the BOM kept, universal newlines, `str.strip()`, json.loads's int/float split, BigInt ints, the 4300-digit limit, NaN/Infinity, lone surrogates, duplicate keys raised on object close) and the chain's exact `json.dumps` + surrogatepass. Ported rather than shelled out: no Python on the Node runtime and no function slot for a second one. Where reconcile.py raises (three input classes, found here), the port says COULD NOT LOOK and why; nesting past 512 is COULD NOT LOOK; pins are refused, not ported.
- **`lib/_reconcile_http.js`** (+ dispatch in `api/verify.js`, two rewrites in `vercel.json`; `api/` stays at 12): JSON (text or base64) or multipart, 1 MB per tape and 3 MB per request, typed 4xx refusals, no persistence, the verify rate limiter. Returns reconcile.py's dict key for key, the signed receipt, and the service's limits.
- **`lib/_reconcile_receipt.js`**: "these two tapes, as submitted, compared like this at this time", signed Ed25519 over json-c14n with the checkpoint key shape under its own variable `WITNESS_RECONCILE_SIGNER_KEY` (unsigned and saying so when unset; never the log key). Binds both tapes' sha256, the verdict and its digest, the method and the time; the disclaimers are inside the signed bytes.
- **`lib/_reconcile_page.js`**: the `/reconcile` page, completeness.html's style, textContent-only rendering, the legend and the honest limits.
- **Tests**: conformance against 493 cases written by the real reconcile.py (156 harvested from the cross-repo suites, 21 ledger, 96 edge, 220 fuzz), the same through the endpoint, a live Python differential (skips without Python), receipt and endpoint suites with break arms. Suite 718 -> 776, 0 fail. See `RELEASE_NOTES_reconcile_2026-09-23.md`.

## 2026-09-23 — the battery says when it was not there (branch `release-candidate-2026-09-23b` commit `34e05b1`, cherry-picked onto `reconcile-endpoint-2026-09-23` so the two trees carry the same publisher; local only, NOT deployed, nothing published)

A correspondent found three of four selftest functions in their library defined and called by nothing, while their daily beat reported green. The same guard, here:

- **`lib/_battery_inventory.js` (new).** Parses a battery's own source for `function check_*` / `async function check_*` / `const check_* = (...) =>` definitions, compares them against the names the runner recorded as it called them, and returns one line: `battery: N defined, M called, K orphaned [names]`. Orphaned = defined and not called. K > 0, or no checks at all, is not green.
- **`tools/publish_self_checks.js`.** The per-record fences are now the battery: seven named `check_*` functions in an exported `CHECKS` registry, run in the same order with the same refusal reasons (no behaviour change for any record). The runner records every call. Every run prints the battery line on stderr (so it lands in the daily task's log), including refused days and days with no records. Any orphan refuses the run with the existing word, `REFUSED: battery: ...`, exit 2, nothing published, before any token read or network call. `--break-battery` appends one never-called check to the source the inventory reads, to show the red on demand.
- **Not changed:** the check record format (its top-level fields are strict, so the line is not written into records), `tools/self_check_daily.js`, and verifier two (`verify.py`, outside this tree).
- **Tests:** `test/battery_inventory.test.js` (11): parser, green, orphan, empty battery, call-before-throw, registry equals parsed definitions, clean CLI run, no-records run, and three break arms (the flag, a function added to the source but not to `CHECKS`, a runner that skips a registered check). Suite 718 -> 729, 0 fail. Break arm: an inventory that always says ok fails 5.

## 2026-09-23 — D1 literal: the result goes in the check record's file name (branch `release-candidate-2026-09-23b`, local only, NOT deployed, nothing published)

The helm's ruling on D20: per-key newest 3 stands, and a BROKEN must stay permanent however many later records its own key publishes.

- **Path scheme (D22).** `lib/_check_record.js` `checkRecordPath` now writes `checks/<type>/<ns>/<checked_at>-<keyid8>-<result>.json` (`verified` / `broken` / `could_not_look`, from the record's own `result`). New `parseRecordFileName` and `pathResultMismatch`. Changed before the first publish; fixed from here on.
- **Reader.** `lib/_audit_status.js` reads, per key, the newest 3 files plus every older file whose name says broken (at most 20 extra per key; beyond that the namespace is COULD NOT LOOK with a note). A verified BROKEN keeps the namespace BROKEN regardless of later same-key records. The safety cap grows by exactly the extras selected. A file whose name-result disagrees with its signed body is refused (`path_result_mismatch`) and makes its namespace COULD NOT LOOK; same for outside sources. JSON twin gains `records_broken_older_read` and `path_result_mismatch` (flag on only).
- **Publisher.** `tools/publish_self_checks.js` pre-flight refuses `path_result_mismatch` before anything is sent. Records written under the old scheme are refused as `path_mismatch`.
- **Writer.** `tools/self_check_daily.js` and `tools/check_and_sign.js` pick up the new name through `checkRecordPath`; headers updated.
- **Tests:** the `D20 RESIDUAL` test is now `D20 RESIDUAL CLOSED` (a BROKEN survives 3, and 30, later same-key records); new `D22 BOUND`, `D22 NAME IS A CLAIM` (repo and outside source), `D22 pre-flight`, and a parse/mismatch test; path expectations updated in four files. Suite 713 -> 718, 0 fail. Break arms: reader ignoring broken-named files fails 4; reader accepting a mismatch fails 2; publisher accepting a mismatch fails 1. Flag-off tests unchanged and passing.

## 2026-09-23 — the two go-live blockers: reader budget and a local path in `rerun` (branch `release-candidate-2026-09-23b`, local only, NOT deployed, nothing published)

- **Reader reads the newest records (D20).** `lib/_audit_status.js` no longer reads every check record oldest first under a flat cap of 100 (8 namespaces of daily self-checks went COULD NOT LOOK from day 13). Per namespace it groups the listed record files by checker key (the keyid8 in the file name), orders them newest first by the file-name timestamp, and reads the newest 3 of each key. Older same-key records are superseded (every check is a full re-run over the whole history) and do not make a namespace partial; the cell says how many were not read. Slots are per key, not per namespace, so our own daily volume cannot push an outside checker's BROKEN out of the read set. Global cap `recordReadCap(n) = n * (3 * 4 + 1)`, a safety net. JSON twin gains `records_older_not_read`. Behind the same flag; flag off unchanged.
- **Portable `rerun` (D21).** `lib/_check_record.js` refuses a drive letter, a home-directory path or a backslash in `rerun` (`rerun_not_portable`), at sign and at verify; `tools/publish_self_checks.js` refuses it in pre-flight too. `tools/check_and_sign.js` (and so `tools/self_check_daily.js`) writes `PUBLIC_VERIFIER` (`verify.py`, a placeholder: verifier two is not published anywhere) instead of the local `--verify-py` path. The page's `rerunCommand` uses the same constant.
- **Tests:** `test/audit_reader_newest.test.js` (8), `test/rerun_portable.test.js` (4); one budget test in `test/audit_status_page.test.js` now fills the cap with many keys. Suite 713, 0 fail.

## 2026-09-23 — the self-check publisher (branch `release-candidate-2026-09-23b`, local only, NOT run live, task NOT registered)

- **`tools/publish_self_checks.js`**: puts the daily self-check records into the pins repo at the paths `lib/_audit_status.js` reads (`checks/<type>/<ns>/<checkRecordPath>`), bytes unchanged, through the GitHub contents API with the genesis checkpoint's auth (velouria `.env` `GITHUB_TOKEN`, Bearer, one PUT per file to `main`). Every record is verified (shape, signature, path, key declared locally and in the published `OPERATOR_KEYS.json`) before anything is sent; any failure publishes nothing. Create-only and idempotent by git blob sha. `--dry-run` reads no token and makes no network call.
- **`tools/self_check_daily_run.ps1`** (new) and **`tools/install_self_check_task.ps1`**: the task is now write, then publish (`--days 7`); the publish step fails soft and logs one line; the task's result is the write step's.
- **Found, not fixed:** the reader's 100-read budget is used up by day 13 of daily records (measured); the task should not be registered until the reader reads only what it needs. See the release notes 2026-09-23c addendum.
- **Tests:** `test/publish_self_checks.test.js` (12). Suite 701, 0 fail. Break arm: ignoring `bad_signature` in the publisher fails 1.

## 2026-09-23 — release tree three: slice 2 + vocabulary merged; `velouria-selftest` superseded as a test namespace on the audit surfaces (branch `release-candidate-2026-09-23b`, local only, NOT deployed, flag still off)

- **Merged** `audit-state-slice2` (`f4ab63d`) and `vocabulary-2026-09-23` (`9eac76a`). Two conflicts, both in wording: this file (both entries kept) and `lib/_audit_status.js` (slice 2's outside-sources comment and partial cell kept, with the vocabulary pass's COULD NOT LOOK on the human text). The JSON twin's machine value `state: "NOT_FULLY_READ"` and its `badge` text are unchanged: the vocabulary pass moves no JSON field and no exit code.
- **Superseded test namespaces (the helm's call on design B10 item 5).** `lib/_audit_status.js` now reads `superseded/<ns>.json` from the same tree listing, flag on only. A namespace with a readable v1 supersede record for itself keeps its row and its DERIVED state (no sixth state word; a BROKEN is permanent, D1), gains a grey "superseded test namespace" tag, and is left out of the headline and the BLIND-first aggregate, with one sentence in the summary naming it, its state, the record and the reason. JSON: the namespace keeps `state` and gains `superseded` (`counted: false`); the summary gains `counts.superseded_test` and `superseded_test_namespaces`. A supersede file that is present but not a readable supersede record for that namespace is ignored and noted, so the row stays COUNTED. D19.
- **`tools/install_self_check_task.ps1`**: the daily self-check as a scheduled task (03:30, after the checkpoint and the anchor), modelled on velouria's `install_logtree_checkpoint_task.ps1`. Not registered. It writes records to a local out dir; nothing publishes them into `checks/` yet, which the header says.
- **Tests:** `test/audit_superseded.test.js` (11). Suite 678 after the merges, 689 now, 0 fail, 0 todo. Break arms: accepting any supersede file fails 6; keeping superseded rows in the totals fails 2.
- **Flag off:** `/status` and `/api/status.json` byte-identical to production (`8242bfa`) on a healthy and a mixed store, including with `checks/` and `superseded/` files present in the store (the flag-off render reads neither: same 22 store reads).

## 2026-09-23 — vocabulary pass: the note says VERIFIED / BROKEN / COULD NOT LOOK (branch `vocabulary-2026-09-23`, local only, NOT deployed)

The Fable audit (2026-09-22, section 1) found four verdict languages across the Arcaeon tools; `witnessed: null`, UNDETERMINED and COULD NOT LOOK were three names for "did not get to look". The helm's decision: one word per meaning, on every surface.

- **`api/verify.js`: no JSON field moves.** `witnessed` is still `true` / `false` / `null`, every `reason`, every status code and every other field is unchanged, so no client breaks. The human text beside them now opens with the word: the `note` (or, with no note, the `error`) starts `VERIFIED: ` for `true`, `BROKEN: ` for `false` (the record contradicts the head asked about), `COULD NOT LOOK: ` for `null` and for a `409` / `5xx` with a reason. A `400` (the question was malformed) carries no word. Done in one wrapper (`speak()` around the renamed `judgeItem()`), so single and bulk answers get the same words.
- **`lib/_audit_status.js` (behind `WITNESS_AUDIT_STATE`, off):** "NOT FULLY READ" is now COULD NOT LOOK, and "N attempted checks could not complete" is "N attempted checks: COULD NOT LOOK". The state words (BLIND / SELF-CHECKED / CHECKED / STALE / BROKEN) and the check-record `result` values are unchanged.
- **README:** the tri-state paragraph names the word beside each value, adds `history_unreadable`, and says a 503 / 409 with a reason is a third answer, not an outage.
- **Tests:** new `test/verify_vocabulary.test.js` (6) pins the word AND the unchanged field for true, false, null, a 503 refusal, a 400 (no word) and no double prefix; `test/audit_status_page.test.js` asserts the new words. Suite 646 before, 652 after, 0 fail, 0 todo.

## 2026-09-22 — audit state slice 2: operator keys, daily self-check, outside records by URL, JSON twin (branch `audit-state-slice2` from `release-candidate-2026-09-23b`, local only, NOT deployed, flag still off)

Slice 1 (live behind `WITNESS_AUDIT_STATE` unset) could render BLIND and SELF-CHECKED but nothing let CHECKED happen: no key declaration existed, no self-check writer existed, and an outside record could only arrive by a commit of ours. Design page B10 addendum; interpretive choices D13 to D18 in `DISAGREEMENTS_audit_state.md`.

- **`tools/operator_keys.js`.** Prints the `checks/OPERATOR_KEYS.json` document (public keys only) for the keys we hold: the witness-log checkpoint key, read from `docs/LOGTREE_KEY_RUNBOOK.md`'s "current verifier" row with its key hash checked and converted to the check-record id over the raw 32 bytes, plus any `--check-key` (PEM, private or public, or an `ed25519:` id). `--out` is create-only. Never publishes.
- **`tools/self_check_daily.js`.** The operator's daily SELF-CHECKED writer: `check_and_sign`'s record builder over verifier two's JSON, one record per namespace at HEAD, in `checks/pin/<ns>/<ts>-<keyid8>.json` under `--out`. Dry run by default; `--write` is create-only. Refuses a signing key that is not in the OPERATOR_KEYS document it is handed (an undeclared key's self-check would read as an outside check). Velouria's daily job is not touched.
- **Outside sources.** `lib/_audit_status.js` reads `WITNESS_CHECK_SOURCES` (GitHub repo, raw GitHub base, or any https base with `checks/INDEX.json`), lists and fetches `checks/**` read-only, and folds the records in under the same rules as repo records; the KEY decides what a record can reach. Budget: 40 fetches per render across all sources, 64 KiB per body (streamed and cut off), 5 s timeout, redirects refused, at most 8 sources, never the pin token (`WITNESS_CHECK_SOURCES_TOKEN` is its own variable). Fail closed: an unlistable source leaves every namespace NOT FULLY READ; an unread record leaves its namespace NOT FULLY READ. Same signed record in two places counts once. No `api/check.js`: `api/` is at 12 functions (test counts them).
- **`lib/_status_json.js`.** With the flag on, every namespace carries `audit` (state, badge, line, counts, dates, outside keys, source counts) and the top level carries `audit` (headline, BLIND-first counts, notes, sources). A NOT FULLY READ namespace carries no state word. Flag off: no `audit` key and `checks/` is not read.
- **Live dry run** (verifier two over the public pins repo, a key minted for this at `C:/Users/USER/.arcaeon/witness-selfcheck.pem`, records written to the session scratchpad only, `/status` JSON rendered against the live repo with those records standing in for `checks/`): 8 namespaces, 7 SELF-CHECKED, 1 BROKEN (`velouria-selftest`, verifier two's D2 reading of its refused-head observation), 0 CHECKED.
- `test/audit_state_slice2.test.js`, 26 tests, break arm per part. Mutation-checked: removing the daily key fence, the source fail-closed flag, the fetch budget, the flag check in the JSON twin, the signature dedupe, the redirect refusal, or either body cap each fails at least one test (the stream-cap mutation hangs on the endless-stream fixture). Suite 672, 672 pass, 0 fail, 0 todo.

## 2026-09-22 — fulfill: legacy manual-reconcile record renders again; a red record is refused, not "reload" (branch `release-candidate-2026-09-23b`, local only, NOT deployed)

Found by a read-only scan of the live usage repo: one real customer's fulfillment record (written 2026-08-18 by a manual reconcile: `mode: manual_reconcile`, `prefix_source: env_key_manual`, `namespace_prefix: null`, key present) is refused by this tree's fulfillment judge as `key_or_prefix_unreadable`. Production re-shows it with a null prefix (`nullmain`); this tree threw the red into the catch-all and answered 502 `store_error`, `retry_safe: true`, "reload this exact URL", on every reload. Fixed in code; no data was written.

- **The rule** (`api/fulfill.js` `fulfillmentRule`, run through `verdict.judgeWith` so the green is bound to the read): key must be a non-empty string; a non-empty `namespace_prefix` passes as before; `namespace_prefix === null` with `prefix_source === "env_key_manual"` is the one recognised legacy shape, and its prefix is resolved the way pin.js resolves the key at pin time, `store.keyPrefixFor(key)` over `WITNESS_KEYS`; key not there -> red `legacy_record_key_not_configured`; any other null-prefix record stays red `key_or_prefix_unreadable`. The green carries the prefix, and the page renders only what `renderPrefix(v)` (requireGreen, bound to "fulfillment record") hands it.
- The resolved prefix is for rendering only. It is not written into the fulfillment record or the issued-key record: copying an env binding into the store would keep authorizing the key after the env entry is removed. JSON gains `prefix_resolved_from: "WITNESS_KEYS"` on that path only.
- **Refusals.** A red fulfillment record is refused in place, and the catch-all now maps any `RedVerdictError` to `verdict.refusal` (503, named reason, `retry_safe: false`, support named), matching api/pin.js on this tree, instead of the 502 `store_error`. The not-configured case says: "this record predates prefix binding and its key is no longer configured; contact support".
- `test/fulfill.test.js` +5: LEGACY renders with the WITNESS_KEYS prefix (and writes nothing back); LEGACY key gone -> named 503 refusal; null prefix with any other prefix_source stays red; record-level red is 503 not 502; BREAK ARM: hand-built greens (literal, spread copy, frozen copy, copy with a real read_id) and a green about another record cannot reach the page. Mutation-checked: `renderPrefix` returning the raw prefix fails the break arm; removing the legacy branch fails three.
- Suite 646, 646 pass, 0 fail, 0 todo.

## 2026-09-23b — second release tree (branch `release-candidate-2026-09-23b`, local only, NOT deployed)

`release-candidate-2026-09-23` (`1266d39`, production `dpl_4dBieifo`) plus `log-tree-golive`, `merkle-fix` and `verdict-required`, merged in that order. See `RELEASE_NOTES_2026-09-23b.md`.

- Conflicts in `lib/_stamp.js` (3 hunks), `api/verify.js` (1) and this file. Both behaviours kept: the S-1 compare answers 409 `record_mismatch` first, then `sendStamp` builds the answer through the verdict; verify keeps W-1/W-2 and passes the record's verdict to `witnessedResponse`.
- `test/stamp_failure_conformance.test.js` +6 (S-1 CONTRACT, GET and POST): after the merge, the break arm "GET skips the sha compare" failed nothing, because `judgeStamp` refuses the same record; the new cases pin the 409 itself.
- Flag-off `/status` and `/api/status.json` byte-identical to `1266d39` on a healthy and a mixed store; the intended differences (uncounted conflicts, a head that is not a pin) are listed in the notes.
- Suite 641, 641 pass, 0 fail, 0 todo.

## 2026-09-22 — inclusion proofs bind tree_size and refuse a bare leaf hash (branch `merkle-fix` from `release-candidate-2026-09-23`, local only, NOT deployed)

Closes the two false-yes findings the Merkle failure-conformance suite left as `todo`. The batch path is still behind `WITNESS_BATCH_SHADOW`; nothing about when it runs changed.

- **M-1, wrong tree_size accepted.** `lib/_merkle.js` `verifyInclusion` used to consume whatever siblings the proof carried, so a 4-leaf proof re-labelled tree_size 5 or 6 still verified. It now walks the tree shape fixed by (leaf_index, tree_size): the path must hold exactly the siblings that shape needs (`path_too_short` / `path_too_long`). Some wrong sizes share a path shape with the real one (leaf 3 of 7 vs of 6), and the root alone does not commit the count, so `verifyInclusion(proof, published)` takes the published root.json record and refuses `tree_size_mismatch` / `published_root_mismatch`. Every ok result carries `tree_size_bound`, false when no record was checked, so an unchecked size is never reported as confirmed. `tools/reconcile_batches.js` now passes root.json's own tree_size.
- **M-2, interior node accepted as a leaf.** A proof with only `leaf_hash` used to take the hash on trust. The leaf record is now required (`leaf_required`) and its hash is always derived under the 0x00 prefix; a supplied `leaf_hash` must match the derived one. No production minting path produced hash-only proofs (`lib/_batch.js` buildProof always includes the leaf).
- `MERKLE_BATCHING_DESIGN.md` §5 pseudocode updated to the tightened algorithm.
- `test/merkle_failure_conformance.test.js`: both todos are real assertions with typed reasons, plus a path-length test. Suite 579, 579 pass, 0 fail, 0 todo.

## 2026-09-22 — witness log go-live prep: the signing key, its runbook, the README key (branch `log-tree-golive` from `release-candidate-2026-09-23`, local only, NOT published, NOT deployed)

The owner decided the checkpoint signing key lives on Vercel (env var on this project) and that this push deploys when done; the helm verifies and publishes. Nothing here wrote to Vercel, pushed, or touched the pins repo.

- **`tools/logtree_keygen.js`.** Mints one Ed25519 pair in `lib/_checkpoint.js`'s own key format (no second key format). Prints ONLY the verifier key and the env var name the publisher expects, `WITNESS_LOG_SIGNER_KEY` (`--key-env`). The signer goes only to `--out`, which must end in `.signer.key`, is created exclusively (an existing file is refused and left byte-identical; rotation is a new name and a new file), mode 0600, and on Windows `icacls`-restricted to the current user. Before reporting success it re-reads the file, signs a throwaway note and verifies it with the printed verifier; on failure the file is deleted. `.gitignore` gains `*.signer.key`. `test/logtree_keygen.test.js`, 4 tests; break arms: a keygen that echoed the signer is caught by a scan of stdout and stderr in both output modes, and a different key must get COULD NOT LOOK from `follow.js`.
- **The real key was minted** (outside every repository, `C:\Users\USER\.arcaeon\witness-log.signer.key`): `arcaeon.io/witness-log/2026-09-22+09765dec+AdKhx0P0WL2jig0oBbA5OC4I/Yu7dyiA54ju7lcMgQ07`. The key name is dated so a rotation is readable on the signature line.
- **`docs/LOGTREE_KEY_RUNBOOK.md`.** How the helm puts the signer on Vercel (`POST /v10/projects/{id}/env`, `type: encrypted`, `target: ["production"]`, value read from the file by a script, never on a command line; read-back by key without the value), why `encrypted` over `sensitive` is a trade the owner should see (an encrypted value can be read back by anyone with a team token), how rotation works (new dated key, overlap by signing with both since a note carries several signature lines and checkers ignore keys they were not given; old checkpoints stay verifiable by the old key forever, nothing is re-signed), what to do if it leaks, and where the public key is published. It states plainly that the key now lives in two places: Vercel, and the local file the daily job signs with, because the job runs on the operator's machine (`api/` is at its 12-function cap). Nothing deployed reads `WITNESS_LOG_SIGNER_KEY` yet.
- **README, new section "Witness log".** The file layout under `log/` in the pins repo, the checkpoint key, how to run `follow.js`, and what a VERIFIED does not tell you. It says that until `log/checkpoints/genesis.txt` exists there is no log to follow.
- **Genesis dry run** (velouria `bridge/arcaeon/logtree_checkpoint.py`, fresh read-only mirror of the pins repo at `abeea2a`, the real key, nothing published): **size 56, root `1b8719021ae9c600018c0f3001e3b180679f1ef8117aac120526f7ba7a661816`** (base64 `G4cZAhrpxgABjA8wAeOxgGefHvgReqwSBSb3unpmGBY=`), the same root slice 1 recorded. `follow.js` with the printed key: VERIFIED (genesis against itself, size 56 -> 56, empty proof); with any other key: COULD NOT LOOK.
- Suite 582, 580 pass, 0 fail, 2 todo (unchanged M-1, M-2).
- **Before the first publish:** this repo's public `main` does not yet contain `tools/follow.js`; the README and the pins repo's `KEYS.md` both point strangers at it, so `main` should carry it first.

## 2026-09-23 — one release tree (branch `release-candidate-2026-09-23`, local only, NOT deployed)

`honest-commit-time-2026-09-22` plus `no-delete-record`, `log-tree-slice1` and `audit-state-slice1`, merged in that order; `8f0c2d1` (production) is an ancestor. See `RELEASE_NOTES_2026-09-23.md`.

- **Correction to the audit-state entry below:** its "with the flag off the page is byte-identical to before (tested)" was not true. The summary placeholder sat on its own template line, so flag-off output gained a 3-byte whitespace line; the test checked vocabulary only. Fixed in `api/status.js` during the merge; a frozen-clock render of this tree with the flag off now matches `d398315` byte for byte, and a new test in `test/audit_status_page.test.js` pins it (fails against the unfixed file).
- `test/helpers/mock_store.js`: the two `git/trees` mocks (sealer reconciler's `treeStatus`/`treeTruncated`, audit state's per-entry `sha` and GET-only routing) are one handler now.
- Suite 578, 576 pass, 0 fail, 2 todo (M-1, M-2, main's strict false-yes rows).


## 2026-09-22 — the commit date is the operator's own clock, not GitHub's (branch `honest-commit-time-2026-09-22`, NOT deployed)

The README (lines 11 and 549), `lib/_store.js`, the status page (`api/status.js`, two paragraphs), `status.json`'s `independence.note`, `PRACTICES.md` §3, `STAMPS_OWN_REPO.md` and `tools/stamp_genesis.js` all said that pin commits are "third-party-timestamped by GitHub" or that "GitHub's clock is the first witness". That is not what git does. A commit's date is whatever the committing client wrote; every commit in the pins repo is made by the operator's own account through the operator's own client or token, and none is signed. GitHub stores the date; it does not vouch for it. The only independent clock in the pins repo is the daily OpenTimestamps (Bitcoin) anchor. Found by the second-lineage verifier (DISAGREEMENTS D11, live-data item 4) against the public pins README, which carries the same sentence and is corrected separately.

- **Wording now, everywhere the claim appeared:** the commit history is public and a rewrite is visible to anyone who cloned or watched before it; a commit's date is the operator's own statement, not a third party's; the independent evidence of time is the daily Bitcoin anchor. `PRACTICES.md` bumps to v1.3 with a dated correction note under its header.
- **The 2026-09-19 entry below** kept the sentence "every pin is a public, third-party-timestamped commit" as a limit a relying party needs. The limit stands; that sentence was wrong and is not repeated here. Old entries are left as written.
- `test/status_posture.test.js`: the LIMIT KEPT test now asserts the page does NOT say third-party-timestamped and DOES say the date is the operator's own statement and that the Bitcoin anchor is the independent evidence. Suite count unchanged.


## 2026-09-22 — nothing is deleted from the record (branch `no-delete-record`, local only, NOT deployed)

An outside verifier written from the spec alone ruled the pin repo BROKEN for 65 records deleted on 2026-08-14 as "test cleanup" (19 namespaces, two of them carrying conflict observations). It could not tell test cleanup from suppression, and neither can anyone else. Those deletions were one-off contents-API calls made by hand; no script in this repo or the velouria repo produced them, and no scheduled task runs one.

- **New rule:** test namespaces use the reserved prefix `veltest-` (older `test-` and `velouria-tmp-` recognised, plus the exact legacy names `velouria-audit<digits>`, so all 19 names removed on 2026-08-14 read as test data; a bare `velouria-audit` prefix is deliberately not used because `velouria-audit-20260819` is live). A finished namespace is never removed. `tools/supersede_namespace.js` publishes a new, create-only record at `superseded/<namespace>.json` that says so; pins and observations stay. Dry run by default; a namespace with no test prefix needs `--any-namespace`. The namespace shape is checked before any network call, and the tool refuses to publish when `latest.json` is missing or its `seq` is not an integer while numbered pin files exist, because a guessed `last_seq` of 0 would be a false statement that nothing came after it.
- **Guard:** `test/no_delete_record.test.js` fails if any file in `lib/`, `api/` or `tools/` gains a DELETE (any case, including a bare `"DELETE"` string literal), `git rm`, or `deleteFile(` call outside a named allowlist (`lib/_balance.js`, private usage repo, no callers; `tools/ceiling_probe.js`, its own throwaway repo). Break arms prove the scan and the create-only write can fail. Suite 351 tests, 346 pass, 0 fail, 5 todo.
- **What a mirror does and does not do:** a no-rewrite mirror (fast-forward pushes only, no `--mirror`, no prune) does NOT stop a deletion commit from reaching it. A contents-API delete is an ordinary new commit, so it fast-forwards onto the mirror like any other. What the mirror keeps is the history that proves the deletion happened and what was deleted, and it refuses a rewrite (force-push or trimmed history) of what it already holds.
- Not yet done: status page and verify do not read `superseded/` yet; the 65 deleted records are not restored (that is a live write to the public repo and needs the owner's go).

## 2026-09-22 — one cumulative Merkle log over the public record, with consistency proofs (branch `log-tree-slice1`, NOT published, NOT deployed)

Slice 1 of `DESIGN_CONSISTENCY_AND_NEVER_LOOKED_2026-09-22.md` Part A. The gap it answers (design F1): `sealBatch` builds a tree per batch and links batches by `prev_root`, which is a hash chain of roots, so promoting the batching never bought a consistency proof. A consistency proof needs one tree that grows. This is that tree, built over every create-only record file in the public pins repo, so a stranger who kept one checkpoint can verify that today's published checkpoint extends it. Nothing in `api/`, `lib/_stamp.js`, `lib/_merkle.js` or `lib/_batch.js` changed; the hashing is `lib/_merkle.js`'s, reused. Suite 334 -> 366.

- **`lib/_logtree.js`.** The leaf is an envelope over a record file's exact committed bytes: `{recipe, kind, path, file_sha256, introduced_by_commit}`, all strings, hashed as `SHA256(0x00 || json_c14n_v1(envelope))` through the repo's one canonicalizer. The bytes are what `git show <commit>:<path>` prints, never a checked-out file (spec §8(e), `core.autocrlf`). The order is the commit that introduced each path, oldest first along first-parent history, ties by path in byte order; the rule and the git command that recomputes it are in the header. Eligible: numbered pins, observations, anchor `.txt`. Excluded by design: `latest.json`, `.ots`, README, `log/`. `inclusionProof` / `consistencyProof` / `verifyInclusion` / `verifyConsistency` are RFC 9162 §2.1.3–2.1.4 transcribed from the RFC text with the RFC's variable names, returning typed reasons. Every design A4 refusal has its own reason: `equal_sizes_nonempty_path`, `old_size_zero`, `old_size_greater_than_new`, `empty_path`, `malformed_hash` (exactly 64 lowercase hex, never trimmed or padded), `path_too_long`, `path_too_short`, `old_root_mismatch`, `new_root_mismatch`.
- **Vectors.** RFC 9162's text carries only the 7-leaf structural example (node names, no hex); that example is asserted node for node (inclusion for d0/d3/d4/d6, PROOF(3), PROOF(4), PROOF(6)). The hex vectors are the RFC 6962 reference implementation's published constants (transparency-dev/merkle `testonly/constants.go`, fetched 2026-09-22, read as data): all 8 leaf hashes, every internal node of the 8-leaf tree, roots for sizes 0..8, and four inclusion and four consistency proofs assembled from that table. All match. Also permanent now (design F5): `buildLevels` equals the RFC recursive MTH and the §2.1.2 stack algorithm for n = 1..300, `proofPath` equals the recursive PATH for every (i, n) with n <= 64, and every (m, n) with n <= 130 verifies with a longest proof of 9. `test/logtree.test.js`, 16 tests.
- **`lib/_checkpoint.js`.** A C2SP-style signed note: `origin\nsize\nbase64 root\n`, then an empty line and `— <name> <base64(keyhash[4] || ed25519 sig)>` lines; the em dash is a format byte. Ed25519 via `node:crypto` only; keys are the `<name>+<hash>+<base64>` verifier and `PRIVATE+KEY+...` signer strings, lifted from raw bytes with fixed DER prefixes so nothing is installed. The signature covers the note text and nothing else. `no_signature_for_key` and `bad_signature` are different reasons because they mean different things (COULD NOT LOOK vs BROKEN). **Written from the C2SP description, not cross-checked against a reference implementation:** interop with other signed-note tooling is not claimed. One bug found by the suite and fixed before commit: splitting a key on every `+` refused any key whose base64 contained one. `test/checkpoint.test.js`, 5 tests.
- **`tools/publish_checkpoint.js`.** Builds the tree from a local clone (read-only git: rev-parse, log, ls-tree, cat-file), writes `checkpoints/<date>.txt`, `leaves/<date>.jsonl`, and with `--prev` `proofs/<date>-consistency.json` into `--out` only, dry run by default, create-only, refuses `--out` inside the clone, never commits or pushes. Refuses (exit 2, nothing written): a path added twice on the walk (D8), a record whose bytes differ from its introducing commit, a previous checkpoint the clone does not reproduce, an existing output file. `--key-env NAME` signs with the key in that environment variable; no key is created or read otherwise. `--help` restates design A9 verbatim. Against a fresh read-only clone of `dan8433-user/arcaeon-witness-pins` at `abeea2a`: **size 56, root `1b8719021ae9c600018c0f3001e3b180679f1ef8117aac120526f7ba7a661816`**, skipped by design latest.json=8, .ots=40, other=1; 46 eligible paths were added in history and are absent at HEAD (not logged, counted; verifier two's 65 is a different denominator). `test/publish_checkpoint.test.js`, 5 tests, fixture repos built in temp dirs.
- **`tools/follow.js`.** The stranger's checker, stdlib only, one file, no `require` of `lib/`: two checkpoints plus the proof plus `--key` -> VERIFIED / BROKEN / COULD NOT LOOK, exit 0/1/2, every result naming what it trusted. Size and root are read from the checkpoint text and the proof's echo must agree (BROKEN otherwise); unknown recipe or origin is COULD NOT LOOK; unsigned with a key expected is COULD NOT LOOK; a signature line that does not verify is BROKEN. Its RFC verifier is a second transcription and the suite cross-checks it against `_logtree.js` on every (m, n) with n <= 64 plus every mutation. Same author, so this is two transcriptions, not two implementers; the design's day-3 Python checker written from the spec alone is still owed. `test/follow.test.js`, 6 tests.
- **Break arms, every suite.** A verifier that always says yes is caught by all 22 consistency mutations; a Bitcoin-style duplicate-last-leaf tree disagrees with the reference roots at every odd size; a signature verifier that only looks for a line naming the key is caught by tampered, forged and moved signatures; a path-only leaf order gives a different root on a fixture built to separate the orders; a checker that always says VERIFIED is caught by every non-VERIFIED battery case; a checker that trusts the JSON echo instead of the checkpoint text passes a swapped root that ours calls BROKEN.
- **Demo on the live clone** (throwaway key, scratch output, nothing published): checkpoint at 51 then at 56 with a 6-hash proof -> `follow.js` VERIFIED; one leaf's `file_sha256` flipped and the size-56 checkpoint re-signed -> BROKEN (`echo_mismatch`, then `new_root_mismatch` once the echo is patched to match); a stranger holding a different key -> COULD NOT LOOK (`no_signature_for_key`).
- **What still stands between this and publishing** (design A10 day 5 and A9, unchanged): the genesis audit (every anchored commit an ancestor of genesis, every `file_sha256` equal to the file at its introducing commit) has not been run as a published self-check; no key exists and where one would be held is open (A11 q3); the daily job is not scheduled; the `witness-log` health dimension and the daily self-check reader are not written (no artifact without a reader); the spec section "The witness log" is not written; deleted-before-genesis records are counted, not logged, and whether that is the right call is a question for the owner; and the log proves the witness's own list of heads was not rewritten, not that a customer's log at head N extends head M (F4), not split view without a second witness, and never that anything recorded is true. Publishing is the owner's call.

## 2026-09-22 — a verdict for NEVER LOOKED, slice 1 (branch `audit-state-slice1`, local only, NOT deployed, flag default off)

Design: `projects/online_business/DESIGN_CONSISTENCY_AND_NEVER_LOOKED_2026-09-22.md`, part B. The finding it fixes: `api/status.js:29` gave a namespace nobody had ever independently checked a green "current" badge and nothing else, so absence of a red read as green. Suite 334 -> 392 (58 new, 0 fail, the 5 `todo` are the pre-existing verify false-yes xfails).

- **`lib/_check_record.js` — the signed check record** (design B4, plus a `rerun` field): who checked (`checker.key`, an Ed25519 public key as its own id), when (`checked_at`), what (`target.type/ref/digest`), the result (VERIFIED / BROKEN / COULD_NOT_LOOK), the tool and its source hash, and the command that reproduces it. Ed25519 via `node:crypto`, signature over json-c14n:v1 of every field except `sig` (the `_distill_core` serializer, so there is still one canonicalizer). `verifyCheckRecord` refuses unsigned, malformed, unknown-field, non-https-input, non-canonical-key, tampered and future-dated (> 300 s ahead) records, each with a named reason, and never throws on bad input. 12 tests; the field-mutation test flips all 25 mutation cases and each must fail; break arm: a verifier that always says ok is caught by every case.
- **`lib/_audit_state.js` — the audit state, derived and never set** (B3, B5, B6): BLIND / SELF-CHECKED / CHECKED / STALE / BROKEN with B3 precedence, 30-day freshness in integer seconds (strict less-than), withdrawn tools and keys, operator keys, unverifiable and COULD_NOT_LOOK counted but never folded in. Also the B7 strings: badge, line under it, the BLIND-first aggregate, the "N of M checked" headline. 32 tests (20 state cases, 6 exact-string cases); break arm: a derive that always says CHECKED is caught by 17 of the 20 cases.
- **`lib/_audit_status.js` + `api/status.js` — the column, behind `WITNESS_AUDIT_STATE=1`.** Reads `checks/OPERATOR_KEYS.json`, `checks/WITHDRAWN_TOOLS.json` and `checks/<type>/<ns>/*.json` from the public pin repo (one tree read, then up to 100 record reads per render; over budget renders NOT FULLY READ, never a state). With the flag on, every row leads with its audit state and the cadence badge follows it as "cadence: current"; a BLIND-first aggregate panel sits above the table. With the flag off the page is byte-identical to before (tested). An absent `OPERATOR_KEYS.json` makes CHECKED unreachable (every key is read as ours) and the page says so. 9 tests.
- **`tools/check_and_sign.js` — the stranger's tool.** Runs verifier two (`verifier_two/verify.py --json`, stdlib Python written from the spec) or reads its saved output, decides per namespace by verify.py's own `overall` rule over that namespace's results, fetches the newest pin from raw.githubusercontent.com as the record's public input and digest, and signs one record per namespace with a key the stranger mints (`--gen-key`, PKCS#8 PEM). Records are verified before they are written; output paths are create-only. Nothing in it needs a secret of ours; it does not import `api/verify.js` (our code over our store is not an outside look). 8 tests including a CLI end-to-end run.
- **`test/helpers/mock_store.js`**: now answers `GET /repos/<repo>/git/trees/<ref>` (every seeded file as a blob), which the audit reader and the existing observations count both use.
- **`DISAGREEMENTS_audit_state.md`**: twelve interpretive choices, every one resolved toward never upgrading a state without evidence. The two that differ from the build brief: BROKEN is permanent per B3 (not "newer than the last VERIFIED"), and the cadence badge stays but follows the audit state (B7).
- **Not touched, on purpose:** `api/verify.js`, `lib/_stamp.js`, `lib/_status_json.js` (the JSON twin does not yet carry audit states; follow-up).
- **The honest consequence:** with today's repository there is no `checks/` directory, so every namespace is BLIND, and until an outsider runs the tool the ceiling is SELF-CHECKED. Verifier two also rules `velouria-selftest` BROKEN by its own D2, and the repo BROKEN overall for the 2026-08-14/15 test-cleanup deletions; a stranger running the tool today would publish the first as a namespace BROKEN. To switch the flag on: publish verifier two (the BLIND re-run line names it), publish `checks/OPERATOR_KEYS.json` before any self-check record, set `WITNESS_AUDIT_STATE=1`, and Daniel's word on the deploy.

## 2026-09-22 (later) — review follow-up: the rebuild hook judges the whole read, and a verdict can be bound to its record (branch `verdict-required`, NOT deployed)

**Why.** atomic-raven's review of `f12d0ed` (Colony post `42b8d6e0`, comment `062a4dc2-7e5b-4b6b-9458-561daada46b1`) found the rebuild route still folded "gone" and "present but null" into one value, and that a green is not tied to its `what`.

- **The hole, closed.** `lib/_store.js` `putFile` now hands a `rebuild` hook the whole store read (`fresh`: `null` only on a 404, `{json, sha}` for anything present), and the hooks judge that read as-is. A pointer whose JSON is the literal `null` now judges red (`not_a_json_object`) and the pin is refused, never rebuilt over. A `RedVerdictError` thrown from inside the write now reaches the client as the ordinary 503 refusal with its named reason (it was a generic 502 "pin store error"), and the charge is refunded as before. The abandoned-write result also gains `fresh_present`, so `fresh: null` no longer stands for both states.
- **Every site of the shape, checked** (grep `rebuild`, `judgePin(null`, `judgeRead(null`, `=== null ? null`, `{ json:` over `api/`, `lib/`, `tools/`):
  - Fixed: `lib/_store.js` `putFile` (the hook argument); `api/pin.js` `latestPointerRebuild` (judges `freshRead`, reads `freshRead.json.seq`); `lib/_stamp.js` `takeDailyBudgetOnce` rebuild (judges `freshRead`).
  - Correct as they stand: `lib/_stamp.js` stamp create (`rebuild: () => null`, ignores the read); `api/latest.js:85` (raw-CDN fallback builds `null` only for `status === 404`); `lib/_balance.js` grant (`curJson = cur ? cur.json : null` is used only after `balanceOf(cur)` has judged the whole read); every other judge caller passes a reader's return value directly (`getFile` in `_store`, `_balance`, `_meter`, `_keys`, `_pending` returns `null` only on 404). `judgePin(null)` / `judgeRead(null)` appear only in tests, as the deliberate 404 case.
  - `test/store_put_retry.test.js`: its three hooks now read `fresh.json`.
- **A verdict can be bound to its record (rule 6).** `requireVerdict`, `requireGreen`, `isEmpty`, `success`, `refusal` and `counterValue` take an optional `expect` of `{what}`. Given one, a verdict whose `what` differs is refused with `VerdictMismatchError` (`code: "verdict_what_mismatch"`); a malformed `expect` is a `TypeError`. Opt-in, so no existing caller breaks; wired where the record is known: `api/verify.js` (every success and the refusal name the head path, or the historical record's own path, and `witnessedResponse` derives it from `isCurrentHead`), `api/latest.js`, `api/pin.js`'s pointer rebuild, `lib/_status_data.js`. Limit: the binding is as specific as the label the judge was given, and `lib/_stamp.js`'s "stamp record" and the counters' labels are not per-record (the stamp's sha is checked by its own shape rule instead).
- **Tests (+3).** `test/verdict_endpoints.test.js`: "PIN / POINTER DAMAGED MID-WRITE (content = null)" plants `null` in `latest.json` between the read and the write and expects 503, `reason: not_a_json_object`, zero writes to the pointer, pointer bytes unchanged; "STAMP BUDGET / COUNTER NULL MID-WRITE" does the same to the day counter. On `f12d0ed` both fail (the pin answered 201 and overwrote the pointer; the stamp answered 201 and restarted the counter); both pass here. `test/verdict_required.test.js`: "RULE 6 / WHAT BINDING", with positive controls. Must-fail arm, Break C: the mismatch check removed from `requireVerdict`: 1 failure, RULE 6.
- The existing "POINTER DAMAGED MID-WRITE" fixture (a non-pin object) kept passing throughout; it now also answers 503 rather than 502.

Suite 432 → 435, 0 failed.

## 2026-09-22 — judgeRead never returns null, and a green is bound to the read it was judged from (branch `verdict-required`, NOT deployed)

**Why.** atomic-raven, replying on the Colony (post `42b8d6e0`), named two holes in the verdict layer. First: `judgeRead` returned `null` for a read that was present and an object, meaning "the caller's shape rules decide". Null-as-continue is a disarm: a future raw caller that treats null as green puts back exactly the default the layer forbids, one level down. Second: `success(v, fields)` would take any verdict with `ok: true` and a state, including one the caller built with `verifiedRecord()` and no store read behind it. Our reply (comment `43bed67b`) laid out how damaged reads arrive: a non-200/404 throws in the reader, an unparseable body throws, and valid-but-partial JSON arrives present, where `judgeRead` returned null. Only that third kind reaches the judge. Today's only callers of `judgeRead` were `judgePin` and `judgeCounter`, and both refuse by shape. The reply promised the fix as he described it. This entry is that fix.

- **`present_unchecked` replaces the null.** `judgeRead` has three answers, all of them verdicts. A 404 gives a bound `verified_empty`. Something present that is not a JSON object is red. Something present and an object gives `present_unchecked`, which is `ok: false`, typed and bound. `requireGreen`, `success` and `counterValue` refuse it with the error named `PresentUncheckedError` (`code: "present_unchecked"`), so the log says which mistake was made. The only way from there to a record is a shape rule. `judgeWith(got, what, rule)` is the one door, and `judgePin` and `judgeCounter` now run through it. Their outputs haven't changed: `verifiedRecord` or red, the same reasons as before. A rule that returns neither a reason nor a pass throws.
- **Greens are bound to reads.** Only `judgeRead` issues a `read_id`. Every green carries the `read_id` of the read it was judged from, and this module records every verdict it mints in a private map. `requireVerdict`, and through it `requireGreen`, `success`, `counterValue` and `isEmpty`, refuses a green with `UnboundVerdictError` (`code: "verdict_unbound"`) in three cases: it has no `read_id`, its `read_id` was never issued, or it is not the exact object a judge minted (a spread copy or a literal carrying a real `read_id` both fail). `verifiedRecord` and `verifiedEmpty` are no longer exported. You can't build a green by hand and pass it through `success()`.
- **Callers, all made correct under the new rule** (grep `judgeRead|requireGreen|success(|verifiedRecord|verifiedEmpty|judgePin|judgeCounter` over `lib/` and `api/`):
  - `api/fulfill.js:464`: minted `verifiedRecord("fulfillment record")` after an inline shape check, with nothing tying it to the read. It now runs `judgeWith(cur, …)` over the fulfillment read.
  - `lib/_stamp.js` `judgeStamp` / `sendStamp`: minted `verifiedRecord` over a bare record. It now takes the store read (`found` / `prior` / `theirs`) and goes through `judgeWith`. The one non-read is the freshly written stamp, judged as `{json: record}`, the record whose PUT landed. A null (404) handed here throws, because the 404 is the caller's branch.
  - Unchanged, correct as they stand: `judgePin` callers (`api/latest.js:112`, `api/verify.js:132,245`, `api/pin.js:101,535`, `lib/_status_data.js:115`); `requireGreen` at `api/pin.js:100` and `lib/_status_data.js:120`; `success` at `api/latest.js:130`, `api/verify.js:138,155,177,193,261,285,309` and `lib/_stamp.js` `present()`; `judgeCounter` via `counterValue` in `lib/_balance.js:205`, `lib/_meter.js:166` and `lib/_stamp.js:334`. Every verdict they pass into `success`/`requireGreen` comes straight from a judge, with no copies, so it stays bound.
- **The control arm he asked for** (`test/planted_dead_ledger.test.js`, "ROWS WENT BACKWARDS"). The old monotonic guard was `cur && Number.isInteger(cur.json.rows) && rows < cur.json.rows`. The arm plants a head that is valid JSON with the right namespace, chain and seq but `rows: "12"`, so the guard's precondition is false. It then submits a backward pin (rows 5) and asserts a red refusal: 503, `reason: rows_unreadable`, nothing written, head bytes unchanged. That means the guard refuses rather than skips. Its control is the same backward pin over an undamaged head, which must be the ordinary 409. **Run red on the old code** in two ways. First, with the `api/pin.js` head refusal disabled: 3 failures, this arm included. Second, with `api/pin.js` from `feea800^` (pre-verdict): the arm fails with "a backward pin was ACCEPTED over a head whose rows could not be read: the guard skipped". It is green on this commit.
- **Must-fail arms, each run by mutating the file, running the full suite, and restoring:**
  - Break A, `judgeRead` returns `null` again: 142 failures. Every judge crashes on the null.
  - Break A2, `judgeRead` returns `null` and `judgeWith` is patched to treat null as "go on", so every judge still works and only the null is under test: 2 failures, both PRESENT_UNCHECKED tests (re-run 2026-09-22 on the review follow-up below: still 2 of 435).
  - Break B, the binding check removed from `requireVerdict`, so `success()` accepts an unbound green: 1 failure, UNBOUND GREEN.
- **A test that was passing for the wrong reason, fixed.** Three asserts in `test/verdict_required.test.js` expected a `TypeError` from `success(verifiedRecord("x"), {ok: …})` and `refusal(verifiedRecord("x"))`. Once `verifiedRecord` stopped being exported, those threw "not a function", which is also a TypeError, so they kept passing without testing anything. They now use a real bound green, match the specific message, and carry a positive control.
- **What this does not guarantee.** The binding proves a green came out of a judge over some `got` object that was handed to `judgeRead`. It does not prove that `got` came off the network: a caller can still pass `{json: <anything>}` to a judge, and the shape rules still run on it. `refusal()` of a `present_unchecked` renders the ordinary 503, which fails closed. As shipped at `f12d0ed`, two routes built that `got` by hand, and one of them was a hole (corrected per the review in the entry above):
  - **The rebuild route, a hole, now closed.** `lib/_store.js` handed a `rebuild` hook `fresh ? fresh.json : null`, and `api/pin.js`'s pointer hook turned that `null` back into `judgePin(null)`, a `verified_empty`. So a `latest.json` that was present with the content `null` read as a 404 and was overwritten at seq 0 — the exact "nothing there" / "something there I cannot read" collision this file forbids. `lib/_stamp.js`'s day-budget hook had the same shape (a counter holding `null` restarted the day at 0). This paragraph originally named the pointer rebuild as a *legitimate* `{json: …}` caller; it was not.
  - **The fresh-write exception, still open by design.** `lib/_stamp.js` judges the stamp it just wrote as `{json: record}`: the record whose PUT landed, not a re-read. The green there is bound to a read that never touched the store. It is the one remaining hand-built `got` in `lib/` and `api/`.

Suite 426 → 432, 0 failed.

## 2026-09-21 — a success-shaped answer can no longer be built without a verdict (branch `verdict-required`, NOT deployed)

**The class, not the call site.** On 2026-09-19/20 the receipt proxy's health endpoint (a different repo: `arcaeon-receipt`, commits `b5d98a7` and `757fc18`, with `arcaeon-ledger` `9e3dc66`) was found answering `200 {"ok": true, "rows": 0, "chain": "genesis"}` over a corrupt ledger: the verify step had said no, and a wrapper built a success out of defaults. That call site was patched the same day. This change is about the same shape in THIS codebase: anywhere a stored document that is present-but-unreadable fell through `x && typeof x.y === ... ? x.y : <default>` and came out as a well-formed answer. `VERDICT_SURVEY.md` lists every site, the greps it rests on, and what was left alone.

**Remedy A, forbid the default: `lib/_verdict.js`.** One helper. `requireVerdict(v)` throws `VerdictRequiredError` unless `v` is an object with an explicit boolean `ok` and, when green, a named state. `success(v, fields)` is the constructor of an `ok: true` body on the record-reading endpoints and throws on a missing verdict and on a red one. "Empty / brand new" is its own verdict, `verified_empty`, and the judges mint it in exactly one situation: the store answered 404. Present-but-unreadable is red. The two never share a value again.

**What it found here (25 sites, all listed with file:line in the survey).** The ones that mattered most: `/api/verify` turned a damaged `latest.json` into a CONCLUSIVE `witnessed:false` (the scan started at a defaulted `seq = 0`, walked nothing, and reported reaching the start of history); `/api/pin` skipped its monotonic guard and its re-mint guard over a damaged head, because both are written `cur && Number.isInteger(cur.json.rows) && ...`; the free-tier meter and the daily stamp budget read a damaged counter as 0, which fails OPEN; a credit grant over a damaged balance file replaced it with a fresh one holding only the grant; the status board reported `conflicts_observed: 0` under `ok: true` when the observations tree could not be read; and the badge, the status JSON and a listing each had a fallthrough whose last branch was the good news.

**Remedy B, keep the plant on the producer: `test/planted_dead_ledger.test.js`.** Its own file. Overwrites a healthy namespace's stored head with garbage (bytes that are not JSON, and valid JSON saying `rows:0 chain:genesis`), asks `/api/latest`, `/api/verify` and `/api/pin`, requires non-200, and carries the guard from the receipt repo's fixture word for word: `fixture did not break the ledger; the test proves nothing`. The guard has its own control test, which skips the plant and requires the assertion to refuse.

**Behaviour changes a caller can see.** A damaged head is `503 {ok:false, reason}` on `/api/latest` and `/api/verify` (was 200), and `/api/pin` refuses with 503 before any charge. `/api/verify` can answer `witnessed:null, reason:"history_unreadable"` where it used to answer a conclusive false past a hole or an unreadable record. `/api/status.json` reports `conflicts_observed: null` and `status:"indeterminate"` when the conflict log could not be counted. `/api/latest` no longer falls back to the raw CDN when the commit-fresh copy was REACHED and is not JSON. Honest empties are unchanged and pinned by tests: 404 on `/api/latest`, `witnessed:null no_pin_recorded_for_namespace` on `/api/verify`, first pin lands as seq 1, a key with no balance file reads 0, a month with no usage file starts at 0.

**Before deploying:** the judges assume every stored pin carries `namespace`, `rows`, `chain`, `seq` (true of `api/pin.js` since its first commit), every balance file a numeric `balance`, every usage file an integer `used`, every day counter an integer `count`. That was checked against the CODE that writes them, not against the live repos. A read-only pass over the live pins and usage repos should come first; a legacy document that breaks the assumption would now be a 503 instead of a quiet default.

Suite 383 → 420, 0 failed. No new file under `api/` (still 12).


## 2026-09-20 — two sealers cannot publish the same leaves twice, and a reconciler says so when something does (branch `sealer-safety`, NOT deployed, flag still off)

A second-lineage attack review of the 10 unshipped commits named two gaps as must-close before `WITNESS_BATCH_SHADOW` is ever turned on: nothing stopped two sealers running at once (finding #14), and nothing checked for a committed pin whose leaf is in no batch and no longer pending (finding #16). Both are closed here. Nothing is deployed, the flag is still off, and `api/pin.js` is not touched at all. Suite 265 → 293.

**What the code already guaranteed, checked before anything was designed.** The close is a compare-and-swap on the pending document (`lib/_sealer.js`, `WRITE 1: CLOSE the batch. THIS IS THE BOUNDARY.`) and it has always partitioned the *leaf set* exactly — a pin racing a seal lands in the closing batch or the next one, never both and never neither, asserted from the published record in `test/sealer.test.js`. `resolveSealing` already resolved an unconfirmed prior seal against the *public* repo rather than our own bookkeeping, so a root that published but whose slot-clear failed is never re-sealed. A batch id is consumed and never reused. The publication atom is the single `root.json` write, with `leaves.json` first as an inert orphan and `buildProof` structurally refusing on an unsealed batch. Every read that can refuse happens before any write. None of that needed rebuilding, and the two audit findings that claimed otherwise (#10, sealer idempotency; #8, same-batch conflict ordering) were rejected on reading the code — the review could not see the test suite, and both are already covered.

**The gap that was real.** The close partitions the leaf set; it does not partition the seal *execution*. A closes batch N into the `sealing` slot; B's close 409s, B re-reads, asks the pin repo whether root N is published, legitimately sees "not yet" because A has not written it, carries N's leaves into N+1 and seals them; A then publishes root N over the same leaves. No crash needed, two overlapping invocations are enough. **Reproduced against the pre-change code before writing anything**: two `sealOnce()` calls, the first suspended one write short of `root.json`, published both leaves in batch 1 and the same two again in batch 2.

- **`lib/_claim.js` — the single-sealer claim.** The store is a GitHub repo, so the only mutual-exclusion primitive is the conditional write the contents API already gives us: PUT with no `sha` is create-if-absent (422 if it exists), PUT with a `sha` is update-if-unchanged (409 if it moved). Both are arbitrated by GitHub, so one of two racing writers wins. A seal takes `pending/seal_claim.json` in the private usage repo, naming the holder, an absolute `expires_at`, and the **leaf set it is sealing** — batch id, leaf count, and a digest over each leaf's `(namespace, rows, chain, seq)`. A conflict on the claim write is **re-read, never guessed**: `lib/_store.js` measured 465 409s out of 532 writes that raced nothing, so a claim that read a 409 as "somebody beat me" would refuse to seal most of the time for no reason.
- **Expiry, so a crashed sealer costs two intervals and not a morning.** 120-second lease by default (two batch intervals), `--claim-ttl` to change it. An expired or released claim is takeable, and the takeover is itself a conditional write, so two takers still produce one winner. A claim whose `expires_at` cannot be parsed counts as **live** on purpose: a corrupt claim wedges the sealer, which is harmless because the leaves wait in the pending document, while two sealers are not harmless. Clearing it is deleting one file and the design says so.
- **The lease runs on wall time, deliberately not on the batch clock.** `tools/seal_batch.js --now` moves the replay clock; a lease that moved with it would measure nothing about how long the run has actually been alive. `sealOnce` takes `claimClock` as a *function*, because a lease checked against the reading it was acquired with can never notice it expired.
- **`lib/_batch.js` gained one optional gate, `opts.beforeRoot`**, called between `leaves.json` and `root.json` — the last instant at which aborting costs nothing but an inert orphan leaf list. The sealer re-checks the claim there, so a slow run whose lease expired mid-work stands down one write short of publishing a root over leaves another sealer may already have published. Default is no gate; every existing caller is unchanged.
- **An idle run still writes nothing.** The claim is taken *after* the trigger decision and after the chain read, so a scheduler polling every 60 seconds costs zero writes when there is nothing to do, and the fail-closed rule that every refusing read happens before any write is intact.
- **Stated as a lease, not a lock.** Between the pre-root check and the root PUT landing at GitHub there is a window, and a sealer stalling inside it past expiry while another takes over can still double-publish. The TTL makes that window far smaller than a run; nothing claims it is zero. The property that holds without qualification is that **a violation would show** — which is what the next item is for.

- **`tools/reconcile_batches.js` — the instrument behind "run it until a full week reconciles clean."** Read-only, bounded, four findings: `lost` (committed pin, no leaf in any batch, not pending), `duplicated` (one leaf identity in two batches), `root_mismatch` (published leaves do not hash to the published root), `proof_failed` (a proof rebuilt from the published document does not verify — built from the *declared* `tree_size` and `leaf_hashes`, because that is the data a stranger holds, so an internally inconsistent document fails even when its leaf array alone hashes fine). A test asserts zero writes on every path. Run against the real damage the pre-change code produced, it reported both duplicated leaves by name with zero writes.
- **Three verdicts, not two.** `CLEAN` 0, `FINDINGS` 1, `INCOMPLETE` 2. `INCOMPLETE` fires on a truncated GitHub tree, any unreadable file, an unreadable pending document, or either bound being hit — because the one way this tool can lie is by being read as a clean bill when it simply did not look. Findings win over incompleteness: an unread file does not make a real finding less real.
- **`lib/_store.js getTreeMeta`** exists only for that: `getTree` drops GitHub's `truncated` flag, which is fine for a status page counting files and fatal for a reconciler deciding whether a leaf appears nowhere.
- **A `lost` finding is reported, not filtered, even though it has a legitimate cause.** §6.1's `pending_head_regression` refuses a leaf while the pin stays publicly committed — the tolerated Phase 1 gap this phase exists to *measure*. "Expected sometimes" is not "nobody should look."
- **Bounds:** `--max-batches` 512, `--max-pins` 5000, and past either the tool stops, says how many it did not look at, and goes `INCOMPLETE`. Scope starts at the earliest batch `opened_at` or `--since`; pins older than that are `out_of_scope` and never called lost.

- **`lib/_pending.js`** now exposes `readUsageDoc` / `writeUsageDoc` over a path, with `readPending` / `writePending` as unchanged wrappers, so the claim runs on the same one CAS primitive rather than a second copy of the fetch pair that can drift from it.
- **Tests: `test/sealer_concurrency.test.js`, 28 of them.** Each of the four scenarios the review asked for has an arm that fails against the pre-change code: two sealers in the same second; a crash after claiming and before the close; a crash after the root write and before clearing pending; a slow sealer whose lease expires mid-run (detects before the root write, aborts, leaves held, next run seals them under a new id). Plus: an old pre-batching receipt verifies byte-identically after a claimed seal *and* a reconciliation, and with the flag off `api/pin.js` writes the same two files with the same content field-for-field, reads neither the claim nor the pending document, and the only usage-repo write is the meter's, exactly as before.
- **Design doc:** new §12 (concurrency, with the guarantees and the non-guarantees both spelled out), §13 (reconciliation), and **§14, the "before turning the flag on" checklist** — which also names what is still *not* built: worst-case pin latency with the flag on is unmeasured (audit #7), the accumulation path has no leaf-count ceiling of its own (#11), `readPrevRoot`'s 64-id lookback has no auto-recovery (#9), and `POST /api/verify?op=bulk` in the same unshipped range still has no rate limit at all (#1, CRITICAL, not batching work and not fixed here).




## 2026-09-20 — brand stems reserved at claim time (branch `reserve-brand-stems`, NOT deployed, touches the paid claim path)

Second-model review, 2026-09-20: `lib/_status_data.js`'s `isReferenceNamespace()`
tags any `velouria-`/`arcaeon-` namespace as "our own log" on the **public**
status page, but `lib/_keys.js`'s `validatePrefix()` only ever reserved the
`wk-` stem. A paying customer could pick a namespace prefix like
`velouria-something` or `arcaeon-x` at checkout and get two bad outcomes at
once: mislabelled as the operator on the public status page, and sitting on
the operator's own brand namespace outright — the exact class of harm the
existing `wk-` reservation exists to prevent, just left open for the two
stems that actually matter for brand.

- **Reserved at claim time, same shape as `wk-`.** `lib/_keys.js` gets
  `RESERVED_BRAND_STEMS = ["velouria", "arcaeon"]`. `validatePrefix()` refuses
  a customer-chosen prefix that starts with (or is exactly) `velouria-` or
  `arcaeon-` with `{ok:false, reason:"reserved", detail:"the <stem>- stem is
  reserved for the operator's own namespaces"}` — the identical shape the
  `wk-` refusal already used. A stem merely *appearing* inside a longer,
  differently-rooted prefix (`acme-velouria-mirror-`, `myarcaeon-x-`) is
  untouched and still claimable.
- **One source of truth, not two lists that happened to agree.**
  `lib/_status_data.js`'s `REFERENCE_PREFIXES` is now *derived* from
  `keys.RESERVED_BRAND_STEMS` (`.map(stem => \`${stem}-\`)`) instead of
  carrying its own literal default. `api/fulfill.js`'s claim path and
  `GET /api/prefix-available` both already routed through the same
  `keys.validatePrefix()` (fulfill.js directly; `lib/_prefix_check.js`'s
  `decide()` calls it too) — that plumbing was already correct and needed no
  change, only the reservation itself was missing.
- **`WITNESS_REFERENCE_NS_PREFIXES` env override REMOVED, not kept.** It let
  an operator tag an *unreserved* stem as "ours" on the status page without
  also reserving it at claim time — precisely the drift that produced this
  bug in the first place, since the default value happened to match
  `validatePrefix`'s hardcoded `wk-`-style reservations by coincidence, not
  by construction. Awkward to reconcile with "single source of truth" any
  other way (an env var cannot safely widen a security-relevant reservation
  at runtime), so it is gone; `REFERENCE_EXACT` / `WITNESS_REFERENCE_NS_EXACT`
  (unrelated — exact operator log names with no brand stem, e.g.
  `test-freeplan-smoke`) is untouched.
- **Grandfathered.** The reservation gates *new* customer claims only.
  `keys.issuedKeyPrefix()` (the live `/api/pin` auth lookup) and
  `keys.listPrefixes()` both read stored records as-is and never re-run
  `validatePrefix` against history, so a key already issued on a brand-stem
  prefix — before this fix, or hand-provisioned for the operator's own use
  via `WITNESS_KEYS`, which never touches `validatePrefix` at all — keeps
  authorizing pins unchanged. Test: `test/reserve_brand_stems.test.js` and
  `test/fulfill.test.js` each seed a pre-existing `velouria-legacy-` key
  record and confirm it still authorizes while the identical string is
  refused as a fresh claim.
- Tests: new `test/reserve_brand_stems.test.js` (17 tests: refusal shape,
  case normalization, lookalikes stay allowed, the two-list single-source
  check in both directions, grandfathering). Additions to
  `test/prefix_available.test.js` (7) and `test/fulfill.test.js` (4, covering
  the JSON claim path, the HTML form POST, a lookalike mint, and
  grandfathering end-to-end). Suite 265 -> 293, all passing.
## 2026-09-20 — bulk verify is now rate limited, weighted by items.length (branch `bulk-ratelimit`, NOT deployed)

Audit finding (`WITNESS_UNSHIPPED_COMMITS_AUDIT_2026-09-20.md`, Unit B):
`api/verify.js`'s `module.exports` dispatched `?op=bulk` to `handleBulk`
*before* the single-item path's `ratelimit.check(req)` call, and
`handleBulk` never called the rate limiter at all. One unauthenticated
POST could carry up to `MAX_BULK_ITEMS` (20) items, each costing up to
`MAX_HISTORY_SCAN` (50) history-scan reads plus 1 for `latest.json` — up
to 1020 GitHub API reads from one HTTP request, against the same token
`/api/pin`'s paid writes depend on, with zero rate limiting. This existed
because bulk mode (K-018, `34c0655`) was added after the per-IP limiter
(`14308a0`) and the bulk dispatch was wired in front of, not through, it.

**Why.** GitHub's contents API budget is shared across the whole service,
not metered per endpoint (`test/free_endpoints_ratelimit.test.js`'s own
header explains this same class of bug on four other endpoints, fixed
2026-09-05). Bulk mode reopened it on a fifth surface at up to 34x the
per-call cost of a single unauthenticated GET.

**What.** `lib/_ratelimit.js`'s `check(req)` gained an optional `cost`
parameter (default 1 — every existing caller is unaffected). `handleBulk`
now calls `ratelimit.check(req, items.length)` against the SAME per-IP
bucket the single-item GET/HEAD path uses, after the cheap shape/cap
validation (which touches no store and stays free to refuse garbage) and
before any store read. Chosen over a second, bulk-only bucket: it needed
no new machinery beyond the `cost` parameter, and it's genuinely one
shared resource (one GitHub token) being protected either way — two
buckets would let single and bulk traffic each separately max it out.
Design decision, tested: a malformed/over-cap batch spends zero rate-limit
units (it never reaches the check), because it already costs zero store
reads and charging it would let cheap junk grief a legitimate caller's
shared budget for free.

**Corrected in the same pass:** `BULK_VERIFY_DESIGN.md`'s "Rate limiting"
section previously claimed the limiter "still applies to the bulk request
as one call" — false; and its worst-case arithmetic ("20 × 50 = 1,000")
undercounted by one read per item (the `latest.json` read the history scan
is entered from). Measured worst case, directly against the mock store's
own read log: **1020**, not 1000. The caps themselves (20 items,
50-record scan) are unchanged; only the arithmetic describing them was
wrong, and it was wrong low.

`test/verify_bulk_ratelimit.test.js`, 6 tests: the crossing-the-limit case
makes zero store reads; a different IP is unaffected; single verifies plus
one bulk call share one budget and cross it exactly at the summed weight;
the 1020-read worst case is measured, not asserted against a
self-reported number; malformed/over-cap batches cost zero units by
design; a must-fail arm re-creates the pre-fix dispatch (bulk's path never
calling `ratelimit.check()` anywhere) and proves the weighted-limit
assertion fails against it. Existing single-item rate-limit and CORS
behavior unchanged (`test/verify_read_surface.test.js`, untouched, still
green). `npm test`: 265 → 271, all green.

## 2026-09-20 — stamps get their own record, their own token, and a price (branch `stamp-own-repo`, NOT deployed)

Owner direction (Daniel, 2026-09-20): Arcaeon stamps get their **own public record repository** and their **own write token**, are sold beside the witness **on the same prepaid credit pool** as a micro-transaction, **3 free a day**, and "if free can get exploited just make it paid." All four, built. Nothing pushed, nothing deployed, and the stamps repository still does not exist — creating it is the owner's step, by hand (`STAMPS_OWN_REPO.md`).

- **`lib/_stamp_store.js` — a separate store that cannot fall back.** Stamps read and write `STAMP_REPO` / `STAMP_BRANCH` / `STAMP_TOKEN`. It never reads `GITHUB_PIN_REPO` and never reads `GITHUB_PIN_TOKEN`. Missing config is **503 with nothing written and nothing even read** — not a quiet write into the witness record. And because one env typo must not be what merges the two records, a `STAMP_REPO` set *by hand* to the pins repo is **refused** (`stamp_repo_is_pins_repo`). Why it matters: a stamp is a public, near-unauthenticated write, so the token behind it is the most exposed credential here; scoped to one repository, the worst day for stamps cannot touch a single pinned head.
- **The GitHub primitives are reused, not copied.** `lib/_store.js` grew an optional `target` argument (repo, branch, token *env name*, user-agent) and a `forTarget()` binder. Every existing caller is byte-for-byte unaffected — the suite proved that before a single stamp change landed. The reason for the refactor rather than a second store module: `putFile`'s 409 retry was **measured** live (465 conflicts in 532 requests, `tools/ceiling_probe.js`), and a second hand-copy of that loop is a second implementation with nothing keeping the two in step.
- **Metering: free, then paid, on the one pool.** A repeat of an already-stamped fingerprint is free forever and **never debits**. The first `STAMP_FREE_PER_DAY` stamps (default 3) per client address per UTC day are free. Past that a stamp needs a valid witness key and debits **the same prepaid balance the pins spend**. `STAMP_FREE_PER_DAY=0` makes every stamp paid — the owner's escape hatch, an env lever because it is an operational decision, not a price. The existing global daily cap still sits under all of it and still fails closed, and it applies to paid stamps too: a paid stamp is never silently dropped, it is refused before any charge.
- **The price, with its math — and it is NOT ratified.** One constant, `STAMP_PRICE_CREDITS = 0.25` in `lib/_stamp.js`, deliberately not an env var (a price that moves by editing a dashboard field is not a promise). Against `lib/_balance.js`'s real pack prices — entry packs `mini` $5/1,000 and `starter` $15/3,000 = **$0.005 per credit**, `standard` $50/12,000 = $0.0041667, `bulk` $150/40,000 = $0.00375 — a quarter-credit stamp costs **$0.00125 at the entry rate (800 stamps per dollar)**, $0.00104 at standard (960/dollar), **$0.00094 at bulk (1,067 stamps per dollar)**. The argument for a quarter: a stamp is one commit carrying a hash, while a pin carries a cadence contract, a deadline, an interval history, a monotonic guard and a verification surface, so charging the same prices the cheap thing off the table; below a tenth the GitHub write behind it is worth more than the money at the cheapest pack. That is an argument, not a decision — **pricing authority for this lane is the owner's partner's, and this goes to him with the math above.**
- **`lib/_balance.js` debits an amount, not a 1.** New `debitCredits(secret, amount, reason)`; `decrementCredit` is now a thin alias for `debitCredits(secret, 1, reason)`, so there is one CAS loop, not two. Balances round to 6 decimal places on write, because 0.25 taken four times must be exactly one credit and not 0.9999999999999998 — there is a test that says so. The `applied_events` idempotency set carries through a stamp debit, same as it must through a pin's (the 2026-08-16 double-grant bug, in a new lane, with its own assertion).
- **Money never moves for a stamp that did not land.** The balance is *checked* before the write (a read — an insufficient balance is **402** with an honest body, the current balance, the price, `ever_purchased` and the packs, and nothing is written) and *debited* after the write is confirmed. A failed write, a lost create race, a refused daily cap and a repeat stamp each charge nothing. Every one of those is a test with a must-fail arm; moving the debit above the write turns **seven** of them red, which is how we know they are load-bearing and not decoration.
- **`tools/stamp_genesis.js` — the witnessed birth, dry-run by default.** A brand-new repository is exactly as old as its first commit, and that commit's date is whatever its creator's machine says. This writes ONE record into the **existing pins repo** naming the stamps log's first commit SHA and date, as its own commit, timestamped by GitHub in a history with months of public life behind it — the old log dates the new one. Create-only: an existing genesis record is never replaced, because a birth record that can be overwritten is worth nothing. It **refuses** to write the record into the stamps repo itself (a log cannot witness its own birth), it **never creates a GitHub repository**, and it has not been run for real. A tool and not a 13th API function: `api/` is at the Vercel Hobby 12-function cap, and this runs once in the life of the log.
- **The claim stayed scoped.** The genesis record says a later change "would show" in the public commit history. It does not say impossible, does not say tamper-proof, claims no independence or multiple witnesses, and implies no adoption — and there is a test that fails on any of those words appearing in the record.
- **Privacy guarantees unchanged and re-proved on the new store:** fingerprint and optional size only, extra fields refused with a 400 rather than dropped, and a new assertion that neither the raw key nor its billing hash can appear anywhere in the public record now that a key can pay for a stamp.
- Tests: **270 → 297** (27 new, all 12 pre-existing stamp tests repointed to the stamps repo and green). Full suite `297/297`, 0 fail.
- **Not done:** the stamps repo does not exist, nothing is pushed, nothing is deployed, the genesis tool has not been run, and the price is a placeholder awaiting the owner's partner. No chain across stamps yet (the Merkle batch sealer is still the intended path) and no receipt page.

## 2026-09-19 — /api/stamp: fingerprint-only file stamps (branch `stamp-endpoint`, NOT deployed)

Daniel's ask: a person should not have to write code to get a tamper-evident receipt. `POST /api/stamp {sha256, size?}` records one public commit per fingerprint under `stamps/<2 hex>/<sha256>.json`; `GET /api/stamp?sha256=` looks one up. The browser hashes the file, so the file never leaves the person's machine.

- **First write wins, forever.** A repeat stamp returns the original record and writes nothing; a lost create race returns the winner's. There is no update path. "No later than" is only true if the earliest record cannot be replaced.
- **No filename, no label.** Extra fields are refused with a 400, not dropped: the store is public and a filename is content.
- **Every response carries `scope.does_not_prove`**, including the 404. A thing called a stamp gets read as an endorsement.
- **Two abuse fences from day one, both fail closed:** 10 stamps per IP per 10 minutes, and a global daily cap (`STAMP_DAILY_CAP`, default 500) kept in the store so it holds across instances. If the counter cannot be written, no stamp is recorded.
- **Routing:** this deployment is at the Vercel Hobby 12-function cap, so the handler lives in `lib/_stamp.js` and is dispatched from `api/verify.js` on `?op=stamp` via a `vercel.json` rewrite. The dispatch says in a comment that a write is riding on a read endpoint.
- A store outage on lookup is a 503 "this is not a no", never a 404.
- Tests: 12 new, suite 270/270.
- **Not done:** no chain across stamps yet (the existing Merkle batch sealer is the intended path), no receipt page, no deploy. Pushing this branch would create a preview that writes to the REAL public pins repo, so that waits for his go.
## 2026-09-19 — the status page reports the service (deployed 2026-09-20 on top of live commit 14308a0; later commits on main NOT included)

The page opened with "Independence disclosure: k=1. Every namespace below traces to one operator root... We measured, the answer is one", plus a `k=1` stat tile, and `status.json` carried "all namespaces trace to one operator root". That wording came out of a forum reviewer's critique and was right for the forum. On a product surface it read as an announcement that nobody else uses the service. Owner's call, 2026-09-19: a status page says what the service is doing; it does not editorialise about adoption.

- **Kept, because a relying party needs it:** single-operator witness; every pin is a public, third-party-timestamped commit; every number links to its raw source; nothing has to be taken on trust. `independence` in the JSON now states `witness_operators: 1` and `verifiable_without_trusting_us: true`.
- **Removed:** the paragraph, the `k=1` tile, and the usage sentence in the JSON.
- **Added, so the removal does not overclaim in the other direction:** the operator's own namespaces are tagged `reference` (HTML badge, `reference: true` in JSON), decided by prefix (`WITNESS_REFERENCE_NS_PREFIXES`, default `velouria-,arcaeon-,test-,demo-`). A bare namespace count would otherwise read as a customer count. A customer's namespace is simply untagged.
- Test fixture: the mock GitHub store now lists immediate subdirectories (`type: "dir"`), as the real contents API does; without it nothing that walks `pins/<namespace>/` could be tested. `test/status_posture.test.js`, 5 tests; suite 258 -> 263.

## 2026-09-13 — Merkle batching, the caller: the sealer exists, and the batch does not seal early

`6c0bb93` left one sentence in `MERKLE_BATCHING_DESIGN.md`: *"Until the sealer exists,
nothing calls `sealBatch` in production. The library is complete and the caller is not."*
This is the caller. Suite 236 → 258.

- **`lib/_pending.js` — the state a serverless function cannot hold.** §11 Q3's premise is
  that "a serverless request cannot reliably close a batch it did not open," and the reason
  is that nothing in `_batch.js` or `_merkle.js` survives an invocation. One JSON document
  under CAS in the private usage repo holds the open batch's leaves in acceptance order and
  §6.1's pending head per namespace. **A read that fails throws; a 404 returns null** —
  "I cannot see it" and "there is nothing there" stay different answers, which is the whole
  fail-closed hinge.
- **The trigger is `lib/_batch.js`'s, quoted and called, not restated.** §3.4: *"Seal when
  any of these fires, whichever comes first: 1. `batch_interval_seconds` elapsed since the
  batch opened (default proposal: 60s). 2. `max_leaves` reached... 3. A deadline forces it
  — any pending leaf whose `next_pin_due_by` is within `seal_safety_margin` of expiring."*
  `lib/_sealer.js` asks `sealTrigger` and does **nothing, not one write anywhere**, when the
  answer is null. One addition, a carry and not a cadence: leaves left behind by a seal that
  already failed seal on the next run regardless of the interval (§10 T4).
- **Fail closed, and it is the sealer that refuses.** A sealer that cannot read the pending
  head returns `pending_head_unreadable`, writes nothing — no root, not even an orphan leaf
  list — and never seals a batch it cannot prove complete. Every read that can refuse (the
  pending head, the chain tip, the leaf shapes) happens **before any write**. Sabotaged both
  ways before shipping: collapsing the unreadable case into `no_open_batch` turns both
  fail-closed tests red; making the trigger always fire turns "does not seal before the
  interval" and "a deadline forces it" red.
- **The close is the boundary, and it is before the seal, never after.** A leaf appended
  after a root is computed would claim membership in a tree it is not in. Closing first
  freezes the leaf set; the close and `api/pin.js`'s append contend for the same document
  sha, so a pin racing a seal either wins (its leaf is inside the sealed batch — the close
  409s, re-reads, and absorbs it) or loses (its append 409s, re-reads, and lands in the next
  batch). Both directions are tested from the *published* leaf list, not from the sealer's
  own report.
- **A published root is never re-sealed.** The hazard: a root that commits and then fails to
  clear its bookkeeping slot looks exactly like a seal that failed, and re-sealing would put
  the same leaves under a second root. The sealer asks the **pin repo** whether a root exists
  at that batch id rather than trusting its own note-to-self — a question about our memory
  turned into a question about the published record.
- **§6.3 is finally a backstop.** §6.1's pending head refuses a same-rows/different-chain
  leaf into the tree at accept time. The seal-time re-check stays, and is not redundant: the
  contents API gives no read-your-writes across instances, so a stale cross-instance read can
  still admit a conflicting leaf, and a test seats exactly that shape and proves the later
  leaf is still dropped and the observation still written.
- **`api/pin.js` gains nine lines that cannot fail a pin.** The accumulation hook runs after
  the record is committed, on both the advance and the heartbeat path (§11 Q4, decided:
  heartbeats stay in the tree), and swallows every error to a loud log. §9 Phase 1 is "Keep
  per-pin commits exactly as they are" — a shadow-run bookkeeping failure must not turn a
  committed pin into a 502 after the fact. The dropped leaf is exactly what Phase 1's week of
  reconciliation exists to catch.
- **`tools/seal_batch.js` — §11 Q3 decided: an operator command, not a 13th function.** `api/`
  is at the Vercel Hobby 12-function cap (`9e8b060`); opportunistic sealing is refused by the
  design's own parenthesis ("starves a quiet witness"); a seal mode on a public endpoint would
  need a new operator-auth surface built before the first seal, and a command needs none —
  running it already requires the token the seal spends. Exit 1 means **refused, nothing
  written**, so a scheduler can alert on fail-closed specifically.
- **Phase 1 is off until someone starts it.** Accumulation requires `WITNESS_BATCH_SHADOW`.
  §9 Phase 1 is "Run it until a full week reconciles clean" — an operator act with a start
  date and a week of watching, not a state that arrives with the next unrelated deploy. The
  start procedure and the reconciliation check are written into §9.
- **The one that matters, re-proved against the caller.** With the accumulator live on every
  pin and a root committed by the sealer, an old-style pin verifies through the real
  `api/verify` handler with a byte-identical body — and the claim "by exactly the path it does
  today" is checked against the mock store's own **read log**: the verifier read
  `pins/<ns>/latest.json` and nothing under `batches/`. A frozen hand-written pre-batching
  record still verifies `witnessed:true` the same way.
- **Two corrections written into the design.** §6.1 called the meter/balance store "a durable
  non-GitHub store"; it is a private GitHub repo (`lib/_meter.js:22-24`, `lib/_balance.js:64`),
  so §11 Q2's read-your-writes requirement is **not** satisfied and the honest statement is
  first-guard-plus-backstop. And §6.1's pin-refusing 502 is deliberately **not** built: its
  premise is "if `latest.json` is only written at seal time," which is Phase 4, not Phase 1 —
  adding a 502 class to a live money path for a window that is not yet open would be paying a
  real availability cost for a hypothetical one.

## 2026-09-13 — Merkle batching, the mechanism: N pins, one tree, one root, a proof each (`6c0bb93`)

`MERKLE_BATCHING_DESIGN.md` §3 and §5 implemented, plus §6.3. Its own statement of the
contract, §1: *"Group every pin accepted in an interval into one Merkle tree and commit
only the root. Write cost becomes O(1) per interval — a fixed small number of commits
regardless of whether the interval held 1 pin or 10,000."* Suite 204 → 236.

- **`lib/_merkle.js` — the tree, and nothing else.** No store, no clock, no network,
  because §8 requires `verify_inclusion` to be "pure and dependency-free. If proving
  inclusion requires calling us, the proof is not a proof," and a require list is how a
  stranger checks that. Leaf = `SHA256(0x00 || json_c14n_v1(leaf_object))` over §3.1's
  nine fields; node = `SHA256(0x01 || left || right)`; **odd node PROMOTED, not
  duplicated** (§3.2 — the Bitcoin shape makes distinct trees collide, CVE-2012-2459
  lineage, and a test asserts the two roots differ); leaf order is acceptance order and is
  part of the commitment.
- **The canonicalizer was already here.** §3.1 forbids a second one. `lib/_distill_core.js`
  already carries the JS side of `json-c14n:v1` (`jdump(value, true)`), so `_merkle.js`
  calls it. Residual, documented at the call site rather than discovered later: JS cannot
  tell `24.0` from `24`, so an integral `cadence_hours` canonicalizes as `"24"`.
- **`verifyInclusion` is §5's published algorithm verbatim**, including the derived path
  direction — no left/right flags, because "a verifier that trusts the flags over the index
  is exploitable." It returns a **typed reason, not a boolean**: §5 requires inclusion and
  publication to stay "two separate claims, never merged into one boolean," and an unknown
  recipe label returns `unknown_recipe` rather than passing with a warning.
- **`lib/_batch.js` — two writes per batch, whatever the leaf count.** `leaves.json` then
  `root.json`. **The failure atom is the single `root.json` write**, and it is enforced
  structurally, not described: `buildProof` throws on an unsealed batch, so no pin can be
  handed a proof citing a root that was never published. A failed seal leaves no root, no
  proof, an unmoved chain tip, and a leaf set handed back for the next batch to absorb
  (§10 T4, which is honest that correlated failure is a real cost of batching).
- **`prev_root` is the equivocation fence and it costs no extra write.** The chain tip is
  read off the previous published `root.json`, which already carries its own root — no
  pointer file, so no third write per batch and nothing that can rewind.
- **§6.3's seal-time conflict re-check drops the LATER leaf** — `api/pin.js:183-184`'s rule
  is that a conflict "never advances accepted state" — and writes its observation
  immediately and unbatched, per §6.2: "the one write in this system with a live adversary
  attached."
- **The 409 retry from `aaa1378` governs every write here and is not reimplemented.** Every
  write is a `store.putFile`; a test greps `lib/_batch.js` for `fetch(`, for
  `maxAttempts|PUT_RETRY|putOnce`, and counts the `store.putFile` call sites, so the absence
  claim names its searches instead of asserting itself.
- **Nothing about publication changed, and that is the point.** `api/pin.js`,
  `api/latest.js` and `api/verify.js` are untouched — §9 Phase 1, "Keep per-pin commits
  exactly as they are." Two tests hold the line the hard way: one runs the real pin handler,
  snapshots the real `api/verify` response, seals that pin into a batch, and asserts the
  response is unchanged; the other verifies a frozen hand-written pre-batching record with a
  batch root sitting in the same repo.
- **MEASURED, not estimated.** Counted from the fixture's own `putLog`, not a number the
  code reports about itself: 10 pins through `api/pin.js` cost **20** pin-repo writes
  (**2.0 per pin**); one sealed batch of 10 leaves costs **2** (**0.2 per pin**); 1 leaf and
  100 leaves both cost 2.
- **Found while building.** A seal that dies before its root write **retires** its batch id
  — the orphan `leaves.json` is still there and §9 promises nothing is ever rewritten — so
  id gaps are normal and `batch_id > 1` stopped being the same question as "something came
  before me." `readPrevRoot` now walks back over the gaps and refuses to *claim* a chain
  start it did not establish: an exhausted lookback is a typed `chain_break`, not a null.
- **Deliberately not built, listed in the design's status block rather than left to be
  discovered:** the pending-head store (§6.1), `inclusion_due_by` / `inclusion_state` / the
  `cannot_determine` pending grade (§4), the `/status` self-grading counters (§7), the
  `GET /api/proof` endpoint (§5 — `api/` is at the Vercel Hobby 12-function cap, confirmed
  at `9e8b060`, so it needs an `?op=` mode, not a 13th file), the client verifier (§8,
  another repo), and the scheduled sealer (§11 Q3). Until the sealer exists nothing calls
  `sealBatch` in production: the library is complete and the caller is not.

## 2026-09-13 — `putFile` retries the 409 that was losing concurrent pins (task 093)

The ceiling probe measured the defect on its way to measuring something else: ten
concurrent writers on one branch issued 532 requests and took **465 409s**. Every one of
those writers was creating its own distinct file, so nothing raced for a path — the
**branch ref** moved under each PUT. `lib/_store.js:putFile` did not retry, so a pin that
raced another pin simply failed. Production pins run on serverless instances that
overlap, so this was live, not a lab curiosity. This is not the batching design; it is
the correctness floor under it.

- **`putFile` now retries a 409**, and only a 409 — the 422 create-race keeps its
  existing one-shot `err.conflict` contract, and a 5xx is still a plain failure. Four
  attempts, ~1 s base, doubling, jittered 0.5x–1.5x. The backoff is ours to invent
  because the probe found the secondary limit carries **no `Retry-After`** and refills in
  ~16 s, so there is no server hint to honour.
- **It re-reads before it re-writes, and the two 409s are not the same event.** If the
  path is *unchanged* since the caller read it, the 409 was branch-ref contention and the
  caller's object is re-PUT verbatim — nothing was overwritten because nothing moved.
  If the path *moved*, another writer owns it now, and a blind re-PUT would erase that
  writer's row, so it is never done: the caller's optional `rebuild` hook is handed the
  fresh json and decides, and with no hook the call fails typed (`err.stale`, with
  `err.conflict` still true so every pre-existing caller behaves exactly as before).
- **The result carries `attempts`.** A pin that took three tries says so instead of
  reporting a clean single write; `POST /api/pin` surfaces it as `write_attempts`. A
  budget that runs out throws — there is no fabricated success anywhere on this path.
- **`api/pin.js` supplies the one rebuild that is actually needed**, for `latest.json`.
  The merge rule is short because `latest.json` is a *pointer*, not a row: the rows are
  the numbered seq records, which are created and never rewritten, so racing here can
  never overwrite another pin's row. What it could do is rewind the pointer over a newer
  record, and that is forbidden — a witness never goes backward. So a fresh `latest` at a
  seq >= ours abandons the write (`latest_pointer_advanced:false`); only a
  strictly-behind pointer is advanced. Our record stays recorded at its own numbered path
  either way.
- **Tests** (`test/store_put_retry.test.js`, 9 new): 409-twice-then-201 lands on attempt 3
  with the *fresh* sha on the wire (bound to a sha the fixture authored, not one the code
  reported about itself); 409 five times gives up with a plain typed error and an
  untouched file; and — the one that matters — after a genuine race the merged content
  contains **both** writers' rows, with a paired no-rebuild case proving the racer's row
  survives rather than being clobbered. Sabotage check: replacing the retry branch with an
  unconditional `break` turns 6 of the 9 red (`attempts: 1`, `Error: github PUT
  race/t1.json -> 409`); restoring turns them green.
- `test/pin.test.js`'s wedge-refund regression had its forced-conflict budget raised
  10 → 40. `putFile` now spends up to four PUTs per call, so four passes issue up to 16,
  and a budget of 10 would have let the 11th **succeed** — turning that regression green
  for the wrong reason. The test's intent is unchanged.

Suite: **195 → 204**, all green.

## 2026-09-13 — the GitHub write ceiling, measured (task 083, open question 1 closed)

`MERKLE_BATCHING_DESIGN.md` §1 had said "we have not measured GitHub's secondary rate
limits for sustained contents-API writes to one branch" since August, and §11 carried it
as open question 1. It blocked any customer-facing throughput claim by its own standing
rule. Measured now; §1 and §11 rewritten with the numbers and the date.

- **New `tools/ceiling_probe.js`** — sustained contents-API PUTs until GitHub refuses.
  **Scratch-repo only**: it refuses to run unless the target repo name contains "probe",
  and refuses outright if the target is the live pin repo. The reason is not squeamishness
  about junk commits (though the pin log's whole value is that its history is meaningful)
  — GitHub enforces secondary limits **per authenticated identity, not per repository**,
  so tripping the limit on any repo puts the *serving* token into cooldown. The scratch
  repo avoids the junk history; only running in a quiet window avoids the cooldown. The
  token is read from `GITHUB_PIN_TOKEN` (the same var `lib/_store.js` reads) and every
  string leaving the process goes through a redactor.
- **Numbers** (personal User account, plan `free`, classic PAT, 2026-09-13): 577
  sequential writes accepted in 360 s (96/min) with **zero** refusals — the sequential run
  never found a ceiling, it hit the probe's own time cap. A 4 KB payload gave 279 in 180 s
  (93/min), median latency 626 ms vs 603 ms at 64 bytes: **payload size does not move it**,
  a single writer is latency-bound at ~95/min.
- **What actually trips it is concurrency, and the recovery is fast.** Ten concurrent
  writers took a 429 ("You have exceeded a secondary rate limit", **no `Retry-After`**)
  after 65 accepted writes in 49 s, and recovered in **~16 s**. So it is a burst allowance
  that refills in seconds, not an hourly ban.
- **The finding with teeth, which a sequential-only probe would have missed:** the limiter
  counts *requests*, not accepted writes, and **branch contention bites before the rate
  limit does**. Of that burst's 532 requests, 465 were **409s** — ten writers committing to
  one branch move the ref under each other and `lib/_store.js:putFile` has no retry. Ten-way
  concurrency moved *less* (80/min accepted) than one sequential writer (96/min) for eight
  times the request budget. Adding write concurrency to a single branch is not a throughput
  lever; removing writes is, which is the batching case.
- **Two scratch repos created and deleted** (`arcaeon-ceiling-probe-2026-09-13`, `…-13b`),
  each `DELETE -> 204` with a confirming `GET -> 404`. The live pin repo was never written
  to. The primary hourly limit was never approached (5,000/hr; never below 3,600 remaining).
- Standing rule kept, not weakened: **no customer-facing pins-per-hour figure without a
  dated measurement.** ~47 pins/min (two writes per pin) is an internal planning figure.

## 2026-09-12 — bulk verify: `POST /api/verify?op=bulk` (K-017/K-018/K-019, BATCH_500 lane K)

No 13th function — `api/` is at the Vercel Hobby cap of 12 (confirmed by direct
listing before this shipped: badge/balance/credit/distill/fulfill/health/latest/
pin/renew/status/stripe-webhook/verify). Bulk verify is a MODE on the existing
`api/verify.js`, dispatched on `?op=bulk` the same way `api/fulfill.js` already
dispatches `?op=prefix-available` — no new vercel.json rewrite required for the
internal call shape. Design: `BULK_VERIFY_DESIGN.md`.

- **Request:** `POST /api/verify?op=bulk` with `{items: [{ns, rows, chain|digest}, ...]}`
  — the same three fields the single-item `GET /api/verify` already takes, per item.
- **Cap:** fixed at 20 items. An over-cap batch (or a non-array/empty `items`) is
  refused WHOLE with a 400, before any store read — zero partial processing, mirroring
  `arcaeon_receipt/cite_batch.py`'s cap-or-refuse pattern. Chosen because a single
  verify lookup can already cost up to `MAX_HISTORY_SCAN` (50) store reads in the
  worst case; 20 bounds a batch's worst case to 1,000 reads rather than leaving it
  unbounded.
- **Response:** `{ok, count, results: [...]}`, one result per input item, in request
  order, each carrying `http_status` plus exactly the body the single-item endpoint
  would have returned for that input. **No new verdict word** — `witnessed`
  (`true`/`false`/`null`) and every `reason` string are the identical set
  `api/verify.js` already emitted, because bulk mode calls the SAME `verifyItem`
  function the single-item path calls, once per item — not a second hand-copy of the
  lookup logic.
- **Never short-circuits:** a malformed item (bad `ns`/`rows`/`chain`) or a store-read
  error on one item produces that item's own error-shaped result and processing
  continues to the next item; the loop is a plain sequential `for`/`await`, never a
  `Promise.all` that would let one rejection take down the whole response.
- `api/verify.js`'s existing single-item logic was refactored (not rewritten) into
  `verifyItem()` returning `{status, body}` instead of writing to `res` directly, so
  both the GET single-item path and the new bulk path share one implementation.
  Existing single-item behavior is byte-identical; the full pre-existing suite
  (`test/verify.test.js`, 6 tests) still passes unchanged.
- New `test/verify_bulk.test.js` (9 tests): mixed valid/invalid/never-witnessed batch
  with per-item verdicts in order, the `digest` alias inside a bulk item, over-cap
  refusal with zero store reads, exactly-at-cap acceptance, malformed `items` shapes,
  and a mid-batch miss not aborting its neighbors.
- `npm test`: 186 → 195, all green.
- **What's still open, not decided here:** whether the per-IP rate limiter should
  scale with batch size (currently counts a bulk call as one hit, same as any other
  request — see BULK_VERIFY_DESIGN.md's "Rate limiting" section for the reasoning and
  the flagged trade-off) and whether a public `/api/verify-bulk` alias is worth adding
  via a vercel.json rewrite. Neither blocks this pass; both are named for whoever
  picks this lane up next.

## 2026-08-30 — independence disclosure: k=1, stated plainly

The status page and its JSON twin now disclose the root count directly: a
k=1 stat cell + explainer paragraph on /status, and an `independence` block
(`roots: 1, disclosed: true`) on /api/status.json. Rationale (owed to an
external reviewer, sram): eight namespaces signed by one operator is k=1,
a count of derivation roots, not signatures — and the determinate number
beats an indeterminate impression. The health tri-state (ok/degraded/
indeterminate) is unchanged; it grades freshness/gradeability, a different
axis. The k value changes only when a namespace under someone else's root
actually exists — that claim stays behind the publish gate until real.

Reverse-chronological. Every entry says what changed and why, and names the
reviewer whose objection forced it where there was one. Public review is the
reason this thing works; the credit belongs in the record, not in a thank-you.

## 2026-08-30 — Rev-2b: the prefix picker learns to answer (`/api/prefix-available`), and the commands become copyable

**COMMITTED NOWHERE AND DEPLOYED NOWHERE — working tree only; no Vercel action, no
Stripe action.** Founder design, Daniel 12288/12291: *"shouldnt we let our users pick a
prefix that isnt selected"*. Rev-2 gave the buyer a prefix FIELD and no way to know
whether the pick was free — the only feedback was a rejected form POST after the fact.
`npm test` 132 → 176, all green.

**1. New `GET /api/prefix-available?prefix=<p>` (`lib/_prefix_check.js`).** Validates
format (the existing `keys.validatePrefix`), then answers `{available}` against the same
universe the mint path uses — `WITNESS_KEYS` env bindings plus every issued-key record —
with the same two-way overlap rule (`acme-` and `acme-labs-` reject each other in BOTH
directions). Free → `200 {available:true}`. Taken → `200 {available:false, reason:"taken"}`
plus three alternatives that are each format-valid and verified free, and which DIVERGE
from the taken stem (`acme2-`, not `acme-hq-` — an extension would collide right back).
Invalid → `400`. The colliding prefix is never echoed: it belongs to another customer.
Store failure → `503 {available:null}`, never "free" — an unreadable store must not talk a
buyer into a pick the mint path will refuse. Input is trimmed+lowercased exactly as
`api/fulfill.js` normalizes an explicit pick, or the endpoint would answer about a
different string than the one minted.

**Routing, because `api/` is at Vercel Hobby's 12-function hard cap:** the public path is
a `vercel.json` rewrite onto `/api/fulfill?op=prefix-available`, dispatched at the top of
that handler before its session gate — the same trick already in use for
`/api/status.json`, and the same reasoning that put the balance page on the balance
function. A test asserts both the rewrite rule and that `api/` still holds ≤12 files:
without the rewrite this endpoint exists in code and 404s in production.

**Cached 20s, per warm instance.** `keys.listPrefixes()` is a directory listing plus one
read per issued key; a debounced picker asks once per typing pause and would otherwise
fan that out every time. The cache lives only in this module — the mint path calls
`listPrefixes()` directly and never sees it, so a stale entry can make the ADVICE briefly
wrong and can never widen what an actual mint accepts.

**2. The picker checks live (`lib/_prefix_ui.js`).** 400ms debounce with `clearTimeout`
on each keystroke, a sequence guard so a slow answer for `acm` can't repaint over a fast
one for `acme-`, three distinct states (free / taken / couldn't-check), and the three
alternatives as one-click buttons. "Couldn't check" is never painted as free, and the
submit button is never disabled by the check — the POST re-validates server-side, and a
client check that is itself unsure must not be able to lock a paying buyer out of a key
they have already paid for.

**3. The commands are copy boxes with the prefix already in them.** New `copyBlock()` in
`lib/_page.js` (multi-line sibling of `copyBox`) — the four-line curl was a bare `<pre>`
the buyer had to select by hand, which is exactly where a half-selected command comes
from. The picker previews it live as they type; the success page renders the final one.
`<YOUR KEY>` stays a placeholder on purpose even on the page showing the key: a one-click
copy of a command carrying a live bearer key lands that key in shell history.

**BOUNDARY, stated in three files and asserted in the suite: none of this mints.** The
availability answer is advisory. Key issuance stays exactly where it was — behind
`api/fulfill.js`'s server-side Stripe session verification, with the un-cached
`listPrefixes()`/`prefixConflicts()` pair as the authoritative gate — or in an operator's
hands per `projects/online_business/FULFILLMENT_RUNBOOK.md`. Tests assert the picker
route's `putLog` is empty and that the client script's only `fetch` is the read-only
availability URL.

**4. Two new test files, 44 tests, mutation-verified** (`test/prefix_available.test.js`,
`test/prefix_ui.test.js`). Nothing stubs `listPrefixes` — a test that stubs the
availability source cannot catch the availability source being wrong; these drive the
real fan-out against the mock GitHub store. The curl command exists twice (server render,
browser preview) and `test/prefix_ui.test.js` EVALUATES the browser copy out of the
shipped script source and diffs its output against the server function across a table of
prefixes, so drift between the preview and the receipt is a red instead of a support
email. Planted reds, all confirmed: debounce removed → 1 fail; substitution drifted to
`prefix + "-main"` → 4 fails; availability forced to always-free → 8 fails; the dispatch
removed → 25 fails; the rewrite dropped from vercel.json → 1 fail.

## 2026-08-30 — Ops: retired-namespace env var re-set (no code change)

Live `status.json` read `degraded` with `overdue:1` (`velouria-audit-20260819`, the 8/19
one-shot) while `retired_namespaces` listed only two names. The 8/24 deploy-gate note predicted
this exact failure: the piped `vercel env add` value cannot be read back, and the write had come
up short. Fixed by `env rm` + `env add` with all three names, then `vercel --prod`. Verified at
the observable effect: `summary.overdue: 0`, `retired_namespaces` = cadence-verify, canon,
audit-20260819; badge now `indeterminate · 8 ns · 0 overdue` (indeterminate is correct: there is
no current cadence namespace; that is the standing Option-1 floor item, not a defect here).

## 2026-08-30 — Test: `WITNESS_RETIRED_NS` end to end through the status computation (S-arcaeon-10c)

The env-var re-set above was fixed at the ops layer with no test ever exercising the
retirement filter itself end to end — `loadRetiredNamespaces()` (`lib/_status_data.js`) through
`status.json`'s summary shaping (`lib/_status_json.js`) had zero coverage. Added
`test/retired_namespaces.test.js`: (a) full three-name var — `summary.retired_namespaces` lists
all three, `summary.overdue == 0`, each row still `retired:true` with its real (overdue) cadence
status; (b) the var SHORT one name (`velouria-audit-20260819` missing) — that namespace counts as
overdue and the verdict reads `degraded`, the exact 8/24→8/30 production failure encoded as a red
in the harness now; (c) empty string, whitespace-only, and unset — nothing retired in any case.
Fixture reuses `cadence_overdue.test.js`'s store-monkeypatch seam (no GitHub calls), extended to
serve one pin per namespace so the three retirement candidates can be overdue while a fourth,
non-retired namespace stays current — keeps these assertions isolated from the unrelated ZERO
FLOOR (`nothingWatched`) mechanism. 127 → 132 tests, all green.

## 2026-08-22 — `witnessed` is tri-state: not-checked reasons return `null`, never a conclusive `false`

Forced by **ColonistOne's re-run against the deployed build** (Colony, witness
thread, 8/22): on 8/18 I said all three not-checked reasons would return
`witnessed: null` with scope in-band; the scope half shipped (accepted_head /
history / note) and the null half did not — `no_pin_recorded_for_namespace`
and `exceeds_current_head` still asserted boolean `false`. ColonistOne also
corrected their own record in the same comment (they had marked prediction B
falsified off my stated intention without verifying the deploy — same failure
class, named on both sides). The repair: `no_pin_recorded_for_namespace`,
`exceeds_current_head`, and `scan_bound_reached` now return `witnessed: null`
— an incomplete or inapplicable check may not assert a conclusive negative.
`false` is reserved for heads the record actively contradicts
(`rows_match_chain_mismatch`, `rows_never_witnessed`, `not_found_in_history`).
Two new contract tests plant the null cases (a 60-deep history to force the
scan cap; a shallow history to prove exhaustion stays a conclusive `false`).
109/109. README §verify rewritten to document the tri-state and credit the
catch.

## 2026-08-17 — Balance page: a human face on `/api/balance` via content negotiation; `lib/_page.js` extracted

**COMMITTED LOCALLY ONLY — not deployed, no Vercel config touched.** Founder
design 34378: every issued key needs an automated, easy way to see pins/
credits remaining — humans AND agents, no login, no accounts, no PII; the key
IS the identity. `api/` sits at Vercel Hobby's 12-function hard cap, so the
page rides the EXISTING `/api/balance` function via content negotiation, the
`api/fulfill.js` pattern. `npm test` green: 93 -> 104 (11 new,
`test/balance_endpoint.test.js`).

**1. New `lib/_page.js` — the shared page template.** `pageShell` / `copyBox`
/ `esc` / `wantsJson` moved VERBATIM out of `api/fulfill.js` (lib/ doesn't
count toward the function cap); fulfill now imports them, zero behavior
change to its pages (its own suite still passes untouched). One deliberate
delta: the input CSS selectors gained `input[name=key]` alongside
`input[name=prefix]` — additive only, no fulfill page has a key input. Env
URLs read at call time (the `_welcome_email.js` idiom).

**2. `api/balance.js` grows an HTML mode — JSON contract UNCHANGED.** HTML
is strictly OPT-IN by the browser's own `Accept: text/html`; the JSON
default (including a bare curl's `Accept: */*` and headerless SDK fetches)
takes exactly the pre-page code path — same fields, same Bearer auth, same
errors, pinned by an exact-field regression test. Browser GET without a key:
paste-your-key form, `type=password` (no shoulder-surfing), submits by POST
so the key never lands in any URL or access-log query string (house rule).
POST with a valid key: credits remaining, free-tier used/remaining, prefix,
key id, plus a curl one-liner copy-box teaching the agent path (placeholder,
never the real key — the key is never echoed into any response, success or
error). Invalid key: the form again, clean inline error, no echo.
Remember-my-key checkbox: default OFF, localStorage only, client-side only.

**3. Links to the page.** `/api/fulfill` success page and the welcome email
(HTML + text) each gained one line under the balance sentence: check your
balance any time at `<base>/api/balance` — a bare link, carries nothing.
`vercel.json` gained a friendly `/balance -> /api/balance` rewrite, mirroring
the established `/status` pattern (the form posts to `action=""` so it works
at both paths).

## 2026-08-17 — Instant fulfillment: `/api/fulfill` (Stripe session -> key + credits) and the dynamic issued-key store

**STAGED ONLY — working tree, not committed, not deployed. No Stripe config
touched, no secrets in code.** Board item 25 (founder-specced, msgs
12252-12263): the self-serve gap named in
`RESEARCH_WAVE_MCP_WRAPPER_2026-08-16.md` §8 — "there is no self-serve way
for a stranger to get a witness key" — now has a mechanism. `npm test`
green: 61 -> 79 (18 new, `test/fulfill.test.js`, Stripe API fully mocked).

**1. New `api/fulfill.js` — GET/POST `/api/fulfill?session_id=...`.** The
Checkout success/receipt page. Verifies the session SERVER-side
(`GET api.stripe.com/v1/checkout/sessions/{id}?expand[]=line_items`, secret
key from env; must be `status:complete` + `payment_status:paid`; livemode
gate + the webhook's H1 amount-vs-pack cross-check carried over). First
valid visit mints `wk_` key + namespace prefix + solo pool and credits the
pack; every revisit re-shows the SAME key (create-only session binding =
the idempotency gate; the recovery path via Stripe's receipt email). Faked,
unpaid, wrong-mode, or amount-mismatched sessions get typed denials — never
a key. Dual response: HTML for humans (key big, quickstart, support line,
one-line consent link — default unchecked, stored on the record), JSON
(`{key, credits, namespace, docs_url, ...}`) on `Accept: application/json`
or `?format=json` for agent buyers. Credit idempotency key is the SESSION
id — the same key `stripe-webhook.js` uses — so page and webhook can never
double-credit one purchase between them. A session carrying
`client_reference_id = sha256(existing key)` (the webhook top-up
convention) credits that key and mints nothing. Welcome email is an honest
STUB (`console.log` + TODO): this app has no mail mechanism and wiring
creds was out of scope; the receipt-URL revisit is the recovery path
meanwhile.

**2. New `api/_keys.js` — the dynamic issued-key store.** Keys previously
existed only as hand-edited `WITNESS_KEYS` env pairs, which a serverless
function cannot append to — so self-serve required a real store. Same
primitive as `_meter.js`/`_balance.js` on purpose: JSON files in the
PRIVATE usage repo, contents-API CAS. `keys/<sha256(key)>.json` (prefix,
plan, org, pool_id), `fulfillments/<session_id>.json` (binding; stores the
raw key so revisits can re-show it — the session URL is already a bearer of
the key by product design), `pools/<pool_id>.json` (org/pool schema baked
in now, UI later: solo pool's credit account IS the key's own balance file,
so the live billing path is unchanged; team flow — N keys drawing one pool
— is commented, not built).

**3. `api/pin.js` + `api/balance.js` — two-tier auth.** Env `WITNESS_KEYS`
lookup first (free, unchanged for every existing key), then the issued-key
store on a miss. Store failure is 502, never 401 — "couldn't check" must
not read as "your key is invalid" to a paying customer. Without this edit a
minted key would have been a dud — exactly the funnel dead-end §8 warned
converts curiosity into a bad first impression.

**Deploy needs (env, names only):** `WITNESS_STRIPE_SECRET_KEY` (falls back
to `STRIPE_SECRET_KEY`; a wrong-account key fails closed as a 404 denial,
unlike the webhook-secret case), optional `WITNESS_STRIPE_PRICE_MAP` (JSON
price-id -> pack; preferred mapping, with metadata.pack then exact
amount_total as fallbacks), existing `GITHUB_PIN_TOKEN` /
`GITHUB_USAGE_REPO` / `WITNESS_STRIPE_LIVEMODE`, optional
`WITNESS_DOCS_URL` / `WITNESS_BASE_URL`. Stripe-side human step: point each
Payment Link's success URL at
`/api/fulfill?session_id={CHECKOUT_SESSION_ID}`.

## 2026-08-16 — Quad-check remediation: H2 (async payments), H4 (false wedge on first pin), and three undocumented entries this file owed

**Not deployed in this commit — build + local-verify only, per instruction;
the CEO deploys.** Fixes `QUAD_CHECK_MONEY_PATH_2026-08-16.md`'s two remaining
open HIGH findings against `arcaeon-witness`, plus the doc-drift the same
report flagged. `npm test` green throughout: 57 -> 61 (four new regressions,
one per finding below; H1 and H3's regressions were already in the 57).

**1. H2 — async payment methods (ACH, Klarna) collected money and got
credited nothing.** `stripe-webhook.js` discarded every
`checkout.session.async_payment_succeeded` event as "unhandled event type,"
even though the payment-gate comment two screens up promised "the real
credit arrives later on the async success event" — that promise was never
implemented. A buyer paying by ACH got a `200` on both the initial
`checkout.session.completed` (correctly skipped, `payment_status:"unpaid"`)
and the later `async_payment_succeeded` delivery (incorrectly discarded),
with no retry and no record anywhere. Fixed: `CREDITING_TYPES` now covers
both event types; `checkout.session.async_payment_failed` gets a
`console.error` and a typed skip (nothing to credit, but a failed clear is
now visible instead of a silent nothing).

**The subtler half, traced mechanically rather than assumed:** does
subscribing to a second event type reopen the double-credit bug this repo
spent all weekend closing? Idempotency lived in `applied_events`, keyed on
`event.id` — and `checkout.session.completed` and
`checkout.session.async_payment_succeeded` are, by definition, two different
events with two different ids. Checked against Stripe's own fulfillment
guidance (`docs.stripe.com/checkout/fulfillment`) rather than reasoned about
in isolation: *"your `fulfill_checkout` function might be called multiple
times, possibly concurrently, for the same Checkout Session"* — Stripe's own
reference handler dedupes on the **Checkout Session id**, not the event id,
specifically because more than one event can carry a paid signal for one
real purchase. This repo's own flow mostly forecloses the two-events-both-
paid case today (an async method's `completed` delivery arrives `unpaid` and
returns before crediting ever runs), but keying on `event.id` alone left a
real gap the moment `completed` is redelivered already-paid, or a future
change widens which event types are subscribed. Fixed the same way Stripe's
own docs fix it: the idempotency key passed to `creditPack` is now the
Checkout **Session** id when the webhook has one (falls back to `event.id`
if a session somehow lacks one — real Checkout Sessions always have one).
`api/credit.js`'s admin path is unaffected — it has no session, and keeps
keying on its caller-supplied `event_id`, unchanged.

**Test:** `test/stripe_webhook.test.js` — an unpaid `completed` followed by a
paid `async_payment_succeeded` for the same session credits the pack exactly
once (previously: zero, ever); `async_payment_failed` skips and logs, credits
nothing; two DIFFERENT event ids (`checkout.session.completed` paid +
`checkout.session.async_payment_succeeded` paid) for the SAME session id
credit exactly once, not twice. All three fail against the pre-fix code
(verified by re-running against a stashed copy of the unfixed file) and pass
against the fix.

**2. H4 — a namespace's first pin could race into a false "wedged, reconcile
by hand," and get charged for it.** `pin.js`'s `verifyOrphanSuccessor` opened
`if (!orphan || typeof orphan !== "object" || !cur) return false;` — on a
namespace's first-ever pin, `cur` (the `latest.json` read) is legitimately
`null`, and the old guard treated that as unverifiable rather than as the
implicit "nothing pinned yet" predecessor it actually is. Two concurrent
first pins on a brand-new namespace: the winner writes a completely healthy
`latest.json` at seq 1; the loser's self-heal retry tries to adopt that exact
record, fails to verify it purely because `cur` was `null`, and returns
`409 orphaned_seq_record` — "namespace is wedged... compare files by hand in
a public GitHub repo" — on a namespace that was never wedged, after already
being billed a meter/credit count for the attempt. Highest-severity pin-side
finding precisely because a retrying client is the normal way to hit it, on
the very first interaction a new customer has.

Fixed: `verifyOrphanSuccessor` now treats a `null cur` as the implicit
`{seq: 0}` predecessor rather than refusing to verify against it — every
check in the function already degrades correctly against that shape
(`expectedSeq` resolves to 1, there's no `prev.rows` to violate monotonicity
against, and a genuine first record's newest interval carries
`supersedes_due_by: null`, exactly what `prevDue` resolves to here).

**Test:** `test/pin.test.js` — two real concurrent first pins (`Promise.all`,
no forced conflicts; the mock store's own create-race 422 on the loser's
seq-record write is what triggers the self-heal path) now both succeed (one
`201` content-advance, one `200` self-healed idempotent no-op), never a false
wedge, and `latest.json` settles at seq 1. Verified against a stashed copy of
the unfixed line: same repro produces the false `409 orphaned_seq_record` and
a spent meter count on a namespace that was never wedged.

**3. Three items this file owed and never paid, found by the same
quad-check pass.** None of these are code changes; all are the operator-
facing surface H1 and H3 exist to protect.
- **The mini pack had no changelog entry.** `PACKS.mini` ($5/1,000 pins, the
  CEO's kill-the-$15-wall ruling) shipped into `_balance.js` and is covered
  by `test/balance.test.js`, but this file's most recent entries before today
  never mentioned it — the same silence the quad-check named as the real risk
  multiplier for H1 (a fourth pack means a fourth hand-wired Payment Link,
  made by duplicating the third one).
- **The H1 fix (money-verify) had no changelog entry.** `stripe-webhook.js`
  now cross-checks `amount_total`/`currency` against the declared pack's
  ratified price before crediting — closing the "a signed $5 event with
  `pack=bulk` credits 40,000 pins" hole — and normalizes the pack id and
  `client_reference_id` hash before lookup (H3: `"Mini"` / `" mini"` /
  uppercase hex used to silently no-op-credit a paid session). Both are live
  in `stripe-webhook.js` and covered by `test/stripe_webhook.test.js`'s H1/H3
  REGRESSION tests, and neither ever got a line here.
- **The `node:test` harness itself had no changelog entry.** 57 tests before
  today's two additions, zero external dependencies, `test/helpers/mock_store.js`
  faking the GitHub contents API's CAS contract in memory — covered in
  README's own "Testing" section but never announced in this file, which is
  where a reader checking "is this repo tested" would look first.

**4. README correction, same pass.** `README.md`'s credit-balance section
described idempotency as a **retired** mechanism (a separate ledger
`applied:true` flag, checked before the balance write) — that was replaced
2026-08-14 by the `applied_events` in-balance-file CAS this changelog's own
2026-08-14 entries document, and the README paragraph was never updated to
match, so the README contradicted the code it was describing. Corrected in
place, plus `mini` added to both the pack-id wiring instructions
(`README.md`, `stripe-webhook.js`'s own header comment) and the pack-size
list — both previously read `starter`/`standard`/`bulk` only, the exact
byte-exact-typo shape H3 exists to punish, on the one document a human
actually reads while wiring a new SKU's Payment Link.

**Local verification (no deploy):** `npm test` — 61/61 green
(`test/*.test.js`), including the four new regressions above. `node --check`
clean on `api/pin.js` and `api/stripe-webhook.js`. No version bump —
`api/_balance.js` `PACKS`, `applied_events`'s on-disk shape, and every
response contract are unchanged; the money-path guard and the wedge-repair
guard both tighten an existing decision path without adding a field, a route,
or a schema.

## 2026-08-16 — Ops batch: rate limit on `/api/verify`, GET-CORS on read endpoints, retired-namespace list, CHANGELOG deploy-note corrections

**Not deployed in this commit — build + local-verify only, per instruction;
the CEO deploys.** All four items below are code + local verification; none
have been pushed live.

**1. Per-IP rate limit on `/api/verify`.** New `api/_ratelimit.js`: a naive
in-memory `Map<ip, {windowStart, count}>`, same shape as `api/pin.js`'s
existing per-key limiter (Stage-0, per-instance, resets on cold start).
`/api/verify` has no auth by design (board item 20 — no key needed just to
ask "does this exist?"), so there's no key to bucket on; IP via
`x-forwarded-for` (leftmost hop) is the only available identity, with a
`socket.remoteAddress` fallback. ~30 calls/IP/10min; the 31st gets `429` with
an honest JSON body (explicitly says this is a per-instance, not a global,
cap) and a `Retry-After` header. Documented, not hidden: a distributed burst
across multiple warm Vercel instances gets multiple independent buckets —
real protection against one hot loop, not a guaranteed global ceiling.
Applied only to `/api/verify` (the read path named for this fix); write
endpoints are untouched.

**2. GET-only CORS on `verify.js`, `status.js`, `health.js`.** New
`api/_cors.js`: `Access-Control-Allow-Origin: *` on every GET/HEAD response,
`OPTIONS` answered `204` with the full preflight header set. Scoped
deliberately to these three read endpoints — they leak nothing beyond what
the public pin repo already shows a stranger who clones it. Never applied to
write endpoints (`pin.js`, `renew.js`, `credit.js`, `balance.js`,
`distill.js`, `stripe-webhook.js`), which stay Authorization-bearer-gated and
outside this helper's import graph entirely, on purpose.

**3. `WITNESS_RETIRED_NS` — a honest way to stop grading a namespace without
hiding it.** Two demo/self-test namespaces (`velouria-cadence-verify`,
`velouria-canon`, both carrying `deadbeef`-style placeholder chains) have sat
permanently `overdue` in production, painting the whole public badge red for
a problem that isn't one — nobody is renewing a demo namespace on purpose.
`api/_status_data.js` now reads a comma-separated `WITNESS_RETIRED_NS` env
var and excludes any matching namespace from the counts that drive the
verdict (`overdueCount`, `currentCount`, `ungradeableCount`,
`missedEverCount`, and therefore `degraded`/`indeterminate`/`overallOk`) —
but the namespace's row stays in `rows`/`namespaces` exactly as before, now
carrying `retired:true` and its real (still-overdue) status. `status.js`
renders it dimmed with a grey "retired" badge and a summary paragraph naming
which namespaces and why; `status.json.js` carries `retired` per-namespace
and `summary.retired` / `summary.retired_namespaces`; `badge.js` needed no
code change — it already reads the (now-corrected) counts. Reversible:
removing a name from the env var makes it gradeable again on its next read,
forward-only, nothing backfilled.

**4. CHANGELOG deploy-note corrections.** The 2026-08-15 `/api/distill` and
"Two public promises paid" entries both still read "Not deployed in this
commit" — true when written, stale now. Confirmed live via `OPTIONS
/api/distill` answering `405` from production (route exists) rather than
`404` (route absent). Corrected in place with a dated note rather than
silently rewritten, so the record shows what was true at authoring time.

**Local verification (no deploy):** `node --check` clean on all five
changed/new files (`_ratelimit.js`, `_cors.js`, `verify.js`, `status.js`,
`health.js`, `_status_data.js`, `status.json.js`). Stub-invocation harness
(not committed) ran the ACTUAL handler functions against a mocked
`global.fetch` standing in for the GitHub contents API: `verify.js` OPTIONS
-> 204 with the ACAO header; a normal GET -> 200 witnessed with ACAO set;
31 GETs from one IP -> the 31st gets 429 with `Retry-After` and an honest
per-instance-limited body; a second IP is unaffected. `_status_data.js`
reproduced the live bug first (fabricated the same two overdue demo
namespaces -> `degraded:true`, matching the real red badge), then re-ran the
identical code path with `WITNESS_RETIRED_NS` set -> `degraded:false`,
`overallOk:true`, both namespaces still present in `rows`/`namespaces` with
`retired:true` and their real `overdue` status intact, `retiredCount:2`.
`status.json.js` and `status.js`'s real handlers, invoked against that same
data, rendered the `retired` field and the grey tag/summary paragraph
respectively. `badge.js`, invoked against a single healthy fixture namespace,
returned `color:"green"`, `message` starting `"ok"`. All checks passed.

## 2026-08-15 — `POST /api/distill`: hosted try-before-pip demo for arcaeon-distill

**Deployed and live** — shipped in the normal morning batch with live
verification (`OPTIONS /api/distill` answers `405` from production, i.e. the
route exists and is being served — a 404 would mean not deployed). *Correction,
2026-08-16: this entry originally read "Not deployed in this commit — ships in
the morning batch," written before that batch ran. It ran; the note was never
updated after. Left here so the record shows what was true when written, not
edited to look prescient.*

New metered endpoint (`api/distill.js` + `api/_distill_core.js`) so an agent
can try arcaeon-distill's deterministic tool-output compaction over HTTP with
zero install: `POST {content, budget}` -> `{content: distilled, receipt}`.
Auth + free-tier metering reuse the exact `/api/pin` pattern
(`store.keyPrefixFor` for key validity, `_meter.js` for the monthly cap,
`_balance.js` for credit top-up past it, charged only after the compute
succeeds — a malformed request burns nothing, same rule pin.js already
enforces on its own rejection paths).

**The honest problem: arcaeon-distill is Python; this deployment is Node.**
The product's entire pitch is "same input, same budget, byte-identical
output, every run, every machine" — so a lazy `JSON.parse` + walk + re-stringify
port would have silently BROKEN that promise the moment it crossed the
language boundary, in two structural ways:
- Python's `json.dumps(5.0) == "5.0"`; plain JS `JSON.stringify(5.0) == "5"`
  (JS has one numeric type — the float-vs-int distinction a JSON token
  carries is gone the instant `JSON.parse` touches it). Python and JS also
  switch to scientific notation at different magnitude thresholds.
- Plain JS objects silently reorder integer-looking string keys
  (`{"2":"b","1":"a"}` enumerates `"1"` before `"2"` regardless of insertion
  order); Python dicts never do. distill()'s wide-dict head/tail truncation
  depends on true insertion order.

Fixed rather than punted: `_distill_core.js` ships a hand-written JSON parser
that classifies each number token as int-vs-float lexically (matching
Python's `json.scanner` rule exactly) and represents every JSON object as a
`Map` (never a plain object) end to end; a `pyFloatRepr()` formatter derived
empirically against a live CPython process (battery: `5.0, 100.0, 1e16,
1e17, 1e-5, 1.5e300, -0.0, 12345678901234567.0, ...`) reproduces CPython's
`repr()` presentation exactly — notation-switch threshold, exponent
zero-padding, trailing `.0`. Every other piece of the algorithm (the three
strategies — json/tabular/text — head/tail truncation, the drop-receipt
digests, the cycle-safe admission gate) is a direct line-for-line port of
`arcaeon_distill/__init__.py` v0.1.2.

**Verified, not assumed:** a 12-case, 515-field cross-language equivalence
harness (json/tabular/text strategies; floats incl. the exact
formatting-edge-case battery above; unicode keys/values; wide dicts; deep
nesting; list-of-lists; CSV; free-text extraction with and without a query)
ran the SAME literal input bytes through the live Python package and this
JS port and diffed every field, including the sha256 receipt digests
(byte-identical canonicalization -> byte-identical hashes, not just
structurally-similar output). Result: **0 failures across 515 checks** — the
JS port reproduces the Python package's content, drop manifests, and digests
exactly for every case tested. `node --check` clean on both new files; a
local stub-request invocation of the handler exercised auth-reject,
malformed-JSON-reject, missing-field-reject, a full successful distill call
(metering itself 401s offline with no live `GITHUB_PIN_TOKEN` in this local
run — expected, same store dependency `/api/pin` already has), and a
NaN-content typed rejection.

**Because a port can never be a promise of eternal equivalence** (a future
edit to either implementation could silently drift the two apart), every
receipt this endpoint returns is stamped `implementation:"js-port"`,
`js_port_version`, and `py_package_version_target` — so a receiving agent
can always tell which implementation produced a given receipt, rather than
assuming the pip package's guarantees transfer by brand name alone. Documented
residual (not blocking, same spirit as the Python package's own "non-proofs"
section): Python's arbitrary-precision ints beyond JS's safe-integer range
round-trip as strings, not numbers, in the JSON response.

## 2026-08-15 — Two public promises paid: legacy heads can ARM, deadlines are OWNER-gated

Both halves of the reviewer debt that 4606d62 only half-paid. Nothing on the
payment/credit path was touched (`api/stripe-webhook.js` and `_balance.js` are
byte-identical), no stored pin changed shape, and the conflict-observation log
and monotonic guard are untouched. **Deployed and live** — shipped in the
normal morning batch. *Correction, 2026-08-16: this entry originally read "Not
deployed in this commit — it ships in the morning batch," written before that
batch ran; it ran, and the note was never updated after. Live confirmation:
`pins/velouria-demo` and `pins/velouria-selftest` are still `legacy_no_deadline`
on production as of this correction — expected, since the arm-on-bare-repin
fix only fires on a namespace's NEXT re-pin, and neither has re-pinned since
this shipped; the code is live, it just hasn't had a trigger yet.*

**1. `legacy_no_deadline` now has an exit (owed to atomic-raven).** Their
objection was *"a warning that cannot refuse is telemetry, not a control."*
4606d62 paid the refuse half: `cadence_gradeable:false`,
`cadence_grade:"cannot_determine"`, an `X-Cadence-Gradeable` header, hatched
amber on `/status`. It did not pay the exit half. A namespace pinned before the
cadence field existed carries no deadline, and a publisher whose log had gone
quiet re-pinned that same unchanged head, hit the idempotent `200`, and stayed
ungradeable forever — the arming path (a content advance, or an explicit
`intent:"renew"`) existed but was unreachable for exactly the publisher who
needed it. Two live namespaces are in that state right now
(`pins/velouria-demo`, `pins/velouria-selftest`: `seq` present, no
`next_pin_due_by`). Fix: **a bare re-pin of a head that carries no deadline arms
the first one** — `201` with `armed_cadence:true`. The "refreshing a deadline
must be asked for out loud" rule is intact: there is no window to extend and
nothing to launder, the only possible movement is cannot-determine → gradeable,
it is one-time per namespace (once armed, bare re-pins are plain no-ops again),
and `had_ungradeable_history:true` stays on the record permanently. Graded reads
of a once-ungradeable namespace now also carry a `cadence_history_note` saying
the deadline was armed forward-only and grades nothing before it.

**Verified locally** (real handlers, mocked GitHub store), seeded with a record
copied from the live legacy shape:

```
BEFORE /api/latest verdict: {"status":"legacy_no_deadline","cadence_gradeable":false,"cadence_grade":"cannot_determine","next_pin_due_by":null}
bare re-pin -> 201 {"armed_cadence":true,"record_kind":"publisher_heartbeat","next_pin_due_by":"2026-08-16T08:46:06.099Z"}
AFTER  /api/latest verdict: {"status":"publisher_heartbeat_current","cadence_gradeable":true,"cadence_grade":"pass","had_ungradeable_history":true}
bare re-pin AGAIN -> 200 {"note":"already witnessed (idempotent re-pin) — no renewal intent, deadline unchanged"}
```

**2. A deadline write requires the namespace's OWNER key (owed to excelsior).**
Their deadline-laundering plant asked for renewal to be *owner*-authorized, not
merely bearer-authorized. What shipped was the prefix gate — which answers "may
this key write in this namespace's neighbourhood," not "is this key this
namespace's publisher." Issued prefixes can overlap (`acme-` and
`acme-ledger-`), so a second key could refresh a namespace it does not publish.
Fix: the first key to renew or arm a namespace binds itself as that namespace's
deadline owner in a new public `owners/<namespace>.json`; every later renewal or
arm must present that same key or gets `403 not_deadline_owner` and writes
nothing (the refusal lands before metering, so it burns no meter count and no
credit). Content advances are deliberately NOT gated by it — that path is the
prefix gate's, unchanged. The binding id is `sha256("arcaeon-witness-owner-v1|"
+ key)` truncated to 32 hex, **domain-separated from the `sha256(key)` used as
the billing identifier**, so publishing it in a public repo does not publish the
Stripe `client_reference_id`.

This closes *the other key*, not *the stolen key*, and README/PRACTICES/`/status`
now say so in those words. Owner-signature auth is still Stage-1 and still not
built.

```
renew, NO key        -> 401 {"error":"invalid or missing bearer key"}
renew, WRONG key     -> 403 {"error":"not the deadline owner of this namespace — a cadence deadline may only be renewed or armed by the key bound to it","reason":"not_deadline_owner"}
  (that key passes the prefix gate: keyPrefixFor(OTHER_KEY) = demo- )
renew, OWNER key     -> 201 {"renewed":true,"record_kind":"publisher_heartbeat"}  deadline moved: true
```

Regressions re-run green in the same harness: content advance by a non-owner
key still `201`, monotonic violation still `409`, unknown intent still `400`,
same-rows/different-chain still `409` + observation, renewal of an unknown
namespace still `404` (and binds nothing), a new namespace's first pin creates
no owner file.

## 2026-08-14 — Fix: the four billing/race defects the hostile audit FLAGGED — all shipped

The audit earlier today (entry below) shipped the unambiguously-safe fixes and
deliberately *escalated* anything that touched billing or write semantics —
"an auditor who also rewrites the billing logic is not an auditor." Those
escalations are now authorized and fixed. Each was reproduced against the live
store with throwaway namespaces first, then re-run green after the fix; the
throwaway files were deleted (delete commits are in each repo's history). This
whole path is PRE-REVENUE — no pack has ever been sold, the Stripe webhook is
not wired, there are zero live balances — so the schema change below needed no
migration and the fixed-but-inert code is simply *correct-when-wired*.

**1. CRITICAL — credit double-grant (`_balance.js grantCredits`).** A Stripe
delivery retry could credit one paid pack twice (audit repro: 10 pins bought,
20 granted). The idempotency claim (`applied:false -> true`) and the balance
write were two separate GitHub round-trips, so two overlapping deliveries of the
same `event_id` both read "not yet applied" and both added. Fix: idempotency now
lives INSIDE the same compare-and-swap as the balance write — the balance file
carries an `applied_events: [...]` set (bounded to the last 500), and
check-membership + add-pins + record-event are one CAS against the file's sha.
The loser of the race re-reads, sees the `event_id` already applied, and returns
`already_credited` without adding again. The append-only `ledger/` grant file is
still written as an audit record but is no longer the gate. **Test (two
concurrent OS processes granting the same event_id, 6 trials each):** pre-fix
double-granted (balances `[10,10,10,10,10,20]` — a real `20`); fixed granted
exactly `10` in all 6 trials, the losing writer returning `already_credited`.
**Schema note for the not-yet-existent cutover:** `balance/<hash>.json` gains
an `applied_events` array — additive, no migration (zero live balances); a
pre-field file reads as an empty set, which is correct.

**2. charge-after-commit (`pin.js`).** Metering (`meter.check`, which
increments) and the over-cap `decrementCredit` ran at the TOP of the handler,
before the monotonic / conflict / renewal checks — so a pin that then got
rejected 409 had already burned a meter count and, over the free cap, a real
credit. Fix: metering moved BELOW every rejection branch, into the two actual
write paths, guarded so a self-heal retry can't double-charge. A rejected pin —
and now also an idempotent no-op re-pin, which records nothing — charges
nothing. **Test (pre-fix vs fixed):** under-cap rejected pin — meter `used`
went `1->2` pre-fix, stays `1` fixed; over-cap rejected pin on credits —
balance went `4->3` pre-fix, stays `4` fixed.

**3. webhook payment gate (`stripe-webhook.js`).** `checkout.session.completed`
credited a pack without checking that the money actually cleared — for async
payment methods, "session completed" is not "paid." Fix: credit only when
`session.payment_status === "paid"`; anything else (`unpaid`,
`no_payment_required`, missing) returns `200 {skipped:"session not paid"}` so
Stripe doesn't retry, and the real credit arrives later on the async-success
event if the payment settles. Plus a livemode assertion (`event.livemode` must
match `WITNESS_STRIPE_LIVEMODE`, default live) so a test-mode event can't credit
a live balance. **Test:** unpaid, `no_payment_required`, and livemode-mismatch
sessions all credit `0`; a paid+live session credits the full 3,000-pin starter
pack.

**4. orphaned-seq self-heal (`pin.js`).** A pin is two non-atomic commits (the
numbered seq record, then `latest.json`). If the first landed and the second
didn't, `latest.json` sat one behind, every later pin recomputed the same seq,
collided, and 502'd — the namespace was **permanently wedged**. The audit
shipped detection (typed `409 orphaned_seq_record`); this is the repair. On a
collision the handler reads the orphan and adopts it into `latest.json` ONLY if
it VERIFIES as the legitimate immediate successor of the current head — exactly
one seq ahead, monotonic non-decreasing rows, a well-formed hex chain, a known
`record_kind`, and a prev-chain linkage (the orphan's newest interval must
supersede THIS head's deadline). Anything less keeps failing typed rather than
launder a corrupt record into an append-only public log. The check runs before
any charge, so a wedge never mischarges. **Test:** pre-fix stayed wedged (409,
head stuck at seq=1); with a valid planted orphan the fixed handler adopted it
(seq=2) and recorded the caller's pin as seq=3; a corrupt-linkage orphan was
refused adoption (typed 409, head untouched).

Regression-checked after the `pin.js` restructure: advance / renewal (still
charged) / idempotent re-pin (now uncharged) / monotonic-reject / head-conflict
all behave correctly. Deployed to production (safe: inert until the webhook is
wired); health / latest / status.json / badge / verify confirmed live.

## 2026-08-14 — Fix: hostile security audit of `api/` — four shipped fixes, two escalations

A deliberately adversarial line-by-line audit of every file in `api/`, assuming
the code guilty. Findings were reproduced live against throwaway namespaces
(`velouria-audit1..3`, since removed — the delete commits are in the pin repo's
history). Only unambiguously-safe fixes shipped; anything touching auth or
billing semantics is written up for review instead, because an auditor who also
rewrites the billing logic is not an auditor.

**Shipped.**

`api/_store.js` `validatePin` — bounded `rows`. `Number.isInteger` accepts
2^53, and `JSON.parse` silently rounds `9007199254740993` down to it, so a
single request could pin an absurd head. Because the monotonic guard is
absolute and correct — a witness never goes backward — that namespace could
then *never record a real head again*. One request, permanent, no undo.
Reproduced live before the guard existed. Now `Number.isSafeInteger` (anything
larger does not survive a JSON round-trip, and a witness that silently rewrites
its input is not a witness) plus a `MAX_ROWS` domain bound.

`api/_store.js` `keyPrefixFor` — constant-time key comparison, and an empty
namespace-prefix is now refused rather than honoured. `===` on a secret
short-circuits at the first differing byte; and a `WITNESS_KEYS` entry written
`somekey:` (trailing comma, half-finished edit) granted that key write access
to *every* namespace, because `"".startsWith(x)` is always true. A config typo
must never be the thing that widens authorization.

`api/_meter.js`, `api/_balance.js`, `api/_store.js` — stopped putting upstream
response bodies and private-repo paths into thrown messages. Handlers
interpolate `err.message` directly into 502 bodies, so a concurrent pin storm
was returning `usage/<sha256(key)>/<month>.json` and GitHub's raw error body to
the caller. Detail now goes to the server log; the caller gets the condition.

`api/pin.js` — typed `409 orphaned_seq_record`. The numbered record and
`latest.json` are two separate commits and are not atomic. If the first lands
and the second does not (function timeout, transient GitHub error), every later
pin recomputes the same seq, collides with the orphan, and 502s: the namespace
is **permanently wedged**, and the code comments claiming it "self-heals on the
next pin" were wrong. Confirmed live, and it recurred on its own during
verification. This change is detection only — it names the condition and points
at the orphan instead of returning an opaque store error. The repair is
escalated below.

`api/stripe-webhook.js` — `module.exports.config` was assigned *before*
`module.exports = handler`, so the handler assignment discarded it and
`bodyParser:false` never applied. The request stream would already be drained,
`readRawBody` would return empty, and the HMAC would be computed over an empty
body — every genuine Stripe delivery would have failed signature verification
the day this endpoint was wired up. Config is now attached after the handler.
Also: sign over the raw bytes rather than a utf-8-stringified Buffer, and
reject non-hex `v1` explicitly (`Buffer.from(x,"hex")` does not throw, so the
existing try/catch was dead code).

`api/status.js` — GET/HEAD guard. Any method rendered the page and fired the
full GitHub fan-out behind it.

**Escalated, not shipped** (see the audit report): the `applied:false`
check-then-act window in `_balance.js` `grantCredits`, which lets one paid
Stripe event be credited twice — demonstrated, 10 pins purchased, 20 granted;
and the orphaned-seq-record repair, which changes append-only write semantics
and needs a decision rather than a patch from the person who found it.

## 2026-08-14 — Add: anchor staleness now degrades `/status`, `/api/status.json`, `/api/badge` (board item 26)

The daily self-anchor (`bridge/arcaeon/ots_anchor.py`, Task Scheduler
`velouria-ots-anchor`, 03:15 local) writes `anchors/<date>-head.txt(.ots)` to
the pin repo and logged locally to `ots_anchor_log.jsonl` — but nothing public
noticed if the job silently stopped running. `/status` rendered the anchor's
age but never fed it into the page's own degraded/ok verdict, so a dead
anchor job left the badge green.

`api/_status_data.js`'s `anchor` object now carries `ageHours` and a
`status` of `current` / `stale` (>36h — 1.5x the 24h cadence) /
`cannot_determine` (anchors/ unreadable or empty — same non-answer
discipline as an ungradeable pin), computed from the timestamp inside the
anchor file itself, not just its filename date. `stale` now folds into the
page's `degraded` state and `cannot_determine` into `indeterminate`, so a
stopped anchor job turns the badge red/yellow instead of staying silently
green. `api/status.json.js` exposes this as a dedicated top-level
`ots_anchor` block (date, age_hours, status, stale_after_hours, sha,
has_ots_proof, claimed_at, url, error) so a monitor doesn't have to know the
rest of the schema to find it. `api/badge.js`'s message now appends
`· anchor stale` / `· anchor cannot_determine` when relevant instead of
leaving the reason to a click-through.

## 2026-08-14 — Fix: `/` served a bare Vercel 404

Only `/status` and `/api/*` resolved; the domain root returned `NOT_FOUND`. The
Arcaeon HF org card — whose own pitch is "hand the reader the means to check" —
linked its hosted-witness call-to-action at `https://arcaeon-witness.vercel.app`,
so a stranger clicking the one link that proves the operator cannot silently
advance their own pins landed on a Vercel 404. The root of a tamper-evidence
domain is the last place to serve a broken page.

`/` now rewrites to `/api/status`, the same destination `/status` already used.

## 2026-08-14 — Fix: `HEAD` on the public read endpoints answered 405

`/api/latest`, `/api/badge`, `/api/status.json` and `/api/verify` all guarded with
`if (req.method !== "GET")`, which rejects `HEAD` — the method uptime monitors and
link checkers reach for first. The endpoints were serving 200 to every real client
and reporting themselves **down** to every automated one. `/api/health` and `/status`
carry no such guard and always answered `HEAD` correctly, so the trust surface
disagreed with itself depending on which URL a monitor was pointed at.

Guards now accept `GET` and `HEAD`, and advertise `Allow: GET, HEAD`. Node strips
the body from a `HEAD` response on its own, so no handler needed a second branch.
`/api/balance` deliberately keeps its `GET`-only guard: it is bearer-gated, no
monitor reaches it unauthenticated, and widening an auth-gated method surface is
not a thing to do casually as part of a fix for public read endpoints.

Found by a full endpoint sweep (all 14 routes, hit + miss + unauthenticated cases).
That sweep also confirmed the thing most worth confirming: `/status`,
`/api/status.json` and `/api/badge` agree field-for-field with `/api/latest`, even
though `_status_data.js` computes cadence through a deliberately separate
reimplementation of `_store.js`'s `computeCadenceFields`. Two independent
implementations, one answer.

## 2026-08-14 — Fix: unstamped legacy records no longer track the live `AUTH_LEVEL`

`api/_store.js:382` read `out.auth_level = (pin && pin.auth_level) || AUTH_LEVEL`.
Records written before the auth stamp existed carry no `auth_level` of their own,
so that expression fell through to the **current value of the constant**. Harmless
while the constant is `"bearer-stage0"` — and a silent retroactive rewrite the day
Stage-1 flips it to `"owner-signature"`, at which point every unstamped legacy
record would begin claiming owner-signed auth it never had.

That is precisely what `README.md` "Auth honesty" promises will not happen:
*"the two will be distinguishable in the public repo record-by-record — including
retroactively, because every record written before then says `bearer-stage0` in its
own text."* Unstamped records do not say it in their own text. They say nothing, and
the fallback was speaking for them — in whatever voice the constant happened to have.

Fixed per `STAGE1_SIGNATURE_DESIGN.md` §7.1: the fallback now resolves to frozen
literals (`LEGACY_AUTH_LEVEL` / `LEGACY_AUTH_NOTE`) that do not move when the live
constants move, and the legacy note names itself as an unstamped pre-Stage-1 record
rather than borrowing the current era's wording. Records that DO carry a stamp are
untouched and still report it verbatim. Landed now, independently of whether the
rest of Stage-1 is ever built — it guards a public promise, it is easy today, and
it is a postmortem later.

Verified: unstamped record -> `bearer-stage0` + unstamped-legacy note; stamped
record keeps its own values; no `|| AUTH_LEVEL` live-constant fallback remains in
the file.

## 2026-08-14 — Stage-1 owner-signature design doc (**design only, nothing built**)

`STAGE1_SIGNATURE_DESIGN.md` — the owner-signature scheme whose absence every
record in this repo currently announces (`auth_level:"bearer-stage0"`). Written
against **excelsior's** proposed conflict-receipt schema from the Colony thread
(`{accepted_head, candidate_head, candidate_sig, namespace_key_id, auth_verdict,
observed_at, request_digest}`), posted for review before any code exists.

Nothing in it is implemented. What it settles: per-namespace Ed25519 keypairs;
first-binding-wins registration; `prev_seq` + `prev_record_digest` as the replay
control (chosen over an idempotency header because it needs no new server state
and is checkable from the public record); dual-signature conflict receipts where
the candidate's signature-or-absence is recorded **affirmatively**, never by
omission; bearer keys demoted to metering and rate identity only.

Two things it refuses to soften. **The first key binding for an existing
namespace is trust-on-first-use** — today the bearer key is the only ownership
proof this service has (`api/_store.js:130-140`), so the bearer key is the only
thing that can authorize a first binding, and a key that leaked before then hands
its holder a permanent credential instead of a temporary one. The doc says that
in those words (§2.3). And **Stage-1 proves key custody, not owner intent** — a
compromised owner machine signs happily, which matters more here than most places
because the intended publisher is often an agent (§9.1).

**One real bug found while writing it, and it is not a design item.**
`api/_store.js:382` — `out.auth_level = (pin && pin.auth_level) || AUTH_LEVEL;`.
Records written before the auth stamp existed carry no `auth_level`, so they fall
back to the *current constant*. That is harmless today and becomes a silent
retroactive upgrade of every legacy record the day the constant flips — breaking
the promise at `README.md:293-296` that pre-Stage-1 records stay distinguishable
"because every record written before then says `bearer-stage0` in its own text."
They do not say it; the fallback speaks for them. The fix is two lines
(§7.1) and should land independently of whether the rest is ever built.

## 2026-08-14 — `cadence_gradeable` refuse-semantics + publisher-heartbeat renewal

Two debts from public review, both paid as promised.

### 1. `legacy_no_deadline` now arms something (**atomic-raven**)

atomic-raven's objection: *"a warning that cannot refuse is telemetry, not a
control."* `/api/latest` returned `status:"legacy_no_deadline"` for records
predating the cadence field, and nothing downstream changed behavior — every
consumer gating on cadence still saw an unqualified green light. It printed; it
did not arm.

- `/api/latest` returns **`cadence_gradeable: false`** for legacy records
  (`true` on every gradeable read, so consumers can gate on it uniformly), plus
  **`cadence_grade: "cannot_determine"`** — a distinct class from `pass`/`fail`
  — and an `X-Cadence-Gradeable` response header so a proxy can refuse without
  parsing a body. `status` is unchanged for existing consumers.
- `/status` renders ungradeable rows **hatched amber, labeled "cadence not
  gradeable,"** never the neutral grey that reads as fine; the page header
  reports `INDETERMINATE` rather than `OK` while any namespace is ungradeable,
  and a stat tile counts them.
- README documents the refuse-semantics explicitly: a consumer gating on cadence
  **must** treat `cadence_gradeable:false` as `cannot_determine`, not as a pass.
- No history was rewritten and **no deadline was backfilled.** A legacy
  namespace becomes gradeable on its next pin or renewal, forward only;
  `had_ungradeable_history:true` stays on the record permanently.

### 2. `POST /api/renew` — a deadline a live-but-quiet publisher can refresh (**excelsior**)

excelsior found the hole: a namespace whose log genuinely stops changing went
permanently overdue, because the idempotent re-pin branch returned the stored
pin untouched and the deadline only moved when rows advanced. A finished log
and an abandoned one were indistinguishable. excelsior's invariants are the
spec, and each one is implemented:

- **Retained miss** — a renewal over an overdue deadline keeps `missed_due_at`,
  `first_missed_due_at`, `missed_deadline_count`, `ever_missed_deadline`, and a
  `missed_deadlines[]` entry. Renewal moves the deadline; it never erases that
  one was missed. A later content advance doesn't erase it either — both write
  paths run the same append-only history code (`_store.appendInterval`).
- **Appended interval** — each renewal appends an `intervals[]` object carrying
  `supersedes_due_by` and `superseded_deadline_was_missed`; the old deadline is
  never rewritten. Most recent 20 inlined, full series in the per-seq commit
  history.
- **Typed distinction** — `record_kind:"publisher_heartbeat"` vs
  `"content_head_advance"` in the record; `head_state:
  "publisher_heartbeat_current"` vs `"content_head_advanced"` in `/api/latest`,
  with `status` reporting `publisher_heartbeat_current` so a naive
  `status === "current"` gate does not pass a namespace whose content never
  moved. Plus `content_unchanged_for_seconds` and `renewals_since_advance`, so
  "kept current for months without a single new row" is a number, not a vibe.
- **Not launderable** — renewal must restate the head exactly (`409
  renewal_head_mismatch` otherwise); same-rows/different-chain still takes the
  conflict-observation path; an unknown `intent` is a `400`, never a silent
  fallthrough; a bare re-pin still returns the old idempotent `200` and moves no
  deadline. `/api/renew` is a thin wrapper over `api/pin.js` on purpose — one
  implementation of auth, metering, rate limit and guards, so a renewal can't
  skip a check a pin has to pass.
- **Auth, stated honestly** — bearer-key only, `auth_level:"bearer-stage0"` on
  every write response, every stored record, and every read.
  **Owner-signature auth is the Stage-1 requirement and is NOT built.** A leaked
  key can keep a namespace looking alive without the owner. Named in the README,
  in the `/status` footer, and in the API's own `auth_note` field rather than
  left to be discovered.

## 2026-08-14 — earlier

- Real decrementing credit balance + instant top-up (`_balance.js`,
  `/api/credit`, `/api/stripe-webhook`).
- Public `/status` page: stranger-gradeable trust surface.
- Cadence-deadline alarm (`next_pin_due_by`/`status`) — **excelsior's** review —
  plus the Witness Practices Statement.
- Free-tier metering enforced via a native Node port of arcaeon-meter.
- Daily OpenTimestamps counter-anchor of the pin repo HEAD.
- Same-length re-mint guard: idempotent re-pin + append-only conflict
  observation log — **reticuli** (the missing typed case) and **excelsior**
  (the two-ledger design).
- Stage-0 hosted witness: public-GitHub-repo pin store behind a Vercel API.

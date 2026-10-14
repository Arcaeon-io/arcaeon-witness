// _case_http.js — POST ?op=case-open, ?op=case-commit and ?op=case-reveal,
// co-hosted on api/verify.js. Underscore prefix = not routed as a serverless
// function.
//
// WHY IT RIDES ON verify.js: api/ is at the Vercel Hobby 12-function cap, and
// the design says so in capitals: "No thirteenth function. Every new route is
// `?op=case-<verb>` on `verify.js`." (CASE_PROTOCOL_DESIGN_2026-10-10.md,
// velouria projects/arcaeon/, version 2). Dispatched next to ?op=reconcile,
// before verify's GET-only CORS helper; it shares nothing with verify's logic.
//
// WHAT IS HERE (design, "Scope of this item, and the next", and "After the
// fix pass"). Item one: the opening and "the registration path
// (?op=case-commit) with its public first-write-wins record". Item 2a: the
// joint reveal (?op=case-reveal) with every refusal, the reconcile run and
// its receipt, and the seal. Item 2b: the key on case-open, the deadline
// horizon, and the reveal's refusal of a registration with no stamp commit.
// Item 2c: the withdrawal (?op=case-withdraw), the reference row
// (?op=case-reference) and the per-key open quota; the page is
// lib/_case_page.js. lib/_case.js holds every schema rule and
// lib/_case_seal.js the seal's; this file reads, writes and refuses.
//
//   POST ?op=case-open    the opening: {protocol_version, policy_version,
//                         scope_digest, party_a, party_b, opened_at, deadline}
//                         -> cases/<case_id>.json, status OPEN, 201.
//   POST ?op=case-commit  {case_id, role, commitment_sha256, verifier, sig}
//                         -> cases/<case_id>/commit_<role>.json, 201, and the
//                         case object's commitments, rebuilt from both roles'
//                         files; status COMMITTED once both are registered.
//                         The same registration again is 200 (a replay).
//   POST ?op=case-reveal  {case_id, reveals: {a: {tape_sha256, salt}, b: ...},
//                         cross_reference?} and the two tapes, tape_a and
//                         tape_b, as ?op=reconcile takes tapes
//                         -> cases/<case_id>.json sealed (status VERDICT), 201,
//                         then its pin, pins/case/<case_id>/.
//   POST ?op=case-withdraw {case_id, role, tape_sha256, salt}
//                         -> cases/<case_id>.json replaced by the redacted
//                         record (status WITHDRAWN), 201, then the marker
//                         cases/<case_id>/withdrawn, create-only.
//   POST ?op=case-reference {case_id, cross_reference, role?, tape_sha256?,
//                         salt?} -> cases/<case_id>/references/<seq>.json,
//                         create-only, 201.
// All five write to the PINS repository through lib/_store.js (design:
// "writes the registration as cases/<case_id>/commit_<role>.json in the pins
// repository"). The stamps repository is only READ, through the stamp read
// path (lib/_stamp_store.js getFile and listCommits on lib/_stamp.js
// stampPath).
//
// REFUSALS ARE TYPED, the reconcile endpoint's rule: {ok:false, error_code,
// error, ...} with a 4xx for a request this service will not act on, a 503 for
// a store it could not read or write, and never a 500 for a bad request.
//
// A KEY TO OPEN (item 2b; design decision 5, the owner's exposure call:
// "Opening costs no credits but needs ARCAEON_KEY ... a stranger can open a
// case for free but not anonymously"). ?op=case-open requires
// `Authorization: Bearer <key>`, any valid issued key, resolved by the same
// function the paid stamp path uses (lib/_stamp.js resolveKey: the
// WITNESS_KEYS env keys first, then the issued-key store, the order
// api/pin.js uses). No key is 401 `key_required`; a key that is not a valid
// issued key (unknown or revoked) is 401 `key_invalid`; a key store that
// cannot be read is 503 `key_store_unreachable`, never a 401, because "could
// not check" is not "your key is invalid". The check runs right after the
// method, before any rate budget is spent, and before the body is read, and
// nothing is charged. THE KEY FIRST, THEN ITS BUDGET (FIX F, 2026-10-12;
// GPT-5.6 §1.5: the per-IP check used to run first, so requests carrying no
// key could spend an address's budget and a valid key from that address was
// refused 429 before it was read). A request with a valid key draws on that
// KEY's budget (lib/_ratelimit.js checkKey, PER-KEY BUCKETS: the per-IP
// limit and window, per key) and never on its address's; every other open
// (no key, a key that is not valid, a key store that could not be read)
// draws on the per-IP budget, and past it is 429 `rate_limited` before its
// 401 or 503. So traffic without the key cannot spend a valid key's budget,
// and a stolen key spends its own (and its own OPEN QUOTA, below). The
// keyless ops (commit, reveal, withdraw) stay per-IP, and so does a
// reference, except one carrying the operator's bearer (THE OPERATOR'S KEY,
// below, THE OPERATOR'S BUDGET). The key read
// is a WITNESS_KEYS lookup in memory, or one read of the issued-key store
// for a key not listed there, ahead of any budget, as api/pin.js reads it.
// The case records nothing about the key: the schema has no field for it.
// Registration takes no issued key and is metered by the stamp, and since
// red-team fix A it is signed by the party's own registration key (ONE KEY
// PER ROLE, below); the reveal, the withdrawal and a role's reference row
// take no key (a role proves itself by its preimage). The key's write quota
// is THE OPEN QUOTA, below.
//
// THE OPENING. lib/_case.js validates it and derives the id; the parties are
// stored in canonical order, so party_a (role a) is whichever party sorts
// first, and the answer says `parties_reordered: true` when that is not the
// order the caller sent. The same opening twice is the same case id, and the
// second is refused `case_exists`: the case file is create-only. Two clock
// rules need a clock and so live here: an opened_at more than
// lib/_check_record.js's DEFAULT_SKEW_SECONDS ahead of this service's clock is
// refused `future_dated` (that file's rule: "A claim from the future is not a
// claim anyone can have evidence for"), and a deadline already passed is
// refused `deadline_passed`, because nothing could ever be registered to it.
// A deadline more than 30 days after opened_at is refused `deadline_too_far`
// (lib/_case.js, THE DEADLINE HORIZON).
//
// THE REGISTRATION (design, "The commitment format"): "Registration verifies
// that a stamp with that hash exists, reads stamp_commit and stamped_at from
// the fetched stamp record (kind file-stamp, matching hash), refuses a second
// registration for the same role (role_already_committed), refuses a
// registration after deadline (late_commitment), and writes the registration
// ... first write wins." And from GPT-5.6's review: "The service must not
// trust copied stamp fields." So the body is exactly five fields, the three
// the design names and the registration key's two (ONE KEY PER ROLE, below),
// and anything else (a stamped_at, a commit, a record_url) is refused
// `unknown_field`, never quietly dropped: a caller who sent one believes it
// was used.
//
// ONE KEY PER ROLE (red-team fix A; lib/_case.js, ONE KEY PER ROLE). The two
// roles of a case are registered by two distinct key ids. The body carries
// the party's verifier and its signature over the registration
// (lib/_case.js registrationSigningBytes); a signature the verifier does not
// confirm is 403 `registration_unauthorized`, checked before anything is
// read. A NEW registration whose key id is the other role's registered key
// id is 409 `same_key_both_roles`, and nothing is written. A registration
// under another key for a role that already has one is
// `role_already_committed`, never a replay. The registration file keeps
// key_id, verifier and sig; the case's commitment entry keeps key_id. Two
// registrations that race past the check (each reads the other role's
// projection absent) both write their files, and the second projection reads
// the first and is refused 409 `same_key_both_roles` (THE PROJECTION,
// below); its file stays, inert. A case whose two commitments share a key id
// (none can be projected now) is SINGLE PARTY, and the joint reveal refuses
// it (409 `single_party`, step 2 below), so it never reaches sealed.
//
// THE STAMP'S SIZE (item 1b; both code reviews, GPT-5.6: "It detects the
// common error of stamping a tape hash rather than the canonical commitment
// bytes"). The design has a party POST {sha256: commitment, size: <length of
// the canonical bytes>} to the stamp endpoint, and a case/1 commitment's
// canonical bytes are always lib/_case.js COMMITMENT_BYTES_LENGTH (272) long.
// So the fetched stamp record must say `size: 272`. A party that stamped its
// tape hash instead of its commitment bytes has stamped the wrong thing, and
// the size is the cheapest tell: that stamp records the tape's length, and a
// stamp with no size records null. Either is refused `stamp_size_mismatch`
// (409, the caller's to fix), and neither the registration nor the case
// update is written. The fix is a NEW commitment: a hash is stamped once,
// forever (lib/_stamp.js, first write wins), so a party that stamped its
// real commitment with no size cannot re-stamp that hash. It draws a fresh
// salt, stamps the new commitment with size 272 and registers that. The size
// is a tell, not a proof: it is the stamper's own declaration, so a wrong
// stamp declaring 272 passes here, and only the reveal's recomputation (item
// two) can catch it. The check runs after the record's readability checks,
// so a damaged record still reads as damaged (503), never as a caller's
// mistake.
//
// STAMP_COMMIT, READ FROM THE STAMP'S HISTORY (item 2a; design decision 1:
// "Item two adds one store primitive, a commits-for-path read of the stamps
// repository (mock supported), and fills stamp_commit from it at
// registration; a stamp path touched by more than one commit is refused
// stamp_history_ambiguous"). The stored stamp record is {kind, v, sha256,
// size, stamped_at}: it does not carry the commit that holds it, and the
// contents read returns only the file's blob sha, which is not a commit. So
// item one recorded `stamp_commit: null`. Now step 6c asks the stamps
// repository for the commits on its branch that touched the stamp's path
// (lib/_store.js listCommitsPage, through lib/_stamp_store.js) and records
// one. Since unit R-RV (the architect's ruling b) it records the OLDEST
// commit that touched the path, every page of the history walked: a stamp is
// written once (lib/_stamp.js, first write wins), so the oldest is the one
// that wrote it, and a later commit touching the path no longer refuses the
// registration (`stamp_history_ambiguous` is gone). None is a history that
// does not show a record the contents read just returned, and a history
// longer than this service reads (STAMP_HISTORY_PAGES) leaves the oldest
// unknown: both 503 `stamp_history_unreadable`; a history that cannot be
// read at all is 503 `stamp_history_unreachable`. In every one of those,
// nothing is written. stamp_commit is required (since unit R-RV the schema
// refuses null, the item-one form; nothing is deployed, so no such record
// exists outside the tests). The commit's date is the stamps
// repository's own statement (lib/_store.js header), not independent time
// evidence; the registration records the commit, not its date.
//
// IDEMPOTENT REPLAY (item 2a). The same registration sent again, the same
// hash under the same key for the same role, is a replay and never
// `role_already_committed`. When the case root projects it, the replay
// rechecks the stamp record (step 6r: present, a readable file-stamp of
// this hash, size 272) and answers 200 with `existing: true`, writing
// nothing, whatever the case's state since (unit R-L4c, c1: a sealed case
// answers the registration it projects). Only a DIFFERENT hash, or another
// key, for a role the root projects is `role_already_committed`.
//
// THE PROJECTION (unit R-L4; these rules replace the unwind, the repair
// notes and the condemned file of units R-N, R-L, R-L2 and R-L3, and nothing
// is ever deleted). A registration is two writes: the registration file,
// create-only, then the case root's projection of it. The file is a CLAIM,
// INERT until the root projects it; the root's entry carries the sha256 of
// the file's bytes (lib/_case.js THE PROJECTION), and every reader takes
// registrations from the projection alone and checks the file against it
// (lib/_case_seal.js projectedRegistrations; a projected file missing or
// not the file projected is 503 `case_record_inconsistent`, never sealed:
// unit R-L4b; the code alone, its reason in the operator log: unit R-L4e).
//   THE CLAIM (unit R-L4c, c4, as the architect ruled; lib/_case.js): a
// registration file is keyed by its claim, the sha256 of the fields a party
// supplies: registrations/<case_id>/<role>/<claim>.json, create-only. More
// than one claim for a role may exist, and the root projects at most one.
// A file is written only when the root as read shows the case open, the
// role unprojected, before the deadline, and able to take it: a role
// projected for another claim is 409 `role_already_committed` naming the
// projected sha256, and nothing is written. There is no cap on claim files
// per role (a cap is a slot an adversary fills); the per-IP limiter is the
// only bound, and a file written under it never stands once the role is
// decided. Every answer after a file is written names its path.
//   The handler projects only after a fresh read of the root (the
// confirming read) shows no withdrawal and no seal, before the deadline by
// the server clock read just before the compare-and-swap (unit R-L4c, c2),
// and the projection is a COMPARE-AND-SWAP over that read; a root that
// already projects the file is the answer, whatever its state since (c1).
// THE TIE RULE: the compare-and-swap decides; one that loses is never
// retried, and the root, read once more, is the answer (200 when it
// projects this file, 409 `role_already_committed` naming the projected
// sha256 when it projects another). The case lock (THE CASE LOCK, below) is
// a courtesy that serializes writers; the compare-and-swap is the guard. If
// the confirming read or the projection fails, nothing more is written: 503
// `registration_unconfirmed`, "the registration file is written and is not
// yet confirmed; send the same registration again". A re-send finds its own
// file at its claim's path and takes it as it is (never its bytes again,
// whose registered_at and stamp fields this service added; also the lost
// create-only race: the winner's file is the same claim, as it is) to the
// confirming read and the projection. Past the deadline a file the root
// does not project never stands: 409 `late_commitment`. A root that reads
// WITHDRAWN at the confirming read is 409 `case_withdrawn`: the file is
// written and has no standing, and it stays. `registration_recorded` in an
// answer is the root's projection of this registration: false when the
// root as read does not project it, null when it is not known (a read or a
// write that failed).

// ROLE BINDING AT REGISTRATION. The service sees a hash, not its preimage, so
// it cannot read the role inside a commitment. What it enforces: the role is
// bound in the registration record and its path, and one hash cannot hold
// both roles of a case (`commitment_registered_to_other_role`). The reveal in
// item two recomputes the commitment under the REGISTERED role, so a role-a
// preimage registered as b cannot match there.
//
// THE JOINT REVEAL (item 2a; design, "The joint reveal and its refusals").
// One request carries both reveals and both tapes; nothing is held between
// steps, and nothing is written until every check below has passed. The
// tapes come as ?op=reconcile takes them (JSON text, base64, or multipart
// parts, read by lib/_reconcile_http.js readFields and tapeFrom with its
// caps), named by role: tape_a is role a's, tape_b role b's (lib/_case.js,
// THE JOINT REVEAL'S BODY, says why not by side). In order:
//   0. the request: the case fields' shape (lib/_case.js validateRevealBody,
//      which refuses a caller's time) and the two tapes; an already-parsed
//      body is measured against the reconcile endpoint's cap;
//   1. the case: WITHDRAWN is `case_withdrawn`; already VERDICT is
//      `not_committed` (a case has one joint reveal); at or past its
//      deadline by this service's clock it reads EXPIRED and the reveal is
//      `expired` (an OPEN case past its deadline is EXPIRED too, not
//      not_committed); otherwise anything but COMMITTED is `not_committed`;
//   2. the registrations are the case root's projection, each projected
//      file checked against the sha256 it carries (THE PROJECTION, above):
//      a projected file missing or not the file projected is 503
//      `case_record_inconsistent` (unit R-L4b), a file that could not be read
//      503 `could_not_look`; one key id in both registrations is a
//      single party (ONE KEY PER ROLE, above): 409 `single_party`. Since
//      unit R-RV the reveal reads no stamp: a seal's stamp_commit and
//      stamped_at are the projected registration's (the stamp was read at
//      registration, and stamp_commit is required there);
//   3. each reveal recomputes the commitment registered to its role, under
//      the REGISTERED role (`commitment_mismatch`): the reveal-time half of
//      role binding, so A's tape and salt sent as B's are refused here;
//   4. each tape's sha256 is the committed tape_sha256 (`tape_substituted`);
//   5. the case's bound policy_version is the port version this build runs,
//      or `policy_unavailable`: it never compares under another version
//      (design decision 8);
//   5b. the key document this deployment carries and the commit it was
//      built from (Design I, lib/_case_seal.js SIGNED UNDER ONE DOCUMENT,
//      sealingDocument): either one unreadable is 503 `document_unavailable`,
//      and nothing is compared or written; since unit R-I (5b2,
//      confirmSealingDocument) so is a commit not on the published branch
//      (KEY_DOCUMENT_BRANCH), and a document at that commit that cannot be
//      read or is not the bundled one;
//   6. the comparison, lib/_reconcile_http.js compare, the very call
//      ?op=reconcile makes, once, role a's tape first; with no reconcile
//      signer it refuses before comparing (red-team fix B, NO SIGNER, NO
//      RECEIPT in lib/_reconcile_receipt.js): 503 `signer_unavailable`,
//      nothing compared, nothing written;
//   7. the receipt, checked deeply (lib/_case_seal.js checkReceipt);
//   8. the seal: the case file, THE ONE WRITE (unit R-RV): the reveal
//      writes the case root once, the VERDICT seal, by compare-and-swap on
//      the blob sha of the COMMITTED root it read at step 1. Nothing is
//      written before it;
//   9. the pin (lib/_case_seal.js pinChain).
// Every refusal in 0 to 5 is a typed 4xx with an error_code (a 503 when the
// store cannot be read or does not agree with itself), carries no verdict,
// writes nothing and never runs reconcile. After 6 has run, a failure
// writes nothing too, so the case stays exactly as it was read: the
// comparison raising is 500 `comparison_failed`, a receipt that fails its
// own check 500 `receipt_check_failed`, a verdict a JSON record cannot hold
// 422 `verdict_not_sealable`, a sealed case the schema refuses 500
// `seal_build_failed`; the server log names the case and the code only. A
// seal write that throws is 503 `case_seal_failed` (the case may not have
// been sealed; the same reveal sent again seals it or says it is sealed). A
// seal whose compare-and-swap loses reads the root once more: VERDICT is 409
// `not_committed`, WITHDRAWN 409 `case_withdrawn` with no verdict, receipt
// or tape digest, and anything else 503 `case_seal_failed`. A
// pin that fails after the case file landed is not a failure of the seal:
// the answer is 201 with `pin: "commit_unrecorded"` (TWO WRITES in
// lib/_case_seal.js), and the sealer's next run pins it (lib/_case_seal.js,
// THE TRIGGER). The pin is the second phase of the case file's write (Design
// J, THE PIN IS THE SECOND PHASE): it records `case_commit`, the commit the
// case file's own write answered with, and the answer carries it too (null
// when that write's answer named none, and then no pin is written). A pin
// written is `pin: "pinned"` with `pin_commit`, the commit that wrote it
// (lib/_case_seal.js THE PIN WORDS: a case's one pin, no pointer, and no
// anchor word). Every success carries `anchor_note`, lib/_case_seal.js
// ANCHOR_NOTE.
// Every time the seal records comes from one read of this service's clock,
// taken after the port returns (unit R-RV, the architect's ruling c):
// revealed_at, the receipt's compared_at, signed_under's retrieved_at, a
// cross_reference's recorded_at, and the pin's pinned_at. The deadline is
// judged by the clock read when the request arrived.
//
// THE OPEN QUOTA (item 2c; design "After item 2b": "twenty opens per key per
// UTC day, 429 open_quota_exceeded"). After the opening is validated and
// before the case is written, the open takes one unit of its key's day
// (takeOpenQuota): a counter record {kind: "case-open-quota", v: 1, day,
// count} in the PRIVATE usage repository, case_opens/<sha256 of the
// key>/<YYYY-MM-DD>.json, created or updated through the store's CAS, so the
// count holds across instances (not a per-instance Map). At twenty the open
// is 429 `open_quota_exceeded`, with retry-after to 00:00 UTC, and nothing
// is written. A counter that cannot be read or written, or that is present
// and unreadable, is 503 `open_quota_unreadable` (never read as zero). The
// same opening twice is refused `case_exists` by a read BEFORE the quota, so
// a duplicate spends nothing; a case write that fails after the quota was
// taken over-counts by one, which errs toward refusing (the stamp budget's
// rule).
//
// THE CASE LOCK (red-team fix C, 2026-10-12; GPT-5.6 §1.1 / §6.2: "A
// commitment can land after withdrawal ... the registration file remains
// written"). A registration file never stands after its case's withdrawal.
// The registration write and the withdrawal's root write take one per-case
// lock, a lease in the PRIVATE usage repository beside the quota counters,
// case_locks/<case_id>.json {kind: "case-lock", v: 1, case_id, holder, op,
// acquired_at, expires_at, state}, acquired by the store's conditional
// writes (create-if-absent, or update-if-unchanged over a released or
// expired one; lib/_claim.js's discipline), held CASE_LOCK_TTL_SECONDS and
// released by the holder. A live lock held by another request is waited on
// CASE_LOCK_ATTEMPTS times and then 503 `case_busy`; a lock that cannot be
// read is 503 `case_lock_unreachable`, one present and unreadable 503
// `case_lock_unreadable`; nothing is written in any of them.
//   Under the lock the commit reads the case again and, when it reads
// WITHDRAWN, writes nothing: 409 case_withdrawn, `registration_recorded:
// false`. A lease is not a lock: one that ran out can be taken over, so a
// withdrawal may land between that read and the projection; then the
// confirming read finds it, the file is inert, and nothing is removed (THE
// PROJECTION, above). After a withdrawal a registration never stands: the
// redacted root projects none (a refusal receipt may name one the root
// projected before it: THE REFUSAL BEFORE THE TAPES). THE LEASE CLOCK is
// read at each attempt; a lease expires CASE_LOCK_TTL_SECONDS after its own
// acquisition.
//
// THE WITHDRAWAL (item 2c; lib/_case.js THE WITHDRAWAL). Keyless: A ROLE
// PROVES ITSELF, below. In order: the body (exactly {case_id, role,
// tape_sha256, salt}); the case, refused if VERDICT (`case_sealed`),
// already WITHDRAWN (`case_withdrawn`) or at or past its deadline
// (`expired`, the case reads EXPIRED); the case root's projection, its files
// checked against it (THE PROJECTION, above); the proof (403
// `withdraw_unauthorized`); the redacted record, signed with the case key
// (lib/_case_seal.js withdrawnRecord; since unit R-N, N1, signed or not
// written: without a case key 503 `signer_unavailable`); the root write, a
// CAS over the case as read; then the marker cases/<case_id>/withdrawn,
// create-only, so a tree listing shows the withdrawal without a fetch, and
// the withdrawn commitment (unit R-N, N2; lib/_case_seal.js THE WITHDRAWN
// COMMITMENT), so ?op=reconcile refuses the withdrawer's tape. A RETRIED
// WITHDRAWAL (unit R-N, C3), the same role with the same preimage, is 200
// with the record as it stands, and writes again a marker or a withdrawn
// commitment that failed. THE CAS DECIDES A RACE: the
// reveal writes the sealed case over the COMMITTED case it read, and the
// withdrawal writes the redacted record over the case it read, each with
// that read's sha. Whichever lands first stands, and the other's write is
// refused by the store: a reveal that loses answers 409 `case_withdrawn`, a
// withdrawal that loses answers 409 `case_sealed`. A registration projected
// meanwhile is no race: the redacted record does not depend on it and is
// written over the fresh case. Registration files are left in place,
// public, standing for no reader, and the answer says so in words
// (registrations_note). A marker that fails leaves the withdrawal
// standing (the root is the authority, and the sealer reads it, skips it as
// terminal and writes the marker); the answer says `marker: "failed"`.
// Nothing of the preimage is kept except salt_sha256 and the sha256 of the
// tape digest's bytes (the withdrawn commitment), and nothing of it is
// logged.
//
// A ROLE PROVES ITSELF (item 2c). By presenting its commitment preimage
// (tape_sha256 and salt): the commitment is recomputed under the NAMED role
// and must equal the commitment the case root projects for that role, its
// file checked against the projection (proves; THE PROJECTION, above). The service never
// learns who the caller is; it learns that the caller holds the preimage the
// role committed to. Before a joint reveal only that role's party holds it.
// After the reveal, the parties have exchanged their reveals out of band, so
// either may hold both; a reference row's "role:a" then means a holder of
// role a's preimage.
//
// THE REFERENCE ROW (item 2c; lib/_case.js THE REFERENCE ROW). Only a
// SEALED case takes one (else 409 `case_not_sealed`, or `case_withdrawn`).
// A VERDICT is a sealed case only when it passes THE SEALED CHECK (item 2d;
// lib/_case_seal.js sealedRecordReason, the check anchorCase runs before it
// pins; since Design I under the key document the case NAMES): it takes a
// row on valid_under_document only (since unit R-REV a key the current
// document lists revoked is 409 `signer_revoked`). A named document it
// cannot read is 409 `document_unavailable`, a seal that names none 409
// `document_unrecorded`, a case one key registered both roles of 409
// `single_party` (red-team fix A), a receipt that does not bind 409
// `verdict_unbound`, a receipt the named document's reconcile key did not
// sign 409 `receipt_unsigned` (red-team fix B), a case signature the
// named document does not confirm 409 `case_signature_invalid`, and since
// unit R-I a key the current document does not list in its role 409
// `signer_unlisted` and (since unit R-REV, whenever it signed) one it lists
// revoked 409 `signer_revoked`, each with its `reason`,
// and no row is written. The check runs before the proof is read. Who appends: a
// registered role proving itself (A ROLE PROVES ITSELF), or THE OPERATOR'S
// KEY, below; the row records which in appended_by. The row
// is written create-only at the next seq (the highest listed plus one); a
// row that lands first at that seq is never written over, and this one
// moves to the next (at most three tries). It is signed with the case key
// (lib/_case_seal.js referenceRow), judged by its own judge before it is
// written, and has no pin of its own. The sealed case is never touched.
// NO PIN GATE (unit R-PIN): no pin and no anchor is read for a row, and its
// answer names no commit; the row is recorded by the commit that writes it.
//
// THE REFERENCE QUOTA (FIX G, 2026-10-12; GPT-5.6 §2C: one role's proof
// could append rows to a case without end). A role appends at most
// REFERENCE_QUOTA_PER_ROLE rows to one case: 20, THE OPEN QUOTA's number, the
// same constant. After every check (the proof, the listing, the next seq,
// the row built and judged) and before the row's write, the request takes
// one unit of that role's count (takeReferenceQuota; once, not again when
// another row takes the seq and this one moves on), a counter record {kind:
// "case-reference-quota", v: 1, case_id, role, count} in the PRIVATE usage
// repository beside the open quota's, case_references/<case_id>/<role>.json,
// through the same CAS (takeUnit). Past it, the request is 409
// `reference_quota`, with `count` (the counter's) and `quota` in the body,
// and nothing is written. A counter that cannot be read or written, or that
// is present and unreadable, is 503 `reference_quota_unreadable`. Only a
// role that has proved itself spends its count, and the roles count apart.
// A row not written after the unit was taken (its write fails, or other rows
// keep taking the seq) over-counts by one, which errs toward refusing (the
// open quota's rule), so `count` can exceed the role's rows that stand. The
// operator's rows are not a role's and take no unit. Across roles, a case
// holds at most 500 rows (THE ROW CAP, lib/_case_seal.js
// MAX_REFERENCE_ROWS; unit R-L2, M3): the 501st is 409 `row_limit`.
//
// THE OPERATOR'S KEY (item 2c; its own key since item 2d).
// `Authorization: Bearer <WITNESS_CASE_OPERATOR_KEY>`, compared in constant
// time. It is a key for this one purpose, read from its own variable and
// never from WITNESS_ADMIN_KEY (api/credit.js's admin key, which tops up
// credit and authorizes nothing here: 2c used it, and the code review of 2c
// asked for a dedicated key). It decides who may append as "operator"; the
// row is signed by the case key either way. An issued customer key is not
// the operator's (401 `reference_unauthorized`). With
// WITNESS_CASE_OPERATOR_KEY unset, what the code does, in its order: a
// request with no role proof and no bearer is 401 `reference_unauthorized`
// (the missing bearer is checked first, so an unconfigured deployment and a
// configured one answer an anonymous request alike), and a request with no
// role proof and a bearer is 503 `operator_key_not_configured`. No bearer
// can append as the operator while it is unset. A role's proof is
// authorized without the variable.
// THE OPERATOR'S BUDGET (2026-10-12; FIX F's shape, A KEY TO OPEN). The
// bearer is compared before any rate budget is spent, and a reference that
// carries the operator's bearer draws on that key's own budget
// (lib/_ratelimit.js checkKey) and never on its address's, whether or not
// its body also carries a role's proof (which then decides who appends, as
// before). Every other reference (no bearer, a bearer that is not the
// operator's, any bearer while the variable is unset) draws on the per-IP
// budget, and past it is 429 `rate_limited` before its 401 or 503. So
// traffic from an address that does not hold the operator's key cannot
// spend the operator's budget.
//
// NOTHING ELSE IS KEPT. No tape and no salt is written or logged by this
// file. The reveal holds both tapes and both salts in memory for one
// request; the sealed case keeps each tape's sha256 once, in `reveals` (the
// design: it "must equal the receipt's received-tape hash"), and each salt
// only as salt_sha256. A withdrawal keeps its salt only as salt_sha256 and
// its tape hash not at all; a reference row keeps neither.

"use strict";

const crypto = require("node:crypto");
const C = require("./_case.js");
const SEAL = require("./_case_seal.js");
const RECONCILE = require("./_reconcile_http.js"); // readFields, tapeFrom, compare: ?op=reconcile's own steps
const T = require("./_reconcile_tapes.js");
const store = require("./_store.js");
const stampStore = require("./_stamp_store.js");
const stamp = require("./_stamp.js"); // stampPath only: the one definition of where a stamp lives
const verdict = require("./_verdict.js");
const ratelimit = require("./_ratelimit.js");
const { DEFAULT_SKEW_SECONDS } = require("./_check_record.js");
const keys = require("./_keys.js"); // keyHash, USAGE_REPO, USAGE_BRANCH: THE OPEN QUOTA's counter

const BODY_MAX_BYTES = 16384;

// THE OPEN QUOTA, above: opens a key may make in one UTC day.
const OPEN_QUOTA_PER_DAY = 20;
// THE REFERENCE QUOTA, above: rows one role may append to one case. One
// number with the open quota's.
const REFERENCE_QUOTA_PER_ROLE = OPEN_QUOTA_PER_DAY;

// The counter lives in the PRIVATE usage repository, beside the meter's
// usage files and the issued keys (lib/_meter.js: "never the public pin
// repo"), named by the key's sha256 (keys.keyHash, the billing identifier),
// never by the key. One file per key per UTC day, create-or-update through
// the store's CAS (lib/_store.js putFile with a rebuild hook), so the count
// holds across serverless instances: it is not a per-instance Map.
function quotaStore() {
  return store.forTarget({ repo: keys.USAGE_REPO, branch: keys.USAGE_BRANCH, tokenEnv: "GITHUB_PIN_TOKEN", ua: "arcaeon-witness-case-quota" });
}
function openQuotaPath(key, day) {
  return `case_opens/${keys.keyHash(key)}/${day}.json`;
}
function quotaRecord(day, count) {
  return { kind: "case-open-quota", v: 1, day, count };
}
function referenceQuotaPath(caseId, role) {
  return `case_references/${caseId}/${role}.json`;
}
function referenceQuotaRecord(caseId, role, count) {
  return { kind: "case-reference-quota", v: 1, case_id: caseId, role, count };
}

// Take one unit of the counter at `path`, held to `limit`; `record(n)` is
// the counter record at count n. Counter first, the write it pays for
// second: if that write then fails, the counter has over-counted by one,
// which errs toward refusing, never toward unlimited (the stamp budget's
// rule, lib/_stamp.js). A counter that is present and unreadable throws
// (lib/_verdict.js judgeCounter: never read as zero), and so does a store
// that cannot be read or written; the caller answers 503.
// -> {ok:true, used} or {ok:false, used} (the quota is spent).
async function takeUnit(path, limit, record, what, message) {
  const q = quotaStore();
  const countOf = (got) => verdict.counterValue(verdict.judgeCounter(got, "count", { what, integer: true }), what);
  // Two takers creating the counter at once: the loser gets the create-race
  // 422 (err.conflict), which putFile does not retry. Re-read and go again,
  // a bounded number of times; past that, the caller refuses.
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const cur = await q.getFile(path);
      const used = countOf(cur);
      if (used >= limit) return { ok: false, used };
      let denied = null;
      let counted = used + 1;
      await q.putFile(path, record(used + 1), message, cur ? cur.sha : undefined, {
        rebuild: (fresh) => {
          const n = countOf(fresh);
          if (n >= limit) {
            denied = { ok: false, used: n };
            return null;
          }
          counted = n + 1;
          return record(n + 1);
        },
      });
      return denied || { ok: true, used: counted };
    } catch (e) {
      if (!(e && e.conflict) || attempt === 3) throw e;
    }
  }
  throw new Error("takeUnit: unreachable");
}

// One unit of `key`'s day. -> {ok, used, day}.
async function takeOpenQuota(key, nowMs) {
  const day = C.utcSeconds(nowMs).slice(0, 10);
  const taken = await takeUnit(openQuotaPath(key, day), OPEN_QUOTA_PER_DAY, (n) => quotaRecord(day, n), "case open quota", `case-open quota ${day}`);
  return { ...taken, day };
}

// One unit of `role`'s rows on case `caseId`. -> {ok, used}.
async function takeReferenceQuota(caseId, role) {
  return takeUnit(referenceQuotaPath(caseId, role), REFERENCE_QUOTA_PER_ROLE, (n) => referenceQuotaRecord(caseId, role, n),
    "case reference quota", `case-reference quota ${caseId.slice(0, 16)} ${role}`);
}

// THE CASE LOCK, above.
const CASE_LOCK_KIND = "case-lock";
const CASE_LOCK_TTL_SECONDS = 30;
const CASE_LOCK_ATTEMPTS = 3;
const CASE_LOCK_WAIT_MS = 1000;
function caseLockPath(caseId) {
  C.casePath(caseId); // the id check
  return `case_locks/${caseId}.json`;
}

// THE LEASE CLOCK (unit R-N, C3): the lock reads the clock afresh at each
// attempt, and a lease's expires_at is its own acquisition + the TTL, never
// the request's arrival + the TTL. `now` is a function: opts.clock (tests
// hand an advancing one), else the fixed opts.now a test hands, else
// Date.now.
function leaseClock(opts) {
  if (opts && typeof opts.clock === "function") return () => Number(opts.clock());
  if (opts && opts.now !== undefined) return () => clock(opts);
  return Date.now;
}

// -> "free" (absent, released or expired by `nowMs`), "held" or "unreadable".
function lockState(json, nowMs) {
  if (json === null || typeof json !== "object" || Array.isArray(json) || json.kind !== CASE_LOCK_KIND || typeof json.holder !== "string") {
    return "unreadable";
  }
  if (json.state === "released") return "free";
  if (json.state !== "held") return "unreadable";
  const until = Date.parse(json.expires_at);
  if (!Number.isFinite(until)) return "unreadable";
  return until <= nowMs ? "free" : "held";
}

// `now` is the lease clock (leaseClock), read at each attempt.
// -> {ok:true, holder, path} or {ok:false, code: "case_busy" |
// "case_lock_unreachable" | "case_lock_unreadable"}.
async function acquireCaseLock(caseId, op, now) {
  const q = quotaStore();
  const path = caseLockPath(caseId);
  const holder = crypto.randomBytes(8).toString("hex");
  for (let attempt = 1; attempt <= CASE_LOCK_ATTEMPTS; attempt += 1) {
    let cur;
    try {
      cur = await q.getFile(path);
    } catch {
      return { ok: false, code: "case_lock_unreachable" };
    }
    const t = now();
    const state = cur === null ? "free" : lockState(cur.json, t);
    if (state === "unreadable") return { ok: false, code: "case_lock_unreadable" };
    if (state === "held") {
      if (attempt < CASE_LOCK_ATTEMPTS) await store._putRetry.sleep(CASE_LOCK_WAIT_MS);
      continue;
    }
    // the lease runs from its acquisition, now
    const record = {
      kind: CASE_LOCK_KIND, v: 1, case_id: caseId, holder, op,
      acquired_at: new Date(t).toISOString(), expires_at: new Date(t + CASE_LOCK_TTL_SECONDS * 1000).toISOString(), state: "held",
    };
    try {
      await q.putFile(path, record, `case ${caseId.slice(0, 16)}: lock (${op})`, cur ? cur.sha : undefined);
      return { ok: true, holder, path };
    } catch (e) {
      if (!(e && e.conflict)) return { ok: false, code: "case_lock_unreachable" };
      // another request took it first: read again
    }
  }
  return { ok: false, code: "case_busy" };
}

// Give it back, only if it is still ours. Never throws: a lock not released
// costs one lease of waiting. `now` is the lease clock.
async function releaseCaseLock(caseId, lock, now) {
  const q = quotaStore();
  try {
    const cur = await q.getFile(lock.path);
    if (!cur || !cur.json || cur.json.holder !== lock.holder || cur.json.state !== "held") return false;
    await q.putFile(lock.path, { ...cur.json, state: "released", released_at: new Date(now()).toISOString() },
      `case ${caseId.slice(0, 16)}: unlock`, cur.sha);
    return true;
  } catch {
    return false;
  }
}

function lockRefusal(lock, nothing) {
  if (lock.code === "case_busy") {
    return new Refusal(503, "case_busy",
      withTail("another request holds this case's lock (a registration or a withdrawal is being written); try again shortly", nothing));
  }
  if (lock.code === "case_lock_unreadable") {
    return new Refusal(503, "case_lock_unreadable", withTail("this case's lock record is present and cannot be read", nothing));
  }
  // a lock write that failed may have landed, so the withdrawal's tail here
  // claims only the case record (follow-up f1 to unit R-N4)
  return new Refusal(503, "case_lock_unreachable", withTail("this case's lock could not be read or written; this is not a 'no'",
    nothing === WROTE_NOTHING ? LOCK_UNREACHABLE_TAIL : nothing, ", and "));
}

// A REFUSAL'S TAIL, what the request did not do (`nothing`). A clause such
// as "nothing was registered" follows `joiner`. The withdrawal's tail,
// WROTE_NOTHING (unit R-N4, R1), is a sentence of its own and follows a
// full stop.
const WROTE_NOTHING = "This request wrote nothing.";
const LOCK_UNREACHABLE_TAIL = "This request wrote nothing to the case record. Try again shortly.";
function withTail(text, nothing, joiner = "; ") {
  return nothing === WROTE_NOTHING || nothing === LOCK_UNREACHABLE_TAIL ? `${text}. ${nothing}` : `${text}${joiner}${nothing}`;
}

class Refusal extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function refuse(res, e) {
  res.setHeader("cache-control", "no-store");
  // a refusal with no sentence (case_record_inconsistent, unit R-L4e) answers its code alone
  if (e.message === "") return res.status(e.status).json({ ok: false, error_code: e.code, ...e.extra });
  return res.status(e.status).json({ ok: false, error_code: e.code, error: e.message, ...e.extra });
}

function fromCaseError(e) {
  return new Refusal(400, e.code, e.message, { field: e.field });
}

function clock(opts) {
  const n = opts && opts.now !== undefined ? Number(opts.now) : opts && typeof opts.clock === "function" ? Number(opts.clock()) : Date.now();
  if (!Number.isFinite(n)) throw new TypeError("case: opts.now must be epoch milliseconds");
  return n;
}

function readJsonBody(req) {
  const declared = Number(req.headers && req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > BODY_MAX_BYTES) {
    throw new Refusal(413, "too_large", `request body is ${declared} bytes; the cap is ${BODY_MAX_BYTES}`, { cap_bytes: BODY_MAX_BYTES });
  }
  const type = String((req.headers && req.headers["content-type"]) || "").split(";")[0].trim().toLowerCase();
  if (type !== "" && type !== "application/json") {
    throw new Refusal(415, "unsupported_media_type", "send application/json");
  }
  let body;
  try {
    body = req.body; // Vercel's parser throws here on malformed JSON
  } catch {
    throw new Refusal(400, "malformed_json", "the request body is not valid JSON");
  }
  if (Buffer.isBuffer(body)) body = body.toString("utf-8");
  if (typeof body === "string") {
    if (Buffer.byteLength(body, "utf-8") > BODY_MAX_BYTES) {
      throw new Refusal(413, "too_large", `request body exceeds the cap of ${BODY_MAX_BYTES} bytes`, { cap_bytes: BODY_MAX_BYTES });
    }
    try {
      body = JSON.parse(body);
    } catch {
      throw new Refusal(400, "malformed_json", "the request body is not valid JSON");
    }
  } else if (body !== null && typeof body === "object") {
    // ALREADY PARSED (item 1b, after Gemini's code review). Vercel parses
    // application/json before this runs, so on the platform req.body is
    // usually an object, and the string branch above never sees it. The only
    // byte check left would be the content-length header, which may be
    // absent or simply wrong. So an object that arrived parsed is measured
    // too: its JSON.stringify form, in UTF-8 bytes, against the same cap,
    // refused in the same words. That form drops the wire's whitespace, so it
    // can read a little smaller than the bytes sent. What it bounds is the
    // object this service goes on to work with. A body this function parsed
    // itself is not measured again: its raw text already passed, and
    // re-serializing can lengthen it (1e9 comes back as 1000000000).
    let text;
    try {
      text = JSON.stringify(body);
    } catch {
      throw new Refusal(400, "malformed_body", "the body must be a JSON object");
    }
    if (typeof text === "string" && Buffer.byteLength(text, "utf-8") > BODY_MAX_BYTES) {
      throw new Refusal(413, "too_large", `request body exceeds the cap of ${BODY_MAX_BYTES} bytes`, { cap_bytes: BODY_MAX_BYTES });
    }
  }
  if (body === undefined || body === null) throw new Refusal(400, "malformed_body", "the body must be a JSON object");
  return body;
}

// A KEY TO OPEN, above. -> {key} when the key is good (held in memory for
// THE OPEN QUOTA's counter, never logged or written), else {refusal}.
async function openKey(req) {
  const k = await stamp.resolveKey(req);
  if (Object.prototype.hasOwnProperty.call(k, "storeError")) {
    console.error(`[case] open: key store read failed (${k.storeError})`);
    return { refusal: new Refusal(503, "key_store_unreachable",
      "the bearer key could not be checked because the key store could not be read; this is not a 'no', and nothing was written") };
  }
  if (!k.key) {
    return { refusal: new Refusal(401, "key_required",
      "opening a case requires a bearer key (Authorization: Bearer <your issued key>); opening costs no credits") };
  }
  if (!k.valid) return { refusal: new Refusal(401, "key_invalid", "the bearer key is not a valid issued key") };
  return { key: k.key };
}

// Method, the key when `requireKey`, the operator's bearer when
// `operatorEnv`, the budget, body (A KEY TO OPEN and THE OPERATOR'S KEY,
// above: the key first, then the budget it draws on). Returns {body, key}
// (key only with `requireKey`) or null (already answered).
async function admit(req, res, verb, { requireKey = false, operatorEnv = null } = {}) {
  res.setHeader("cache-control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("allow", "POST");
    refuse(res, new Refusal(405, "method_not_allowed", `POST a JSON body to ?op=case-${verb}`));
    return null;
  }
  const k = requireKey ? await openKey(req) : { key: null };
  const budgetKey = k.key || (operatorEnv && operatorBearer(req, operatorEnv) === "ok" ? operatorEnv[OPERATOR_KEY_ENV] : null);
  const rl = budgetKey ? await ratelimit.checkKey(keys.keyHash(budgetKey)) : await ratelimit.check(req);
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    const minutes = Math.round(rl.windowSeconds / 60);
    refuse(res, new Refusal(429, "rate_limited", "rate limit exceeded", {
      note: budgetKey
        ? `per-key limiter: ~${rl.limit} calls per key per ${minutes} minutes, drawn on only by requests carrying this valid key`
        : `naive per-IP limiter shared with /api/verify: ~${rl.limit} calls per IP per ${minutes} minutes`,
      retry_after_seconds: rl.retryAfterSeconds,
    }));
    return null;
  }
  if (k.refusal) {
    if (k.refusal.status === 401) res.setHeader("www-authenticate", 'Bearer realm="arcaeon-witness"');
    refuse(res, k.refusal);
    return null;
  }
  try {
    return { body: readJsonBody(req), key: k.key };
  } catch (e) {
    refuse(res, e instanceof Refusal ? e : new Refusal(400, "unreadable_body", "the request body could not be read"));
    return null;
  }
}

// ---- judges: a store read in, a verdict out (lib/_verdict.js) ----

function judgeCase(got, path, caseId) {
  return verdict.judgeWith(got, path, (json) => {
    const r = C.validateCase(json);
    if (!r.ok) return `case_${r.code}`;
    if (json.case_id !== caseId) return "case_not_at_its_path";
    return true;
  });
}


// The design's three conditions on the fetched record: "kind file-stamp,
// matching hash", and a stamped_at that reads as a time. Readability only: a
// readable record whose size is not a commitment's is the caller's mistake,
// a typed 409 at step 6b of handleCaseCommit, not a damaged store (503).
function judgeStampRecord(got, sha) {
  return verdict.judgeWith(got, "stamp record", (json) => {
    if (json.kind !== "file-stamp") return "not_a_file_stamp";
    if (json.v !== 1) return "unknown_stamp_version";
    if (json.sha256 !== sha) return "sha256_mismatch";
    if (!C.isIsoUtc(json.stamped_at)) return "stamped_at_unreadable";
    return true;
  });
}

// ---------------------------------------------------------------------------
// POST ?op=case-open
// ---------------------------------------------------------------------------
async function handleCaseOpen(req, res, opts = {}) {
  const admitted = await admit(req, res, "open", { requireKey: true });
  if (!admitted) return;
  const nowMs = clock(opts);

  let opened;
  try {
    opened = C.validateOpening(admitted.body);
  } catch (e) {
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    throw e;
  }
  const { opening, parties_reordered } = opened;
  if (Date.parse(opening.opened_at) > nowMs + DEFAULT_SKEW_SECONDS * 1000) {
    return refuse(res, new Refusal(400, "future_dated",
      `opened_at is more than ${DEFAULT_SKEW_SECONDS} seconds ahead of this service's clock`, { field: "opened_at" }));
  }
  if (Date.parse(opening.deadline) <= nowMs) {
    return refuse(res, new Refusal(400, "deadline_passed",
      "the deadline has already passed by this service's clock, so nothing could be registered to this case", { field: "deadline" }));
  }

  const caseId = C.deriveCaseId(opening);
  const record = C.newCase(opening, caseId);
  const self = C.validateCase(record);
  if (!self.ok) {
    // This service built a case its own schema refuses: its defect, not the caller's.
    console.error(`[case] open: built an invalid case (${self.code} at ${self.field})`);
    return refuse(res, new Refusal(500, "internal_error", "this service built a case object its own schema refuses; nothing was written"));
  }
  const path = C.casePath(caseId);

  // The same opening twice is refused before any quota is spent: a read
  // first, so a duplicate costs nothing (the create-only write below still
  // decides a race).
  let prior;
  try {
    prior = await store.getFile(path);
  } catch (e) {
    console.error(`[case] open: case read failed (${e && e.message})`);
    return refuse(res, new Refusal(503, "store_unreachable", "could not check whether this case already exists; nothing was written"));
  }
  if (prior !== null) {
    return refuse(res, new Refusal(409, "case_exists",
      "a case with this id already exists. The same opening (protocol, policy, scope, parties and opened_at) is the same case, and a case is opened once",
      { case_id: caseId, case_path: path }));
  }

  // THE OPEN QUOTA, above: one unit of this key's day, counted in the store.
  let quota;
  try {
    quota = await takeOpenQuota(admitted.key, nowMs);
  } catch (e) {
    // Never e.message: the counter's path names the key's hash.
    console.error(`[case] open: the open quota could not be read or written${e && e.status ? ` (${e.status})` : ""}`);
    return refuse(res, new Refusal(503, "open_quota_unreadable",
      "the opening quota for this key could not be checked; this is not a 'no', and nothing was written"));
  }
  if (!quota.ok) {
    const retry = Math.max(1, Math.ceil((Date.parse(`${quota.day}T00:00:00Z`) + 86400000 - nowMs) / 1000));
    res.setHeader("retry-after", String(retry));
    return refuse(res, new Refusal(429, "open_quota_exceeded",
      `this key has opened ${OPEN_QUOTA_PER_DAY} cases today (UTC ${quota.day}), the most a key may open in a day; nothing was written. ` +
        "The count starts again at 00:00 UTC.",
      { quota_per_day: OPEN_QUOTA_PER_DAY, day: quota.day, retry_after_seconds: retry }));
  }

  let put;
  try {
    put = await store.putFile(path, record, `case ${caseId.slice(0, 16)}: open`, undefined, {
      // Someone opened this same case between our check and our write. Theirs
      // stands; a case file is never overwritten.
      rebuild: () => null,
    });
  } catch (e) {
    if (e && e.conflict) put = { abandoned: true };
    else {
      console.error(`[case] open: write failed (${e && e.message})`);
      return refuse(res, new Refusal(503, "store_error", "could not record the case; nothing was written that you should rely on"));
    }
  }
  if (put && put.abandoned) {
    return refuse(res, new Refusal(409, "case_exists",
      "a case with this id already exists. The same opening (protocol, policy, scope, parties and opened_at) is the same case, and a case is opened once",
      { case_id: caseId, case_path: path }));
  }

  // The write landed; the record judged is the one whose PUT succeeded.
  const v = judgeCase({ json: record }, path, caseId);
  const commit = put && put.commit && put.commit.sha;
  return res.status(201).json(verdict.success(v, {
    case_id: caseId,
    status: record.status,
    parties_reordered,
    role_note: "Role a is party_a and role b is party_b, in canonical order (label, then side). Compute a commitment with the role your party holds in this case.",
    case: record,
    ...(commit ? { commit } : {}),
  }, "case-open"));
}

// ---------------------------------------------------------------------------
// POST ?op=case-commit
// ---------------------------------------------------------------------------

// The case record as stored now, valid, or null (absent or unreadable), or
// undefined when the read failed.
async function caseRead(cpath) {
  let g;
  try {
    g = await store.getFile(cpath);
  } catch {
    return undefined;
  }
  return g && C.validateCase(g.json).ok ? g.json : null;
}
// Its status (null when absent or unreadable), or undefined when the read failed.
async function caseStatus(cpath) {
  const k = await caseRead(cpath);
  return k === undefined ? undefined : k === null ? null : k.status;
}

// THE INCONSISTENT RECORD (unit R-L4b; its answer since unit R-L4e): the
// body is the error code case_record_inconsistent and nothing else (no
// sentence, no reason, no role). The reason, the case and the role go to the
// operator log; the sealer's run reports them in its refused record.
function inconsistentRefusal(caseId, role, reason) {
  console.error(`[case] case_record_inconsistent: case ${caseId}, role ${role}, ${reason}`);
  return new Refusal(503, "case_record_inconsistent", "");
}

// What a reader answers when the projection could not be taken (THE
// PROJECTION IS THE REGISTRATION, unit R-L4; lib/_case_seal.js
// projectedRegistrations): a projected file missing or not the file
// projected is 503 case_record_inconsistent (unit R-L4b), and the case
// never seals; a file that could not be read is 503 could_not_look.
// `nothing` ends it.
function projectionRefusal(caseId, proj, nothing) {
  if (proj.inconsistent) return inconsistentRefusal(caseId, proj.role, proj.reason);
  return new Refusal(503, "could_not_look", withTail(`role ${proj.role}'s registration file could not be read (${proj.reason}); this is not a 'no'`,
    nothing, ", and "), { case_id: caseId, role: proj.role, reason: proj.reason });
}

// The role holds another projection (lib/_case.js THE CLAIM: the root
// projects at most one claim per role, and the first projection wins):
// 409 role_already_committed, naming the projected entry and the sha256 of
// the projected file. `extra` is added to the refusal's fields.
function roleTaken(kase, role, extra = {}) {
  const mine = kase.commitments[role];
  return new Refusal(409, "role_already_committed", `role ${role} already has a registered commitment; only the first registration counts`,
    { case_id: kase.case_id, role, registered: C.commitmentEntry(mine), projected_sha256: mine.registration_sha256, ...extra });
}

// Why the case root `kase` cannot take role `role`'s registration `record`
// beside the other role's projection, or null (THE PROJECTION, below): the
// other role holds this commitment, or registered under this key. A role
// the root already projects is roleTaken's, before this.
function projectionBar(kase, record) {
  const role = record.role;
  const other = role === "a" ? "b" : "a";
  const theirs = kase.commitments[other];
  if (theirs && theirs.commitment_sha256 === record.commitment_sha256) {
    return new Refusal(409, "commitment_registered_to_other_role",
      `this commitment is already registered to role ${other} of this case; a commitment's preimage names exactly one role`,
      { case_id: kase.case_id, role, other_role: other });
  }
  if (theirs && theirs.key_id === record.key_id) {
    return new Refusal(409, "same_key_both_roles",
      `role ${other} of this case is registered under key ${record.key_id}, and the two roles of a case are registered by two distinct keys; ` +
        "nothing was registered", { case_id: kase.case_id, role, other_role: other, key_id: record.key_id });
  }
  return null;
}

// THE PROJECTION (unit R-L4, rules 2 and 3; unit R-L4c): role
// `record.role`'s registration file at `rpath`, whose bytes have sha256
// `fileSha256`, projected into the case root by a COMPARE-AND-SWAP over a
// fresh read of the root (the confirming read). A root that already
// projects this file is the answer, whatever its state since (c1);
// otherwise it must show the case OPEN or COMMITTED, the role unprojected,
// before its deadline by `serverNow()`, the server clock read just before
// the compare-and-swap (c2: never the clock the request arrived by), and
// able to take it (projectionBar).
//   THE TIE RULE (the architect's ruling on c4): the compare-and-swap
// decides. One that loses is never retried: the root is read once more and
// answered from: 200 when it projects this file, 409 role_already_committed
// naming the projected sha256 when it projects another, the refusal its
// state gives, or 503 (written, not yet confirmed: send it again). Nothing
// here writes anything but the case root, and nothing is ever removed.
// -> {ok:true, case, added} (added: [role] when this write projected it,
//    [] when the root already did), or {ok:false, refusal}.
async function projectRegistration(cpath, record, rpath, fileSha256, serverNow) {
  const caseId = record.case_id;
  const role = record.role;
  const said = { registration_path: rpath, registration_sha256: fileSha256, received_at: record.registered_at };
  const unconfirmed = (recorded) => ({ ok: false, refusal: new Refusal(503, "registration_unconfirmed", UNCONFIRMED,
    { case_id: caseId, role, registration_recorded: recorded, ...said }) });
  // what the root shows: done, refused, or a case to project into
  const judge = (k) => {
    const mine = k.commitments ? k.commitments[role] : null;
    if (mine && mine.registration_sha256 === fileSha256) return { done: true };
    if (k.status === "WITHDRAWN") {
      return { refusal: new Refusal(409, "case_withdrawn", WITHDRAWN_BEFORE_CONFIRMED,
        { case_id: caseId, role, status: "WITHDRAWN", registration_recorded: false, ...said }) };
    }
    if (!C.REGISTERABLE_STATUSES.includes(k.status)) {
      return { refusal: new Refusal(409, "case_not_open",
        `the case is ${k.status}; a commitment is registered only while it is OPEN or COMMITTED. The registration file is written and has no standing`,
        { case_id: caseId, role, status: k.status, registration_recorded: false, ...said }) };
    }
    if (mine) return { refusal: roleTaken(k, role, { registration_recorded: false, ...said }) };
    if (C.pastDeadline(k, serverNow())) {
      return { refusal: new Refusal(409, "late_commitment", LATE_UNCONFIRMED,
        { case_id: caseId, role, deadline: k.deadline, registration_recorded: false, ...said }) };
    }
    const bar = projectionBar(k, record);
    if (bar) {
      bar.extra = { ...bar.extra, registration_recorded: false, ...said };
      return { refusal: bar };
    }
    return { next: C.applyRegistration(k, record, fileSha256) };
  };
  let got;
  try {
    got = await store.getFile(cpath);
  } catch (e) {
    console.error(`[case] commit: the confirming read of the case failed (${e && e.message})`);
    return unconfirmed(null);
  }
  if (!got || !C.validateCase(got.json).ok || got.json.case_id !== caseId) return unconfirmed(null);
  const first = judge(got.json);
  if (first.refusal) return { ok: false, refusal: first.refusal };
  if (first.done) return { ok: true, case: got.json, added: [] };
  let put;
  try {
    put = await store.putFile(cpath, first.next, `case ${caseId.slice(0, 16)}: commitment ${role} registered`, got.sha, { rebuild: () => null });
  } catch (e) {
    console.error(`[case] commit: the projection could not be written (${e && e.message})`);
    // the write threw, so it may have landed: not known
    return unconfirmed(null);
  }
  if (!(put && put.abandoned)) return { ok: true, case: first.next, added: [role] };
  // the compare-and-swap lost: the root, read once more, is the answer
  const now = await caseRead(cpath);
  if (now === undefined || now === null) return unconfirmed(null);
  const last = judge(now);
  if (last.done) return { ok: true, case: now, added: [] };
  if (last.refusal) return { ok: false, refusal: last.refusal };
  return unconfirmed(false);
}

// The stamp a commitment rests on, read through the stamp read path (the
// stamps repository only) and judged: present, a readable file-stamp of this
// hash, of a commitment's size (THE STAMP'S SIZE), and, when `history` is
// asked for, the public commit that holds it (STAMP_COMMIT): since unit R-RV
// (the architect's ruling b) the oldest commit that touched its path, found
// by walking every page of that path's history (stampHistory). `nothing`
// ends every refusal: what this request did not do, and a refusal says how
// to recover (a new commitment). Only registration reads a stamp; since
// unit R-RV the reveal does not.
// -> {ok:true, record, commit} (commit only with `history`),
//    {ok:false, missing:true} (no stamp for this hash), or {ok:false, refusal}.
async function readStamp(sha, { history = false, nothing = "nothing was registered" } = {}) {
  const advice = "Draw a new salt, compute a new commitment, stamp it with size " +
    `${C.COMMITMENT_BYTES_LENGTH} and register that hash. `;
  const st = stampStore.status();
  if (!st.configured) {
    return { ok: false, refusal: new Refusal(503, "stamp_store_not_configured",
      `the stamp record is not configured on this deployment, so no stamp can be checked; ${nothing}`, { reason: st.reason }) };
  }
  const spath = stamp.stampPath(sha);
  let sg;
  try {
    sg = await stampStore.getFile(spath);
  } catch (e) {
    console.error(`[case] stamp read failed (${e && e.message})`);
    return { ok: false, refusal: new Refusal(503, "stamp_store_unreachable", `the stamp record could not be read; this is not a 'no', and ${nothing}`) };
  }
  if (sg === null) return { ok: false, missing: true };
  const sv = judgeStampRecord(sg, sha);
  if (!sv.ok) {
    return { ok: false, refusal: new Refusal(503, "stamp_record_unreadable",
      `the stamp stored for this hash is present but is not a readable file-stamp record for it; ${nothing}`, { reason: sv.reason }) };
  }
  const stampedSize = sg.json.size;
  if (stampedSize !== C.COMMITMENT_BYTES_LENGTH) {
    const said = Number.isSafeInteger(stampedSize) ? `a size of ${stampedSize} bytes`
      : stampedSize === null || stampedSize === undefined ? "no size" : "a size that is not a whole number of bytes";
    return { ok: false, refusal: new Refusal(409, "stamp_size_mismatch",
      `the stamp for this hash records ${said}, and a case/1 commitment's canonical bytes are ${C.COMMITMENT_BYTES_LENGTH}, ` +
        "so it is not a stamp of a commitment. A hash is stamped once, so this one cannot be re-stamped. " +
        `${advice}${sentence(nothing)}`,
      { commitment_sha256: sha, stamped_size: Number.isSafeInteger(stampedSize) ? stampedSize : null, expected_size: C.COMMITMENT_BYTES_LENGTH }) };
  }
  if (!history) return { ok: true, record: sg.json };
  let commits;
  try {
    commits = await stampHistory(spath);
  } catch (e) {
    const unreadable = !!e && (e.code === "listing_unreadable" || e.code === "commits_unreadable");
    console.error(`[case] stamp history read failed (${e && e.message})`);
    return { ok: false, refusal: unreadable
      ? new Refusal(503, "stamp_history_unreadable", `the stamp's commit history was answered but cannot be read as a list of commits; ${nothing}`, { reason: e.code })
      : new Refusal(503, "stamp_history_unreachable", `the stamp's commit history could not be read; this is not a 'no', and ${nothing}`) };
  }
  if (commits === null) {
    return { ok: false, refusal: new Refusal(503, "stamp_history_unreadable",
      `the stamp's commit history is longer than this service reads (${STAMP_HISTORY_PAGES * 100} commits), so the oldest commit that ` +
        `touched it is not known; ${nothing}`, { reason: "commits_beyond_bound" }) };
  }
  if (commits.length === 0) {
    return { ok: false, refusal: new Refusal(503, "stamp_history_unreadable",
      `the stamp record for this hash is present, but no commit in its history touches it, so there is no public commit to name; ${nothing}`,
      { reason: "no_commit_touches_path" }) };
  }
  return { ok: true, record: sg.json, commit: commits[commits.length - 1].sha };
}

// Every commit that touched a stamp's path, newest first, walking every page
// of its history: the Link header's next page is followed, and a full page
// with none named is not the last either (lib/_case_seal.js allCommitsOf's
// rule). At most STAMP_HISTORY_PAGES pages of 100. -> the list, or null past
// the bound. A read that fails throws.
const STAMP_HISTORY_PAGES = 10;
async function stampHistory(spath) {
  const list = [];
  let page = 1;
  for (let n = 0; n < STAMP_HISTORY_PAGES; n += 1) {
    const got = await stampStore.listCommitsPage(spath, { perPage: 100, page });
    list.push(...got.list);
    if (got.next === null && got.list.length < 100) return list;
    page = got.next === null ? page + 1 : got.next;
  }
  return null;
}

// "nothing was registered" -> "Nothing was registered."
function sentence(s) {
  return `${s[0].toUpperCase()}${s.slice(1)}.`;
}

async function handleCaseCommit(req, res, opts = {}) {
  const admitted = await admit(req, res, "commit");
  if (!admitted) return;
  const nowMs = clock(opts);

  let asked;
  try {
    asked = C.validateRegistrationBody(admitted.body);
  } catch (e) {
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    throw e;
  }
  const { case_id, role, commitment_sha256, key_id } = asked;
  const cpath = C.casePath(case_id);

  // 0. The registration key proves the registration (ONE KEY PER ROLE).
  if (C.registrationSignatureReason(asked) !== null) {
    return refuse(res, new Refusal(403, "registration_unauthorized",
      "sig is not the signature of the verifier's key over this registration (json-c14n:v1 of {kind, v, case_id, role, " +
        "commitment_sha256}, lib/_case.js registrationSigningBytes); nothing was registered", { case_id, role, key_id }));
  }

  // 1. The case.
  let got;
  try {
    got = await store.getFile(cpath);
  } catch (e) {
    console.error(`[case] commit: case read failed (${e && e.message})`);
    return refuse(res, new Refusal(503, "store_unreachable", "the case record could not be read; this is not a 'no'"));
  }
  if (got === null) {
    return refuse(res, new Refusal(404, "case_not_found", "no case is open with this id", { case_id }));
  }
  const cv = judgeCase(got, cpath, case_id);
  if (!cv.ok) {
    return refuse(res, new Refusal(503, "case_record_unreadable",
      "the stored case is present but cannot be read as a valid arcaeon-case/1 record; nothing was registered", { reason: cv.reason }));
  }
  const kase = got.json;
  // THE CLAIM (lib/_case.js; unit R-L4c, c4): this registration's claim, the
  // sha256 of the fields a party supplies, names the one path its file has.
  const claim = C.claimSha256(asked);
  const rpath = C.registrationPath(case_id, role, claim);
  // THE PROJECTION FIRST (unit R-L4c, c1): a registration the root already
  // projects is answered as it stands (step 6r below), whatever the case's
  // state since; only one it does not project is refused by that state. A
  // withdrawn root holds no projection (lib/_case.js WITHDRAWN_FIELDS).
  const standing = kase.commitments ? kase.commitments[role] : null;
  const replay = !!standing && standing.claim_sha256 === claim;
  if (!replay && !C.REGISTERABLE_STATUSES.includes(kase.status)) {
    return refuse(res, new Refusal(409, "case_not_open", `the case is ${kase.status}; a commitment is registered only while it is OPEN or COMMITTED`,
      { case_id, status: kase.status }));
  }

  // 2. THE PROJECTION IS THE REGISTRATION (unit R-L4): the registrations
  // are the case root's projection, each projected file checked against the
  // sha256 the projection carries (lib/_case_seal.js projectedRegistrations).
  // A registration file the root does not project is a claim, inert until
  // it is projected; none is read here to decide what stands.
  const proj = await SEAL.projectedRegistrations(kase);
  if (!proj.ok) return refuse(res, projectionRefusal(case_id, proj, "nothing was registered"));

  if (replay) {
    // 6r. THE RETRY RECHECKS THE STAMP (item 2a; item 1b's finding 7): a
    // replay answers only once the stamp record passes steps 6 and 6b again,
    // size included.
    const sc = await readStamp(commitment_sha256, { nothing: "nothing was projected" });
    if (!sc.ok && sc.missing) {
      return refuse(res, new Refusal(503, "stamp_record_unreadable",
        "the stamp this registration rests on is no longer in the stamp record, and a stamp is never removed; nothing was projected",
        { reason: "stamp_missing" }));
    }
    if (!sc.ok) return refuse(res, sc.refusal);
    return res.status(200).json(commitAnswer(kase, role, JSON.parse(proj.texts[role]), rpath, { created: false, added: [] }));
  }

  // 3, 4 and 4b. A FILE IS WRITTEN ONLY WHEN THE ROOT AS READ CAN TAKE IT
  // (the architect's ruling on c4): a role the root projects for another
  // claim is 409 role_already_committed naming the projected sha256 (first
  // projection wins); one hash cannot hold both roles (its preimage names
  // one role), and the two roles register under two keys (ONE KEY PER
  // ROLE). Each writes nothing.
  if (standing) return refuse(res, roleTaken(kase, role));
  const bar = projectionBar(kase, { role, commitment_sha256, key_id });
  if (bar) return refuse(res, bar);

  // 5. THE CLAIM'S FILE, at this registration's own path. A file there is
  // this registration, written before and not projected: it is taken as it
  // is, its own bytes and the fields this service added when it was written
  // (rule 3: a re-send finishes from where a 503 left it), and never
  // written again.
  let held;
  try {
    held = await store.getRawFile(rpath);
  } catch (e) {
    console.error(`[case] commit: registration read failed (${e && e.message})`);
    return refuse(res, new Refusal(503, "store_unreachable", "the registration file could not be read; this is not a 'no', and nothing was registered"));
  }
  // 5a. Before the deadline. Past it, a file the root does not project can
  // never stand, and none is written.
  if (C.pastDeadline(kase, nowMs)) {
    return refuse(res, new Refusal(409, "late_commitment", held ? LATE_UNCONFIRMED : "the case's deadline has passed; no commitment can be registered to it now",
      { case_id, deadline: kase.deadline, ...(held ? { registration_recorded: false, registration_path: rpath } : {}) }));
  }

  // 6. The stamp, read through the stamp read path. Never a caller's copy.
  // 6b. Its size is a commitment's (THE STAMP'S SIZE, above).
  // 6c. The oldest commit that touched it (STAMP_COMMIT, above). A file
  // already written records its stamp's commit, so a re-send rechecks the
  // stamp as a replay does (6r), not its history.
  const sc = await readStamp(commitment_sha256, held ? { nothing: "nothing was projected" } : { history: true });
  if (!sc.ok && sc.missing && held) {
    return refuse(res, new Refusal(503, "stamp_record_unreadable",
      "the stamp this registration rests on is no longer in the stamp record, and a stamp is never removed; nothing was projected",
      { reason: "stamp_missing" }));
  }
  if (!sc.ok && sc.missing) {
    return refuse(res, new Refusal(404, "no_commitment",
      "no stamp is recorded for this commitment hash. Stamp it first (POST /api/stamp), then register it",
      { commitment_sha256 }));
  }
  if (!sc.ok) return refuse(res, sc.refusal);

  // 7. The file at the claim's path holds this registration (THE SAME
  // REGISTRATION, lib/_case.js partySuppliedDiffers): a file there that
  // does not was not written by this service, and is never projected.
  // -> {record, text} or {refusal}.
  const claimOf = (text) => {
    let file;
    try {
      file = JSON.parse(text);
    } catch {
      file = null;
    }
    const differs = C.partySuppliedDiffers(file, asked);
    if (!differs) return { record: file, text };
    return { refusal: new Refusal(503, "registration_record_unreadable",
      "the file at this registration's path is present and does not hold this registration; it is never projected, and nothing was written",
      { case_id, role, registration_path: rpath, differs, registration_recorded: false }) };
  };
  let record = null;
  let text = null;
  if (held) {
    const found = claimOf(held.text);
    if (found.refusal) return refuse(res, found.refusal);
    ({ record, text } = found);
  }

  // 7a. THE CASE LOCK (red-team fix C), a courtesy that serializes the
  // writers of a case: the guard is the compare-and-swap (THE PROJECTION).
  const lease = leaseClock(opts);
  const lock = await acquireCaseLock(case_id, "commit", lease);
  if (!lock.ok) return refuse(res, lockRefusal(lock, "nothing was registered"));
  let created = false;
  let projected;
  try {
    if (!held) {
      const before = await caseStatus(cpath);
      if (before === undefined) {
        return refuse(res, new Refusal(503, "store_unreachable", "the case record could not be read again before the registration's write; this is not a 'no', and nothing was registered"));
      }
      // A case that reads but is not a valid case record cannot say whether
      // it was withdrawn, and a registration is written only when it can.
      if (before === null) {
        return refuse(res, new Refusal(503, "case_record_unreadable",
          "the case record, read again under the lock before the registration's write, is missing or not a valid case record, so this " +
            "service cannot tell whether the case was withdrawn; nothing was registered", { case_id }));
      }
      if (before === "WITHDRAWN") {
        return refuse(res, new Refusal(409, "case_withdrawn",
          "the case was withdrawn before this registration was written; a withdrawn case takes no registration, and nothing was registered",
          { case_id, role, registration_recorded: false, received_at: C.utcSeconds(nowMs) }));
      }
      // 7b. The write, create-only, at the claim's path: the request's
      // party-supplied fields, the time it was received (this service's
      // clock) and the stamp's commit and time. A file that landed first at
      // this path is this registration (the lost create-only race: the
      // winner's file, as it is, is simply the file).
      record = C.registrationRecord({ case_id, role, commitment_sha256, registered_at: C.utcSeconds(nowMs), stamp_commit: sc.commit,
        stamped_at: sc.record.stamped_at, key_id, verifier: asked.verifier, sig: asked.sig });
      let put;
      try {
        put = await store.putFile(rpath, record, `case ${case_id.slice(0, 16)}: commitment ${role}`, undefined, { rebuild: () => null });
      } catch (e) {
        if (e && e.conflict) put = { abandoned: true };
        else {
          console.error(`[case] commit: registration write failed (${e && e.message})`);
          return refuse(res, new Refusal(503, "store_error", "could not record the registration; nothing was registered"));
        }
      }
      if (put && put.abandoned) {
        let won;
        try {
          won = await store.getRawFile(rpath);
        } catch {
          won = undefined;
        }
        if (!won) {
          return refuse(res, new Refusal(503, "store_error", "a registration for this role landed first and could not be read back",
            { case_id, role, registration_recorded: won === null ? false : null }));
        }
        const found = claimOf(won.text);
        if (found.refusal) return refuse(res, found.refusal);
        ({ record, text } = found);
      } else {
        text = store.fileText(record);
        created = true;
      }
    }
    // 8. THE CONFIRMING READ AND THE PROJECTION (rules 2 and 3): nothing
    // more is written when either fails, and the same registration sent
    // again finishes from here.
    projected = await projectRegistration(cpath, record, rpath, sha256hex(Buffer.from(text, "utf8")), lease);
  } finally {
    await releaseCaseLock(case_id, lock, lease);
  }
  if (!projected.ok) return refuse(res, projected.refusal);
  return res.status(created ? 201 : 200).json(commitAnswer(projected.case, role, record, rpath, { created, added: projected.added }));
}

// The commit path's answer: the case root as it now projects `role`, and
// `registration`, the record its file holds, at `rpath`, the path the
// answer names (a sender learns its claim's fate from its own answer).
function commitAnswer(kase, role, registration, rpath, { created, added }) {
  const case_id = kase.case_id;
  const v = judgeCase({ json: kase }, C.casePath(case_id), case_id);
  return verdict.success(v, {
    case_id,
    role,
    existing: !created,
    registration,
    registration_path: rpath,
    projected: added,
    status: kase.status,
    case: kase,
  }, "case-commit");
}

// ---------------------------------------------------------------------------
// POST ?op=case-reveal (THE JOINT REVEAL, above)
// ---------------------------------------------------------------------------

// The request, read the way ?op=reconcile reads its body, split into the
// case fields and the tape fields, which revealTapes decodes later
// (lib/_reconcile_http.js tapeFrom). The case fields are not validated here
// (unit R-N, N3): only the case_id is read before the case, and on a
// withdrawn case only the requester's own opening after it.
// -> {caseFields, tapeFields}. Throws a Refusal or a reconcile Refusal.
function revealFields(fields, fromMultipart) {
  if (fields === null || typeof fields !== "object" || Array.isArray(fields)) {
    throw new Refusal(400, "malformed_body", "the body must be an object with case_id, reveals, tape_a and tape_b");
  }
  if (!fromMultipart) {
    // An already-parsed body is measured too (item 1b's rule), here against
    // the reconcile endpoint's cap, since the reveal carries two tapes.
    let text;
    try {
      text = JSON.stringify(fields);
    } catch {
      throw new Refusal(400, "malformed_body", "the body must be a JSON object");
    }
    if (typeof text === "string" && Buffer.byteLength(text, "utf-8") > RECONCILE.BODY_MAX_BYTES) {
      throw new Refusal(413, "too_large", `request body exceeds the cap of ${RECONCILE.BODY_MAX_BYTES} bytes`, { cap_bytes: RECONCILE.BODY_MAX_BYTES });
    }
  }
  const tapeFields = {};
  const caseFields = {};
  for (const k of Object.keys(fields)) (C.REVEAL_TAPE_FIELDS.includes(k) ? tapeFields : caseFields)[k] = fields[k];
  // THE REFUSAL BEFORE THE TAPES (Design N): only the case fields are split
  // out here; the tape fields stay as they arrived until the case is known
  // to take a reveal (revealTapes).
  if (fromMultipart) {
    // A multipart reveal carries each case field as a part: case_id as text,
    // reveals and cross_reference as JSON text.
    for (const k of Object.keys(caseFields)) {
      const text = caseFields[k].toString("utf-8");
      if (k === "reveals" || k === "cross_reference") {
        try {
          caseFields[k] = JSON.parse(text);
        } catch {
          throw new Refusal(400, "malformed_json", `the ${k} part is not valid JSON`, { field: k });
        }
      } else {
        caseFields[k] = text;
      }
    }
  }
  return { caseFields, tapeFields };
}

// The two tapes, decoded from their fields (lib/_reconcile_http.js tapeFrom).
// Throws a reconcile Refusal.
function revealTapes(tapeFields, fromMultipart) {
  return {
    a: RECONCILE.tapeFrom(tapeFields, "tape_a", fromMultipart),
    b: RECONCILE.tapeFrom(tapeFields, "tape_b", fromMultipart),
  };
}

// THE REFUSAL BEFORE THE TAPES (Design N; since unit R-N, N1 and N3): a
// joint reveal of a withdrawn case is refused, its tapes never decoded or hashed.
// A refusal receipt is issued to a party only: the request names its role
// (`role`) and carries that role's own opening, reveals[role]; the other
// role's entry is never read and never hashed. The opening must recompute
// the commitment the case root projected for that role before the
// withdrawal (lib/_case_seal.js rootBeforeWithdrawal, its files checked
// against it: THE PROJECTION; a file the root never projected, one written
// after the withdrawal among them, never stood). Anything else is 404
// not_a_party, with no receipt. The
// receipt (lib/_case_seal.js THE REFUSAL RECEIPT) is signed with the
// reconcile key under the key document this deployment carries, confirmed
// at its commit, or it is not issued: 503 signer_unavailable or
// document_unavailable, and no environment variable is named to the caller
// (the server log has why). -> a Refusal.
async function withdrawnRefusal(caseId, caseFields, at, env, opts) {
  const nothing = "nothing was compared, and nothing about the tapes is kept";
  const notParty = () => new Refusal(404, "not_a_party",
    "the case was withdrawn, and a refusal receipt is issued to a party only: name your role (role) and carry that role's own opening, " +
      `reveals[role] = {tape_sha256, salt}, recomputing the commitment that role registered before the withdrawal; ${nothing}`, { case_id: caseId });
  const own = C.refusalOpening(caseFields);
  if (!own) return notParty();
  const before = await SEAL.rootBeforeWithdrawal(caseId);
  if (!before.ok) {
    return new Refusal(503, "store_unreachable", `the case root before the withdrawal could not be read (${before.reason}); this is not a 'no', and ${nothing}`,
      { case_id: caseId });
  }
  const proj = await SEAL.projectedRegistrations(before.kase);
  if (!proj.ok) return projectionRefusal(caseId, proj, nothing);
  const reg = proj.entries[own.role];
  if (!reg) return notParty();
  if (C.commitmentSha256({ case_id: caseId, role: own.role, tape_sha256: own.tape_sha256, salt: own.salt }) !== reg.commitment_sha256) return notParty();
  const sealing = SEAL.sealingDocument(env, { keyDocument: opts.keyDocument });
  const confirmed = sealing.ok ? await SEAL.confirmSealingDocument(sealing, env) : { ok: false, reason: "sealing_document_unknown" };
  if (!confirmed.ok) {
    console.error(`[case] reveal: no refusal receipt, the key document is unavailable (${sealing.ok ? confirmed.reason : sealing.reason})`);
    return new Refusal(503, "document_unavailable",
      `the case was withdrawn, and this deployment cannot name and confirm the key document a refusal receipt is signed under, so it issues none; ${nothing}`,
      { case_id: caseId, reason: confirmed.reason });
  }
  const signer = SEAL.loadReconcileSigner(env, { keyDocument: sealing.doc });
  if (!signer.ok) {
    console.error(`[case] reveal: no refusal receipt, no published reconcile signer (${signer.reason})`);
    return new Refusal(503, "signer_unavailable",
      `the case was withdrawn, and this deployment has no published reconcile signer, so it issues no refusal receipt; ${nothing}`, { case_id: caseId });
  }
  const receipt = SEAL.refusalReceipt({ caseId, at, role: own.role, commitmentSha256: reg.commitment_sha256,
    signedUnder: { document_sha256: sealing.document_sha256, document_commit: sealing.document_commit, retrieved_at: at } }, signer);
  return new Refusal(409, "case_withdrawn",
    "the case was withdrawn, and consent to compare is not jointly held, so this reveal is refused and its tapes are never decoded or " +
      "hashed; nothing was compared, and nothing about the tapes is kept. The refusal receipt names your role and commitment, is signed with the " +
      "reconcile key under the key document it names, and may be shown to anyone",
    { case_id: caseId, status: "WITHDRAWN", refusal_receipt: receipt });
}

// THE ONE WRITE (unit R-RV, rule 4): a seal write that throws may have
// landed, so the answer says neither that it did nor that it did not.
const SEAL_FAILED = "The case may not have been sealed. Nothing was pinned. Send the same reveal again: it seals the case, or answers that " +
  "it is already sealed.";
const WITHDRAWN_BEFORE_SEAL = "The case was withdrawn before this reveal could seal it. Nothing was recorded, and this response carries no verdict.";

// THE ONE WRITE, LOST (unit R-RV, rule 3): the seal's compare-and-swap lost,
// so the root is read once more and answered from what it is now: VERDICT is
// another request's seal; WITHDRAWN a withdrawal that landed first, answered
// with no verdict, receipt or tape digest; anything else, a root still
// COMMITTED or a read that fails, is case_seal_failed with rule 4's text (the
// architect's ruling a: no state of its own).
async function sealLostRefusal(cpath, caseId) {
  const now = await caseRead(cpath);
  const status = now ? now.status : null;
  if (status === "VERDICT") {
    return new Refusal(409, "not_committed",
      "another request sealed this case while this one ran, and a case has one joint reveal; nothing was sealed", { case_id: caseId, status });
  }
  if (status === "WITHDRAWN") return new Refusal(409, "case_withdrawn", WITHDRAWN_BEFORE_SEAL, { case_id: caseId, status });
  return new Refusal(503, "case_seal_failed", SEAL_FAILED, { case_id: caseId });
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function handleCaseReveal(req, res, opts = {}) {
  res.setHeader("cache-control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("allow", "POST");
    return refuse(res, new Refusal(405, "method_not_allowed", "POST the joint reveal and both tapes to ?op=case-reveal"));
  }
  const rl = await ratelimit.check(req);
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    return refuse(res, new Refusal(429, "rate_limited", "rate limit exceeded", {
      note: `naive per-IP limiter shared with /api/verify: ~${rl.limit} calls per IP per ${Math.round(rl.windowSeconds / 60)} minutes`,
      retry_after_seconds: rl.retryAfterSeconds,
    }));
  }
  // The clock when the request arrived: the deadline is judged by it, and a
  // refusal receipt is dated by it. The seal's times are one later read
  // (THE ONE CLOCK READ, at step 6).
  const nowMs = clock(opts);
  const env = opts.env || process.env;

  // 0. The request: its case_id. The other case fields are read at step 1b,
  // once the case is known not to be withdrawn (unit R-N, N3), and the tapes
  // are decoded at step 1d, once it is known to take a reveal (Design N).
  let caseFields;
  let tapeFields;
  let fromMultipart;
  let case_id;
  try {
    let fields;
    ({ fields, fromMultipart } = await RECONCILE.readFields(req));
    ({ caseFields, tapeFields } = revealFields(fields, fromMultipart));
    case_id = C.revealCaseId(caseFields);
  } catch (e) {
    if (e instanceof Refusal || e instanceof RECONCILE.Refusal) return refuse(res, e);
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    return refuse(res, new Refusal(400, "unreadable_body", "the request body could not be read"));
  }
  const cpath = C.casePath(case_id);

  // 1. The case, and where it stands by this service's clock.
  let got;
  try {
    got = await store.getFile(cpath);
  } catch (e) {
    console.error(`[case] reveal: case read failed (${e && e.message})`);
    return refuse(res, new Refusal(503, "store_unreachable", "the case record could not be read; this is not a 'no'"));
  }
  if (got === null) return refuse(res, new Refusal(404, "case_not_found", "no case is open with this id", { case_id }));
  const cv = judgeCase(got, cpath, case_id);
  if (!cv.ok) {
    return refuse(res, new Refusal(503, "case_record_unreadable",
      "the stored case is present but cannot be read as a valid arcaeon-case/1 record; nothing was compared", { reason: cv.reason }));
  }
  const kase = got.json;
  // 1a. THE REFUSAL BEFORE THE TAPES (Design N): a joint reveal after a
  // withdrawal is refused here, before its tapes are decoded or hashed, and
  // nothing about them is stored or logged. A party gets a signed refusal
  // receipt (withdrawnRefusal); the public case record and page do not
  // change.
  if (kase.status === "WITHDRAWN") return refuse(res, await withdrawnRefusal(case_id, caseFields, C.utcSeconds(nowMs), env, opts));
  // 1b. The joint reveal's body, both openings, read whole now.
  let asked;
  try {
    asked = C.validateRevealBody(caseFields);
  } catch (e) {
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    throw e;
  }
  if (kase.status === "VERDICT") {
    return refuse(res, new Refusal(409, "not_committed",
      "the case is already sealed with a verdict, and a case has one joint reveal; nothing was compared", { case_id, status: kase.status }));
  }
  if (C.pastDeadline(kase, nowMs)) {
    return refuse(res, new Refusal(409, "expired",
      "the case's deadline has passed by this service's clock; the joint reveal must be received before it, so the case reads EXPIRED. Nothing was compared",
      { case_id, deadline: kase.deadline, status: "EXPIRED" }));
  }
  if (kase.status !== "COMMITTED") {
    return refuse(res, new Refusal(409, "not_committed",
      "the case is not COMMITTED: both roles must have a registered commitment before the joint reveal. If both parties have " +
        "registered and the case still reads OPEN, send either registration again; the replay completes the case. Nothing was compared",
      { case_id, status: kase.status }));
  }
  // 1d. The tapes, decoded now that the case takes a reveal.
  let tapes;
  try {
    tapes = revealTapes(tapeFields, fromMultipart);
  } catch (e) {
    if (e instanceof Refusal || e instanceof RECONCILE.Refusal) return refuse(res, e);
    return refuse(res, new Refusal(400, "unreadable_body", "the request body could not be read"));
  }

  // 2. THE PROJECTION IS THE REGISTRATION (unit R-L4): the registrations
  // are the case root's projection, each projected file checked against the
  // sha256 the projection carries (lib/_case_seal.js
  // projectedRegistrations). A case whose record is inconsistent is never
  // sealed (unit R-L4b).
  const proj = await SEAL.projectedRegistrations(kase);
  if (!proj.ok) return refuse(res, projectionRefusal(case_id, proj, "nothing was compared"));
  const regs = proj.entries;
  // 2s. ONE KEY PER ROLE: one key id registered both roles. Such a case is a
  // single party and never reaches sealed.
  if (C.singleParty(kase)) {
    return refuse(res, new Refusal(409, "single_party",
      `both roles of this case are registered under one key, ${kase.commitments.a.key_id}, and the two roles of a case are registered ` +
        "by two distinct keys; a single-party case is never sealed. Nothing was compared", { case_id, key_id: kase.commitments.a.key_id }));
  }

  // 3. Each reveal recomputes the commitment registered to its role, under
  // that REGISTERED role: the reveal-time half of role binding. A's tape and
  // salt sent as b's are refused here.
  for (const r of C.ROLES) {
    const recomputed = C.commitmentSha256({ case_id, role: r, tape_sha256: asked.reveals[r].tape_sha256, salt: asked.reveals[r].salt });
    if (recomputed !== regs[r].commitment_sha256) {
      return refuse(res, new Refusal(409, "commitment_mismatch",
        `the reveal for role ${r} does not recompute the commitment registered to role ${r} of this case ` +
          "(sha256 of json-c14n:v1 {case_id, role, tape_sha256, salt, protocol_version}); nothing was compared",
        { case_id, role: r }));
    }
  }
  // 4. Each tape is the one its commitment fixed.
  for (const r of C.ROLES) {
    if (sha256hex(tapes[r]) !== asked.reveals[r].tape_sha256) {
      return refuse(res, new Refusal(409, "tape_substituted",
        `the tape submitted as tape_${r} is not the tape role ${r} committed to: its sha256 differs from the committed tape_sha256; nothing was compared`,
        { case_id, role: r }));
    }
  }
  // 5. This build runs the case's bound policy version, and only that one
  // (design decision 8: "it never compares under another version").
  if (kase.policy_version !== T.PORT_VERSION) {
    return refuse(res, new Refusal(409, "policy_unavailable",
      `the case is bound to reconcile port version ${kase.policy_version}, and this service runs ${T.PORT_VERSION}; ` +
        "it does not compare a case under another version than the one it bound. Nothing was compared",
      { case_id, policy_version: kase.policy_version, runnable_version: T.PORT_VERSION }));
  }

  // 5b. The document this deployment carries, and its commit (Design I).
  const sealing = SEAL.sealingDocument(env, { keyDocument: opts.keyDocument });
  if (!sealing.ok) {
    console.error(`[case] reveal: the key document is unavailable (${sealing.reason})`);
    return refuse(res, new Refusal(503, "document_unavailable",
      "this deployment cannot name the key document it would seal under, so it seals nothing; nothing was compared", { case_id, reason: sealing.code }));
  }
  // 5b2. THE SEALER READS WHAT IT NAMES (unit R-I, I2; lib/_case_seal.js
  // confirmSealingDocument): the commit it names is on the published branch,
  // and the document there is the one it carries. Otherwise every case it
  // sealed would name a document no reader can hold it to: it refuses here,
  // so nothing is written and nothing compared.
  const confirmed = await SEAL.confirmSealingDocument(sealing, env);
  if (!confirmed.ok) {
    console.error(`[case] reveal: the key document at the deployment's commit does not confirm the bundled one (${confirmed.reason})`);
    return refuse(res, new Refusal(503, "document_unavailable",
      "the key document at the commit this deployment names is not, or could not be read as, the one it carries, so it seals nothing; " +
        "nothing was compared", { case_id, reason: confirmed.reason }));
  }

  // 5c. The reconcile signer, read before anything is compared (red-team
  // fix B's refusal, made here rather than inside the comparison).
  const rsigner = SEAL.loadReconcileSigner(env, { keyDocument: sealing.doc });
  if (!rsigner.ok) {
    console.error(`[case] reveal: no published reconcile signer (${rsigner.reason})`);
    return refuse(res, new Refusal(503, "signer_unavailable",
      "this deployment has no published reconcile signer, and a case is never sealed with a receipt it cannot sign with one; nothing was compared and nothing was sealed",
      { case_id, reason: rsigner.code }));
  }

  // 5c2. ONE SIGNATURE RULE (lib/_case_seal.js): an unsigned seal never
  // verifies, so the reveal seals only signed. Without a case key the
  // document it carries lists, it refuses here, before anything is written
  // or compared.
  const csigner = SEAL.loadCaseSigner(env, { keyDocument: sealing.doc });
  if (!csigner.ok) {
    return refuse(res, new Refusal(503, "case_signer_unavailable",
      "this deployment has no case key that the key document it carries lists, and an unsigned seal never verifies, so it seals " +
        "nothing; nothing was compared and nothing was sealed", { case_id, reason: csigner.code }));
  }

  // A failure from here on writes nothing (unit R-RV, rule 2): the case
  // stays as it was read, and the server log names the case and the code
  // only, never a tape, a hash or a salt.
  const failed = (refusal) => {
    console.error(`[case] reveal: case ${case_id}, ${refusal.code}`);
    return refuse(res, refusal);
  };

  // 6. The comparison: ?op=reconcile's own call, once. Role a's tape is
  // reconcile's first argument, tape_a in its answer and in the receipt.
  // THE ONE CLOCK READ (unit R-RV, the architect's ruling c): compare reads
  // this service's clock after the port returns, for the receipt's
  // compared_at, and that one read is every time the seal and its pin
  // record.
  let sealMs;
  let compared;
  try {
    compared = RECONCILE.compare(tapes.a, tapes.b, { env, clock: () => (sealMs = clock(opts)), keyDocument: sealing.doc });
  } catch (e) {
    if (!e || (!e.portError && !e.signerUnavailable)) throw e;
    return failed(new Refusal(500, "comparison_failed", "the comparison failed inside this service; no verdict was reached and nothing was sealed",
      { case_id }));
  }
  const revealedAt = C.utcSeconds(sealMs);

  // 7. The receipt, checked deeply before anything is sealed (lib/_case_seal.js).
  const rc = SEAL.checkReceipt(compared.receipt, {
    kase,
    tapeSha256: { a: asked.reveals.a.tape_sha256, b: asked.reveals.b.tape_sha256 },
    tapeBytes: { a: tapes.a.length, b: tapes.b.length },
    result: compared.result,
    revealedAt,
    signer: rsigner,
  });
  if (!rc.ok) {
    return failed(new Refusal(500, "receipt_check_failed", "the receipt this service built for the comparison failed its own check; nothing was sealed",
      { case_id, reason: rc.reason }));
  }
  const st = SEAL.storableReceipt(compared.receipt);
  if (!st.ok && st.reason === "integer_beyond_json") {
    return failed(new Refusal(422, "verdict_not_sealable",
      "the verdict names a call index larger than 2^53 - 1, which a JSON case record cannot hold without changing the receipt's " +
        "signed bytes; nothing was sealed", { case_id }));
  }
  if (!st.ok) {
    return failed(new Refusal(500, "receipt_check_failed", "the receipt could not be held in a case record; nothing was sealed",
      { case_id, reason: st.reason }));
  }

  // 8. The seal: the case file, authoritative (lib/_case_seal.js), signed
  // with the case key read at 5c2.
  const signedUnder = { document_sha256: sealing.document_sha256, document_commit: sealing.document_commit, retrieved_at: revealedAt };
  let sealed;
  try {
    sealed = SEAL.sealCase(kase, { reveals: asked.reveals, receipt: st.receipt, crossReference: asked.cross_reference, revealedAt, signedUnder }, csigner);
  } catch (e) {
    if (!(e instanceof C.CaseError)) throw e;
    return failed(new Refusal(500, "seal_build_failed", "this service built a sealed case its own schema refuses; nothing was sealed", { case_id }));
  }
  const chain = SEAL.caseChain(sealed);
  // THE ONE WRITE (unit R-RV, rule 1): over the COMMITTED root read at step
  // 1 (CAS on got.sha). A lost swap is answered from what the root now is.
  let put;
  try {
    put = await store.putFile(cpath, sealed, `case ${case_id.slice(0, 16)}: sealed, ${sealed.verdict.verdict.verdict}`, got.sha, { rebuild: () => null });
  } catch (e) {
    if (e && e.conflict) put = { abandoned: true };
    else return failed(new Refusal(503, "case_seal_failed", SEAL_FAILED, { case_id }));
  }
  if (put && put.abandoned) return refuse(res, await sealLostRefusal(cpath, case_id));

  // 9. The pin, recording the commit the case file's write answered with. A
  // pin that fails leaves the case sealed and reports pin:
  // "commit_unrecorded", computed, never stored.
  const caseCommit = SEAL.commitOfPut(put);
  const pin = await SEAL.pinChain(case_id, chain, sealMs, caseCommit);
  if (pin.pin !== "pinned") console.error(`[case] reveal: sealed, pin ${pin.pin} (${pin.reason || "see record"})`);

  const v = judgeCase({ json: sealed }, cpath, case_id);
  const body = verdict.success(v, {
    case_id,
    status: sealed.status,
    case: sealed,
    chain,
    case_commit: caseCommit,
    pin: pin.pin,
    pin_commit: pin.pin_commit || null,
    pin_namespace: SEAL.pinNamespace(case_id),
    anchor_note: SEAL.ANCHOR_NOTE,
    sealed_by: csigner.ok ? { name: csigner.name, verifier: csigner.verifier, alg: "ed25519" } : null,
    verdict: compared.result,
    service_limits: RECONCILE.SERVICE_LIMITS.slice(),
  }, "case-reveal");
  res.setHeader("content-type", "application/json; charset=utf-8");
  return res.status(201).send(T.wireJson(body));
}

// ---------------------------------------------------------------------------
// shared by the withdrawal and the reference (item 2c)
// ---------------------------------------------------------------------------

// Read and judge the case at `cpath`. -> {kase, got} or {refusal}.
async function readCase(cpath, caseId, where, nothing) {
  let got;
  try {
    got = await store.getFile(cpath);
  } catch (e) {
    console.error(`[case] ${where}: case read failed (${e && e.message})`);
    return { refusal: new Refusal(503, "store_unreachable", withTail("the case record could not be read; this is not a 'no'", nothing, ", and ")) };
  }
  if (got === null) return { refusal: new Refusal(404, "case_not_found", "no case is open with this id", { case_id: caseId }) };
  const cv = judgeCase(got, cpath, caseId);
  if (!cv.ok) {
    return { refusal: new Refusal(503, "case_record_unreadable",
      withTail("the stored case is present but cannot be read as a valid arcaeon-case/1 record", nothing), { reason: cv.reason }) };
  }
  return { kase: got.json, got };
}

// The registrations a role proves itself against (the withdrawal and the
// reference): the case root's projection, each projected file checked
// against the sha256 it carries (THE PROJECTION IS THE REGISTRATION, unit
// R-L4). -> {regs} (the projected entries) or {refusal}.
async function readAuthority(kase, nothing) {
  const proj = await SEAL.projectedRegistrations(kase);
  if (!proj.ok) return { refusal: projectionRefusal(kase.case_id, proj, nothing) };
  return { regs: proj.entries };
}

// A ROLE PROVES ITSELF (THE WITHDRAWAL, THE REFERENCE ROW, above): the
// commitment recomputed from the presented preimage, under the NAMED role,
// equals that role's registration file. Pure. -> true or false.
function proves(caseId, regs, { role, tape_sha256, salt }) {
  const reg = regs[role];
  if (!reg) return false;
  return C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) === reg.commitment_sha256;
}

// ---------------------------------------------------------------------------
// POST ?op=case-withdraw (THE WITHDRAWAL, above)
// ---------------------------------------------------------------------------
async function handleCaseWithdraw(req, res, opts = {}) {
  const admitted = await admit(req, res, "withdraw");
  if (!admitted) return;
  const nowMs = clock(opts);
  const env = opts.env || process.env;

  let asked;
  try {
    asked = C.validateWithdrawBody(admitted.body);
  } catch (e) {
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    throw e;
  }
  const { case_id, role } = asked;
  const cpath = C.casePath(case_id);
  // R1 (unit R-N4): no answer here says "nothing was withdrawn" unless this
  // request confirmed it; every refusal that wrote nothing ends with
  // WROTE_NOTHING.
  const nothing = WROTE_NOTHING;

  // 1. The case, and where it stands by this service's clock.
  const rc = await readCase(cpath, case_id, "withdraw", nothing);
  if (rc.refusal) return refuse(res, rc.refusal);
  const { kase, got } = rc;
  // 1r. A RETRIED WITHDRAWAL IS IDEMPOTENT (unit R-N, C3): the role that
  // withdrew, presenting the same preimage again, gets 200 and the record as
  // it stands; a marker that failed is written now. Anyone else is refused
  // as before.
  if (kase.status === "WITHDRAWN") {
    const retried = await retriedWithdrawal(kase, asked);
    if (retried && retried.refusal) return refuse(res, retried.refusal);
    if (retried) return res.status(200).json(retried);
  }
  const stand = withdrawStanding(kase, nowMs, case_id);
  if (stand) return refuse(res, stand);

  // 2. The registrations: the case root's projection (THE PROJECTION).
  const auth = await readAuthority(kase, nothing);
  if (auth.refusal) return refuse(res, auth.refusal);

  // 3. The role proves itself by its commitment preimage.
  if (!proves(case_id, auth.regs, asked)) {
    return refuse(res, new Refusal(403, "withdraw_unauthorized",
      `the preimage presented does not recompute a commitment registered to role ${role} of this case ` +
        "(sha256 of json-c14n:v1 {case_id, role, tape_sha256, salt, protocol_version}), so it does not show that the caller holds that role. " +
        nothing, { case_id, role }));
  }

  // 4. The redacted record, signed with the case key. ONE SIGNATURE RULE
  // EVERYWHERE (unit R-N, N1): without a case key the document lists, no
  // record is written (the server log says why; the caller gets the code).
  const signer = SEAL.loadCaseSigner(env, { keyDocument: opts.keyDocument });
  if (!signer.ok) {
    console.error(`[case] withdraw: no case signer (${signer.code}: ${signer.reason})`);
    return refuse(res, new Refusal(503, "signer_unavailable",
      `this deployment has no case key that the key document it carries lists, and a withdrawal record is signed or not written. ${nothing}`,
      { case_id, reason: signer.code }));
  }
  let record;
  try {
    record = SEAL.withdrawnRecord(kase, { role, at: C.utcSeconds(nowMs), salt: asked.salt, reason: asked.reason }, signer);
  } catch (e) {
    if (!(e instanceof C.CaseError)) throw e;
    console.error(`[case] withdraw: built an invalid withdrawal record (${e.code} at ${e.field})`);
    return refuse(res, new Refusal(500, "internal_error", `this service built a withdrawal record its own schema refuses. ${nothing}`));
  }

  // 5. The root write: a CAS over the case as read, under THE CASE LOCK
  // (red-team fix C), the lock a registration's write takes too. The case
  // may move meanwhile. If a registration was projected, the redacted record
  // does not depend on it and is written over the fresh case. If a reveal
  // sealed it, or another withdrawal landed, that write stands and this one
  // is refused by what the case now is.
  // Since unit R-L (L1) nothing is written before the record: the
  // withdrawal proves the role, takes the lock, writes the signed record,
  // writes the marker and answers. A withdrawal that loses (the case sealed,
  // or expired, first) writes nothing and removes nothing (L4).
  const lease = leaseClock(opts);
  const lock = await acquireCaseLock(case_id, "withdraw", lease);
  if (!lock.ok) return refuse(res, lockRefusal(lock, nothing));
  let put;
  try {
    put = await store.putFile(cpath, record, `case ${case_id.slice(0, 16)}: withdrawn by role ${role}`, got.sha, {
      rebuild: (fresh) => {
        if (!fresh || !C.validateCase(fresh.json).ok || fresh.json.case_id !== case_id) return null;
        if (!C.REGISTERABLE_STATUSES.includes(fresh.json.status) || C.pastDeadline(fresh.json, nowMs)) return null;
        return record;
      },
    });
  } catch (e) {
    if (e && e.conflict) put = { abandoned: true };
    else {
      console.error(`[case] withdraw: case write failed (${e && e.message})`);
      await releaseCaseLock(case_id, lock, lease);
      // the write threw, so it may have landed (unit R-N4, R3)
      return refuse(res, new Refusal(503, "store_error", MAY_HAVE_LANDED, { case_id }));
    }
  }
  await releaseCaseLock(case_id, lock, lease);
  if (put && put.abandoned) {
    let again;
    try {
      again = await store.getFile(cpath);
    } catch {
      again = undefined;
    }
    const current = again && C.validateCase(again.json).ok ? again.json : null;
    // the lock, in the private usage repository, was written and released;
    // the pins repository was not written (unit R-L, L4)
    const lost = current ? withdrawStanding(current, nowMs, case_id, WROTE_NO_PINS) : null;
    if (lost) return refuse(res, lost);
    // the case read fine, and can still be withdrawn: the write kept losing
    // to other writes (unit R-L2, M2)
    if (current) return refuse(res, new Refusal(503, "store_error", KEPT_CHANGING, { case_id, reason: "case_kept_changing" }));
    return refuse(res, new Refusal(503, "store_error",
      `the case moved while this withdrawal was written, and what it is now could not be read. ${WROTE_NO_PINS} Send the same withdrawal again.`,
      { case_id, reason: "case_moved" }));
  }

  // 6. The marker, create-only, so a tree listing shows the withdrawal
  // without a fetch (lib/_case_seal.js caseTreeIndex). The record above is
  // the authority: a marker that fails leaves the case withdrawn, and the
  // answer says so; a retried withdrawal and the sealer's withdrawn path
  // write it again.
  const marker = await SEAL.writeWithdrawnMarker(case_id, record.withdrawal.at);
  return res.status(201).json(withdrawalAnswer(record, { existing: false, marker }));
}

// A withdrawal that lost after it took the case lock (unit R-L, L4): the
// lock record, in the private usage repository, was written and released.
const WROTE_NO_PINS = "This request wrote nothing to the pins repository.";
// The root write kept losing, and the case read after it can still be
// withdrawn (unit R-L2, M2).
// (unit R-L3, d: the lock record, in the private usage repository, was written)
const KEPT_CHANGING = "the case kept changing while this request tried to write; nothing was written to the case record. Send it again.";
// THE PROJECTION (unit R-L4, rule 3): the confirming read or the projection
// failed, and nothing more was written; the same registration sent again
// finds the file and projects it.
const UNCONFIRMED = "the registration file is written and is not yet confirmed; send the same registration again";
// The confirming read found the case withdrawn (rule 6). Whether the file
// was written before or after the withdrawal is not known here; it is inert
// either way, and it stays.
const WITHDRAWN_BEFORE_CONFIRMED = "the case was withdrawn before this registration was confirmed; the registration file is written and has no standing";
// A file the root does not project, past the deadline (rule 8).
// (Unit R-L4c: it says no more than the clock it was judged by shows; unit
// R-L4d, d2: and no more than this request read.)
const LATE_UNCONFIRMED = "the case's deadline has passed, and the registration file written for this request was not confirmed when this request read the case";
// The root write threw, so it may have landed (unit R-N4, R3).
const MAY_HAVE_LANDED = "The withdrawal record may not have been written. Send the same withdrawal again to finish or to confirm.";

// The withdrawal's answer, a first one (201) or a retry's (200).
function withdrawalAnswer(record, { existing, marker }) {
  const case_id = record.case_id;
  const v = judgeCase({ json: record }, C.casePath(case_id), case_id);
  return verdict.success(v, {
    case_id,
    status: "WITHDRAWN",
    existing,
    withdrawn_by: record.withdrawal.by_role,
    // a stored unsigned record's sig_reason is the server's to log, not the
    // caller's to read (unit R-N3, N8); a signed record is shown whole
    case: record.sig === null ? withoutSigReason(record) : record,
    marker,
    marker_path: C.withdrawnMarkerPath(case_id),
    registrations_note: SEAL.WITHDRAWN_REGISTRATIONS_NOTE,
    // the public claim, and no more (unit R-L, L2)
    withdrawal_note: SEAL.WITHDRAWAL_CLAIM,
    preimage_note: "Presenting the preimage spends this commitment: a withdrawn case can never be revealed. Nothing of the preimage is " +
      "kept except the sha256 of the salt, in the withdrawal record.",
    signed_by_note: record.sig === null ? "This withdrawal record is stored unsigned." : `Signed by ${record.signed_by}; the verifier is published at /${SEAL.CASE_KEYS_DOC}.`,
  }, "case-withdraw");
}

function withoutSigReason(record) {
  const { sig_reason: _unshown, ...shown } = record;
  return shown;
}

// A RETRIED WITHDRAWAL (unit R-N, C3): `asked` is the role that withdrew
// `kase` (WITHDRAWN) presenting its preimage again, when its salt is the one
// the record keeps the sha256 of and its preimage recomputes the commitment
// the case root projected for that role before the withdrawal (since unit
// R-L4: lib/_case_seal.js rootBeforeWithdrawal, its files checked against
// it, THE PROJECTION). Then the marker is written again, create-only, and
// the answer is the record as it stands.
// -> the answer body, {refusal} (the root before the withdrawal, or a file
// it projects, could not be read), or null (not that withdrawer: the caller
// refuses as before).
async function retriedWithdrawal(kase, asked) {
  const w = kase.withdrawal;
  if (asked.role !== w.by_role || C.saltSha256(asked.salt) !== w.salt_sha256) return null;
  const before = await SEAL.rootBeforeWithdrawal(kase.case_id);
  const proj = before.ok ? await SEAL.projectedRegistrations(before.kase) : null;
  if (proj && !proj.ok && proj.inconsistent) return { refusal: projectionRefusal(kase.case_id, proj, WROTE_NOTHING) };
  if (!proj || !proj.ok) {
    // a read that failed is not an answer (follow-up f4 to unit R-N4)
    return { refusal: new Refusal(503, "store_unreachable",
      "The case is withdrawn. This request could not finish checking it. Send the same withdrawal again.", { case_id: kase.case_id }) };
  }
  if (!proves(kase.case_id, proj.entries, asked)) return null;
  const marker = await SEAL.writeWithdrawnMarker(kase.case_id, w.at);
  return withdrawalAnswer(kase, { existing: true, marker });
}

// Whether a case may still be withdrawn. -> null, or the Refusal saying why
// not: VERDICT is case_sealed, WITHDRAWN is case_withdrawn, an OPEN or
// COMMITTED case at or past its deadline reads EXPIRED (expired). Each ends
// with `tail`, what the request wrote: nothing, unless the caller says.
function withdrawStanding(kase, nowMs, caseId, tail = WROTE_NOTHING) {
  if (kase.status === "VERDICT") {
    return new Refusal(409, "case_sealed", `the case is sealed with a verdict, and a sealed case cannot be withdrawn. ${tail}`,
      { case_id: caseId, status: "VERDICT" });
  }
  if (kase.status === "WITHDRAWN") {
    return new Refusal(409, "case_withdrawn", `the case is already withdrawn. ${tail}`, { case_id: caseId, status: "WITHDRAWN" });
  }
  if (C.pastDeadline(kase, nowMs)) {
    return new Refusal(409, "expired",
      `the case's deadline has passed by this service's clock, so it reads EXPIRED, and an expired case is not withdrawn. ${tail}`,
      { case_id: caseId, deadline: kase.deadline, status: "EXPIRED" });
  }
  return null;
}

// ---------------------------------------------------------------------------
// POST ?op=case-reference (THE REFERENCE ROW, above)
// ---------------------------------------------------------------------------

// THE OPERATOR'S KEY, above: `Authorization: Bearer
// <WITNESS_CASE_OPERATOR_KEY>`, compared in constant time. Its own key, read
// from its own variable, never WITNESS_ADMIN_KEY. The order is the
// behaviour: no bearer is "missing" (401) whether or not the key is set; a
// bearer with the key unset is "unset" (503).
// -> "ok" | "missing" | "unset" | "wrong".
const OPERATOR_KEY_ENV = "WITNESS_CASE_OPERATOR_KEY";
function operatorBearer(req, env) {
  const auth = (req.headers && req.headers.authorization) || "";
  const given = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!given) return "missing";
  const want = env[OPERATOR_KEY_ENV];
  if (!want) return "unset";
  const a = Buffer.from(String(given), "utf8");
  const b = Buffer.from(String(want), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? "ok" : "wrong";
}

// Create-only attempts at the next seq before giving up.
const REFERENCE_WRITE_ATTEMPTS = 3;

// What each code of lib/_case_seal.js sealedRecordReason means, in the
// reference's refusal.
const UNSEALED_WORDS = Object.freeze({
  single_party: "one key registered both of its roles",
  verdict_unbound: "the receipt it carries is not bound to it",
  receipt_unsigned: "the receipt it carries is not signed by this service's reconcile signer",
  document_unavailable: "the key document it names could not be read on this request, which is not a no",
  document_unrecorded: "it names no key document it was signed under",
  case_signature_invalid: "its signature is not confirmed by the published key document",
  // unit R-I
  signer_unlisted: "a key that signed it is not listed in its role in the current key document",
  signer_revoked: "a key that signed it is listed as revoked in the key document this service carries, whenever it signed",
});

async function handleCaseReference(req, res, opts = {}) {
  const env = opts.env || process.env;
  const admitted = await admit(req, res, "reference", { operatorEnv: env });
  if (!admitted) return;
  const nowMs = clock(opts);

  let asked;
  try {
    asked = C.validateReferenceBody(admitted.body);
  } catch (e) {
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    throw e;
  }
  const { case_id, proof } = asked;
  const cpath = C.casePath(case_id);
  const nothing = "no row was written";

  // 0. Who appends: a role's proof (checked at step 3), or the operator.
  if (proof === null) {
    const op = operatorBearer(req, env);
    if (op === "unset") {
      return refuse(res, new Refusal(503, "operator_key_not_configured",
        `no role proof was presented, and the operator's key is not configured on this deployment, so the request cannot be authorized; ${nothing}`));
    }
    if (op !== "ok") {
      res.setHeader("www-authenticate", 'Bearer realm="arcaeon-witness"');
      return refuse(res, new Refusal(401, "reference_unauthorized",
        "a reference row is appended by a registered role, presenting role, tape_sha256 and salt (its commitment preimage), " +
          `or by the operator's bearer key; ${op === "missing" ? "neither was presented" : "the bearer key is not the operator's"}, and ${nothing}`));
    }
  }

  // 1. The case: only a sealed case takes a reference row.
  const rc = await readCase(cpath, case_id, "reference", nothing);
  if (rc.refusal) return refuse(res, rc.refusal);
  const kase = rc.kase;
  if (kase.status === "WITHDRAWN") {
    return refuse(res, new Refusal(409, "case_withdrawn", `the case was withdrawn, and a withdrawn case takes no reference; ${nothing}`,
      { case_id, status: "WITHDRAWN" }));
  }
  if (kase.status !== "VERDICT") {
    const status = C.pastDeadline(kase, nowMs) ? "EXPIRED" : kase.status;
    return refuse(res, new Refusal(409, "case_not_sealed",
      `the case is ${status}; a reference row is appended to a sealed case only (a reveal may carry its own cross_reference); ${nothing}`,
      { case_id, status }));
  }
  // 1b. THE SEALED CHECK (item 2d; Design I): a VERDICT is a sealed case
  // only when it holds under the key document it names (lib/_case_seal.js
  // sealedRecordReason, the check anchorCase runs before it pins):
  // valid_under_document only. Anything else takes no row; since unit R-REV
  // a revoked key's case is 409 signer_revoked, whenever it was signed.
  const keyDocument = opts.keyDocument === undefined ? SEAL.PUBLISHED_KEYS : opts.keyDocument;
  const answer = await SEAL.sealedRecordReason(kase, keyDocument);
  if (answer.code === "signer_revoked") {
    return refuse(res, new Refusal(409, "signer_revoked",
      `the case reads VERDICT, and ${UNSEALED_WORDS.signer_revoked} (${answer.reason}), so it is not treated as a sealed case; ${nothing}`,
      { case_id, status: "VERDICT", reason: answer.reason }));
  }
  const unsealed = SEAL.sealHolds(answer) ? null : answer;
  if (unsealed) {
    console.error(`[case] reference: the stored VERDICT does not verify (${unsealed.code}: ${unsealed.reason})`);
    return refuse(res, new Refusal(409, unsealed.code,
      `the case reads VERDICT, but its sealed record does not verify (${unsealed.reason}): ${UNSEALED_WORDS[unsealed.code] || unsealed.code}, ` +
        `so it is not treated as a sealed case; ${nothing}`,
      { case_id, status: "VERDICT", reason: unsealed.reason }));
  }

  // 1c. NO PIN GATE (unit R-PIN). A row is a truthful record whether or not
  // a pin ever lists it (Fable, sitting 1, Q1(c)): no pin and no anchor is
  // read here, and no state the appender cannot affect refuses a row. Before
  // a row is written this request reads the case root, runs the sealed
  // check, loads the signer and lists the rows' seqs (and, for a role, its
  // registrations, to check its proof).

  // 2 and 3. A role proves itself against the registration files.
  let appendedBy = "operator";
  if (proof !== null) {
    const auth = await readAuthority(kase, nothing);
    if (auth.refusal) return refuse(res, auth.refusal);
    if (!proves(case_id, auth.regs, proof)) {
      return refuse(res, new Refusal(403, "reference_unauthorized",
        `the preimage presented does not recompute the commitment registered to role ${proof.role} of this case; ${nothing}`,
        { case_id, role: proof.role }));
    }
    appendedBy = `role:${proof.role}`;
  }

  // 3b. ONE SIGNATURE RULE EVERYWHERE (unit R-N, N1): an unsigned row is not
  // a record, so none is written. Without a case key the document lists,
  // 503, before any quota is spent (the server log says why).
  const signer = SEAL.loadCaseSigner(env, { keyDocument });
  if (!signer.ok) {
    console.error(`[case] reference: no case signer (${signer.code}: ${signer.reason})`);
    return refuse(res, new Refusal(503, "signer_unavailable",
      `this deployment has no case key that the key document it carries lists, and an unsigned row is not a record; ${nothing}`,
      { case_id, reason: signer.code }));
  }

  // 4. The row, create-only at the next seq. Another row landing first takes
  // that seq; this one moves to the next. A row is never written over.
  const recordedAt = C.utcSeconds(nowMs);
  let row = null;
  let rpath = null;
  let judged = null;
  let unitTaken = proof === null; // the operator is not a role: no unit
  for (let attempt = 1; attempt <= REFERENCE_WRITE_ATTEMPTS && row === null; attempt += 1) {
    let seqs;
    try {
      seqs = await SEAL.referenceSeqs(case_id);
    } catch (e) {
      console.error(`[case] reference: listing failed (${e && e.message})`);
      return refuse(res, new Refusal(503, "store_unreachable", `the case's reference rows could not be listed; this is not a 'no', and ${nothing}`));
    }
    const seq = (seqs.length ? seqs[seqs.length - 1] : 0) + 1;
    // THE ROW CAP (unit R-L2, M3; lib/_case_seal.js MAX_REFERENCE_ROWS)
    if (seq > SEAL.MAX_REFERENCE_ROWS) {
      return refuse(res, new Refusal(409, "row_limit",
        `this case holds ${SEAL.MAX_REFERENCE_ROWS} reference rows, the most one case holds; ${nothing}`, { case_id }));
    }
    let built;
    try {
      built = SEAL.referenceRow({ caseId: case_id, seq, crossReference: asked.cross_reference, recordedAt, appendedBy }, signer);
    } catch (e) {
      if (!(e instanceof C.CaseError)) throw e;
      console.error(`[case] reference: built an invalid row (${e.code} at ${e.field})`);
      return refuse(res, new Refusal(500, "internal_error", `this service built a reference row its own schema refuses; ${nothing}`));
    }
    const p = C.referencePath(case_id, seq);
    // The row's own judge, before the write: this service never writes a
    // row its readers would refuse (a clock behind the seal, say).
    const pre = SEAL.judgeReferenceRow({ json: built }, { path: p, caseId: case_id, seq, sealed: kase, keyDocument });
    if (!pre.ok) {
      console.error(`[case] reference: built a row its own judge refuses (${pre.reason})`);
      return refuse(res, new Refusal(500, "internal_error", `this service built a reference row its own judge refuses; ${nothing}`, { reason: pre.reason }));
    }
    // THE REFERENCE QUOTA, above: one unit of this role's rows on this case,
    // taken once, after every check and before the row's write.
    if (!unitTaken) {
      let quota;
      try {
        quota = await takeReferenceQuota(case_id, proof.role);
      } catch (e) {
        console.error(`[case] reference: the reference quota could not be read or written${e && e.status ? ` (${e.status})` : ""}`);
        return refuse(res, new Refusal(503, "reference_quota_unreadable",
          `the reference quota for role ${proof.role} of this case could not be checked; this is not a 'no', and ${nothing}`,
          { case_id, role: proof.role }));
      }
      if (!quota.ok) {
        return refuse(res, new Refusal(409, "reference_quota",
          `role ${proof.role} has appended ${quota.used} reference rows to this case, the most one role may append ` +
            `(${REFERENCE_QUOTA_PER_ROLE}); ${nothing}`,
          { case_id, role: proof.role, count: quota.used, quota: REFERENCE_QUOTA_PER_ROLE }));
      }
      unitTaken = true;
    }
    try {
      await store.putFile(p, built, `case ${case_id.slice(0, 16)}: reference ${seq}`, undefined, { rebuild: () => null });
      row = built;
      rpath = p;
      judged = pre;
    } catch (e) {
      if (!(e && e.conflict)) {
        console.error(`[case] reference: row write failed (${e && e.message})`);
        return refuse(res, new Refusal(503, "store_error", `could not write the reference row; ${nothing}`, { case_id }));
      }
      // another row took this seq: list again and take the next
    }
  }
  if (row === null) {
    return refuse(res, new Refusal(503, "reference_seq_contended", `other rows kept taking the next seq; ${nothing}. Send it again`, { case_id }));
  }

  // 5. The live count, read back from the rows (the sealed case is untouched).
  const live = await SEAL.liveRecords(kase, { keyDocument });
  return res.status(201).json(verdict.success(judged, {
    case_id,
    seq: row.seq,
    path: rpath,
    appended_by: appendedBy,
    row,
    records_sealed: kase.records,
    records_live: live.ok ? live.records : null,
    sealed_case_note: "The sealed case is not changed: its records field is the count at seal time and never changes. The live count is " +
      "read from the valid reference rows.",
    anchor_note: C.REFERENCE_ANCHOR_NOTE,
  }, "case-reference"));
}

module.exports = {
  handleCaseOpen,
  handleCaseCommit,
  handleCaseReveal,
  handleCaseWithdraw,
  handleCaseReference,
  BODY_MAX_BYTES,
  OPEN_QUOTA_PER_DAY,
  REFERENCE_QUOTA_PER_ROLE,
  OPERATOR_KEY_ENV,
  CASE_LOCK_TTL_SECONDS,
  _internal: { withdrawStanding, caseLockPath, acquireCaseLock, releaseCaseLock, lockState, leaseClock, Refusal, readJsonBody, judgeStampRecord, revealFields, openQuotaPath, takeOpenQuota, referenceQuotaPath, takeReferenceQuota, operatorBearer },
};

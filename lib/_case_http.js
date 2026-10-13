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
// registrations that race past the check (each reads the other role's file
// absent) both stand, first write wins per role, and the case projects both:
// a case whose two commitments share a key id is SINGLE PARTY, and the joint
// reveal refuses it (409 `single_party`, step 2 below), so it never reaches
// sealed.
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
// (lib/_store.js listCommits, through lib/_stamp_store.js) and records the
// one it names. A stamp is written once (lib/_stamp.js, first write wins),
// so exactly one commit is the honest history: more than one is refused
// `stamp_history_ambiguous` (409; this service will not choose between two
// commits of the public record), none is a history that does not show a
// record the contents read just returned (503 `stamp_history_unreadable`),
// and a history that cannot be read at all is 503
// `stamp_history_unreachable`. In every one of those, nothing is written:
// a registration never records `stamp_commit: null` any more. (The schema
// still reads null, so a record written by item one stays readable; nothing
// is deployed, so none exists outside the tests.) The commit's date is the stamps
// repository's own statement (lib/_store.js header), not independent time
// evidence; the registration records the commit, not its date.
//
// IDEMPOTENT REPLAY (item 2a; item 1b's report, "Repair symmetry"). The same
// registration sent again, the same hash for the same role, is a replay and
// never `role_already_committed`. It answers 200 with `existing: true`. If
// the case object does not yet project every registration file (either
// role's), the replay projects them, so either party's replay repairs both
// projections, and `projected` lists the roles it added. If the case
// already projects every file, the replay writes nothing and confirms. Only
// a DIFFERENT hash for a role that has a registration file is
// `role_already_committed`. A replay or completion rechecks the stamp record
// before it projects anything (step 6r: present, a readable file-stamp of
// this hash, size 272; not its commit history, which the file already
// records), and is not held to the deadline: the registration was received
// before it.
//
// TWO WRITES, AND WHICH ONE IS AUTHORITATIVE. A registration is two writes:
// the registration file, then the case object. The registration file is the
// authority (create-only: first write wins per (case_id, role)); the case
// object's `commitments` is its projection. If the file lands and the case
// update does not, the answer is 503 `case_update_failed` with
// `registration_recorded: true`, and sending the SAME registration again
// completes the projection, even after the deadline, because the registration
// itself was received before it. A different hash for that role is refused
// `role_already_committed`. (GPT's review of the seal, applied here first:
// "two writes, define the failure".)
//
// EVERY PROJECTION READS BOTH FILES (item 1b, after GPT-5.6's code review:
// "The code never rebuilds `commitments` from both authoritative registration
// records"). The case update does not apply only the role being registered.
// It rebuilds `commitments` from BOTH registration files that exist,
// cases/<case_id>/commit_a.json and commit_b.json, read through the same
// store. So if role b's file landed and b's case update failed, role a's
// registration projects b's file too, and the case reads COMMITTED without b
// ever retrying. When the write races another writer, the rebuild hook reads
// both files again on top of the fresh case. A case entry that no file holds,
// or that differs from its file, is never written over: the projection
// refuses it, and the caller gets `case_update_failed` with the registration
// still standing.
//
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
//   2. the registration files are the authority and the case object must
//      agree with them role by role (design decision 4), else 503
//      `case_record_inconsistent`; one key id in both registrations is a
//      single party (ONE KEY PER ROLE, above): 409 `single_party`; a
//      registration that names no stamp
//      commit (`stamp_commit: null`, the item-one form) cannot reveal: 409
//      `commitment_history_missing` (item 2b, after GPT-5.6's review of 2a:
//      the claim names a public dated commit, and such a registration does
//      not name one; no such registration exists outside the tests, so there
//      is nothing to migrate, and the rule fails closed); and each
//      registration still rests on its
//      stamp as registered (the design: "verifies both commitments against
//      the public stamps and the registrations"): the same stamp rules as at
//      registration (size 272, one commit), the same stamped_at and commit;
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
//   8. the seal: the case file, written over the COMMITTED case it read;
//   9. the pin (lib/_case_seal.js pinChain).
// Every refusal in 0 to 5 is a typed 4xx with an error_code (a 503 when the
// store cannot be read or does not agree with itself), carries no verdict,
// writes nothing and never runs reconcile. After 6 has run: a receipt that
// fails its own check, or a sealed case the schema refuses, is a 500 with
// nothing written (this service's defect); a verdict a JSON record cannot
// hold is 422 `verdict_not_sealable`; a case write that fails is 503
// `case_seal_failed`, with no pin; a case that moved meanwhile (another
// reveal sealed it, or it was withdrawn) is refused by what it now is. A
// pin that fails after the case file landed is not a failure of the seal:
// the answer is 201 with `pin: "commit_unrecorded"` (TWO WRITES in
// lib/_case_seal.js), and the sealer's next run pins it (lib/_case_seal.js,
// THE TRIGGER). The pin is the second phase of the case file's write (Design
// J, THE PIN IS THE SECOND PHASE): it records `case_commit`, the commit the
// case file's own write answered with, and the answer carries it too (null
// when that write's answer named none, and then no pin is written). A pin
// written is `pin: "pinned"` with `pin_commit`, the commit that wrote it:
// never "anchored", which only a daily anchor record can make a case
// (lib/_case_seal.js THE ANCHOR WORDS). Every success carries `anchor_note`,
// lib/_case_seal.js ANCHOR_NOTE.
// Every time recorded comes from one read of this service's clock, taken
// when the request arrived: revealed_at, the receipt's compared_at and a
// cross_reference's recorded_at.
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
// false`, with `received_at`, the registered_at it would have recorded.
// After its write, still under the lock, it reads the case once more. A
// lease is not a lock: one that ran out can be taken over, so a withdrawal
// may land between the two reads. Then the race was lost after the write,
// and inside the same critical section the registration is removed
// (lib/_case_unregister.js, the pins repository's one deletion, made only
// under the signed repair note kept for that file since units R-L and R-L2;
// since unit R-N no case log event is written): 409 case_withdrawn with `registration_removed` and
// `registration_recorded`, the file's real state (a removal that failed
// leaves it there, true, and the sealer completes the recorded removal
// later: lib/_case_seal.js repairWithdrawn and completeRemovals).
//   UNIT R-N (C1 to C3). After a withdrawal a registration file never stands:
// every reader treats a registration under a WITHDRAWN case as not
// standing, one written before it included (it stays in the public record,
// and a refusal receipt may name it: THE REFUSAL BEFORE THE TAPES). A read
// of the case after the write that fails unwinds the registration too: 503
// `registration_unconfirmed`, never a registration standing on an
// assumption. THE LEASE CLOCK is read at each attempt; a lease expires
// CASE_LOCK_TTL_SECONDS after its own acquisition.
//
// THE WITHDRAWAL (item 2c; lib/_case.js THE WITHDRAWAL). Keyless: A ROLE
// PROVES ITSELF, below. In order: the body (exactly {case_id, role,
// tape_sha256, salt}); the case, refused if VERDICT (`case_sealed`),
// already WITHDRAWN (`case_withdrawn`) or at or past its deadline
// (`expired`, the case reads EXPIRED); both registration files, the
// authority, and the case's agreement with them; the proof (403
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
// written over the fresh case. Registration files written before it are
// left in place, public, standing for no reader, and the answer says so in
// words (registrations_note). A marker that fails leaves the withdrawal
// standing (the root is the authority, and the sealer reads it, skips it as
// terminal and writes the marker); the answer says `marker: "failed"`.
// Nothing of the preimage is kept except salt_sha256 and the sha256 of the
// tape digest's bytes (the withdrawn commitment), and nothing of it is
// logged.
//
// A ROLE PROVES ITSELF (item 2c). By presenting its commitment preimage
// (tape_sha256 and salt): the commitment is recomputed under the NAMED role
// and must equal that role's registration file (proves). The service never
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
// row on valid_under_document and signer_since_revoked. A named document it
// cannot read is 409 `document_unavailable`, a seal that names none 409
// `document_unrecorded`, a case one key registered both roles of 409
// `single_party` (red-team fix A), a receipt that does not bind 409
// `verdict_unbound`, a receipt the named document's reconcile key did not
// sign 409 `receipt_unsigned` (red-team fix B), a case signature the
// named document does not confirm 409 `case_signature_invalid`, and since
// unit R-I a key the current document does not list in its role 409
// `signer_unlisted` and one it lists revoked, with the case not shown pinned
// before the revoking commit, 409 `signer_revoked`, each with its `reason`,
// and no row is written. The check runs before the proof is read. Who appends: a
// registered role proving itself (A ROLE PROVES ITSELF), or THE OPERATOR'S
// KEY, below; the row records which in appended_by. The row
// is written create-only at the next seq (the highest listed plus one); a
// row that lands first at that seq is never written over, and this one
// moves to the next (at most three tries). It is signed with the case key
// (lib/_case_seal.js referenceRow), judged by its own judge before it is
// written, and has no pin of its own. The sealed case is never touched.
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
const UNREG = require("./_case_unregister.js"); // a condemned file's recorded removal, completed on a replay (unit R-L3)
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

// Whether `registration` is the one on file for `role` now (unit R-N2, m10:
// registration_recorded is the file's real state). -> true, false (no file,
// or another registration), or null (the read failed: not known).
async function registrationOnFile(caseId, role, registration) {
  let g;
  try {
    g = await store.getFile(C.registrationPath(caseId, role));
  } catch {
    return null;
  }
  return !!g && !!g.json && g.json.commitment_sha256 === registration.commitment_sha256 && g.json.key_id === registration.key_id;
}

// A registration that must not stand (unit R-N, C1 and C2), removed inside
// the critical section the caller holds: one written after its case was
// withdrawn (`why`: registration_after_withdrawal), or one whose case could
// not be read after its write (registration_unconfirmed). Since unit R-L
// (L3) a commit message is not a record: the removal is made only after a
// signed repair note is written for the file, the one its path, its blob
// and the commit its write answered with name (lib/_case_seal.js
// removeRegistration, THE REPAIR NOTE; unit R-L2, M1). A note records that
// a removal was decided (unit R-L2, B1). A note that cannot be written
// removes nothing, and a removal that fails after its note leaves both; the
// sealer completes a recorded removal (lib/_case_seal.js completeRemovals).
// -> {removed, recorded, note_path}: recorded is the file's real state, read
//    back when the removal did not land (a read that fails says it may be
//    there); note_path is the note that covers this file, or null.
async function unwindRegistration({ caseId, role, put, why, at, env, keyDocument }) {
  const rpath = C.registrationPath(caseId, role);
  const blob = put && put.content && put.content.sha;
  const done = await SEAL.removeRegistration({ caseId, role, blobSha: blob, createdInCommit: SEAL.commitOfPut(put), reason: why, at, env, keyDocument });
  const notePath = done.removed || done.reason === "removal_failed" ? done.note_path : null;
  if (!done.removed) console.error(`[case] commit: a registration that must not stand was not removed (${done.reason})`);
  const removed = done.removed;
  if (removed) return { removed, recorded: false, note_path: notePath };
  let recorded = true;
  try {
    recorded = (await store.getFile(rpath)) !== null;
  } catch {
    recorded = true;
  }
  return { removed, recorded, note_path: notePath };
}

// What became of a registration that must not stand (unwindRegistration's
// answer), for the refusal: removed after its note; a note written and the
// removal not made (then `noted` says what follows); or no note and nothing
// removed (then `unnoted`). A note is said as what it is: a removal of this
// file was recorded (unit R-L2, B1).
function unwoundWords(unwound, why, { noted, unnoted }) {
  if (unwound.removed) return `it was removed after a signed repair note was written for it (a removal of this file was recorded for ${why})`;
  if (unwound.note_path) {
    return `a signed repair note is written for it (a removal of this file was recorded for ${why}), and the removal has not been made, so ${noted}`;
  }
  return `no repair note could be written and confirmed, so nothing was removed: ${unnoted}`;
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

function judgeRegistration(got, path, kase, role) {
  return verdict.judgeWith(got, path, (json) => {
    const r = C.validateRegistrationRecord(json);
    if (!r.ok) return `registration_${r.code}`;
    if (json.case_id !== kase.case_id || json.role !== role) return "registration_not_at_its_path";
    if (Date.parse(json.registered_at) >= Date.parse(kase.deadline)) return "registration_after_deadline";
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

// Both registration files of a case, each read through the store and judged:
// the authority the case object projects. Read in role order, a then b.
// -> {ok:true, regs:{a, b}}, where a role with no file is null, or
//    {ok:false, why: "unreachable" | "unreadable", role, reason}.
// Since unit R-L3 (THE CONDEMNED FILE, rule 2) a file under a standing,
// verified repair note is not a registration: it reads as absent (null in
// `regs`), and `condemned` names it, through the one helper every reader
// asks (lib/_case_seal.js registrationsStanding). `keyDocument` is the
// current key document the note is checked under. -> {ok:true, regs,
// condemned} or {ok:false, why: "unreachable" | "unreadable" |
// "could_not_look", role, reason}.
async function readRegistrations(kase, { keyDocument } = {}) {
  const regs = {};
  const files = {};
  for (const r of C.ROLES) {
    const p = C.registrationPath(kase.case_id, r);
    let g;
    try {
      g = await store.getFile(p);
    } catch (e) {
      console.error(`[case] commit: registration read failed (${e && e.message})`);
      return { ok: false, why: "unreachable", role: r };
    }
    if (g === null) {
      regs[r] = null;
      files[r] = null;
      continue;
    }
    const rv = judgeRegistration(g, p, kase, r);
    if (!rv.ok) return { ok: false, why: "unreadable", role: r, reason: rv.reason };
    regs[r] = g.json;
    files[r] = g;
  }
  const st = await SEAL.registrationsStanding(kase.case_id, files, { keyDocument });
  if (!st.ok) return { ok: false, why: "could_not_look", role: st.role, reason: st.reason };
  const condemned = { a: null, b: null };
  for (const r of C.ROLES) {
    if (!st.condemned[r]) continue;
    condemned[r] = { ...st.condemned[r], blob: files[r].sha };
    regs[r] = null;
  }
  return { ok: true, regs, condemned };
}

// What a could-not-look from readRegistrations says.
function standingUnread(read) {
  return `whether role ${read.role || "a or b"}'s registration file is under a repair note could not be read now (${read.reason}); this is not a 'no'`;
}

// The case object as the projection of the registration files (pure; see
// EVERY PROJECTION READS BOTH FILES above). Every role whose file exists and
// whose entry the case lacks is applied through lib/_case.js
// applyRegistration. An entry already in the case must be its file's, and an
// entry with no file is refused, never kept or dropped quietly.
// -> {next, added: [the roles applied]}. Throws CaseError, and never returns
// a case the schema would refuse to read back.
function projectFiles(kase, regs) {
  let next = kase;
  const added = [];
  for (const r of C.ROLES) {
    const entry = next.commitments[r];
    if (regs[r] === null) {
      if (entry !== null) {
        throw new C.CaseError("status_inconsistent", `commitments.${r}`, `the case shows a registration for role ${r} that no registration file holds`);
      }
      continue;
    }
    if (entry !== null) {
      if (!C.sameEntry(entry, C.commitmentEntry(regs[r]))) {
        throw new C.CaseError("status_inconsistent", `commitments.${r}`, `the case's entry for role ${r} is not its registration file's`);
      }
      continue;
    }
    next = C.applyRegistration(next, regs[r]);
    added.push(r);
  }
  const v = C.validateCase(next);
  if (!v.ok) throw new C.CaseError("status_inconsistent", v.field, `the projected case would not be a valid record (${v.code})`);
  return { next, added };
}

/// Project the registration files into the case object (the second write).
// `reg` is the registration this request made, is completing or is
// replaying; `regs` is both files as step 2 of handleCaseCommit read them,
// with `reg` standing in for its own role. Returns {ok:true, case, added}
// with the case as written (or as it already stood, when every file was
// already projected and nothing needed writing), or {ok:false, code}.
async function project(cpath, got, reg, regs, { keyDocument } = {}) {
  let built;
  try {
    built = projectFiles(got.json, { ...regs, [reg.role]: reg });
  } catch (e) {
    if (e instanceof C.CaseError) return { ok: false, code: e.code };
    throw e;
  }
  // A replay of a registration the case already projects, with nothing else
  // to add, writes nothing (IDEMPOTENT REPLAY, above).
  if (built.added.length === 0) return { ok: true, case: got.json, added: [] };
  let written = built.next;
  let added = built.added;
  let put;
  try {
    put = await store.putFile(cpath, written, `case ${reg.case_id.slice(0, 16)}: commitment ${reg.role} registered`, got.sha, {
      // Another writer moved the case (most often the other role's
      // registration). Read both files again and rebuild on top of theirs.
      // If the case already projects every file, or can no longer take
      // them, write nothing and let the re-read below decide.
      rebuild: async (fresh) => {
        if (!fresh || !C.validateCase(fresh.json).ok || fresh.json.case_id !== reg.case_id) return null;
        if (!C.REGISTERABLE_STATUSES.includes(fresh.json.status)) return null;
        const again = await readRegistrations(fresh.json, { keyDocument });
        if (!again.ok) return null;
        const mine = again.regs[reg.role];
        if (!mine || !C.sameEntry(C.commitmentEntry(mine), C.commitmentEntry(reg))) return null;
        let rebuilt;
        try {
          rebuilt = projectFiles(fresh.json, again.regs);
        } catch {
          return null;
        }
        if (rebuilt.added.length === 0) return null;
        written = rebuilt.next;
        added = rebuilt.added;
        return written;
      },
    });
  } catch (e) {
    console.error(`[case] commit: case update failed (${e && e.message})`);
    return { ok: false, code: "store_error" };
  }
  if (put && put.abandoned) {
    let again;
    try {
      again = await store.getFile(cpath);
    } catch {
      return { ok: false, code: "store_error" };
    }
    if (again && C.validateCase(again.json).ok) {
      // WITHDRAWN IS A TYPED ANSWER (item 2a; item 1b's finding 5). The
      // redacted record has no `commitments`, so reading one off it threw a
      // TypeError here, which surfaced as a 500. A case withdrawn while this
      // registration was being projected is a state this service can name.
      if (again.json.status === "WITHDRAWN") return { ok: false, code: "case_withdrawn" };
      if (C.sameEntry(again.json.commitments[reg.role], C.commitmentEntry(reg))) {
        return { ok: true, case: again.json, added: [] };
      }
    }
    return { ok: false, code: "case_moved" };
  }
  return { ok: true, case: written, added };
}

// The stamp a commitment rests on, read through the stamp read path (the
// stamps repository only) and judged: present, a readable file-stamp of this
// hash, of a commitment's size (THE STAMP'S SIZE), and, when `history` is
// asked for, held by exactly one public commit (STAMP_COMMIT). `nothing`
// ends every refusal: what this request did not do. At registration a
// refusal says how to recover (a new commitment); at the reveal (`reveal`)
// it does not, because a role that is registered cannot register again.
// -> {ok:true, record, commit} (commit only with `history`),
//    {ok:false, missing:true} (no stamp for this hash), or {ok:false, refusal}.
async function readStamp(sha, { history = false, nothing = "nothing was registered", reveal = false } = {}) {
  const advice = reveal ? "" : "Draw a new salt, compute a new commitment, stamp it with size " +
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
        `so it is not a stamp of a commitment. ${reveal ? "" : "A hash is stamped once, so this one cannot be re-stamped. "}` +
        `${advice}${sentence(nothing)}`,
      { commitment_sha256: sha, stamped_size: Number.isSafeInteger(stampedSize) ? stampedSize : null, expected_size: C.COMMITMENT_BYTES_LENGTH }) };
  }
  if (!history) return { ok: true, record: sg.json };
  let commits;
  try {
    commits = await stampStore.listCommits(spath, { perPage: 2 });
  } catch (e) {
    const unreadable = !!e && (e.code === "listing_unreadable" || e.code === "commits_unreadable");
    console.error(`[case] stamp history read failed (${e && e.message})`);
    return { ok: false, refusal: unreadable
      ? new Refusal(503, "stamp_history_unreadable", `the stamp's commit history was answered but cannot be read as a list of commits; ${nothing}`, { reason: e.code })
      : new Refusal(503, "stamp_history_unreachable", `the stamp's commit history could not be read; this is not a 'no', and ${nothing}`) };
  }
  if (commits.length === 0) {
    return { ok: false, refusal: new Refusal(503, "stamp_history_unreadable",
      `the stamp record for this hash is present, but no commit in its history touches it, so there is no public commit to name; ${nothing}`,
      { reason: "no_commit_touches_path" }) };
  }
  if (commits.length > 1) {
    return { ok: false, refusal: new Refusal(409, "stamp_history_ambiguous",
      "more than one commit touches the stamp record for this hash. A stamp is written once, so this service cannot say which public " +
        `commit holds this one, and it will not choose. ${advice}${sentence(nothing)}`,
      { commitment_sha256: sha, commits: commits.map((c) => c.sha) }) };
  }
  return { ok: true, record: sg.json, commit: commits[0].sha };
}

// "nothing was registered" -> "Nothing was registered."
function sentence(s) {
  return `${s[0].toUpperCase()}${s.slice(1)}.`;
}

async function handleCaseCommit(req, res, opts = {}) {
  const admitted = await admit(req, res, "commit");
  if (!admitted) return;
  const nowMs = clock(opts);
  // the deployment's: the case signer and its key document, for a repair note (unit R-L, L3)
  const env = opts.env || process.env;
  const keyDocument = opts.keyDocument;

  let asked;
  try {
    asked = C.validateRegistrationBody(admitted.body);
  } catch (e) {
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    throw e;
  }
  const { case_id, role, commitment_sha256, key_id } = asked;
  const other = role === "a" ? "b" : "a";
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
  if (!C.REGISTERABLE_STATUSES.includes(kase.status)) {
    return refuse(res, new Refusal(409, "case_not_open", `the case is ${kase.status}; a commitment is registered only while it is OPEN or COMMITTED`,
      { case_id, status: kase.status }));
  }

  // 2. Both registration files: the authority the case object projects.
  // A condemned file is not one (unit R-L3, rule 2).
  const read = await readRegistrations(kase, { keyDocument });
  if (!read.ok && read.why === "unreachable") {
    return refuse(res, new Refusal(503, "store_unreachable", "a registration record could not be read; this is not a 'no'"));
  }
  if (!read.ok && read.why === "could_not_look") {
    return refuse(res, new Refusal(503, "could_not_look", `${standingUnread(read)}, and nothing was registered`, { case_id, role: read.role, reason: read.reason }));
  }
  if (!read.ok) {
    return refuse(res, new Refusal(503, "registration_record_unreadable",
      `the stored registration for role ${read.role} is present but cannot be read as a valid record; nothing was registered`, { reason: read.reason, role: read.role }));
  }
  const regs = read.regs;
  for (const r of C.ROLES) {
    const entry = kase.commitments[r];
    if (entry !== null && !(regs[r] && C.sameEntry(entry, C.commitmentEntry(regs[r])))) {
      return refuse(res, new Refusal(503, "case_record_inconsistent",
        `the case object shows a registration for role ${r} that its registration record does not; nothing was registered`, { role: r }));
    }
  }

  // 3. First write wins per (case_id, role). The file is the authority (step
  // 2 proved any case entry is its file's), so only a DIFFERENT hash, or the
  // same hash under another key, is a second registration. The same hash
  // under the same key again is a replay (IDEMPOTENT REPLAY).
  if (regs[role] && (regs[role].commitment_sha256 !== commitment_sha256 || regs[role].key_id !== key_id)) {
    return refuse(res, new Refusal(409, "role_already_committed",
      `role ${role} already has a registered commitment; only the first registration counts`, { case_id, role, registered: C.commitmentEntry(regs[role]) }));
  }
  // 4. One hash cannot hold both roles: its preimage names one role.
  const theirs = regs[other] || kase.commitments[other];
  if (theirs && theirs.commitment_sha256 === commitment_sha256) {
    return refuse(res, new Refusal(409, "commitment_registered_to_other_role",
      `this commitment is already registered to role ${other} of this case; a commitment's preimage names exactly one role`, { case_id, role, other_role: other }));
  }
  // 4b. ONE KEY PER ROLE: a new registration's key id is not the key id the
  // other role registered with. (A completion or replay of a file that
  // already stands is not refused here: the file is the authority, and a case
  // that projects one key id twice is single party, never sealed.)
  if (!regs[role] && theirs && theirs.key_id === key_id) {
    return refuse(res, new Refusal(409, "same_key_both_roles",
      `role ${other} of this case is registered under key ${key_id}, and the two roles of a case are registered by two distinct keys; ` +
        "nothing was registered", { case_id, role, other_role: other, key_id }));
  }

  // 4c. THE CONDEMNED FILE, REMOVED (unit R-L3, rule 1): a file at this
  // role's path under a standing, verified repair note is not a
  // registration. Under the case lock its recorded removal is completed (the
  // note stands: no second note), and the registration is then written
  // afresh below, a new write, with every check, the deadline included. A
  // removal that cannot be completed changes nothing.
  let removedEarlier = false;
  if (read.condemned[role]) {
    const lease = leaseClock(opts);
    const lock = await acquireCaseLock(case_id, "commit", lease);
    if (!lock.ok) return refuse(res, lockRefusal(lock, "nothing was changed"));
    try {
      const status = await caseStatus(cpath);
      if (!C.REGISTERABLE_STATUSES.includes(status)) {
        return refuse(res, new Refusal(409, "case_not_open",
          `the case read again under the lock is ${status || "unreadable"}; a commitment is registered only while it is OPEN or COMMITTED, and nothing was changed`,
          { case_id, status }));
      }
      const noted = read.condemned[role];
      try {
        await UNREG.removeRegistrationAfterWithdrawal(C.registrationPath(case_id, role), noted.blob,
          `case ${case_id.slice(0, 16)}: commitment ${role} removed (${noted.note.reason}); repair note ${noted.note_path}`,
          { createdInCommit: noted.created, keyDocument });
      } catch (e) {
        console.error(`[case] commit: the recorded removal of role ${role}'s file was not completed (${e && e.message})`);
        return refuse(res, new Refusal(503, "removal_incomplete",
          `role ${role}'s registration file is under a repair note (a removal of it was recorded), and that removal could not be completed now; ` +
            "nothing was changed. Send the same registration again", { case_id, role, repair_note: noted.note_path }));
      }
      removedEarlier = true;
    } finally {
      await releaseCaseLock(case_id, lock, lease);
    }
  }

  let registration = regs[role]; // non-null only when completing or replaying an earlier registration
  let created = false;
  if (registration) {
    // 6r. THE RETRY RECHECKS THE STAMP (item 2a; item 1b's finding 7): a
    // completion or a replay projects nothing until the stamp record passes
    // steps 6 and 6b again, size included. The deadline is not rechecked:
    // the registration itself was received before it.
    const sc = await readStamp(commitment_sha256, { nothing: "nothing was projected" });
    if (!sc.ok && sc.missing) {
      return refuse(res, new Refusal(503, "stamp_record_unreadable",
        "the stamp this registration rests on is no longer in the stamp record, and a stamp is never removed; nothing was projected",
        { reason: "stamp_missing" }));
    }
    if (!sc.ok) return refuse(res, sc.refusal);
  } else {
    // 5. Before the deadline.
    if (C.pastDeadline(kase, nowMs)) {
      return refuse(res, new Refusal(409, "late_commitment", removedEarlier
        ? "the earlier registration was removed under a repair note and the deadline has passed; no commitment can be registered to it now"
        : "the case's deadline has passed; no commitment can be registered to it now",
      { case_id, deadline: kase.deadline }));
    }

    // 6. The stamp, read through the stamp read path. Never a caller's copy.
    // 6b. Its size is a commitment's (THE STAMP'S SIZE, above).
    // 6c. Exactly one public commit holds it (STAMP_COMMIT, above).
    const sc = await readStamp(commitment_sha256, { history: true });
    if (!sc.ok && sc.missing) {
      return refuse(res, new Refusal(404, "no_commitment",
        "no stamp is recorded for this commitment hash. Stamp it first (POST /api/stamp), then register it",
        { commitment_sha256 }));
    }
    if (!sc.ok) return refuse(res, sc.refusal);

    // 7. The registration record, create-only.
    const record = C.registrationRecord({
      case_id,
      role,
      commitment_sha256,
      registered_at: C.utcSeconds(nowMs),
      stamp_commit: sc.commit,
      stamped_at: sc.record.stamped_at,
      key_id,
      verifier: asked.verifier,
      sig: asked.sig,
    });
    const rpath = C.registrationPath(case_id, role);
    // 7a. THE CASE LOCK (red-team fix C): the write, and a read of the case
    // before it and after it, under the lock the withdrawal takes too.
    const lease = leaseClock(opts);
    const lock = await acquireCaseLock(case_id, "commit", lease);
    if (!lock.ok) return refuse(res, lockRefusal(lock, "nothing was registered"));
    let put;
    try {
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
          { case_id, role, registration_recorded: false, received_at: record.registered_at }));
      }
      try {
        put = await store.putFile(rpath, record, `case ${case_id.slice(0, 16)}: commitment ${role}`, undefined, {
          // Another registration for this role landed between our read and our
          // write. It is earlier; it stands.
          rebuild: () => null,
        });
      } catch (e) {
        if (e && e.conflict) put = { abandoned: true };
        else {
          console.error(`[case] commit: registration write failed (${e && e.message})`);
          return refuse(res, new Refusal(503, "store_error", "could not record the registration; nothing was registered"));
        }
      }
      // 7b. After the write, under the same lock: a withdrawal that landed
      // meanwhile (the lease ran out and was taken over) means this
      // registration must not stand. A REGISTRATION NEVER STANDS ON AN
      // ASSUMPTION (unit R-N, C2): a case that cannot be read here cannot
      // show it was not withdrawn, so the registration is unwound too.
      if (!(put && put.abandoned)) {
        const after = await caseRead(cpath);
        if (!after) {
          const unwound = await unwindRegistration({ caseId: case_id, role, put, why: "registration_unconfirmed", at: record.registered_at, env, keyDocument });
          // unit R-L3 (rule 3): with a note written, what is true is that a
          // removal was recorded, and that the same registration sent again
          // is written fresh (rule 1)
          return refuse(res, new Refusal(503, "registration_unconfirmed", unwound.note_path ? UNCONFIRMED_NOTED
            : "the case record could not be read after the registration's write, so this service cannot show the case was not withdrawn " +
              "meanwhile, and a registration never stands on an assumption: no repair note could be written and confirmed, so nothing was " +
              "removed: the file may be there, and it stands only once a read of the case confirms it. Send the same registration again",
            { case_id, role, registration_recorded: unwound.recorded, registration_removed: unwound.removed, repair_note: unwound.note_path,
              received_at: record.registered_at }));
        }
        if (after.status === "WITHDRAWN") {
          const unwound = await unwindRegistration({ caseId: case_id, role, put, why: "registration_after_withdrawal", at: record.registered_at, env, keyDocument });
          return refuse(res, new Refusal(409, "case_withdrawn",
            "the case was withdrawn while this registration was being written, so the registration does not stand: " +
              unwoundWords(unwound, "registration_after_withdrawal", {
                noted: "the file is still there, standing for no reader, and the operator's sealer run completes the recorded removal",
                unnoted: "the file is still there, standing for no reader, and the operator's sealer run completes its removal",
              }),
            { case_id, role, registration_recorded: unwound.recorded, received_at: record.registered_at, registration_removed: unwound.removed,
              repair_note: unwound.note_path }));
        }
      }
    } finally {
      await releaseCaseLock(case_id, lock, lease);
    }
    if (put && put.abandoned) {
      let won;
      try {
        won = await store.getFile(rpath);
      } catch {
        won = undefined;
      }
      const wv = won ? judgeRegistration(won, rpath, kase, role) : null;
      // unit R-N2 (m10): registration_recorded is this registration's real
      // state: not on file when another is, unknown (null) when the read failed
      if (!wv || !wv.ok) {
        return refuse(res, new Refusal(503, "store_error", "a registration for this role landed first and could not be read back",
          { case_id, role, registration_recorded: won === null ? false : null }));
      }
      if (won.json.commitment_sha256 !== commitment_sha256 || won.json.key_id !== key_id) {
        return refuse(res, new Refusal(409, "role_already_committed",
          `role ${role} already has a registered commitment; only the first registration counts`,
          { case_id, role, registered: C.commitmentEntry(won.json), registration_recorded: false }));
      }
      registration = won.json;
    } else {
      registration = record;
      created = true;
    }
  }

  // 8. Project into the case object: from BOTH registration files, so a
  // registration the other role recorded earlier is projected too.
  const upd = await project(cpath, got, registration, regs, { keyDocument });
  if (!upd.ok && upd.code === "case_withdrawn") {
    return refuse(res, new Refusal(409, "case_withdrawn",
      "the case was withdrawn while this registration was being projected. A registration file written before the withdrawal stays in " +
        "the public record, and a registration under a withdrawn case does not stand: no reader counts it",
      { case_id, role, registration_recorded: await registrationOnFile(case_id, role, registration), registration }));
  }
  if (!upd.ok) {
    return refuse(res, new Refusal(503, "case_update_failed",
      "the registration is recorded (first write wins), but the case object was not brought up to date. " +
        "Send the same registration again to complete it.",
      { case_id, role, registration_recorded: await registrationOnFile(case_id, role, registration), registration, reason: upd.code }));
  }
  const v = judgeCase({ json: upd.case }, cpath, case_id);
  // a fresh write after a condemned file's removal answers 200 (unit R-L3):
  // the same registration, sent again, is now on file
  return res.status(created && !removedEarlier ? 201 : 200).json(verdict.success(v, {
    case_id,
    role,
    existing: !created,
    ...(removedEarlier ? { earlier_removed: true } : {}),
    registration,
    projected: upd.added,
    status: upd.case.status,
    case: upd.case,
  }, "case-commit"));
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
// the commitment of that role's registration file, and the file must have
// been written before the withdrawal (lib/_case_seal.js
// registrationAgainstWithdrawal: one under a withdrawn case written after it
// does not stand). Anything else is 404 not_a_party, with no receipt. The
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
  const w = await SEAL.withdrawalCommitOf(caseId);
  if (!w.ok) {
    return new Refusal(503, "store_unreachable", `the withdrawal's commit could not be read (${w.reason}); this is not a 'no', and ${nothing}`, { case_id: caseId });
  }
  const g = await SEAL.registrationAgainstWithdrawal(caseId, own.role, w);
  if (g.absent) return notParty();
  if (!g.ok) {
    return new Refusal(503, "store_unreachable", `role ${own.role}'s registration could not be read against the withdrawal (${g.reason}); ` +
      `this is not a 'no', and ${nothing}`, { case_id: caseId });
  }
  const reg = g.json;
  if (!C.validateRegistrationRecord(reg).ok || reg.case_id !== caseId || reg.role !== own.role || !g.before) return notParty();
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

// THE TWO-PHASE REVEAL: a case that moved under the reveal, refused by what
// it now is.
async function movedRefusal(cpath, caseId, nothing) {
  const now = await caseRead(cpath);
  const status = now ? now.status : null;
  if (status === "WITHDRAWN") {
    return new Refusal(409, "case_withdrawn", `the case was withdrawn while this reveal ran; ${nothing}`, { case_id: caseId, status });
  }
  if (status === "VERDICT") {
    return new Refusal(409, "not_committed",
      `another request sealed this case while this one ran, and a case has one joint reveal; ${nothing}`, { case_id: caseId, status });
  }
  return new Refusal(503, "case_seal_failed", `the case moved while this reveal ran and was not sealed by it; ${nothing}`, { case_id: caseId, reason: "case_moved" });
}

// THE TWO-PHASE REVEAL: the failure appended after the attempt (unit R-N,
// E1), over the attempt as written. -> true when it landed. Never throws.
async function recordRevealFailure(cpath, attempted, attemptSha, failure) {
  try {
    const failedCase = { ...attempted, reveal_attempts: [...attempted.reveal_attempts, { event: "failure", reason: failure.reason, at: failure.at }] };
    const put = await store.putFile(cpath, failedCase, `case ${attempted.case_id.slice(0, 16)}: reveal failed (${failure.reason})`,
      attemptSha, { rebuild: () => null });
    return !(put && put.abandoned);
  } catch (e) {
    console.error(`[case] reveal: the failure could not be recorded (${e && e.message})`);
    return false;
  }
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
  // One clock read, the service's: the reveal time, the receipt's compared_at
  // and every time the seal records.
  const nowMs = clock(opts);
  const revealedAt = C.utcSeconds(nowMs);
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
  if (kase.status === "WITHDRAWN") return refuse(res, await withdrawnRefusal(case_id, caseFields, revealedAt, env, opts));
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

  // 2. The registration files are the authority (design decision 4), and the
  // case object must agree with them, role by role. A condemned file is not
  // one (unit R-L3, rule 2): the case is not committed while it is a role's
  // only file, whatever the case object projected.
  const read = await readRegistrations(kase, { keyDocument: opts.keyDocument });
  if (!read.ok && read.why === "unreachable") {
    return refuse(res, new Refusal(503, "store_unreachable", "a registration record could not be read; this is not a 'no'"));
  }
  if (!read.ok && read.why === "could_not_look") {
    return refuse(res, new Refusal(503, "could_not_look", `${standingUnread(read)}, and nothing was compared`, { case_id, role: read.role, reason: read.reason }));
  }
  for (const r of C.ROLES) {
    if (read.ok && read.condemned[r]) {
      return refuse(res, new Refusal(409, "not_committed",
        `role ${r}'s registration file is under a repair note (a removal of it was recorded), so it does not stand and the case is not ` +
          "committed; nothing was compared", { case_id, role: r, repair_note: read.condemned[r].note_path }));
    }
  }
  if (!read.ok) {
    return refuse(res, new Refusal(503, "registration_record_unreadable",
      `the stored registration for role ${read.role} is present but cannot be read as a valid record; nothing was compared`, { reason: read.reason, role: read.role }));
  }
  const regs = read.regs;
  for (const r of C.ROLES) {
    if (!regs[r] || !C.sameEntry(kase.commitments[r], C.commitmentEntry(regs[r]))) {
      return refuse(res, new Refusal(503, "case_record_inconsistent",
        `the case object's registration for role ${r} is not its registration file's; nothing was compared`, { case_id, role: r }));
    }
  }
  // 2s. ONE KEY PER ROLE: one key id registered both roles. Such a case is a
  // single party and never reaches sealed.
  if (C.singleParty(kase)) {
    return refuse(res, new Refusal(409, "single_party",
      `both roles of this case are registered under one key, ${kase.commitments.a.key_id}, and the two roles of a case are registered ` +
        "by two distinct keys; a single-party case is never sealed. Nothing was compared", { case_id, key_id: kase.commitments.a.key_id }));
  }
  // 2a. A registration that names no public stamp commit cannot reveal
  // (item 2b): the claim names a public dated commit.
  for (const r of C.ROLES) {
    if (regs[r].stamp_commit === null) {
      return refuse(res, new Refusal(409, "commitment_history_missing",
        `role ${r}'s registration names no public stamp commit (stamp_commit is null), so this service cannot show which public ` +
          "commit holds the commitment it rests on; a case with such a registration cannot reveal. Nothing was compared",
        { case_id, role: r }));
    }
  }
  // 2b. Each registration still rests on its stamp, as registered: the same
  // stamp rules as at registration, and the same stamped_at and commit.
  for (const r of C.ROLES) {
    const sc = await readStamp(regs[r].commitment_sha256, { history: true, nothing: "nothing was compared", reveal: true });
    if (!sc.ok && sc.missing) {
      return refuse(res, new Refusal(503, "stamp_record_unreadable",
        `the stamp role ${r}'s registration rests on is no longer in the stamp record, and a stamp is never removed; nothing was compared`,
        { reason: "stamp_missing", role: r }));
    }
    if (!sc.ok) return refuse(res, new Refusal(sc.refusal.status, sc.refusal.code, sc.refusal.message, { ...sc.refusal.extra, role: r }));
    if (sc.record.stamped_at !== regs[r].stamped_at || sc.commit !== regs[r].stamp_commit) {
      return refuse(res, new Refusal(503, "case_record_inconsistent",
        `the stamp role ${r}'s registration rests on no longer reads as it did when it was registered; nothing was compared`,
        { case_id, role: r, reason: "stamp_differs_from_registration" }));
    }
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
  // before the attempt, so nothing is written and nothing compared.
  const confirmed = await SEAL.confirmSealingDocument(sealing, env);
  if (!confirmed.ok) {
    console.error(`[case] reveal: the key document at the deployment's commit does not confirm the bundled one (${confirmed.reason})`);
    return refuse(res, new Refusal(503, "document_unavailable",
      "the key document at the commit this deployment names is not, or could not be read as, the one it carries, so it seals nothing; " +
        "nothing was compared", { case_id, reason: confirmed.reason }));
  }

  // 5c. The reconcile signer, read before anything is written: a reveal
  // that cannot compare records no attempt (red-team fix B's refusal, made
  // here before the attempt rather than inside the comparison).
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

  // 5d. THE TWO-PHASE REVEAL (red-team fix E; lib/_case.js): the attempt,
  // appended to reveal_attempts in the COMMITTED case BEFORE the comparison
  // runs, over the case as read (CAS). A case that moved meanwhile is refused
  // by what it now is, and nothing is compared. APPEND-ONLY (unit R-N, E1):
  // every earlier attempt and failure stays, and the seal is built from the
  // case with them, so the sealed record carries them in its signed bytes.
  const attempted = {
    ...kase,
    reveal_attempts: [...(Array.isArray(kase.reveal_attempts) ? kase.reveal_attempts : []), {
      event: "attempt",
      commitments: { a: regs.a.commitment_sha256, b: regs.b.commitment_sha256 },
      input_sha256: C.revealInputSha256({ case_id, policy_version: kase.policy_version, tape_sha256: { a: asked.reveals.a.tape_sha256, b: asked.reveals.b.tape_sha256 } }),
      at: revealedAt,
    }],
  };
  let attemptPut;
  try {
    attemptPut = await store.putFile(cpath, attempted, `case ${case_id.slice(0, 16)}: reveal attempt`, got.sha, { rebuild: () => null });
  } catch (e) {
    if (e && e.conflict) attemptPut = { abandoned: true };
    else {
      console.error(`[case] reveal: the attempt could not be written (${e && e.message})`);
      return refuse(res, new Refusal(503, "reveal_attempt_unwritten",
        "the reveal's attempt could not be recorded in the case before the comparison, so nothing was compared and nothing was sealed", { case_id }));
    }
  }
  if (attemptPut && attemptPut.abandoned) {
    const moved = await movedRefusal(cpath, case_id, "nothing was compared");
    // THE LEASE RACE, IN TRUE WORDS (unit R-N, N4; the words since unit
    // R-N2, m4): the tapes were decoded and hashed (steps 1d to 4) before
    // the withdrawal landed. Nothing of them is written, and no receipt is
    // issued here: a party asks again, naming its role, and gets one.
    if (moved.code === "case_withdrawn") {
      return refuse(res, new Refusal(409, "case_withdrawn",
        "Refused. A withdrawal landed while this reveal was in progress. Nothing computed from the tapes is kept.",
        { case_id, status: "WITHDRAWN" }));
    }
    return refuse(res, moved);
  }
  let attemptSha = attemptPut && attemptPut.content && attemptPut.content.sha;
  if (typeof attemptSha !== "string") {
    const reread = await store.getFile(cpath).catch(() => null);
    attemptSha = reread ? reread.sha : undefined;
  }
  // A failure after the attempt is appended after it, over the attempt as
  // written; the answer says whether that write landed.
  const failed = (reason) => recordRevealFailure(cpath, attempted, attemptSha, { reason, at: revealedAt });

  // 6. The comparison: ?op=reconcile's own call, once. Role a's tape is
  // reconcile's first argument, tape_a in its answer and in the receipt.
  let compared;
  try {
    compared = RECONCILE.compare(tapes.a, tapes.b, { env, now: nowMs, keyDocument: sealing.doc });
  } catch (e) {
    if (!e || (!e.portError && !e.signerUnavailable)) throw e;
    console.error(`[case] reveal: the comparison failed (${e.causeName || e.reason})`);
    const recorded = await failed("comparison_failed");
    return refuse(res, new Refusal(500, "internal_error", "the comparison failed inside this service; no verdict was reached and nothing was sealed",
      { reveal_failure_recorded: recorded }));
  }

  // 7. The receipt, checked deeply before anything is sealed (lib/_case_seal.js).
  const rc = SEAL.checkReceipt(compared.receipt, {
    kase: attempted,
    tapeSha256: { a: asked.reveals.a.tape_sha256, b: asked.reveals.b.tape_sha256 },
    tapeBytes: { a: tapes.a.length, b: tapes.b.length },
    result: compared.result,
    revealedAt,
    signer: rsigner,
  });
  if (!rc.ok) {
    console.error(`[case] reveal: receipt check failed (${rc.reason})`);
    const recorded = await failed("receipt_check_failed");
    return refuse(res, new Refusal(500, "internal_error",
      "the receipt this service built for the comparison failed its own check; nothing was sealed", { reason: rc.reason, reveal_failure_recorded: recorded }));
  }
  const st = SEAL.storableReceipt(compared.receipt);
  if (!st.ok && st.reason === "integer_beyond_json") {
    const recorded = await failed("verdict_not_sealable");
    return refuse(res, new Refusal(422, "verdict_not_sealable",
      "the verdict names a call index larger than 2^53 - 1, which a JSON case record cannot hold without changing the receipt's " +
        "signed bytes; nothing was sealed", { case_id, reveal_failure_recorded: recorded }));
  }
  if (!st.ok) {
    console.error(`[case] reveal: receipt not storable (${st.reason})`);
    const recorded = await failed("receipt_check_failed");
    return refuse(res, new Refusal(500, "internal_error", "the receipt could not be held in a case record; nothing was sealed",
      { reason: st.reason, reveal_failure_recorded: recorded }));
  }

  // 8. The seal: the case file, authoritative (lib/_case_seal.js), signed
  // with the case key read at 5c2.
  const signedUnder = { document_sha256: sealing.document_sha256, document_commit: sealing.document_commit, retrieved_at: revealedAt };
  let sealed;
  try {
    sealed = SEAL.sealCase(attempted, { reveals: asked.reveals, receipt: st.receipt, crossReference: asked.cross_reference, revealedAt, signedUnder }, csigner);
  } catch (e) {
    if (!(e instanceof C.CaseError)) throw e;
    console.error(`[case] reveal: built an invalid sealed case (${e.code} at ${e.field})`);
    const recorded = await failed("seal_build_failed");
    return refuse(res, new Refusal(500, "internal_error", "this service built a sealed case its own schema refuses; nothing was sealed",
      { reveal_failure_recorded: recorded }));
  }
  const chain = SEAL.caseChain(sealed);
  let put;
  try {
    // over the attempt as written (CAS): the second of the reveal's two phases
    put = await store.putFile(cpath, sealed, `case ${case_id.slice(0, 16)}: sealed, ${sealed.verdict.verdict.verdict}`, attemptSha, {
      // The case moved since the attempt was written (another reveal sealed
      // it, or it was withdrawn). Whatever it is now stands; the re-read below
      // says what.
      rebuild: () => null,
    });
  } catch (e) {
    if (e && e.conflict) put = { abandoned: true };
    else {
      console.error(`[case] reveal: case write failed (${e && e.message})`);
      const recorded = await failed("case_seal_failed");
      return refuse(res, new Refusal(503, "case_seal_failed",
        "the comparison ran, but the sealed case could not be written; nothing was sealed and nothing was anchored. The case is still " +
          "COMMITTED, and it records this reveal's attempt and its failure",
        { case_id, reveal_failure_recorded: recorded }));
    }
  }
  if (put && put.abandoned) return refuse(res, await movedRefusal(cpath, case_id, "nothing was sealed"));

  // 9. The pin, recording the commit the case file's write answered with. A
  // pin that fails leaves the case sealed and reports pin:
  // "commit_unrecorded", computed, never stored.
  const caseCommit = SEAL.commitOfPut(put);
  const pin = await SEAL.pinChain(case_id, chain, nowMs, caseCommit);
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

// Both registration files, the authority, and the case object's agreement
// with them (the commit and reveal paths' own check). -> {regs} or {refusal}.
async function readAuthority(kase, nothing, { keyDocument } = {}) {
  const read = await readRegistrations(kase, { keyDocument });
  if (!read.ok && read.why === "unreachable") {
    return { refusal: new Refusal(503, "store_unreachable", withTail("a registration record could not be read; this is not a 'no'", nothing, ", and ")) };
  }
  if (!read.ok && read.why === "could_not_look") {
    return { refusal: new Refusal(503, "could_not_look", withTail(standingUnread(read), nothing, ", and "), { role: read.role, reason: read.reason }) };
  }
  if (!read.ok) {
    return { refusal: new Refusal(503, "registration_record_unreadable",
      withTail(`the stored registration for role ${read.role} is present but cannot be read as a valid record`, nothing), { reason: read.reason, role: read.role }) };
  }
  for (const r of C.ROLES) {
    const entry = kase.commitments[r];
    if (entry !== null && !(read.regs[r] && C.sameEntry(entry, C.commitmentEntry(read.regs[r])))) {
      return { refusal: new Refusal(503, "case_record_inconsistent",
        withTail(`the case object shows a registration for role ${r} that its registration record does not`, nothing), { role: r }) };
    }
  }
  return { regs: read.regs };
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

  // 2. The registration files are the authority.
  const auth = await readAuthority(kase, nothing, { keyDocument: opts.keyDocument });
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
        if (!C.REGISTERABLE_STATUSES.includes(fresh.json.status) || C.pastDeadline(fresh.json, nowMs) || Array.isArray(fresh.json.reveal_attempts)) return null;
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
// The 503 after a failed after-read, once a repair note stands (unit R-L3, rule 3).
const UNCONFIRMED_NOTED = "The registration was written and could not be confirmed, so a removal of it was recorded. Send the same registration " +
  "again; it will be written fresh.";
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
// the record keeps the sha256 of and its preimage recomputes that role's
// registration file. Then the marker is written again, create-only, and the
// answer is the record as it stands.
// -> the answer body, {refusal} (the registration read failed), or null
// (not that withdrawer: the caller refuses as before).
async function retriedWithdrawal(kase, asked) {
  const w = kase.withdrawal;
  if (asked.role !== w.by_role || C.saltSha256(asked.salt) !== w.salt_sha256) return null;
  let reg;
  try {
    reg = await store.getFile(C.registrationPath(kase.case_id, asked.role));
  } catch {
    // a read that failed is not an answer (follow-up f4 to unit R-N4)
    return { refusal: new Refusal(503, "store_unreachable",
      "The case is withdrawn. This request could not finish checking it. Send the same withdrawal again.", { case_id: kase.case_id }) };
  }
  if (!reg || !C.validateRegistrationRecord(reg.json).ok || reg.json.case_id !== kase.case_id || reg.json.role !== asked.role) return null;
  if (!proves(kase.case_id, { [asked.role]: reg.json }, asked)) return null;
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
  // THE TWO-PHASE REVEAL (red-team fix E): a joint reveal was attempted, its
  // comparison input is recorded in the case, and a withdrawal would erase
  // that trace. The parties send the same reveal again to seal it.
  if (Array.isArray(kase.reveal_attempts)) {
    // a list with no attempt event (never valid, never written) still refuses,
    // with no attempt time (follow-up f6 to unit R-N4)
    const last = kase.reveal_attempts.filter((e) => e.event === "attempt").pop();
    return new Refusal(409, "reveal_attempted",
      "a joint reveal of this case was attempted (the case records the attempt), and a case whose comparison was attempted is not withdrawn " +
        `by one role. ${tail}`, { case_id: caseId, status: kase.status, reveal_attempt_at: last ? last.at : null });
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
  signer_revoked: "a key that signed it is revoked in the current key document, and the case file is not shown written before the revocation was recorded in the pins repository",
});

// A pin that could not be read refuses nothing (unit R-J3, F4 and F5): 503
// could_not_look, which is not a refusal of the row. A pin whose commit
// history is longer than this service reads is not a read to retry (unit
// R-L, g5): no "Try again".
function pinCouldNotLook(case_id, reason, nothing) {
  const text = reason === "pin_commits_beyond_bound"
    ? `could not look; this is not a refusal of the row. The case's pin reads could_not_look on this request (${reason}): the pin's commit ` +
      `history is longer than this service reads, and ${nothing}`
    : `could not look; this is not a refusal of the row. Try again. The case's pin reads could_not_look on this request (${reason}), and ${nothing}`;
  return new Refusal(503, "could_not_look", text, { case_id, status: "VERDICT", state: "could_not_look", reason });
}

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
  // valid_under_document or signer_since_revoked. Anything else takes no row.
  const keyDocument = opts.keyDocument === undefined ? SEAL.PUBLISHED_KEYS : opts.keyDocument;
  const answer = await SEAL.sealedRecordReason(kase, keyDocument);
  // under a revoked key, a pin that could not be read (unit R-J3, F4)
  if (answer.code === "pin_unavailable") return refuse(res, pinCouldNotLook(case_id, answer.reason, nothing));
  const unsealed = SEAL.sealHolds(answer) ? null : answer;
  if (unsealed) {
    console.error(`[case] reference: the stored VERDICT does not verify (${unsealed.code}: ${unsealed.reason})`);
    return refuse(res, new Refusal(409, unsealed.code,
      `the case reads VERDICT, but its sealed record does not verify (${unsealed.reason}): ${UNSEALED_WORDS[unsealed.code] || unsealed.code}, ` +
        `so it is not treated as a sealed case; ${nothing}`,
      { case_id, status: "VERDICT", reason: unsealed.reason }));
  }

  // 1c. FIX D (GPT-5.6 §1.2: "A reference may be appended before the case
  // anchor exists"). A row is appended only to a case that is pinned or
  // anchored (Design J's words, lib/_case_seal.js THE ANCHOR WORDS). Any
  // other state read (commit_unrecorded, pin_commit_mismatch, conflict,
  // unreadable) is 409 case_not_pinned with the state and its reason (its
  // name since unit R-J, J8: the check is for a pin). A pin that could not
  // be read is 503 could_not_look, not a refusal of the row (unit R-J3, F5).
  //   THE ANCHOR-CONFLICT CHECK (unit R-N, D1): the daily anchor records are
  // read too (anchorState with the anchor lookup): a daily anchor record
  // whose head conflicts with the pin (another chain, no JSON, or off the
  // branch: unit R-J, J5 and J6) is 409 anchor_conflict. A row is refused
  // only on that proven conflict (unit R-L2, M4): an anchor lookup that
  // could not look, a head not shown and a changed record refuse no row,
  // since the row's signed sentence asserts no anchoring; the case page says
  // the anchor state as read. A pin no anchor record holds yet takes a row.
  // The case read is the case served, held to the bytes at its case_commit
  // (unit R-J, J4).
  const st = await SEAL.anchorState(case_id, kase);
  if (st.pin === "conflict" && st.anchor) {
    // worded by the conflict's reason (unit R-J2, B1)
    return refuse(res, new Refusal(409, "anchor_conflict",
      `the case's pin holds its chain, and ${SEAL.conflictWords(st.reason)} (${st.anchor.path}); ` +
        `a row is not appended to a case whose anchor conflicts; ${nothing}`, { case_id, status: "VERDICT", state: st.pin, reason: st.reason }));
  }
  if (st.pin === "could_not_look") return refuse(res, pinCouldNotLook(case_id, st.reason, nothing));
  if (st.pin !== "pinned" && st.pin !== "anchored") {
    return refuse(res, new Refusal(409, "case_not_pinned",
      `the case is sealed, and its pin reads ${st.pin} (${st.reason}); a reference row is appended only to a case that reads pinned ` +
        `or anchored, so ${nothing}`,
      { case_id, status: "VERDICT", state: st.pin, reason: st.reason }));
  }

  // 2 and 3. A role proves itself against the registration files.
  let appendedBy = "operator";
  if (proof !== null) {
    const auth = await readAuthority(kase, nothing, { keyDocument });
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
  let rowCommit = null;
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
      const put = await store.putFile(p, built, `case ${case_id.slice(0, 16)}: reference ${seq}`, undefined, { rebuild: () => null });
      // THE ROW'S TWO WRITES (Design J; lib/_case_seal.js): the commit this
      // write answered with, named in the answer; a later pin of the case
      // may list it (unit R-J3, F1)
      rowCommit = SEAL.commitOfPut(put);
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
    row_commit: rowCommit,
    // unit R-J2 (B2): no future event stated as fact, as in the row's sentence
    row_commit_note: "row_commit is the commit the pins repository assigned to this row's write (null when that write's answer named " +
      "none). The row cannot name it itself. A later pin of the case may list that commit; the case page says a pin lists it only " +
      "after reading that pin.",
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

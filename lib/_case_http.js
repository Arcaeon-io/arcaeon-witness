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
// keyless ops (commit, reveal, withdraw, reference) stay per-IP. The key read
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
//      and nothing is compared or written;
//   6. the comparison, lib/_reconcile_http.js compare, the very call
//      ?op=reconcile makes, once, role a's tape first; with no reconcile
//      signer it refuses before comparing (red-team fix B, NO SIGNER, NO
//      RECEIPT in lib/_reconcile_receipt.js): 503 `signer_unavailable`,
//      nothing compared, nothing written;
//   7. the receipt, checked deeply (lib/_case_seal.js checkReceipt);
//   8. the seal: the case file, written over the COMMITTED case it read;
//   9. the pin, its anchor (lib/_case_seal.js pinChain).
// Every refusal in 0 to 5 is a typed 4xx with an error_code (a 503 when the
// store cannot be read or does not agree with itself), carries no verdict,
// writes nothing and never runs reconcile. After 6 has run: a receipt that
// fails its own check, or a sealed case the schema refuses, is a 500 with
// nothing written (this service's defect); a verdict a JSON record cannot
// hold is 422 `verdict_not_sealable`; a case write that fails is 503
// `case_seal_failed`, with no pin; a case that moved meanwhile (another
// reveal sealed it, or it was withdrawn) is refused by what it now is. A
// pin that fails after the case file landed is not a failure of the seal:
// the answer is 201 with `pin: "pending"` (TWO WRITES in lib/_case_seal.js),
// and the sealer's next run pins it (lib/_case_seal.js, THE TRIGGER). Every
// success carries `anchor_note`, lib/_case_seal.js ANCHOR_NOTE: a case pin
// is anchored by the pins-repository commit and the daily anchor of the
// repository head, not as a log-tree leaf.
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
// THE WITHDRAWAL (item 2c; lib/_case.js THE WITHDRAWAL). Keyless: A ROLE
// PROVES ITSELF, below. In order: the body (exactly {case_id, role,
// tape_sha256, salt}); the case, refused if VERDICT (`case_sealed`),
// already WITHDRAWN (`case_withdrawn`) or at or past its deadline
// (`expired`, the case reads EXPIRED); both registration files, the
// authority, and the case's agreement with them; the proof (403
// `withdraw_unauthorized`); the redacted record, signed with the case key
// (lib/_case_seal.js withdrawnRecord); the root write, a CAS over the case
// as read; then the marker cases/<case_id>/withdrawn, create-only, so a tree
// listing shows the withdrawal without a fetch. THE CAS DECIDES A RACE: the
// reveal writes the sealed case over the COMMITTED case it read, and the
// withdrawal writes the redacted record over the case it read, each with
// that read's sha. Whichever lands first stands, and the other's write is
// refused by the store: a reveal that loses answers 409 `case_withdrawn`, a
// withdrawal that loses answers 409 `case_sealed`. A registration projected
// meanwhile is no race: the redacted record does not depend on it and is
// written over the fresh case. Registration files are left in place,
// public, and the answer says so in words (registrations_note). A marker
// that fails leaves the withdrawal standing (the root is the authority, and
// the sealer reads it and skips it as terminal); the answer says `marker:
// "failed"`. Nothing of the preimage is kept except salt_sha256, and
// nothing of it is logged.
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
// sign 409 `receipt_unsigned` (red-team fix B), and a case signature the
// named document does not confirm 409 `case_signature_invalid`, each with
// its `reason`, and no row is written. The check runs before the proof is read. Who appends: a
// registered role proving itself (A ROLE PROVES ITSELF), or THE OPERATOR'S
// KEY, below; the row records which in appended_by. The row
// is written create-only at the next seq (the highest listed plus one); a
// row that lands first at that seq is never written over, and this one
// moves to the next (at most three tries). It is signed with the case key
// (lib/_case_seal.js referenceRow), judged by its own judge before it is
// written, and has no pin of its own. The sealed case is never touched.
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
// can append as the operator while it is unset. A role's proof does not
// read the variable at all.
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

// Take one unit of `key`'s day. Counter first, case second: if the case
// write then fails, the counter has over-counted by one, which errs toward
// refusing, never toward unlimited (the stamp budget's rule, lib/_stamp.js).
// A counter that is present and unreadable throws (lib/_verdict.js
// judgeCounter: never read as zero), and so does a store that cannot be
// read or written; the caller answers 503.
// -> {ok:true, used, day} or {ok:false, used, day} (the quota is spent).
async function takeOpenQuota(key, nowMs) {
  const day = C.utcSeconds(nowMs).slice(0, 10);
  const q = quotaStore();
  const path = openQuotaPath(key, day);
  const countOf = (got) => verdict.counterValue(verdict.judgeCounter(got, "count", { what: "case open quota", integer: true }), "case open quota");
  // Two opens creating the day's counter at once: the loser gets the
  // create-race 422 (err.conflict), which putFile does not retry. Re-read and
  // go again, a bounded number of times; past that, the caller refuses.
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const cur = await q.getFile(path);
      const used = countOf(cur);
      if (used >= OPEN_QUOTA_PER_DAY) return { ok: false, used, day };
      let denied = null;
      let counted = used + 1;
      await q.putFile(path, quotaRecord(day, used + 1), `case-open quota ${day}`, cur ? cur.sha : undefined, {
        rebuild: (fresh) => {
          const n = countOf(fresh);
          if (n >= OPEN_QUOTA_PER_DAY) {
            denied = { ok: false, used: n, day };
            return null;
          }
          counted = n + 1;
          return quotaRecord(day, n + 1);
        },
      });
      return denied || { ok: true, used: counted, day };
    } catch (e) {
      if (!(e && e.conflict) || attempt === 3) throw e;
    }
  }
  throw new Error("takeOpenQuota: unreachable");
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
  const n = opts && opts.now !== undefined ? Number(opts.now) : Date.now();
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
      "opening a case requires a bearer key (Authorization: Bearer <your ARCAEON_KEY>); opening costs no credits") };
  }
  if (!k.valid) return { refusal: new Refusal(401, "key_invalid", "the bearer key is not a valid issued key") };
  return { key: k.key };
}

// Method, the key when `requireKey`, the budget, body (A KEY TO OPEN, above:
// the key first, then the budget it draws on). Returns {body, key} (key only
// with `requireKey`) or null (already answered).
async function admit(req, res, verb, { requireKey = false } = {}) {
  res.setHeader("cache-control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("allow", "POST");
    refuse(res, new Refusal(405, "method_not_allowed", `POST a JSON body to ?op=case-${verb}`));
    return null;
  }
  const k = requireKey ? await openKey(req) : { key: null };
  const rl = k.key ? await ratelimit.checkKey(keys.keyHash(k.key)) : await ratelimit.check(req);
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    const minutes = Math.round(rl.windowSeconds / 60);
    refuse(res, new Refusal(429, "rate_limited", "rate limit exceeded", {
      note: k.key
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

// Both registration files of a case, each read through the store and judged:
// the authority the case object projects. Read in role order, a then b.
// -> {ok:true, regs:{a, b}}, where a role with no file is null, or
//    {ok:false, why: "unreachable" | "unreadable", role, reason}.
async function readRegistrations(kase) {
  const regs = {};
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
      continue;
    }
    const rv = judgeRegistration(g, p, kase, r);
    if (!rv.ok) return { ok: false, why: "unreadable", role: r, reason: rv.reason };
    regs[r] = g.json;
  }
  return { ok: true, regs };
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
async function project(cpath, got, reg, regs) {
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
        const again = await readRegistrations(fresh.json);
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
  const read = await readRegistrations(kase);
  if (!read.ok && read.why === "unreachable") {
    return refuse(res, new Refusal(503, "store_unreachable", "a registration record could not be read; this is not a 'no'"));
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
      return refuse(res, new Refusal(409, "late_commitment", "the case's deadline has passed; no commitment can be registered to it now",
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
    let put;
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
    if (put && put.abandoned) {
      let won;
      try {
        won = await store.getFile(rpath);
      } catch {
        won = undefined;
      }
      const wv = won ? judgeRegistration(won, rpath, kase, role) : null;
      if (!wv || !wv.ok) {
        return refuse(res, new Refusal(503, "store_error", "a registration for this role landed first and could not be read back"));
      }
      if (won.json.commitment_sha256 !== commitment_sha256 || won.json.key_id !== key_id) {
        return refuse(res, new Refusal(409, "role_already_committed",
          `role ${role} already has a registered commitment; only the first registration counts`, { case_id, role, registered: C.commitmentEntry(won.json) }));
      }
      registration = won.json;
    } else {
      registration = record;
      created = true;
    }
  }

  // 8. Project into the case object: from BOTH registration files, so a
  // registration the other role recorded earlier is projected too.
  const upd = await project(cpath, got, registration, regs);
  if (!upd.ok && upd.code === "case_withdrawn") {
    return refuse(res, new Refusal(409, "case_withdrawn",
      "the case was withdrawn while this registration was being projected. The registration file stands in the public record; " +
        "a withdrawn case takes no more registrations",
      { case_id, role, registration_recorded: true, registration }));
  }
  if (!upd.ok) {
    return refuse(res, new Refusal(503, "case_update_failed",
      "the registration is recorded and stands (first write wins), but the case object was not brought up to date. " +
        "Send the same registration again to complete it.",
      { case_id, role, registration_recorded: true, registration, reason: upd.code }));
  }
  const v = judgeCase({ json: upd.case }, cpath, case_id);
  return res.status(created ? 201 : 200).json(verdict.success(v, {
    case_id,
    role,
    existing: !created,
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
// case fields (lib/_case.js validateRevealBody) and the two tapes
// (lib/_reconcile_http.js tapeFrom). -> {asked, tapes: {a, b}}. Throws a
// Refusal, a reconcile Refusal or a CaseError.
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
  const asked = C.validateRevealBody(caseFields);
  const tapes = {
    a: RECONCILE.tapeFrom(tapeFields, "tape_a", fromMultipart),
    b: RECONCILE.tapeFrom(tapeFields, "tape_b", fromMultipart),
  };
  return { asked, tapes };
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

  // 0. The request.
  let asked;
  let tapes;
  try {
    const { fields, fromMultipart } = await RECONCILE.readFields(req);
    ({ asked, tapes } = revealFields(fields, fromMultipart));
  } catch (e) {
    if (e instanceof Refusal || e instanceof RECONCILE.Refusal) return refuse(res, e);
    if (e instanceof C.CaseError) return refuse(res, fromCaseError(e));
    return refuse(res, new Refusal(400, "unreadable_body", "the request body could not be read"));
  }
  const { case_id } = asked;
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
  if (kase.status === "WITHDRAWN") {
    return refuse(res, new Refusal(409, "case_withdrawn", "the case was withdrawn; a withdrawn case takes no reveal", { case_id, status: kase.status }));
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

  // 2. The registration files are the authority (design decision 4), and the
  // case object must agree with them, role by role.
  const read = await readRegistrations(kase);
  if (!read.ok && read.why === "unreachable") {
    return refuse(res, new Refusal(503, "store_unreachable", "a registration record could not be read; this is not a 'no'"));
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
      "this deployment cannot name the key document it would seal under, so it seals nothing; nothing was compared", { case_id, reason: sealing.reason }));
  }

  // 6. The comparison: ?op=reconcile's own call, once. Role a's tape is
  // reconcile's first argument, tape_a in its answer and in the receipt.
  let compared;
  try {
    compared = RECONCILE.compare(tapes.a, tapes.b, { env, now: nowMs, keyDocument: sealing.doc });
  } catch (e) {
    if (e && e.signerUnavailable) {
      return refuse(res, new Refusal(503, "signer_unavailable",
        "this deployment has no published reconcile signer, and a case is never sealed with a receipt it cannot sign with one; nothing was compared and nothing was sealed",
        { case_id, reason: e.reason }));
    }
    if (!e || !e.portError) throw e;
    console.error(`[case] reveal: port raised ${e.causeName}`);
    return refuse(res, new Refusal(500, "internal_error", "the comparison failed inside this service; no verdict was reached and nothing was sealed"));
  }

  // 7. The receipt, checked deeply before anything is sealed (lib/_case_seal.js).
  const rsigner = SEAL.loadReconcileSigner(env, { keyDocument: sealing.doc });
  const rc = SEAL.checkReceipt(compared.receipt, {
    kase,
    tapeSha256: { a: asked.reveals.a.tape_sha256, b: asked.reveals.b.tape_sha256 },
    tapeBytes: { a: tapes.a.length, b: tapes.b.length },
    result: compared.result,
    revealedAt,
    signer: rsigner,
  });
  if (!rc.ok) {
    console.error(`[case] reveal: receipt check failed (${rc.reason})`);
    return refuse(res, new Refusal(500, "internal_error",
      "the receipt this service built for the comparison failed its own check; nothing was sealed", { reason: rc.reason }));
  }
  const st = SEAL.storableReceipt(compared.receipt);
  if (!st.ok && st.reason === "integer_beyond_json") {
    return refuse(res, new Refusal(422, "verdict_not_sealable",
      "the verdict names a call index larger than 2^53 - 1, which a JSON case record cannot hold without changing the receipt's " +
        "signed bytes; nothing was sealed", { case_id }));
  }
  if (!st.ok) {
    console.error(`[case] reveal: receipt not storable (${st.reason})`);
    return refuse(res, new Refusal(500, "internal_error", "the receipt could not be held in a case record; nothing was sealed", { reason: st.reason }));
  }

  // 8. The seal: the case file, authoritative (lib/_case_seal.js).
  const csigner = SEAL.loadCaseSigner(env, { keyDocument: sealing.doc });
  const signedUnder = { document_sha256: sealing.document_sha256, document_commit: sealing.document_commit, retrieved_at: revealedAt };
  let sealed;
  try {
    sealed = SEAL.sealCase(kase, { reveals: asked.reveals, receipt: st.receipt, crossReference: asked.cross_reference, revealedAt, signedUnder }, csigner);
  } catch (e) {
    if (!(e instanceof C.CaseError)) throw e;
    console.error(`[case] reveal: built an invalid sealed case (${e.code} at ${e.field})`);
    return refuse(res, new Refusal(500, "internal_error", "this service built a sealed case its own schema refuses; nothing was sealed"));
  }
  const chain = SEAL.caseChain(sealed);
  let put;
  try {
    put = await store.putFile(cpath, sealed, `case ${case_id.slice(0, 16)}: sealed, ${sealed.verdict.verdict.verdict}`, got.sha, {
      // The case moved since it was read (another reveal sealed it, or it
      // was withdrawn). Whatever it is now stands; the re-read below says what.
      rebuild: () => null,
    });
  } catch (e) {
    if (e && e.conflict) put = { abandoned: true };
    else {
      console.error(`[case] reveal: case write failed (${e && e.message})`);
      return refuse(res, new Refusal(503, "case_seal_failed",
        "the comparison ran, but the sealed case could not be written; nothing was sealed and nothing was anchored. The case is still COMMITTED",
        { case_id }));
    }
  }
  if (put && put.abandoned) {
    let again;
    try {
      again = await store.getFile(cpath);
    } catch {
      again = undefined;
    }
    const status = again && C.validateCase(again.json).ok ? again.json.status : null;
    if (status === "WITHDRAWN") {
      return refuse(res, new Refusal(409, "case_withdrawn", "the case was withdrawn while this reveal ran; nothing was sealed", { case_id, status }));
    }
    if (status === "VERDICT") {
      return refuse(res, new Refusal(409, "not_committed",
        "another request sealed this case while this one ran, and a case has one joint reveal; this one sealed nothing", { case_id, status }));
    }
    return refuse(res, new Refusal(503, "case_seal_failed", "the case moved while this reveal ran and was not sealed by it", { case_id, reason: "case_moved" }));
  }

  // 9. The pin: the seal's anchor. A pin that fails leaves the case sealed
  // and reports pin: "pending", computed, never stored.
  const pin = await SEAL.pinChain(case_id, chain, nowMs);
  if (pin.pin !== "anchored") console.error(`[case] reveal: sealed, pin ${pin.pin} (${pin.reason || "see record"})`);

  const v = judgeCase({ json: sealed }, cpath, case_id);
  const body = verdict.success(v, {
    case_id,
    status: sealed.status,
    case: sealed,
    chain,
    pin: pin.pin,
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
    return { refusal: new Refusal(503, "store_unreachable", `the case record could not be read; this is not a 'no', and ${nothing}`) };
  }
  if (got === null) return { refusal: new Refusal(404, "case_not_found", "no case is open with this id", { case_id: caseId }) };
  const cv = judgeCase(got, cpath, caseId);
  if (!cv.ok) {
    return { refusal: new Refusal(503, "case_record_unreadable",
      `the stored case is present but cannot be read as a valid arcaeon-case/1 record; ${nothing}`, { reason: cv.reason }) };
  }
  return { kase: got.json, got };
}

// Both registration files, the authority, and the case object's agreement
// with them (the commit and reveal paths' own check). -> {regs} or {refusal}.
async function readAuthority(kase, nothing) {
  const read = await readRegistrations(kase);
  if (!read.ok && read.why === "unreachable") {
    return { refusal: new Refusal(503, "store_unreachable", `a registration record could not be read; this is not a 'no', and ${nothing}`) };
  }
  if (!read.ok) {
    return { refusal: new Refusal(503, "registration_record_unreadable",
      `the stored registration for role ${read.role} is present but cannot be read as a valid record; ${nothing}`, { reason: read.reason, role: read.role }) };
  }
  for (const r of C.ROLES) {
    const entry = kase.commitments[r];
    if (entry !== null && !(read.regs[r] && C.sameEntry(entry, C.commitmentEntry(read.regs[r])))) {
      return { refusal: new Refusal(503, "case_record_inconsistent",
        `the case object shows a registration for role ${r} that its registration record does not; ${nothing}`, { role: r }) };
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
  const nothing = "nothing was withdrawn";

  // 1. The case, and where it stands by this service's clock.
  const rc = await readCase(cpath, case_id, "withdraw", nothing);
  if (rc.refusal) return refuse(res, rc.refusal);
  const { kase, got } = rc;
  const stand = withdrawStanding(kase, nowMs, case_id);
  if (stand) return refuse(res, stand);

  // 2. The registration files are the authority.
  const auth = await readAuthority(kase, nothing);
  if (auth.refusal) return refuse(res, auth.refusal);

  // 3. The role proves itself by its commitment preimage.
  if (!proves(case_id, auth.regs, asked)) {
    return refuse(res, new Refusal(403, "withdraw_unauthorized",
      `the preimage presented does not recompute a commitment registered to role ${role} of this case ` +
        "(sha256 of json-c14n:v1 {case_id, role, tape_sha256, salt, protocol_version}), so it does not show that the caller holds that role; " +
        `${nothing}`, { case_id, role }));
  }

  // 4. The redacted record, signed with the case key (or unsigned, saying why).
  const signer = SEAL.loadCaseSigner(env, { keyDocument: opts.keyDocument });
  let record;
  try {
    record = SEAL.withdrawnRecord(kase, { role, at: C.utcSeconds(nowMs), salt: asked.salt }, signer);
  } catch (e) {
    if (!(e instanceof C.CaseError)) throw e;
    console.error(`[case] withdraw: built an invalid withdrawal record (${e.code} at ${e.field})`);
    return refuse(res, new Refusal(500, "internal_error", `this service built a withdrawal record its own schema refuses; ${nothing}`));
  }

  // 5. The root write: a CAS over the case as read. The case may move
  // meanwhile. If a registration was projected, the redacted record does not
  // depend on it and is written over the fresh case. If a reveal sealed it,
  // or another withdrawal landed, that write stands and this one is refused
  // by what the case now is.
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
      return refuse(res, new Refusal(503, "store_error", `could not write the withdrawal record; ${nothing}`, { case_id }));
    }
  }
  if (put && put.abandoned) {
    let again;
    try {
      again = await store.getFile(cpath);
    } catch {
      again = undefined;
    }
    const current = again && C.validateCase(again.json).ok ? again.json : null;
    const lost = current ? withdrawStanding(current, nowMs, case_id) : null;
    if (lost) return refuse(res, new Refusal(lost.status, lost.code, `the case changed while this withdrawal ran: ${lost.message}`, lost.extra));
    return refuse(res, new Refusal(503, "store_error", `the case moved while this withdrawal ran and was not withdrawn by it; ${nothing}`,
      { case_id, reason: "case_moved" }));
  }

  // 6. The marker, create-only, so a tree listing shows the withdrawal
  // without a fetch (lib/_case_seal.js caseTreeIndex). The record above is
  // the authority: a marker that fails leaves the case withdrawn, and the
  // sealer reads the root and skips it as terminal.
  const marker = await writeWithdrawnMarker(case_id, record.withdrawal.at);

  const v = judgeCase({ json: record }, cpath, case_id);
  return res.status(201).json(verdict.success(v, {
    case_id,
    status: "WITHDRAWN",
    withdrawn_by: role,
    case: record,
    marker,
    marker_path: C.withdrawnMarkerPath(case_id),
    registrations_note: SEAL.WITHDRAWN_REGISTRATIONS_NOTE,
    preimage_note: "Presenting the preimage spends this commitment: a withdrawn case can never be revealed. Nothing of the preimage is " +
      "kept except the sha256 of the salt, in the withdrawal record.",
    signed_by_note: record.sig === null ? record.sig_reason : `Signed by ${record.signed_by}; the verifier is published at /${SEAL.CASE_KEYS_DOC}.`,
  }, "case-withdraw"));
}

// Whether a case may still be withdrawn. -> null, or the Refusal saying why
// not: VERDICT is case_sealed, WITHDRAWN is case_withdrawn, an OPEN or
// COMMITTED case at or past its deadline reads EXPIRED (expired).
function withdrawStanding(kase, nowMs, caseId) {
  if (kase.status === "VERDICT") {
    return new Refusal(409, "case_sealed", "the case is sealed with a verdict, and a sealed case cannot be withdrawn; nothing was withdrawn",
      { case_id: caseId, status: "VERDICT" });
  }
  if (kase.status === "WITHDRAWN") {
    return new Refusal(409, "case_withdrawn", "the case is already withdrawn; nothing was withdrawn", { case_id: caseId, status: "WITHDRAWN" });
  }
  if (C.pastDeadline(kase, nowMs)) {
    return new Refusal(409, "expired",
      "the case's deadline has passed by this service's clock, so it reads EXPIRED, and an expired case is not withdrawn; nothing was withdrawn",
      { case_id: caseId, deadline: kase.deadline, status: "EXPIRED" });
  }
  return null;
}

// -> "written", "existing" (a marker was already there; never written over)
// or "failed" (the withdrawal stands; see step 6).
async function writeWithdrawnMarker(caseId, at) {
  const mpath = C.withdrawnMarkerPath(caseId);
  try {
    await store.putFile(mpath, { kind: "case-withdrawn-marker", v: 1, case_id: caseId, withdrawn_at: at },
      `case ${caseId.slice(0, 16)}: withdrawn marker`, undefined, { rebuild: () => null });
    return "written";
  } catch (e) {
    if (e && e.conflict) return "existing";
    console.error(`[case] withdraw: marker write failed (${e && e.message})`);
    return "failed";
  }
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
});

async function handleCaseReference(req, res, opts = {}) {
  const admitted = await admit(req, res, "reference");
  if (!admitted) return;
  const nowMs = clock(opts);
  const env = opts.env || process.env;

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
        `no role proof was presented, and the operator's key is not configured on this deployment (${OPERATOR_KEY_ENV}), so the request cannot be authorized; ${nothing}`));
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
  const answer = await SEAL.sealedRecordReason(kase, keyDocument, { currentCommit: env[SEAL.DEPLOY_COMMIT_ENV] });
  const unsealed = SEAL.sealHolds(answer) ? null : answer;
  if (unsealed) {
    console.error(`[case] reference: the stored VERDICT does not verify (${unsealed.code}: ${unsealed.reason})`);
    return refuse(res, new Refusal(409, unsealed.code,
      `the case reads VERDICT, but its sealed record does not verify (${unsealed.reason}): ${UNSEALED_WORDS[unsealed.code] || unsealed.code}, ` +
        `so it is not treated as a sealed case; ${nothing}`,
      { case_id, status: "VERDICT", reason: unsealed.reason }));
  }

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

  // 4. The row, create-only at the next seq. Another row landing first takes
  // that seq; this one moves to the next. A row is never written over.
  const signer = SEAL.loadCaseSigner(env, { keyDocument });
  const recordedAt = C.utcSeconds(nowMs);
  let row = null;
  let rpath = null;
  let judged = null;
  for (let attempt = 1; attempt <= REFERENCE_WRITE_ATTEMPTS && row === null; attempt += 1) {
    let seqs;
    try {
      seqs = await SEAL.referenceSeqs(case_id);
    } catch (e) {
      console.error(`[case] reference: listing failed (${e && e.message})`);
      return refuse(res, new Refusal(503, "store_unreachable", `the case's reference rows could not be listed; this is not a 'no', and ${nothing}`));
    }
    const seq = (seqs.length ? seqs[seqs.length - 1] : 0) + 1;
    if (seq > C.MAX_REFERENCE_SEQ) {
      return refuse(res, new Refusal(409, "references_full", `this case holds the most reference rows a case can; ${nothing}`, { case_id }));
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
  OPERATOR_KEY_ENV,
  _internal: { Refusal, readJsonBody, judgeStampRecord, revealFields, openQuotaPath, takeOpenQuota, operatorBearer },
};

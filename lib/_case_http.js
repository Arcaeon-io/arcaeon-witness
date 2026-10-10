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
// its receipt, and the seal. Withdrawal, the addendum and the page are item
// 2b and are not here. lib/_case.js holds every schema rule and
// lib/_case_seal.js the seal's; this file reads, writes and refuses.
//
//   POST ?op=case-open    the opening: {protocol_version, policy_version,
//                         scope_digest, party_a, party_b, opened_at, deadline}
//                         -> cases/<case_id>.json, status OPEN, 201.
//   POST ?op=case-commit  {case_id, role, commitment_sha256}
//                         -> cases/<case_id>/commit_<role>.json, 201, and the
//                         case object's commitments, rebuilt from both roles'
//                         files; status COMMITTED once both are registered.
//                         The same registration again is 200 (a replay).
//   POST ?op=case-reveal  {case_id, reveals: {a: {tape_sha256, salt}, b: ...},
//                         cross_reference?} and the two tapes, tape_a and
//                         tape_b, as ?op=reconcile takes tapes
//                         -> cases/<case_id>.json sealed (status VERDICT), 201,
//                         then its pin, pins/case/<case_id>/.
// All three write to the PINS repository through lib/_store.js (design:
// "writes the registration as cases/<case_id>/commit_<role>.json in the pins
// repository"). The stamps repository is only READ, through the stamp read
// path (lib/_stamp_store.js getFile and listCommits on lib/_stamp.js
// stampPath).
//
// REFUSALS ARE TYPED, the reconcile endpoint's rule: {ok:false, error_code,
// error, ...} with a 4xx for a request this service will not act on, a 503 for
// a store it could not read or write, and never a 500 for a bad request.
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
//
// THE REGISTRATION (design, "The commitment format"): "Registration verifies
// that a stamp with that hash exists, reads stamp_commit and stamped_at from
// the fetched stamp record (kind file-stamp, matching hash), refuses a second
// registration for the same role (role_already_committed), refuses a
// registration after deadline (late_commitment), and writes the registration
// ... first write wins." And from GPT-5.6's review: "The service must not
// trust copied stamp fields." So the body is exactly three fields and anything
// else (a stamped_at, a commit, a record_url) is refused `unknown_field`,
// never quietly dropped: a caller who sent one believes it was used.
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
//      `case_record_inconsistent`; and each registration still rests on its
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
//   6. the comparison, lib/_reconcile_http.js compare, the very call
//      ?op=reconcile makes, once, role a's tape first;
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
// the answer is 201 with `pin: "pending"` (TWO WRITES in lib/_case_seal.js).
// Every time recorded comes from one read of this service's clock, taken
// when the request arrived: revealed_at, the receipt's compared_at and a
// cross_reference's recorded_at.
//
// NOTHING ELSE IS KEPT. No tape and no salt is written or logged by this
// file. The reveal holds both tapes and both salts in memory for one
// request; the sealed case keeps each tape's sha256 once, in `reveals` (the
// design: it "must equal the receipt's received-tape hash"), and each salt
// only as salt_sha256.

"use strict";

const crypto = require("node:crypto");
const C = require("./_case.js");
const SEAL = require("./_case_seal.js");
const RECONCILE = require("./_reconcile_http.js"); // readFields, tapeFrom, compare: ?op=reconcile's own steps
const receipts = require("./_reconcile_receipt.js");
const T = require("./_reconcile_tapes.js");
const store = require("./_store.js");
const stampStore = require("./_stamp_store.js");
const stamp = require("./_stamp.js"); // stampPath only: the one definition of where a stamp lives
const verdict = require("./_verdict.js");
const ratelimit = require("./_ratelimit.js");
const { DEFAULT_SKEW_SECONDS } = require("./_check_record.js");

const BODY_MAX_BYTES = 16384;

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

// Method, rate limit, body. Returns {body} or null (already answered).
async function admit(req, res, verb) {
  res.setHeader("cache-control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("allow", "POST");
    refuse(res, new Refusal(405, "method_not_allowed", `POST a JSON body to ?op=case-${verb}`));
    return null;
  }
  const rl = await ratelimit.check(req);
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    refuse(res, new Refusal(429, "rate_limited", "rate limit exceeded", {
      note: `naive per-IP limiter shared with /api/verify: ~${rl.limit} calls per IP per ${Math.round(rl.windowSeconds / 60)} minutes`,
      retry_after_seconds: rl.retryAfterSeconds,
    }));
    return null;
  }
  try {
    return { body: readJsonBody(req) };
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
  const admitted = await admit(req, res, "open");
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
  const { case_id, role, commitment_sha256 } = asked;
  const other = role === "a" ? "b" : "a";
  const cpath = C.casePath(case_id);

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
  // 2 proved any case entry is its file's), so only a DIFFERENT hash is a
  // second registration. The same hash again is a replay (IDEMPOTENT REPLAY).
  if (regs[role] && regs[role].commitment_sha256 !== commitment_sha256) {
    return refuse(res, new Refusal(409, "role_already_committed",
      `role ${role} already has a registered commitment; only the first registration counts`, { case_id, role, registered: C.commitmentEntry(regs[role]) }));
  }
  // 4. One hash cannot hold both roles: its preimage names one role.
  const theirs = regs[other] || kase.commitments[other];
  if (theirs && theirs.commitment_sha256 === commitment_sha256) {
    return refuse(res, new Refusal(409, "commitment_registered_to_other_role",
      `this commitment is already registered to role ${other} of this case; a commitment's preimage names exactly one role`, { case_id, role, other_role: other }));
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
      if (won.json.commitment_sha256 !== commitment_sha256) {
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
    if (sc.record.stamped_at !== regs[r].stamped_at || (regs[r].stamp_commit !== null && sc.commit !== regs[r].stamp_commit)) {
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

  // 6. The comparison: ?op=reconcile's own call, once. Role a's tape is
  // reconcile's first argument, tape_a in its answer and in the receipt.
  let compared;
  try {
    compared = RECONCILE.compare(tapes.a, tapes.b, { env, now: nowMs });
  } catch (e) {
    if (!e || !e.portError) throw e;
    console.error(`[case] reveal: port raised ${e.causeName}`);
    return refuse(res, new Refusal(500, "internal_error", "the comparison failed inside this service; no verdict was reached and nothing was sealed"));
  }

  // 7. The receipt, checked deeply before anything is sealed (lib/_case_seal.js).
  const rsigner = receipts.loadSigner(env);
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
  const csigner = SEAL.loadCaseSigner(env);
  let sealed;
  try {
    sealed = SEAL.sealCase(kase, { reveals: asked.reveals, receipt: st.receipt, crossReference: asked.cross_reference, revealedAt }, csigner);
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
    sealed_by: csigner.ok ? { name: csigner.name, verifier: csigner.verifier, alg: "ed25519" } : null,
    verdict: compared.result,
    service_limits: RECONCILE.SERVICE_LIMITS.slice(),
  }, "case-reveal");
  res.setHeader("content-type", "application/json; charset=utf-8");
  return res.status(201).send(T.wireJson(body));
}

module.exports = {
  handleCaseOpen,
  handleCaseCommit,
  handleCaseReveal,
  BODY_MAX_BYTES,
  _internal: { Refusal, readJsonBody, judgeStampRecord, revealFields },
};

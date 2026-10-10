// _case_http.js — POST ?op=case-open and POST ?op=case-commit, co-hosted on
// api/verify.js. Underscore prefix = not routed as a serverless function.
//
// WHY IT RIDES ON verify.js: api/ is at the Vercel Hobby 12-function cap, and
// the design says so in capitals: "No thirteenth function. Every new route is
// `?op=case-<verb>` on `verify.js`." (CASE_PROTOCOL_DESIGN_2026-10-10.md,
// velouria projects/arcaeon/, version 2). Dispatched next to ?op=reconcile,
// before verify's GET-only CORS helper; it shares nothing with verify's logic.
//
// WHAT THIS ITEM IS (design, "Scope of this item, and the next"): "the schema
// module with the case id rule, the commitment rule and canonical bytes, the
// registration path (?op=case-commit) with its public first-write-wins record".
// The joint reveal, the seal, withdrawal and the page are item two and are not
// here. lib/_case.js holds every rule; this file reads, writes and refuses.
//
//   POST ?op=case-open    the opening: {protocol_version, policy_version,
//                         scope_digest, party_a, party_b, opened_at, deadline}
//                         -> cases/<case_id>.json, status OPEN, 201.
//   POST ?op=case-commit  {case_id, role, commitment_sha256}
//                         -> cases/<case_id>/commit_<role>.json, 201, and the
//                         case object's commitments, rebuilt from both roles'
//                         files; status COMMITTED once both are registered.
// Both write to the PINS repository through lib/_store.js (design: "writes the
// registration as cases/<case_id>/commit_<role>.json in the pins
// repository"). The stamps repository is only READ, through the stamp read
// path (lib/_stamp_store.js getFile on lib/_stamp.js stampPath).
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
// STAMP_COMMIT IS NULL, AND WHY. The stored stamp record is {kind, v, sha256,
// size, stamped_at}; it does not carry the commit that holds it, and the
// contents-API read returns only the file's blob sha, which is not a commit.
// So there is no commit to read "from the fetched stamp record", and this
// service will not take one from a caller. Every registration records
// `stamp_commit: null` until a commits-for-path read exists; the stamp's
// history is derivable from the hash alone (lib/_stamp.js history_url), the
// same way the design derives record_url at render time.
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
// NOTHING ELSE IS KEPT. No tape and no salt reaches this file: neither op
// accepts one.

"use strict";

const C = require("./_case.js");
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

// Project the registration files into the case object (the second write).
// `reg` is the registration this request made or is completing; `regs` is
// both files as step 2 of handleCaseCommit read them, with `reg` standing in
// for its own role. Returns {ok:true, case} with the case as written, or
// {ok:false, code}.
async function project(cpath, got, reg, regs) {
  let written;
  try {
    written = projectFiles(got.json, { ...regs, [reg.role]: reg }).next;
  } catch (e) {
    if (e instanceof C.CaseError) return { ok: false, code: e.code };
    throw e;
  }
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
        let built;
        try {
          built = projectFiles(fresh.json, again.regs);
        } catch {
          return null;
        }
        if (built.added.length === 0) return null;
        written = built.next;
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
    if (again && C.validateCase(again.json).ok && C.sameEntry(again.json.commitments[reg.role], C.commitmentEntry(reg))) {
      return { ok: true, case: again.json };
    }
    return { ok: false, code: "case_moved" };
  }
  return { ok: true, case: written };
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

  // 3. First write wins per (case_id, role).
  if (kase.commitments[role] !== null) {
    return refuse(res, new Refusal(409, "role_already_committed",
      `role ${role} already has a registered commitment; only the first registration counts`, { case_id, role, registered: kase.commitments[role] }));
  }
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

  let registration = regs[role]; // non-null only when completing an earlier registration
  let created = false;
  if (!registration) {
    // 5. Before the deadline.
    if (C.pastDeadline(kase, nowMs)) {
      return refuse(res, new Refusal(409, "late_commitment", "the case's deadline has passed; no commitment can be registered to it now",
        { case_id, deadline: kase.deadline }));
    }

    // 6. The stamp, read through the stamp read path. Never a caller's copy.
    const st = stampStore.status();
    if (!st.configured) {
      return refuse(res, new Refusal(503, "stamp_store_not_configured",
        "the stamp record is not configured on this deployment, so no stamp can be checked; nothing was registered", { reason: st.reason }));
    }
    let sg;
    try {
      sg = await stampStore.getFile(stamp.stampPath(commitment_sha256));
    } catch (e) {
      console.error(`[case] commit: stamp read failed (${e && e.message})`);
      return refuse(res, new Refusal(503, "stamp_store_unreachable", "the stamp record could not be read; this is not a 'no'"));
    }
    if (sg === null) {
      return refuse(res, new Refusal(404, "no_commitment",
        "no stamp is recorded for this commitment hash. Stamp it first (POST /api/stamp), then register it",
        { commitment_sha256 }));
    }
    const sv = judgeStampRecord(sg, commitment_sha256);
    if (!sv.ok) {
      return refuse(res, new Refusal(503, "stamp_record_unreadable",
        "the stamp stored for this hash is present but is not a readable file-stamp record for it; nothing was registered", { reason: sv.reason }));
    }
    // 6b. The stamp is of a commitment's canonical bytes (THE STAMP'S SIZE, above).
    const stampedSize = sg.json.size;
    if (stampedSize !== C.COMMITMENT_BYTES_LENGTH) {
      const said = Number.isSafeInteger(stampedSize) ? `a size of ${stampedSize} bytes`
        : stampedSize === null || stampedSize === undefined ? "no size" : "a size that is not a whole number of bytes";
      return refuse(res, new Refusal(409, "stamp_size_mismatch",
        `the stamp for this hash records ${said}, and a case/1 commitment's canonical bytes are ${C.COMMITMENT_BYTES_LENGTH}, ` +
          "so it is not a stamp of a commitment. A hash is stamped once, so this one cannot be re-stamped: draw a new salt, " +
          `compute a new commitment, stamp it with size ${C.COMMITMENT_BYTES_LENGTH} and register that hash. Nothing was registered`,
        { commitment_sha256, stamped_size: Number.isSafeInteger(stampedSize) ? stampedSize : null, expected_size: C.COMMITMENT_BYTES_LENGTH }));
    }

    // 7. The registration record, create-only.
    const record = C.registrationRecord({
      case_id,
      role,
      commitment_sha256,
      registered_at: C.utcSeconds(nowMs),
      stamp_commit: null,
      stamped_at: sg.json.stamped_at,
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
    status: upd.case.status,
    case: upd.case,
  }, "case-commit"));
}

module.exports = {
  handleCaseOpen,
  handleCaseCommit,
  BODY_MAX_BYTES,
  _internal: { Refusal, readJsonBody, judgeStampRecord },
};

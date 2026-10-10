// _case.js — the arcaeon-case/1 schema: the case object, the case id rule and
// the commitment rule. Underscore prefix = not routed as a serverless function.
// This file does no I/O of any kind: no store, no fetch, and no clock it is not
// handed as an argument. lib/_case_http.js is the part that reads and writes.
//
// WHAT A CASE IS (CASE_PROTOCOL_DESIGN_2026-10-10.md, velouria
// projects/arcaeon/, version 2, the design this was built from). Two parties,
// an agent side and a tool side, want their two tapes compared by this
// service, and want each tape fixed before the comparison. So each party
// computes a commitment hash locally, stamps it (lib/_stamp.js: a public,
// dated commit), and registers it to the case under its role. Item two of the
// design is one request carrying both reveals and both tapes; this file gives
// that request the rules it will check against. It does not implement it.
//
// THE CLAIM, AND ONLY THIS (design, "The claim this item makes, and only
// this"): "Each accepted reveal matched a public commitment registered to this
// case and role before the deadline; the service ran its recorded comparison
// after receiving both accepted tapes in one request; the commitments, the
// comparison and the times are sealed and anchored." Item one builds the
// registration that sentence starts from, and nothing here claims more. LIMITS
// below carries the design's four non-claims, one sentence each, and every
// case object carries them.
//
// THE CASE ID RULE (design, case object table, `case_id`):
//   case_id = sha256( json-c14n:v1( {protocol_version, policy_version,
//             scope_digest, party_a, party_b, opened_at} ) )
// with party_a and party_b "in canonical order (sorted by `label`, then
// `side`)" and opened_at "normalized to UTC seconds". GPT-5.6's review is why
// the ordering and the normalization are part of the rule: "Require canonical
// ordering of party_a and party_b, exact timestamp normalization ...
// Otherwise 'both can derive it' is not reliable across implementations." So:
//   - labels compare by Unicode CODE POINT, which is how Python compares str
//     and how json-c14n:v1 sorts keys. JavaScript's own `<` compares UTF-16
//     code units, and the two disagree as soon as a label holds a character
//     outside the Basic Multilingual Plane (test 1 plants exactly that);
//   - a tie on label AND side is refused (`parties_not_distinct`): the rule
//     has nothing left to order by, and a key_id does not break the tie,
//     because the design does not say it does;
//   - opened_at may arrive with a fraction or an offset; it is converted to
//     UTC and the fraction is dropped (truncated, never rounded), and the id
//     is taken over YYYY-MM-DDTHH:MM:SSZ;
//   - `deadline` is NOT in the id. A retried case with a new deadline is the
//     same opening only if every id field is the same, and then it is refused
//     as a duplicate, not given a second id.
// Role a binds to party_a and role b to party_b, exactly (design: "Commitment
// role `a` binds to `party_a` and `b` to `party_b`, exactly (GPT: role binding
// was underspecified)"). Since party_a is whichever party sorts first, a party
// learns its role from the canonical order, not from where it listed itself.
//
// THE COMMITMENT RULE (design, "The commitment format"):
//   commitment = sha256( json-c14n:v1( {case_id, role, tape_sha256, salt,
//                protocol_version: "case/1"} ) )
// salt is 32 random bytes as 64 hex characters. There is no manifest hash:
// "the witness never sees an evidence manifest in this item, so hashing one
// into the commitment proved nothing to anyone (Gemini)". tape_sha256 stays,
// strict: "without it the witness proves only that something was committed,
// not that the exact tape compared was fixed before disclosure." Every value
// in the preimage is a fixed-length ASCII string, so its canonical bytes are
// always COMMITMENT_BYTES_LENGTH long: that is the `size` a party stamps.
// Unknown fields in a commitment input are refused: a caller who passes a
// manifest hash believes it is bound, and it is not.
//
// ONE CANONICALIZER. Both hashes go through lib/_check_record.js's
// canonicalBytes, the json-c14n:v1 signing rule, which is lib/_merkle.js's
// serializer, which is the JS side of arcaeon_ledger.artefact._canon_json
// (json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
// allow_nan=False).encode("utf-8")). test/fixtures/case/c14n_cases.json holds
// bytes written by that Python function, and test 2 compares them byte for
// byte. Two input rules exist only so the two sides cannot diverge: a label
// or key_id holding a lone surrogate is refused (JSON.stringify escapes one,
// Python's strict UTF-8 encode raises on it), and so is one holding a control
// character (it would otherwise be an escape-sequence edge on a public page).
//
// TYPED ERRORS. Every refusal in this file is a CaseError with `code` from
// CASE_ERROR_CODES and `field` naming the offender, so the HTTP layer can turn
// it into a typed 4xx without reading the message. validateCase never throws;
// it answers {ok:false, code, field, error}.
//
// THE CASE OBJECT (design table, authoritative). Unknown top-level fields are
// refused, the lib/_check_record.js rule: "A field the verifier does not know
// about is a field a reader might trust that nobody checked." `sig_reason` is
// declared for that reason (GPT: "otherwise _check_record.js should reject the
// reason as an unknown top-level field"). An open or committed case is not
// sealed and carries `sig: null` with UNSEALED_SIG_REASON; sealing is item
// two. A stored status of EXPIRED is refused: "Expiry writes nothing; the page
// computes EXPIRED from deadline against the service clock". A WITHDRAWN case
// is the fixed redacted form and nothing else ("no labels, no commitments").
//
// NEVER HELD HERE: a tape, a salt, a manifest. The commitment functions take a
// salt because a party computes its commitment with them; nothing in this
// file or lib/_case_http.js writes one anywhere, and a registration body that
// carries one is refused as an unknown field.

"use strict";

const crypto = require("node:crypto");
const { canonicalBytes } = require("./_check_record.js");
const T = require("./_reconcile_tapes.js"); // PORT_VERSION only

const SCHEMA = "arcaeon-case/1";
const CASE_VERSION = 1;
const PROTOCOL_VERSION = "case/1";

// "policy_version: the reconcile port's method version as its receipt reports
// it" — lib/_reconcile_receipt.js methodBlock().port_version. A deployment can
// only run the port it has, so an opening naming another version is refused.
const SUPPORTED_POLICY_VERSION = T.PORT_VERSION;

const ROLES = Object.freeze(["a", "b"]);
const SIDES = Object.freeze(["agent", "tool"]);
const STATUSES = Object.freeze(["OPEN", "COMMITTED", "VERDICT", "WITHDRAWN", "EXPIRED"]);
const STORED_STATUSES = Object.freeze(["OPEN", "COMMITTED", "VERDICT", "WITHDRAWN"]);
const REGISTERABLE_STATUSES = Object.freeze(["OPEN", "COMMITTED"]);

const TOP_LEVEL_FIELDS = Object.freeze([
  "v", "case_id", "protocol_version", "policy_version", "scope_digest", "party_a", "party_b",
  "opened_at", "deadline", "commitments", "reveals", "verdict", "records", "cross_reference",
  "status", "withdrawal", "limits", "sig", "sig_reason",
]);
// design, "Withdrawal and expiry records": the redacted form, "and nothing else"
const WITHDRAWN_FIELDS = Object.freeze([
  "v", "case_id", "protocol_version", "status", "opened_at", "withdrawal", "limits", "sig", "sig_reason",
]);
const OPENING_FIELDS = Object.freeze([
  "protocol_version", "policy_version", "scope_digest", "party_a", "party_b", "opened_at", "deadline",
]);
const CASE_ID_FIELDS = Object.freeze([
  "protocol_version", "policy_version", "scope_digest", "party_a", "party_b", "opened_at",
]);
const PARTY_FIELDS = Object.freeze(["side", "label", "key_id"]);
const COMMITMENT_INPUT_FIELDS = Object.freeze(["case_id", "role", "tape_sha256", "salt", "protocol_version"]);
const COMMITMENT_ENTRY_FIELDS = Object.freeze(["commitment_sha256", "registered_at", "stamp_commit", "stamped_at"]);
const REVEAL_ENTRY_FIELDS = Object.freeze(["tape_sha256", "salt_sha256", "revealed_at"]);
const CROSS_REFERENCE_FIELDS = Object.freeze(["operator", "reference", "url", "recorded_at"]);
const WITHDRAWAL_FIELDS = Object.freeze(["by_role", "at"]);

// The public registration record, cases/<case_id>/commit_<role>.json.
const REGISTRATION_KIND = "case-commitment";
const REGISTRATION_FIELDS = Object.freeze([
  "kind", "v", "case_id", "role", "commitment_sha256", "registered_at", "stamp_commit", "stamped_at",
]);
// What a caller may send to ?op=case-commit, and nothing else.
const REGISTRATION_BODY_FIELDS = Object.freeze(["case_id", "role", "commitment_sha256"]);

// The four non-claims (design, the claim section: "The service does not
// establish who the parties are (labels are recorded, never verified), that
// either tape is complete or true, that the parties did not exchange tapes
// privately before committing, or fault. The page carries those four
// sentences."). Inside every case object, and so inside the signed bytes once
// item two signs one.
const LIMITS = Object.freeze([
  "This service does not establish who the parties are. Labels are recorded, never verified.",
  "This service does not establish that either tape is complete or true.",
  "This service does not establish that the parties did not exchange tapes privately before committing.",
  "This service does not establish fault.",
]);

const UNSEALED_SIG_REASON = "This case is not sealed. An open or committed case object carries no signature.";

const CASE_ERROR_CODES = Object.freeze([
  "not_an_object",
  "unknown_field",
  "missing_field",
  "malformed_field",
  "unknown_version",
  "unsupported_protocol_version",
  "unsupported_policy_version",
  "bad_role",
  "parties_not_distinct",
  "parties_not_canonical",
  "deadline_not_after_opened_at",
  "case_id_mismatch",
  "duplicate_commitment",
  "status_inconsistent",
  "limits_altered",
  "sig_reason_missing",
  "role_already_committed",
  "case_not_open",
]);

class CaseError extends Error {
  constructor(code, field, message) {
    super(message);
    this.name = "CaseError";
    if (!CASE_ERROR_CODES.includes(code)) throw new TypeError(`CaseError: unknown code ${code}`);
    this.code = code;
    this.field = field;
  }
}

// ---------------------------------------------------------------------------
// small checks
// ---------------------------------------------------------------------------
const HEX64 = /^[0-9a-f]{64}$/;
// A git object id: sha1 (40) or sha256 (64), lowercase.
const GIT_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const MAX_TEXT_CODE_POINTS = 200;
// Times this service writes: UTC, whole seconds, literal Z.
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
// A time this service copies from another record verbatim (a stamp's
// stamped_at is toISOString(), milliseconds included): the lib/_check_record.js
// ISO_UTC rule.
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
// What an opening may send for opened_at / deadline before normalization.
const ISO_IN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;
const MAX_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function checkHex64(v, field) {
  if (typeof v !== "string" || !HEX64.test(v)) {
    throw new CaseError("malformed_field", field, `${field} must be exactly 64 lowercase hex characters`);
  }
  return v;
}

// A label, key id or version string: recorded as given, so it has to be a
// string both canonicalizers encode to the same bytes.
function checkText(v, field) {
  if (typeof v !== "string" || v.length === 0) {
    throw new CaseError("malformed_field", field, `${field} must be a non-empty string`);
  }
  if (LONE_SURROGATE.test(v)) {
    throw new CaseError("malformed_field", field, `${field} holds a lone surrogate, which json-c14n:v1 cannot encode`);
  }
  if (CONTROL.test(v)) {
    throw new CaseError("malformed_field", field, `${field} holds a control character`);
  }
  if (Array.from(v).length > MAX_TEXT_CODE_POINTS) {
    throw new CaseError("malformed_field", field, `${field} is longer than ${MAX_TEXT_CODE_POINTS} characters`);
  }
  return v;
}

function onlyFields(obj, allowed, where) {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      throw new CaseError("unknown_field", where ? `${where}.${k}` : k, `unknown field ${JSON.stringify(k).slice(0, 80)}${where ? ` in ${where}` : ""}`);
    }
  }
}

function requireFields(obj, required, where) {
  for (const k of required) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) {
      throw new CaseError("missing_field", where ? `${where}.${k}` : k, `${where ? `${where}.` : ""}${k} is required`);
    }
  }
}

// Python's str ordering: by code point, not by UTF-16 code unit.
function compareCodePoints(a, b) {
  const ai = Array.from(a);
  const bi = Array.from(b);
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i += 1) {
    const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ai.length - bi.length;
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------
// -> epoch milliseconds (whole seconds, the fraction truncated), or null.
function parseIsoToUtcSecondsMs(s) {
  if (typeof s !== "string") return null;
  const m = ISO_IN.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (y < 1970 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return null;
  const wall = Date.UTC(y, mo - 1, d, h, mi, se);
  const back = new Date(wall);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null; // 30 February
  let offsetMinutes = 0;
  if (m[8] !== "Z") {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) return null;
    offsetMinutes = (m[9] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const utc = wall - offsetMinutes * 60000;
  if (utc < 0 || utc > MAX_TIME_MS) return null;
  return utc;
}

function utcSeconds(ms) {
  if (!Number.isFinite(ms)) throw new TypeError("utcSeconds: not a time");
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// "opened_at normalized to UTC seconds": any accepted form -> YYYY-MM-DDTHH:MM:SSZ.
function normalizeUtcSeconds(s, field = "time") {
  const ms = parseIsoToUtcSecondsMs(s);
  if (ms === null) {
    throw new CaseError("malformed_field", field,
      `${field} must be an ISO 8601 time with a date, hours, minutes, seconds and Z or a +HH:MM offset`);
  }
  return utcSeconds(ms);
}

function isUtcSeconds(s) {
  return typeof s === "string" && UTC_SECONDS.test(s) && parseIsoToUtcSecondsMs(s) !== null;
}

function isIsoUtc(s) {
  return typeof s === "string" && ISO_UTC.test(s) && Number.isFinite(Date.parse(s));
}

// ---------------------------------------------------------------------------
// parties
// ---------------------------------------------------------------------------
// -> a clean copy {side, label[, key_id]}. key_id, when absent, is ABSENT in
// the canonical bytes (not null): one spelling for "no key id".
function cleanParty(p, field) {
  if (!isPlainObject(p)) throw new CaseError("malformed_field", field, `${field} must be an object {side, label, key_id?}`);
  onlyFields(p, PARTY_FIELDS, field);
  requireFields(p, ["side", "label"], field);
  if (!SIDES.includes(p.side)) throw new CaseError("malformed_field", `${field}.side`, `${field}.side must be "agent" or "tool"`);
  const out = { side: p.side, label: checkText(p.label, `${field}.label`) };
  if (Object.prototype.hasOwnProperty.call(p, "key_id")) out.key_id = checkText(p.key_id, `${field}.key_id`);
  return out;
}

function compareParties(p, q) {
  const byLabel = compareCodePoints(p.label, q.label);
  return byLabel !== 0 ? byLabel : compareCodePoints(p.side, q.side);
}

// -> {party_a, party_b, reordered}. Throws parties_not_distinct on a tie.
function canonicalParties(p, q) {
  const c = compareParties(p, q);
  if (c === 0) {
    throw new CaseError("parties_not_distinct", "party_b",
      "the two parties have the same label and the same side, so the rule (label, then side) cannot order them");
  }
  return c < 0 ? { party_a: p, party_b: q, reordered: false } : { party_a: q, party_b: p, reordered: true };
}

// ---------------------------------------------------------------------------
// the case id
// ---------------------------------------------------------------------------
// The preimage object for the id, from opening-shaped fields in any party
// order and any accepted time form. Reads the six id fields and nothing else
// (an opening's `deadline` is not part of the id).
function caseIdPreimage(fields) {
  if (!isPlainObject(fields)) throw new CaseError("not_an_object", "$", "the opening must be a JSON object");
  requireFields(fields, CASE_ID_FIELDS);
  if (fields.protocol_version !== PROTOCOL_VERSION) {
    throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  }
  const policy = checkText(fields.policy_version, "policy_version");
  const scope = checkHex64(fields.scope_digest, "scope_digest");
  const { party_a, party_b } = canonicalParties(cleanParty(fields.party_a, "party_a"), cleanParty(fields.party_b, "party_b"));
  return {
    protocol_version: PROTOCOL_VERSION,
    policy_version: policy,
    scope_digest: scope,
    party_a,
    party_b,
    opened_at: normalizeUtcSeconds(fields.opened_at, "opened_at"),
  };
}

function caseIdBytes(fields) {
  return canonicalBytes(caseIdPreimage(fields));
}

function deriveCaseId(fields) {
  return sha256hex(caseIdBytes(fields));
}

// ---------------------------------------------------------------------------
// the opening
// ---------------------------------------------------------------------------
// -> {opening: {the seven fields, normalized, parties in canonical order},
//     parties_reordered}. The clock checks (future-dated, deadline already
// past) need a clock, so they are the HTTP layer's.
function validateOpening(body, { policyVersion = SUPPORTED_POLICY_VERSION } = {}) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the opening must be a JSON object");
  onlyFields(body, OPENING_FIELDS);
  requireFields(body, OPENING_FIELDS);
  if (body.protocol_version !== PROTOCOL_VERSION) {
    throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  }
  checkText(body.policy_version, "policy_version");
  if (body.policy_version !== policyVersion) {
    throw new CaseError("unsupported_policy_version", "policy_version",
      `this service runs reconcile port version ${policyVersion}; a case opened under another version could not be compared under it`);
  }
  const pre = caseIdPreimage(body);
  const { reordered } = canonicalParties(cleanParty(body.party_a, "party_a"), cleanParty(body.party_b, "party_b"));
  const deadline = normalizeUtcSeconds(body.deadline, "deadline");
  if (Date.parse(deadline) <= Date.parse(pre.opened_at)) {
    throw new CaseError("deadline_not_after_opened_at", "deadline", "deadline must be later than opened_at");
  }
  return { opening: { ...pre, deadline }, parties_reordered: reordered };
}

// The OPEN case object for a validated opening.
function newCase(opening, caseId) {
  const id = caseId === undefined ? deriveCaseId(opening) : caseId;
  return {
    v: CASE_VERSION,
    case_id: id,
    protocol_version: opening.protocol_version,
    policy_version: opening.policy_version,
    scope_digest: opening.scope_digest,
    party_a: opening.party_a,
    party_b: opening.party_b,
    opened_at: opening.opened_at,
    deadline: opening.deadline,
    commitments: { a: null, b: null },
    reveals: null,
    verdict: null,
    records: 1,
    cross_reference: null,
    status: "OPEN",
    withdrawal: null,
    limits: LIMITS.slice(),
    sig: null,
    sig_reason: UNSEALED_SIG_REASON,
  };
}

// ---------------------------------------------------------------------------
// the commitment
// ---------------------------------------------------------------------------
function commitmentPreimage(input) {
  if (!isPlainObject(input)) throw new CaseError("not_an_object", "$", "the commitment input must be an object");
  onlyFields(input, COMMITMENT_INPUT_FIELDS);
  requireFields(input, ["case_id", "role", "tape_sha256", "salt"]);
  const protocol = Object.prototype.hasOwnProperty.call(input, "protocol_version") ? input.protocol_version : PROTOCOL_VERSION;
  if (protocol !== PROTOCOL_VERSION) {
    throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  }
  checkHex64(input.case_id, "case_id");
  if (!ROLES.includes(input.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  checkHex64(input.tape_sha256, "tape_sha256");
  checkHex64(input.salt, "salt");
  return {
    case_id: input.case_id,
    role: input.role,
    tape_sha256: input.tape_sha256,
    salt: input.salt,
    protocol_version: PROTOCOL_VERSION,
  };
}

function commitmentBytes(input) {
  return canonicalBytes(commitmentPreimage(input));
}

function commitmentSha256(input) {
  return sha256hex(commitmentBytes(input));
}

// 32 random bytes as hex: the salt a party keeps until the joint reveal.
function newSalt() {
  return crypto.randomBytes(32).toString("hex");
}

const COMMITMENT_BYTES_LENGTH = commitmentBytes({
  case_id: "0".repeat(64), role: "a", tape_sha256: "0".repeat(64), salt: "0".repeat(64),
}).length;

// ---------------------------------------------------------------------------
// registrations
// ---------------------------------------------------------------------------
function validateRegistrationBody(body) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the registration must be a JSON object");
  for (const k of Object.keys(body)) {
    if (!REGISTRATION_BODY_FIELDS.includes(k)) {
      throw new CaseError("unknown_field", k,
        `unknown field ${JSON.stringify(k).slice(0, 80)}: a registration carries case_id, role and commitment_sha256 only; ` +
          "the stamp's commit and time are read from the stamp record, never taken from a caller");
    }
  }
  requireFields(body, REGISTRATION_BODY_FIELDS);
  checkHex64(body.case_id, "case_id");
  if (!ROLES.includes(body.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  checkHex64(body.commitment_sha256, "commitment_sha256");
  return { case_id: body.case_id, role: body.role, commitment_sha256: body.commitment_sha256 };
}

function checkCommitmentEntry(e, field) {
  if (!isPlainObject(e)) throw new CaseError("malformed_field", field, `${field} must be null or an object`);
  onlyFields(e, COMMITMENT_ENTRY_FIELDS, field);
  requireFields(e, COMMITMENT_ENTRY_FIELDS, field);
  checkHex64(e.commitment_sha256, `${field}.commitment_sha256`);
  if (!isUtcSeconds(e.registered_at)) throw new CaseError("malformed_field", `${field}.registered_at`, `${field}.registered_at must be UTC seconds`);
  if (e.stamp_commit !== null && (typeof e.stamp_commit !== "string" || !GIT_SHA.test(e.stamp_commit))) {
    throw new CaseError("malformed_field", `${field}.stamp_commit`, `${field}.stamp_commit must be null or a git commit id`);
  }
  if (!isIsoUtc(e.stamped_at)) throw new CaseError("malformed_field", `${field}.stamped_at`, `${field}.stamped_at must be an ISO 8601 UTC time`);
}

function registrationRecord({ case_id, role, commitment_sha256, registered_at, stamp_commit, stamped_at }) {
  const rec = { kind: REGISTRATION_KIND, v: 1, case_id, role, commitment_sha256, registered_at, stamp_commit, stamped_at };
  const r = validateRegistrationRecord(rec);
  if (!r.ok) throw new CaseError(r.code, r.field, r.error);
  return rec;
}

function validateRegistrationRecord(rec) {
  try {
    if (!isPlainObject(rec)) throw new CaseError("not_an_object", "$", "a registration record must be an object");
    onlyFields(rec, REGISTRATION_FIELDS);
    requireFields(rec, REGISTRATION_FIELDS);
    if (rec.kind !== REGISTRATION_KIND) throw new CaseError("malformed_field", "kind", `kind must be "${REGISTRATION_KIND}"`);
    if (rec.v !== 1) throw new CaseError("unknown_version", "v", "v must be 1");
    checkHex64(rec.case_id, "case_id");
    if (!ROLES.includes(rec.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
    const { kind, v, case_id, role, ...entry } = rec; // eslint-disable-line no-unused-vars
    checkCommitmentEntry(entry, "registration");
    return { ok: true };
  } catch (e) {
    if (e instanceof CaseError) return { ok: false, code: e.code, field: e.field, error: e.message };
    throw e;
  }
}

// The per-role entry of the case object, from a registration record.
function commitmentEntry(reg) {
  return {
    commitment_sha256: reg.commitment_sha256,
    registered_at: reg.registered_at,
    stamp_commit: reg.stamp_commit,
    stamped_at: reg.stamped_at,
  };
}

function sameEntry(x, y) {
  return !!x && !!y && COMMITMENT_ENTRY_FIELDS.every((k) => x[k] === y[k]);
}

// A NEW case object with `reg` projected into commitments[reg.role]. Refuses
// a case that is not OPEN or COMMITTED, and a role that already holds an
// entry. Pure: no I/O, and the argument is not mutated.
//
// STATUS NEVER REGRESSES (item 1b, after Gemini's code review: "If this
// function is somehow called on a case that has already advanced to VERDICT
// ... it will regress the status to COMMITTED"). Every status other than OPEN
// or COMMITTED (VERDICT, WITHDRAWN, a stored EXPIRED, anything unknown) is
// refused `case_not_open` before anything is computed; that guard was here in
// the item-one build. What item 1b changes is the status itself: it is no
// longer computed from the commitments, which could turn a COMMITTED case
// with an empty slot back into OPEN. The one move this function makes is
// OPEN to COMMITTED, when the second role lands; a COMMITTED case stays
// COMMITTED.
function applyRegistration(caseObj, reg) {
  if (!REGISTERABLE_STATUSES.includes(caseObj.status)) {
    throw new CaseError("case_not_open", "status", `the case is ${caseObj.status}, not OPEN or COMMITTED`);
  }
  if (caseObj.case_id !== reg.case_id) throw new CaseError("case_id_mismatch", "case_id", "the registration is for another case");
  if (caseObj.commitments[reg.role] !== null) {
    throw new CaseError("role_already_committed", "role", `role ${reg.role} already has a registered commitment`);
  }
  const commitments = { ...caseObj.commitments, [reg.role]: commitmentEntry(reg) };
  const both = commitments.a !== null && commitments.b !== null;
  const status = caseObj.status === "OPEN" && both ? "COMMITTED" : caseObj.status;
  return { ...caseObj, commitments, status };
}

function pastDeadline(caseObj, nowMs) {
  return nowMs >= Date.parse(caseObj.deadline);
}

// ---------------------------------------------------------------------------
// the case object: validation (never throws)
// ---------------------------------------------------------------------------
function checkSig(rec) {
  if (rec.sig !== null && (typeof rec.sig !== "string" || rec.sig === "")) {
    throw new CaseError("malformed_field", "sig", "sig must be null or a non-empty string");
  }
  if (rec.sig_reason !== null && (typeof rec.sig_reason !== "string" || rec.sig_reason === "")) {
    throw new CaseError("malformed_field", "sig_reason", "sig_reason must be null or a non-empty string");
  }
  if (rec.sig === null && rec.sig_reason === null) {
    throw new CaseError("sig_reason_missing", "sig_reason", "an unsigned case must say why (sig_reason)");
  }
  if (rec.sig !== null && rec.sig_reason !== null) {
    throw new CaseError("malformed_field", "sig_reason", "a signed case carries no sig_reason");
  }
}

function checkLimits(rec) {
  const l = rec.limits;
  if (!Array.isArray(l) || l.length !== LIMITS.length || l.some((s, i) => s !== LIMITS[i])) {
    throw new CaseError("limits_altered", "limits", "limits must be the four non-claims, unaltered and in order");
  }
}

function checkWithdrawal(w, field) {
  if (!isPlainObject(w)) throw new CaseError("malformed_field", field, `${field} must be an object {by_role, at}`);
  onlyFields(w, WITHDRAWAL_FIELDS, field);
  requireFields(w, WITHDRAWAL_FIELDS, field);
  if (!ROLES.includes(w.by_role)) throw new CaseError("bad_role", `${field}.by_role`, 'by_role must be "a" or "b"');
  if (!isUtcSeconds(w.at)) throw new CaseError("malformed_field", `${field}.at`, `${field}.at must be UTC seconds`);
}

function checkWithdrawn(rec) {
  onlyFields(rec, WITHDRAWN_FIELDS);
  requireFields(rec, WITHDRAWN_FIELDS);
  if (rec.v !== CASE_VERSION) throw new CaseError("unknown_version", "v", "v must be 1");
  checkHex64(rec.case_id, "case_id");
  if (rec.protocol_version !== PROTOCOL_VERSION) throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  if (!isUtcSeconds(rec.opened_at)) throw new CaseError("malformed_field", "opened_at", "opened_at must be UTC seconds");
  checkWithdrawal(rec.withdrawal, "withdrawal");
  checkLimits(rec);
  checkSig(rec);
}

function checkFull(rec) {
  onlyFields(rec, TOP_LEVEL_FIELDS);
  requireFields(rec, TOP_LEVEL_FIELDS);
  if (rec.v !== CASE_VERSION) throw new CaseError("unknown_version", "v", "v must be 1");
  checkHex64(rec.case_id, "case_id");
  if (rec.protocol_version !== PROTOCOL_VERSION) throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  checkText(rec.policy_version, "policy_version");
  checkHex64(rec.scope_digest, "scope_digest");
  const pa = cleanParty(rec.party_a, "party_a");
  const pb = cleanParty(rec.party_b, "party_b");
  const order = compareParties(pa, pb);
  if (order === 0) throw new CaseError("parties_not_distinct", "party_b", "the two parties cannot be ordered");
  if (order > 0) throw new CaseError("parties_not_canonical", "party_a", "party_a must be the party that sorts first (label, then side)");
  for (const f of ["opened_at", "deadline"]) {
    if (!isUtcSeconds(rec[f])) throw new CaseError("malformed_field", f, `${f} must be UTC seconds (YYYY-MM-DDTHH:MM:SSZ)`);
  }
  if (Date.parse(rec.deadline) <= Date.parse(rec.opened_at)) {
    throw new CaseError("deadline_not_after_opened_at", "deadline", "deadline must be later than opened_at");
  }
  if (deriveCaseId(rec) !== rec.case_id) {
    throw new CaseError("case_id_mismatch", "case_id", "case_id is not the id this case's own opening fields derive");
  }

  const c = rec.commitments;
  if (!isPlainObject(c)) throw new CaseError("malformed_field", "commitments", "commitments must be an object {a, b}");
  onlyFields(c, ROLES, "commitments");
  requireFields(c, ROLES, "commitments");
  for (const r of ROLES) {
    if (c[r] === null) continue;
    checkCommitmentEntry(c[r], `commitments.${r}`);
    if (Date.parse(c[r].registered_at) >= Date.parse(rec.deadline)) {
      throw new CaseError("status_inconsistent", `commitments.${r}.registered_at`, "a registration must be received before the deadline");
    }
  }
  if (c.a !== null && c.b !== null && c.a.commitment_sha256 === c.b.commitment_sha256) {
    throw new CaseError("duplicate_commitment", "commitments.b", "one commitment hash cannot be registered to both roles");
  }

  if (rec.reveals !== null) {
    if (!isPlainObject(rec.reveals)) throw new CaseError("malformed_field", "reveals", "reveals must be null or an object {a, b}");
    onlyFields(rec.reveals, ROLES, "reveals");
    requireFields(rec.reveals, ROLES, "reveals");
    for (const r of ROLES) {
      const e = rec.reveals[r];
      const f = `reveals.${r}`;
      if (!isPlainObject(e)) throw new CaseError("malformed_field", f, `${f} must be an object`);
      onlyFields(e, REVEAL_ENTRY_FIELDS, f);
      requireFields(e, REVEAL_ENTRY_FIELDS, f);
      checkHex64(e.tape_sha256, `${f}.tape_sha256`);
      checkHex64(e.salt_sha256, `${f}.salt_sha256`);
      if (!isUtcSeconds(e.revealed_at)) throw new CaseError("malformed_field", `${f}.revealed_at`, `${f}.revealed_at must be UTC seconds`);
    }
  }
  // The receipt in full (lib/_reconcile_receipt.js). Item two writes it and
  // owns its deeper check; here it must at least be an object.
  if (rec.verdict !== null && !isPlainObject(rec.verdict)) {
    throw new CaseError("malformed_field", "verdict", "verdict must be null or the reconcile receipt object");
  }

  if (rec.cross_reference !== null) {
    const x = rec.cross_reference;
    if (!isPlainObject(x)) throw new CaseError("malformed_field", "cross_reference", "cross_reference must be null or an object");
    onlyFields(x, CROSS_REFERENCE_FIELDS, "cross_reference");
    requireFields(x, CROSS_REFERENCE_FIELDS, "cross_reference");
    checkText(x.operator, "cross_reference.operator");
    checkText(x.reference, "cross_reference.reference");
    if (typeof x.url !== "string" || !/^https:\/\/\S+$/.test(x.url)) {
      throw new CaseError("malformed_field", "cross_reference.url", "cross_reference.url must be an https URL");
    }
    if (!isUtcSeconds(x.recorded_at)) throw new CaseError("malformed_field", "cross_reference.recorded_at", "cross_reference.recorded_at must be UTC seconds");
  }
  if (rec.records !== (rec.cross_reference === null ? 1 : 2)) {
    throw new CaseError("status_inconsistent", "records", "records is 2 only with a cross_reference, and 1 without one");
  }

  if (!STATUSES.includes(rec.status)) throw new CaseError("malformed_field", "status", `status must be one of ${STATUSES.join(", ")}`);
  if (!STORED_STATUSES.includes(rec.status)) {
    throw new CaseError("malformed_field", "status", "EXPIRED is computed on read from the deadline; it is never stored");
  }
  if (rec.withdrawal !== null) {
    throw new CaseError("status_inconsistent", "withdrawal", "a withdrawn case is the redacted record, never a full case object");
  }
  const both = c.a !== null && c.b !== null;
  const bad = (why) => { throw new CaseError("status_inconsistent", "status", `${rec.status}: ${why}`); };
  if (rec.status === "OPEN") {
    if (both) bad("both roles are registered, so the status is COMMITTED");
    if (rec.reveals !== null || rec.verdict !== null) bad("an open case has no reveals and no verdict");
  } else if (rec.status === "COMMITTED") {
    if (!both) bad("both roles must be registered");
    if (rec.reveals !== null || rec.verdict !== null) bad("a committed case has no reveals and no verdict");
  } else if (rec.status === "VERDICT") {
    if (!both) bad("both roles must be registered");
    if (rec.reveals === null || rec.verdict === null) bad("a verdict needs both reveals and the receipt");
  }

  checkLimits(rec);
  checkSig(rec);
}

function validateCase(rec) {
  try {
    if (!isPlainObject(rec)) throw new CaseError("not_an_object", "$", "a case must be a JSON object");
    if (rec.status === "WITHDRAWN") checkWithdrawn(rec);
    else checkFull(rec);
    return { ok: true };
  } catch (e) {
    if (e instanceof CaseError) return { ok: false, code: e.code, field: e.field, error: e.message };
    throw e;
  }
}

// ---------------------------------------------------------------------------
// where things live (the pins repository, design "The commitment format")
// ---------------------------------------------------------------------------
function casePath(caseId) {
  checkHex64(caseId, "case_id");
  return `cases/${caseId}.json`;
}

function registrationPath(caseId, role) {
  checkHex64(caseId, "case_id");
  if (!ROLES.includes(role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  return `cases/${caseId}/commit_${role}.json`;
}

module.exports = {
  SCHEMA,
  CASE_VERSION,
  PROTOCOL_VERSION,
  SUPPORTED_POLICY_VERSION,
  ROLES,
  SIDES,
  STATUSES,
  STORED_STATUSES,
  REGISTERABLE_STATUSES,
  TOP_LEVEL_FIELDS,
  WITHDRAWN_FIELDS,
  OPENING_FIELDS,
  CASE_ID_FIELDS,
  REGISTRATION_KIND,
  REGISTRATION_FIELDS,
  REGISTRATION_BODY_FIELDS,
  LIMITS,
  UNSEALED_SIG_REASON,
  CASE_ERROR_CODES,
  COMMITMENT_BYTES_LENGTH,
  CaseError,
  compareCodePoints,
  normalizeUtcSeconds,
  utcSeconds,
  isUtcSeconds,
  isIsoUtc,
  canonicalParties,
  caseIdPreimage,
  caseIdBytes,
  deriveCaseId,
  validateOpening,
  newCase,
  commitmentPreimage,
  commitmentBytes,
  commitmentSha256,
  newSalt,
  validateRegistrationBody,
  registrationRecord,
  validateRegistrationRecord,
  commitmentEntry,
  sameEntry,
  applyRegistration,
  pastDeadline,
  validateCase,
  casePath,
  registrationPath,
};

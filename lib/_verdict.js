// lib/_verdict.js — the verdict is a REQUIRED argument, never a default.
//
// The defect class this closes (found 2026-09-19/20 in the receipt proxy's
// health endpoint, one repo over): a library verify step said "this ledger is
// broken" and a wrapper above it ignored that and built a well-formed success
// out of DEFAULT values — rows 0, chain "genesis", ok true. A damaged log read
// as a brand-new one. The patch fixed the call site. This file is for the
// class: in this codebase a success-shaped answer about a stored record can be
// built only by handing over an explicit verdict about that record.
//
// Three rules, all enforced by throwing rather than by convention:
//   1. No verdict, no answer. requireVerdict(undefined) THROWS. Nothing in
//      this file has a default value for ok / state / value.
//   2. Red never renders green. success() and counterValue() THROW on a red
//      verdict; the caller has to take the red branch on purpose.
//   3. Empty is a verdict, not a fallthrough. A brand-new namespace, a key
//      that never bought credit, a day with no stamps yet — those are real
//      states, and they are reachable ONLY through verifiedEmpty(), which the
//      judges below mint in exactly one situation: the store said 404 (the
//      readers return null for that and for nothing else). A document that is
//      present but unreadable is RED. "Nothing there" and "something there I
//      cannot read" never share a value.
//   4. (2026-09-22) A green is bound to a read. judgeRead is the only thing
//      that issues a read_id, and every green verdict carries the read_id of
//      the store read it was judged from. requireVerdict / requireGreen /
//      success() refuse a green that carries no read_id, or one this module
//      did not mint. A hand-built {ok: true, state: "verified_record"} cannot
//      be rendered: there is no public constructor of a green any more.
//   5. (2026-09-22) judgeRead never returns null. A read that is present and
//      an object used to come back as null ("the caller's shape rules
//      decide"), which a future raw caller could read as green: the default
//      rule 1 forbids, reintroduced one layer down. It now comes back as the
//      typed verdict `present_unchecked`, which is NOT green; requireGreen
//      refuses it by name. Only a judge with shape rules (judgePin,
//      judgeCounter, judgeWith) turns it into a record or a red.
//   6. (2026-09-22) A verdict can be bound to its record. requireVerdict,
//      requireGreen, isEmpty, success, counterValue and refusal take an
//      optional `expect` of {what}; when it is given, a verdict whose `what`
//      is not that record is refused (VerdictMismatchError), so a green judged
//      from one record cannot gate an answer about another. Opt-in, because
//      the verdict only knows the label its judge was handed: the binding is as
//      specific as that label (a pin path is; "stamp record" is not).
//   Rules 4 and 5 were raised by atomic-raven on the Colony (post 42b8d6e0);
//   our reply, comment 43bed67b, said we would make them as he described.
//
// Not an endpoint: lives in lib/ (Vercel Hobby's 12-function cap counts api/).

"use strict";

const STATES = Object.freeze({
  RECORD: "verified_record", // a stored document was read and has the shape it must have
  EMPTY: "verified_empty",   // the store answered 404: nothing has been recorded yet
  UNCHECKED: "present_unchecked", // the store answered with an object; no shape rule has judged it. NOT green.
});

class VerdictRequiredError extends Error {
  constructor(where, got) {
    const shape = got === null ? "null" : Array.isArray(got) ? "array" : typeof got;
    super(
      `${where || "verdict"}: a verdict is required and none was given (got ${shape}) — ` +
      "refusing to build an answer from defaults"
    );
    this.name = "VerdictRequiredError";
    this.code = "verdict_required";
  }
}

class RedVerdictError extends Error {
  constructor(where, verdict) {
    super(`${where || "verdict"}: red verdict (${verdict.reason}) cannot be rendered as a success`);
    this.name = "RedVerdictError";
    this.code = "red_verdict";
    this.verdict = verdict;
  }
}

// A green that was not minted from a judged read. Subclass of
// VerdictRequiredError on purpose: an unbound green is not a verdict.
class UnboundVerdictError extends VerdictRequiredError {
  constructor(where, why) {
    super(where, undefined);
    this.message =
      `${where || "verdict"}: green verdict is not bound to a store read (${why}) — ` +
      "only a judge over a read that judgeRead issued can mint a green";
    this.name = "UnboundVerdictError";
    this.code = "verdict_unbound";
  }
}

// A verdict about one record offered as the gate for an answer about another.
class VerdictMismatchError extends VerdictRequiredError {
  constructor(where, got, want) {
    super(where, undefined);
    this.message =
      `${where || "verdict"}: the verdict is about ${JSON.stringify(got)} and this answer is about ` +
      `${JSON.stringify(want)} — a verdict gates only the record it was judged from`;
    this.name = "VerdictMismatchError";
    this.code = "verdict_what_mismatch";
  }
}

// A present read that no shape rule has judged, handed to something that
// needed green. Named, so the log says WHICH mistake it was.
class PresentUncheckedError extends Error {
  constructor(where, v) {
    super(
      `${where || "verdict"}: the store read of ${v.what} is present but no shape rule has judged it ` +
      "(present_unchecked) — refusing to treat 'present and an object' as green"
    );
    this.name = "PresentUncheckedError";
    this.code = "present_unchecked";
    this.verdict = v;
  }
}

// ---- read binding ----
// ISSUED_READS holds every read_id judgeRead has handed out. BOUND maps each
// verdict this module minted from a read to that read_id. Both are private:
// nothing outside this file can add to them, so a verdict object built
// anywhere else (a literal, a spread copy, a frozen clone) is never in BOUND.
const ISSUED_READS = new Set();
const BOUND = new WeakMap();
let readSeq = 0;

function issueReadId() {
  readSeq += 1;
  const id = `read-${readSeq.toString(36)}`;
  ISSUED_READS.add(id);
  return id;
}

function mintBound(body, readId) {
  if (typeof readId !== "string" || !ISSUED_READS.has(readId)) {
    throw new UnboundVerdictError(`mint(${body.what})`, "read_id was not issued by judgeRead");
  }
  const v = Object.freeze({ ...body, read_id: readId });
  BOUND.set(v, readId);
  return v;
}

// ---- minting ----
// Greens are minted only here, only from a read_id judgeRead issued. There is
// no exported verifiedRecord / verifiedEmpty any more (until 2026-09-22 there
// was, and api/fulfill.js and lib/_stamp.js used it to mint greens with no
// store read behind them).
function verifiedRecord(what, readId, extra) {
  return mintBound({ ...(extra || {}), ok: true, state: STATES.RECORD, what: String(what) }, readId);
}
function verifiedEmpty(what, readId, extra) {
  return mintBound({ ...(extra || {}), ok: true, state: STATES.EMPTY, what: String(what) }, readId);
}
function presentUnchecked(what, readId) {
  return mintBound({ ok: false, state: STATES.UNCHECKED, what: String(what), reason: STATES.UNCHECKED }, readId);
}
function red(what, reason, detail) {
  if (typeof reason !== "string" || !reason) {
    throw new VerdictRequiredError(`red(${what})`, reason);
  }
  return Object.freeze({ ok: false, what: String(what), reason, detail: detail ? String(detail) : null });
}

// Throws unless `v` is an object whose `ok` is an explicit boolean — and, when
// green, names WHICH green it is. `{}`, `undefined`, `{ok: 1}`, `{ok: true}`
// with no state: all thrown. Returns the verdict so it can be used inline.
function requireVerdict(v, where, expect) {
  if (!v || typeof v !== "object" || Array.isArray(v) || typeof v.ok !== "boolean") {
    throw new VerdictRequiredError(where, v);
  }
  // Rule 6: bound to a record when the caller names one.
  if (expect !== undefined && expect !== null) {
    if (typeof expect !== "object" || typeof expect.what !== "string" || !expect.what) {
      throw new TypeError(`${where || "verdict"}: expect must be {what: <non-empty string>}`);
    }
    if (v.what !== expect.what) throw new VerdictMismatchError(where, v.what, expect.what);
  }
  if (v.ok === true && v.state !== STATES.RECORD && v.state !== STATES.EMPTY) {
    throw new VerdictRequiredError(`${where || "verdict"} (green without a state)`, v.state);
  }
  if (v.ok === false && (typeof v.reason !== "string" || !v.reason)) {
    throw new VerdictRequiredError(`${where || "verdict"} (red without a reason)`, v.reason);
  }
  if (v.ok === true || v.state === STATES.UNCHECKED) {
    // Rule 4: a green (and a present_unchecked, which claims a read) must be
    // the very object this module minted from an issued read.
    if (typeof v.read_id !== "string" || !v.read_id) throw new UnboundVerdictError(where, "no read_id");
    if (!ISSUED_READS.has(v.read_id)) throw new UnboundVerdictError(where, `read_id ${v.read_id} was not issued by judgeRead`);
    if (BOUND.get(v) !== v.read_id) throw new UnboundVerdictError(where, "verdict was not minted by a judge");
  }
  return v;
}

function requireGreen(v, where, expect) {
  requireVerdict(v, where, expect);
  if (v.state === STATES.UNCHECKED) throw new PresentUncheckedError(where, v);
  if (!v.ok) throw new RedVerdictError(where, v);
  return v;
}

function isEmpty(v, where, expect) {
  return requireVerdict(v, where, expect).ok === true && v.state === STATES.EMPTY;
}

// The ONLY constructor of an `ok: true` body on the record-reading endpoints.
// `fields` may not smuggle its own `ok`.
function success(v, fields, where, expect) {
  requireGreen(v, where || "success", expect);
  if (fields && Object.prototype.hasOwnProperty.call(fields, "ok")) {
    throw new TypeError("success(): `ok` comes from the verdict, never from the fields");
  }
  return { ok: true, ...(fields || {}) };
}

// The red branch, as a response. 503: the store answered, and what it holds
// cannot be read as the record it should be. Never 200, never a 404 (a 404
// here would say "nothing recorded", which is the lie this file exists for).
function refusal(v, where, expect) {
  requireVerdict(v, where || "refusal", expect);
  if (v.ok) throw new TypeError("refusal(): verdict is green; there is nothing to refuse");
  return {
    status: 503,
    body: {
      ok: false,
      error: `stored ${v.what} is present but cannot be read as a valid record`,
      reason: v.reason,
      ...(v.detail ? { detail: v.detail } : {}),
      note:
        "this is NOT 'nothing recorded' and NOT a refutation: something is stored here and it does not have " +
        "the shape it must have, so this service declines to answer from it. The commit history of the " +
        "public repo is the authority.",
    },
  };
}

function isPlainObject(x) {
  return !!x && typeof x === "object" && !Array.isArray(x);
}

// ---- judges: a store read in, a verdict out ----
//
// `got` is exactly what the store readers return: null (404) or {json, sha}.
// `undefined` is neither — it means the caller never did the read — and throws.
//
// Never returns null (rule 5). Three answers, all verdicts:
//   verified_empty     the store said 404                        (green, bound)
//   red                present but not a JSON object              (not green)
//   present_unchecked  present and an object; shape NOT judged    (not green, bound)
// Damaged reads reach this function one way only: valid-but-partial JSON
// (a non-200/404 and an unparseable body both throw in the store readers),
// which is why the third answer must not be green.
function judgeRead(got, what) {
  if (got === undefined) throw new VerdictRequiredError(`judge(${what}): no store read was passed`, got);
  const readId = issueReadId();
  if (got === null) return verifiedEmpty(what, readId);
  if (!isPlainObject(got) || !isPlainObject(got.json)) {
    return red(what, "not_a_json_object");
  }
  return presentUnchecked(what, readId);
}

// The one door from present_unchecked to a record: a shape rule. `rule(json)`
// returns a reason string (red), or an object of extra verdict fields /
// `true` (green). Anything else is a rule that did not decide, and throws.
// `onEmpty(readId)` lets a judge give its 404 a value (a counter's 0).
function judgeWith(got, what, rule, onEmpty) {
  if (typeof rule !== "function") throw new VerdictRequiredError(`judgeWith(${what}): a shape rule`, rule);
  const first = judgeRead(got, what);
  if (first.state === STATES.EMPTY) return onEmpty ? onEmpty(first.read_id) : first;
  if (first.state !== STATES.UNCHECKED) return first; // red from judgeRead
  const out = rule(got.json);
  if (typeof out === "string" && out) return red(what, out);
  if (out === true) return verifiedRecord(what, first.read_id);
  if (isPlainObject(out) && !("ok" in out) && !("state" in out) && !("read_id" in out)) {
    return verifiedRecord(what, first.read_id, out);
  }
  throw new VerdictRequiredError(`judgeWith(${what}): the shape rule returned neither a reason nor a pass`, out);
}

const CHAIN_RE = /^[0-9a-fA-F]{8,64}$/; // same rule as lib/_store.js CHAIN_RE (kept local: _store requires nothing from here, and this file requires nothing at all)

// A stored pin record (pins/<ns>/latest.json or a numbered seq record). Every
// record this service has ever written carries these four fields (they are in
// the first commit of api/pin.js), so none of them is "legacy-optional".
//
// NOT A CASE SEAL (case protocol item 2b). A case seal's pin
// (pins/case/<case_id>/, lib/_case_seal.js) is its own record type with its
// own judge, judgeCaseSeal below. This judge refuses one by name, whether it
// is recognised by its record_kind or by its namespace, so no generic reader
// (the status page, /api/latest, /api/verify) can ever take a case seal for
// a namespace's head, or a namespace's head for a case seal.
function judgePin(got, { what = "pin record", namespace = null } = {}) {
  // judgeRead (inside judgeWith) answers 404 / not-an-object; present_unchecked
  // goes on to these shape rules and comes out verifiedRecord or red.
  return judgeWith(got, what, (p) => {
    if (p.record_kind === CASE_SEAL.record_kind || (typeof p.namespace === "string" && p.namespace.startsWith(CASE_SEAL_NS_PREFIX))) {
      return "case_seal_not_a_generic_pin";
    }
    if (!Number.isSafeInteger(p.rows) || p.rows < 1) return "rows_unreadable";
    if (typeof p.chain !== "string" || !CHAIN_RE.test(p.chain)) return "chain_unreadable";
    if (!Number.isSafeInteger(p.seq) || p.seq < 1) return "seq_unreadable";
    if (namespace !== null && p.namespace !== namespace) return "namespace_mismatch";
    return true;
  });
}

// ---- the case_seal record type (case protocol item 2b) ----
//
// The pin a sealed case is pinned by, pins/case/<case_id>/00000001.json and
// its pointer latest.json, written by lib/_case_seal.js pinChain and nothing
// else (POST /api/pin cannot write there: its namespace rule refuses the
// slash). Exactly these eight fields, every one required:
//   namespace    "case/<64 lowercase hex case id>"
//   rows         3: the case's three records (two registration files and the
//                sealed case file)
//   chain        64 lowercase hex: sha256 of the sealed case's json-c14n:v1
//                bytes minus sig
//   pinned_at    ISO 8601 UTC with milliseconds (toISOString), this service's
//                clock when it pinned
//   seq          1: one pin per case, ever
//   record_kind  "case_seal"
//   auth_level   "case-seal": no bearer key wrote it
//   auth_note    a non-empty sentence saying so
// and, since Design J (2026-10-12; lib/_case_seal.js TWO WRITES), one more,
// written in every pin since and absent only from a pin written before:
//   case_commit  40 lowercase hex: the pins-repository commit that wrote the
//                sealed case file. A pin without it reads commit_unrecorded.
// No cadence field: a seal promises no next pin, and a next_pin_due_by would
// read as overdue a day later. A field outside these is refused, a missing
// one is refused, and a wrong value is refused, each by name.
const CASE_SEAL_FIELDS = Object.freeze([
  "namespace", "rows", "chain", "pinned_at", "seq", "record_kind", "auth_level", "auth_note",
]);
const CASE_SEAL_OPTIONAL = Object.freeze(["case_commit"]);
const GIT_COMMIT_RE = /^[0-9a-f]{40}$/;
const CASE_SEAL = Object.freeze({ record_kind: "case_seal", auth_level: "case-seal", rows: 3, seq: 1 });
const CASE_SEAL_NS_PREFIX = "case/";
const CASE_SEAL_NS_RE = /^case\/[0-9a-f]{64}$/;
const CASE_SEAL_CHAIN_RE = /^[0-9a-f]{64}$/;
const CASE_SEAL_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CASE_SEAL_NOTE_MAX = 2000;

function judgeCaseSeal(got, { what = "case seal record", namespace = null } = {}) {
  return judgeWith(got, what, (p) => {
    for (const k of Object.keys(p)) if (!CASE_SEAL_FIELDS.includes(k) && !CASE_SEAL_OPTIONAL.includes(k)) return "case_seal_unknown_field";
    for (const k of CASE_SEAL_FIELDS) if (!Object.prototype.hasOwnProperty.call(p, k)) return "case_seal_missing_field";
    if (p.record_kind !== CASE_SEAL.record_kind) return "case_seal_wrong_record_kind";
    if (p.auth_level !== CASE_SEAL.auth_level) return "case_seal_wrong_auth_level";
    if (typeof p.namespace !== "string" || !CASE_SEAL_NS_RE.test(p.namespace)) return "case_seal_namespace_unreadable";
    if (namespace !== null && p.namespace !== namespace) return "namespace_mismatch";
    if (p.rows !== CASE_SEAL.rows) return "case_seal_wrong_rows";
    if (p.seq !== CASE_SEAL.seq) return "case_seal_wrong_seq";
    if (typeof p.chain !== "string" || !CASE_SEAL_CHAIN_RE.test(p.chain)) return "chain_unreadable";
    if (typeof p.pinned_at !== "string" || !CASE_SEAL_TIME_RE.test(p.pinned_at) || !Number.isFinite(Date.parse(p.pinned_at))) {
      return "case_seal_pinned_at_unreadable";
    }
    if (typeof p.auth_note !== "string" || p.auth_note.trim() === "" || p.auth_note.length > CASE_SEAL_NOTE_MAX) {
      return "case_seal_auth_note_unreadable";
    }
    if (Object.prototype.hasOwnProperty.call(p, "case_commit") && (typeof p.case_commit !== "string" || !GIT_COMMIT_RE.test(p.case_commit))) {
      return "case_seal_case_commit_unreadable";
    }
    return true;
  });
}

// A stored counter document (credit balance, monthly usage, a day's stamp
// budget). 404 -> verified empty, value 0. Present with a readable number ->
// that number. Present WITHOUT one -> red. `|| 0` is the expression this
// replaces: it read a damaged balance as "never bought anything", and a
// damaged usage counter as "has used nothing this month" — the second one
// fails OPEN.
function judgeCounter(got, field, { what = "counter", integer = false } = {}) {
  return judgeWith(got, what, (json) => {
    const n = json[field];
    if (typeof n !== "number" || !Number.isFinite(n) || n < 0 || (integer && !Number.isInteger(n))) {
      return `${field}_unreadable`;
    }
    return { value: n };
  }, (readId) => verifiedEmpty(what, readId, { value: 0 }));
}

// The number out of a counter verdict. Throws on red and on no-verdict, so a
// caller cannot reach a number without having looked.
function counterValue(v, where, expect) {
  requireGreen(v, where || "counterValue", expect);
  if (typeof v.value !== "number") throw new VerdictRequiredError(`${where || "counterValue"} (verdict carries no value)`, v.value);
  return v.value;
}

// A listing the GitHub API must answer with an array. A 200 that is not an
// array (the path is a file, or the body is not what we think it is) used to
// read as "an empty directory" — the listing twin of rows:0/chain:genesis.
function requireListing(body, what) {
  if (!Array.isArray(body)) {
    const err = new Error(`${what}: the store answered 200 but not with a listing — refusing to read that as empty`);
    err.code = "listing_unreadable";
    throw err;
  }
  return body;
}

module.exports = {
  STATES,
  VerdictRequiredError,
  RedVerdictError,
  UnboundVerdictError,
  VerdictMismatchError,
  PresentUncheckedError,
  red,
  requireVerdict,
  requireGreen,
  isEmpty,
  success,
  refusal,
  judgeRead,
  judgeWith,
  judgePin,
  judgeCaseSeal,
  CASE_SEAL_FIELDS,
  CASE_SEAL,
  judgeCounter,
  counterValue,
  requireListing,
};

// _case_seal.js — the seal of a case: the sealed case object, its signature,
// its chain, its pin, and the check of the reconcile receipt it carries.
// Underscore prefix = not routed as a serverless function.
//
// WHAT THIS IS (CASE_PROTOCOL_DESIGN_2026-10-10.md, velouria
// projects/arcaeon/, "The joint reveal and its refusals", step 5, and the
// decisions after the item-one build, 2, 7 and 11). lib/_case_http.js's
// ?op=case-reveal checks a joint reveal, runs the existing reconcile once,
// and hands this file the reconcile receipt. This file checks that receipt,
// builds the sealed case object (status VERDICT), signs it, writes nothing
// itself except the pin, and answers the one question the page will ask of
// a seal: is it anchored yet. The case file write is lib/_case_http.js's.
//
// THE SEALED OBJECT. The COMMITTED case, plus:
//   status: "VERDICT";
//   reveals: per role {tape_sha256, salt_sha256, revealed_at}. salt_sha256
//     is lib/_case.js saltSha256, the sha256 of the salt's 32 bytes; the
//     salt itself is never stored (design: "Never a tape, never a salt");
//     revealed_at is this service's clock when the request arrived, one time
//     for both roles because there is one request;
//   verdict: the reconcile receipt in full (lib/_reconcile_receipt.js),
//     exactly as ?op=reconcile would have signed it for these two tapes;
//   records: 1, or 2 when the reveal carried a cross_reference, which is
//     recorded as {operator, reference, url, recorded_at} with recorded_at
//     the same service clock (design decision 11);
//   sig / sig_reason (THE SIGNATURE, below).
// After this the object never changes (design decision 2: "The sealed object
// never changes after sealing"). There is no `anchor` field: whether the
// seal is anchored is read from the pin, at render time, never stored.
//
// THE SIGNATURE. The lib/_check_record.js rule: Ed25519 over the json-c14n:v1
// bytes of the whole case minus `sig` (that file's `preimage`), so every
// field, the four limits and the receipt included, is inside the signed
// bytes. The key is its own key (design decision 7): WITNESS_CASE_SIGNER_KEY,
// in the signer-string shape of lib/_checkpoint.js and the reconcile signer,
//   PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 || seed)>,
// and it is never the witness log's key (WITNESS_LOG_SIGNER_KEY) or the
// reconcile receipt's key (WITNESS_RECONCILE_SIGNER_KEY). A receipt says
// "these two tapes compared like this"; a sealed case says "these
// commitments, these reveals and that receipt belong to this case". A reader
// who could not tell the two signatures apart could carry one claim's
// strength onto the other, so the keys stay apart. When either other key is
// set in the same environment and has the same public key (or the same
// string), the case is not signed, and says why. The guard can only see the
// keys this process can see: the log key normally lives with the
// publisher, not here, so the real fence is that the variable is its own.
// Unset, unparseable or refused, the case is sealed UNSIGNED: `sig: null`
// with `sig_reason` naming the reason (never the key). An unsigned seal is
// still a seal: the verdict is the same, the signature is missing.
//   The case object has no field naming its key (the design's table has
// none, and an unknown field is refused). The reveal's answer carries the
// verifier string, <name>+<8 hex>+<base64(0x01 || pub)>, and verifyCase
// takes one: a reader holds the published verifier, as for the log.
//
// THE CHAIN AND THE PIN (design: "pins {namespace: "case/<case_id>", rows:
// 3, chain: sha256(json-c14n(case minus sig))}. The case file is
// authoritative; the pin is its anchor."). The chain is the sha256 of the
// SAME bytes the signature covers, so a pinned chain fixes the signed bytes.
// The pin goes through the store, not through POST /api/pin (no bearer key,
// no meter, no credit: it is this service's own record of its own seal), on
// the two paths api/pin.js writes a pin to and in the same order:
//   pins/case/<case_id>/00000001.json   the numbered record, create-only,
//   pins/case/<case_id>/latest.json     then the pointer,
// each read back through lib/_verdict.js judgePin. One pin per case, ever,
// so seq is 1. rows is 3: the case's three records, its two registration
// files and the sealed case file. The record is {namespace, rows, chain,
// pinned_at, seq, record_kind: "case_seal", auth_level, auth_note}; it
// carries none of api/pin.js's cadence fields, because a seal promises no
// next pin.
//   "case/<case_id>" is not a namespace api/pin.js accepts (lib/_store.js
// validatePin: [a-z0-9-]{1,64}), so no bearer key can ever write a pin into
// a case's namespace, before or after the seal. Two readers do not know
// about it yet: lib/_logtree.js's leaf table reads pins/<ns>/<seq>.json one
// level deep, so a case pin is not a leaf of the witness log, and the status
// page lists every directory under pins/ as a namespace, so it would read
// pins/case as one. Both are item 2b's to settle before any deploy; nothing
// here is deployed.
//
// TWO WRITES, AND WHICH ONE IS AUTHORITATIVE. The case file first, then the
// pin. A case file write that fails leaves no pin (the pin is never
// attempted) and the case COMMITTED. A pin that fails after the case file
// landed leaves the case standing, sealed: the reveal answers with
// `pin: "pending"`, and anchorState computes the same answer from the pin's
// absence. anchorCase(case_id) is the retry: it reads the stored case file,
// recomputes the chain from it, and pins that, so a retry cannot change the
// chain. A numbered record left by an earlier attempt whose pointer write
// failed is adopted when it holds this chain (api/pin.js's healIfWedged
// adopts a verified orphan the same way). A pin under the case's namespace
// with any other chain is never written over: `pin: "conflict"`.
//
// THE RECEIPT CHECK (design decision 11: "the reveal validates the reconcile
// receipt's structure and signature and takes reveal and addendum times
// from the service clock"). Before anything is sealed, checkReceipt holds
// the receipt to: exactly the receipt's fields; its kind, version, claim
// and five non-claims verbatim; this build's method block, whose port
// version is the case's policy_version; each received-tape digest equal to
// the tape_sha256 committed for its role (tape_a is role a's), and its byte
// count the submitted tape's; the verdict block and verdict_digest equal to
// the comparison's own result; compared_at equal to the reveal's service
// time; and, when WITNESS_RECONCILE_SIGNER_KEY is set, a signature that
// verifies under it (lib/_reconcile_receipt.js verifyReceiptText), or, when
// it is not, `sig: null` with the loader's own reason. A receipt that fails
// is this service's defect, not the caller's: nothing is sealed.
//
// JSON. The receipt holds the verdict's call index as a BigInt (the port
// keeps Python's arbitrary-precision ints). A case file is JSON, and JSON
// read by this service is read as doubles, so storableReceipt turns each
// BigInt into a Number only when that is exact (at most 2^53 - 1), and
// proves the stored form signs the same bytes. A verdict at a call index
// past that cannot be sealed without changing the receipt's signed bytes;
// it is refused, and the tapes, already committed, stay unsealed.
//
// NOTHING ELSE IS KEPT. No tape and no salt reaches anything this file
// writes or logs.

"use strict";

const crypto = require("node:crypto");
const C = require("./_case.js");
const store = require("./_store.js");
const verdict = require("./_verdict.js");
const checkpoint = require("./_checkpoint.js");
const checkRecord = require("./_check_record.js");
const receipts = require("./_reconcile_receipt.js");
const T = require("./_reconcile_tapes.js");

const CASE_SIGNER_ENV = "WITNESS_CASE_SIGNER_KEY";
// The two keys a case is never signed with (THE SIGNATURE, above).
const OTHER_KEYS = Object.freeze([
  ["WITNESS_LOG_SIGNER_KEY", "the witness log's key"],
  [receipts.SIGNER_ENV, "the reconcile receipt key"],
]);

const PIN_ROWS = 3;
const PIN_SEQ = 1;
const PIN_RECORD_KIND = "case_seal";
const PIN_AUTH_LEVEL = "case-seal";
const RAW_DIGEST_PREFIX = "sha256:raw-bytes:v1:";
const C14N_DIGEST = /^sha256:json-c14n:v1:[0-9a-f]{64}$/;

const RECEIPT_REQUIRED = Object.freeze([
  "kind", "v", "claim", "tapes", "method", "verdict", "verdict_digest", "compared_at", "does_not_claim", "signer", "sig",
]);
const RECEIPT_OPTIONAL = Object.freeze(["verdict_digest_note", "unsigned_reason"]);
const RECEIPT_VERDICT_FIELDS = Object.freeze(["verdict", "at", "side", "matched", "counts", "findings", "could_not_look", "exit_code"]);
const VERDICT_WORDS = Object.freeze([T.MATCHED, T.MISSING, T.ALTERED, T.COULD_NOT_LOOK]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function has(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// json-c14n:v1 equality (BigInt and Number of one value are the same bytes).
function sameC14n(x, y) {
  const a = T.c14nBytes(x);
  const b = T.c14nBytes(y);
  return a !== null && b !== null && a.equals(b);
}

// ---------------------------------------------------------------------------
// the key
// ---------------------------------------------------------------------------
// Reads WITNESS_CASE_SIGNER_KEY. Never logs or returns the key itself:
// -> {ok:true, name, verifier, privateKey} or {ok:false, reason}.
function loadCaseSigner(env = process.env) {
  const raw = env[CASE_SIGNER_ENV];
  if (!raw) return { ok: false, reason: `no case signing key is configured (${CASE_SIGNER_ENV} is not set)` };
  const mine = String(raw).trim();
  const k = checkpoint.parseSignerKey(mine);
  if (!k.ok) return { ok: false, reason: `the configured case signing key does not parse (${k.reason})` };
  for (const [name, what] of OTHER_KEYS) {
    const other = env[name];
    if (!other) continue;
    const theirs = String(other).trim();
    const o = checkpoint.parseSignerKey(theirs);
    if (theirs === mine || (o.ok && o.pub.equals(k.pub))) {
      return { ok: false, reason: `the configured case signing key is ${what} (${name}), and a case is never signed with it` };
    }
  }
  const verifier = `${k.name}+${k.hash}+${Buffer.concat([Buffer.from([0x01]), k.pub]).toString("base64")}`;
  return { ok: true, name: k.name, verifier, privateKey: k.privateKey };
}

// ---------------------------------------------------------------------------
// the signed bytes, the chain, the signature
// ---------------------------------------------------------------------------
// The json-c14n:v1 bytes of the case minus `sig` (lib/_check_record.js).
function sealPreimage(rec) {
  return checkRecord.preimage(rec);
}

// sha256 of the signed bytes: the pin's chain.
function caseChain(rec) {
  return sha256hex(sealPreimage(rec));
}

// A NEW object: `unsigned` signed with `signer`, or unsigned with the reason.
function signCase(unsigned, signer) {
  const rec = { ...unsigned };
  if (signer && signer.ok) {
    rec.sig_reason = null;
    rec.sig = null;
    rec.sig = crypto.sign(null, sealPreimage(rec), signer.privateKey).toString("base64");
  } else {
    rec.sig = null;
    rec.sig_reason = `This case is sealed and not signed: ${signer && signer.reason ? signer.reason : "no signer"}.`;
  }
  return rec;
}

// ---------------------------------------------------------------------------
// the receipt
// ---------------------------------------------------------------------------
// The receipt's binding to a case, the part a reader can check from the
// sealed case alone. Returns a reason, or null when it holds.
//   policyVersion  the case's policy_version (the receipt's port version)
//   tapeSha256     {a, b}: the committed tape hashes, role a = tape_a
//   comparedAt     the reveal's service time (UTC seconds)
//   exactMethod    true at seal time: the method block is this build's own
function receiptBinding(r, { policyVersion, tapeSha256, comparedAt, exactMethod }) {
  if (!isPlainObject(r)) return "receipt_not_an_object";
  for (const k of Object.keys(r)) {
    if (!RECEIPT_REQUIRED.includes(k) && !RECEIPT_OPTIONAL.includes(k)) return "receipt_unknown_field";
  }
  for (const k of RECEIPT_REQUIRED) if (!has(r, k)) return "receipt_missing_field";
  if (r.kind !== receipts.RECEIPT_KIND || r.v !== receipts.RECEIPT_VERSION) return "receipt_not_a_reconcile_receipt";
  if (r.claim !== receipts.CLAIM) return "receipt_claim_altered";
  if (!Array.isArray(r.does_not_claim) || !sameC14n(r.does_not_claim, receipts.DOES_NOT_CLAIM)) return "receipt_limits_altered";
  if (!isPlainObject(r.method) || r.method.port_version !== policyVersion) return "receipt_policy_mismatch";
  if (exactMethod && !sameC14n(r.method, receipts.methodBlock())) return "receipt_method_altered";

  const t = r.tapes;
  if (!isPlainObject(t) || Object.keys(t).length !== 2 || !has(t, "tape_a") || !has(t, "tape_b")) return "receipt_tapes_unreadable";
  for (const [slot, role] of [["tape_a", "a"], ["tape_b", "b"]]) {
    const e = t[slot];
    if (!isPlainObject(e) || Object.keys(e).length !== 2 || !has(e, "digest") || !has(e, "bytes")) return "receipt_tapes_unreadable";
    if (!Number.isSafeInteger(e.bytes) || e.bytes < 0) return "receipt_tapes_unreadable";
    if (e.digest !== `${RAW_DIGEST_PREFIX}${tapeSha256[role]}`) return `receipt_${slot}_mismatch`;
  }

  const vb = r.verdict;
  if (!isPlainObject(vb) || Object.keys(vb).length !== RECEIPT_VERDICT_FIELDS.length || !RECEIPT_VERDICT_FIELDS.every((k) => has(vb, k))) {
    return "receipt_verdict_unreadable";
  }
  if (!VERDICT_WORDS.includes(vb.verdict)) return "receipt_verdict_unreadable";

  if (r.verdict_digest === null) {
    if (typeof r.verdict_digest_note !== "string" || !r.verdict_digest_note) return "receipt_verdict_digest_unreadable";
  } else if (typeof r.verdict_digest !== "string" || !C14N_DIGEST.test(r.verdict_digest) || has(r, "verdict_digest_note")) {
    return "receipt_verdict_digest_unreadable";
  }
  if (r.compared_at !== comparedAt) return "receipt_time_mismatch";

  if (r.sig === null) {
    if (r.signer !== null || typeof r.unsigned_reason !== "string" || !r.unsigned_reason) return "receipt_signature_unreadable";
  } else {
    const s = r.signer;
    if (typeof r.sig !== "string" || has(r, "unsigned_reason") || !isPlainObject(s) || Object.keys(s).length !== 3 ||
      typeof s.name !== "string" || typeof s.verifier !== "string" || s.alg !== "ed25519") {
      return "receipt_signature_unreadable";
    }
  }
  return null;
}

// The deep check at seal time (THE RECEIPT CHECK, above).
//   kase         the COMMITTED case being sealed
//   tapeSha256   {a, b}: the committed tape hashes
//   tapeBytes    {a, b}: the submitted tapes' byte counts
//   result       the comparison's own result (lib/_reconcile_tapes.js)
//   revealedAt   the reveal's service time, UTC seconds
//   signer       lib/_reconcile_receipt.js loadSigner() for this request
// -> {ok:true} or {ok:false, reason}.
function checkReceipt(r, { kase, tapeSha256, tapeBytes, result, revealedAt, signer }) {
  const no = (reason) => ({ ok: false, reason });
  const why = receiptBinding(r, { policyVersion: kase.policy_version, tapeSha256, comparedAt: revealedAt, exactMethod: true });
  if (why) return no(why);
  if (r.tapes.tape_a.bytes !== tapeBytes.a || r.tapes.tape_b.bytes !== tapeBytes.b) return no("receipt_tape_size_mismatch");
  const vb = r.verdict;
  if (vb.verdict !== result.verdict || vb.at !== result.at || vb.side !== result.side || vb.matched !== result.matched ||
    !sameC14n(vb.counts, result.counts) || vb.findings !== result.findings.length ||
    vb.could_not_look !== result.could_not_look.length || vb.exit_code !== result.exit_code) {
    return no("receipt_verdict_mismatch");
  }
  if (r.verdict_digest !== T.digestC14n(result)) return no("receipt_verdict_digest_mismatch");
  if (signer && signer.ok) {
    if (r.sig === null || r.signer.verifier !== signer.verifier || r.signer.name !== signer.name) return no("receipt_signer_mismatch");
    const v = receipts.verifyReceiptText(T.wireJson(r), signer.verifier);
    if (!v.ok) return no(`receipt_${v.reason}`);
  } else if (r.sig !== null || r.unsigned_reason !== (signer && signer.reason ? signer.reason : "no signer")) {
    return no("receipt_unsigned_inconsistent");
  }
  return { ok: true };
}

// The receipt as a case file can hold it (JSON, above).
// -> {ok:true, receipt} or {ok:false, reason}.
function storableReceipt(r) {
  let beyond = false;
  function walk(v) {
    if (typeof v === "bigint") {
      if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < -BigInt(Number.MAX_SAFE_INTEGER)) beyond = true;
      return Number(v);
    }
    if (Array.isArray(v)) return v.map(walk);
    if (isPlainObject(v)) {
      const out = {};
      for (const k of Object.keys(v)) out[k] = walk(v[k]);
      return out;
    }
    return v;
  }
  const copy = walk(r);
  if (beyond) return { ok: false, reason: "integer_beyond_json" };
  let stored;
  try {
    stored = JSON.parse(JSON.stringify(copy));
  } catch {
    return { ok: false, reason: "not_json" };
  }
  if (!sameC14n(stored, r)) return { ok: false, reason: "not_json" };
  if (r.sig !== null) {
    const v = receipts.verifyReceiptText(T.wireJson(stored), r.signer.verifier);
    if (!v.ok) return { ok: false, reason: `stored_receipt_${v.reason}` };
  }
  return { ok: true, receipt: stored };
}

// The stored receipt's binding to the sealed case it is in.
function checkSealedReceipt(rec) {
  return receiptBinding(rec.verdict, {
    policyVersion: rec.policy_version,
    tapeSha256: { a: rec.reveals.a.tape_sha256, b: rec.reveals.b.tape_sha256 },
    comparedAt: rec.reveals.a.revealed_at,
    exactMethod: false,
  });
}

// ---------------------------------------------------------------------------
// the seal
// ---------------------------------------------------------------------------
// The sealed case (THE SEALED OBJECT, above), signed. Pure. Throws CaseError
// if the result would not be a valid record: this service's defect.
//   kase            the COMMITTED case, as stored and validated
//   reveals         {a: {tape_sha256, salt}, b: {...}} as validated
//   receipt         storableReceipt(...).receipt
//   crossReference  {operator, reference, url} or null
//   revealedAt      the service clock, UTC seconds
function sealCase(kase, { reveals, receipt, crossReference, revealedAt }, signer) {
  if (kase.status !== "COMMITTED") {
    throw new C.CaseError("status_inconsistent", "status", `only a COMMITTED case is sealed; this one is ${kase.status}`);
  }
  const entry = (r) => ({ tape_sha256: reveals[r].tape_sha256, salt_sha256: C.saltSha256(reveals[r].salt), revealed_at: revealedAt });
  const unsigned = JSON.parse(JSON.stringify({
    ...kase,
    reveals: { a: entry("a"), b: entry("b") },
    verdict: receipt,
    records: crossReference ? 2 : 1,
    cross_reference: crossReference
      ? { operator: crossReference.operator, reference: crossReference.reference, url: crossReference.url, recorded_at: revealedAt }
      : null,
    status: "VERDICT",
  }));
  const sealed = signCase(unsigned, signer);
  const v = C.validateCase(sealed);
  if (!v.ok) throw new C.CaseError(v.code, v.field, `the sealed case would not be a valid record (${v.error})`);
  const why = checkSealedReceipt(sealed);
  if (why) throw new C.CaseError("status_inconsistent", "verdict", `the sealed receipt is not bound to this case (${why})`);
  return sealed;
}

// A sealed case read back: the schema, the receipt's binding, then the
// signature under `verifierStr` (a verifier string, THE SIGNATURE), and the
// receipt's own signature when `opts.receiptVerifier` is given.
// -> {ok:true, chain} or {ok:false, reason, field[, sig_reason]}. Never throws.
function verifyCase(rec, verifierStr, opts = {}) {
  const bad = (reason, field) => ({ ok: false, reason, field });
  const v = C.validateCase(rec);
  if (!v.ok) return bad(v.code, v.field);
  if (rec.status !== "VERDICT") return bad("not_sealed", "status");
  const why = checkSealedReceipt(rec);
  if (why) return bad(why, "verdict");
  if (rec.sig === null) return { ok: false, reason: "unsigned", field: "sig", sig_reason: rec.sig_reason };
  const sigBytes = Buffer.from(rec.sig, "base64");
  if (sigBytes.length !== 64 || sigBytes.toString("base64") !== rec.sig) return bad("malformed_signature", "sig");
  const vk = checkpoint.parseVerifierKey(verifierStr);
  if (!vk.ok) return bad("bad_verifier", "verifier");
  let good = false;
  try {
    good = crypto.verify(null, sealPreimage(rec), vk.publicKey, sigBytes);
  } catch {
    good = false;
  }
  if (!good) return bad("bad_signature", "sig");
  const nowMs = Number.isFinite(opts.nowMs) ? opts.nowMs : Date.now();
  if (Date.parse(rec.reveals.a.revealed_at) > nowMs + checkRecord.DEFAULT_SKEW_SECONDS * 1000) return bad("future_dated", "reveals.a.revealed_at");
  if (opts.receiptVerifier !== undefined) {
    const r = receipts.verifyReceiptText(T.wireJson(rec.verdict), opts.receiptVerifier);
    if (!r.ok) return bad(`receipt_${r.reason}`, "verdict");
  }
  return { ok: true, chain: caseChain(rec) };
}

// ---------------------------------------------------------------------------
// the pin (THE CHAIN AND THE PIN, TWO WRITES, above)
// ---------------------------------------------------------------------------
function pinNamespace(caseId) {
  C.casePath(caseId); // the id check
  return `case/${caseId}`;
}

function pinPaths(caseId) {
  const ns = pinNamespace(caseId);
  return { ns, seq: `pins/${ns}/${String(PIN_SEQ).padStart(8, "0")}.json`, latest: `pins/${ns}/latest.json` };
}

function pinRecord(caseId, chain, nowMs) {
  return {
    namespace: pinNamespace(caseId),
    rows: PIN_ROWS,
    chain,
    pinned_at: new Date(nowMs).toISOString(),
    seq: PIN_SEQ,
    record_kind: PIN_RECORD_KIND,
    auth_level: PIN_AUTH_LEVEL,
    auth_note:
      `Written by this service when it sealed ${C.casePath(caseId)} (POST ?op=case-reveal), not by POST /api/pin: ` +
      "no bearer key wrote it. chain is the sha256 of the case's json-c14n:v1 bytes minus sig; rows counts the case's " +
      "three records, its two registration files and the sealed case file.",
  };
}

// A stored pin record is this case's anchor for `chain`.
function isOurPin(json, ns, chain) {
  return isPlainObject(json) && json.namespace === ns && json.rows === PIN_ROWS && json.seq === PIN_SEQ &&
    typeof json.chain === "string" && json.chain.toLowerCase() === chain;
}

// -> one of
//   {pin: "anchored", existing, record}   the pointer holds this chain
//   {pin: "pending", reason}              not pinned yet; a retry may pin it
//   {pin: "conflict", record}             another chain is pinned here; never overwritten
//   {pin: "unreadable", reason}           a pin record is present and unreadable
async function pinChain(caseId, chain, nowMs = Date.now()) {
  const { ns, seq, latest } = pinPaths(caseId);
  const judged = (got, what) => verdict.judgePin(got, { what, namespace: ns });
  const pending = (reason) => ({ pin: "pending", reason });

  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return pending("store_unreachable");
  }
  if (cur !== null) {
    const v = judged(cur, latest);
    if (!v.ok) return { pin: "unreadable", reason: v.reason };
    return isOurPin(cur.json, ns, chain) ? { pin: "anchored", existing: true, record: cur.json } : { pin: "conflict", record: cur.json };
  }

  // The numbered record first: an earlier attempt may have written it and
  // then failed the pointer.
  let prior;
  try {
    prior = await store.getFile(seq);
  } catch {
    return pending("store_unreachable");
  }
  let record;
  if (prior !== null) {
    const v = judged(prior, seq);
    if (!v.ok) return { pin: "unreadable", reason: v.reason };
    if (!isOurPin(prior.json, ns, chain)) return { pin: "conflict", record: prior.json };
    record = prior.json;
  } else {
    record = pinRecord(caseId, chain, nowMs);
    try {
      await store.putFile(seq, record, `case ${caseId.slice(0, 16)}: seal pin rows=${PIN_ROWS} seq=${PIN_SEQ}`);
    } catch (e) {
      if (!(e && e.conflict)) {
        console.error(`[case] seal: pin record write failed (${e && e.message})`);
        return pending("store_error");
      }
      let won;
      try {
        won = await store.getFile(seq);
      } catch {
        return pending("store_unreachable");
      }
      if (!won || !judged(won, seq).ok || !isOurPin(won.json, ns, chain)) return { pin: "conflict", record: won ? won.json : null };
      record = won.json;
    }
  }

  let put;
  try {
    put = await store.putFile(latest, record, `latest case/${caseId.slice(0, 16)} rows=${PIN_ROWS} seq=${PIN_SEQ} (case seal)`, undefined, {
      rebuild: () => null, // a pointer that appeared meanwhile is judged below, never written over
    });
  } catch (e) {
    if (!(e && e.conflict)) {
      console.error(`[case] seal: pin pointer write failed (${e && e.message})`);
      return pending("store_error");
    }
    put = { abandoned: true };
  }
  if (put && put.abandoned) {
    let won;
    try {
      won = await store.getFile(latest);
    } catch {
      return pending("store_unreachable");
    }
    if (won && judged(won, latest).ok && isOurPin(won.json, ns, chain)) return { pin: "anchored", existing: true, record: won.json };
    return { pin: "conflict", record: won ? won.json : null };
  }
  return { pin: "anchored", existing: false, record };
}

// The anchor state of a sealed case, COMPUTED from the pin (design decision
// 2): never a field of the case. Reads only. -> {pin: "anchored" | "pending"
// | "conflict" | "unreadable" | "unknown", ...}.
async function anchorState(caseId, chain) {
  const { ns, latest } = pinPaths(caseId);
  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return { pin: "unknown", reason: "store_unreachable" };
  }
  if (cur === null) return { pin: "pending" };
  const v = verdict.judgePin(cur, { what: latest, namespace: ns });
  if (!v.ok) return { pin: "unreadable", reason: v.reason };
  return isOurPin(cur.json, ns, chain) ? { pin: "anchored", record: cur.json } : { pin: "conflict", record: cur.json };
}

// The retry by case_id: read the stored case file, recompute its chain from
// it, and pin that. -> {ok:true, chain, pin, ...} or {ok:false, code}.
async function anchorCase(caseId, opts = {}) {
  const nowMs = opts.now !== undefined ? Number(opts.now) : Date.now();
  const cpath = C.casePath(caseId);
  let got;
  try {
    got = await store.getFile(cpath);
  } catch {
    return { ok: false, code: "store_unreachable" };
  }
  if (got === null) return { ok: false, code: "case_not_found" };
  const v = verdict.judgeWith(got, cpath, (json) => {
    const r = C.validateCase(json);
    if (!r.ok) return `case_${r.code}`;
    return json.case_id === caseId ? true : "case_not_at_its_path";
  });
  if (!v.ok) return { ok: false, code: "case_record_unreadable", reason: v.reason };
  if (got.json.status !== "VERDICT") return { ok: false, code: "not_sealed", status: got.json.status };
  const chain = caseChain(got.json);
  const p = await pinChain(caseId, chain, nowMs);
  return { ok: true, chain, ...p };
}

module.exports = {
  CASE_SIGNER_ENV,
  PIN_ROWS,
  PIN_RECORD_KIND,
  loadCaseSigner,
  sealPreimage,
  caseChain,
  signCase,
  checkReceipt,
  storableReceipt,
  checkSealedReceipt,
  sealCase,
  verifyCase,
  pinNamespace,
  pinPaths,
  pinChain,
  anchorState,
  anchorCase,
  _internal: { receiptBinding, pinRecord, isOurPin },
};

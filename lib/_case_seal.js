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
// strength onto the other, so the keys stay apart.
//   SEPARATION FAILS CLOSED (item 2b; GPT-5.6's review of 2a: "If
// WITNESS_CASE_SIGNER_KEY is configured to the same private key as the
// reconcile signer but WITNESS_RECONCILE_SIGNER_KEY is missing in that
// function's environment, the guard cannot detect reuse and signs the
// case"). The case key is used only when it can be SHOWN different from
// both other keys: each of WITNESS_LOG_SIGNER_KEY and
// WITNESS_RECONCILE_SIGNER_KEY must be present in this environment and
// parse, and its public verifier string and its public key bytes must both
// differ from the case key's (the bytes too, because one key under two names
// has two verifier strings). A case key that IS one of them is refused by
// name (`case_key_is_other_key`). When either other key is absent or does
// not parse, the difference cannot be established and the seal goes out
// unsigned, `key_separation_unverifiable`, never signed. (The log key does
// live on the witness project's Vercel environment: docs/LOGTREE_KEY_RUNBOOK.md,
// "the signer key lives on Vercel, as an environment variable on the
// witness project".)
// Unset, unparseable or refused, the case is sealed UNSIGNED: `sig: null`
// with `sig_reason` naming the reason (never the key), in the form
//   "This case is sealed and not signed (<code>): <why>."
// with <code> one of case_key_unset, case_key_unparseable,
// case_key_is_other_key, key_separation_unverifiable. An unsigned seal is
// still a seal: the verdict is the same, the signature is missing.
//   SIGNED_BY (item 2b). The sealed case names its key in `signed_by`, the
// key id <name>+<8 hex> (lib/_checkpoint.js's key naming), set by signCase
// in the step that signs, so it is inside the signed bytes; null when
// unsigned. The verifier, <name>+<8 hex>+<base64(0x01 || pub)>, is
// published in a version-controlled public document,
// .well-known/arcaeon/case-signing-keys.json (CASE_KEYS_DOC below; the
// snapshot keys' pattern, a static file at the project root served at
// /.well-known/arcaeon/), one entry {key_id, verifier, since, note, status}
// per key. A reader looks signed_by up there and checks the signature with
// verifyCase, which also requires that the verifier it was handed is the key
// signed_by names. The reveal's answer still carries `sealed_by`.
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
// each read back through lib/_verdict.js judgeCaseSeal. One pin per case,
// ever, so seq is 1. rows is 3: the case's three records, its two
// registration files and the sealed case file.
//   THE case_seal RECORD TYPE (item 2b). The record is exactly {namespace,
// rows, chain, pinned_at, seq, record_kind: "case_seal", auth_level:
// "case-seal", auth_note}, judged by its own judge (lib/_verdict.js
// judgeCaseSeal: an unknown field, a missing field or a wrong value is
// refused by name). It carries none of api/pin.js's cadence fields, because
// a seal promises no next pin. The generic judgePin refuses a case seal by
// name, so no generic reader can take one for a namespace's head.
//   "case/<case_id>" is not a namespace api/pin.js accepts (lib/_store.js
// validatePin: [a-z0-9-]{1,64}, and the bare namespace "case" is reserved
// there too, so pins/case/ holds case seals and nothing else), so no bearer
// key can ever write a pin into a case's namespace, before or after the
// seal. THE READERS (item 2b) know it: the status page skips pins/case in
// its namespace listing and shows case anchors as their own row
// (caseAnchorSummary below), and lib/_logtree.js is unchanged, because its
// v1 leaf table reads pins/<ns>/<seq>.json one level deep and widening it
// would move every position. So, in words, ANCHOR_NOTE below: a case pin is
// anchored by the pins-repository commit and the daily anchor of the
// repository head, not as a log-tree leaf. The reveal's answer carries that
// sentence as `anchor_note`; the case page (item 2c) will too.
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
//   Before it pins, anchorCase holds the stored case to the full sealed-
// receipt check (item 2b; GPT-5.6: "anchorCase anchors structurally valid but
// receipt-unbound verdicts"): checkSealedReceipt, the receipt's binding to
// the case's reveals, compared_at and policy, and, for a signed receipt, its
// signature under the verifier it carries. A schema-valid VERDICT that fails
// is refused `verdict_unbound` and nothing is written.
//   THE TRIGGER (item 2b; design "After item 2a": "anchorCase runs from the
// sealer's authenticated run, never from a public read"). lib/_sealer.js
// sealOnce, the operator's own command (tools/seal_batch.js, which needs
// the pins token to run at all), calls anchorPending on every run: one tree
// read lists the cases that hold both registration files and no pin
// pointer (a case without both cannot be sealed), and anchorCase runs for
// each, at most SEALER_CASE_READS per run, the window rotating with the
// run's clock so that none waits forever behind the rest. Idempotent: a
// pinned case is not listed again, and a retry never changes the chain.
// No public ?op writes a pin.
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

const PIN_ROWS = verdict.CASE_SEAL.rows;
const PIN_SEQ = verdict.CASE_SEAL.seq;
const PIN_RECORD_KIND = verdict.CASE_SEAL.record_kind;
const PIN_AUTH_LEVEL = verdict.CASE_SEAL.auth_level;
const RAW_DIGEST_PREFIX = "sha256:raw-bytes:v1:";

// THE READERS, above: the sentence the reveal's answer and the case page carry.
const ANCHOR_NOTE =
  "A case pin is anchored by the pins-repository commit that writes it and by the daily anchor of the repository head, " +
  "not as a log-tree leaf: the witness log's v1 leaves are pins/<namespace>/<seq>.json one level deep, and a case pin " +
  "sits at pins/case/<case_id>/.";

// SIGNED_BY, above: the published key document, repository-relative. Served
// as a static file at /.well-known/arcaeon/case-signing-keys.json, the way
// the snapshot signing keys are served at arcaeon.io.
const CASE_KEYS_DOC = ".well-known/arcaeon/case-signing-keys.json";
const CASE_KEYS_SCHEMA = "arcaeon-signing-keys/1";
const CASE_KEYS_TOP_FIELDS = Object.freeze(["schema", "issuer", "description", "matching", "status_meaning", "rotation", "updated", "keys"]);
const CASE_KEY_ENTRY_FIELDS = Object.freeze(["key_id", "verifier", "since", "note", "status"]);
const CASE_KEY_STATUSES = Object.freeze(["active", "retired", "revoked"]);

// THE TRIGGER, above: case files read per sealer run, at most.
const SEALER_CASE_READS = 25;
// THE READERS, above: case files read per status render, at most.
const STATUS_CASE_READS = 100;

const CASE_FILE_RE = /^cases\/([0-9a-f]{64})\.json$/;
const CASE_REG_RE = /^cases\/([0-9a-f]{64})\/commit_([ab])\.json$/;
const CASE_PIN_LATEST_RE = /^pins\/case\/([0-9a-f]{64})\/latest\.json$/;
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
// A parsed key's public verifier string and key id (lib/_checkpoint.js).
function verifierOf(k) {
  return `${k.name}+${k.hash}+${Buffer.concat([Buffer.from([0x01]), k.pub]).toString("base64")}`;
}
function keyIdOf(k) {
  return `${k.name}+${k.hash}`;
}

// Reads WITNESS_CASE_SIGNER_KEY and the two keys it must be shown different
// from (SEPARATION FAILS CLOSED, above). Never logs or returns a key itself:
// -> {ok:true, name, keyId, verifier, privateKey} or {ok:false, code, reason}.
function loadCaseSigner(env = process.env) {
  const no = (code, reason) => ({ ok: false, code, reason });
  const raw = env[CASE_SIGNER_ENV];
  if (!raw) return no("case_key_unset", `no case signing key is configured (${CASE_SIGNER_ENV} is not set)`);
  const mine = String(raw).trim();
  const k = checkpoint.parseSignerKey(mine);
  if (!k.ok) return no("case_key_unparseable", `the configured case signing key does not parse (${k.reason})`);
  const verifier = verifierOf(k);
  const unshown = [];
  for (const [name, what] of OTHER_KEYS) {
    const other = env[name];
    if (!other) {
      unshown.push(`${what} (${name} is not set in this environment)`);
      continue;
    }
    const theirs = String(other).trim();
    const o = checkpoint.parseSignerKey(theirs);
    if (theirs === mine || (o.ok && (o.pub.equals(k.pub) || verifierOf(o) === verifier))) {
      return no("case_key_is_other_key", `the configured case signing key is ${what} (${name}), and a case is never signed with it`);
    }
    if (!o.ok) unshown.push(`${what} (${name} does not parse)`);
  }
  if (unshown.length) {
    return no("key_separation_unverifiable",
      `the case signing key cannot be shown different from ${unshown.join(" or ")}, so it is not used`);
  }
  return { ok: true, name: k.name, keyId: keyIdOf(k), verifier, privateKey: k.privateKey };
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
// signed_by is set here and nowhere else, before the signature is taken, so
// it is inside the signed bytes (SIGNED_BY, above).
function signCase(unsigned, signer) {
  const rec = { ...unsigned };
  if (signer && signer.ok) {
    rec.signed_by = signer.keyId;
    rec.sig_reason = null;
    rec.sig = null;
    rec.sig = crypto.sign(null, sealPreimage(rec), signer.privateKey).toString("base64");
  } else {
    rec.signed_by = null;
    rec.sig = null;
    const code = signer && signer.code ? signer.code : "case_key_unset";
    rec.sig_reason = `This case is sealed and not signed (${code}): ${signer && signer.reason ? signer.reason : "no signer"}.`;
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

// The full sealed-receipt check anchorCase runs before it pins (TWO WRITES,
// above): the binding, then, for a signed receipt, its signature under the
// verifier it carries (the stored form, the bytes storableReceipt proved at
// seal time). Returns a reason, or null when it holds.
function checkStoredReceipt(rec) {
  const why = checkSealedReceipt(rec);
  if (why) return why;
  const r = rec.verdict;
  if (r.sig !== null) {
    const v = receipts.verifyReceiptText(T.wireJson(r), r.signer.verifier);
    if (!v.ok) return `receipt_${v.reason}`;
  }
  return null;
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
  // The key the case names is the key that verified it (SIGNED_BY, above).
  if (keyIdOf(vk) !== rec.signed_by) return bad("signer_mismatch", "signed_by");
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

// A stored pin record, already judged a case_seal record for `ns`
// (lib/_verdict.js judgeCaseSeal), is this case's anchor for `chain`.
function isOurPin(json, ns, chain) {
  return isPlainObject(json) && json.namespace === ns && json.rows === PIN_ROWS && json.seq === PIN_SEQ &&
    json.record_kind === PIN_RECORD_KIND && json.chain === chain;
}

function judgeSeal(got, what, ns) {
  return verdict.judgeCaseSeal(got, { what, namespace: ns });
}

// -> one of
//   {pin: "anchored", existing, record}   the pointer holds this chain
//   {pin: "pending", reason}              not pinned yet; a retry may pin it
//   {pin: "conflict", record}             another chain is pinned here; never overwritten
//   {pin: "unreadable", reason}           a pin record is present and unreadable
async function pinChain(caseId, chain, nowMs = Date.now()) {
  const { ns, seq, latest } = pinPaths(caseId);
  const judged = (got, what) => judgeSeal(got, what, ns);
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
  const v = judgeSeal(cur, latest, ns);
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
  // The full sealed-receipt check, before any pin write (TWO WRITES, above).
  const unbound = checkStoredReceipt(got.json);
  if (unbound) return { ok: false, code: "verdict_unbound", reason: unbound };
  const chain = caseChain(got.json);
  const p = await pinChain(caseId, chain, nowMs);
  return { ok: true, chain, ...p };
}

// ---------------------------------------------------------------------------
// the readers: the pins tree, the sealer's pass, the status row
// ---------------------------------------------------------------------------
// What a recursive tree listing (lib/_store.js getTree / getTreeMeta entries)
// says about the cases, by path alone: which case files exist, which roles
// hold a registration file, which cases hold a pin pointer.
function caseTreeIndex(entries) {
  const cases = new Set();
  const regs = new Map();
  const pinned = new Set();
  for (const e of entries || []) {
    if (!e || (e.type !== undefined && e.type !== "blob") || typeof e.path !== "string") continue;
    let m = CASE_FILE_RE.exec(e.path);
    if (m) {
      cases.add(m[1]);
      continue;
    }
    m = CASE_REG_RE.exec(e.path);
    if (m) {
      if (!regs.has(m[1])) regs.set(m[1], new Set());
      regs.get(m[1]).add(m[2]);
      continue;
    }
    m = CASE_PIN_LATEST_RE.exec(e.path);
    if (m) pinned.add(m[1]);
  }
  // Only a case with both registration files can be sealed (a VERDICT
  // carries both roles' registrations, and the reveal reads both files).
  const sealable = [...cases].filter((id) => regs.has(id) && regs.get(id).size === 2).sort();
  return { cases, regs, pinned, sealable };
}

// At most `max` of `ids`, a window that moves on by `max` each minute of
// `nowMs`, so with more candidates than one run reads, each is read within
// ceil(n / max) runs a minute apart (THE TRIGGER, above).
function rotatingWindow(ids, max, nowMs) {
  if (ids.length <= max) return ids.slice();
  const start = (Math.floor(nowMs / 60000) * max) % ids.length;
  const out = [];
  for (let i = 0; i < max; i += 1) out.push(ids[(start + i) % ids.length]);
  return out;
}

// The sealer's pass (THE TRIGGER, above). Never throws. -> a report:
//   {ok:true, candidates, read, deferred, anchored: [ids pinned now],
//    already: [ids found pinned], not_sealed, pending: [{case_id, reason}],
//    refused: [{case_id, code, reason}], conflict: [ids], unreadable: [ids],
//    truncated}
//   or {ok:false, reason, detail} when the tree cannot be read (nothing
//   written).
async function anchorPending({ now = Date.now(), maxReads = SEALER_CASE_READS } = {}) {
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  let meta;
  try {
    meta = await store.getTreeMeta();
  } catch (e) {
    return { ok: false, reason: "tree_unreadable", detail: e && e.message ? e.message : null };
  }
  const idx = caseTreeIndex(meta.entries);
  const candidates = idx.sealable.filter((id) => !idx.pinned.has(id));
  const picked = rotatingWindow(candidates, maxReads, nowMs);
  const out = {
    ok: true,
    candidates: candidates.length,
    read: picked.length,
    deferred: candidates.length - picked.length,
    anchored: [],
    already: [],
    not_sealed: 0,
    pending: [],
    refused: [],
    conflict: [],
    unreadable: [],
    truncated: meta.truncated === true,
  };
  for (const id of picked) {
    let r;
    try {
      r = await anchorCase(id, { now: nowMs });
    } catch (e) {
      out.refused.push({ case_id: id, code: "threw", reason: e && e.message ? e.message : null });
      continue;
    }
    if (!r.ok) {
      if (r.code === "not_sealed") out.not_sealed += 1;
      else if (r.code === "store_unreachable") out.pending.push({ case_id: id, reason: r.code });
      else out.refused.push({ case_id: id, code: r.code, reason: r.reason || null });
      continue;
    }
    if (r.pin === "anchored") (r.existing ? out.already : out.anchored).push(id);
    else if (r.pin === "pending") out.pending.push({ case_id: id, reason: r.reason || null });
    else if (r.pin === "conflict") out.conflict.push(id);
    else out.unreadable.push(id);
  }
  return out;
}

// The status page's case row (THE READERS, above), from the tree the page
// already read. Reads each sealable case file and, for a sealed one, its pin
// pointer, at most `maxReads` case files. Never throws; feeds no verdict.
//   {case_files, sealed, anchored, pending, conflict, unreadable,
//    read, unread, partial}
async function caseAnchorSummary(entries, { maxReads = STATUS_CASE_READS } = {}) {
  const idx = caseTreeIndex(entries);
  const picked = idx.sealable.slice(0, maxReads);
  const out = {
    case_files: idx.cases.size,
    sealed: 0,
    anchored: 0,
    pending: 0,
    conflict: 0,
    unreadable: 0,
    read: picked.length,
    unread: idx.sealable.length - picked.length,
    partial: idx.sealable.length > picked.length,
  };
  for (const id of picked) {
    const cpath = C.casePath(id);
    let got;
    try {
      got = await store.getFile(cpath);
    } catch {
      out.unreadable += 1;
      continue;
    }
    if (got === null) continue; // listed, then gone: not counted
    const v = verdict.judgeWith(got, cpath, (json) => {
      const r = C.validateCase(json);
      if (!r.ok) return `case_${r.code}`;
      return json.case_id === id ? true : "case_not_at_its_path";
    });
    if (!v.ok) {
      out.unreadable += 1;
      continue;
    }
    if (got.json.status !== "VERDICT") continue;
    out.sealed += 1;
    const st = await anchorState(id, caseChain(got.json));
    if (st.pin === "anchored") out.anchored += 1;
    else if (st.pin === "pending") out.pending += 1;
    else if (st.pin === "conflict") out.conflict += 1;
    else out.unreadable += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// the published key document (SIGNED_BY, above)
// ---------------------------------------------------------------------------
// The entry the document carries for a loaded case signer.
function keyDocumentEntry(signer, { since, note, status = "active" }) {
  if (!signer || !signer.ok) throw new TypeError("keyDocumentEntry: a loaded case signer is required");
  return { key_id: signer.keyId, verifier: signer.verifier, since, note, status };
}

// The document's shape. -> {ok:true, keys} or {ok:false, reason, at}.
function checkKeyDocument(doc) {
  const no = (reason, at) => ({ ok: false, reason, at });
  if (!isPlainObject(doc)) return no("not_an_object", "$");
  for (const k of CASE_KEYS_TOP_FIELDS) if (!has(doc, k)) return no("missing_field", k);
  if (doc.schema !== CASE_KEYS_SCHEMA) return no("wrong_schema", "schema");
  for (const k of ["issuer", "description", "matching", "rotation"]) {
    if (typeof doc[k] !== "string" || !doc[k].trim()) return no("malformed_field", k);
  }
  if (!isPlainObject(doc.status_meaning) || !CASE_KEY_STATUSES.every((s) => typeof doc.status_meaning[s] === "string")) {
    return no("malformed_field", "status_meaning");
  }
  if (typeof doc.updated !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(doc.updated)) return no("malformed_field", "updated");
  if (!Array.isArray(doc.keys)) return no("malformed_field", "keys");
  const seen = new Set();
  for (let i = 0; i < doc.keys.length; i += 1) {
    const e = doc.keys[i];
    const at = `keys[${i}]`;
    if (!isPlainObject(e)) return no("malformed_entry", at);
    for (const k of Object.keys(e)) if (!CASE_KEY_ENTRY_FIELDS.includes(k)) return no("unknown_field", `${at}.${k}`);
    for (const k of CASE_KEY_ENTRY_FIELDS) if (!has(e, k)) return no("missing_field", `${at}.${k}`);
    const vk = checkpoint.parseVerifierKey(e.verifier);
    if (!vk.ok) return no("bad_verifier", `${at}.verifier`);
    if (e.key_id !== keyIdOf(vk)) return no("key_id_mismatch", `${at}.key_id`);
    if (typeof e.since !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(e.since)) return no("malformed_field", `${at}.since`);
    if (typeof e.note !== "string" || !e.note.trim()) return no("malformed_field", `${at}.note`);
    if (!CASE_KEY_STATUSES.includes(e.status)) return no("malformed_field", `${at}.status`);
    if (seen.has(e.key_id)) return no("duplicate_key_id", `${at}.key_id`);
    seen.add(e.key_id);
  }
  return { ok: true, keys: doc.keys.slice() };
}

// The document's entry for a key id, or null.
function publishedEntry(doc, keyId) {
  const c = checkKeyDocument(doc);
  if (!c.ok) return null;
  return c.keys.find((e) => e.key_id === keyId) || null;
}

module.exports = {
  CASE_SIGNER_ENV,
  OTHER_KEYS,
  PIN_ROWS,
  PIN_RECORD_KIND,
  ANCHOR_NOTE,
  CASE_KEYS_DOC,
  CASE_KEYS_SCHEMA,
  CASE_KEY_ENTRY_FIELDS,
  SEALER_CASE_READS,
  STATUS_CASE_READS,
  loadCaseSigner,
  sealPreimage,
  caseChain,
  signCase,
  checkReceipt,
  storableReceipt,
  checkSealedReceipt,
  checkStoredReceipt,
  sealCase,
  verifyCase,
  pinNamespace,
  pinPaths,
  pinChain,
  anchorState,
  anchorCase,
  caseTreeIndex,
  anchorPending,
  caseAnchorSummary,
  keyDocumentEntry,
  checkKeyDocument,
  publishedEntry,
  _internal: { receiptBinding, pinRecord, isOurPin, rotatingWindow, verifierOf, keyIdOf },
};

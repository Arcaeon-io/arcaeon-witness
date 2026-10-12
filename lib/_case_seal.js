// _case_seal.js — the seal of a case: the sealed case object, its signature,
// its chain, its pin, and the check of the reconcile receipt it carries;
// since item 2c also the two other records the case key signs (a
// withdrawal record and a reference row) and the published key document
// every signature is checked against.
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
//   PUBLICATION FAILS CLOSED (item 2c; GPT-5.6's review of 2b: "A configured
// signer may sign cases although its public verifier is absent from the
// published key document"). After separation, the key must be an ACTIVE
// entry of the committed key document (PUBLISHED_KEYS below, loaded with
// require() when this module loads, so the function bundle carries it),
// holding exactly the key's verifier string. A key that is not listed, is
// listed retired or revoked, or is listed with another verifier, or a
// document that does not read, is not used: the seal goes out unsigned,
// `key_unpublished`. So a signature this service makes is always one the
// public document confirms. The document lists no key until item three
// mints one, so until then every seal is unsigned.
// Unset, unparseable or refused, the case is sealed UNSIGNED: `sig: null`
// with `sig_reason` naming the reason (never the key), in the form
//   "This case is sealed and not signed (<code>): <why>."
// with <code> one of case_key_unset, case_key_unparseable,
// case_key_is_other_key, key_separation_unverifiable, key_unpublished. An
// unsigned seal is still a seal: the verdict is the same, the signature is
// missing.
//   SIGNED_BY (item 2b). The sealed case names its key in `signed_by`, the
// key id <name>+<8 hex> (lib/_checkpoint.js's key naming), set by signCase
// in the step that signs, so it is inside the signed bytes; null when
// unsigned. The verifier, <name>+<8 hex>+<base64(0x01 || pub)>, is
// published in a version-controlled public document served at
// /.well-known/arcaeon/case-signing-keys.json (CASE_KEYS_DOC below; the
// snapshot keys' pattern), committed at
// public/.well-known/arcaeon/case-signing-keys.json (CASE_KEYS_FILE; public/
// is vercel.json's outputDirectory, README "Deploy shape"), one entry
// {key_id, verifier, since, note, status} per key. A reader looks signed_by
// up there and checks the signature with
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
// (caseAnchorSummary below, counted from the repository tree ALONE since
// item 2c: no case file and no pin is fetched per render, and a truncated
// tree makes the row `partial`), and lib/_logtree.js is unchanged, because
// its v1 leaf table reads pins/<ns>/<seq>.json one level deep and widening
// it would move every position. So, in words, ANCHOR_NOTE below: a case pin
// is anchored by the pins-repository commit and the daily anchor of the
// repository head, not as a log-tree leaf. The reveal's answer carries that
// sentence as `anchor_note`, and so does the case page (lib/_case_page.js).
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
// the case's reveals, compared_at and policy, and its signature (since
// red-team fix B, A RECEIPT IS THE SERVICE'S, below: by the service's
// reconcile signer). A schema-valid VERDICT that fails is refused
// `verdict_unbound` (or `receipt_unsigned`) and nothing is written.
//   Then the stored case's OWN signature (item 2c, fix 1; GPT-5.6's review of
// 2b: "A pending signed case whose sig is replaced with garbage still has a
// bound receipt and can be anchored"): a signed case must verify under the
// verifier its signed_by names in the key document, and that entry must be
// listed and not revoked (publishedSignatureReason). A case whose sig does
// not verify is refused `case_signature_invalid` and nothing is written. An
// unsigned seal has no signature to check and is pinned as the seal it is.
//   Since item 2d those two checks are one routine, sealedRecordReason (THE
// SEALED CHECK, below), and every reader of a stored VERDICT runs it before
// treating it as sealed: anchorCase before it pins, ?op=case-reference
// before it appends a row (a typed 409 by the same two codes), and the case
// page before it shows a verdict (a does-not-verify state instead).
//   TERMINAL STATES (item 2c, fix 6). A root read as WITHDRAWN, or as OPEN
// or COMMITTED at or past its deadline (EXPIRED, computed, never stored),
// will never be sealed: anchorCase answers `terminal` with that status and
// reads and writes nothing more.
//   SINGLE PARTY (red-team fix A; lib/_case.js ONE KEY PER ROLE). A case
// whose two commitments share a key id never reaches sealed: sealCase
// refuses to build one, THE SEALED CHECK refuses a stored VERDICT that is one
// (`single_party`, its first check), and anchorCase answers `not_sealed` with
// reason `single_party` for one read as COMMITTED or VERDICT, after the
// terminal states and before any other check, with nothing written. anchorPending counts it in
// `not_sealed` and lists it in `single_party`.
//   THE TRIGGER (item 2b; design "After item 2a": "anchorCase runs from the
// sealer's authenticated run, never from a public read"). lib/_sealer.js
// sealOnce, the operator's own command (tools/seal_batch.js, which needs
// the pins token to run at all), calls anchorPending on every run: one tree
// read lists the cases that hold both registration files (a case without
// both cannot be sealed) and no withdrawn marker, PINNED ONES INCLUDED (item
// 2c, fix 5: a squatter or an unreadable pin under a pinned case is judged
// with the case_seal judge and reported as `conflict` or `unreadable`, never
// skipped forever), and anchorCase runs for each, at most SEALER_CASE_READS
// per run, the window rotating with the run's clock so that none waits
// forever behind the rest. A case with the marker cases/<case_id>/withdrawn
// is not considered at all, by the tree alone (fix 6). Idempotent: a pinned
// case is only read and judged, and a retry never changes the chain. No
// public ?op writes a pin.
//
// THE WITHDRAWAL RECORD AND THE REFERENCE ROW (item 2c). The case key signs
// two more records with the same rule and the same routine (signRecord): the
// redacted record a withdrawal publishes (withdrawnRecord; lib/_case.js THE
// WITHDRAWAL), and a reference row appended to a sealed case (referenceRow;
// lib/_case.js THE REFERENCE ROW). Each carries signed_by and sig, or
// sig: null with its sig_reason, exactly like a sealed case, and PUBLICATION
// FAILS CLOSED holds for both. A reference row has its own judge
// (judgeReferenceRow) and no pin of its own; THE LIVE RECORD COUNT
// (liveRecords) is 2 when the sealed case carries its cross_reference or a
// valid row exists, 1 only when every listed row was read and none is
// valid, and not established when a read that found no valid row was cut
// short (item 2d); the sealed case's own `records` never changes.
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
// time; and a signature that verifies under WITNESS_RECONCILE_SIGNER_KEY
// (lib/_reconcile_receipt.js verifyReceiptText). With no signer, or an
// unsigned receipt, it is `receipt_unsigned` (red-team fix B: the reveal
// never gets that far, since the comparison itself refuses to run without a
// signer). A receipt that fails is this service's defect, not the caller's:
// nothing is sealed.
//
// A RECEIPT IS THE SERVICE'S (red-team fix B; GPT-5.6's red-team review,
// §3.1: "Fabricate a case verdict without actually running reconcile ... If
// the reconcile receipt is unsigned, checkStoredReceipt() accepts it"). A
// stored receipt holds only with a signature by the service's reconcile
// signer over its canonical bytes (lib/_reconcile_receipt.js preimage). Before
// this, a receipt was checked under the verifier it carried itself, so a
// receipt signed by any key, or by none, passed. checkStoredReceipt holds it
// to THE SERVICE'S VERIFIER (lib/_reconcile_receipt.js expectedVerifier, or
// the `receiptVerifier` a caller hands it): unsigned, signed under another
// verifier, or read where no verifier is known, it is `receipt_unsigned`,
// and THE SEALED CHECK answers {code: "receipt_unsigned", reason} with the
// reason one of `unsigned`, `unknown_signer` or `no_reconcile_verifier`. A
// receipt that names the service's verifier and whose signature does not
// verify was altered after signing: `verdict_unbound`, its verifyReceiptText
// reason, as before. A reader that knows no verifier fails closed: every
// receipt is refused. The page shows such a case as not verifying; the
// sealer refuses it (`refused`, code receipt_unsigned) and pins nothing;
// ?op=case-reference refuses it 409.
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
// writes or logs; a withdrawal record keeps the salt only as salt_sha256.

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

// SIGNED_BY, above: the published key document. CASE_KEYS_DOC is where the
// domain serves it, relative to the domain's root (the way the snapshot
// signing keys are served at arcaeon.io), and the name every message and the
// case page use for it. CASE_KEYS_FILE is where it is committed, relative to
// the repository: public/ is vercel.json's outputDirectory, so the domain
// serves public/<path> at /<path> and nothing outside public/ statically
// (README "Deploy shape"). The functions that load this module carry the
// same file through vercel.json's includeFiles.
const CASE_KEYS_DOC = ".well-known/arcaeon/case-signing-keys.json";
const CASE_KEYS_FILE = `public/${CASE_KEYS_DOC}`;
const CASE_KEYS_SCHEMA = "arcaeon-signing-keys/1";
const CASE_KEYS_TOP_FIELDS = Object.freeze(["schema", "issuer", "description", "matching", "status_meaning", "rotation", "updated", "keys"]);
const CASE_KEY_ENTRY_FIELDS = Object.freeze(["key_id", "verifier", "since", "note", "status"]);
const CASE_KEY_STATUSES = Object.freeze(["active", "retired", "revoked"]);

// THE PUBLISHED KEYS (item 2c, fix 2). The committed key document, loaded
// with require() when this module loads, so the function bundle carries it
// (a file read by path at request time depends on the bundler tracing it; a
// required module is always in the bundle), and named again in vercel.json's
// includeFiles for every function that loads this module, so the bundle
// holds the same bytes the domain serves. A frozen copy: nothing here can
// change the trust anchor at runtime. If the file does not load, this is
// null, checkKeyDocument refuses null, and every seal goes out unsigned
// (key_unpublished): fail closed, never a crash of verify.js.
function deepFreeze(v) {
  if (v && typeof v === "object") {
    for (const k of Object.keys(v)) deepFreeze(v[k]);
    Object.freeze(v);
  }
  return v;
}
const PUBLISHED_KEYS = (() => {
  try {
    return deepFreeze(JSON.parse(JSON.stringify(require("../public/.well-known/arcaeon/case-signing-keys.json"))));
  } catch (e) {
    console.error(`[case] the committed case key document did not load (${e && e.message}); every seal is unsigned`);
    return null;
  }
})();

// THE TRIGGER, above: case files read per sealer run, at most.
const SEALER_CASE_READS = 25;

const CASE_FILE_RE = /^cases\/([0-9a-f]{64})\.json$/;
const CASE_REG_RE = /^cases\/([0-9a-f]{64})\/commit_([ab])\.json$/;
const CASE_PIN_LATEST_RE = /^pins\/case\/([0-9a-f]{64})\/latest\.json$/;
// The withdrawal's marker (item 2c): lib/_case.js withdrawnMarkerPath.
const CASE_WITHDRAWN_RE = /^cases\/([0-9a-f]{64})\/withdrawn$/;
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
// from (SEPARATION FAILS CLOSED, above), then requires the key to be an
// active entry of the key document (PUBLICATION FAILS CLOSED, above).
// `keyDocument` is the committed document (PUBLISHED_KEYS) unless a test
// hands it another; the verify.js dispatch never does. Never logs or
// returns a private key:
// -> {ok:true, name, keyId, verifier, privateKey, entry} or
//    {ok:false, code, reason[, keyId, verifier]} (the public half only,
//    when the key parsed, so the entry for it can be printed).
function loadCaseSigner(env = process.env, { keyDocument = PUBLISHED_KEYS } = {}) {
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
  const keyId = keyIdOf(k);
  const pub = activeEntry(keyDocument, keyId, verifier);
  if (!pub.ok) return { ok: false, code: "key_unpublished", reason: pub.reason, keyId, verifier };
  return { ok: true, name: k.name, keyId, verifier, privateKey: k.privateKey, entry: pub.entry };
}

// PUBLICATION FAILS CLOSED, above: the document's entry for `keyId`, active,
// holding exactly `verifier` (the whole string: a key id is the name and a
// 32-bit hash, and only the verifier names the key's bytes).
// -> {ok:true, entry} or {ok:false, reason}.
function activeEntry(doc, keyId, verifier) {
  const c = checkKeyDocument(doc);
  if (!c.ok) {
    return { ok: false, reason: `the case key document does not read (${c.reason} at ${c.at}), so no case key is published and the configured key is not used` };
  }
  const e = c.keys.find((x) => x.key_id === keyId);
  if (!e) return { ok: false, reason: `the configured case signing key ${keyId} is not listed in ${CASE_KEYS_DOC}, so it is not used` };
  if (e.status !== "active") return { ok: false, reason: `the configured case signing key ${keyId} is listed in ${CASE_KEYS_DOC} as ${e.status}, not active, so it is not used` };
  if (e.verifier !== verifier) return { ok: false, reason: `the entry for ${keyId} in ${CASE_KEYS_DOC} holds another verifier, so the configured key is not used` };
  return { ok: true, entry: e };
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

// A NEW object: `unsigned` signed with `signer`, or unsigned with the reason
// in the form "<unsignedWords> (<code>): <why>.". One routine for every
// record the case key signs (a sealed case, a withdrawal record, a reference
// row: item 2c). signed_by is set here and nowhere else, before the
// signature is taken, so it is inside the signed bytes (SIGNED_BY, above).
function signRecord(unsigned, signer, unsignedWords) {
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
    rec.sig_reason = `${unsignedWords} (${code}): ${signer && signer.reason ? signer.reason : "no signer"}.`;
  }
  return rec;
}

function signCase(unsigned, signer) {
  return signRecord(unsigned, signer, "This case is sealed and not signed");
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
  // A RECEIPT IS THE SERVICE'S, above: no signer, or an unsigned receipt, never seals.
  if (!signer || !signer.ok || r.sig === null) return no("receipt_unsigned");
  if (r.signer.verifier !== signer.verifier || r.signer.name !== signer.name) return no("receipt_signer_mismatch");
  const v = receipts.verifyReceiptText(T.wireJson(r), signer.verifier);
  if (!v.ok) return no(`receipt_${v.reason}`);
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

// A RECEIPT IS THE SERVICE'S, above. Why a bound receipt `r` is not signed
// by the service's reconcile signer, `expected` (a verifier string, or null
// when the reader knows none): one of RECEIPT_UNSIGNED_REASONS, or a
// verifyReceiptText reason under `expected` (the receipt was altered after
// signing), or null when it holds.
const RECEIPT_UNSIGNED_REASONS = Object.freeze(["unsigned", "no_reconcile_verifier", "unknown_signer"]);
function receiptSignerReason(r, expected) {
  if (r.sig === null) return "unsigned";
  if (typeof expected !== "string" || !expected) return "no_reconcile_verifier";
  if (r.signer.verifier !== expected) return "unknown_signer";
  const v = receipts.verifyReceiptText(T.wireJson(r), expected);
  return v.ok ? null : v.reason;
}

// The reader's expected verifier: `receiptVerifier` when the caller hands
// one (null meaning none), else THE SERVICE'S VERIFIER from the process
// environment (lib/_reconcile_receipt.js expectedVerifier).
function receiptVerifierOf(opts) {
  return opts && opts.receiptVerifier !== undefined ? opts.receiptVerifier : receipts.expectedVerifier(process.env);
}

// The full sealed-receipt check anchorCase runs before it pins (TWO WRITES,
// above): the binding, then the signature by the service's reconcile signer
// (A RECEIPT IS THE SERVICE'S, above), on the stored form, the bytes
// storableReceipt proved at seal time. `opts.receiptVerifier` as
// receiptVerifierOf. Returns a reason ("receipt_unsigned" for a receipt the
// service did not sign), or null when it holds.
function checkStoredReceipt(rec, opts = {}) {
  const why = checkSealedReceipt(rec);
  if (why) return why;
  const signed = receiptSignerReason(rec.verdict, receiptVerifierOf(opts));
  if (signed === null) return null;
  return RECEIPT_UNSIGNED_REASONS.includes(signed) ? "receipt_unsigned" : `receipt_${signed}`;
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
  if (C.singleParty(kase)) {
    throw new C.CaseError("status_inconsistent", "commitments", "one key id registered both roles: a single-party case is never sealed (SINGLE PARTY)");
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

// A signed record's signature (a case, a withdrawal record, a reference
// row: the lib/_check_record.js rule, Ed25519 over json-c14n:v1 of the
// record minus sig) under `verifierStr`, and the key the record names in
// signed_by is that verifier's key (SIGNED_BY, above). No schema, no clock.
// -> null when it holds, else {reason, field}.
function signatureReason(rec, verifierStr) {
  const sigBytes = Buffer.from(String(rec.sig), "base64");
  if (typeof rec.sig !== "string" || sigBytes.length !== 64 || sigBytes.toString("base64") !== rec.sig) {
    return { reason: "malformed_signature", field: "sig" };
  }
  const vk = checkpoint.parseVerifierKey(verifierStr);
  if (!vk.ok) return { reason: "bad_verifier", field: "verifier" };
  let good = false;
  try {
    good = crypto.verify(null, sealPreimage(rec), vk.publicKey, sigBytes);
  } catch {
    good = false;
  }
  if (!good) return { reason: "bad_signature", field: "sig" };
  if (keyIdOf(vk) !== rec.signed_by) return { reason: "signer_mismatch", field: "signed_by" };
  return null;
}

// A signed record's signature checked against the key document (fix 1 of
// item 2c, and every reader after it): the entry signed_by names must be
// listed and not revoked (a retired key's records stay trusted: the
// document's status_meaning), and the signature must verify under that
// entry's verifier. An unsigned record (sig null) is not this function's:
// the caller decides what unsigned means. `doc` defaults to the committed
// document. -> null when it holds, else a reason.
function publishedSignatureReason(rec, doc = PUBLISHED_KEYS) {
  if (rec.sig === null) return "unsigned";
  const c = checkKeyDocument(doc);
  if (!c.ok) return "key_document_unreadable";
  const e = c.keys.find((x) => x.key_id === rec.signed_by);
  if (!e) return "signer_unpublished";
  if (e.status === "revoked") return "signer_revoked";
  const sr = signatureReason(rec, e.verifier);
  return sr ? sr.reason : null;
}

// THE SEALED CHECK (item 2d): what every reader of a stored VERDICT holds
// it to before treating it as sealed, one routine so the readers cannot
// drift. anchorCase runs it before it pins, ?op=case-reference before it
// appends a row, and the case page before it shows a verdict. In order:
//   0. one key per role (red-team fix A): a case whose two commitments share
//      a key id is `single_party`, reason `same_key_both_roles`.
//   1. the receipt: its binding to the case's reveals, compared_at and
//      policy (a failure is `verdict_unbound`), then its signature by the
//      service's reconcile signer (red-team fix B, A RECEIPT IS THE
//      SERVICE'S, above): unsigned, under another verifier, or read where no
//      verifier is known is `receipt_unsigned`, with the reason `unsigned`,
//      `unknown_signer` or `no_reconcile_verifier`; a signature by that
//      signer that does not verify is `verdict_unbound`.
//   2. the case's own signature, when it is signed: under the verifier its
//      signed_by names in the key document, an entry that is listed and not
//      revoked (publishedSignatureReason). A failure is
//      `case_signature_invalid`. An unsigned seal has no signature to check
//      and passes as the seal it is.
// `rec` is a case the schema already accepts, with status VERDICT. `doc`
// is the key document (the committed one when undefined).
// `opts.receiptVerifier` is the service's reconcile verifier (null for
// none); when undefined it is read from the process environment
// (receiptVerifierOf).
// -> null when it holds, else {code, reason}.
function sealedRecordReason(rec, doc = PUBLISHED_KEYS, opts = {}) {
  if (C.singleParty(rec)) return { code: "single_party", reason: "same_key_both_roles" };
  const unbound = checkSealedReceipt(rec);
  if (unbound) return { code: "verdict_unbound", reason: unbound };
  const signed = receiptSignerReason(rec.verdict, receiptVerifierOf(opts));
  if (signed !== null && RECEIPT_UNSIGNED_REASONS.includes(signed)) return { code: "receipt_unsigned", reason: signed };
  if (signed !== null) return { code: "verdict_unbound", reason: `receipt_${signed}` };
  if (rec.sig !== null) {
    const bad = publishedSignatureReason(rec, doc);
    if (bad) return { code: "case_signature_invalid", reason: bad };
  }
  return null;
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
  const sr = signatureReason(rec, verifierStr);
  if (sr) return bad(sr.reason, sr.field);
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
// it, and pin that. Before any pin write: the schema; the root's state
// (TERMINAL STATES, above: WITHDRAWN, or OPEN or COMMITTED at or past its
// deadline, is `terminal`, and nothing more is read or written); the full
// sealed-receipt check; and the stored case's own signature under the
// verifier its signed_by names in the key document (item 2c, fix 1).
//   opts.now          the run's clock, epoch milliseconds
//   opts.keyDocument  the key document the signature is checked against;
//                     the committed one unless a test hands another
//   opts.receiptVerifier  the service's reconcile verifier (A RECEIPT IS THE
//                     SERVICE'S); read from the process environment when
//                     undefined
// -> {ok:true, chain, pin, ...} or {ok:false, code[, status, reason]}.
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
  const status = got.json.status;
  // TERMINAL STATES (item 2c, fix 6): never sealed, so never anchored.
  if (status === "WITHDRAWN") return { ok: false, code: "terminal", status: "WITHDRAWN" };
  if (status !== "VERDICT" && C.pastDeadline(got.json, nowMs)) return { ok: false, code: "terminal", status: "EXPIRED" };
  // SINGLE PARTY (red-team fix A): never sealed, whatever its status reads.
  if (C.singleParty(got.json)) return { ok: false, code: "not_sealed", status, reason: "single_party" };
  if (status !== "VERDICT") return { ok: false, code: "not_sealed", status };
  // THE SEALED CHECK, before any pin write (TWO WRITES, above): the full
  // sealed-receipt check, then the stored case's own signature (item 2c, fix
  // 1). An unsigned seal is still a seal and is pinned as one.
  const unsealed = sealedRecordReason(got.json, opts.keyDocument === undefined ? PUBLISHED_KEYS : opts.keyDocument, { receiptVerifier: opts.receiptVerifier });
  if (unsealed) return { ok: false, code: unsealed.code, reason: unsealed.reason };
  const chain = caseChain(got.json);
  const p = await pinChain(caseId, chain, nowMs);
  return { ok: true, chain, ...p };
}

// A pin pointer under a case that is not sealed: a pin no seal backs. Read
// and judged, never written over. -> {pin: "unreadable" | "conflict" |
// "absent" | "unknown", reason?}.
async function strayPin(caseId) {
  const { ns, latest } = pinPaths(caseId);
  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return { pin: "unknown", reason: "store_unreachable" };
  }
  if (cur === null) return { pin: "absent" };
  const v = judgeSeal(cur, latest, ns);
  if (!v.ok) return { pin: "unreadable", reason: v.reason };
  return { pin: "conflict", reason: "pin_without_seal" };
}

// ---------------------------------------------------------------------------
// the readers: the pins tree, the sealer's pass, the status row
// ---------------------------------------------------------------------------
// What a recursive tree listing (lib/_store.js getTree / getTreeMeta entries)
// says about the cases, by path alone: which case files exist, which roles
// hold a registration file, which cases hold a pin pointer, and which carry
// the withdrawn marker cases/<case_id>/withdrawn (item 2c).
function caseTreeIndex(entries) {
  const cases = new Set();
  const regs = new Map();
  const pinned = new Set();
  const withdrawn = new Set();
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
    m = CASE_WITHDRAWN_RE.exec(e.path);
    if (m) {
      withdrawn.add(m[1]);
      continue;
    }
    m = CASE_PIN_LATEST_RE.exec(e.path);
    if (m) pinned.add(m[1]);
  }
  // Only a case with both registration files can be sealed (a VERDICT
  // carries both roles' registrations, and the reveal reads both files).
  const sealable = [...cases].filter((id) => regs.has(id) && regs.get(id).size === 2).sort();
  return { cases, regs, pinned, withdrawn, sealable };
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

// The sealer's pass (THE TRIGGER, above). Never throws. The candidates are
// every case that holds both registration files and no withdrawn marker,
// PINNED ONES INCLUDED (item 2c, fix 5; Gemini's review of 2b: with pinned
// cases left out, a squatter or unreadable pin was never looked at again),
// so the rotating window reaches a pinned case too and judges its
// latest.json with the case_seal judge (through anchorCase and pinChain, or
// strayPin for a case that is not sealed), and reports what it found. A case
// with the withdrawn marker is not considered at all, by the tree alone
// (fix 6), and a root read as WITHDRAWN or past its deadline unrevealed is
// skipped and reported as `terminal`.
// -> a report:
//   {ok:true, candidates, pinned, withdrawn_skipped, read, deferred,
//    anchored: [ids pinned now], already: [ids found pinned],
//    not_sealed, single_party: [ids, each also counted in not_sealed],
//    terminal: [{case_id, status}],
//    pending: [{case_id, reason}], refused: [{case_id, code, reason}],
//    conflict: [ids], unreadable: [ids], truncated}
//   or {ok:false, reason, detail} when the tree cannot be read (nothing
//   written).
async function anchorPending({ now = Date.now(), maxReads = SEALER_CASE_READS, keyDocument, receiptVerifier } = {}) {
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  let meta;
  try {
    meta = await store.getTreeMeta();
  } catch (e) {
    return { ok: false, reason: "tree_unreadable", detail: e && e.message ? e.message : null };
  }
  const idx = caseTreeIndex(meta.entries);
  const candidates = idx.sealable.filter((id) => !idx.withdrawn.has(id));
  const picked = rotatingWindow(candidates, maxReads, nowMs);
  const out = {
    ok: true,
    candidates: candidates.length,
    pinned: candidates.filter((id) => idx.pinned.has(id)).length,
    withdrawn_skipped: idx.sealable.length - candidates.length,
    read: picked.length,
    deferred: candidates.length - picked.length,
    anchored: [],
    already: [],
    not_sealed: 0,
    single_party: [],
    terminal: [],
    pending: [],
    refused: [],
    conflict: [],
    unreadable: [],
    truncated: meta.truncated === true,
  };
  for (const id of picked) {
    let r;
    try {
      r = await anchorCase(id, { now: nowMs, keyDocument, receiptVerifier });
    } catch (e) {
      out.refused.push({ case_id: id, code: "threw", reason: e && e.message ? e.message : null });
      continue;
    }
    if (!r.ok) {
      // A pin pointer under a case that is not sealed is judged, not skipped.
      if ((r.code === "not_sealed" || r.code === "terminal") && idx.pinned.has(id)) {
        const s = await strayPin(id);
        if (s.pin === "unreadable") {
          out.unreadable.push(id);
          continue;
        }
        if (s.pin === "conflict") {
          out.conflict.push(id);
          continue;
        }
        if (s.pin === "unknown") {
          out.pending.push({ case_id: id, reason: s.reason });
          continue;
        }
      }
      if (r.code === "terminal") out.terminal.push({ case_id: id, status: r.status });
      else if (r.code === "not_sealed") {
        out.not_sealed += 1;
        if (r.reason === "single_party") out.single_party.push(id);
      } else if (r.code === "store_unreachable") out.pending.push({ case_id: id, reason: r.code });
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
// already read and from nothing else: it never fetches a case file or a pin
// (item 2c, fix 3; Gemini's review of 2b: up to 100 sequential reads a
// render). By path alone:
//   case_files  the cases/<case_id>.json files
//   anchored    a case file with both registration files and a pin pointer,
//               pins/case/<case_id>/latest.json
//   pending     a case file with both registration files, no pin pointer and
//               no withdrawn marker. The tree cannot tell which this is:
//               sealed and waiting for the sealer's pin, not yet revealed,
//               or past its deadline with no reveal.
//   withdrawn   a case file with the marker cases/<case_id>/withdrawn, never
//               counted as pending
//   partial     the tree read was truncated (lib/_store.js getTree's
//               `truncated`), so every count above may be short
// Never throws; feeds no verdict.
function caseAnchorSummary(entries, { truncated = false } = {}) {
  const idx = caseTreeIndex(entries);
  let anchored = 0;
  let pending = 0;
  let withdrawn = 0;
  for (const id of idx.cases) {
    if (idx.withdrawn.has(id)) {
      withdrawn += 1;
      continue;
    }
    if (!(idx.regs.has(id) && idx.regs.get(id).size === 2)) continue;
    if (idx.pinned.has(id)) anchored += 1;
    else pending += 1;
  }
  return { case_files: idx.cases.size, anchored, pending, withdrawn, partial: truncated === true };
}

// ---------------------------------------------------------------------------
// the withdrawal record and the reference row (item 2c)
// ---------------------------------------------------------------------------
// The sentence a withdrawal's answer and a WITHDRAWN case's page carry
// (design decision 3: "the page for a WITHDRAWN case says in words that
// registrations, if any, remain in the public record").
const WITHDRAWN_REGISTRATIONS_NOTE =
  "The registration files of this case, if any, remain in the public record of the pins repository. A withdrawal " +
  "does not erase them, and this withdrawal record does not list them.";

// The redacted record that replaces an OPEN or COMMITTED case (lib/_case.js,
// THE WITHDRAWAL), signed with the case key like a seal, or unsigned with
// its reason. Pure; `salt` is hashed here and goes nowhere else. Throws
// CaseError if the result would not be a valid record (this service's
// defect).
//   kase    the OPEN or COMMITTED case, as stored and validated
//   role    the role whose commitment preimage proved it
//   at      the service clock, UTC seconds
//   salt    the role's salt, already matched to its registration
function withdrawnRecord(kase, { role, at, salt }, signer) {
  if (!C.REGISTERABLE_STATUSES.includes(kase.status)) {
    throw new C.CaseError("status_inconsistent", "status", `only an OPEN or COMMITTED case is withdrawn; this one is ${kase.status}`);
  }
  const unsigned = {
    v: C.CASE_VERSION,
    case_id: kase.case_id,
    protocol_version: kase.protocol_version,
    status: "WITHDRAWN",
    opened_at: kase.opened_at,
    withdrawal: { by_role: role, at, salt_sha256: C.saltSha256(salt) },
    limits: C.LIMITS.slice(),
  };
  const rec = signRecord(unsigned, signer, "This withdrawal record is not signed");
  const v = C.validateCase(rec);
  if (!v.ok) throw new C.CaseError(v.code, v.field, `the withdrawal record would not be a valid record (${v.error})`);
  return rec;
}

// A reference row (lib/_case.js, THE REFERENCE ROW), signed with the case
// key, or unsigned with its reason. Pure. Throws CaseError on a row the
// schema refuses.
function referenceRow({ caseId, seq, crossReference, recordedAt, appendedBy }, signer) {
  const unsigned = {
    kind: C.REFERENCE_KIND,
    v: 1,
    case_id: caseId,
    seq,
    cross_reference: { operator: crossReference.operator, reference: crossReference.reference, url: crossReference.url },
    recorded_at: recordedAt,
    appended_by: appendedBy,
    anchor_note: C.REFERENCE_ANCHOR_NOTE,
  };
  const rec = signRecord(unsigned, signer, "This reference row is not signed");
  const v = C.validateReferenceRow(rec);
  if (!v.ok) throw new C.CaseError(v.code, v.field, `the reference row would not be a valid row (${v.error})`);
  return rec;
}

// The case_reference judge: a stored row, read through the store, against
// its path and the sealed case it belongs to. Exactly the row's fields (the
// schema), its case and seq the path's, recorded no earlier than the seal,
// and, when signed, a signature the key document confirms
// (publishedSignatureReason). A signed row the document cannot confirm is
// not valid. An unsigned row is valid and unsigned, as an unsigned seal is
// a seal. -> a lib/_verdict.js verdict.
function judgeReferenceRow(got, { path, caseId, seq, sealed, keyDocument = PUBLISHED_KEYS }) {
  return verdict.judgeWith(got, path, (json) => {
    const r = C.validateReferenceRow(json);
    if (!r.ok) return `reference_${r.code}`;
    if (json.case_id !== caseId || json.seq !== seq) return "reference_not_at_its_path";
    if (sealed && sealed.reveals && Date.parse(json.recorded_at) < Date.parse(sealed.reveals.a.revealed_at)) return "reference_before_seal";
    if (json.sig !== null) {
      const bad = publishedSignatureReason(json, keyDocument);
      if (bad) return `reference_signature_${bad}`;
    }
    return true;
  });
}

const REFERENCE_NAME_RE = /^([0-9]{8})\.json$/;
// Reference rows read per live count, at most (the page's read bound).
const REFERENCE_ROW_READS = 20;

// The seqs the references directory holds, ascending, by name alone. A
// listing that cannot be read throws (the caller says so; it is never read
// as "no rows").
async function referenceSeqs(caseId) {
  const entries = await store.listDir(C.referencesDir(caseId));
  const seqs = [];
  for (const e of entries) {
    const m = e && e.type === "file" && typeof e.name === "string" ? REFERENCE_NAME_RE.exec(e.name) : null;
    if (m && Number(m[1]) >= 1) seqs.push(Number(m[1]));
  }
  return seqs.sort((x, y) => x - y);
}

// THE LIVE RECORD COUNT (design, "After item 2b": "the sealed records field
// is the count at seal time and never changes; the page derives the live
// count from valid addenda"). 2 when the sealed case carries its
// cross_reference or at least one valid reference row exists, else 1:
// records counts operators that hold a record of this case, one or two,
// never rows. Reads the references directory and at most `maxRows` rows, in
// seq order. Never throws.
//   NEVER A COUNT FROM A TRUNCATED READ (item 2d; the code review of 2c: with
// twenty invalid rows before a valid one, the window read only the twenty
// and said "one record"). The count is 2 as soon as the seal carries its
// cross_reference or one valid row is read, whatever was left unread: a
// record is at most two, so no unread row can change it. It is 1 only when
// the read was whole, every listed row read and judged, and none is valid.
// When the read ends without a valid row and a listed row was not seen (left
// past the window, or a read of it that failed, which is not an invalid
// row), that row might be valid, so the count is NOT ESTABLISHED:
// `indeterminate: true` and `records: null`, never 1. A caller says so in
// words; it never reads null as one.
// -> {ok:true, records: 1 | 2 | null, indeterminate, sealed_records, rows:
//     [valid rows], invalid: [{seq, reason}], unreadable: [seqs whose read
//     failed], unread, partial} or {ok:false, reason}.
async function liveRecords(sealed, { keyDocument = PUBLISHED_KEYS, maxRows = REFERENCE_ROW_READS } = {}) {
  if (!sealed || sealed.status !== "VERDICT") return { ok: false, reason: "not_sealed" };
  let seqs;
  try {
    seqs = await referenceSeqs(sealed.case_id);
  } catch {
    return { ok: false, reason: "references_unreadable" };
  }
  const picked = seqs.slice(0, maxRows);
  const rows = [];
  const invalid = [];
  const unreadable = [];
  for (const seq of picked) {
    const p = C.referencePath(sealed.case_id, seq);
    let got;
    try {
      got = await store.getFile(p);
    } catch {
      unreadable.push(seq); // not seen, so not judged: never counted as invalid
      continue;
    }
    if (got === null) continue; // listed, then gone
    const v = judgeReferenceRow(got, { path: p, caseId: sealed.case_id, seq, sealed, keyDocument });
    if (v.ok) rows.push(got.json);
    else invalid.push({ seq, reason: v.reason });
  }
  const unread = seqs.length - picked.length;
  const whole = unread === 0 && unreadable.length === 0;
  const two = sealed.cross_reference !== null || rows.length > 0;
  const indeterminate = !two && !whole;
  return {
    ok: true,
    records: two ? 2 : indeterminate ? null : 1,
    indeterminate,
    sealed_records: sealed.records,
    rows,
    invalid,
    unreadable,
    unread,
    partial: unread > 0,
  };
}

// ---------------------------------------------------------------------------
// the published key document (SIGNED_BY, above)
// ---------------------------------------------------------------------------
// The entry the document carries for a case key: a loaded signer, or
// loadCaseSigner's key_unpublished answer, which carries the public half
// (keyId, verifier) of a key that parsed and is not listed yet. Only the
// public half is read.
function keyDocumentEntry(signer, { since, note, status = "active" }) {
  if (!signer || typeof signer.keyId !== "string" || typeof signer.verifier !== "string") {
    throw new TypeError("keyDocumentEntry: a case key that parsed (keyId and verifier) is required");
  }
  const vk = checkpoint.parseVerifierKey(signer.verifier);
  if (!vk.ok || keyIdOf(vk) !== signer.keyId) throw new TypeError("keyDocumentEntry: keyId is not the key the verifier names");
  return { key_id: signer.keyId, verifier: signer.verifier, since, note, status };
}

// The document's shape. -> {ok:true, keys} or {ok:false, reason, at}.
function checkKeyDocument(doc) {
  const no = (reason, at) => ({ ok: false, reason, at });
  if (!isPlainObject(doc)) return no("not_an_object", "$");
  // Exact fields, like every record here (item 2c, fix 4): a top-level field
  // the checker does not know is a field a reader might trust that nobody
  // checked.
  for (const k of Object.keys(doc)) if (!CASE_KEYS_TOP_FIELDS.includes(k)) return no("unknown_field", k);
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
  CASE_KEYS_FILE,
  CASE_KEYS_SCHEMA,
  CASE_KEY_ENTRY_FIELDS,
  PUBLISHED_KEYS,
  SEALER_CASE_READS,
  loadCaseSigner,
  sealPreimage,
  caseChain,
  signCase,
  checkReceipt,
  storableReceipt,
  checkSealedReceipt,
  checkStoredReceipt,
  RECEIPT_UNSIGNED_REASONS,
  sealedRecordReason,
  sealCase,
  verifyCase,
  signatureReason,
  publishedSignatureReason,
  signRecord,
  WITHDRAWN_REGISTRATIONS_NOTE,
  withdrawnRecord,
  referenceRow,
  judgeReferenceRow,
  referenceSeqs,
  liveRecords,
  REFERENCE_ROW_READS,
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
  _internal: { receiptBinding, pinRecord, isOurPin, rotatingWindow, verifierOf, keyIdOf, activeEntry, strayPin },
};

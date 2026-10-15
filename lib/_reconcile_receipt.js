// _reconcile_receipt.js — the signed receipt of one hosted completeness
// verdict. Underscore prefix = not routed as a serverless function by Vercel.
//
// What a receipt says, all of it: "these two tapes, as submitted, compared
// like this at this time". It binds
//   * the sha256 of each tape's bytes exactly as the service received them,
//   * the method (the reconcile.py rules, the port's version, and the sha256
//     of the reference source it was checked against),
//   * the verdict (word, call, side, counts) and the json-c14n digest of the
//     whole verdict document the service returned beside it,
//   * the time the service compared them,
// and it lists what it does NOT claim, inside the signed bytes, so the
// disclaimer cannot be cut off a copy without breaking the signature.
//
// Signing reuses the witness's existing key shape (lib/_checkpoint.js): one
// Ed25519 key in the signer-string format
//   PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 || seed)>
// read from ONE environment variable, and the public half published as the
// verifier string <name>+<8 hex>+<base64(0x01 || pub)>, which the receipt
// carries. The preimage is the check-record rule (lib/_check_record.js): the
// json-c14n:v1 bytes of the whole receipt minus `sig`.
//
// The key is its own key, not the log's. WITNESS_LOG_SIGNER_KEY signs
// checkpoints of the witness log; a receipt signed with it would let a
// reader confuse "the witness log says" with "this service compared two
// uploads".
//
// NO SIGNER, NO RECEIPT (red-team fix B; GPT-5.6's red-team review, §3.1:
// "Fabricate a case verdict without actually running reconcile": an
// unsigned reconcile receipt passed the stored-receipt check, a function
// removed in unit R-SIG). This
// service never produces an unsigned receipt: when WITNESS_RECONCILE_SIGNER_KEY
// is absent or does not parse, ?op=reconcile and the case reveal refuse with
// 503 signer_unavailable and compare nothing (lib/_reconcile_http.js
// compare). signReceipt still writes the unsigned form (`sig: null`,
// `unsigned_reason`) when handed no signer, because a receipt from before
// this rule, or one written by hand, can take that shape and readers must
// recognise it; no path of this service hands it no signer. Since Design I
// the key must also be an active reconcile entry of the key document the
// deployment carries (lib/_case_seal.js loadReconcileSigner), and a reader
// holds a stored receipt to the reconcile entry of the document the sealed
// case NAMES (lib/_case_seal.js THE SEALED CHECK), never to its own
// environment. THE SERVICE'S VERIFIER (expectedVerifier) is only the
// private-side pointer to which published entry is the service's, for the
// operator's tools (tools/preview_dry_run.js): the public half of
// WITNESS_RECONCILE_SIGNER_KEY where this environment holds it, else
// WITNESS_RECONCILE_VERIFIER, the verifier string alone.

"use strict";

const crypto = require("node:crypto");
const checkpoint = require("./_checkpoint.js");
const T = require("./_reconcile_tapes.js");

const RECEIPT_KIND = "arcaeon-reconcile-receipt";
const RECEIPT_VERSION = 1;
const SIGNER_ENV = "WITNESS_RECONCILE_SIGNER_KEY";
// NO SIGNER, NO RECEIPT, above: the private-side pointer to the service's
// published reconcile entry, its verifier string (public).
const VERIFIER_ENV = "WITNESS_RECONCILE_VERIFIER";

const CLAIM = "These two tapes, as submitted, compared like this at this time.";

const DOES_NOT_CLAIM = Object.freeze([
  "It does not claim either tape is a true or complete record of any agent's calls. " +
    "The service saw only the bytes submitted to it, and nothing about where they came from.",
  "It does not claim the two tapes came from independent recorders. A tape the operator " +
    "owns is not an outside witness; MATCHED between two tapes one party wrote is consistency, not independence.",
  "It does not claim anything about calls that crossed neither recorder.",
  "It does not claim the tapes were not cut or rewritten in agreement. No witness pin was checked.",
  "It does not keep the tapes. Only their digests are in this receipt.",
]);

function nowIso(now) {
  return new Date(now === undefined ? Date.now() : now).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function methodBlock() {
  return {
    rules: "arcaeon_ledger.reconcile (arcaeon-ledger 0.8.0), two tapes, no pin",
    impl: "js-port",
    port: "arcaeon-witness lib/_reconcile_tapes.js",
    port_version: T.PORT_VERSION,
    reference: {
      package: T.REFERENCE.package,
      version: T.REFERENCE.version,
      module: T.REFERENCE.module,
      reconcile_sha256: T.REFERENCE.reconcile_sha256,
      ledger_init_sha256: T.REFERENCE.ledger_init_sha256,
    },
  };
}

// The receipt before signing. `result` is reconcileTapes()'s dict.
function buildReceipt({ bytesA, bytesB, result, now }) {
  const verdictDigest = T.digestC14n(result);
  const r = {
    kind: RECEIPT_KIND,
    v: RECEIPT_VERSION,
    claim: CLAIM,
    tapes: {
      tape_a: { digest: T.digestBytes(bytesA), bytes: bytesA.length },
      tape_b: { digest: T.digestBytes(bytesB), bytes: bytesB.length },
    },
    method: methodBlock(),
    verdict: {
      verdict: result.verdict,
      at: result.at,
      side: result.side,
      matched: result.matched,
      counts: result.counts,
      findings: result.findings.length,
      could_not_look: result.could_not_look.length,
      exit_code: result.exit_code,
    },
    verdict_digest: verdictDigest,
    compared_at: nowIso(now),
    does_not_claim: DOES_NOT_CLAIM.slice(),
  };
  if (verdictDigest === null) {
    // json-c14n:v1 is strict UTF-8 (arcaeon_ledger.artefact._canon_json) and a
    // reason quoting a tape's lone surrogate cannot be encoded. Say so; the
    // verdict word, call, side and counts above are still bound.
    r.verdict_digest_note = "the verdict text has a lone surrogate from a tape, which json-c14n:v1 cannot encode";
  }
  return r;
}

function preimage(receipt) {
  const body = {};
  for (const k of Object.keys(receipt)) if (k !== "sig") body[k] = receipt[k];
  const b = T.c14nBytes(body);
  if (b === null) throw new TypeError("reconcile receipt: not encodable as json-c14n:v1");
  return b;
}

// Reads the signer from the environment. Never logs or returns the key.
function loadSigner(env = process.env) {
  const s = env[SIGNER_ENV];
  if (!s) return { ok: false, reason: `no signer key configured (${SIGNER_ENV} is not set)` };
  const k = checkpoint.parseSignerKey(String(s).trim());
  if (!k.ok) return { ok: false, reason: `the configured signer key does not parse (${k.reason})` };
  const verifier = `${k.name}+${k.hash}+${Buffer.concat([Buffer.from([0x01]), k.pub]).toString("base64")}`;
  return { ok: true, name: k.name, verifier, privateKey: k.privateKey };
}

// THE SERVICE'S VERIFIER (NO SIGNER, NO RECEIPT, above): which published
// reconcile entry is the service's, read from `env`: the signer key's own
// verifier when it is set and parses, else VERIFIER_ENV's when that parses
// as a verifier. -> the verifier string, or null when neither names one.
function expectedVerifier(env = process.env) {
  const s = loadSigner(env);
  if (s.ok) return s.verifier;
  const v = env[VERIFIER_ENV];
  if (!v) return null;
  const t = String(v).trim();
  return checkpoint.parseVerifierKey(t).ok ? t : null;
}

// Sign in place. Returns the receipt (signed, or unsigned with the reason).
function signReceipt(receipt, signer) {
  if (!signer || !signer.ok) {
    receipt.signer = null;
    receipt.unsigned_reason = signer ? signer.reason : "no signer";
    receipt.sig = null;
    return receipt;
  }
  receipt.signer = { name: signer.name, verifier: signer.verifier, alg: "ed25519" };
  receipt.sig = crypto.sign(null, preimage(receipt), signer.privateKey).toString("base64");
  return receipt;
}

// Verify a receipt given as the JSON text the service returned (or any text
// holding just the receipt object). Reads it with the Python-faithful parser,
// so a call index past 2^53 still verifies. `expectVerifier` pins the key; a
// receipt signed by any other key, or checked with no key named, is refused
// as `unknown_signer` (unit R-WIDE, C7). A saved answer whose receipt has no
// verdict digest is `signed_partial`, never ok.
function verifyReceiptText(text, expectVerifier) {
  let m;
  try {
    m = T._internal.pyLoads(String(text).trim(), false);
  } catch (e) {
    return { ok: false, reason: "malformed_receipt" };
  }
  if (!(m instanceof Map)) return { ok: false, reason: "malformed_receipt" };
  // The whole saved answer ({ok, verdict, receipt, ...}) is accepted too; the
  // receipt inside it is what is checked, and the verdict beside it is held to
  // the receipt's verdict_digest.
  let served = null;
  if (m.get("receipt") instanceof Map) {
    served = m.get("verdict");
    m = m.get("receipt");
  }
  if (m.get("kind") !== RECEIPT_KIND || m.get("v") !== BigInt(RECEIPT_VERSION)) {
    return { ok: false, reason: "not_a_reconcile_receipt" };
  }
  const sig = m.get("sig");
  const signer = m.get("signer");
  if (sig === null || sig === undefined) return { ok: false, reason: "unsigned" };
  if (typeof sig !== "string" || !(signer instanceof Map) || typeof signer.get("verifier") !== "string") {
    return { ok: false, reason: "malformed_receipt" };
  }
  const vk = checkpoint.parseVerifierKey(signer.get("verifier"));
  if (!vk.ok) return { ok: false, reason: "malformed_signer" };
  // unit R-WIDE (C7): a receipt is held to a key the caller names; with
  // none named, the key the receipt names for itself proves nothing
  if (expectVerifier === undefined || signer.get("verifier") !== expectVerifier) {
    return { ok: false, reason: "unknown_signer" };
  }
  const sigBytes = Buffer.from(sig, "base64");
  if (sigBytes.toString("base64") !== sig || sigBytes.length !== 64) return { ok: false, reason: "malformed_signature" };
  const body = new Map(m);
  body.delete("sig");
  const text2 = T._internal.pyDumps(body, { sortKeys: true, itemSep: ",", keySep: ":", ascii: false, allowNan: false });
  const good = crypto.verify(null, Buffer.from(text2, "utf-8"), vk.publicKey, sigBytes);
  if (!good) return { ok: false, reason: "bad_signature" };
  if (served !== null && served !== undefined) {
    const d = m.get("verdict_digest");
    if (typeof d === "string" && T.digestC14n(served) !== d) return { ok: false, reason: "verdict_does_not_match_receipt" };
    // unit R-WIDE (C7): a receipt with no verdict digest (a tape's lone
    // surrogate; verdict_digest_note) binds the verdict word, call, side and
    // counts and not the verdict text beside it, so that text is not checked:
    // the signature holds, and the answer says it is partial
    if (typeof d !== "string") return { ok: false, reason: "signed_partial", signer: signer.get("verifier") };
  }
  return { ok: true, reason: "signed", signer: signer.get("verifier") };
}

module.exports = {
  RECEIPT_KIND,
  RECEIPT_VERSION,
  SIGNER_ENV,
  VERIFIER_ENV,
  CLAIM,
  DOES_NOT_CLAIM,
  buildReceipt,
  methodBlock, // read by lib/_case_seal.js's receipt check (case protocol item 2a)
  loadSigner,
  expectedVerifier,
  signReceipt,
  verifyReceiptText,
  preimage,
};

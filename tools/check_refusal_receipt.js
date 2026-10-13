#!/usr/bin/env node
// tools/check_refusal_receipt.js — check a refusal receipt (unit R-N2, m6;
// lib/_case_seal.js THE REFUSAL RECEIPT) without asking this service.
//
//   node tools/check_refusal_receipt.js <receipt.json> [--document <file>]
//
// With --document <file>: offline, and partial (unit R-N3, N3). It checks
// the receipt's form, the file's json-c14n:v1 sha256 against
// signed_under.document_sha256, signed_by an active reconcile key in that
// file, and the signature under it. That proves the signature against the
// document you supplied and nothing about whether that document is the
// published one: the trust root, that signed_under.document_commit is on
// the published branch, needs the network, and so does whether the key is
// still listed, not revoked, in the current document. So the offline check
// never prints ok: true. It prints {ok: false, reason: "offline_partial",
// signature_ok, signature_reason, not_checked} and exits 3, whatever it
// found (an input it cannot read is signature_ok: false, signature_reason
// "unreadable"). The exported offline() answers {signature_ok, reason},
// never a key named ok (unit R-N4, R4).
// Without --document: the readers' own check (verifyRefusalReceipt), which
// reads the named document from GitHub's raw host, checks its commit is on
// the published branch, and holds the key to the current document this
// checkout carries. Only this check prints ok: true and exits 0; it exits 1
// otherwise, and on a usage error.
"use strict";

const fs = require("fs");
const crypto = require("crypto");
const S = require("../lib/_case_seal.js");
const { canonicalBytes } = require("../lib/_check_record.js");

const NOT_CHECKED_OFFLINE = ["the document's commit is on the published branch", "the key is still listed, not revoked, in the current key document"];

function offline(rec, doc) {
  const no = (reason) => ({ signature_ok: false, reason });
  const form = S.refusalReceiptFormReason(rec);
  if (form) return no(form);
  if (crypto.createHash("sha256").update(canonicalBytes(doc)).digest("hex") !== rec.signed_under.document_sha256) return no("document_sha256_mismatch");
  const c = S.checkKeyDocument(doc);
  if (!c.ok) return no("named_document_unreadable");
  const e = c.keys.find((x) => x.key_id === rec.signed_by && (x.role === undefined ? "case" : x.role) === "reconcile");
  if (!e) return no("signer_unpublished");
  if (e.status !== "active") return no("signer_not_active");
  const sr = S.signatureReason(rec, e.verifier);
  return sr ? no(sr.reason) : { signature_ok: true, reason: null };
}

async function main(argv) {
  const file = argv.find((a, i) => !a.startsWith("--") && argv[i - 1] !== "--document");
  const at = argv.indexOf("--document");
  if (!file || (at >= 0 && !argv[at + 1])) {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: "usage", usage: "node tools/check_refusal_receipt.js <receipt.json> [--document <file>]" })}\n`);
    return 1;
  }
  if (at >= 0) {
    let sig;
    try {
      sig = offline(JSON.parse(fs.readFileSync(file, "utf8")), JSON.parse(fs.readFileSync(argv[at + 1], "utf8")));
    } catch {
      sig = { signature_ok: false, reason: "unreadable" };
    }
    process.stdout.write(`${JSON.stringify({ ok: false, reason: "offline_partial", signature_ok: sig.signature_ok, signature_reason: sig.reason,
      not_checked: NOT_CHECKED_OFFLINE }, null, 2)}\n`);
    return 3;
  }
  let out;
  try {
    out = await S.verifyRefusalReceipt(JSON.parse(fs.readFileSync(file, "utf8")));
  } catch (e) {
    out = { ok: false, reason: "unreadable", detail: e && e.message };
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  return out.ok === true ? 0 : 1;
}

if (require.main === module) main(process.argv.slice(2)).then((code) => process.exit(code));

module.exports = { offline, main };

#!/usr/bin/env node
// tools/check_refusal_receipt.js — check a refusal receipt (unit R-N2, m6;
// lib/_case_seal.js THE REFUSAL RECEIPT) without asking this service.
//
//   node tools/check_refusal_receipt.js <receipt.json> [--document <file>]
//
// With --document, the key document at the receipt's
// signed_under.document_commit, saved as a file: offline. The receipt's form,
// the document's json-c14n:v1 sha256 against signed_under.document_sha256,
// signed_by an active reconcile key there, and the signature under it. Two
// things need the network and are NOT checked offline, and the output says
// so: that the commit is on the published branch, and that the key is still
// listed, not revoked, in the current document.
// Without --document: the readers' own check (verifyRefusalReceipt), which
// reads the named document from GitHub's raw host and holds the key to the
// current document this checkout carries.
// Prints one JSON object; exits 0 when the receipt verifies, 1 otherwise.
"use strict";

const fs = require("fs");
const crypto = require("crypto");
const S = require("../lib/_case_seal.js");
const { canonicalBytes } = require("../lib/_check_record.js");

const NOT_CHECKED_OFFLINE = ["the document's commit is on the published branch", "the key is still listed, not revoked, in the current key document"];

function offline(rec, doc) {
  const no = (reason) => ({ ok: false, reason });
  const form = S.refusalReceiptFormReason(rec);
  if (form) return no(form);
  if (crypto.createHash("sha256").update(canonicalBytes(doc)).digest("hex") !== rec.signed_under.document_sha256) return no("document_sha256_mismatch");
  const c = S.checkKeyDocument(doc);
  if (!c.ok) return no("named_document_unreadable");
  const e = c.keys.find((x) => x.key_id === rec.signed_by && (x.role === undefined ? "case" : x.role) === "reconcile");
  if (!e) return no("signer_unpublished");
  if (e.status !== "active") return no("signer_not_active");
  const sr = S.signatureReason(rec, e.verifier);
  return sr ? no(sr.reason) : { ok: true, not_checked: NOT_CHECKED_OFFLINE };
}

async function main(argv) {
  const file = argv.find((a, i) => !a.startsWith("--") && argv[i - 1] !== "--document");
  const at = argv.indexOf("--document");
  if (!file || (at >= 0 && !argv[at + 1])) {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: "usage", usage: "node tools/check_refusal_receipt.js <receipt.json> [--document <file>]" })}\n`);
    return 1;
  }
  let out;
  try {
    const rec = JSON.parse(fs.readFileSync(file, "utf8"));
    out = at >= 0 ? offline(rec, JSON.parse(fs.readFileSync(argv[at + 1], "utf8"))) : await S.verifyRefusalReceipt(rec);
  } catch (e) {
    out = { ok: false, reason: "unreadable", detail: e && e.message };
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  return out.ok ? 0 : 1;
}

if (require.main === module) main(process.argv.slice(2)).then((code) => process.exit(code));

module.exports = { offline };

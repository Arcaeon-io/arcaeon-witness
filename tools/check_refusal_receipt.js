#!/usr/bin/env node
// tools/check_refusal_receipt.js — check a refusal receipt (unit R-N2, m6;
// lib/_case_seal.js THE REFUSAL RECEIPT) without asking this service.
//
//   node tools/check_refusal_receipt.js <receipt.json> [--document <file>]
//
// With --document <file>: offline, and partial (unit R-N3, N3). It checks
// the receipt's form, then the one reader (lib/_case_seal.js
// signedUnderReason, unit R-SIG) with the file in place of the named
// document: the file's json-c14n:v1 sha256 against
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
// never a key named ok (unit R-N4, R4); asynchronous since unit R-SIG.
// Without --document: the readers' own check (verifyRefusalReceipt), which
// reads the named document from GitHub's raw host, checks its commit is on
// the published branch, and holds the key to the current document this
// checkout carries, which (unit R-WIDE, B2) must be the document at the tip
// of the published branch (lib/_case_seal.js carriedDocumentPublished).
// Only this check prints ok: true and exits 0; else 1, as on a usage error.
"use strict";

const fs = require("fs");
const S = require("../lib/_case_seal.js");

const NOT_CHECKED_OFFLINE = ["the document's commit is on the published branch", "the key is still listed, not revoked, in the current key document"];

async function offline(rec, doc) {
  const form = S.refusalReceiptFormReason(rec);
  if (form) return { signature_ok: false, reason: form };
  // the one reader, with the file as the named document and no current one
  const a = await S.signedUnderReason(rec, "reconcile", null, { named: doc });
  return S.sealHolds(a) ? { signature_ok: true, reason: null } : { signature_ok: false, reason: a.reason };
}

// opts.keyDocument: the document this checkout carries (tests hand another).
async function main(argv, { keyDocument = S.PUBLISHED_KEYS, env = process.env } = {}) {
  const file = argv.find((a, i) => !a.startsWith("--") && argv[i - 1] !== "--document");
  const at = argv.indexOf("--document");
  if (!file || (at >= 0 && !argv[at + 1])) {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: "usage", usage: "node tools/check_refusal_receipt.js <receipt.json> [--document <file>]" })}\n`);
    return 1;
  }
  if (at >= 0) {
    let sig;
    try {
      sig = await offline(JSON.parse(fs.readFileSync(file, "utf8")), JSON.parse(fs.readFileSync(argv[at + 1], "utf8")));
    } catch {
      sig = { signature_ok: false, reason: "unreadable" };
    }
    process.stdout.write(`${JSON.stringify({ ok: false, reason: "offline_partial", signature_ok: sig.signature_ok, signature_reason: sig.reason,
      not_checked: NOT_CHECKED_OFFLINE }, null, 2)}\n`);
    return 3;
  }
  let out;
  try {
    out = await S.verifyRefusalReceipt(JSON.parse(fs.readFileSync(file, "utf8")), keyDocument);
  } catch (e) {
    out = { ok: false, reason: "unreadable", detail: e && e.message };
  }
  if (out.ok === true) {
    const pub = await S.carriedDocumentPublished(keyDocument, env);
    if (!pub.ok) out = { ok: false, reason: pub.code, detail: pub.reason };
  }
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  return out.ok === true ? 0 : 1;
}

if (require.main === module) main(process.argv.slice(2)).then((code) => process.exit(code));

module.exports = { offline, main };

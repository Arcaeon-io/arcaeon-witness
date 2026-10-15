#!/usr/bin/env node
// tools/check_refusal_receipt.js — check a refusal receipt (unit R-N2, m6;
// lib/_case_seal.js THE REFUSAL RECEIPT) without asking this service.
//
//   node tools/check_refusal_receipt.js <receipt.json> [--document <file>]
//
// With --document <file>: offline, and partial (unit R-N3, N3). It checks
// the form, then the one reader (lib/_case_seal.js signedUnderReason) with
// the file as the named document: its json-c14n:v1 sha256 against
// signed_under.document_sha256, signed_by an active reconcile key in it, the
// signature under it. That proves the signature against the document you
// supplied and nothing about whether that document is the published one
// (its commit on the published branch, and the key still listed, not
// revoked, need the network). It prints {ok: false, reason:
// "offline_partial", signature_ok, signature_reason, not_checked}, exit 3.
// offline() answers {signature_ok, reason}, never a key named ok (R-N4, R4).
// Without --document: the readers' own check (verifyRefusalReceipt) under
// the document this checkout carries, which (unit R-WIDE, B2) must be the
// one at the tip of the published branch (carriedDocumentPublished). Since
// R-WIDE (C5) it prints {signature_valid, [reason, detail,] not_checked},
// never a key named ok, and names what no receipt shows: whether the case
// reads WITHDRAWN now, and the projection its record keeps. Exit 0 only for
// signature_valid: true; 1 otherwise, and on a usage error.
"use strict";

const fs = require("fs");
const S = require("../lib/_case_seal.js");

const NOT_CHECKED_ONLINE = ["whether the case reads WITHDRAWN now", "the projection the withdrawal record keeps"];
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
  const said = out.ok === true ? { signature_valid: true } : { signature_valid: false, reason: out.reason, ...(out.detail ? { detail: out.detail } : {}) };
  process.stdout.write(`${JSON.stringify({ ...said, not_checked: NOT_CHECKED_ONLINE }, null, 2)}\n`);
  return said.signature_valid ? 0 : 1;
}

if (require.main === module) main(process.argv.slice(2)).then((code) => process.exit(code));

module.exports = { offline, main };

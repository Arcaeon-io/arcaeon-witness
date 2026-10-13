// _case_unregister.js — the one deletion this service makes in the pins
// repository, and the only one it can make (red-team fix C, 2026-10-12;
// GPT-5.6 §1.1 / §6.2: "A commitment can land after withdrawal").
// Underscore prefix = not routed as a serverless function.
//
// The public record only grows (test/no_delete_record.test.js), with one
// decided exception: a registration file, cases/<case_id>/commit_<role>.json,
// that must not stand. lib/_case_http.js THE CASE LOCK makes a registration
// that landed after its case was withdrawn a lost race (the registration's
// lock lease ran out and the withdrawal took it over), and removes it inside
// the same critical section; since unit R-N (C2) it also removes one whose
// case could not be read after its write, and lib/_case_seal.js
// repairWithdrawn removes, on the sealer's run, one written after the
// withdrawal whose first removal failed (C1). The removal is itself a
// commit, so the file stays in the repository's history. Since unit R-L
// (L3) a commit message is not a record: no removal is made unless a signed
// repair note, removals/<case_id>/<sha256 of the path>.json, is there and
// names this file and blob (lib/_case_seal.js THE REPAIR NOTE writes it
// first, and verifies it).
//
// Anything but a registration file is refused before any request is made.
"use strict";

const crypto = require("crypto");
const store = require("./_store.js");

const API = "https://api.github.com";
const REGISTRATION_FILE = /^cases\/([0-9a-f]{64})\/commit_[ab]\.json$/;
const BLOB_SHA = /^[0-9a-f]{40}$/;

// Remove the registration file at `path`, whose current blob sha is
// `blobSha` (the contents API removes a file only at the blob it names).
// -> {commit} (the removal's commit, or null when the answer named none).
// Throws on anything else, and on a store that does not remove it.
async function removeRegistrationAfterWithdrawal(path, blobSha, message) {
  if (typeof path !== "string" || !REGISTRATION_FILE.test(path)) {
    throw new TypeError("removeRegistrationAfterWithdrawal: only a case's registration file is ever removed");
  }
  if (typeof blobSha !== "string" || !BLOB_SHA.test(blobSha)) {
    throw new TypeError("removeRegistrationAfterWithdrawal: the file's blob sha is required");
  }
  // THE REPAIR NOTE FIRST (unit R-L, L3): one there, naming this file and blob
  const caseId = REGISTRATION_FILE.exec(path)[1];
  const notePath = `removals/${caseId}/${crypto.createHash("sha256").update(path, "utf8").digest("hex")}.json`;
  let note;
  try {
    note = await store.getFile(notePath);
  } catch {
    throw new Error(`the repair note for ${path} could not be read, so nothing was removed`);
  }
  const n = note && note.json;
  if (!n || n.case_id !== caseId || n.removed_path !== path || n.removed_blob_sha !== blobSha) {
    throw new Error(`no repair note names ${path} at this blob, so nothing was removed`);
  }
  const headers = {
    accept: "application/vnd.github+json",
    "user-agent": "arcaeon-witness",
    "x-github-api-version": "2022-11-28",
    "content-type": "application/json",
  };
  if (process.env.GITHUB_PIN_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_PIN_TOKEN}`;
  const r = await fetch(`${API}/repos/${store.REPO}/contents/${path}`, {
    method: "DELETE",
    headers,
    body: JSON.stringify({ message, sha: blobSha, branch: store.BRANCH }),
  });
  if (!r.ok) throw new Error(`github remove ${path} -> ${r.status}`);
  let body = null;
  try {
    body = await r.json();
  } catch {
    body = null;
  }
  const c = body && body.commit && body.commit.sha;
  return { commit: typeof c === "string" && BLOB_SHA.test(c) ? c : null };
}

module.exports = { removeRegistrationAfterWithdrawal };

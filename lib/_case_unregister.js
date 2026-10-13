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
// repair note is there that names this file. Since unit R-L2 (M1 and a
// minor) the note is the one kept for this file (lib/_case_seal.js THE
// REPAIR NOTE: its path, blob and creating commit), this module checks its
// signature itself (verifyRepairNote, under the key document it is given),
// and the file at the path must be the one that commit created: a file
// created later at the same path, byte-identical or not, is another file.
//
// Anything but a registration file is refused before any request is made.
"use strict";

const store = require("./_store.js");

const API = "https://api.github.com";
const REGISTRATION_FILE = /^cases\/([0-9a-f]{64})\/commit_[ab]\.json$/;
const BLOB_SHA = /^[0-9a-f]{40}$/;

// Remove the registration file at `path`, whose current blob sha is
// `blobSha` (the contents API removes a file only at the blob it names) and
// which commit `createdInCommit` created, under the repair note kept for
// that file, checked under `keyDocument` (the current key document;
// lib/_case_seal.js PUBLISHED_KEYS when not given).
// -> {commit} (the removal's commit, or null when the answer named none).
// Throws on anything else, and on a store that does not remove it.
async function removeRegistrationAfterWithdrawal(path, blobSha, message, { createdInCommit, keyDocument } = {}) {
  if (typeof path !== "string" || !REGISTRATION_FILE.test(path)) {
    throw new TypeError("removeRegistrationAfterWithdrawal: only a case's registration file is ever removed");
  }
  if (typeof blobSha !== "string" || !BLOB_SHA.test(blobSha)) {
    throw new TypeError("removeRegistrationAfterWithdrawal: the file's blob sha is required");
  }
  if (typeof createdInCommit !== "string" || !BLOB_SHA.test(createdInCommit)) {
    throw new TypeError("removeRegistrationAfterWithdrawal: the commit that created the file is required");
  }
  // required here, not above: lib/_case_seal.js requires this module
  const SEAL = require("./_case_seal.js");
  // THE REPAIR NOTE FIRST (unit R-L, L3): the one kept for this file, naming it
  const caseId = REGISTRATION_FILE.exec(path)[1];
  const notePath = SEAL.repairNotePath(caseId, path, blobSha, createdInCommit);
  let note;
  try {
    note = await store.getFile(notePath);
  } catch {
    throw new Error(`the repair note for ${path} could not be read, so nothing was removed`);
  }
  const n = note && note.json;
  if (!n || n.v !== 2 || n.case_id !== caseId || n.removed_path !== path || n.removed_blob_sha !== blobSha || n.created_in_commit !== createdInCommit) {
    throw new Error(`no repair note names ${path} at this blob and creating commit, so nothing was removed`);
  }
  // its signature, checked here (unit R-L2)
  const v = await SEAL.verifyRepairNote(n, keyDocument === undefined ? SEAL.PUBLISHED_KEYS : keyDocument);
  if (!v.ok) throw new Error(`the repair note for ${path} does not verify (${v.reason}), so nothing was removed`);
  // the file at the path is the one that commit created (unit R-L2, M1)
  let newest;
  try {
    newest = await store.listCommits(path, { perPage: 1 });
  } catch {
    throw new Error(`the commit that created the file at ${path} could not be read, so nothing was removed`);
  }
  if (!newest.length || newest[0].sha !== createdInCommit) {
    throw new Error(`the file at ${path} was not created by ${createdInCommit}, so nothing was removed`);
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

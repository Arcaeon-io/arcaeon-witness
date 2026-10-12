// _case_unregister.js — the one deletion this service makes in the pins
// repository, and the only one it can make (red-team fix C, 2026-10-12;
// GPT-5.6 §1.1 / §6.2: "A commitment can land after withdrawal").
// Underscore prefix = not routed as a serverless function.
//
// The public record only grows (test/no_delete_record.test.js), with one
// decided exception: a registration file, cases/<case_id>/commit_<role>.json,
// that landed after its case was withdrawn. lib/_case_http.js THE CASE LOCK
// makes that a lost race (the registration's lock lease ran out and the
// withdrawal took it over), and handles it inside the same critical section:
// this removes the file, and a case log event, commit_after_withdrawal
// (lib/_case.js THE CASE LOG), says what was removed and why. The removal is
// itself a commit, so the file stays in the repository's history.
//
// Anything but a registration file is refused before any request is made.
"use strict";

const store = require("./_store.js");

const API = "https://api.github.com";
const REGISTRATION_FILE = /^cases\/[0-9a-f]{64}\/commit_[ab]\.json$/;
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

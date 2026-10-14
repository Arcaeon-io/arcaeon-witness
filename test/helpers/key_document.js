// test/helpers/key_document.js — key documents for the case tests since
// Design I (2026-10-12): entries with a role, the deployment a document is
// bundled in, and that document served from the public repository at the
// deployment's commit, as a reader fetches it (lib/_case_seal.js
// fetchNamedDocument, the mock's raw host).
//
// A deployment is named by the commit it was built from. Here that commit is
// derived from the document itself (sha1 of its json-c14n:v1 bytes, 40 hex),
// so one document is always served at one commit, and two documents never
// share one: a test that seals under a document and reads under another
// sees two commits, as it would on GitHub.
"use strict";

const crypto = require("crypto");
const S = require("../../lib/_case_seal.js");
const { canonicalBytes } = require("../../lib/_check_record.js");

const keyIdOf = (k) => k.verifier.split("+").slice(0, 2).join("+");

// A key document entry for a throwaway key ({signer, verifier} as
// lib/_checkpoint.js generateKey makes one). `role` absent is a case key.
// Since unit R-REV a status is active or revoked, and no entry carries a
// revocation date.
function entry(k, { role, status = "active", since = "2026-10-10", note = "a test key" } = {}) {
  const e = { key_id: keyIdOf(k), verifier: k.verifier, since, note, status };
  if (role !== undefined) e.role = role;
  return e;
}
const reconcileEntry = (k, over = {}) => entry(k, { role: "reconcile", note: "a test reconcile key", ...over });

// The committed document's prose with these entries.
function docWith(...entries) {
  return { ...S.PUBLISHED_KEYS, keys: entries };
}

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const commitOf = (doc) => crypto.createHash("sha1").update(canonicalBytes(doc)).digest("hex");

// `doc` served from the public repository at `commit` (commitOf(doc) by
// default) on the mock store `gh`, that commit on the repository's published
// branch (unit R-I: a reader holds a named commit to the branch,
// lib/_case_seal.js commitOnBranch), after every commit served before it.
// -> the commit.
function serve(gh, doc, commit = commitOf(doc)) {
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, text);
  // the commit carries no text of its own: the raw host serves only what
  // seedRaw planted, so a test can still take the file away
  gh.seedCommit(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE);
  return commit;
}

// `doc` served at `commit` by the raw host but on no branch of the
// repository (a side branch's commit, or a fork's). -> the commit.
function serveOffBranch(gh, doc, commit = commitOf(doc)) {
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, `${JSON.stringify(doc, null, 2)}\n`);
  gh.seedSideCommit(S.KEY_DOCUMENT_REPO, commit);
  return commit;
}

// The environment of a deployment built with `doc` bundled: `env` plus
// VERCEL_GIT_COMMIT_SHA, with `doc` served at that commit. A document that
// is not an object is no deployment's: `env` comes back unchanged.
function deployed(gh, env, doc) {
  if (doc === null || typeof doc !== "object") return env;
  return { ...env, [S.DEPLOY_COMMIT_ENV]: serve(gh, doc) };
}

// signed_under for a seal built by hand (lib/_case_seal.js sealCase), with
// `doc` served at its commit.
function signedUnder(gh, doc, retrievedAt) {
  return { document_sha256: sha256(canonicalBytes(doc)), document_commit: serve(gh, doc), retrieved_at: retrievedAt };
}

module.exports = { keyIdOf, entry, reconcileEntry, docWith, commitOf, serve, serveOffBranch, deployed, signedUnder, sha256 };

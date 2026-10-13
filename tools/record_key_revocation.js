#!/usr/bin/env node
// tools/record_key_revocation.js — the operator command that records a key's
// revocation marker in the pins repository (unit R-I, 2026-10-13;
// lib/_case_seal.js THE TRUST ROOT and THE REVOCATION MARKER).
//
// WHY A MARKER. A sealed case's pin is a commit of the pins repository; the
// key document is a file of this repository. Git orders commits only within
// one repository, so "was this case pinned before the key was revoked?" is
// answered in the pins repository: the commit that writes the key's marker,
// revocations/<fingerprint>.json, is the revoking commit R, and a case whose
// pin records a commit strictly before R keeps its verdict (under a banner);
// any other case signed by the key does not verify. A marker counts only
// beside the key document's own revocation: a marker for a key the current
// document does not list as revoked revokes nothing (the sealer's run
// reports it as marker_without_revocation).
//
// THE ORDER OF THE STEPS (the operator's):
//   1. commit the key document with the key's status revoked (and its
//      revoked_since) on the published branch, and deploy it;
//   2. run this command from a checkout of that commit. It reads the key
//      document of the checkout (the bundled copy the service carries), finds
//      the oldest commit of the published branch at which the document lists
//      the key revoked (the commits API for the document's path, walked
//      oldest first, each commit's document read from the raw host), and
//      writes the marker {kind: "key-revocation", v: 1, key_id,
//      key_fingerprint, revoked_in_commit}.
//
// CREATE-ONLY. A marker is written once. A marker already at the path is
// never overwritten: the command refuses (marker_exists) and writes nothing,
// whatever it holds. The command also refuses a key the document does not
// list (not_listed) or does not list as revoked (not_revoked), and writes
// nothing when the revoking commit cannot be found or read.
//
// THE READER'S OWN CHECK (unit R-I2, M1). Before it writes, the command runs
// the check every reader runs on a marker (lib/_case_seal.js
// checkRevocationMarker) against the readers' published branch,
// KEY_DOCUMENT_BRANCH of this shell (main unless set), whatever branch it
// was told to walk, and refuses one a reader would reject
// (marker_rejected): a marker naming a commit that is not on that branch, or
// whose document does not list the key revoked, would make every case under
// the key read revocation_marker_invalid until a valid one is written.
//
// OPERATOR COMMAND
//
//   GITHUB_PIN_TOKEN=...  \
//   GITHUB_PIN_REPO=dan8433-user/arcaeon-witness-pins \
//   node tools/record_key_revocation.js <key_id> [--write]
//
// Without --write it prints the marker it would write and writes nothing.
// KEY_DOCUMENT_BRANCH names the key document's published branch (main unless
// set); set it to the value the deployment carries, since the readers hold
// the marker to that branch. It prints one JSON object and exits 0 when the
// marker was written (or would be), 1 otherwise. It never prints or reads
// private key material.
"use strict";

const store = require("../lib/_store.js");
const S = require("../lib/_case_seal.js");

// The commits touching the key document on `branch`, oldest first (every
// page). Throws when a page cannot be read.
async function documentCommitsOldestFirst(branch) {
  const target = { repo: S.KEY_DOCUMENT_REPO, branch, tokenEnv: store.PINS_TARGET.tokenEnv };
  const all = [];
  for (let page = 1; page <= 50; page += 1) {
    const list = await store.listCommits(S.CASE_KEYS_FILE, { perPage: 100, page }, target);
    all.push(...list);
    if (list.length < 100) return all.reverse();
  }
  throw new Error("the key document has more commits than this command walks");
}

// The oldest commit of `branch` at which the key document lists `entry`
// (its key id and verifier, in its role) as revoked.
// -> {ok:true, commit} or {ok:false, code, reason}.
async function findRevokingCommit(entry, { branch = S.keyDocumentBranch() } = {}) {
  let commits;
  try {
    commits = await documentCommitsOldestFirst(branch);
  } catch (e) {
    return { ok: false, code: "could_not_look", reason: `the key document's commits could not be read (${e && e.message})` };
  }
  const role = (e) => (e.role === undefined ? "case" : e.role);
  for (const c of commits) {
    const at = await S.fetchNamedDocument(c.sha);
    if (!at.ok) return { ok: false, code: "could_not_look", reason: `the key document at ${c.sha} could not be read (${at.reason})` };
    const k = S.checkKeyDocument(at.doc);
    if (!k.ok) continue;
    const there = k.keys.find((x) => x.key_id === entry.key_id && x.verifier === entry.verifier && role(x) === role(entry));
    if (there && there.status === "revoked") return { ok: true, commit: c.sha };
  }
  return { ok: false, code: "revoking_commit_not_found", reason: `no commit of ${branch} lists ${entry.key_id} as revoked` };
}

// Record the marker for `keyId`, revoked in `currentDocument` (the checkout's
// key document unless a test hands another), written only with `write`.
// -> {ok:true, written, path, marker, commit} (commit: the marker's own
//    commit when written, else null) or {ok:false, code, reason[, path]}.
async function recordRevocation({ keyId, currentDocument = S.PUBLISHED_KEYS, branch = S.keyDocumentBranch(), write = false } = {}) {
  const c = S.checkKeyDocument(currentDocument);
  if (!c.ok) return { ok: false, code: "document_unreadable", reason: `the key document does not read (${c.reason} at ${c.at})` };
  const entry = c.keys.find((e) => e.key_id === keyId);
  if (!entry) return { ok: false, code: "not_listed", reason: `${keyId} is not listed in the key document` };
  if (entry.status !== "revoked") return { ok: false, code: "not_revoked", reason: `the key document lists ${keyId} as ${entry.status}, not revoked` };
  const found = await findRevokingCommit(entry, { branch });
  if (!found.ok) return found;
  const marker = S.revocationMarkerFor(entry, found.commit);
  const path = S.revocationMarkerPath(entry.verifier);
  // THE READER'S OWN CHECK (above), against the readers' published branch
  const check = await S.checkRevocationMarker(entry, marker);
  if (!check.ok) {
    return { ok: false, code: "marker_rejected", reason: `a reader would reject this marker (${check.reason}): its revoking commit ${found.commit} ` +
      `is not, or could not be read as, a commit of ${S.keyDocumentBranch()} at which the key document lists ${keyId} revoked`, path };
  }
  let existing;
  try {
    existing = await store.getFile(path);
  } catch (e) {
    return { ok: false, code: "could_not_look", reason: `the marker path could not be read (${e && e.message})`, path };
  }
  if (existing !== null) return { ok: false, code: "marker_exists", reason: "a marker is already recorded for this key, and a marker is never overwritten", path };
  if (!write) return { ok: true, written: false, path, marker, commit: null };
  let put;
  try {
    put = await store.putFile(path, marker, `revocation marker: ${keyId}`, undefined, { rebuild: () => null });
  } catch (e) {
    if (e && e.conflict) return { ok: false, code: "marker_exists", reason: "another writer recorded a marker for this key first", path };
    return { ok: false, code: "store_error", reason: `the marker could not be written (${e && e.message})`, path };
  }
  if (put && put.abandoned) return { ok: false, code: "marker_exists", reason: "another writer recorded a marker for this key first", path };
  return { ok: true, written: true, path, marker, commit: S.commitOfPut(put) };
}

async function main(argv) {
  const keyId = argv.find((a) => !a.startsWith("--"));
  if (!keyId) {
    process.stdout.write(`${JSON.stringify({ ok: false, code: "usage",
      reason: "node tools/record_key_revocation.js <key_id> [--write]; KEY_DOCUMENT_BRANCH names the key document's published branch (main unless set)" })}\n`);
    return 1;
  }
  const out = await recordRevocation({ keyId, write: argv.includes("--write") });
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  return out.ok ? 0 : 1;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (e) => {
    process.stderr.write(`record_key_revocation: ${e && e.message}\n`);
    process.exit(1);
  });
}

module.exports = { recordRevocation, findRevokingCommit };

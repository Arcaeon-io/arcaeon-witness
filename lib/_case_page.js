// _case_page.js — the public case page, GET /case/<case_id> (vercel.json
// rewrite -> /api/verify?op=case-page&case_id=<case_id>). Underscore prefix =
// not routed as a serverless function: the page rides on api/verify.js, like
// /reconcile (lib/_reconcile_page.js), because api/ is at the Hobby cap of
// twelve functions.
//
// WHAT IT SHOWS (CASE_PROTOCOL_DESIGN_2026-10-10.md, velouria
// projects/arcaeon/, "What the public case page shows", and "After item 2b"):
// "Status, protocol and policy versions, both labels with the sentence
// 'labels are recorded, not verified', both registration times with links to
// the public stamp commits (derived from the hashes), the reveal time, the
// verdict word and the first divergence, records in words, the
// cross-reference if any, the anchor state, the four limits. A WITHDRAWN case
// shows the redacted record only. An EXPIRED case shows the opening and the
// word. Never a tape, never a salt, never a manifest." With 2c's additions:
// the live record count read from valid reference rows, the anchor state
// computed from the pin (never stored; since Design J one of the anchor
// words, lib/_case_seal.js THE ANCHOR WORDS, or commit_unrecorded when the
// pin is absent or names no commit for the case file), and
// signed_by looked up in the published key document, which the page links.
//
// So, by status (EXPIRED computed from the deadline against this service's
// clock, never stored):
//   OPEN, COMMITTED  status, versions, labels and the sentence, the opening
//                    time and the deadline, each registration's time with
//                    its stamp commit and its registration record, the four
//                    limits.
//   VERDICT          all of that, and the reveal time, the verdict word and
//                    the first divergence, records in words (sealed and
//                    live), the cross-reference (the seal's own and any valid
//                    reference row), the anchor state, signed_by and the key
//                    document.
//   WITHDRAWN        the redacted record only (case id, protocol, opening
//                    time, which role withdrew and when, signed_by, the four
//                    limits) and the sentence that registrations, if any,
//                    remain in the public record. No label, no commitment, no
//                    link to a registration: the redacted record does not
//                    list them, and the page does not either.
//   EXPIRED          the opening (versions, labels and the sentence, the
//                    opening time, the deadline) and the word.
//   DOES NOT VERIFY  (item 2d) a case stored as VERDICT that fails THE
//                    SEALED CHECK (lib/_case_seal.js sealedRecordReason: the
//                    receipt bound to it and, since red-team fix B, signed
//                    by this service's reconcile signer, then a signed
//                    case's signature under the verifier its signed_by names
//                    in the key document, the check anchorCase runs before
//                    it pins), since Design I under the key document the
//                    case names, read at the commit it names.
//   COULD NOT LOOK   (Design I) a VERDICT whose named key document cannot be
//                    read when this page was read, or confirmed on the published
//                    branch, or whose current document does not read
//                    (document_unavailable): neither a yes nor a no. HTTP
//                    503, the id, the stored status, WHICH document (unit
//                    R-I: the named one, at its commit, or the current one)
//                    and why it could not be read, and the four limits; no
//                    verdict and no does-not-verify state.
//                    Not a verdict: the id, the stored status, which check
//                    failed and its reason, the key the record names, links
//                    to the record and its history, and the four limits. No
//                    verdict word, records, cross-reference, anchor, label
//                    or registration: nothing in such a record is confirmed.
//   SINGLE PARTY     (red-team fix A; lib/_case.js ONE KEY PER ROLE) a case,
//                    in any status but WITHDRAWN, whose two commitments
//                    share a key id: one key registered both roles, so it is
//                    never sealed. Not a case between two keys: the id,
//                    the stored status, the word single_party, the one key
//                    id, the opening and registration times, links to the
//                    record and its history, and the four limits. No label:
//                    the labels are the opener's text, and one of them names
//                    a party that registered nothing, so the page names
//                    neither. No verdict, records, cross-reference or anchor,
//                    even when the record reads VERDICT. Checked before THE
//                    SEALED CHECK and before EXPIRED.
// RECORDS IN WORDS (item 2d). The live count is lib/_case_seal.js
// liveRecords'. When it could not be established (the read ended without a
// valid row while some listed row was not seen), the page says the count
// could not be established, and never "one record".
// THE DOCUMENT AND THE PIN (Design I). A VERDICT that holds names the key
// document it was sealed under: "sealed under document <sha256> at commit
// <W>", linked to the document at that commit, with retrieved_at labelled
// "service clock, unverified" (the public time bound is the commit's time,
// never the service's clock), and "pinned at commit <P>" with the pins
// repository's own commit time for the commit that wrote its numbered pin
// record (read only once its pointer is read).
// THE ANCHOR WORDS (Design J). The anchor row says pinned, anchored or
// could_not_look, from lib/_case_seal.js anchorState: anchored names the
// daily anchor record (linked at the commit that wrote it), that commit and
// the head of the pins repository it names, each a link; pinned says no
// daily anchor record read holds the pin yet, or that the anchor could not be
// looked up; could_not_look says what could not be read and claims nothing.
// The "case commit" row names the commit the pin records for the case file,
// read at that commit (lib/_case_seal.js THE PIN IS THE SECOND PHASE);
// commit_unrecorded and pin_commit_mismatch say so in the anchor row and are
// never pinned or anchored. Each reference row shown names the commit that
// wrote it, as the case's pins list it and read at it, or says
// commit_unrecorded, pin_commit_mismatch or could_not_look (THE ROW'S TWO
// WRITES). Its "signed by" row says the
// signature was verified under that named document. A case whose key the
// CURRENT document marks revoked, whose case file was written before the
// key's revocation was recorded in the pins repository (signer_since_revoked;
// unit R-I, I1), stays sealed and carries a banner that says exactly that
// (unit R-I2, M2): "The case file was written at commit P, before this key's
// revocation was recorded in the pins repository at commit R. The key
// document lists the key as revoked at its commit W.", each linked; never a
// date as the order, and never the reader's own deployment as the revoking
// commit. Revoked with the case file not shown written before R (signer_revoked), or not
// listed in the current document (signer_unlisted), the record does not
// verify. The verdict word is the sealed one whatever a later document says.
// Not shown, ever: a tape, a tape hash, a salt, a salt hash, the scope
// manifest or its digest. The tests grep the page for each.
//
// EVERY VALUE IS ESCAPED. A label is the parties' own text; a
// cross-reference's operator, reference and url are a caller's. All of it
// goes through esc() into text or a double-quoted attribute, and a
// cross-reference url is already https and printable ASCII (lib/_case.js).
// The page has no script, and its content-security-policy allows none.
//
// READS. One case file; for a sealed case that passes THE SEALED CHECK, its
// pin (the anchor state: the pointer, the numbered record's commits and that
// record at the commit that wrote it, the anchors listing and at most
// lib/_case_seal.js ANCHOR_RECORD_READS daily anchor records with the pin at
// the head each names) and its reference rows (the live count, at most
// lib/_case_seal.js REFERENCE_ROW_READS rows), and for each row shown the
// commit its case's pins list for it (the case's numbered pins below the
// pointer, at most lib/_case_seal.js PIN_WALK_READS, and the row at that
// commit). A VERDICT that fails the
// check reads nothing more. Behind the shared per-IP limiter, like every
// public read on verify.js. Nothing is written.

"use strict";

const C = require("./_case.js");
const SEAL = require("./_case_seal.js");
const store = require("./_store.js");
const stampStore = require("./_stamp_store.js");
const stamp = require("./_stamp.js"); // stampPath only
const verdict = require("./_verdict.js");
const ratelimit = require("./_ratelimit.js");
const brandMark = require("./_brand_mark.js");

const HEX64 = /^[0-9a-f]{64}$/;
const LABELS_SENTENCE = "Labels are recorded, not verified.";
const KEY_DOC_URL = `/${SEAL.CASE_KEYS_DOC}`;
const PINS_URL = `https://github.com/${store.REPO}`;

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function link(href, text) {
  return `<a href="${esc(href)}" rel="nofollow noopener noreferrer">${esc(text)}</a>`;
}
function pinsBlob(p) {
  return `${PINS_URL}/blob/${store.BRANCH}/${p}`;
}
function pinsCommits(p) {
  return `${PINS_URL}/commits/${store.BRANCH}/${p}`;
}
// The key document at one commit of this public repository (Design I).
function documentAt(commit) {
  return `https://github.com/${SEAL.KEY_DOCUMENT_REPO}/blob/${commit}/${SEAL.CASE_KEYS_FILE}`;
}

const VERDICT_WORDS = Object.freeze({ MATCHED: "MATCHED", MISSING: "MISSING", ALTERED: "ALTERED", COULD_NOT_LOOK: "COULD NOT LOOK" });

const STYLE = `
  :root { color-scheme: dark light; --bg: #0b0c0e; --panel: #141619; --border: #2a2d31; --text: #e6e8eb; --muted: #9aa0a6;
    --accent-strong: #34d399; --fail: #f87171; --warn: #fbbf24; --link: #8ab4f8; }
  @media (prefers-color-scheme: light) { :root { --bg: #f6f7f8; --panel: #ffffff; --border: #dcdfe3; --text: #1b1d1f; --muted: #5b6066;
    --accent-strong: #056238; --fail: #b3261e; --warn: #8a5a00; --link: #1a56b0; } }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
  main { max-width: 880px; margin: 0 auto; padding: 32px 16px 80px; }
  h1 { font-size: 20px; font-weight: 700; margin: 0 0 4px; }
  .subtitle { color: var(--muted); font-size: 13.5px; margin: 0 0 24px; word-break: break-all; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin: 0 0 10px; font-weight: 600; }
  section.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px 20px; margin-bottom: 16px; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size: 13px; word-break: break-all; }
  table.facts { width: 100%; border-collapse: collapse; font-size: 13.5px; }
  table.facts th, table.facts td { border-bottom: 1px solid var(--border); text-align: left; padding: 6px 10px; vertical-align: top; }
  table.facts th { color: var(--muted); font-weight: 600; width: 34%; }
  table.facts td { word-break: break-word; }
  .word { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; letter-spacing: 0.04em; font-weight: 700;
    border: 1px solid var(--border); }
  .word.pass { color: var(--accent-strong); border-color: var(--accent-strong); }
  .word.fail { color: var(--fail); border-color: var(--fail); }
  .notice { border: 1px solid var(--warn); border-radius: 6px; padding: 10px 14px; font-size: 13.5px; margin: 8px 0; }
  ul.plain { margin: 4px 0; padding-left: 20px; }
  ul.plain li { margin: 4px 0; }
  .muted { color: var(--muted); font-size: 13.5px; }
  a { color: var(--link); }
  footer { color: var(--muted); font-size: 12px; margin-top: 40px; text-align: center; }
  .arc-head { display: flex; align-items: center; gap: 10px; margin: 0 0 18px; }
  .arc-word { color: var(--text); font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; }
  footer .arc-footer { margin: 0 0 8px; }
`;

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
${brandMark.FAVICON_LINK}
<style>${STYLE}</style>
</head>
<body>
<main>
  <header class="arc-head">${brandMark.headerMark("dark-auto")}<span class="arc-word">Arcaeon</span></header>
${body}
  <footer><p class="arc-footer">${brandMark.footerMark("dark-auto")}</p>case page &middot; the witness keeps no tape and no salt, in any state</footer>
</main>
</body>
</html>
`;
}

function facts(rows) {
  return `<table class="facts">${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join("")}</table>`;
}

function limitsPanel(limits) {
  return `  <section class="panel"><h2>What this service does not establish</h2><ul class="plain">${limits.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></section>\n`;
}

function partiesPanel(kase) {
  const party = (role, p) => [`party ${role} (role ${role})`, `${esc(p.label)} <span class="muted">(${esc(p.side)} side)</span>`];
  return `  <section class="panel"><h2>Parties</h2>${facts([party("a", kase.party_a), party("b", kase.party_b)])}<p class="muted">${esc(LABELS_SENTENCE)} A label is the account or key string a party disclosed; this service records it and never checks who holds it.</p></section>\n`;
}

// The stamps repository, for the derived stamp links; null when this
// deployment has none configured (the commit id is then shown as text).
function stampsRepo() {
  const st = stampStore.status();
  return st.configured ? { repo: st.repo, branch: st.branch } : null;
}

// A ROLE THE ROOT DOES NOT PROJECT (unit R-L4c, c4, as the architect
// ruled): the page says only that no registration is confirmed for it. It
// does not list, count or link a claim file, and reads none: a sender learns
// its own claim's fate from its own answer, which names the claim's path.
// The WITHDRAWN and EXPIRED pages show no registration rows; their status
// word is the terminal state.
const NO_REGISTRATION = "no registration is confirmed for this role";

// What this page read of the registrations of `kase` (THE PROJECTION IS THE
// REGISTRATION, lib/_case_seal.js projectedRegistrations): the projection,
// each projected file checked, and nothing else (a withdrawn root projects
// nothing, and nothing is read). -> {damaged: null | the helper's answer,
// unread: {a, b} (the reason a projected file's read failed, or null)}.
async function registrationReads(kase) {
  const out = { damaged: null, unread: { a: null, b: null } };
  if (kase.status === "WITHDRAWN") return out;
  const proj = await SEAL.projectedRegistrations(kase);
  if (!proj.ok && proj.damaged) out.damaged = proj;
  else if (!proj.ok) out.unread[proj.role] = proj.reason;
  return out;
}

function registrationsPanel(kase, reads) {
  const repo = stampsRepo();
  const rows = [];
  for (const r of C.ROLES) {
    if (reads.unread[r]) {
      rows.push([`role ${r}`, esc(`its registration file could not be read when this page was read (${reads.unread[r]})`)]);
      continue;
    }
    const e = kase.commitments[r];
    if (e === null) {
      rows.push([`role ${r}`, `<span class="muted">${esc(NO_REGISTRATION)}</span>`]);
      continue;
    }
    const commit = e.stamp_commit === null
      ? '<span class="muted">no stamp commit recorded</span>'
      : repo ? link(`https://github.com/${repo.repo}/commit/${e.stamp_commit}`, `stamp commit ${e.stamp_commit.slice(0, 12)}`) : `<code>${esc(e.stamp_commit)}</code>`;
    const record = repo ? ` &middot; ${link(`https://github.com/${repo.repo}/blob/${repo.branch}/${stamp.stampPath(e.commitment_sha256)}`, "stamp record")}` : "";
    const reg = ` &middot; ${link(pinsCommits(C.registrationPath(kase.case_id, r, e.claim_sha256)), "registration record and its commit")}`;
    rows.push([`role ${r} registered at`, `${esc(e.registered_at)} <span class="muted">(stamped ${esc(e.stamped_at)})</span><br>${commit}${record}${reg}`]);
  }
  return `  <section class="panel"><h2>Registrations</h2>${facts(rows)}<p class="muted">Each role registered one commitment hash, stamped first as a public, dated commit. The links are derived from the hashes; the commitment's contents are not shown. A registration stands only once the case root projects it, with the sha256 of the file's bytes.</p></section>\n`;
}

// DAMAGED (unit R-L4): a registration file the case root projects is
// missing, or is not the file projected. Its own page: no registration, no
// verdict, no reference row and no anchor is shown from such a case, and
// nothing here resolves it. Never kept.
function damagedPage(kase, d, head) {
  const id = kase.case_id;
  return page(`Case ${id.slice(0, 12)}: DAMAGED`, head("DAMAGED") +
    `  <section class="panel"><h2>A registration file is not what the case root projects</h2>${facts([
      ["status", `<span class="word fail">DAMAGED</span> <span class="muted">(stored as ${esc(kase.status)})</span>`],
      ["what was read", esc(`${SEAL.damagedWords(id, d)}.`)],
      ["record", `${link(pinsBlob(C.casePath(id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")} &middot; ` +
        `${link(pinsCommits(d.path), "the registration file's history")}`],
    ])}<p class="notice">A registration stands only by the case root's projection, checked against the file it projects, and this one ` +
    "does not hold. A damaged case is never sealed and never pinned; this page shows no registration, no verdict, no reference row and no " +
    "anchor from it, and nothing here resolves it.</p></section>\n" + limitsPanel(kase.limits));
}

function signedByHtml(rec, doc) {
  if (rec.sig === null) {
    return `unsigned: ${esc(rec.sig_reason)} <span class="muted">(${link(KEY_DOC_URL, "the case key document")})</span>`;
  }
  const entry = SEAL.publishedEntry(doc, rec.signed_by);
  const bad = SEAL.publishedSignatureReason(rec, doc);
  const listed = entry ? `listed in the key document as ${esc(entry.status)}` : "not listed in the key document";
  const holds = bad === null ? "the signature verifies under the published verifier" : `the signature cannot be confirmed by the key document (${esc(bad)})`;
  return `<code>${esc(rec.signed_by)}</code>, ${listed}; ${holds}. ${link(KEY_DOC_URL, "The case key document")}.`;
}

function firstDivergence(vb) {
  if (vb.verdict === "MATCHED") return `none: every call matched (${esc(vb.matched)} matched)`;
  if (vb.verdict === "COULD_NOT_LOOK") return "none: the comparison could not look, so there is no first divergence";
  const side = typeof vb.side === "string" && vb.side ? `, ${vb.verdict === "MISSING" ? "short on" : "on"} the ${esc(vb.side)} tape` : "";
  return `at call ${esc(vb.at)}${side}`;
}

// A commit of the pins repository, as a link to it.
function pinsCommit(sha) {
  return link(`${PINS_URL}/commit/${sha}`, sha.slice(0, 12));
}

// THE ANCHOR WORDS (Design J; lib/_case_seal.js anchorState): anchored only
// with the daily anchor record, its own commit and the head it names;
// pinned with the commit that wrote the pin; could_not_look claims nothing.
// Since unit R-J3 every state is said by its reason, and only what was read.
function anchorHtml(st) {
  if (st.pin === "anchored") {
    const a = st.anchor;
    // unit R-J (J2): what is checked, and what is not
    return "anchored: a daily anchor record in this repository names a head that holds this pin; this page does not check the " +
      `OpenTimestamps proof. The record ${link(`${PINS_URL}/blob/${a.record_commit.sha}/${a.path}`, a.path)}, ` +
      `written at commit ${pinsCommit(a.record_commit.sha)}, names the head ${pinsCommit(a.head_commit)} of the pins repository, and the pin ` +
      "read at that head holds this case's chain.";
  }
  if (st.pin === "pinned") {
    // no daily anchor record read (the revocation order's answer)
    if (st.anchor && st.anchor.not_looked_up) return "pinned; no daily anchor record was read for this answer, so no anchor is claimed.";
    // unit R-J3 (F6): a head not shown yet, said as that, naming it (unit R-L, g2)
    if (st.anchor && st.anchor.could_not_look === "anchor_head_not_shown") {
      return `pinned; a daily anchor record names the head <code>${esc(st.anchor.head_commit)}</code>, which is not shown by the repository ` +
        "yet (could_not_look: anchor_head_not_shown), so no anchor is claimed.";
    }
    // unit R-L (g1, g7): what was read of the record itself
    const words = st.anchor && anchorRecordWords(st.anchor.could_not_look);
    if (words) return words;
    if (st.anchor && st.anchor.could_not_look) {
      return `pinned; whether a daily anchor record holds its pin could not be read when this page was read (could_not_look: ${esc(st.anchor.could_not_look)}), ` +
        "so no anchor is claimed.";
    }
    return "pinned, not anchored yet: no daily anchor record held its pin when this page was read. The operator's daily job records the pins " +
      "repository's head; once a record names a head that holds this pin, the case reads anchored.";
  }
  // THE PIN IS THE SECOND PHASE (Design J; lib/_case_seal.js TWO WRITES);
  // since unit R-J3 (F1) a later pin is said as possible, never as fact
  if (st.pin === "commit_unrecorded" && st.reason === "no_case_commit") {
    return "commit_unrecorded: its pin names no commit for the case file, so the case is not shown as pinned or anchored. A later sealer " +
      "run may record that commit in a next pin of the case.";
  }
  if (st.pin === "commit_unrecorded") {
    return `commit_unrecorded: the case is sealed and not yet pinned (${esc(st.reason)}), so it is not shown as pinned or anchored. A later ` +
      "sealer run may pin it.";
  }
  if (st.pin === "pin_commit_mismatch") {
    return `pin_commit_mismatch: its pin names commit ${pinsCommit(st.case_commit)} for the case file, and ` +
      `${esc(mismatchWords(st.reason, "case file"))} (${esc(st.reason)}), so the case is not shown as pinned or anchored.`;
  }
  if (st.pin === "could_not_look" && st.reason === "pin_pointer_unreadable") {
    return "could_not_look: its pin pointer could not be read when this page was read (pin_pointer_unreadable), so nothing is claimed about " +
      "its pin or its anchor.";
  }
  // the pointer was read and holds this case's chain (unit R-J3, F6)
  if (st.pin === "could_not_look") {
    return `could_not_look: a pin of this case's chain was read, and ${esc(couldNotLookWords(st.reason, "case file"))} (${esc(st.reason)}), ` +
      "so the case is not shown as pinned or anchored.";
  }
  if (st.pin === "conflict") {
    // worded by its reason (unit R-J2, B1)
    return `conflict: ${esc(SEAL.conflictWords(st.reason))} (${esc(st.reason || "conflict")}). This service never writes over a pin; the case file ` +
      "is the authority.";
  }
  return `unreadable: a record is present at this case's pin pointer and cannot be read as a case seal record (${esc(st.reason)}).`;
}

// What the anchor cell says when the daily anchor record itself was read
// and not read through (unit R-L, g1 and g7), or null: the record changed
// at its newest commit (every read succeeded), its own commit could not be
// read, it could not be read at that commit, or its commit list did not
// end or named none.
function anchorRecordWords(reason) {
  const r = String(reason || "");
  const was = `(could_not_look: ${esc(r)})`;
  if (r === "anchor_record_changed") {
    return `pinned ${was}; a daily anchor record for this case was read and named a different head at its newest commit, so no anchor is claimed.`;
  }
  // unit R-L2: a record whose newest commit names no head
  if (r === "anchor_record_names_no_head") {
    return `pinned ${was}; a daily anchor record for this case was read at its newest commit and no longer names a head, so no anchor is claimed.`;
  }
  if (r === "anchor_record_commit_unreadable") return `pinned; the commit that wrote a daily anchor record could not be read when this page was read ${was}, so no anchor is claimed.`;
  if (r.startsWith("anchor_record_at_commit_")) return `pinned; a daily anchor record could not be read at its own commit when this page was read ${was}, so no anchor is claimed.`;
  if (r === "anchor_record_commits_beyond_bound") return `pinned; a daily anchor record's commit history is longer than this service reads ${was}, so no anchor is claimed.`;
  if (r === "anchor_record_commits_none") return `pinned; the repository lists no commit for a daily anchor record ${was}, so no anchor is claimed.`;
  return null;
}

// What a pin_commit_mismatch reason says, for the case file or a row (unit
// R-J2, n6 and n7): only the reason's own claim, in canonical form
// (json-c14n:v1) where bytes were compared.
function mismatchWords(reason, file) {
  const r = String(reason || "");
  if (r.endsWith("_at_commit_differs")) return `the ${file} at that commit is not this ${file} in canonical form (json-c14n:v1)`;
  if (r.endsWith("_absent_at_commit")) return `the pins repository holds no ${file} at that commit`;
  // unit R-L (g4): one wording for a commit not shown, "yet" only for could_not_look
  if (r.endsWith("_commit_not_found")) return "that commit is not shown by the repository";
  if (r.endsWith("_commit_off_branch")) return "that commit is not on the published branch of the pins repository";
  return `the ${file} there is not shown to be this ${file} in canonical form (json-c14n:v1)`;
}

// What a could_not_look reason says, for the case file or a row (unit R-J3,
// F6): only the read that failed, or the commit not shown yet. "It" is the
// pin that names the commit.
function couldNotLookWords(reason, file) {
  const r = String(reason || "");
  const when = "when this page was read";
  if (r.endsWith("_commit_not_shown")) return "the commit it names is not shown by the repository yet";
  if (r === "pin_commit_unreadable") return `the commit that wrote its pin record could not be read ${when}`;
  // unit R-L (g5): no read failed
  if (r === "pin_commits_beyond_bound") return "the pin's commit history is longer than this service reads";
  if (r === "pin_commits_none") return "the repository lists no commit for the pin";
  if (r.startsWith("pin_at_commit_")) return `its pin record could not be read at the commit that wrote it ${when}`;
  if (r.includes("_at_commit_")) return `the ${file} at the commit it names could not be read ${when}`;
  if (r.includes("_commit_exists_")) return `whether the pins repository has the commit it names could not be read ${when}`;
  if (r.includes("_commit_")) return `whether the commit it names is on the published branch of the pins repository could not be read ${when}`;
  return `the ${file} could not be read ${when}`;
}

// 1 or 2 and nothing else: a count that was not established (null) never
// falls through to "one record" (lib/_verdict.js's rule, a branch taken on
// purpose).
function recordsWords(n) {
  if (n === 2) return "two records: a second operator holds a record of this case";
  if (n === 1) return "one record: this service's, and no other operator's is recorded";
  throw new verdict.VerdictRequiredError("case page: a records count of 1 or 2", n);
}

// The records line from lib/_case_seal.js liveRecords. A count it could not
// establish (item 2d: the read ended without a valid row and some row was
// not seen) is said in words, never shown as one record.
function liveRecordsHtml(kase, live) {
  const seal = `at seal time: ${esc(recordsWords(kase.records))}`;
  if (!live.ok) {
    return `${esc(recordsWords(kase.records))} at seal time <span class="muted">(the reference rows could not be read when this page was read, so a later one is not counted here)</span>`;
  }
  const notes = `${live.invalid.length ? ` <span class="muted">${esc(live.invalid.length)} reference row(s) are not valid and are not counted.</span>` : ""}` +
    `${live.unreadable.length ? ` <span class="muted">${esc(live.unreadable.length)} reference row(s) could not be read when this page was read.</span>` : ""}` +
    `${live.partial ? ` <span class="muted">${esc(live.unread)} more reference row(s) were not read when this page was read.</span>` : ""}`;
  if (live.indeterminate) {
    return `the live count could not be established when this page was read: no valid reference row was among the rows read, and ` +
      `${esc(live.unread + live.unreadable.length)} row(s) were not seen, so a valid one may be among them <span class="muted">(${seal})</span>${notes}`;
  }
  return `${esc(recordsWords(live.records))}${live.records !== kase.records ? ` (${seal}; the reference rows add the second)` : ""}${notes}`;
}

// THE ROW'S TWO WRITES (Design J; lib/_case_seal.js referenceCommitStates):
// the commit that wrote a row, as the case's pins list it and read at it.
// Since unit R-J2 (B2) a row is said to be recorded by its commit and listed
// by a pin only when that pin was read for this page; its anchor state is
// never computed, and the word "anchored" is never said of a row. Since
// unit R-J3 a row whose commit was not read says so (not_read), by its
// reason, and could_not_look is said only of a read that failed.
const ROW_ANCHOR = "anchor state: not computed";
const ROW_NOT_READ = Object.freeze({
  pin_below_absent: "not read: a pin below the pointer is absent (pin_below_absent), so the pins below it were not read for this row",
  pin_below_not_a_pin: "not read: a record below the pointer is not this case's pin at its seq (pin_below_not_a_pin), so the pins below it " +
    "were not read for this row",
  pins_not_read: `not read: the pins read for this page (the pointer and ${SEAL.PIN_WALK_READS} below it) do not list the commit that wrote ` +
    "this row, and the pins below them were not read (pins_not_read)",
  // unit R-L (L5): the pointer's index names a pin, read, that does not list the row
  index_not_in_pin: "not read: the pin the pointer's index names for this row does not list it (index_not_in_pin)",
});
function rowCommitHtml(c) {
  if (!c) return "";
  const muted = (html) => ` <span class="muted">${html}; ${ROW_ANCHOR}</span>`;
  if (c.state === "recorded") {
    return muted(`recorded by commit ${pinsCommit(c.commit)}; listed by pin ${esc(c.pin_seq)}, read when this page was read`);
  }
  if (c.state === "pin_commit_mismatch") {
    return muted(`pin_commit_mismatch: pin ${esc(c.pin_seq)} names commit ${pinsCommit(c.commit)} for this row, and ` +
      `${esc(mismatchWords(c.reason, "row"))} (${esc(c.reason)})`);
  }
  // the row read at the commit a pin lists (unit R-J3, F6)
  if (c.state === "could_not_look" && c.commit) {
    return muted(`could_not_look: pin ${esc(c.pin_seq)} names commit ${pinsCommit(c.commit)} for this row, and ` +
      `${esc(couldNotLookWords(c.reason, "row"))} (${esc(c.reason)})`);
  }
  if (c.state === "could_not_look") return muted(`could_not_look: a pin below the pointer could not be read when this page was read (${esc(c.reason)})`);
  if (c.state === "not_read" && c.case_pin) {
    return muted(`not read: this case is not shown as pinned (${esc(c.case_pin)}: ${esc(c.reason)}), so no pin was read for the commit that ` +
      "wrote this row");
  }
  if (c.state === "not_read") return muted(esc(ROW_NOT_READ[c.reason] || `not read: the commit that wrote this row was not read for this page (${c.reason})`));
  return muted("commit_unrecorded: no pin of this case read when this page was read lists the commit that wrote this row");
}

function crossRows(kase, live, rowCommits) {
  const out = [];
  const x = kase.cross_reference;
  if (x) out.push(["with the reveal", `${esc(x.operator)}: ${esc(x.reference)} &middot; ${link(x.url, x.url)} <span class="muted">(recorded ${esc(x.recorded_at)})</span>`]);
  if (live && live.ok) {
    for (const r of live.rows) {
      const rc = rowCommits && rowCommits.get(r.seq);
      // the row at its commit once it reads recorded, as the case link (unit R-J2, n1)
      const rowHref = rc && rc.state === "recorded" ? `${PINS_URL}/blob/${rc.commit}/${C.referencePath(kase.case_id, r.seq)}`
        : pinsBlob(C.referencePath(kase.case_id, r.seq));
      out.push([`reference row ${r.seq}`, `${esc(r.cross_reference.operator)}: ${esc(r.cross_reference.reference)} &middot; ${link(r.cross_reference.url, r.cross_reference.url)} ` +
        `<span class="muted">(recorded ${esc(r.recorded_at)}, appended by ${esc(r.appended_by)}, ${link(rowHref, "the row")})</span>` +
        rowCommitHtml(rc)]);
    }
  }
  return out;
}

// THE DOCUMENT AND THE PIN, above: the commit that wrote the case's
// numbered pin record (lib/_case_seal.js anchorState reads it, the oldest
// commit touching it, and the record at that commit), with its date. Since
// unit R-J3 (BL1) by state and reason: "no pin of this case's chain" only
// where the pointer was read and holds none; where the pointer was read and
// holds this case's chain, the cell says so, and why the case is not shown
// pinned.
function pinnedHtml(st) {
  if (st.pin === "pinned" || st.pin === "anchored") {
    return `pinned at commit ${pinsCommit(st.pin_commit.sha)}, ` +
      `${esc(`${st.pin_commit.date || "a time the repository did not give"} (the pins repository's commit time)`)}`;
  }
  if (st.pin === "commit_unrecorded" && st.reason === "not_pinned") return "not pinned yet: no pin pointer is present under this case's namespace (not_pinned)";
  if (st.pin === "conflict" && st.reason === "pointer_holds_another_chain") {
    return "no pin of this case's chain: the pin pointer under this case's namespace holds another chain (pointer_holds_another_chain)";
  }
  if (st.pin === "unreadable") return `a record is present at this case's pin pointer and cannot be read as a case seal record (${esc(st.reason)})`;
  if (st.pin === "could_not_look" && st.reason === "pin_pointer_unreadable") return "not known when this page was read: the pin pointer could not be read (pin_pointer_unreadable)";
  return `a pin of this case's chain was read; the case is not shown as pinned or anchored (${esc(st.reason)})`;
}

// The commit that wrote the case file, as the pin names it and the reader
// read it (THE PIN IS THE SECOND PHASE, Design J). Since unit R-J3 (F9)
// "not known" only when a read failed; otherwise what was read.
function caseCommitHtml(st) {
  if (st.pin === "pinned" || st.pin === "anchored") {
    return `written at commit ${pinsCommit(st.case_commit)} <span class="muted">(named by its pin, and the case file read at that commit is this case)</span>`;
  }
  if (st.pin === "commit_unrecorded" && st.reason === "no_case_commit") return "commit_unrecorded: its pin names none (no_case_commit)";
  if (st.pin === "commit_unrecorded") return `commit_unrecorded: no pin pointer is present to name it (${esc(st.reason)})`;
  if (st.pin === "pin_commit_mismatch") {
    return `not shown: its pin names ${pinsCommit(st.case_commit)}, and ${esc(mismatchWords(st.reason, "case file"))} (${esc(st.reason)})`;
  }
  if (st.pin === "conflict" && st.reason === "pointer_holds_another_chain") {
    return "not shown: the pin pointer under this case's namespace holds another chain (pointer_holds_another_chain)";
  }
  // a daily anchor record's conflict: the pin and the case file at its commit were read
  if (st.pin === "conflict" && st.anchor) {
    return `the case file read at commit ${pinsCommit(st.record.case_commit)}, which its pin names, is this case; the case is not shown as ` +
      `pinned or anchored (${esc(st.reason)})`;
  }
  if (st.pin === "conflict") {
    return `not shown: its pin names ${pinsCommit(st.record.case_commit)}, and the case file there was not read: ` +
      `${esc(SEAL.conflictWords(st.reason))} (${esc(st.reason)})`;
  }
  if (st.pin === "unreadable") return `not shown: a record is present at this case's pin pointer and cannot be read as a case seal record (${esc(st.reason)})`;
  // unit R-L (g3): the case file at that commit was read, and is this case
  if (st.pin === "could_not_look" && st.reason === "case_commit_not_shown") {
    return `its pin names ${pinsCommit(st.case_commit)}, and the case file read at that commit is this case; whether that commit is on the ` +
      "published branch is not shown by the repository yet (case_commit_not_shown)";
  }
  return `not known when this page was read (${esc(st.reason)})`;
}

function sealedUnderHtml(answer) {
  return `sealed under document <code>${esc(answer.document_sha256.slice(0, 16))}</code> at commit ${link(documentAt(answer.document_commit), answer.document_commit.slice(0, 12))}, ` +
    `read by the service at ${esc(answer.retrieved_at)} (service clock, unverified) <span class="muted">(the public time bound is that commit's time, ` +
    "never the service's clock)</span> <span class=\"muted\">" + esc(KEY_DATES_NOTE) + "</span>";
}

// Beside the key document a case names (unit R-L, L6).
const KEY_DATES_NOTE = "Dates in a key document are shown for information and are not enforced; a key is judged by its status in the named document.";

function sealedSignedByHtml(kase) {
  if (kase.sig === null) return `unsigned: ${esc(kase.sig_reason)}`;
  return `<code>${esc(kase.signed_by)}</code>, the signature verified under the key document this case names`;
}

// signer_since_revoked (THE DOCUMENT AND THE PIN, above; unit R-I, I1): the
// banner, by commit order and never by a date. Since unit R-I2 (M2) it says
// exactly what is proven: the case file's commit P (the case_commit its pin
// records) comes before the commit R that recorded the key's revocation
// marker in the pins repository, and the key document lists the key as
// revoked at its commit W (at, not from: the reader checks the document at
// W only, never that W's parent did not list it; unit R-N, n5). It does not
// say when the revocation was committed or deployed: W comes before R.
function revokedSinceBanner(answer) {
  const items = answer.revoked.map((r) => `The ${esc(r.role)} key <code>${esc(r.key_id)}</code> is revoked. The case file was written at ` +
    `commit ${pinsCommit(answer.case_commit)}, before this key's revocation was recorded in the pins repository at commit ` +
    `${pinsCommit(r.revoking_commit)}. The key document lists the key as revoked at its commit ` +
    `${link(documentAt(r.revoked_in_document_commit), r.revoked_in_document_commit.slice(0, 12))}.`);
  return `  <section class="panel"><p class="notice"><strong>A key that signed this case is revoked.</strong> ${items.join(" ")} This case ` +
    "was sealed under the key document it names, in which that key was active. It stays sealed, and the verdict below is the one it " +
    "was sealed with.</p></section>\n";
}

function sealedPanels(kase, anchor, live, answer, rowCommits) {
  const vb = kase.verdict.verdict;
  const word = VERDICT_WORDS[vb.verdict] || "COULD NOT LOOK";
  const cls = vb.verdict === "MATCHED" ? "pass" : vb.verdict === "MISSING" || vb.verdict === "ALTERED" ? "fail" : "";
  const liveText = liveRecordsHtml(kase, live);
  const cross = crossRows(kase, live, rowCommits);
  let html = answer.code === "signer_since_revoked" ? revokedSinceBanner(answer) : "";
  html += `  <section class="panel"><h2>The verdict</h2>${facts([
    ["revealed at", esc(kase.reveals.a.revealed_at)],
    ["verdict", `<span class="word ${cls}">${esc(word)}</span>`],
    ["first divergence", firstDivergence(vb)],
    ["policy (reconcile port version)", `<code>${esc(kase.verdict.method && kase.verdict.method.port_version)}</code>`],
  ])}<p class="muted">The service ran its recorded comparison once, after receiving both accepted tapes in one request. Each accepted reveal matched the commitment registered to its role before the deadline.</p></section>\n`;
  html += `  <section class="panel"><h2>Records</h2>${facts([["records", liveText]])}</section>\n`;
  html += `  <section class="panel"><h2>Cross-reference</h2>${cross.length ? facts(cross) : '<p class="muted">none recorded</p>'}</section>\n`;
  html += `  <section class="panel"><h2>Anchor and signature</h2>${facts([
    ["key document", sealedUnderHtml(answer)],
    ["anchor", anchorHtml(anchor)],
    ["pin", pinnedHtml(anchor)],
    ["case commit", caseCommitHtml(anchor)],
    ["signed by", sealedSignedByHtml(kase)],
    // unit R-J (J4): the case file at the commit its pin names, once the
    // bytes there are the case served; the branch's file otherwise
    ["case record", `${link(anchor.pin === "pinned" || anchor.pin === "anchored" ? `${PINS_URL}/blob/${anchor.case_commit}/${C.casePath(kase.case_id)}`
      : pinsBlob(C.casePath(kase.case_id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(kase.case_id)), "its history")}`],
  ])}<p class="muted">${esc(anchorNoteFor(anchor))}</p></section>\n`;
  return html;
}

// The general sentence only beside a case that reads pinned or anchored;
// otherwise what was read (unit R-J2, n3).
function anchorNoteFor(st) {
  if (st.pin === "pinned" || st.pin === "anchored") return SEAL.ANCHOR_NOTE;
  return `This page read this case's pin as ${st.pin} (${st.reason}) and claims nothing more about its pin or its anchor.`;
}

const UNVERIFIED_CHECKS = Object.freeze({
  verdict_unbound: "the receipt: the reconcile receipt it carries is not bound to it (its reveals, compared_at and policy, and a signed receipt's own signature)",
  case_signature_invalid: "the case signature: it is not confirmed under the verifier its signed_by names in the key document the case names",
  receipt_unsigned: "the receipt's signer: the reconcile receipt it carries is not signed by this service's reconcile signer",
  document_unrecorded: "the key document: the record names none it was sealed under, so it cannot be held to one",
  // unit R-I
  signer_unlisted: "the current key document: a key that signed it is not listed there in its role",
  signer_revoked: "the key's revocation: a key that signed it is revoked in the current key document, and this case's file is not shown written before the revocation was recorded in the pins repository",
});

// THE DOES-NOT-VERIFY STATE (item 2d). A case stored as VERDICT whose sealed
// record fails lib/_case_seal.js sealedRecordReason: no verdict word, no
// first divergence, no records, no cross-reference, no anchor state, and no
// label or registration either, since nothing in the record is confirmed.
// Only the id, the stored status, which check failed and why, the key the
// record names, and links to the record and its history.
function unverifiedPage(kase, unsealed, head) {
  const id = kase.case_id;
  const names = kase.sig === null ? "no key: it is stored unsigned" : `<code>${esc(kase.signed_by)}</code>`;
  return page(`Case ${id.slice(0, 12)}: DOES NOT VERIFY`, head("SEALED RECORD DOES NOT VERIFY") +
    `  <section class="panel"><h2>The sealed record does not verify</h2>${facts([
      ["status as stored", `<span class="word fail">${esc(kase.status)}</span>, not shown as sealed`],
      ["the check that failed", `${esc(UNVERIFIED_CHECKS[unsealed.code] || unsealed.code)} <span class="muted">(<code>${esc(unsealed.code)}</code>)</span>`],
      ["reason", `<code>${esc(unsealed.reason)}</code>`],
      ["the record names", `${names} <span class="muted">(${link(KEY_DOC_URL, "the case key document")})</span>`],
      ["record", `${link(pinsBlob(C.casePath(id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}`],
    ])}<p class="notice">This case is stored as VERDICT, but its sealed record does not verify, so this page shows no verdict from it: ` +
    "no verdict word, no first divergence, no records count, no cross-reference and no anchor state. A sealed record is shown only " +
    "when it names the key document it was sealed under, and under that document, read at the commit it names, the reconcile receipt " +
    "it carries is bound to it and signed by a published reconcile key and, when it is signed, its own signature verifies under the " +
    "key its signed_by names. Each key that signed it must also be listed in its role in the current key document; a key that is not " +
    "makes the record signer_unlisted. A key the current key document lists as revoked holds only for a case whose case file was " +
    "written before the key's revocation was recorded in the pins repository; any other case it signed is signer_revoked. The case " +
    "file and its history are the public record.</p></section>\n" +
    limitsPanel(C.LIMITS));
}

// SINGLE PARTY (red-team fix A), above. One key id registered both roles:
// no label, no verdict, nothing read beyond the case file.
function singlePartyPage(kase, nowMs, head) {
  const id = kase.case_id;
  const stored = kase.status !== "VERDICT" && C.pastDeadline(kase, nowMs) ? `${kase.status}, past its deadline` : kase.status;
  const reg = (r) => `${esc(kase.commitments[r].registered_at)} ${link(pinsCommits(C.registrationPath(id, r, kase.commitments[r].claim_sha256)),
    "registration record and its commit")}`;
  return page(`Case ${id.slice(0, 12)}: SINGLE PARTY`, head("SINGLE PARTY") +
    `  <section class="panel"><h2>One key registered both roles</h2>${facts([
      ["status", `<span class="word fail">single_party</span> <span class="muted">(stored as ${esc(stored)}, not shown as a case between two keys)</span>`],
      ["the one key", `<code>${esc(kase.commitments.a.key_id)}</code> registered role a and role b`],
      ["protocol", `<code>${esc(kase.protocol_version)}</code>`],
      ["opened at", `${esc(kase.opened_at)} <span class="muted">(the opener's clock, an assertion)</span>`],
      ["role a registered at", reg("a")],
      ["role b registered at", reg("b")],
      ["record", `${link(pinsBlob(C.casePath(id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}`],
    ])}<p class="notice">Both roles of this case are registered under one key, and the two roles of a case are registered by two ` +
    "distinct keys. A single-party case is never sealed: this page shows no verdict, no records count, no cross-reference and no " +
    `anchor from it, and it names no party. ${esc(LABELS_SENTENCE)} The labels are the opener's text, and one of them would name a ` +
    "party that registered nothing.</p></section>\n" + limitsPanel(kase.limits));
}

// COULD NOT LOOK (Design I), above: a document did not read. Since unit
// R-I (I5) the page says which: the one the case names (at its commit, or
// not confirmed on the published branch), or the current one this reader
// carries.
function couldNotLookPage(kase, answer, head) {
  const id = kase.case_id;
  const current = answer.document === "current";
  const heading = current ? "The current key document this reader carries could not be read" : "The key document this case names could not be read";
  const which = current
    ? ["the document that could not be read", "the current key document this deployment carries, which says whether a key was since revoked or is still listed"]
    : ["the document it names", `at commit ${link(documentAt(answer.document_commit), answer.document_commit)}`];
  // unit R-I2 (m4): a commit that is not on the published branch is not a
  // read to retry; the page says what it is
  const offBranch = !current && answer.reason === "commit_not_on_branch";
  const closing = offBranch
    ? "The commit this case names is not on the published branch of the key document's repository, so the document it names is not a " +
      "published one, and this page says neither that the sealed record verifies nor that it does not."
    : `${current ? "The current one" : "The one it names"} could not be read when this page was read, so this page says neither that the sealed ` +
      "record verifies nor that it does not. This is not a no; try again.";
  return page(`Case ${id.slice(0, 12)}: COULD NOT LOOK`, head("COULD NOT LOOK") +
    `  <section class="panel"><h2>${esc(offBranch ? "The key document this case names is not on the published branch" : heading)}</h2>${facts([
      ["status as stored", `<span class="word">${esc(kase.status)}</span>`],
      which,
      ["why", `<code>${esc(answer.reason)}</code>`],
      ["record", `${link(pinsBlob(C.casePath(id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}`],
    ])}<p class="notice">A sealed case is held to the key document it names, read from the public repository at the commit it ` +
    `names on the published branch, and to the current key document. ${esc(closing)}</p></section>\n` + limitsPanel(C.LIMITS));
}

// COULD NOT LOOK at the pin under a revoked key (unit R-J3, F4): a key
// that signed the case is revoked in the current key document, and whether
// its pin shows the case file written before the revocation was recorded
// could not be read. Neither a yes nor a no: no verdict, and no "does not
// verify".
function pinCouldNotLookPage(kase, answer, head) {
  const id = kase.case_id;
  const keys = answer.revoked.map((r) => `the ${esc(r.role)} key <code>${esc(r.key_id)}</code>`).join("; ");
  return page(`Case ${id.slice(0, 12)}: COULD NOT LOOK`, head("COULD NOT LOOK") +
    `  <section class="panel"><h2>Whether this case holds under its revoked key could not be read</h2>${facts([
      ["status as stored", `<span class="word">${esc(kase.status)}</span>`],
      ["revoked in the current key document", keys],
      ["its pin", `could_not_look <span class="muted">(<code>${esc(answer.reason)}</code>)</span>`],
      ["record", `${link(pinsBlob(C.casePath(id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}`],
    ])}<p class="notice">${esc("A key that signed this case is revoked in the current key document. A case under a revoked key holds only " +
      "when its pin shows its case file written before the key's revocation was recorded in the pins repository, and whether this case's " +
      `pin shows that could not be read when this page was read (could_not_look: ${answer.reason}), so this page says neither that the ` +
      // a history longer than this service reads is not a read to retry (unit R-L, g5)
      `sealed record verifies nor that it does not. This is not a no${answer.reason === "pin_commits_beyond_bound" ? "." : "; try again."}`)}</p></section>\n` +
    limitsPanel(C.LIMITS));
}

// The page's whole body for a case read and judged, at `nowMs`, with
// signatures checked under the key document the case names and `doc` (the
// reader's current document, the committed one) for each key's listing and
// revocation. -> {status, html}.
async function renderCase(kase, nowMs, doc = SEAL.PUBLISHED_KEYS) {
  const id = kase.case_id;
  const head = (word) => `  <h1>Case: ${esc(word)}</h1>\n  <p class="subtitle"><code>${esc(id)}</code></p>\n`;

  // SINGLE PARTY (red-team fix A), before the sealed check and EXPIRED.
  if (C.singleParty(kase)) return { status: 200, html: singlePartyPage(kase, nowMs, head), definite: true, until: untilOf(kase) };

  // THE SEALED CHECK (item 2d; Design I), before a VERDICT is shown as
  // sealed and before its pin or its reference rows are read.
  let answer = null;
  if (kase.status === "VERDICT") {
    answer = await SEAL.sealedRecordReason(kase, doc);
    if (answer.code === "document_unavailable") return { status: 503, html: couldNotLookPage(kase, answer, head) };
    if (answer.code === "pin_unavailable") return { status: 503, html: pinCouldNotLookPage(kase, answer, head) };
    if (!SEAL.sealHolds(answer)) return { status: 200, html: unverifiedPage(kase, answer, head), definite: false };
  }

  // THE PROJECTION IS THE REGISTRATION (unit R-L4): what the root projects,
  // each file checked, and nothing else (unit R-L4c, c4). A case
  // whose projected file is missing or not the file projected is DAMAGED,
  // before anything else is shown of it (a single-party page and a sealed
  // record that does not verify show no registration, and read none).
  const reads = await registrationReads(kase);
  if (reads.damaged) return { status: 200, html: damagedPage(kase, reads.damaged, head), definite: false };
  const readAll = !reads.unread.a && !reads.unread.b;

  if (kase.status === "WITHDRAWN") {
    const w = kase.withdrawal;
    return { status: 200, html: page(`Case ${id.slice(0, 12)}: WITHDRAWN`, head("WITHDRAWN") +
      `  <section class="panel"><h2>The withdrawal record</h2>${facts([
        ["status", '<span class="word">WITHDRAWN</span>'],
        ["protocol", `<code>${esc(kase.protocol_version)}</code>`],
        ["opened at", esc(kase.opened_at)],
        ["withdrawn", `by role ${esc(w.by_role)}, at ${esc(w.at)} <span class="muted">(the role proved itself with its commitment preimage)</span>`],
        // THE REASON (Design N): a code from the request; a record from before names none
        ["reason", w.reason === undefined ? '<span class="muted">none recorded</span>' : `<code>${esc(w.reason)}</code>`],
        // unit R-N2 (m7): a withdrawal record is held to the signature rule:
        // an unsigned one is not a record, and its sig_reason is never
        // printed; the case reads WITHDRAWN all the same
        ["signed by", kase.sig === null ? "withdrawal record, unsigned: not a record" : signedByHtml(kase, doc)],
        ["record", `${link(pinsBlob(C.casePath(id)), "the withdrawal record")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}`],
      ])}<p class="notice">${esc(SEAL.WITHDRAWAL_CLAIM)}</p><p class="notice">${esc(SEAL.WITHDRAWN_REGISTRATIONS_NOTE)}</p></section>\n` +
      limitsPanel(kase.limits)), definite: readAll };
  }

  const expired = kase.status !== "VERDICT" && C.pastDeadline(kase, nowMs);
  const opening = facts([
    ["status", `<span class="word">${esc(expired ? "EXPIRED" : kase.status)}</span>`],
    ["protocol", `<code>${esc(kase.protocol_version)}</code>`],
    ["policy (reconcile port version)", `<code>${esc(kase.policy_version)}</code>`],
    ["opened at", `${esc(kase.opened_at)} <span class="muted">(the opener's clock, an assertion)</span>`],
    ["deadline", esc(kase.deadline)],
  ]);
  if (expired) {
    return { status: 200, html: page(`Case ${id.slice(0, 12)}: EXPIRED`, head("EXPIRED") +
      `  <section class="panel"><h2>The opening</h2>${opening}<p class="muted">No joint reveal was received before the deadline, by this service's clock, so the case reads EXPIRED. Expiry is read, not written, and implies no actor.</p></section>\n` +
      partiesPanel(kase) + limitsPanel(kase.limits)), definite: readAll };
  }

  let body = head(kase.status) + `  <section class="panel"><h2>The case</h2>${opening}</section>\n` + partiesPanel(kase) +
    registrationsPanel(kase, reads);
  let definite = readAll;
  if (kase.status === "VERDICT") {
    const chain = SEAL.caseChain(kase);
    const anchor = await SEAL.anchorState(id, kase);
    const live = await SEAL.liveRecords(kase, { keyDocument: doc });
    const rowCommits = live.ok ? await SEAL.referenceCommitStates(id, chain, anchor, live.rows) : null;
    body += sealedPanels(kase, anchor, live, answer, rowCommits);
    definite = definite && definitePage(anchor, live, rowCommits);
  } else {
    body += `  <section class="panel"><h2>Not sealed yet</h2><p class="muted">${kase.status === "OPEN"
      ? "Each role registers a stamped commitment before the deadline; then one request carries both reveals and both tapes."
      : "Both roles are registered. One request carrying both reveals and both tapes, received before the deadline, seals the case."}</p>${revealAttemptHtml(kase)}${facts([["signed by", signedByHtml(kase, doc)]])}</section>\n`;
  }
  return { status: 200, html: page(`Case ${id.slice(0, 12)}: ${kase.status}`, body + limitsPanel(kase.limits)), definite,
    until: untilOf(kase) };
}

// THE PAGE CACHE'S RULE (unit R-J2, M2): a page is kept only when every
// state on it was read with a definite answer. Nothing could_not_look (the
// pin, its anchor, the reference rows, a row's commit), and no
// pin_commit_mismatch (a commit the host shows late reads as one until it
// shows it), and no row whose commit was not read (not_read; unit R-J3). A
// page whose sealed record does not verify is never kept.
const ROW_NOT_DEFINITE = Object.freeze(["could_not_look", "pin_commit_mismatch", "not_read"]);
function definitePage(anchor, live, rowCommits) {
  if (anchor.pin === "could_not_look" || anchor.pin === "pin_commit_mismatch") return false;
  if (anchor.anchor && anchor.anchor.could_not_look) return false;
  if (!live.ok || live.partial || live.indeterminate || live.unreadable.length) return false;
  for (const c of rowCommits ? rowCommits.values() : []) if (ROW_NOT_DEFINITE.includes(c.state)) return false;
  return true;
}

// An unsealed case's page is kept no later than its deadline (unit R-J2,
// M2): past it, the case reads EXPIRED.
function untilOf(kase) {
  return kase.status === "VERDICT" ? Infinity : Date.parse(kase.deadline);
}

// THE TWO-PHASE REVEAL (red-team fix E; lib/_case.js): a COMMITTED case
// that records reveal attempts says so: how many, and how the latest ended
// when the case records that (unit R-N, E1: the list is append-only). Its
// comparison input hash is not shown (never a tape hash, nor one made from
// them).
function revealAttemptHtml(kase) {
  const list = kase.reveal_attempts;
  if (!Array.isArray(list) || !list.length) return "";
  const attempts = list.filter((e) => e.event === "attempt");
  const t = attempts[attempts.length - 1];
  const after = list[list.length - 1];
  const f = after.event === "failure" ? after : null;
  const count = attempts.length === 1 ? "" : `This case records ${attempts.length} joint reveal attempts. The latest: `;
  return `<p class="notice">${esc(count + (f
    ? `A joint reveal was attempted at ${t.at} and did not complete (${f.reason}, at ${f.at}). The case is not sealed; the same reveal, ` +
      "sent again before the deadline, seals it."
    : `A joint reveal was attempted at ${t.at}, and the case does not record that it completed. The case is not sealed; the same reveal, ` +
      "sent again before the deadline, seals it."))}</p>`;
}

function sendHtml(res, status, html) {
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  return res.status(status).send(html);
}

function notice(title, text) {
  return page(title, `  <h1>${esc(title)}</h1>\n  <section class="panel"><p>${esc(text)}</p></section>\n`);
}

// GET ?op=case-page&case_id=<64 hex>. Never writes. opts.now is the clock
// and opts.keyDocument the current key document (tests); the dispatch passes
// neither, so the page reads the service clock and the committed document.
// Since unit R-I the page reads nothing of its own deployment's commit: the
// revoking commit it shows is the one the key's marker was written in.
async function handleCasePage(req, res, opts = {}) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("allow", "GET, HEAD");
    res.setHeader("cache-control", "no-store");
    return res.status(405).json({ ok: false, error_code: "method_not_allowed", error: "GET /case/<case_id>" });
  }
  const nowMs = opts.now !== undefined ? Number(opts.now) : Date.now();
  const id = String((req.query || {}).case_id || "");
  if (!HEX64.test(id)) return sendHtml(res, 400, notice("Not a case id", "A case id is 64 lowercase hex characters: /case/<case_id>."));
  const rl = await ratelimit.check(req);
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    return sendHtml(res, 429, notice("Too many requests", `This address asked too often; try again in ${rl.retryAfterSeconds} seconds.`));
  }
  const doc = opts.keyDocument === undefined ? SEAL.PUBLISHED_KEYS : opts.keyDocument;
  const cpath = C.casePath(id);
  let got;
  try {
    got = await store.getFile(cpath);
  } catch (e) {
    console.error(`[case] page: case read failed (${e && e.message})`);
    return sendHtml(res, 503, notice("Could not look", "The case record could not be read when this page was read. That is not a no; try again."));
  }
  if (got === null) return sendHtml(res, 404, notice("No such case", "No case with this id is recorded."));
  const v = verdict.judgeWith(got, cpath, (json) => {
    const r = C.validateCase(json);
    if (!r.ok) return `case_${r.code}`;
    return json.case_id === id ? true : "case_not_at_its_path";
  });
  if (!v.ok) {
    return sendHtml(res, 503, notice("Could not look",
      `A record is stored for this case id and it cannot be read as a valid arcaeon-case/1 record (${v.reason}). This page does not answer from it.`));
  }
  verdict.requireGreen(v, "case page", { what: cpath });
  // J7 (unit R-J), since unit R-J2 (M2) read against the root: a page this
  // instance kept for the case is answered again only for the same root
  // (its blob sha), the same key document, inside its time
  const hit = pageCache.get(id);
  if (hit && hit.doc === doc && hit.sha === got.sha && nowMs >= hit.at && nowMs < hit.until) return sendHtml(res, 200, hit.html);
  const out = await renderCase(got.json, nowMs, doc);
  const html = withReadAt(out.html, nowMs);
  if (out.status === 200 && out.definite) {
    keepPage(id, { at: nowMs, until: Math.min(nowMs + PAGE_CACHE_MS, out.until === undefined ? Infinity : out.until), doc, sha: got.sha, html });
  }
  return sendHtml(res, out.status, html);
}

// Every case page says when it was read (unit R-J2, M2), above its footer:
// a kept page keeps the time it was read.
function withReadAt(html, nowMs) {
  return html.replace("\n  <footer>", `\n  <p class="muted">read at ${esc(C.utcSeconds(nowMs))}</p>\n  <footer>`);
}

// THE PAGE CACHE (unit R-J, J7; a second-model review of Design J, finding
// 7: each view made many uncached reads). Per instance, per case: a 200
// page that THE PAGE CACHE'S RULE (above) calls definite is kept for
// PAGE_CACHE_MS by the page's clock, and an unsealed case's no later than
// its deadline; at most PAGE_CACHE_MAX cases (the oldest dropped first).
// Every view reads the case root first and is answered from the cache only
// for the same root (unit R-J2, M2). Nothing else is cached here: a 404, a
// 503 or a notice is read again. The per-IP limiter runs before it.
const PAGE_CACHE_MS = 60000;
const PAGE_CACHE_MAX = 500;
const pageCache = new Map();
// A page kept again moves to the newest place, so the cap drops the oldest
// kept (unit R-J3, F8).
function keepPage(id, entry) {
  pageCache.delete(id);
  if (pageCache.size >= PAGE_CACHE_MAX) pageCache.delete(pageCache.keys().next().value);
  pageCache.set(id, entry);
}

module.exports = {
  handleCasePage, LABELS_SENTENCE, PAGE_CACHE_MS,
  _internal: {
    renderCase, esc, mismatchWords, clearPageCache: () => pageCache.clear(), keepPage, cachedIds: () => [...pageCache.keys()], PAGE_CACHE_MAX,
    cells: { pin: pinnedHtml, anchor: anchorHtml, caseCommit: caseCommitHtml, row: rowCommitHtml, note: anchorNoteFor },
  },
};

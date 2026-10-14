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
// cross-reference if any, the pin state, the four limits. A WITHDRAWN case
// shows the redacted record only. An EXPIRED case shows the opening and the
// word. Never a tape, never a salt, never a manifest." With 2c's additions:
// the live record count read from valid reference rows, the pin state
// computed from the case's one pin (never stored; since unit R-PIN one of
// lib/_case_seal.js THE PIN WORDS: pinned, not_pinned, pin_commit_mismatch,
// conflict, unreadable or could_not_look, never "anchored"), and
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
//                    reference row), the pin state, signed_by and the key
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
// never the service's clock), and its pin line (THE PIN LINE, unit R-PIN;
// lib/_case_seal.js pinState): "Pinned at commit P (the pins repository's
// commit time, T)", P linked, or the state's own sentence for not_pinned,
// pin_commit_mismatch, conflict, unreadable and could_not_look. Under it,
// once, a fixed sentence says the daily anchor records and their
// OpenTimestamps proofs are in anchors/, that this page does not check them,
// and how to check one with `ots verify`. The word "anchored" is never
// printed. A reference row shown links the row and the commit that wrote
// it; nothing is said of its pin or its anchoring. Its "signed by" row says the
// signature was verified under that named document. A case a key signed
// that the CURRENT document lists revoked (signer_revoked; unit R-REV, the
// architect's ruling) is the SIGNED BY A REVOKED KEY page, at 200: one
// sentence naming the key and the commit of the document this service
// carries, and no verdict, whenever it was signed. Not listed in the current
// document (signer_unlisted), the record does not verify. The verdict word
// is the sealed one whatever a later document says.
// Not shown, ever: a tape, a tape hash, a salt, a salt hash, the scope
// manifest or its digest. The tests grep the page for each.
//
// EVERY VALUE IS ESCAPED. A label is the parties' own text; a
// cross-reference's operator, reference and url are a caller's. All of it
// goes through esc() into text or a double-quoted attribute, and a
// cross-reference url is already https and printable ASCII (lib/_case.js).
// The page has no script, and its content-security-policy allows none.
//
// READS. One case file; each registration file the case root projects;
// for a sealed case that passes THE SEALED CHECK, its pin (pinState: the pin
// file, its commits, that record at the commit that wrote it, and the case
// file at the commit the pin names) and its reference rows (the live count,
// at most lib/_case_seal.js REFERENCE_ROW_READS rows). A VERDICT that fails
// the check reads nothing more. Rendered on every request: no page is kept
// (unit R-PIN), and the shared per-IP limiter, like every public read on
// verify.js, is the only bound. Nothing is written.

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
// nothing, and nothing is read). -> {inconsistent: null | the helper's answer,
// unread: {a, b} (the reason a projected file's read failed, or null)}.
async function registrationReads(kase) {
  const out = { inconsistent: null, unread: { a: null, b: null } };
  if (kase.status === "WITHDRAWN") return out;
  const proj = await SEAL.projectedRegistrations(kase);
  if (!proj.ok && proj.inconsistent) out.inconsistent = proj;
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
  return `  <section class="panel"><h2>Registrations</h2>${facts(rows)}<p class="muted">Each role registers one commitment hash, stamped first as a public, dated commit. The links are derived from the hashes; the commitment's contents are not shown. A registration stands only once the case root projects it, with the sha256 of the file's bytes.</p></section>\n`;
}

// THE RECORD IS INCONSISTENT (unit R-L4b; the architect cut the named
// state): a registration file the case root projects is missing, or does
// not hash to the projected sha256. The could-not-look page, with that
// reason and the fixed sentence below, and nothing from the case: no
// status, registration, verdict, reference row or pin. 503, never kept.
// Since unit R-L4e the page's one sentence: no heading, no reason and no
// role (the reason goes to the operator log), and nothing else from the case.
const INCONSISTENT_SENTENCE = "The stored record for this case does not agree with itself. Nothing is asserted about this case while that is so.";
function inconsistentPage(kase, head, why) {
  const id = kase.case_id;
  console.error(`[case] page: case_record_inconsistent: case ${id}, role ${why.role}, ${why.reason}`);
  return page(`Case ${id.slice(0, 12)}: COULD NOT LOOK`, head("COULD NOT LOOK") +
    `  <section class="panel"><p class="notice">${esc(INCONSISTENT_SENTENCE)}</p><p class="muted"><code>case_record_inconsistent</code> &middot; ` +
    `${link(pinsBlob(C.casePath(id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}</p></section>\n`);
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

// The cross-references: the reveal's own, and each valid reference row read
// (unit R-PIN: a row is recorded by the commit that writes it; no pin lists
// it, and nothing is said of its commit or its anchoring).
function crossRows(kase, live) {
  const out = [];
  const x = kase.cross_reference;
  if (x) out.push(["with the reveal", `${esc(x.operator)}: ${esc(x.reference)} &middot; ${link(x.url, x.url)} <span class="muted">(recorded ${esc(x.recorded_at)})</span>`]);
  if (live && live.ok) {
    for (const r of live.rows) {
      out.push([`reference row ${r.seq}`, `${esc(r.cross_reference.operator)}: ${esc(r.cross_reference.reference)} &middot; ${link(r.cross_reference.url, r.cross_reference.url)} ` +
        `<span class="muted">(recorded ${esc(r.recorded_at)}, appended by ${esc(r.appended_by)}, ` +
        `${link(pinsCommits(C.referencePath(kase.case_id, r.seq)), "the row and the commit that wrote it")})</span>`]);
    }
  }
  return out;
}

// THE PIN LINE (unit R-PIN; lib/_case_seal.js pinState): "Pinned at commit
// P (the pins repository's commit time, T)", P linked, or each other
// state's own sentence, by its reason, and only what was read.
function pinnedHtml(st) {
  if (st.pin === "pinned") {
    return `Pinned at commit ${pinsCommit(st.pin_commit.sha)} ` +
      `${esc(`(the pins repository's commit time, ${st.pin_commit.date || "a time the repository did not give"})`)}`;
  }
  if (st.pin === "not_pinned") return "Not pinned: no pin file is present under this case's namespace (not_pinned).";
  if (st.pin === "pin_commit_mismatch") {
    return `pin_commit_mismatch: its pin names commit ${pinsCommit(st.case_commit)} for the case file, and ` +
      `${esc(mismatchWords(st.reason, "case file"))} (${esc(st.reason)}), so the case is not shown as pinned.`;
  }
  if (st.pin === "conflict") {
    // worded by its reason (unit R-J2, B1)
    return `conflict: ${esc(SEAL.conflictWords(st.reason))} (${esc(st.reason)}). This service never writes over a pin; the case file ` +
      "is the authority.";
  }
  if (st.pin === "unreadable") return `unreadable: a record is present at this case's pin path and cannot be read as a case seal record (${esc(st.reason)}).`;
  if (st.reason === "pin_read_failed") return "could_not_look: this case's pin could not be read when this page was read (pin_read_failed), so nothing is claimed about it.";
  return `could_not_look: ${esc(couldNotLookWords(st.reason, "case file"))} (${esc(st.reason)}), so the case is not shown as pinned.`;
}

// Printed once, under the pin line (unit R-PIN; the architect's words): the
// daily anchor records are not read by this page.
const ANCHORS_SENTENCE = "Daily anchor records and their OpenTimestamps proofs are in `anchors/` in the pins repository; this page does not " +
  "check them, and you can check one yourself by running `ots verify` on the proof file beside the record.";
function anchorsSentenceHtml() {
  return esc(ANCHORS_SENTENCE).replace(/`([^`]+)`/g, "<code>$1</code>");
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

function sealedPanels(kase, pin, live, answer) {
  const vb = kase.verdict.verdict;
  const word = VERDICT_WORDS[vb.verdict] || "COULD NOT LOOK";
  const cls = vb.verdict === "MATCHED" ? "pass" : vb.verdict === "MISSING" || vb.verdict === "ALTERED" ? "fail" : "";
  const liveText = liveRecordsHtml(kase, live);
  const cross = crossRows(kase, live);
  let html = `  <section class="panel"><h2>The verdict</h2>${facts([
    ["revealed at", esc(kase.reveals.a.revealed_at)],
    ["verdict", `<span class="word ${cls}">${esc(word)}</span>`],
    ["first divergence", firstDivergence(vb)],
    ["policy (reconcile port version)", `<code>${esc(kase.verdict.method && kase.verdict.method.port_version)}</code>`],
  ])}<p class="muted">The service ran its recorded comparison once, after receiving both accepted tapes in one request. Each accepted reveal matched the commitment registered to its role before the deadline.</p></section>\n`;
  html += `  <section class="panel"><h2>Records</h2>${facts([["records", liveText]])}</section>\n`;
  html += `  <section class="panel"><h2>Cross-reference</h2>${cross.length ? facts(cross) : '<p class="muted">none recorded</p>'}</section>\n`;
  html += `  <section class="panel"><h2>Pin and signature</h2>${facts([
    ["key document", sealedUnderHtml(answer)],
    // the architect's sentence, once, directly under the pin line (unit R-PINf, f2)
    ["pin", `${pinnedHtml(pin)}<br><span class="muted">${anchorsSentenceHtml()}</span>`],
    ["signed by", sealedSignedByHtml(kase)],
    // unit R-J (J4): the case file at the commit its pin names, once the
    // bytes there are the case served; the branch's file otherwise
    ["case record", `${link(pin.pin === "pinned" ? `${PINS_URL}/blob/${pin.case_commit}/${C.casePath(kase.case_id)}`
      : pinsBlob(C.casePath(kase.case_id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(kase.case_id)), "its history")}`],
  ])}</section>\n`;
  return html;
}

const UNVERIFIED_CHECKS = Object.freeze({
  verdict_unbound: "the receipt: the reconcile receipt it carries is not bound to it (its reveals, compared_at and policy, and a signed receipt's own signature)",
  case_signature_invalid: "the case signature: it is not confirmed under the verifier its signed_by names in the key document the case names",
  receipt_unsigned: "the receipt's signer: the reconcile receipt it carries is not signed by this service's reconcile signer",
  document_unrecorded: "the key document: the record names none it was sealed under, so it cannot be held to one",
  // unit R-I
  signer_unlisted: "the current key document: a key that signed it is not listed there in its role",
});

// THE DOES-NOT-VERIFY STATE (item 2d). A case stored as VERDICT whose sealed
// record fails lib/_case_seal.js sealedRecordReason: no verdict word, no
// first divergence, no records, no cross-reference, no pin state, and no
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
    "no verdict word, no first divergence, no records count, no cross-reference and no pin state. A sealed record is shown only " +
    "when it names the key document it was sealed under, and under that document, read at the commit it names, the reconcile receipt " +
    "it carries is bound to it and signed by a published reconcile key and, when it is signed, its own signature verifies under the " +
    "key its signed_by names. Each key that signed it must also be listed in its role in the current key document; a key that is not " +
    "makes the record signer_unlisted. The case file and its history are the public record.</p></section>\n" +
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
    `pin from it, and it names no party. ${esc(LABELS_SENTENCE)} The labels are the opener's text, and one of them would name a ` +
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
    ? ["the document that could not be read", "the current key document this deployment carries, which lists each key in its role as active or revoked"]
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

// SIGNED BY A REVOKED KEY (unit R-REV; the architect's ruling): a key that
// signed this case is listed revoked in the key document this service
// carries, so the page shows no verdict, whenever the case was signed, and
// prints exactly one sentence under the heading. V is the commit
// sealingDocument reports for that document (the deployment's own commit);
// a deployment that does not know its commit says so in its place.
function revokedPage(kase, answer, head, doc, env) {
  const id = kase.case_id;
  const sealing = SEAL.sealingDocument(env, { keyDocument: doc });
  const V = sealing.ok ? link(documentAt(sealing.document_commit), sealing.document_commit.slice(0, 12)) : "not known to this deployment";
  return page(`Case ${id.slice(0, 12)}: SIGNED BY A REVOKED KEY`, head("SIGNED BY A REVOKED KEY") +
    `  <section class="panel"><p class="notice">The key that signed this case (<code>${esc(answer.key_id)}</code>) is listed as revoked in ` +
    `the key document this service carries (commit ${V}), so this page does not show its verdict, whenever it was signed.</p></section>\n`);
}

// The page's whole body for a case read and judged, at `nowMs`, with
// signatures checked under the key document the case names and `doc` (the
// reader's current document, the committed one) for each key's listing and
// revocation; `env` names the deployment's commit for the revoked page.
// -> {status, html}.
async function renderCase(kase, nowMs, doc = SEAL.PUBLISHED_KEYS, env = process.env) {
  const id = kase.case_id;
  const head = (word) => `  <h1>Case: ${esc(word)}</h1>\n  <p class="subtitle"><code>${esc(id)}</code></p>\n`;

  // SINGLE PARTY (red-team fix A), before the sealed check and EXPIRED.
  if (C.singleParty(kase)) return { status: 200, html: singlePartyPage(kase, nowMs, head) };

  // THE SEALED CHECK (item 2d; Design I), before a VERDICT is shown as
  // sealed and before its pin or its reference rows are read.
  let answer = null;
  if (kase.status === "VERDICT") {
    answer = await SEAL.sealedRecordReason(kase, doc);
    if (answer.code === "document_unavailable") return { status: 503, html: couldNotLookPage(kase, answer, head) };
    if (answer.code === "signer_revoked") return { status: 200, html: revokedPage(kase, answer, head, doc, env) };
    if (!SEAL.sealHolds(answer)) return { status: 200, html: unverifiedPage(kase, answer, head) };
  }

  // THE PROJECTION IS THE REGISTRATION (unit R-L4): what the root projects,
  // each file checked, and nothing else (unit R-L4c, c4). A case
  // whose projected file is missing or not the file projected is the
  // could-not-look page, case_record_inconsistent (unit R-L4b), before
  // anything else is shown of it (a single-party page and a sealed
  // record that does not verify show no registration, and read none).
  const reads = await registrationReads(kase);
  if (reads.inconsistent) return { status: 503, html: inconsistentPage(kase, head, reads.inconsistent) };

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
      limitsPanel(kase.limits)) };
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
      partiesPanel(kase) + limitsPanel(kase.limits)) };
  }

  let body = head(kase.status) + `  <section class="panel"><h2>The case</h2>${opening}</section>\n` + partiesPanel(kase) +
    registrationsPanel(kase, reads);
  if (kase.status === "VERDICT") {
    const pin = await SEAL.pinState(id, kase);
    const live = await SEAL.liveRecords(kase, { keyDocument: doc });
    body += sealedPanels(kase, pin, live, answer);
  } else {
    body += `  <section class="panel"><h2>Not sealed yet</h2><p class="muted">${kase.status === "OPEN"
      ? "Each role registers a stamped commitment before the deadline; then one request carries both reveals and both tapes."
      : "Both roles are registered. One request carrying both reveals and both tapes, received before the deadline, seals the case."}</p>${revealAttemptHtml(kase)}${facts([["signed by", signedByHtml(kase, doc)]])}</section>\n`;
  }
  return { status: 200, html: page(`Case ${id.slice(0, 12)}: ${kase.status}`, body + limitsPanel(kase.limits)) };
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
// opts.env names the deployment's commit, which only the SIGNED BY A REVOKED
// KEY page shows (unit R-REV: V, the commit of the document it carries);
// the dispatch passes none, so the page reads process.env.
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
  // Rendered on every request (unit R-PIN): no page is kept, and the
  // per-IP limiter above is the only bound.
  const out = await renderCase(got.json, nowMs, doc, opts.env || process.env);
  return sendHtml(res, out.status, out.html);
}

module.exports = {
  handleCasePage, LABELS_SENTENCE, ANCHORS_SENTENCE,
  _internal: {
    renderCase, esc, mismatchWords,
    cells: { pin: pinnedHtml },
  },
};

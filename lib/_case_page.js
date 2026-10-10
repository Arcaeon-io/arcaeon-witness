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
// computed from the pin ("pending" when it is absent, never stored), and
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
//                    receipt bound to it, then a signed case's signature
//                    under the verifier its signed_by names in the key
//                    document, the check anchorCase runs before it pins).
//                    Not a verdict: the id, the stored status, which check
//                    failed and its reason, the key the record names, links
//                    to the record and its history, and the four limits. No
//                    verdict word, records, cross-reference, anchor, label
//                    or registration: nothing in such a record is confirmed.
// RECORDS IN WORDS (item 2d). The live count is lib/_case_seal.js
// liveRecords'. When it could not be established (the read ended without a
// valid row while some listed row was not seen), the page says the count
// could not be established, and never "one record".
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
// pin pointer (the anchor state) and its reference rows (the live count, at
// most lib/_case_seal.js REFERENCE_ROW_READS rows). A VERDICT that fails the
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

function registrationsPanel(kase) {
  const repo = stampsRepo();
  const rows = [];
  for (const r of C.ROLES) {
    const e = kase.commitments[r];
    if (e === null) {
      rows.push([`role ${r}`, '<span class="muted">not registered</span>']);
      continue;
    }
    const commit = e.stamp_commit === null
      ? '<span class="muted">no stamp commit recorded</span>'
      : repo ? link(`https://github.com/${repo.repo}/commit/${e.stamp_commit}`, `stamp commit ${e.stamp_commit.slice(0, 12)}`) : `<code>${esc(e.stamp_commit)}</code>`;
    const record = repo ? ` &middot; ${link(`https://github.com/${repo.repo}/blob/${repo.branch}/${stamp.stampPath(e.commitment_sha256)}`, "stamp record")}` : "";
    const reg = ` &middot; ${link(pinsCommits(C.registrationPath(kase.case_id, r)), "registration record and its commit")}`;
    rows.push([`role ${r} registered at`, `${esc(e.registered_at)} <span class="muted">(stamped ${esc(e.stamped_at)})</span><br>${commit}${record}${reg}`]);
  }
  return `  <section class="panel"><h2>Registrations</h2>${facts(rows)}<p class="muted">Each role registered one commitment hash, stamped first as a public, dated commit. The links are derived from the hashes; the commitment's contents are not shown.</p></section>\n`;
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

function anchorHtml(st) {
  if (st.pin === "anchored") {
    return `anchored: its pin ${link(pinsBlob(`pins/${SEAL.pinNamespace(st.caseId)}/latest.json`), "pins/case/<case_id>/latest.json")} holds this case's chain.`;
  }
  if (st.pin === "pending") return "sealed, not yet anchored: its pin is not written yet. The operator's sealer run writes it, with the chain of the case file as stored.";
  if (st.pin === "conflict") return "a pin under this case's namespace holds another chain. This service never writes over it; the case file is the authority.";
  if (st.pin === "unreadable") return "a pin is present under this case's namespace and cannot be read as a case seal record.";
  return "the pin could not be read on this request, so the anchor state is not known.";
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
    return `${esc(recordsWords(kase.records))} at seal time <span class="muted">(the reference rows could not be read on this request, so a later one is not counted here)</span>`;
  }
  const notes = `${live.invalid.length ? ` <span class="muted">${esc(live.invalid.length)} reference row(s) are not valid and are not counted.</span>` : ""}` +
    `${live.unreadable.length ? ` <span class="muted">${esc(live.unreadable.length)} reference row(s) could not be read on this request.</span>` : ""}` +
    `${live.partial ? ` <span class="muted">${esc(live.unread)} more reference row(s) were not read on this request.</span>` : ""}`;
  if (live.indeterminate) {
    return `the live count could not be established on this request: no valid reference row was among the rows read, and ` +
      `${esc(live.unread + live.unreadable.length)} row(s) were not seen, so a valid one may be among them <span class="muted">(${seal})</span>${notes}`;
  }
  return `${esc(recordsWords(live.records))}${live.records !== kase.records ? ` (${seal}; the reference rows add the second)` : ""}${notes}`;
}

function crossRows(kase, live) {
  const out = [];
  const x = kase.cross_reference;
  if (x) out.push(["with the reveal", `${esc(x.operator)}: ${esc(x.reference)} &middot; ${link(x.url, x.url)} <span class="muted">(recorded ${esc(x.recorded_at)})</span>`]);
  if (live && live.ok) {
    for (const r of live.rows) {
      out.push([`reference row ${r.seq}`, `${esc(r.cross_reference.operator)}: ${esc(r.cross_reference.reference)} &middot; ${link(r.cross_reference.url, r.cross_reference.url)} ` +
        `<span class="muted">(recorded ${esc(r.recorded_at)}, appended by ${esc(r.appended_by)}, ${link(pinsBlob(C.referencePath(kase.case_id, r.seq)), "the row")})</span>`]);
    }
  }
  return out;
}

function sealedPanels(kase, anchor, live, doc) {
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
  html += `  <section class="panel"><h2>Anchor and signature</h2>${facts([
    ["anchor", anchorHtml(anchor)],
    ["signed by", signedByHtml(kase, doc)],
    ["case record", `${link(pinsBlob(C.casePath(kase.case_id)), "the case file")} &middot; ${link(pinsCommits(C.casePath(kase.case_id)), "its history")}`],
  ])}<p class="muted">${esc(SEAL.ANCHOR_NOTE)}</p></section>\n`;
  return html;
}

const UNVERIFIED_CHECKS = Object.freeze({
  verdict_unbound: "the receipt: the reconcile receipt it carries is not bound to it (its reveals, compared_at and policy, and a signed receipt's own signature)",
  case_signature_invalid: "the case signature: it is not confirmed under the verifier its signed_by names in the published key document",
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
    "when the reconcile receipt it carries is bound to it and, when it is signed, its signature verifies under the verifier its " +
    "signed_by names in the published key document. The case file and its history are the public record.</p></section>\n" +
    limitsPanel(C.LIMITS));
}

// The page's whole body for a case read and judged, at `nowMs`, with
// signatures checked against `doc` (the committed key document).
async function renderCase(kase, nowMs, doc = SEAL.PUBLISHED_KEYS) {
  const id = kase.case_id;
  const head = (word) => `  <h1>Case: ${esc(word)}</h1>\n  <p class="subtitle"><code>${esc(id)}</code></p>\n`;

  // THE SEALED CHECK (item 2d), before a VERDICT is shown as sealed and
  // before its pin or its reference rows are read.
  if (kase.status === "VERDICT") {
    const unsealed = SEAL.sealedRecordReason(kase, doc);
    if (unsealed) return unverifiedPage(kase, unsealed, head);
  }

  if (kase.status === "WITHDRAWN") {
    const w = kase.withdrawal;
    return page(`Case ${id.slice(0, 12)}: WITHDRAWN`, head("WITHDRAWN") +
      `  <section class="panel"><h2>The withdrawal record</h2>${facts([
        ["status", '<span class="word">WITHDRAWN</span>'],
        ["protocol", `<code>${esc(kase.protocol_version)}</code>`],
        ["opened at", esc(kase.opened_at)],
        ["withdrawn", `by role ${esc(w.by_role)}, at ${esc(w.at)} <span class="muted">(the role proved itself with its commitment preimage)</span>`],
        ["signed by", signedByHtml(kase, doc)],
        ["record", `${link(pinsBlob(C.casePath(id)), "the withdrawal record")} &middot; ${link(pinsCommits(C.casePath(id)), "its history")}`],
      ])}<p class="notice">${esc(SEAL.WITHDRAWN_REGISTRATIONS_NOTE)}</p></section>\n` + limitsPanel(kase.limits));
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
    return page(`Case ${id.slice(0, 12)}: EXPIRED`, head("EXPIRED") +
      `  <section class="panel"><h2>The opening</h2>${opening}<p class="muted">No joint reveal was received before the deadline, by this service's clock, so the case reads EXPIRED. Expiry is read, not written, and implies no actor.</p></section>\n` +
      partiesPanel(kase) + limitsPanel(kase.limits));
  }

  let body = head(kase.status) + `  <section class="panel"><h2>The case</h2>${opening}</section>\n` + partiesPanel(kase) + registrationsPanel(kase);
  if (kase.status === "VERDICT") {
    const anchor = { ...(await SEAL.anchorState(id, SEAL.caseChain(kase))), caseId: id };
    const live = await SEAL.liveRecords(kase, { keyDocument: doc });
    body += sealedPanels(kase, anchor, live, doc);
  } else {
    body += `  <section class="panel"><h2>Not sealed yet</h2><p class="muted">${kase.status === "OPEN"
      ? "Each role registers a stamped commitment before the deadline; then one request carries both reveals and both tapes."
      : "Both roles are registered. One request carrying both reveals and both tapes, received before the deadline, seals the case."}</p>${facts([["signed by", signedByHtml(kase, doc)]])}</section>\n`;
  }
  return page(`Case ${id.slice(0, 12)}: ${kase.status}`, body + limitsPanel(kase.limits));
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
// and opts.keyDocument the key document (tests); the dispatch passes
// neither, so the page reads the service clock and the committed document.
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
  const cpath = C.casePath(id);
  let got;
  try {
    got = await store.getFile(cpath);
  } catch (e) {
    console.error(`[case] page: case read failed (${e && e.message})`);
    return sendHtml(res, 503, notice("Could not look", "The case record could not be read on this request. That is not a no; try again."));
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
  const doc = opts.keyDocument === undefined ? SEAL.PUBLISHED_KEYS : opts.keyDocument;
  return sendHtml(res, 200, await renderCase(got.json, nowMs, doc));
}

module.exports = { handleCasePage, LABELS_SENTENCE, _internal: { renderCase, esc } };

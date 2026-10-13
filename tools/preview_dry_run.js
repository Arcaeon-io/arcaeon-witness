#!/usr/bin/env node
// tools/preview_dry_run.js — a dry run of the case protocol against a preview
// deployment, before anything is promoted (case protocol item 3a).
//
// It drives the preview over HTTP the way a party would, compares what the
// preview serves with this checkout, and prints exactly one line per check,
// in this order, each starting with VERIFIED, BROKEN or COULD NOT LOOK and
// followed by its evidence (HTTP status, byte count, sha256, case_id, or why
// it could not look):
//
//   (a) /.well-known/arcaeon/case-signing-keys.json is served byte-identical
//       to the committed file in this checkout,
//       public/.well-known/arcaeon/case-signing-keys.json (sha256 compared).
//   (b) the /case/:case_id rewrite in this checkout's vercel.json delivers
//       the case page: GET /case/<case_id> for a case this run opened answers
//       200 text/html naming that case_id, with the status OPEN.
//   (c) case-open with the issued key answers 201. With --exhaust-quota the
//       run keeps opening until the 21st open of the UTC day is refused 429
//       open_quota_exceeded (lib/_case_http.js THE OPEN QUOTA, 20 a key a
//       day); without it the line is COULD NOT LOOK, saying so.
//   (d) a stamp, then an immediate read of the stamp's commit, sees it: role
//       a's commitment is stamped (POST /api/stamp, size 272) and registered
//       at once (?op=case-commit, which reads the stamp's commit history);
//       the registration must name the commit the stamp answered with. Each
//       role registers under its own throwaway registration key, made for
//       this run and held in memory only (lib/_case.js ONE KEY PER ROLE: the
//       two roles of a case are two distinct key ids); only the public
//       verifier and the signature are sent.
//   (e) case-reveal with a JSON body sent chunked, with NO content-length
//       header, is accepted: role b is stamped and registered, then the
//       joint reveal goes out in chunks and must answer 201, sealed VERDICT,
//       SIGNED: the sealed case names its key in signed_by, its sig verifies
//       under that key's ACTIVE entry in this checkout's key document
//       (lib/_case_seal.js sealedRecordReason, the receipt binding included,
//       and since red-team fix B its receipt signed by the service's
//       reconcile signer: see THE RECONCILE VERIFIER, below), and the
//       answer's chain is 64 hex and the case's own. A seal that is
//       unsigned (sig or signed_by missing or null), or signed by a key the
//       document does not list as active, is BROKEN: the run exists to show
//       the published case signer is installed.
//   (f) the sealer's case pass (lib/_sealer.js anchorCases, the pass
//       tools/seal_batch.js runs) against the preview's pins store. It reads
//       and writes that store directly, never through the preview, so it
//       needs the pins token: without --pin-token it is COULD NOT LOOK. With
//       it, the store GITHUB_PIN_REPO / GITHUB_PIN_BRANCH name must hold the
//       case this run opened on the preview (else it is not the preview's
//       store, and the line says so), the pass must report nothing refused,
//       in conflict or unreadable, and the case sealed in (e) must be
//       pinned (lib/_case_seal.js THE ANCHOR WORDS: the pin holds its chain
//       at the commit that wrote it, read on the raw host) or anchored, its
//       pin record's chain equal to the 64-hex chain the reveal answered
//       with; a pin under any other chain is BROKEN. A pin it could not read
//       at its commit (a pins store the raw host does not serve, say) is
//       COULD NOT LOOK.
//   (g) nothing at the project root that is not meant to be public is
//       served: README.md, package.json, package-lock.json, and every file
//       under lib/, tools/ and test/ in this checkout (tests/ too, if it
//       exists) must answer 404. Any other answer that arrives (a 2xx, a
//       301/302/307/308 redirect, a 403, anything) is BROKEN, with the
//       paths; only a request that got no answer at all is COULD NOT LOOK.
//
// USAGE
//
//   node tools/preview_dry_run.js --base <preview URL> --key <issued key>
//        [--bypass <secret>] [--operator-key <k>] [--pin-token <t>] [--exhaust-quota]
//
//   --base <url>        the preview's origin, https://<deployment>.vercel.app
//                       (no path, no query).
//   --bypass <secret>   the Vercel project's Protection Bypass for Automation
//                       secret. Read from VERCEL_AUTOMATION_BYPASS_SECRET when
//                       the flag is absent. Sent as x-vercel-protection-bypass
//                       on every request to the preview, and nothing else:
//                       never x-vercel-set-bypass-cookie, which Vercel answers
//                       with a 307 to the same URL (its cookie handshake)
//                       instead of the page.
//   --key <key>         an issued key (ARCAEON_KEY). Sent only as the bearer of
//                       case-open and of the two stamps. Use a key that has not
//                       opened a case today if --exhaust-quota is given.
//   --operator-key <k>  WITNESS_CASE_OPERATOR_KEY, which authenticates
//                       ?op=case-reference. No check above calls that op, so
//                       it is accepted and never sent.
//   --pin-token <t>     the pins store's token (GITHUB_PIN_TOKEN), for (f) only.
//                       It is set for the pass alone and never sent to the
//                       preview. Set GITHUB_PIN_REPO and GITHUB_PIN_BRANCH to
//                       the preview's pins store if it is not the default.
//   --exhaust-quota     run the quota half of (c): up to 21 opens.
//   --help              this text
//
//   KEY_DOCUMENT_BRANCH (environment; unit R-I2) the key document's published
//                       branch, main unless set. (e) and (f) hold each sealed
//                       case's named document commit to it (lib/_case_seal.js
//                       commitOnBranch), so this shell must set the same
//                       value as the preview deployment, or a preview of
//                       another branch reads as not published here.
//
// THE RECONCILE VERIFIER (red-team fix B; Design I). Since Design I a
// sealed case is held to the key document it NAMES (signed_under), read
// from the public repository at the commit it names, for both its case
// signature and its receipt's (lib/_case_seal.js THE SEALED CHECK); (e) and
// (f) both use that check, and a named document that cannot be read is
// COULD NOT LOOK. (e) also holds the seal to THIS checkout's document (the
// one (a) compares): a seal under another document is BROKEN. And it holds
// the receipt's signer to the preview's own reconcile key, which
// WITNESS_RECONCILE_VERIFIER names on this machine (the verifier string; it
// is public), or the signer key itself if it is set here (the private-side
// pointer to which published reconcile entry is the preview's,
// lib/_reconcile_receipt.js expectedVerifier). With neither, (e) is COULD
// NOT LOOK, saying so; a receipt signed by another key is BROKEN.
//
// A PROTECTED PREVIEW. The project protects its previews with Vercel
// Authentication, so a request without the bypass is answered 401 with
// Vercel's SSO page before any function runs. The first request is the
// GET of (a). When it answers 401 with that page, nothing more is asked of
// the preview and every check is COULD NOT LOOK, with the reason "protected
// preview, no bypass given", or, when a bypass was given, "protected
// preview, the bypass given was refused". Exit 3. The page is told from any
// other 401 by Vercel's marks on it: a link to vercel.com/sso-api, a
// _vercel_sso_nonce cookie, or the title "Authentication Required" served by
// Vercel. Another 401 leaves the checks to run, and each reads it as
// COULD NOT LOOK on its own.
//
// NOTHING SECRET IS PRINTED. Neither key, the bypass secret, the operator
// key nor the pin token appears on stdout or stderr: every line is checked
// for each of them and any occurrence is replaced before it is written.
// stdout carries the seven lines and nothing else; progress goes to stderr.
//
// IT WRITES TO THE PREVIEW'S STORES. A dry run is real traffic: one case (21
// with --exhaust-quota) is opened in the preview's pins store, two stamps go
// to its stamps store (free, or 0.25 credits each from the key once the
// address's free stamps are spent), two registrations and one sealed case
// with its pin are written, and with --pin-token the case pass may pin other
// pending cases there. The parties are labelled "preview-dry-run agent" and
// "preview-dry-run tool". The tapes are the MATCHED pair of
// test/fixtures/reconcile/cases.json that test/case_reveal.test.js seals.
// The per-IP limiter (30 calls in 10 minutes, shared by every case op and
// the page) leaves room for one --exhaust-quota run in a window; a second
// run inside it reads 429 rate_limited, which is COULD NOT LOOK, never
// mistaken for the quota.
//
// EXIT CODES: 0 every check VERIFIED; 2 a check BROKEN; 3 a check COULD NOT
// LOOK (3 wins over 2); 1 usage.
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const C = require("../lib/_case.js");
const S = require("../lib/_case_seal.js");
const checkpoint = require("../lib/_checkpoint.js"); // generateKey: the run's two registration keys
const { canonicalBytes } = require("../lib/_check_record.js"); // (e): this checkout's document, as a seal names it
const receipts = require("../lib/_reconcile_receipt.js"); // expectedVerifier: THE RECONCILE VERIFIER

const ROOT = path.join(__dirname, "..");
const VERIFIED = "VERIFIED";
const BROKEN = "BROKEN";
const COULD_NOT_LOOK = "COULD NOT LOOK";

const CHECKS = Object.freeze([
  ["a", "case key document"],
  ["b", "case page rewrite"],
  ["c", "case-open and the open quota"],
  ["d", "stamp, then its commit read at once"],
  ["e", "chunked case-reveal"],
  ["f", "sealer's case pass"],
  ["g", "root-file exposure"],
]);

// THE OPEN QUOTA (lib/_case_http.js OPEN_QUOTA_PER_DAY): the 21st is refused.
const QUOTA_PER_DAY = 20;
const CASE_PAGE_SOURCE = "/case/:case_id";
const EXPOSED_FILES = Object.freeze(["README.md", "package.json", "package-lock.json"]);
const EXPOSED_DIRS = Object.freeze(["lib", "tools", "test", "tests"]);
const EXPOSURE_CONCURRENCY = 8;
const TAPES_FIXTURE = "test/fixtures/reconcile/cases.json";
const TAPES_NAME = /^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/;
const REVEAL_CHUNKS = 4;
const TIMEOUT_MS = 30000;
// A PROTECTED PREVIEW, above.
const BYPASS_ENV = "VERCEL_AUTOMATION_BYPASS_SECRET";
const BYPASS_HEADER = "x-vercel-protection-bypass";

function helpText() {
  const src = fs.readFileSync(__filename, "utf8").split("\n");
  const out = [];
  for (const line of src.slice(1)) {
    if (!line.startsWith("//")) break;
    out.push(line.replace(/^\/\/ ?/, ""));
  }
  return out.join("\n");
}

function parseArgs(argv) {
  const a = { exhaustQuota: false };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${t} needs a value`);
      return argv[++i];
    };
    if (t === "--help" || t === "-h") a.help = true;
    else if (t === "--base") a.base = next();
    else if (t === "--key") a.key = next();
    else if (t === "--bypass") a.bypass = next();
    else if (t === "--operator-key") a.operatorKey = next();
    else if (t === "--pin-token") a.pinToken = next();
    else if (t === "--exhaust-quota") a.exhaustQuota = true;
    else throw new Error(`unknown argument ${t}`);
  }
  return a;
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function tryJson(buf) {
  try {
    return JSON.parse(buf.toString("utf8"));
  } catch {
    return null;
  }
}

// A function's own refusal names itself: error_code (the case ops), or
// reason (the stamp endpoint).
function codeOf(json) {
  if (!json || typeof json !== "object") return null;
  if (typeof json.error_code === "string") return json.error_code;
  if (typeof json.reason === "string") return json.reason;
  return null;
}

function said(ans) {
  if (ans.error) return ans.error;
  const code = codeOf(tryJson(ans.body));
  return `HTTP ${ans.status}${code ? ` ${code}` : ""}`;
}

// ---------------------------------------------------------------------------
// HTTP: node's own client, one connection per request, never a redirect
// followed, never a body decoded (accept-encoding: identity), never throws.
// Three clocks, so nothing can hang the run: the request's socket going
// quiet `timeoutMs` before an answer starts, the answer going quiet
// `timeoutMs` mid-body (res.setTimeout), and a deadline of `deadlineMs`
// (four idle periods unless given) on the whole exchange, which also ends an
// answer that trickles in forever. -> {status, headers, body} or {error}.
// ---------------------------------------------------------------------------
function request(base, method, target, { headers = {}, body = null, chunks = null, timeoutMs = TIMEOUT_MS, deadlineMs = timeoutMs * 4 } = {}) {
  return new Promise((resolve) => {
    let done = false;
    let req = null;
    let res = null;
    let deadline = null;
    const finish = (v) => {
      if (!done) {
        done = true;
        clearTimeout(deadline);
        resolve(v);
      }
    };
    const abandon = (error) => {
      finish({ error });
      if (res) res.destroy();
      if (req) req.destroy();
    };
    const u = new URL(target, base);
    const mod = u.protocol === "https:" ? https : http;
    const h = { "accept-encoding": "identity", "user-agent": "arcaeon-preview-dry-run/1", ...headers };
    if (body !== null) h["content-length"] = String(Buffer.byteLength(body));
    if (chunks !== null) h["transfer-encoding"] = "chunked";
    deadline = setTimeout(() => abandon(`no complete answer in ${deadlineMs / 1000}s`), deadlineMs);
    try {
      req = mod.request(u, { method, headers: h, agent: false }, (r) => {
        res = r;
        const parts = [];
        res.setTimeout(timeoutMs, () => abandon(`the answer stalled mid-body (nothing for ${timeoutMs / 1000}s)`));
        res.on("data", (c) => parts.push(c));
        res.on("end", () => finish({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts) }));
        res.on("error", (e) => finish({ error: `the answer broke off (${e.code || e.message})` }));
        res.on("close", () => finish({ error: "the answer broke off before its end" }));
      });
    } catch (e) {
      finish({ error: `the request could not be made (${e.code || e.message})` });
      return;
    }
    // Before an answer starts; once it has, its own clock (res.setTimeout) owns it.
    req.setTimeout(timeoutMs, () => {
      if (!res) abandon(`no answer in ${timeoutMs / 1000}s`);
    });
    req.on("error", (e) => finish({ error: `no answer (${e.code || e.message})` }));
    if (chunks !== null) {
      for (const c of chunks) req.write(c);
      req.end();
    } else {
      req.end(body === null ? undefined : body);
    }
  });
}

// Every request to the preview: `request` with the bypass, when one was
// given, as x-vercel-protection-bypass on every request, and no cookie
// asked for (--bypass, above: x-vercel-set-bypass-cookie draws a 307).
function send(ctx, method, target, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (ctx.bypass) headers[BYPASS_HEADER] = ctx.bypass;
  return request(ctx.base, method, target, { ...opts, headers });
}

// Vercel's SSO page: a 401 carrying a link to vercel.com/sso-api, a
// _vercel_sso_nonce cookie, or the title "Authentication Required" served
// by Vercel (A PROTECTED PREVIEW, above).
function vercelSso(ans) {
  if (ans.error || ans.status !== 401) return false;
  const html = ans.body.toString("utf8");
  const cookies = [].concat(ans.headers["set-cookie"] || []).join("\n");
  const byVercel = /vercel/i.test(String(ans.headers.server || "")) || /vercel/i.test(html);
  return /vercel\.com\/sso-api/i.test(html) || /_vercel_sso_nonce=/i.test(cookies) ||
    (byVercel && /<title>\s*Authentication Required\s*<\/title>/i.test(html));
}

// Why an answer is not one the check can judge, or null when it is the
// function's own answer to judge. A 429, a 502/503/504 that is not a
// deployment saying it is not configured, and a 401/403 that is not the
// function's own JSON refusal (deployment protection answers before the
// function) cannot be judged.
function unlooked(ans) {
  if (ans.error) return ans.error;
  const json = tryJson(ans.body);
  const code = codeOf(json);
  if (ans.status === 429) return `${said(ans)}: refused for rate, not judged`;
  if ([502, 503, 504].includes(ans.status)) {
    if (code && /not_configured/.test(code)) return null;
    return `${said(ans)}: the preview could not answer this request`;
  }
  if ((ans.status === 401 || ans.status === 403) && !(json && json.ok === false)) {
    return `HTTP ${ans.status} before any function answered (deployment protection?)`;
  }
  return null;
}

const verified = (text) => ({ word: VERIFIED, text });
const broken = (text) => ({ word: BROKEN, text });
const couldNotLook = (text) => ({ word: COULD_NOT_LOOK, text });

// ---------------------------------------------------------------------------
// the run's case: one opening, its two parties, their tapes and salts
// ---------------------------------------------------------------------------
function loadTapes(root) {
  let fx;
  try {
    fx = JSON.parse(fs.readFileSync(path.join(root, ...TAPES_FIXTURE.split("/")), "utf8"));
  } catch (e) {
    return { why: `the tape pair could not be read from ${TAPES_FIXTURE} (${e.code || e.name})` };
  }
  const c = (fx.cases || []).find((x) => TAPES_NAME.test(x.name) && x.python);
  if (!c) return { why: `${TAPES_FIXTURE} holds no MATCHED agent-vs-tool pair named as test/case_reveal.test.js names it` };
  return { a: Buffer.from(c.a_b64, "base64"), b: Buffer.from(c.b_b64, "base64") };
}

function party(caseId, role, tape) {
  const salt = C.newSalt();
  const tape_sha256 = sha256hex(tape);
  return { role, tape, salt, tape_sha256, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}

// An opening only this run makes: its scope digest names the run and the
// open's number. The parties are already in canonical order (agent sorts
// before tool), so role a is the agent.
function opening(ctx, n) {
  const nowMs = Date.now();
  return {
    protocol_version: C.PROTOCOL_VERSION,
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha256hex(`arcaeon preview dry run ${ctx.runId} open ${n}`),
    party_a: { side: "agent", label: "preview-dry-run agent" },
    party_b: { side: "tool", label: "preview-dry-run tool" },
    opened_at: C.utcSeconds(nowMs - 60000),
    deadline: C.utcSeconds(nowMs + 86400000),
  };
}

function postJson(ctx, target, obj, { bearer = null } = {}) {
  const headers = { "content-type": "application/json" };
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  return send(ctx, "POST", target, { headers, body: JSON.stringify(obj) });
}

async function open(ctx, n) {
  ctx.log(`(c) case-open ${n}`);
  const ans = await postJson(ctx, "/api/verify?op=case-open", opening(ctx, n), { bearer: ctx.key });
  const json = ans.error ? null : tryJson(ans.body);
  return { ans, json, caseId: ans.status === 201 && json && /^[0-9a-f]{64}$/.test(String(json.case_id)) ? json.case_id : null };
}

// Open #1, shared by (b), (c), (d), (e) and (f): made once, when first needed.
async function firstOpen(ctx) {
  if (!ctx.first) ctx.first = await open(ctx, 1);
  return ctx.first;
}

// The verdict on an open that did not answer 201.
function openFailed(o, n) {
  const why = unlooked(o.ans);
  if (why) return couldNotLook(`case-open ${n} with the issued key: ${why}`);
  if (o.ans.status === 201) return broken(`case-open ${n} with the issued key answered HTTP 201 without a case_id`);
  return broken(`case-open ${n} with the issued key answered ${said(o.ans)}, not 201`);
}

async function stampIt(ctx, sha) {
  ctx.log("stamp");
  const ans = await postJson(ctx, "/api/stamp", { sha256: sha, size: C.COMMITMENT_BYTES_LENGTH }, { bearer: ctx.key });
  const json = ans.error ? null : tryJson(ans.body);
  if (ans.status === 201 && json && typeof json.commit === "string") return { ok: true, commit: json.commit, ans };
  if (ans.status === 200 && json && json.existing === true) {
    return { ok: false, verdict: couldNotLook(`the stamp answered HTTP 200 existing: this hash was stamped before, so the write is not fresh`) };
  }
  if (ans.status === 201) return { ok: false, verdict: couldNotLook("the stamp answered HTTP 201 and named no commit to compare") };
  if (ans.status === 402) return { ok: false, verdict: couldNotLook("the stamp answered HTTP 402: the issued key's balance is below a stamp's price once the free stamps are spent") };
  const why = unlooked(ans);
  if (why) return { ok: false, verdict: couldNotLook(`the stamp: ${why}`) };
  return { ok: false, verdict: broken(`the stamp answered ${said(ans)}, not 201`) };
}

// A registration signed by the role's own key for this run (ONE KEY PER
// ROLE, lib/_case.js): the verifier and the signature, never the key.
async function register(ctx, caseId, p) {
  ctx.log(`case-commit role ${p.role}`);
  const k = ctx.regKeys[p.role];
  const fields = { case_id: caseId, role: p.role, commitment_sha256: p.commitment_sha256 };
  const ans = await postJson(ctx, "/api/verify?op=case-commit", { ...fields, verifier: k.verifier, sig: C.signRegistration(fields, k.signer) });
  return { ans, json: ans.error ? null : tryJson(ans.body) };
}

// ---------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------
async function checkKeyDocument(ctx) {
  const rel = S.CASE_KEYS_DOC;
  let local;
  try {
    local = fs.readFileSync(path.join(ctx.root, ...S.CASE_KEYS_FILE.split("/")));
  } catch (e) {
    return couldNotLook(`the committed ${S.CASE_KEYS_FILE} could not be read in this checkout (${e.code || e.name})`);
  }
  const want = sha256hex(local);
  // The run's first request is this GET (run, below); its answer is read here.
  const ans = ctx.keysDocAnswer || (await send(ctx, "GET", `/${rel}`));
  ctx.keysDocAnswer = null;
  if (ans.error) return couldNotLook(`GET /${rel}: ${ans.error}`);
  if (ans.status === 200) {
    const got = sha256hex(ans.body);
    if (got === want) return verified(`GET /${rel}: HTTP 200, ${ans.body.length} bytes, sha256 ${got}, byte-identical to the committed file`);
    return broken(`GET /${rel}: HTTP 200, ${ans.body.length} bytes, sha256 ${got}; the committed file is ${local.length} bytes, sha256 ${want}`);
  }
  if (ans.status === 404) return broken(`GET /${rel}: HTTP 404, not served (the committed file is ${local.length} bytes, sha256 ${want})`);
  return couldNotLook(`GET /${rel}: ${unlooked(ans) || `HTTP ${ans.status}, neither the file nor a 404`}`);
}

// A rewrite source as Vercel writes one (":name" segments, optionally with a
// "(regex)") -> RegExp, or null.
function sourceRegex(source) {
  if (typeof source !== "string" || !source.startsWith("/")) return null;
  const parts = source.split("/").map((seg) => {
    const m = /^:([A-Za-z_][A-Za-z0-9_]*)(\((.+)\))?$/.exec(seg);
    if (m) return `(${m[3] || "[^/]+"})`;
    return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  });
  try {
    return new RegExp(`^${parts.join("/")}$`);
  } catch {
    return null;
  }
}

function caseRewrite(vercel) {
  const rewrites = vercel && Array.isArray(vercel.rewrites) ? vercel.rewrites : [];
  return rewrites.find((r) => r && r.source === CASE_PAGE_SOURCE && sourceRegex(r.source)) || null;
}

async function checkCasePage(ctx) {
  const rw = caseRewrite(ctx.vercel);
  const o = await firstOpen(ctx);
  if (!o.caseId) {
    const why = `no case_id to ask for: case-open answered ${said(o.ans)}`;
    return rw ? couldNotLook(why) : broken(`this checkout's vercel.json has no rewrite for ${CASE_PAGE_SOURCE}; ${why}`);
  }
  const id = o.caseId;
  ctx.log(`(b) GET /case/${id}`);
  const ans = await send(ctx, "GET", `/case/${id}`);
  if (!rw) return broken(`this checkout's vercel.json has no rewrite for ${CASE_PAGE_SOURCE}; GET /case/${id}: ${said(ans)}`);
  const via = `vercel.json rewrites ${rw.source} to ${rw.destination}`;
  if (ans.error) return couldNotLook(`${via}; GET /case/${id}: ${ans.error}`);
  const type = String(ans.headers["content-type"] || "");
  const html = ans.body.toString("utf8");
  if (ans.status === 200 && /^text\/html\b/i.test(type) && html.includes(`<code>${id}</code>`) && html.includes("<h1>Case: OPEN</h1>")) {
    return verified(`${via}; GET /case/${id}: HTTP 200 ${type.split(";")[0]}, ${ans.body.length} bytes, the page of case_id ${id}, status OPEN`);
  }
  const why = unlooked(ans);
  if (why) return couldNotLook(`${via}; GET /case/${id}: ${why}`);
  if (ans.status === 200) {
    const missing = !/^text\/html\b/i.test(type) ? `content-type ${type || "none"}, not text/html`
      : !html.includes(`<code>${id}</code>`) ? "the page does not name this case_id" : "the page does not say Case: OPEN";
    return broken(`${via}; GET /case/${id}: HTTP 200, ${ans.body.length} bytes, but ${missing}`);
  }
  return broken(`${via}; GET /case/${id}: HTTP ${ans.status}, ${ans.body.length} bytes, not the case page`);
}

async function checkOpenQuota(ctx) {
  const o = await firstOpen(ctx);
  if (!o.caseId) {
    const v = openFailed(o, 1);
    const tail = ctx.exhaustQuota ? "the quota run needs the first open to succeed, so it was not started" : "the quota was not tried: --exhaust-quota was not given";
    return { word: v.word, text: `${v.text}; ${tail}` };
  }
  const first = `case-open 1 with the issued key answered HTTP 201 (case_id ${o.caseId})`;
  if (!ctx.exhaustQuota) return couldNotLook(`${first}; the 21st open of the day was not tried: --exhaust-quota was not given`);
  let last = null;
  for (let n = 2; n <= QUOTA_PER_DAY + 1; n += 1) {
    const r = await open(ctx, n);
    if (r.caseId) {
      last = r.caseId;
      continue;
    }
    const code = codeOf(r.json);
    if (r.ans.status === 429 && code === "rate_limited") {
      return couldNotLook(`${first}; open ${n} was refused HTTP 429 rate_limited by the per-IP limiter, not by the open quota, ` +
        `with ${n - 1} opens accepted in this run`);
    }
    if (r.ans.status === 429 && code === "open_quota_exceeded") {
      const retry = r.ans.headers["retry-after"];
      if (n === QUOTA_PER_DAY + 1) {
        return verified(`${first}; opens 1-${QUOTA_PER_DAY} answered HTTP 201 and open ${n} was refused HTTP 429 open_quota_exceeded ` +
          `(quota_per_day ${r.json.quota_per_day}, day ${r.json.day}${retry ? `, retry-after ${retry}s` : ""})`);
      }
      return couldNotLook(`${first}; open ${n} of this run was refused HTTP 429 open_quota_exceeded after ${n - 1} accepted: this key ` +
        "had opened cases earlier today, so this run cannot count to the 21st open of the day (use a key that has not opened a case today)");
    }
    const v = openFailed(r, n);
    return { word: v.word, text: `${first}; ${v.text}, ${n - 1} opens accepted in this run` };
  }
  return broken(`${first}; open ${QUOTA_PER_DAY + 1} of this run was accepted HTTP 201 (case_id ${last}): ` +
    `no open quota refused it after ${QUOTA_PER_DAY}`);
}

async function checkStampRead(ctx) {
  const o = await firstOpen(ctx);
  if (!o.caseId) return couldNotLook(`no case to register a stamped commitment to: case-open answered ${said(o.ans)}`);
  if (ctx.tapes.why) return couldNotLook(ctx.tapes.why);
  const a = party(o.caseId, "a", ctx.tapes.a);
  ctx.log("(d) role a: stamp, then case-commit");
  const st = await stampIt(ctx, a.commitment_sha256);
  if (!st.ok) return st.verdict;
  const r = await register(ctx, o.caseId, a);
  const stamped = `stamp of role a's commitment ${a.commitment_sha256} answered HTTP 201, commit ${st.commit}`;
  if (r.ans.status === 201 && r.json && r.json.registration) {
    ctx.roleA = a;
    const read = r.json.registration.stamp_commit;
    if (read === st.commit) return verified(`${stamped}; case-commit at once answered HTTP 201 and read stamp_commit ${read}, the same commit`);
    return broken(`${stamped}; case-commit at once answered HTTP 201 but read stamp_commit ${read}, another commit`);
  }
  const code = codeOf(r.json);
  if (r.ans.status === 404 && code === "no_commitment") {
    return broken(`${stamped}; case-commit at once answered HTTP 404 no_commitment: the read did not see the stamp`);
  }
  if (r.ans.status === 503 && code === "stamp_history_unreadable" && r.json.reason === "no_commit_touches_path") {
    return broken(`${stamped}; case-commit at once answered HTTP 503 stamp_history_unreadable (no_commit_touches_path): the read did not see the stamp's commit`);
  }
  const why = unlooked(r.ans);
  if (why) return couldNotLook(`${stamped}; case-commit: ${why}`);
  return broken(`${stamped}; case-commit at once answered ${said(r.ans)}, not 201`);
}

const HEX64 = /^[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// THE RECONCILE VERIFIER, above: why (e) cannot judge a receipt's signer.
const NO_RECONCILE_VERIFIER = `no reconcile verifier is known here (set ${receipts.VERIFIER_ENV} to the public verifier of the preview's ` +
  `${receipts.SIGNER_ENV}), so the receipt's signer cannot be checked`;

// (e)'s judgement of a 201 VERDICT answer: the sealed case it carries is
// signed, sealed under this checkout's key document, its receipt signed by
// the preview's own reconcile key, valid under the document it names (read
// at its commit, so its key was active there and is not revoked here), and
// the answer's chain is 64 hex and that case's own.
// -> verified(what was shown) or broken / couldNotLook(why not).
async function sealedAnswer(ctx, id, json) {
  const k = json.case;
  if (!isObject(k)) return broken("it carries no sealed case object");
  const absent = (v) => (v === undefined ? "missing" : v === null ? "null" : null);
  if (absent(k.signed_by) || absent(k.sig)) {
    return broken(`the seal is unsigned (signed_by ${absent(k.signed_by) || "set"}, sig ${absent(k.sig) || "set"}` +
      `${typeof k.sig_reason === "string" ? `; sig_reason: ${k.sig_reason}` : ""}): the published case signer is not installed`);
  }
  const v = C.validateCase(k);
  if (!v.ok) return broken(`its sealed case is not a valid arcaeon-case/1 record (${v.code} at ${v.field})`);
  if (k.status !== "VERDICT" || k.case_id !== id) return broken(`its sealed case is ${k.status} for case_id ${k.case_id}, not this case's VERDICT`);
  const doc = S.checkKeyDocument(ctx.keyDocument);
  if (!doc.ok) return couldNotLook(`this checkout's ${S.CASE_KEYS_FILE} does not read (${doc.reason} at ${doc.at}), so the signature cannot be checked`);
  const mine = crypto.createHash("sha256").update(canonicalBytes(ctx.keyDocument)).digest("hex");
  if (!isObject(k.signed_under) || k.signed_under.document_sha256 !== mine) {
    return broken(`it was sealed under ${isObject(k.signed_under) ? `the key document ${k.signed_under.document_sha256} at commit ${k.signed_under.document_commit}` : "no recorded key document"}, ` +
      `not this checkout's ${S.CASE_KEYS_FILE} (${mine})`);
  }
  if (!ctx.receiptVerifier) return couldNotLook(NO_RECONCILE_VERIFIER);
  const rs = isObject(k.verdict) && isObject(k.verdict.signer) ? k.verdict.signer.verifier : null;
  if (rs !== ctx.receiptVerifier) return broken(`its receipt is signed by ${rs || "no key"}, not the reconcile key ${receipts.VERIFIER_ENV} names`);
  const answer = await S.sealedRecordReason(k, ctx.keyDocument);
  if (answer.code === "document_unavailable") {
    // unit R-I (I5): which document could not be read
    if (answer.document === "current") return couldNotLook(`the current key document this checkout carries could not be read (${answer.reason})`);
    return couldNotLook(`the key document it names (commit ${answer.document_commit}) could not be read from the public repository (${answer.reason})`);
  }
  if (answer.code !== "valid_under_document") {
    return broken(`its sealed record does not hold under the key document it names (${answer.code}${answer.reason ? `: ${answer.reason}` : ""})`);
  }
  if (typeof json.chain !== "string" || !HEX64.test(json.chain)) return broken(`its chain ${JSON.stringify(json.chain)} is not 64 hex`);
  const own = S.caseChain(k);
  if (json.chain !== own) return broken(`its chain ${json.chain} is not the sealed case's own (${own})`);
  return verified(`signed by ${k.signed_by}, verified under its active entry in ${S.CASE_KEYS_FILE}, the document it names at commit ` +
    `${k.signed_under.document_commit}; chain ${json.chain}, the case's own`);
}

async function checkChunkedReveal(ctx) {
  const o = await firstOpen(ctx);
  if (!o.caseId) return couldNotLook(`no case to reveal: case-open answered ${said(o.ans)}`);
  if (!ctx.roleA) return couldNotLook("role a was not registered in (d), so the case cannot be COMMITTED for a reveal");
  const id = o.caseId;
  const b = party(id, "b", ctx.tapes.b);
  ctx.log("(e) role b: stamp, then case-commit");
  const st = await stampIt(ctx, b.commitment_sha256);
  if (!st.ok) return couldNotLook(`setup, role b's stamp: ${st.verdict.text}`);
  const r = await register(ctx, id, b);
  if (!(r.ans.status === 201 && r.json && r.json.status === "COMMITTED")) {
    return couldNotLook(`setup, role b's registration answered ${said(r.ans)}${r.json && r.json.status ? ` (status ${r.json.status})` : ""}, not 201 COMMITTED`);
  }
  const a = ctx.roleA;
  const text = JSON.stringify({
    case_id: id,
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    tape_a_b64: a.tape.toString("base64"),
    tape_b_b64: b.tape.toString("base64"),
  });
  const bytes = Buffer.from(text, "utf8");
  const size = Math.ceil(bytes.length / REVEAL_CHUNKS);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += size) chunks.push(bytes.subarray(i, i + size));
  ctx.log(`(e) case-reveal, chunked, ${bytes.length} bytes in ${chunks.length} chunks`);
  const ans = await send(ctx, "POST", "/api/verify?op=case-reveal", { headers: { "content-type": "application/json" }, chunks });
  const sent = `a JSON body of ${bytes.length} bytes sent in ${chunks.length} chunks with no content-length`;
  const json = ans.error ? null : tryJson(ans.body);
  if (ans.status === 201 && json && json.case_id === id && json.status === "VERDICT") {
    const head = `case-reveal with ${sent} answered HTTP 201 VERDICT for case_id ${id}`;
    const seal = await sealedAnswer(ctx, id, json);
    if (seal.word !== VERIFIED) return { word: seal.word, text: `${head}, but ${seal.text}` };
    ctx.sealed = { caseId: id, chain: json.chain, pin: json.pin };
    const word = json.verdict && json.verdict.verdict ? `, verdict ${json.verdict.verdict}` : "";
    return verified(`${head}${word}: ${seal.text}, pin ${json.pin}`);
  }
  // The one signature rule (lib/_case_seal.js): a preview without a case key
  // its document lists seals nothing and says so. That is the deployment's
  // configuration, not an answer it could not give: BROKEN.
  // Unit R-I (I2): a preview whose bundled key document is not the one at
  // the commit it names, or whose commit is not on its published branch
  // (KEY_DOCUMENT_BRANCH), seals nothing and says so. Its configuration, not
  // a read that failed: BROKEN. A document it could not read stays COULD NOT LOOK.
  if (ans.status === 503 && json && json.error_code === "document_unavailable" &&
    (json.reason === "bundled_document_differs" || json.reason === "commit_not_on_branch")) {
    return broken(`case-reveal with ${sent} answered HTTP 503 document_unavailable (${json.reason}): the preview's key document is not the ` +
      "one at the commit it names on its published branch, so the preview seals nothing");
  }
  if (ans.status === 503 && json && json.error_code === "case_signer_unavailable") {
    return broken(`case-reveal with ${sent} answered HTTP 503 case_signer_unavailable (${json.reason}): the published case signer is not ` +
      "installed, so the preview seals nothing");
  }
  const why = unlooked(ans);
  if (why) return couldNotLook(`case-reveal with ${sent}: ${why}`);
  return broken(`case-reveal with ${sent} answered ${said(ans)}${ans.status === 201 ? " without a sealed VERDICT for this case" : ", not 201"}`);
}

async function checkSealerPass(ctx) {
  if (!ctx.pinToken) {
    return couldNotLook("the sealer's case pass (lib/_sealer.js anchorCases, as tools/seal_batch.js runs it) reads and writes the pins store " +
      "directly, never through the preview, and needs the pins token: --pin-token was not given");
  }
  const o = await firstOpen(ctx);
  if (!o.caseId) return couldNotLook(`no case was opened on the preview, so no store can be shown to be the preview's: case-open answered ${said(o.ans)}`);
  const store = require("../lib/_store.js");
  const where = `the pins store ${store.REPO}@${store.BRANCH}`;
  const had = Object.prototype.hasOwnProperty.call(process.env, "GITHUB_PIN_TOKEN");
  const before = process.env.GITHUB_PIN_TOKEN;
  process.env.GITHUB_PIN_TOKEN = ctx.pinToken;
  try {
    ctx.log(`(f) ${where}: the case opened on the preview, then the case pass`);
    let got;
    try {
      got = await store.getFile(C.casePath(o.caseId));
    } catch (e) {
      return couldNotLook(`${where} could not be read (${e && e.message})`);
    }
    if (got === null) {
      return couldNotLook(`${where} does not hold case ${o.caseId}, which this run opened on the preview, so it is not the preview's pins ` +
        "store (set GITHUB_PIN_REPO and GITHUB_PIN_BRANCH to the preview's)");
    }
    const doc = S.checkKeyDocument(ctx.keyDocument);
    if (!doc.ok) return couldNotLook(`this checkout's ${S.CASE_KEYS_FILE} does not read (${doc.reason} at ${doc.at}), so the pass could not check a seal's signature`);
    const sealer = require("../lib/_sealer.js");
    const rep = await sealer.anchorCases({ now: new Date(), keyDocument: ctx.keyDocument });
    if (!rep.ok) {
      if (rep.reason === "tree_unreadable") return couldNotLook(`${where}: the case pass could not read the tree (${rep.detail})`);
      return broken(`${where}: the case pass failed (${rep.reason}${rep.detail ? `: ${rep.detail}` : ""})`);
    }
    const summary = `${where}: the case pass read ${rep.read} of ${rep.candidates} candidates (${rep.deferred} deferred): ` +
      `pinned ${rep.newly_pinned.length}, already ${rep.already.length}, pending ${rep.pending.length}, refused ${rep.refused.length}, ` +
      `conflict ${rep.conflict.length}, unreadable ${rep.unreadable.length}, terminal ${rep.terminal.length}, could not look ${rep.could_not_look.length}`;
    const bad = [
      ...rep.refused.map((x) => `refused ${x.case_id} (${x.code})`),
      ...rep.conflict.map((x) => `conflict ${x}`),
      ...rep.unreadable.map((x) => `unreadable ${x}`),
    ];
    if (bad.length) return broken(`${summary}; ${bad.slice(0, 5).join(", ")}${bad.length > 5 ? `, and ${bad.length - 5} more` : ""}`);
    if (rep.truncated) return couldNotLook(`${summary}; the tree came back truncated, so the pass could not see every case`);
    if (!ctx.sealed) return couldNotLook(`${summary}; no case was sealed in (e), so no case of this run shows the pass's pin`);
    const unread = rep.could_not_look.find((x) => x.case_id === ctx.sealed.caseId);
    if (unread) return couldNotLook(`${summary}; the key document case ${ctx.sealed.caseId} names could not be read (${unread.reason}), so the pass did not pin it`);
    const want = ctx.sealed.chain;
    if (typeof want !== "string" || !HEX64.test(want)) return broken(`${summary}; the reveal's chain ${JSON.stringify(want)} is not 64 hex, so no pin can be for it`);
    const st = await S.anchorState(ctx.sealed.caseId, want);
    const by = rep.newly_pinned.includes(ctx.sealed.caseId) ? "pinned by this pass" : "pinned at its reveal";
    // Pinned (or anchored) counts only for the reveal's own chain, read off the pin record.
    const held = st.pin === "pinned" || st.pin === "anchored";
    const pinned = st.record && typeof st.record.chain === "string" ? st.record.chain : null;
    if (held && pinned === want) {
      const anchored = st.pin === "anchored"
        ? `; anchored by ${st.anchor.path}, written at commit ${st.anchor.record_commit.sha} (the anchor's proof is not checked by this tool)`
        : "; not anchored yet";
      return verified(`${summary}; case ${ctx.sealed.caseId} is pinned at commit ${st.pin_commit.sha}, chain ${want} (${by})${anchored}`);
    }
    if (held) {
      return broken(`${summary}; case ${ctx.sealed.caseId} reads ${st.pin} under chain ${JSON.stringify(pinned)}, not the reveal's chain ${want}`);
    }
    const waiting = rep.pending.find((x) => x.case_id === ctx.sealed.caseId);
    if (st.pin === "could_not_look") {
      return couldNotLook(`${summary}; the pin of case ${ctx.sealed.caseId} could not be read (${st.reason})`);
    }
    if (st.pin === "commit_unrecorded" && waiting) {
      return couldNotLook(`${summary}; case ${ctx.sealed.caseId} is not pinned yet (${waiting.reason || "store unreachable"})`);
    }
    if (st.pin === "commit_unrecorded" && !rep.newly_pinned.includes(ctx.sealed.caseId) && rep.deferred > 0) {
      return couldNotLook(`${summary}; case ${ctx.sealed.caseId} is not pinned yet and fell outside this run's window`);
    }
    return broken(`${summary}; case ${ctx.sealed.caseId} reads pin ${st.pin}${st.reason ? ` (${st.reason})` : ""}, not pinned under the reveal's chain`);
  } finally {
    if (had) process.env.GITHUB_PIN_TOKEN = before;
    else delete process.env.GITHUB_PIN_TOKEN;
  }
}

// Every file under `dir` in this checkout, as root-relative "/" paths.
function filesUnder(root, dir) {
  const out = [];
  const walk = (rel) => {
    let entries;
    try {
      entries = fs.readdirSync(path.join(root, ...rel.split("/")), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = `${rel}/${e.name}`;
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

function exposurePaths(root) {
  const dirs = EXPOSED_DIRS.map((d) => [d, filesUnder(root, d)]);
  return { paths: [...EXPOSED_FILES, ...dirs.flatMap(([, f]) => f)], counts: dirs.filter(([, f]) => f.length).map(([d, f]) => `${d}/ ${f.length}`) };
}

async function checkExposure(ctx) {
  const { paths, counts } = exposurePaths(ctx.root);
  ctx.log(`(g) GET ${paths.length} root paths`);
  const results = new Array(paths.length);
  let next = 0;
  const worker = async () => {
    while (next < paths.length) {
      const i = next;
      next += 1;
      const target = `/${paths[i].split("/").map(encodeURIComponent).join("/")}`;
      results[i] = await send(ctx, "GET", target, { timeoutMs: 15000 });
    }
  };
  await Promise.all(Array.from({ length: Math.min(EXPOSURE_CONCURRENCY, paths.length) }, worker));
  // Any answer that arrives and is not a 404 is BROKEN (a 2xx serves the
  // file, a redirect points somewhere, a 403 says it is there); only a
  // request that got no answer at all could not look.
  const answered = [];
  const unanswered = [];
  paths.forEach((p, i) => {
    const r = results[i];
    if (r.error) unanswered.push(`${p} (${r.error})`);
    else if (r.status !== 404) {
      const to = r.headers.location ? ` to ${r.headers.location}` : "";
      answered.push(`${p} (HTTP ${r.status}${to}, ${r.body.length} bytes)`);
    }
  });
  const list = (xs) => `${xs.slice(0, 10).join(", ")}${xs.length > 10 ? `, and ${xs.length - 10} more` : ""}`;
  const asked = `${paths.length} paths (${EXPOSED_FILES.join(", ")}, ${counts.join(", ")})`;
  if (answered.length) return broken(`${answered.length} of ${asked} answered other than 404: ${list(answered)}`);
  if (unanswered.length) return couldNotLook(`${unanswered.length} of ${asked} got no answer: ${list(unanswered)}`);
  return verified(`${asked}: every one answered HTTP 404`);
}

const RUNNERS = Object.freeze({
  a: checkKeyDocument,
  b: checkCasePage,
  c: checkOpenQuota,
  d: checkStampRead,
  e: checkChunkedReveal,
  f: checkSealerPass,
  g: checkExposure,
});

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------
// -> the exit code: 3 if any check COULD NOT LOOK, else 2 if any is BROKEN,
// else 0.
function exitCodeOf(results) {
  if (results.some((r) => r.word === COULD_NOT_LOOK)) return 3;
  if (results.some((r) => r.word === BROKEN)) return 2;
  return 0;
}

// Every secret this run holds, longest first, replaced wherever it appears.
function redactor(secrets) {
  const list = secrets.filter((s) => typeof s === "string" && s.length > 0).sort((x, y) => y.length - x.length);
  return (text) => {
    let out = String(text);
    for (const s of list) out = out.split(s).join("[redacted]");
    return out;
  };
}

// opts: {base, key, bypass, operatorKey, pinToken, exhaustQuota, root,
// vercel, keyDocument, receiptVerifier, stdout(line), stderr(line)}. root
// defaults to this checkout, vercel to its vercel.json, keyDocument to its
// public/.well-known/arcaeon/case-signing-keys.json, parsed (null when it does not
// read), and receiptVerifier to THE RECONCILE VERIFIER read from this
// process's environment (null for none); the CLI never passes another, a
// test may (lib/_case_seal.js's own rule for keyDocument).
// -> {code, results: [{id, title, word, text, line}]}.
async function run(opts) {
  const root = opts.root || ROOT;
  const redact = redactor([opts.key, opts.bypass, opts.operatorKey, opts.pinToken]);
  const stdout = opts.stdout || ((l) => process.stdout.write(`${l}\n`));
  const stderr = opts.stderr || ((l) => process.stderr.write(`${l}\n`));
  let vercel = opts.vercel;
  if (vercel === undefined) {
    try {
      vercel = JSON.parse(fs.readFileSync(path.join(root, "vercel.json"), "utf8"));
    } catch {
      vercel = null;
    }
  }
  let keyDocument = opts.keyDocument;
  if (keyDocument === undefined) {
    try {
      keyDocument = JSON.parse(fs.readFileSync(path.join(root, ...S.CASE_KEYS_FILE.split("/")), "utf8"));
    } catch {
      keyDocument = null;
    }
  }
  const ctx = {
    base: opts.base,
    keyDocument,
    key: opts.key,
    bypass: opts.bypass || null,
    keysDocAnswer: null,
    pinToken: opts.pinToken || null,
    receiptVerifier: opts.receiptVerifier !== undefined ? opts.receiptVerifier : receipts.expectedVerifier(process.env),
    exhaustQuota: opts.exhaustQuota === true,
    root,
    vercel,
    runId: crypto.randomBytes(8).toString("hex"),
    // One registration key per role, for this run only, never printed.
    regKeys: { a: checkpoint.generateKey("preview-dry-run/party-a"), b: checkpoint.generateKey("preview-dry-run/party-b") },
    tapes: loadTapes(root),
    first: null,
    roleA: null,
    sealed: null,
    log: (l) => stderr(redact(`dry run: ${l}`)),
  };
  ctx.log(`preview ${ctx.base}, run ${ctx.runId}, ${ctx.bypass ? "with" : "without"} a protection bypass`);
  // The first request, (a)'s GET (A PROTECTED PREVIEW, above). Vercel's SSO
  // page here means nothing else would be answered either: every check is
  // COULD NOT LOOK and nothing more is asked of the preview.
  ctx.log(`(a) GET /${S.CASE_KEYS_DOC}`);
  ctx.keysDocAnswer = await send(ctx, "GET", `/${S.CASE_KEYS_DOC}`);
  const shut = vercelSso(ctx.keysDocAnswer)
    ? couldNotLook(`${ctx.bypass ? "protected preview, the bypass given was refused" : "protected preview, no bypass given"} ` +
      `(the first request, GET /${S.CASE_KEYS_DOC}, answered HTTP 401 with Vercel's SSO page; ` +
      `${ctx.bypass ? "check the project's Protection Bypass for Automation secret" : `give --bypass or set ${BYPASS_ENV}`})`)
    : null;
  const results = [];
  for (const [id, title] of CHECKS) {
    let r = shut;
    if (!r) {
      try {
        r = await RUNNERS[id](ctx);
      } catch (e) {
        r = couldNotLook(`the check itself failed (${e && e.name}: ${e && e.message})`);
      }
    }
    const line = redact(`${r.word} (${id}) ${title}: ${r.text}`).replace(/[\r\n]+/g, " ");
    stdout(line);
    results.push({ id, title, word: r.word, text: r.text, line });
  }
  return { code: exitCodeOf(results), results };
}

async function main(argv) {
  let a;
  try {
    a = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`usage: ${e.message}\n`);
    return 1;
  }
  if (a.help) {
    process.stdout.write(helpText() + "\n");
    return 0;
  }
  if (!a.base || !a.key) {
    process.stderr.write("usage: --base <preview URL> and --key <issued key> are required (--help for the rest)\n");
    return 1;
  }
  let u;
  try {
    u = new URL(a.base);
  } catch {
    process.stderr.write("usage: --base is not a URL\n");
    return 1;
  }
  if (!["http:", "https:"].includes(u.protocol) || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash || u.username || u.password) {
    process.stderr.write("usage: --base must be the preview's origin, http(s)://host[:port], with no path, query or credentials\n");
    return 1;
  }
  for (const [flag, v] of [["--key", a.key], ["--bypass", a.bypass], ["--operator-key", a.operatorKey], ["--pin-token", a.pinToken]]) {
    if (v !== undefined && !String(v).trim()) {
      process.stderr.write(`usage: ${flag} must not be empty\n`);
      return 1;
    }
  }
  // The flag, else the environment; an empty variable is no bypass.
  const fromEnv = process.env[BYPASS_ENV];
  const bypass = a.bypass !== undefined ? a.bypass : fromEnv && fromEnv.trim() ? fromEnv : undefined;
  const { code } = await run({
    base: u.origin,
    key: a.key,
    bypass,
    operatorKey: a.operatorKey,
    pinToken: a.pinToken,
    exhaustQuota: a.exhaustQuota,
  });
  return code;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (e) => {
    process.stderr.write(`dry run: failed (${e && e.name})\n`);
    process.exit(3);
  });
}
module.exports = { main, run, exitCodeOf, sourceRegex, exposurePaths, vercelSso, CHECKS, QUOTA_PER_DAY, BYPASS_ENV, _internal: { request } };

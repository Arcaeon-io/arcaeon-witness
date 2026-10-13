// test/case_item2b.test.js — the case protocol, item 2b
// (CASE_PROTOCOL_DESIGN_2026-10-10.md, "After item 2a"): the three fixes
// after GPT-5.6's review of 2a, the readers, the case_seal record type,
// signed_by and the published key document, the sealer trigger, and the two
// protocol rules (a key on case-open; the 30-day deadline horizon).
//
//   FIX 1  anchorCase runs the full sealed-receipt check before it pins: a
//          schema-valid VERDICT whose receipt does not bind its reveals is
//          refused verdict_unbound with no pin write (GPT's planted test).
//   FIX 2  signer separation fails closed: a case key that cannot be shown
//          different from the receipt key and the log key seals unsigned,
//          key_separation_unverifiable (GPT's planted test); a separate key
//          with both others present signs.
//   FIX 3  a registration with stamp_commit null cannot reveal:
//          commitment_history_missing, 409, nothing written, no reconcile.
//   READERS  /status skips pins/case as a namespace and counts case anchors
//          in their own row, and a sealed case does not degrade it; the log
//          tree's leaf set is unchanged by a sealed case; the reveal and the
//          seal's header say how a case pin is anchored.
//   CASE_SEAL  the pin's own record type and judge.
//   SIGNED_BY  the key id in the case, and the published key document.
//   SEALER  the sealer's run pins a pending case once; a second run pins
//          nothing; the chain is the seal's.
//   OPEN KEY, HORIZON  decisions 5 and 12.
//
// The fixtures are 2a's (test/case_reveal.test.js): the same reconcile tape
// pair, the same opening, the same party and stamp helpers, repeated here
// because a test file cannot require another test file without running it.
// Each test plants the failure it exists to catch; MUST-FAIL ARMs show the
// wrong behaviour caught by the same check. Every store is the in-memory
// mock: no network.
//
// ITEM 2C CHANGED THIS FILE (test/case_item2c.test.js holds 2c's own tests):
//   - fixture: KEYS_DOC (the committed key document plus the test key) is
//     handed to the reveal, the anchor retry, the sealer and the direct
//     loadCaseSigner calls, because the case key now signs only as an active
//     entry of the key document (fix 2) and the retry checks a stored
//     case's signature against it (fix 1);
//   - expectations, where 2c's rules change the pinned behaviour: the status
//     row is counted from the tree alone (fix 3), so `sealed`, `conflict`,
//     `unreadable`, `read` and `unread` are gone, `withdrawn` is new, and a
//     committed case counts as pending; a damaged case file is no longer
//     read, so it no longer shows as unreadable (both STATUS tests renamed
//     to say so); the sealer's second run keeps the pinned case as a
//     candidate and reads it as already anchored (fix 5); verify.js
//     dispatches six case ops, not three (renamed).
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0003:case-test-";
delete process.env.WITNESS_BATCH_SHADOW;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const T = require("../lib/_reconcile_tapes.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const checkRecord = require("../lib/_check_record.js");
const verdict = require("../lib/_verdict.js");
const logtree = require("../lib/_logtree.js");
const keys = require("../lib/_keys.js");
const stamp = require("../lib/_stamp.js");
const sealer = require("../lib/_sealer.js");
const { gatherStatusData } = require("../lib/_status_data.js");
const statusHandler = require("../api/status.js");
const pinHandler = require("../api/pin.js");
const verifyHandler = require("../api/verify.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const ROOT = path.join(__dirname, "..");
const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z"); // open and register
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-10");
const LOG_ENV = "WITNESS_LOG_SIGNER_KEY";
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, [LOG_ENV]: LOG_KEY.signer });
// Item 2c: the case key signs only as an ACTIVE entry of the key document,
// and the anchor retry checks a stored signature against it; the committed
// document lists no key, so the signing tests hand the seal, the retry and
// the sealer a copy that lists the test key (see test/case_reveal.test.js),
// and, since Design I, the reconcile key as a reconcile entry.
const KEYS_DOC = Object.freeze({ ...S.PUBLISHED_KEYS, keys: [S.keyDocumentEntry(S.loadCaseSigner(SIGNED), { since: "2026-10-10", note: "the test environment's case key" }),
  KD.reconcileEntry(RECEIPT_KEY)] });
const OPEN_KEY = "case-test-open-key-0003";
const OPEN_AUTH = Object.freeze({ authorization: `Bearer ${OPEN_KEY}` });

function pairNamed(re) {
  const c = reconcileFixtures.cases.find((x) => re.test(x.name) && x.python);
  assert.ok(c, String(re));
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
const [AGENT_TAPE, TOOL_TAPE] = pairNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/);

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
function freshIp() {
  ipSeq += 1;
  return `10.77.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function req(op, body, headers) {
  const auth = headers === undefined ? (op === "case-open" ? OPEN_AUTH : {}) : headers;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": freshIp(), ...auth }, body });
}
function parsed(res) {
  return typeof res._body === "string" ? JSON.parse(res._body) : res._body;
}

const AGENT = Object.freeze({ side: "agent", label: "agent-operator@example.com" });
const TOOL = Object.freeze({ side: "tool", label: "tool-operator@example.com" });
function opening(over = {}) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha("the scope manifest both parties agreed"),
    party_a: { ...AGENT },
    party_b: { ...TOOL },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: DEADLINE,
    ...over,
  };
}
function plantStamp(hash, stampedAt = "2026-10-10T07:45:00.123Z") {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: stampedAt });
}
function party(caseId, role, tape, salt = C.newSalt()) {
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function call(handler, op, body, now, headers) {
  const res = makeRes();
  await handler(req(op, body, headers), res, { now });
  return res;
}
async function committedCase({ over } = {}) {
  const o = await call(H.handleCaseOpen, "case-open", opening(over), NOW);
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) {
    plantStamp(p.commitment_sha256);
    const r = await call(H.handleCaseCommit, "case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }), NOW);
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
  assert.equal(storedCase(id).status, "COMMITTED");
  return { id, a, b };
}
function revealBody(id, a, b) {
  return {
    case_id: id,
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    tape_a_b64: a.tape.toString("base64"),
    tape_b_b64: b.tape.toString("base64"),
  };
}
async function reveal(body, { now = REVEAL_AT, env = SIGNED, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
// A sealed case; `pinFails` leaves it sealed with pin: pending.
async function sealedCase({ over, env = SIGNED, pinFails = false } = {}) {
  const c = await committedCase({ over });
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(revealBody(c.id, c.a, c.b), { env });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.pin, pinFails ? "commit_unrecorded" : "pinned");
  return { ...c, r };
}
function storedCase(id) {
  return gh.read(PINS, C.casePath(id));
}
function pinFilesOf(id) {
  return [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`pins/case/${id}/`));
}
function spyReconcile(t) {
  const real = T.reconcileTapes;
  let n = 0;
  T.reconcileTapes = (...args) => {
    n += 1;
    return real(...args);
  };
  t.after(() => {
    T.reconcileTapes = real;
  });
  return () => n;
}
// The judge's input shape: what lib/_store.js getFile returns.
const asRead = (json) => ({ json, sha: "0".repeat(40) });

// =============================================================================
// FIX 1: anchorCase runs the full sealed-receipt check before it pins
// =============================================================================

// A sealed case without its reveal_attempts (a VERDICT may lack them).
function withoutAttempts(k) {
  const { reveal_attempts: _attempts, ...rest } = k; // eslint-disable-line no-unused-vars
  return rest;
}

test("FIX 1: anchorCase refuses a schema-valid VERDICT whose receipt does not bind its reveals (verdict_unbound) and writes no pin", async () => {
  const { id } = await sealedCase({ pinFails: true });
  const good = storedCase(id);
  // unit R-N (E1): with the attempt that sealed it kept, swapped reveals are not even a valid record
  const swapped = { ...good, reveals: { a: { ...good.reveals.a, tape_sha256: good.reveals.b.tape_sha256 }, b: { ...good.reveals.b, tape_sha256: good.reveals.a.tape_sha256 } } };
  assert.deepEqual([C.validateCase(swapped).code, C.validateCase(swapped).field], ["status_inconsistent", "reveal_attempts.0.input_sha256"]);
  assert.deepEqual(pinFilesOf(id), [], "fixture: sealed, no pin yet");
  const R = good.verdict;
  const plants = {
    // the receipt's compared_at is not the reveal time
    compared_at: { ...good, verdict: { ...R, compared_at: "2026-10-10T09:00:01Z" } },
    // the receipt's received-tape digest for tape_a is not role a's committed tape
    tape_a_digest: { ...good, verdict: { ...R, tapes: { ...R.tapes, tape_a: { ...R.tapes.tape_a, digest: `sha256:raw-bytes:v1:${"0".repeat(64)}` } } } },
    // the reveals name the other role's tape: the receipt no longer binds them
    // (with no reveal_attempts: since unit R-N, E1, the attempt that sealed
    // the case binds the reveals too, and the schema refuses the swap first)
    reveals_swapped: { ...withoutAttempts(good), reveals: { a: { ...good.reveals.a, tape_sha256: good.reveals.b.tape_sha256 }, b: { ...good.reveals.b, tape_sha256: good.reveals.a.tape_sha256 } } },
    // a signed receipt altered after signing (a count): bound, but its signature breaks
    receipt_altered: { ...good, verdict: { ...R, verdict: { ...R.verdict, findings: R.verdict.findings + 1 } } },
  };
  const reasons = {};
  for (const [name, bad] of Object.entries(plants)) {
    assert.deepEqual(C.validateCase(bad), { ok: true }, `${name}: fixture is schema-valid`);
    gh.seed(PINS, C.casePath(id), bad);
    const writes = gh.putLog.length;
    const got = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
    assert.equal(got.ok, false, name);
    assert.equal(got.code, "verdict_unbound", `${name}: ${JSON.stringify(got)}`);
    reasons[name] = got.reason;
    assert.equal(gh.putLog.length, writes, `${name}: no write`);
    assert.deepEqual(pinFilesOf(id), [], `${name}: no pin`);
  }
  assert.equal(reasons.compared_at, "receipt_time_mismatch");
  assert.equal(reasons.tape_a_digest, "receipt_tape_a_mismatch");
  assert.equal(reasons.reveals_swapped, "receipt_tape_a_mismatch");
  assert.equal(reasons.receipt_altered, "receipt_bad_signature");
  // MUST-FAIL ARM: the 2a retry judged the schema only, and the schema
  // accepts every plant above, so only the receipt check stands between them
  // and a pin. The binding check alone also misses the altered count.
  for (const bad of Object.values(plants)) assert.equal(C.validateCase(bad).ok, true);
  assert.equal(S.checkSealedReceipt(plants.receipt_altered), null, "the binding alone does not see an altered count");
  // control: the case as sealed anchors
  gh.seed(PINS, C.casePath(id), good);
  const ok = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
  assert.equal(ok.ok, true);
  assert.equal(ok.pin, "pinned");
  assert.equal(ok.chain, S.caseChain(good));
});

// =============================================================================
// FIX 2: signer separation fails closed
// =============================================================================

// The 2a guard, kept here as the MUST-FAIL ARM: it skipped a key it could not see.
function guard2a(env) {
  const k = checkpoint.parseSignerKey(String(env[S.CASE_SIGNER_ENV]).trim());
  for (const name of [LOG_ENV, receipts.SIGNER_ENV]) {
    if (!env[name]) continue;
    const o = checkpoint.parseSignerKey(String(env[name]).trim());
    if (String(env[name]).trim() === String(env[S.CASE_SIGNER_ENV]).trim() || (o.ok && o.pub.equals(k.pub))) return false;
  }
  return true;
}

test("FIX 2: WITNESS_CASE_SIGNER_KEY set to the receipt key's value with WITNESS_RECONCILE_SIGNER_KEY unset is never used to sign, key_separation_unverifiable (since the one signature rule nothing is sealed unsigned)", async () => {
  const env = { [S.CASE_SIGNER_ENV]: RECEIPT_KEY.signer, [LOG_ENV]: LOG_KEY.signer };
  const loaded = S.loadCaseSigner(env);
  assert.equal(loaded.ok, false);
  assert.equal(loaded.code, "key_separation_unverifiable");
  assert.match(loaded.reason, /WITNESS_RECONCILE_SIGNER_KEY is not set/);
  // Since red-team fix B a deployment with no reconcile signer compares
  // nothing, so in this environment the reveal seals nothing at all.
  const c = await committedCase();
  const refused = await reveal(revealBody(c.id, c.a, c.b), { env });
  assert.equal(refused.status, 503, JSON.stringify(refused.body).slice(0, 200));
  assert.equal(refused.body.error_code, "signer_unavailable");
  // unit R-N2 (B2): the body carries a code, never the loader's words
  assert.equal(refused.body.reason, "reconcile_key_unset");
  assert.doesNotMatch(JSON.stringify(refused.body), /WITNESS_|VERCEL_|GITHUB_|is not set/);
  assert.equal(storedCase(c.id).status, "COMMITTED", "never sealed, so never signed with the receipt key");
  // Where separation cannot be shown beside a reconcile signer (the log key
  // unset), the case is never signed: since the one signature rule the
  // reveal seals only signed, so it refuses, and nothing is sealed.
  const u = await committedCase({ over: { scope_digest: sha("log key unset") } });
  const unsep = await reveal(revealBody(u.id, u.a, u.b), { env: { [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer } });
  assert.equal(unsep.status, 503, JSON.stringify(unsep.body).slice(0, 200));
  assert.deepEqual([unsep.body.error_code, unsep.body.reason], ["case_signer_unavailable", "key_separation_unverifiable"]);
  assert.equal(storedCase(u.id).status, "COMMITTED", "never sealed, so never signed");
  const why = S.loadCaseSigner({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer });
  assert.match(why.reason, /WITNESS_LOG_SIGNER_KEY is not set/);
  assert.ok(!JSON.stringify(unsep.body).includes("PRIVATE") && !why.reason.includes(CASE_KEY.verifier.split("+").slice(2).join("+")), "the reason never quotes a key");
  // MUST-FAIL ARM: the 2a guard could not see the receipt key and would have
  // signed the case with it.
  assert.equal(guard2a(env), true);
  // the other ways separation cannot be shown: the log key absent, or present and unparseable
  for (const [name, e, why] of [
    ["log key unset", { [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, /WITNESS_LOG_SIGNER_KEY is not set/],
    ["both unset", { [S.CASE_SIGNER_ENV]: CASE_KEY.signer }, /witness log's key .* or the reconcile receipt key/],
    ["log key unparseable", { ...SIGNED, [LOG_ENV]: "PRIVATE+KEY+nope" }, /WITNESS_LOG_SIGNER_KEY does not parse/],
  ]) {
    const l = S.loadCaseSigner(e);
    assert.equal(l.ok, false, name);
    assert.equal(l.code, "key_separation_unverifiable", name);
    assert.match(l.reason, why, name);
  }
});

test("FIX 2: a legitimately separate case key signs when both other keys are present; one key under another name is still the same key", async () => {
  const loaded = S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC });
  assert.equal(loaded.ok, true);
  assert.equal(loaded.verifier, CASE_KEY.verifier);
  const { id, r } = await sealedCase();
  const k = storedCase(id);
  assert.equal(typeof k.sig, "string");
  assert.equal(k.sig_reason, null);
  // the one signature rule: the sealed check, under the document the case names
  assert.equal((await S.sealedRecordReason(k, KEYS_DOC)).code, "valid_under_document");
  assert.equal(S.caseChain(k), r.body.chain);
  // the log key's bytes under a new name: a different verifier string, the same key
  const seed = Buffer.from(LOG_KEY.signer.split("+").slice(4).join("+"), "base64").subarray(1);
  const pub = checkpoint.parseSignerKey(LOG_KEY.signer).pub;
  const alias = `PRIVATE+KEY+arcaeon.io/case-alias+${checkpoint.keyHash("arcaeon.io/case-alias", pub).toString("hex")}+${Buffer.concat([Buffer.from([1]), seed]).toString("base64")}`;
  assert.equal(checkpoint.parseSignerKey(alias).ok, true, "fixture: the alias parses");
  const refused = S.loadCaseSigner({ ...SIGNED, [S.CASE_SIGNER_ENV]: alias });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, "case_key_is_other_key");
  assert.match(refused.reason, /witness log's key/);
  // and the receipt key itself, with both others present, is refused by name
  const asReceipt = S.loadCaseSigner({ ...SIGNED, [S.CASE_SIGNER_ENV]: RECEIPT_KEY.signer });
  assert.equal(asReceipt.code, "case_key_is_other_key");
  assert.match(asReceipt.reason, /reconcile receipt key/);
});

// =============================================================================
// FIX 3: a registration with stamp_commit null cannot reveal
// =============================================================================

test("FIX 3: a registration with stamp_commit null cannot reveal: 409 commitment_history_missing, nothing written, reconcile never run", async (t) => {
  const runs = spyReconcile(t);
  // A COMMITTED case whose role b registration is in the item-one form
  // (stamp_commit null), planted whole: no handler writes that form any more.
  const kase = C.newCase(C.validateOpening(opening({ scope_digest: sha("item-one registration") })).opening);
  const id = kase.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  const regs = {};
  for (const p of [a, b]) {
    plantStamp(p.commitment_sha256);
    const commit = p.role === "b" ? null : gh.commitsFor(STAMPS, stamp.stampPath(p.commitment_sha256))[0].sha;
    regs[p.role] = C.registrationRecord({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256, registered_at: "2026-10-10T08:00:00Z",
      stamp_commit: commit, stamped_at: "2026-10-10T07:45:00.123Z", ...REG.keyFields({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }) });
    gh.seed(PINS, C.registrationPath(id, p.role), regs[p.role]);
  }
  const committed = { ...kase, commitments: { a: C.commitmentEntry(regs.a), b: C.commitmentEntry(regs.b) }, status: "COMMITTED" };
  assert.deepEqual(C.validateCase(committed), { ok: true }, "fixture: the schema still reads the item-one form");
  gh.seed(PINS, C.casePath(id), committed);
  const writes = gh.putLog.length;
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.ok, false);
  assert.equal(r.body.error_code, "commitment_history_missing");
  assert.equal(r.body.role, "b");
  assert.equal(r.body.verdict, undefined);
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.equal(runs(), 0, "reconcile never run");
  assert.equal(storedCase(id).status, "COMMITTED");
  // MUST-FAIL ARM: the same case with role b's commit filled in reveals.
  const filled = C.registrationRecord({ ...regs.b, stamp_commit: gh.commitsFor(STAMPS, stamp.stampPath(b.commitment_sha256))[0].sha });
  gh.seed(PINS, C.registrationPath(id, "b"), filled);
  gh.seed(PINS, C.casePath(id), { ...committed, commitments: { ...committed.commitments, b: C.commitmentEntry(filled) } });
  const ok = await reveal(revealBody(id, a, b));
  assert.equal(ok.status, 201, JSON.stringify(ok.body).slice(0, 300));
  assert.equal(runs(), 1);
});

// =============================================================================
// THE READERS: /status, the log tree, the anchor sentence
// =============================================================================

// A healthy board: one current namespace, a fresh daily anchor, a reachable store.
function healthyBoard(t) {
  const realReachable = store.repoReachable;
  store.repoReachable = async () => true;
  t.after(() => {
    store.repoReachable = realReachable;
  });
  const now = Date.now();
  gh.seed(PINS, "pins/acme-prod/latest.json", { namespace: "acme-prod", rows: 40, chain: "cafebabe", seq: 1, pinned_at: new Date(now - 60000).toISOString(),
    cadence_hours: 24, next_pin_due_by: new Date(now + 3600e3).toISOString() });
  const day = new Date(now).toISOString().slice(0, 10);
  gh._repoMap(PINS).set(`anchors/${day}-head.txt`, { content: `${"a".repeat(40)} ${new Date(now - 3600e3).toISOString()}\n`, sha: "f".repeat(40) });
}
function verdictOf(d) {
  return { degraded: d.degraded, indeterminate: d.indeterminate, overallOk: d.overallOk, namespaces: d.namespaces, errCount: d.errCount };
}

test("STATUS: a store holding a sealed case does not degrade /status; pins/case is not a namespace; case anchors are their own row (case files, pinned, pending, from the tree)", async (t) => {
  healthyBoard(t);
  const before = await gatherStatusData();
  assert.equal(before.overallOk, true, `fixture: a healthy board (${JSON.stringify(verdictOf(before))})`);
  // item 2c (fix 3): the row is counted from the tree alone
  assert.deepEqual(before.caseAnchors, { case_files: 0, pinned: 0, pending: 0, withdrawn: 0, partial: false });

  const one = await sealedCase();
  const withOne = await gatherStatusData();
  assert.deepEqual(verdictOf(withOne), verdictOf(before), "the sealed case changed nothing in the verdict");
  assert.deepEqual(withOne.namespaces, ["acme-prod"]);
  assert.ok(!withOne.rows.some((r) => r.ns === "case"), "no namespace row for pins/case");
  assert.equal(withOne.caseAnchors.case_files, 1);
  assert.equal(withOne.caseAnchors.pinned, 1);
  assert.equal(withOne.caseAnchors.pending, 0);

  // a second, pending case and a committed (unsealed) one
  await sealedCase({ over: { scope_digest: sha("pending one") }, pinFails: true });
  await committedCase({ over: { scope_digest: sha("committed only") } });
  const withThree = await gatherStatusData();
  assert.deepEqual(verdictOf(withThree), verdictOf(before), "a pending anchor changes nothing in the verdict either");
  assert.equal(withThree.caseAnchors.case_files, 3);
  assert.equal(withThree.caseAnchors.pinned, 1);
  // item 2c (fix 3): by the tree alone the committed case and the sealed one
  // waiting for its pin are both pending (both registration files, no pin)
  assert.equal(withThree.caseAnchors.pending, 2);
  assert.equal(withThree.caseAnchors.withdrawn, 0);

  // the page and the JSON twin say the same
  const html = makeRes();
  await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": freshIp() } }), html);
  const page = String(html._body);
  assert.equal(html._status, 200);
  assert.match(page, /<h2>Case seals<\/h2>/);
  assert.ok(page.includes("not as a log-tree leaf"), "the anchor sentence is on the page");
  assert.match(page, /badge-green" style="font-size:\.95rem">OK</);
  const json = makeRes();
  await statusHandler(makeReq({ method: "GET", query: { format: "json" }, headers: { "x-forwarded-for": freshIp() } }), json);
  const j = parsed(json);
  assert.equal(j.status, "ok");
  assert.deepEqual([j.case_anchors.case_files, j.case_anchors.pinned, j.case_anchors.pending], [3, 1, 2]);
  assert.equal(j.case_anchors.feeds_status, false);
  assert.ok(!j.namespaces.some((n) => n.namespace === "case"));

  // MUST-FAIL ARM: the pins listing does hold a "case" directory, and read as
  // a namespace it has no latest.json, which the 2a status code turned into
  // an error row (degraded). Its records are refused by the generic judge too.
  const listed = await store.listDir("pins");
  assert.ok(listed.some((e) => e.name === "case" && e.type === "dir"), "the listing shows pins/case");
  assert.equal(await store.getFile("pins/case/latest.json"), null);
  const casePin = await store.getFile(S.pinPaths(one.id).latest);
  assert.equal(verdict.judgePin(casePin, { what: "x", namespace: S.pinNamespace(one.id) }).reason, "case_seal_not_a_generic_pin");
});

test("STATUS: a damaged case file changes nothing in the case row, which reads no case file; a tree that cannot be read is shown as not counted; neither feeds a verdict; nothing is read when no case exists", async (t) => {
  healthyBoard(t);
  const base = verdictOf(await gatherStatusData());
  const reads = gh.getLog.length;
  await gatherStatusData();
  assert.ok(!gh.getLog.slice(reads).some((p) => p.startsWith("cases/") || p.startsWith("pins/case/")), "no case read without a case");
  const { id } = await sealedCase();
  gh.seed(PINS, C.casePath(id), { ...storedCase(id), anchor: "pending" });
  const before = gh.getLog.length;
  const d = await gatherStatusData();
  // item 2c (fix 3): the row never reads the case file, so the damage is not
  // seen here; by path the case is anchored (both registrations and a pin)
  assert.ok(!gh.getLog.slice(before).some((p) => p.startsWith("cases/") || p.startsWith("pins/case/")), "no case file or case pin read");
  assert.equal(d.caseAnchors.pinned, 1);
  assert.deepEqual(verdictOf(d), base);
  // the tree unreadable: the conflicts are uncounted (indeterminate, as
  // before) and the case row says it was not counted, never zero
  gh.treeStatus = 502;
  const d2 = await gatherStatusData();
  assert.equal(d2.caseAnchors, null);
  assert.match(d2.caseErr, /could not be read/);
  assert.equal(d2.indeterminate, true, "the uncounted conflicts make it indeterminate, as before 2b");
});

test("LOG TREE: a sealed case and its pin add no leaf to the witness log tree v1; the reveal and the seal's header say how a case is pinned and anchored", async () => {
  // a generic pin, so the leaf set is not empty
  const p = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: `Bearer ${OPEN_KEY}` }, body: { namespace: "case-test-log", rows: 5, chain: "abcdef01" } }), p);
  assert.equal(p._status, 201, JSON.stringify(p._body));
  const leaves = () => [...gh.repos.get(PINS).keys()].filter((x) => logtree.kindOfPath(x)).sort();
  const before = leaves();
  assert.deepEqual(before, ["pins/case-test-log/00000001.json"]);
  const { id, r } = await sealedCase();
  const after = leaves();
  assert.deepEqual(after, before, "the leaf set is unchanged by a sealed case");
  const casePaths = [...gh.repos.get(PINS).keys()].filter((x) => x.startsWith("cases/") || x.startsWith("pins/case/"));
  assert.ok(casePaths.includes(S.pinPaths(id).seq) && casePaths.includes(C.casePath(id)), "fixture: the case and its pin are in the repo");
  for (const x of casePaths) assert.equal(logtree.kindOfPath(x), null, x);
  // MUST-FAIL ARM: a widened v1 pin pattern would take the case pin as a
  // leaf, which would move every later position.
  const widened = /^pins\/.+\/[0-9]{8}\.json$/;
  assert.ok(widened.test(S.pinPaths(id).seq));

  // the sentence, in the reveal's answer and in lib/_case_seal.js's header
  assert.equal(r.body.anchor_note, S.ANCHOR_NOTE);
  assert.match(S.ANCHOR_NOTE, /pinned by the pins-repository commit that writes its pin, and anchored only when a daily anchor record names a head .* not as a log-tree leaf/);
  const header = fs.readFileSync(path.join(ROOT, "lib", "_case_seal.js"), "utf-8").replace(/\r\n/g, "\n").split("\n").filter((l) => l.startsWith("//")).map((l) => l.replace(/^\/\/ ?/, "")).join(" ");
  assert.match(header.replace(/\s+/g, " "), /a case is pinned by the pins-repository commit that writes its pin, and anchored only when a daily anchor record names a head that holds that pin \(THE ANCHOR WORDS, below\), not as a log-tree leaf/);
});

// =============================================================================
// THE case_seal RECORD TYPE
// =============================================================================

test("CASE_SEAL: the seal's pin is exactly the case_seal record type; an extra field, a missing record_kind or a wrong value is refused; the generic judge takes none of it, and the case judge takes no generic pin", async () => {
  const { id } = await sealedCase();
  const { ns, seq, latest } = S.pinPaths(id);
  const rec = gh.read(PINS, latest);
  assert.deepEqual(Object.keys(rec).sort(), [...verdict.CASE_SEAL_FIELDS, "case_commit"].sort(), "Design J: every pin since names the commit that wrote the case file");
  assert.deepEqual(gh.read(PINS, seq), rec);
  const ok = verdict.judgeCaseSeal(asRead(rec), { what: latest, namespace: ns });
  assert.equal(ok.ok, true, JSON.stringify(ok));
  assert.equal(verdict.judgeCaseSeal(asRead(S._internal.pinRecord(id, "1".repeat(64), REVEAL_AT)), { namespace: ns }).ok, true, "pinRecord builds the type");

  const without = (k) => {
    const o = { ...rec };
    delete o[k];
    return o;
  };
  const plants = {
    case_seal_unknown_field: [{ ...rec, next_pin_due_by: "2026-10-11T09:00:00.000Z" }, { ...rec, cadence_hours: 24 }, { ...rec, intent: "renew" }],
    case_seal_missing_field: [without("record_kind"), without("auth_level"), without("auth_note"), without("pinned_at")],
    case_seal_wrong_record_kind: [{ ...rec, record_kind: "content_head_advance" }, { ...rec, record_kind: "publisher_heartbeat" }],
    case_seal_wrong_auth_level: [{ ...rec, auth_level: "bearer-stage0" }],
    case_seal_wrong_rows: [{ ...rec, rows: 4 }, { ...rec, rows: "3" }],
    case_seal_wrong_seq: [{ ...rec, seq: 0 }, { ...rec, seq: "1" }, { ...rec, seq: 100000000 }], // Design J: seq 2 and on are a case's next pins
    case_seal_namespace_unreadable: [{ ...rec, namespace: "acme-prod" }, { ...rec, namespace: `case/${id.toUpperCase()}` }],
    namespace_mismatch: [{ ...rec, namespace: `case/${"9".repeat(64)}` }],
    chain_unreadable: [{ ...rec, chain: rec.chain.toUpperCase() }, { ...rec, chain: "abcdef01" }],
    case_seal_pinned_at_unreadable: [{ ...rec, pinned_at: "2026-10-10T09:00:00Z" }, { ...rec, pinned_at: "soon" }],
    case_seal_auth_note_unreadable: [{ ...rec, auth_note: " " }, { ...rec, auth_note: 7 }],
  };
  for (const [reason, recs] of Object.entries(plants)) {
    for (const bad of recs) {
      const v = verdict.judgeCaseSeal(asRead(bad), { what: latest, namespace: ns });
      assert.equal(v.ok, false, `${reason}: ${JSON.stringify(bad).slice(0, 120)}`);
      assert.equal(v.reason, reason, `${reason}: got ${v.reason}`);
    }
  }
  // the generic judge refuses a case seal, by its kind or by its namespace
  assert.equal(verdict.judgePin(asRead(rec), { namespace: ns }).reason, "case_seal_not_a_generic_pin");
  assert.equal(verdict.judgePin(asRead(without("record_kind")), {}).reason, "case_seal_not_a_generic_pin");
  assert.equal(verdict.judgePin(asRead({ ...rec, namespace: "acme-prod" }), { namespace: "acme-prod" }).reason, "case_seal_not_a_generic_pin");
  // a generic pin, as api/pin.js writes one: the generic judge takes it, the case judge does not
  const p = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: `Bearer ${OPEN_KEY}` }, body: { namespace: "case-test-generic", rows: 9, chain: "0123abcd" } }), p);
  assert.equal(p._status, 201, JSON.stringify(p._body));
  const generic = await store.getFile("pins/case-test-generic/latest.json");
  assert.equal(verdict.judgePin(generic, { namespace: "case-test-generic" }).ok, true, "control: the generic judge reads a generic pin");
  const asSeal = verdict.judgeCaseSeal(generic, {});
  assert.equal(asSeal.ok, false, "a generic pin is not judged by the case judge");
  assert.equal(asSeal.reason, "case_seal_unknown_field");
  // and the bare namespace "case" can never be pinned, so pins/case/ holds case seals only
  const reserved = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: `Bearer ${OPEN_KEY}` }, body: { namespace: "case", rows: 1, chain: "0123abcd" } }), reserved);
  assert.equal(reserved._status, 400);
  assert.match(reserved._body.error, /reserved/);
  assert.equal(store.validatePin({ namespace: "case", rows: 1, chain: "0123abcd" }) !== null, true);
  assert.equal(store.validatePin({ namespace: "case-x", rows: 1, chain: "0123abcd" }), null, "control: only the bare name is reserved");
});

// =============================================================================
// SIGNED_BY and the published key document
// =============================================================================

test("SIGNED_BY: the reveal writes the case signer's key id inside the signed bytes; an unsigned record and an open case carry null; the schema refuses a mismatch", async () => {
  const keyId = CASE_KEY.verifier.split("+").slice(0, 2).join("+");
  const vk = checkpoint.parseVerifierKey(CASE_KEY.verifier);
  assert.equal(keyId, `${vk.name}+${vk.hash}`, "fixture: lib/_checkpoint.js's key naming");
  const o = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("open signed_by") }), NOW);
  assert.equal(o._body.case.signed_by, null, "an open case is unsigned");
  const { id, r } = await sealedCase();
  const k = storedCase(id);
  assert.equal(k.signed_by, keyId);
  assert.ok(checkRecord.preimage(k).toString("utf-8").includes(`"signed_by":"${keyId}"`), "inside the signed bytes");
  assert.equal(r.body.case.signed_by, keyId);
  assert.equal((await S.sealedRecordReason(k, KEYS_DOC)).code, "valid_under_document");
  assert.equal(S.caseChain(k), r.body.chain);
  // altering signed_by breaks the signature (it is signed), and a case signed
  // by the right key that names another is refused as a signer mismatch
  assert.equal(S.signatureReason({ ...k, signed_by: "arcaeon.io/other+12345678" }, CASE_KEY.verifier).reason, "bad_signature");
  const lying = S.signCase({ ...k, sig: null, sig_reason: null }, { ...S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC }), keyId: "arcaeon.io/other+12345678" });
  assert.equal(S.signatureReason(lying, CASE_KEY.verifier).reason, "signer_mismatch");
  // an unsigned record carries null (built the seal module's way: since the
  // one signature rule the reveal itself never seals unsigned)
  const unsigned = S.signRecord({ ...k, signed_by: null, sig: null, sig_reason: null }, S.loadCaseSigner({ [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }),
    "This case is sealed and not signed");
  assert.equal(unsigned.signed_by, null);
  assert.match(unsigned.sig_reason, /\(case_key_unset\)/);
  // the schema: signed with no key id, a key id with no signature, a malformed key id
  assert.equal(C.validateCase({ ...k, signed_by: null }).code, "malformed_field");
  assert.equal(C.validateCase({ ...unsigned, signed_by: keyId }).code, "malformed_field");
  for (const badId of ["no-plus-here", "name+1234567", "name+ABCDEF12", "two words+12345678", `${CASE_KEY.verifier}`]) {
    assert.equal(C.validateCase({ ...k, signed_by: badId }).field, "signed_by", badId);
  }
  const { signed_by, ...missing } = k; // eslint-disable-line no-unused-vars
  assert.equal(C.validateCase(missing).code, "missing_field");
  assert.ok(C.TOP_LEVEL_FIELDS.includes("signed_by"));
});

test("KEY DOCUMENT: .well-known/arcaeon/case-signing-keys.json is valid JSON with the required fields, served the snapshot keys' way; an entry for the seal's key is what the seal signs with", async () => {
  const file = path.join(ROOT, ...S.CASE_KEYS_FILE.split("/"));
  assert.equal(S.CASE_KEYS_DOC, ".well-known/arcaeon/case-signing-keys.json", "where the domain serves it");
  assert.equal(S.CASE_KEYS_FILE, "public/.well-known/arcaeon/case-signing-keys.json", "where it is committed");
  const text = fs.readFileSync(file, "utf-8");
  const doc = JSON.parse(text);
  const checked = S.checkKeyDocument(doc);
  assert.equal(checked.ok, true, JSON.stringify(checked));
  assert.equal(doc.schema, "arcaeon-signing-keys/1", "the snapshot keys' schema");
  assert.ok(Array.isArray(doc.keys));
  for (const e of doc.keys) for (const f of ["key_id", "verifier", "since", "note"]) assert.ok(Object.prototype.hasOwnProperty.call(e, f), f);
  // Served as a static file, as favicon.svg is, not a function under api/:
  // public/ is vercel.json's declared outputDirectory (README "Deploy
  // shape"), and nothing of it is left at the repository root.
  assert.equal(JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf-8")).outputDirectory, "public");
  assert.ok(fs.existsSync(path.join(ROOT, "public", "favicon.svg")));
  assert.equal(fs.existsSync(path.join(ROOT, ".well-known")), false);

  // In the test environment: the entry the document carries for the seal's
  // key is exactly the key the seal names and signs with.
  const signer = S.loadCaseSigner(SIGNED);
  const entry = S.keyDocumentEntry(signer, { since: "2026-10-10", note: "the test environment's case key" });
  const withKey = { ...doc, keys: [...doc.keys, entry] };
  assert.equal(S.checkKeyDocument(withKey).ok, true);
  const { id } = await sealedCase();
  const k = storedCase(id);
  const found = S.publishedEntry(withKey, k.signed_by);
  assert.deepEqual(found, entry);
  assert.equal(found.verifier, CASE_KEY.verifier);
  assert.equal(S.signatureReason(k, found.verifier), null);
  assert.equal(S.publishedEntry(doc, k.signed_by), null, "the test key is not in the committed document");

  // MUST-FAIL ARMs: a document the checker refuses
  const bad = {
    key_id_mismatch: { ...doc, keys: [{ ...entry, key_id: "arcaeon.io/other+12345678" }] },
    missing_field: { ...doc, keys: [{ key_id: entry.key_id, verifier: entry.verifier, since: entry.since, status: "active" }] },
    unknown_field: { ...doc, keys: [{ ...entry, private_key: "never" }] },
    bad_verifier: { ...doc, keys: [{ ...entry, verifier: "not+a+verifier" }] },
    duplicate_key_id: { ...doc, keys: [entry, entry] },
    wrong_schema: { ...doc, schema: "arcaeon-signing-keys/0" },
  };
  for (const [reason, d] of Object.entries(bad)) assert.equal(S.checkKeyDocument(d).reason, reason, reason);
  const { keys: _k, ...noKeys } = doc; // eslint-disable-line no-unused-vars
  assert.equal(S.checkKeyDocument(noKeys).reason, "missing_field");
});

test("KEY DOCUMENT, THIS ENVIRONMENT: the case key configured where the suite runs is an active entry of the committed document",
  { skip: process.env.WITNESS_CASE_SIGNER_KEY ? false : "WITNESS_CASE_SIGNER_KEY is not set where the suite runs (no case key provisioned here), so there is no configured key to look up" },
  () => {
    const doc = JSON.parse(fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")), "utf-8"));
    const k = checkpoint.parseSignerKey(String(process.env.WITNESS_CASE_SIGNER_KEY).trim());
    assert.equal(k.ok, true, "the configured case key parses");
    const e = S.publishedEntry(doc, `${k.name}+${k.hash}`);
    assert.ok(e, "the configured case key is listed in .well-known/arcaeon/case-signing-keys.json");
    assert.equal(e.status, "active");
    assert.equal(e.verifier, S._internal.verifierOf(k));
  });

// =============================================================================
// THE SEALER: anchorCase runs from the sealer's run
// =============================================================================

test("SEALER: a sealer run with one pending case pins it once; a second run pins nothing new; the chain is the seal's", async () => {
  const { id, r } = await sealedCase({ pinFails: true });
  const sealed = storedCase(id);
  const chain = r.body.chain;
  assert.equal(chain, S.caseChain(sealed));
  // MUST-FAIL ARM: without a trigger the case stays pending (2a)
  assert.deepEqual(await S.anchorState(id, chain), { pin: "commit_unrecorded", reason: "not_pinned" });

  const writes = gh.putLog.length;
  const run1 = await sealer.sealOnce({ now: new Date(REVEAL_AT + 120000), keyDocument: KEYS_DOC });
  assert.equal(run1.reason, "no_open_batch", "the batch pass is what it was");
  assert.equal(run1.cases.ok, true, JSON.stringify(run1.cases));
  assert.deepEqual(run1.cases.newly_pinned, [id]);
  assert.equal(run1.cases.candidates, 1);
  const pinWrites = gh.putLog.slice(writes).map((w) => w.path);
  assert.deepEqual(pinWrites, [S.pinPaths(id).seq, S.pinPaths(id).latest], "the pin's two writes and nothing else");
  const pinned = gh.read(PINS, S.pinPaths(id).latest);
  assert.equal(pinned.chain, chain);
  assert.equal(pinned.pinned_at, new Date(REVEAL_AT + 120000).toISOString());
  assert.deepEqual(storedCase(id), sealed, "the sealed case is untouched");

  const run2 = await sealer.sealOnce({ now: new Date(REVEAL_AT + 180000), keyDocument: KEYS_DOC });
  assert.equal(run2.cases.ok, true);
  // item 2c (fix 5): a pinned case stays in the window and its pin is judged
  assert.equal(run2.cases.candidates, 1);
  assert.equal(run2.cases.pinned, 1);
  assert.deepEqual(run2.cases.already, [id]);
  assert.deepEqual(run2.cases.newly_pinned, []);
  assert.equal(gh.putLog.length, writes + 2, "nothing new");
  assert.equal(gh.read(PINS, S.pinPaths(id).latest).chain, chain, "the chain is identical");
  assert.deepEqual((await S.anchorState(id, chain)).pin, "pinned");
});

test("SEALER: a committed case is passed over, an unbound verdict is refused, a tree it cannot read is reported; none writes, and the batch receipt stands", async () => {
  await committedCase({ over: { scope_digest: sha("only committed") } });
  const bad = await sealedCase({ over: { scope_digest: sha("unbound") }, pinFails: true });
  const k = storedCase(bad.id);
  gh.seed(PINS, C.casePath(bad.id), { ...k, verdict: { ...k.verdict, compared_at: "2026-10-10T09:00:01Z" } });
  const writes = gh.putLog.length;
  const run = await sealer.sealOnce({ now: new Date(REVEAL_AT + 60000), keyDocument: KEYS_DOC });
  assert.equal(run.cases.ok, true);
  assert.equal(run.cases.candidates, 2);
  assert.equal(run.cases.not_sealed, 1);
  assert.deepEqual(run.cases.refused, [{ case_id: bad.id, code: "verdict_unbound", reason: "receipt_time_mismatch" }]);
  assert.equal(gh.putLog.length, writes);
  gh.treeStatus = 502;
  const blind = await sealer.sealOnce({ now: new Date(REVEAL_AT + 120000), keyDocument: KEYS_DOC });
  assert.equal(blind.reason, "no_open_batch");
  assert.equal(blind.cases.ok, false);
  assert.equal(blind.cases.reason, "tree_unreadable");
  assert.equal(gh.putLog.length, writes);
});

test("SEALER: with more pending cases than one run reads, the window moves on each minute and every case is pinned", async () => {
  const ids = [];
  for (let i = 0; i < 3; i += 1) ids.push((await sealedCase({ over: { scope_digest: sha(`window ${i}`) }, pinFails: true })).id);
  const pinnedNow = new Set();
  for (let minute = 0; minute < 3; minute += 1) {
    const out = await S.anchorPending({ now: REVEAL_AT + 60000 * (minute + 1), maxReads: 1, keyDocument: KEYS_DOC });
    assert.equal(out.read, 1);
    for (const id of out.newly_pinned) pinnedNow.add(id);
  }
  assert.deepEqual([...pinnedNow].sort(), ids.slice().sort(), "each pinned within ceil(3 / 1) runs");
  // the window itself
  const W = S._internal.rotatingWindow;
  const five = ["a", "b", "c", "d", "e"];
  const seen = new Set();
  for (let m = 0; m < 3; m += 1) for (const x of W(five, 2, m * 60000)) seen.add(x);
  assert.equal(seen.size, 5);
  assert.deepEqual(W(["a", "b"], 5, 0), ["a", "b"]);
});

test("SEALER: no public op writes a pin; verify.js dispatches exactly the six case ops", async () => {
  const src = fs.readFileSync(path.join(ROOT, "api", "verify.js"), "utf-8");
  const ops = [...src.matchAll(/op === "(case-[a-z-]+)"/g)].map((m) => m[1]).sort();
  // item 2c adds case-withdraw, case-reference and case-page; none of them pins
  assert.deepEqual(ops, ["case-commit", "case-open", "case-page", "case-reference", "case-reveal", "case-withdraw"]);
  const { id } = await sealedCase({ pinFails: true });
  const writes = gh.putLog.length;
  for (const op of ["case-anchor", "case-pin", "case-page"]) {
    for (const method of ["GET", "POST"]) {
      const res = makeRes();
      await verifyHandler(makeReq({ method, query: { op, case_id: id }, headers: { "x-forwarded-for": freshIp() } }), res);
      assert.notEqual(res._status, 201, `${method} ?op=${op}`);
    }
  }
  assert.equal(gh.putLog.length, writes, "no public request pinned it");
  assert.deepEqual(pinFilesOf(id), []);
});

// =============================================================================
// THE TWO PROTOCOL RULES: a key on case-open, the 30-day horizon
// =============================================================================

test("OPEN KEY: case-open needs a valid bearer key: none is 401 key_required, an unknown or revoked one 401 key_invalid, a store failure 503; nothing is written and the case records nothing of the key", async () => {
  const issued = "wk_" + "1".repeat(48);
  const revoked = "wk_" + "2".repeat(48);
  gh.seed(USAGE, keys.issuedKeyPath(keys.keyHash(issued)), { namespace_prefix: "wk-case-test-", plan: "free", org: null, pool_id: "p" });
  gh.seed(USAGE, keys.issuedKeyPath(keys.keyHash(revoked)), { namespace_prefix: "wk-case-test2-", revoked: true });
  const writes = gh.putLog.length;
  const refusals = [
    ["no header", {}, 401, "key_required"],
    ["not bearer", { authorization: `Basic ${OPEN_KEY}` }, 401, "key_required"],
    ["empty bearer", { authorization: "Bearer " }, 401, "key_required"],
    ["unknown key", { authorization: "Bearer wk_not_a_key_anyone_was_issued" }, 401, "key_invalid"],
    ["revoked issued key", { authorization: `Bearer ${revoked}` }, 401, "key_invalid"],
  ];
  for (const [name, headers, status, code] of refusals) {
    const res = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha(name) }), NOW, headers);
    assert.equal(res._status, status, `${name}: ${JSON.stringify(res._body)}`);
    assert.equal(res._body.ok, false);
    assert.equal(res._body.error_code, code, name);
    assert.match(String(res._headers["www-authenticate"]), /^Bearer /, name);
  }
  // the key comes before the body: no key and a malformed body is still 401
  const early = await call(H.handleCaseOpen, "case-open", { not: "an opening" }, NOW, {});
  assert.equal(early._status, 401);
  // the issued-key store unreadable: 503, never a 401
  const inner = global.fetch;
  global.fetch = async (url, o) => (String(url).includes(`/repos/${USAGE}/contents/keys/`)
    ? { status: 500, ok: false, json: async () => ({}), text: async () => "down" } : inner(url, o));
  let down;
  try {
    down = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("store down") }), NOW, { authorization: "Bearer wk_some_key" });
  } finally {
    global.fetch = inner;
  }
  assert.equal(down._status, 503);
  assert.equal(down._body.error_code, "key_store_unreachable");
  assert.equal(gh.putLog.length, writes, "no refusal wrote anything");

  // MUST-FAIL ARM: the same openings with a valid key are accepted, an env
  // key and an issued key alike, so the refusals above were the key's
  for (const [name, auth] of [["env key", OPEN_AUTH], ["issued key", { authorization: `Bearer ${issued}` }]]) {
    const ok = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha(`ok ${name}`) }), NOW, auth);
    assert.equal(ok._status, 201, `${name}: ${JSON.stringify(ok._body)}`);
    const text = JSON.stringify(storedCase(ok._body.case_id));
    for (const secret of [OPEN_KEY, issued, keys.keyHash(issued), keys.keyHash(OPEN_KEY)]) assert.ok(!text.includes(secret), `${name}: the case records nothing of the key`);
    assert.deepEqual(Object.keys(storedCase(ok._body.case_id)).sort(), [...C.TOP_LEVEL_FIELDS].sort());
  }
  // and through the real verify.js dispatch
  const viaVerify = makeRes();
  await verifyHandler(req("case-open", opening({ scope_digest: sha("via verify") }), {}), viaVerify);
  assert.equal(viaVerify._status, 401);
  assert.equal(viaVerify._body.error_code, "key_required");
  // registration and the reveal stay keyless
  const { id, a, b } = await committedCase({ over: { scope_digest: sha("keyless rest") } });
  assert.equal((await reveal(revealBody(id, a, b))).status, 201);
});

test("HORIZON: a deadline more than 30 days after opened_at is refused deadline_too_far at open; exactly 30 days is accepted", async () => {
  const at = "2026-10-10T07:30:00Z";
  const plus = (s) => new Date(Date.parse(at) + s * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const day30 = 30 * 86400;
  const writes = gh.putLog.length;
  for (const deadline of [plus(day30 + 1), plus(day30 + 86400), "2026-11-09T09:30:01+02:00", "2027-10-10T07:30:00Z"]) {
    const res = await call(H.handleCaseOpen, "case-open", opening({ deadline, scope_digest: sha(`far ${deadline}`) }), NOW);
    assert.equal(res._status, 400, `${deadline}: ${JSON.stringify(res._body)}`);
    assert.equal(res._body.error_code, "deadline_too_far", deadline);
    assert.equal(res._body.field, "deadline");
  }
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.throws(() => C.validateOpening(opening({ deadline: plus(day30 + 1) })), (e) => e instanceof C.CaseError && e.code === "deadline_too_far");
  // exactly thirty days, and thirty days written with an offset, are accepted
  for (const deadline of [plus(day30), "2026-11-09T09:30:00+02:00"]) {
    const ok = await call(H.handleCaseOpen, "case-open", opening({ deadline, scope_digest: sha(`at ${deadline}`) }), NOW);
    assert.equal(ok._status, 201, `${deadline}: ${JSON.stringify(ok._body)}`);
    assert.equal(ok._body.case.deadline, plus(day30));
  }
  assert.equal(C.MAX_DEADLINE_DAYS, 30);
  // MUST-FAIL ARM: by the rules before 2b (later than opened_at, not yet
  // passed by this service's clock) the far opening was acceptable.
  const far = plus(day30 + 1);
  assert.ok(Date.parse(far) > Date.parse(at) && Date.parse(far) > NOW);
});

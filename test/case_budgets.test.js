// test/case_budgets.test.js — what spends which budget on the case ops.
//
// FIX F (2026-10-12; GPT-5.6 §1.5, test/case_redteam.test.js): ?op=case-open
// reads its bearer key BEFORE any rate budget is spent. A valid key draws on
// its own bucket (lib/_ratelimit.js checkKey), never its address's; anything
// else (no key, a key that is not valid) draws on the per-IP bucket and past
// it is 429 before its 401. The keyless ops stay per-IP.
// THE OPERATOR'S BEARER (2026-10-12, the same shape on ?op=case-reference):
// a request carrying WITNESS_CASE_OPERATOR_KEY's bearer draws on that key's
// own budget, never its address's; any other reference draws on the per-IP
// budget, and past it is 429 before its 401 or 503.
// FIX G (2026-10-12; GPT-5.6 §2C): a role appends at most
// REFERENCE_QUOTA_PER_ROLE rows to one case (the open quota's 20), counted
// in the private usage repository; past it, 409 reference_quota with the
// count. The roles count apart, and the operator takes no unit.
// Every store is the in-memory mock; every budget is the process's limiter,
// fresh for each test (test/helpers/mock_store.js install).
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0031:case-test-,case-test-open-key-0032:case-test2-";
delete process.env.WITNESS_BATCH_SHADOW;
delete process.env.WITNESS_ADMIN_KEY;
delete process.env.WITNESS_CASE_OPERATOR_KEY;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const ratelimit = require("../lib/_ratelimit.js");
const S = require("../lib/_case_seal.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const KEY = "case-test-open-key-0031";
const OTHER_KEY = "case-test-open-key-0032";
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const bearer = (k) => ({ authorization: `Bearer ${k}` });

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
  return `10.75.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function opening(over = {}) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha("the scope manifest both parties agreed"),
    party_a: { side: "agent", label: "agent-operator@example.com" },
    party_b: { side: "tool", label: "tool-operator@example.com" },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: "2026-10-10T20:00:00Z",
    ...over,
  };
}
async function call(handler, op, body, { headers = {}, ip = freshIp(), now = NOW } = {}) {
  const res = makeRes();
  await handler(makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": ip, ...headers }, body }), res, { now });
  return res;
}
const open = (over, o) => call(H.handleCaseOpen, "case-open", opening(over), o);
// A body the schema refuses (400) after admit() has let it in: spends one unit, writes nothing.
const spend = (handler, op, o) => call(handler, op, { not: "a case body" }, o);

// =============================================================================
// FIX F: the key first, then the budget it draws on
// =============================================================================

test("FIX F: a valid key's opens draw on the key's own budget: from one address, its LIMIT+1th is 429 with the per-key note, while that address's budget and another key's stay unspent", async () => {
  const ip = freshIp();
  for (let i = 0; i < ratelimit.LIMIT; i += 1) {
    const r = await spend(H.handleCaseOpen, "case-open", { headers: bearer(KEY), ip });
    assert.equal(r._status, 400, `keyed call ${i + 1}: ${JSON.stringify(r._body)}`);
  }
  const over = await open({ scope_digest: sha("past the key's budget") }, { headers: bearer(KEY), ip: freshIp() });
  assert.equal(over._status, 429, JSON.stringify(over._body));
  assert.equal(over._body.error_code, "rate_limited");
  assert.match(over._body.note, /^per-key limiter: ~30 calls per key per 10 minutes/);
  assert.ok(Number(over._headers["retry-after"]) > 0);
  assert.equal(gh.putLog.length, 0, "nothing written");
  // the key's budget is the key's alone: not the address's, not another key's
  const other = await open({ scope_digest: sha("another key, same address") }, { headers: bearer(OTHER_KEY), ip });
  assert.equal(other._status, 201, JSON.stringify(other._body));
  const bare = await open({ scope_digest: sha("no key, same address") }, { headers: {}, ip });
  assert.equal(bare._status, 401, `the keyed calls spent nothing of the address's budget: ${JSON.stringify(bare._body)}`);
  assert.equal(bare._body.error_code, "key_required");
});

test("FIX F: an open whose key is not valid draws on the address's budget, and past it is 429 (the per-IP note) before its 401; a valid key from that address still opens", async () => {
  const ip = freshIp();
  for (let i = 0; i < ratelimit.LIMIT; i += 1) {
    const r = await open({ scope_digest: sha(`bad key ${i}`) }, { headers: bearer(`${KEY}x`), ip });
    assert.equal(r._status, 401, JSON.stringify(r._body));
    assert.equal(r._body.error_code, "key_invalid");
  }
  const over = await open({ scope_digest: sha("bad key, over") }, { headers: bearer(`${KEY}x`), ip });
  assert.equal(over._status, 429, JSON.stringify(over._body));
  assert.equal(over._body.error_code, "rate_limited");
  assert.match(over._body.note, /^naive per-IP limiter/);
  assert.equal(over._headers["www-authenticate"], undefined, "the 429 is answered, not the 401");
  const valid = await open({ scope_digest: sha("the key holder at that address") }, { headers: bearer(KEY), ip });
  assert.equal(valid._status, 201, JSON.stringify(valid._body));
});

test("FIX F: the keyless ops stay per-IP, and a bearer key on one of them does not move it to the key's budget", async () => {
  for (const [handler, op] of [[H.handleCaseCommit, "case-commit"], [H.handleCaseWithdraw, "case-withdraw"], [H.handleCaseReference, "case-reference"]]) {
    const ip = freshIp();
    for (let i = 0; i < ratelimit.LIMIT; i += 1) {
      assert.equal((await spend(handler, op, { headers: bearer(KEY), ip }))._status, 400, `${op} ${i + 1}`);
    }
    const over = await spend(handler, op, { headers: bearer(KEY), ip });
    assert.equal(over._status, 429, `${op}: ${JSON.stringify(over._body)}`);
    assert.match(over._body.note, /^naive per-IP limiter/);
  }
  const keyed = await open({ scope_digest: sha("the key's budget is untouched") }, { headers: bearer(KEY) });
  assert.equal(keyed._status, 201, JSON.stringify(keyed._body));
});

// =============================================================================
// FIX G: the reference quota, per case and per role
// =============================================================================

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test-budgets/2026-10-12");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test-budgets/2026-10-12");
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer });
const KEYS_DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPERATOR_KEY = "case-budgets-operator-key";
const OPERATOR_ENV = Object.freeze({ ...SIGNED, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY });
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0042", url: "https://second-operator.example/cases/0042" });
const [AGENT_TAPE, TOOL_TAPE] = (() => {
  const c = reconcileFixtures.cases.find((x) => /^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/.test(x.name) && x.python);
  assert.ok(c, "the fixture tape pair");
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
})();

function party(caseId, role, tape) {
  const tape_sha256 = sha(tape);
  const salt = C.newSalt();
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function sealedCase(scope) {
  const o = await open({ scope_digest: sha(scope) }, { headers: bearer(KEY) });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) {
    gh.seed(STAMPS, stamp.stampPath(p.commitment_sha256), { kind: "file-stamp", v: 1, sha256: p.commitment_sha256, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
    const r = await call(H.handleCaseCommit, "case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }));
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
  const res = makeRes();
  await H.handleCaseReveal(makeReq({ method: "POST", query: { op: "case-reveal" }, headers: { "content-type": "application/json", "x-forwarded-for": freshIp() }, body: {
    case_id: id,
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    tape_a_b64: a.tape.toString("base64"),
    tape_b_b64: b.tape.toString("base64"),
  } }), res, { now: REVEAL_AT, env: KD.deployed(gh, SIGNED, KEYS_DOC), keyDocument: KEYS_DOC });
  assert.equal(res._status, 201, JSON.stringify(res._body).slice(0, 300));
  return { id, a, b };
}
const proofOf = (id, p) => ({ case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt });
async function reference(body, { env = SIGNED, headers = {}, ip = freshIp(), now = REVEAL_AT + 3600000 } = {}) {
  const res = makeRes();
  await H.handleCaseReference(makeReq({ method: "POST", query: { op: "case-reference" }, headers: { "content-type": "application/json", "x-forwarded-for": ip, ...headers }, body }), res, { now, env, keyDocument: KEYS_DOC });
  return res;
}
const xref = (n) => ({ ...XREF, reference: `ref-${n}` });
const rowsIn = (id) => [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.referencesDir(id)}/`)).length;
const quotaFile = (id, role) => H._internal.referenceQuotaPath(id, role);
const writesTo = (repo) => gh.putLog.filter((x) => x.repo === repo).length;

test("FIX G: one role appends REFERENCE_QUOTA_PER_ROLE (20, the open quota's constant) rows to a case; its next is 409 reference_quota with the count, and nothing is written; the other role and the operator still append", async () => {
  assert.equal(H.REFERENCE_QUOTA_PER_ROLE, 20);
  assert.equal(H.REFERENCE_QUOTA_PER_ROLE, H.OPEN_QUOTA_PER_DAY, "one number");
  const { id, a, b } = await sealedCase("G quota");
  for (let i = 1; i <= 20; i += 1) {
    const r = await reference({ ...proofOf(id, a), cross_reference: xref(i) });
    assert.equal(r._status, 201, `row ${i}: ${JSON.stringify(r._body)}`);
  }
  assert.equal(rowsIn(id), 20);
  const pins = writesTo(PINS);
  const usage = writesTo(USAGE);
  const over = await reference({ ...proofOf(id, a), cross_reference: xref(21) });
  assert.equal(over._status, 409, JSON.stringify(over._body));
  assert.equal(over._body.ok, false);
  assert.equal(over._body.error_code, "reference_quota");
  assert.equal(over._body.case_id, id);
  assert.equal(over._body.role, "a");
  assert.equal(over._body.count, 20);
  assert.equal(over._body.quota, 20);
  assert.match(over._body.error, /role a has appended 20 reference rows to this case, the most one role may append \(20\); no row was written/);
  assert.equal(over._headers["cache-control"], "no-store");
  assert.equal(writesTo(PINS), pins, "no row");
  assert.equal(writesTo(USAGE), usage, "no counter write");
  assert.equal(rowsIn(id), 20);
  // the counter: in the private usage repository, never the public pins repository
  assert.equal(quotaFile(id, "a"), `case_references/${id}/a.json`);
  assert.deepEqual(gh.read(USAGE, quotaFile(id, "a")), { kind: "case-reference-quota", v: 1, case_id: id, role: "a", count: 20 });
  assert.equal(gh.has(PINS, quotaFile(id, "a")), false);
  // the other role counts apart
  const rb = await reference({ ...proofOf(id, b), cross_reference: xref("b") });
  assert.equal(rb._status, 201, JSON.stringify(rb._body));
  assert.equal(gh.read(USAGE, quotaFile(id, "b")).count, 1);
  // the operator is not a role: no unit is taken
  const u = writesTo(USAGE);
  const op = await reference({ case_id: id, cross_reference: xref("op") }, { env: OPERATOR_ENV, headers: { authorization: `Bearer ${OPERATOR_KEY}` } });
  assert.equal(op._status, 201, JSON.stringify(op._body));
  assert.equal(op._body.appended_by, "operator");
  assert.equal(writesTo(USAGE), u, "the operator's row takes no unit");
  assert.equal(rowsIn(id), 22);
  // and role a stays refused
  assert.equal((await reference({ ...proofOf(id, a), cross_reference: xref(22) }))._status, 409);
});

test("FIX G: one number: REFERENCE_QUOTA_PER_ROLE is defined as OPEN_QUOTA_PER_DAY, by name, so a change to the open quota's number changes both", () => {
  const code = fs.readFileSync(path.join(__dirname, "..", "lib", "_case_http.js"), "utf-8").replace(/\r\n/g, "\n");
  assert.match(code, /^const OPEN_QUOTA_PER_DAY = 20;$/m);
  assert.match(code, /^const REFERENCE_QUOTA_PER_ROLE = OPEN_QUOTA_PER_DAY;$/m);
});

test("FIX G: only a role that proved itself on a sealed case spends its count", async () => {
  const { id, a } = await sealedCase("G proof");
  const o = await open({ scope_digest: sha("G proof, not sealed") }, { headers: bearer(KEY) });
  assert.equal(o._status, 201);
  const usage = writesTo(USAGE);
  const wrong = await reference({ ...proofOf(id, a), salt: C.newSalt(), cross_reference: xref(1) });
  assert.equal(wrong._status, 403, JSON.stringify(wrong._body));
  assert.equal(wrong._body.error_code, "reference_unauthorized");
  const unsealed = await reference({ ...proofOf(o._body.case_id, party(o._body.case_id, "a", AGENT_TAPE)), cross_reference: xref(2) });
  assert.equal(unsealed._status, 409);
  assert.equal(unsealed._body.error_code, "case_not_sealed");
  assert.equal(writesTo(USAGE), usage, "no counter was written");
  assert.equal(gh.has(USAGE, quotaFile(id, "a")), false);
  assert.equal(gh.has(USAGE, quotaFile(o._body.case_id, "a")), false);
});

test("FIX G: the count is read from the store, per case: a counter planted past the quota refuses with its count, one at 19 admits one row, another case's counter is not this one's, and a damaged counter is 503 reference_quota_unreadable, never zero", async () => {
  const { id, a, b } = await sealedCase("G store");
  gh.seed(USAGE, quotaFile(sha("another case"), "a"), { kind: "case-reference-quota", v: 1, case_id: sha("another case"), role: "a", count: 20 });
  gh.seed(USAGE, quotaFile(id, "a"), { kind: "case-reference-quota", v: 1, case_id: id, role: "a", count: 19 });
  const last = await reference({ ...proofOf(id, a), cross_reference: xref(1) });
  assert.equal(last._status, 201, JSON.stringify(last._body));
  assert.equal(gh.read(USAGE, quotaFile(id, "a")).count, 20);
  assert.equal((await reference({ ...proofOf(id, a), cross_reference: xref(2) }))._body.error_code, "reference_quota");
  gh.seed(USAGE, quotaFile(id, "a"), { kind: "case-reference-quota", v: 1, case_id: id, role: "a", count: 25 });
  const past = await reference({ ...proofOf(id, a), cross_reference: xref(3) });
  assert.equal(past._status, 409);
  assert.equal(past._body.count, 25, "the count is the counter's, not the quota");
  gh.seed(USAGE, quotaFile(id, "b"), { kind: "case-reference-quota", v: 1, case_id: id, role: "b", count: "many" });
  const pins = writesTo(PINS);
  const damaged = await reference({ ...proofOf(id, b), cross_reference: xref(4) });
  assert.equal(damaged._status, 503, JSON.stringify(damaged._body));
  assert.equal(damaged._body.error_code, "reference_quota_unreadable");
  assert.equal(damaged._body.role, "b");
  assert.equal(writesTo(PINS), pins, "no row");
  assert.equal(rowsIn(id), 1);
});

test("FIX G: 26 references by one role at once append at most 20 rows, and the counter agrees", async () => {
  const { id, a } = await sealedCase("G concurrent");
  const results = await Promise.all(Array.from({ length: 26 }, (_, i) => reference({ ...proofOf(id, a), cross_reference: xref(i) })));
  const ok = results.filter((r) => r._status === 201).length;
  for (const r of results) assert.ok([201, 409, 503].includes(r._status), JSON.stringify(r._body));
  assert.ok(ok > 0, "some appended");
  assert.ok(ok <= 20, `${ok} appended`);
  assert.equal(rowsIn(id), ok);
  const count = gh.read(USAGE, quotaFile(id, "a")).count;
  assert.ok(count >= ok && count <= 20, `counter ${count}, rows ${ok}`);
});

test("FIX G: a row whose seq another row takes moves to the next seq and takes no second unit", async () => {
  const { id, a } = await sealedCase("G moved");
  const viaMock = global.fetch;
  let planted = false;
  global.fetch = async (url, o) => {
    if (!planted && (o && o.method) === "PUT" && String(url).includes(`/repos/${PINS}/contents/${C.referencePath(id, 1)}`)) {
      planted = true;
      gh.seed(PINS, C.referencePath(id, 1), { another: "row, first" });
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await reference({ ...proofOf(id, a), cross_reference: xref(1) });
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(planted, true, "fixture: another row took seq 1 between the listing and the write");
  assert.equal(r._status, 201, JSON.stringify(r._body));
  assert.equal(r._body.seq, 2);
  assert.equal(gh.read(USAGE, quotaFile(id, "a")).count, 1, "one row, one unit");
});

test("FIX G: two takers creating a role's counter at once: the one that loses the create re-reads and counts on, never a 503", async () => {
  const { id, a } = await sealedCase("G create race");
  const viaMock = global.fetch;
  let raced = false;
  global.fetch = async (url, o) => {
    if (!raced && (o && o.method) === "PUT" && String(url).includes(`/repos/${USAGE}/contents/${quotaFile(id, "a")}`)) {
      raced = true;
      gh.seed(USAGE, quotaFile(id, "a"), { kind: "case-reference-quota", v: 1, case_id: id, role: "a", count: 5 });
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await reference({ ...proofOf(id, a), cross_reference: xref(1) });
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(raced, true, "fixture: the counter was created between this request's read and its create");
  assert.equal(r._status, 201, JSON.stringify(r._body));
  assert.equal(gh.read(USAGE, quotaFile(id, "a")).count, 6, "the other taker's 5, then this one");
});

// =============================================================================
// THE OPERATOR'S BEARER: the same shape as FIX F, on ?op=case-reference
// =============================================================================

const AS_OPERATOR = Object.freeze({ authorization: `Bearer ${OPERATOR_KEY}` });

test("OPERATOR: after references with no proof and no bearer spend one address's budget, the operator's reference from that address still appends", async () => {
  const { id } = await sealedCase("O victim");
  const ip = freshIp();
  let n = 0;
  let last;
  do {
    last = await reference({ case_id: id, cross_reference: xref(`junk ${n}`) }, { env: OPERATOR_ENV, ip });
    n += 1;
  } while (last._status === 401 && n <= ratelimit.LIMIT + 5);
  assert.equal(last._status, 429, "the address's budget is spent by requests that carry no bearer");
  assert.equal(n, ratelimit.LIMIT + 1);
  const op = await reference({ case_id: id, cross_reference: xref("the operator's row") }, { env: OPERATOR_ENV, headers: AS_OPERATOR, ip });
  assert.equal(op._status, 201, `the operator is not refused by the budget unauthenticated requests spent: ${JSON.stringify(op._body)}`);
  assert.equal(op._body.appended_by, "operator");
});

test("OPERATOR: the operator's bearer draws on its own budget: from one address, its LIMIT+1th call is 429 with the per-key note, while that address's budget stays unspent", async () => {
  const { id, a } = await sealedCase("O budget");
  const ip = freshIp();
  for (let i = 0; i < ratelimit.LIMIT; i += 1) {
    const r = await reference({ not: "a reference body" }, { env: OPERATOR_ENV, headers: AS_OPERATOR, ip });
    assert.equal(r._status, 400, `operator call ${i + 1}: ${JSON.stringify(r._body)}`);
  }
  const over = await reference({ case_id: id, cross_reference: xref("past the operator's budget") }, { env: OPERATOR_ENV, headers: AS_OPERATOR, ip: freshIp() });
  assert.equal(over._status, 429, JSON.stringify(over._body));
  assert.equal(over._body.error_code, "rate_limited");
  assert.match(over._body.note, /^per-key limiter: ~30 calls per key per 10 minutes/);
  const role = await reference({ ...proofOf(id, a), cross_reference: xref("a role, same address") }, { env: OPERATOR_ENV, ip });
  assert.equal(role._status, 201, `the operator's calls spent nothing of the address's budget: ${JSON.stringify(role._body)}`);
  const bare = await reference({ case_id: id, cross_reference: xref("no bearer, same address") }, { env: OPERATOR_ENV, ip });
  assert.equal(bare._status, 401, JSON.stringify(bare._body));
  assert.equal(bare._body.error_code, "reference_unauthorized");
});

test("OPERATOR: a bearer that is not the operator's, or any bearer while the operator's key is unset, draws on the address's budget, and past it is 429 before its 401 or 503", async () => {
  const { id } = await sealedCase("O not the operator");
  for (const [env, headers, status, code] of [
    [OPERATOR_ENV, { authorization: "Bearer not-the-operator" }, 401, "reference_unauthorized"],
    [OPERATOR_ENV, { authorization: `Bearer ${OPERATOR_KEY}x` }, 401, "reference_unauthorized"],
    [SIGNED, AS_OPERATOR, 503, "operator_key_not_configured"],
  ]) {
    const ip = freshIp();
    for (let i = 0; i < ratelimit.LIMIT; i += 1) {
      const r = await reference({ case_id: id, cross_reference: xref(`not the operator ${i}`) }, { env, headers, ip });
      assert.equal(r._status, status, JSON.stringify(r._body));
      assert.equal(r._body.error_code, code);
    }
    const over = await reference({ case_id: id, cross_reference: xref("not the operator, over") }, { env, headers, ip });
    assert.equal(over._status, 429, `${code}: ${JSON.stringify(over._body)}`);
    assert.match(over._body.note, /^naive per-IP limiter/);
  }
  const op = await reference({ case_id: id, cross_reference: xref("the operator") }, { env: OPERATOR_ENV, headers: AS_OPERATOR });
  assert.equal(op._status, 201, JSON.stringify(op._body));
});

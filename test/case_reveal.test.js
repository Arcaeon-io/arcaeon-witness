// test/case_reveal.test.js — the case protocol, item 2a: the joint reveal
// (POST ?op=case-reveal, lib/_case_http.js), the reconcile run and its
// receipt, and the seal (lib/_case_seal.js: the sealed case, its signature
// with WITNESS_CASE_SIGNER_KEY, its chain, its pin, the computed anchor
// state and the retry by case_id).
//
// Numbered as in CASE_PROTOCOL_DESIGN_2026-10-10.md "Tests the worker
// writes": 6 (every reveal refusal, typed, no verdict, reconcile never
// invoked), 7 (reconcile runs once on the accepted path; the receipt's
// received-tape hashes are the committed ones), 8 (expiry, and the two
// writes of the seal: a pin that fails leaves the case standing with
// pin: pending computed, a case write that fails leaves no pin, a retry
// never changes the chain), 9 (the sealed case verifies under
// lib/_check_record.js's rule; an unknown field is refused; sig: null
// carries sig_reason), 12 (no tape and no salt persists, on the reveal
// path), plus the reveal halves of tests 4 and 5, policy_unavailable, the
// receipt deep check on a tampered receipt, and the stamp-size reveal path
// (design, "After the fix pass"). Tests 10 and 11 (withdrawal, the
// addendum) and the page are item 2c. Item 2b (test/case_item2b.test.js)
// changed three fixtures here, no expectation: case-open now needs a bearer
// key (OPEN_AUTH below); the signing environment carries the log key too,
// since the case key signs only when it can be shown different from both
// other keys; and a hand-unsigned copy of a signed case carries signed_by
// null. TEST 8's squatter is now a well-formed case_seal record (still a
// conflict), with an added arm for a malformed one (unreadable). Item 2c
// (test/case_item2c.test.js) changed two fixtures here, no expectation: the
// reveal and the anchor retries are handed KEYS_DOC (the committed key
// document plus the test key), because the case key now signs only as an
// active entry of the key document and the retry checks a stored case's
// signature against it; and the planted WITHDRAWN record is in the 2c
// redacted form (signed_by, withdrawal.salt_sha256). Each test
// plants the failure it exists to catch; MUST-FAIL ARMs run the wrong behaviour through the same
// check. Every store is the in-memory mock: no network.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
// ?op=case-open requires a bearer key (item 2b): one env key for the tests.
process.env.WITNESS_KEYS = "case-test-open-key-0002:case-test-";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const T = require("../lib/_reconcile_tapes.js");
const R = require("../lib/_reconcile_http.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const checkRecord = require("../lib/_check_record.js");
const stamp = require("../lib/_stamp.js");
const verifyHandler = require("../api/verify.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z"); // open and register
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-10");
// Item 2b: the case key signs only when it can be shown different from BOTH
// other keys, so the signing environment carries all three.
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
// Item 2c: the case key signs only when it is an ACTIVE entry of the key
// document (lib/_case_seal.js, PUBLICATION FAILS CLOSED), and the anchor
// retry checks a stored case's signature against that document. The
// committed document lists no key, so these tests hand the seal and the
// retry a copy that lists the test key, the way they hand the seal the test
// env. (loadCaseSigner's key_unpublished answer carries the public half.)
// Design I: the document lists the reconcile key too, as a reconcile entry,
// and a reveal runs on a deployment built with it (KD.deployed).
const KEYS_DOC = Object.freeze({ ...S.PUBLISHED_KEYS, keys: [S.keyDocumentEntry(S.loadCaseSigner(SIGNED), { since: "2026-10-10", note: "the test environment's case key" }),
  KD.reconcileEntry(RECEIPT_KEY)] });

// The clean cross-repo pair (MATCHED 5 of 5 under reconcile.py), and a pair
// that is ALTERED at call 2.
function pairNamed(re) {
  const c = reconcileFixtures.cases.find((x) => re.test(x.name) && x.python);
  assert.ok(c, String(re));
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
const [AGENT_TAPE, TOOL_TAPE] = pairNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/);
const [ALT_AGENT, ALT_TOOL] = pairNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_answer_changed0: agent vs tool$/);

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
  return `10.66.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
// The bearer key ?op=case-open requires (item 2b); commit and reveal take none.
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0002" });
function req(op, body, headers = {}) {
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": freshIp(),
    ...(op === "case-open" ? OPEN_AUTH : {}), ...headers }, body });
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
// A party's local work for a tape it holds as bytes.
function party(caseId, role, tape, salt = C.newSalt()) {
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function call(handler, op, body, now) {
  const res = makeRes();
  await handler(req(op, body), res, { now });
  return res;
}
// An open case with both roles registered: role a holds tapeA, role b tapeB.
async function committedCase({ over, tapeA = AGENT_TAPE, tapeB = TOOL_TAPE } = {}) {
  const o = await call(H.handleCaseOpen, "case-open", opening(over), NOW);
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", tapeA);
  const b = party(id, "b", tapeB);
  for (const p of [a, b]) {
    plantStamp(p.commitment_sha256);
    const r = await call(H.handleCaseCommit, "case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }), NOW);
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
  assert.equal(storedCase(id).status, "COMMITTED");
  return { id, a, b };
}
function revealBody(id, a, b, extra = {}) {
  return {
    case_id: id,
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    tape_a_b64: a.tape.toString("base64"),
    tape_b_b64: b.tape.toString("base64"),
    ...extra,
  };
}
async function reveal(body, { now = REVEAL_AT, env = SIGNED, request, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(request || req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res), res };
}
function storedCase(id) {
  return gh.read(PINS, C.casePath(id));
}
function storedText() {
  let out = "";
  for (const [, files] of gh.repos) for (const [, f] of files) out += f.content;
  return out;
}
// Counts calls of the port while a test runs.
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
const RAW = (hex) => `sha256:raw-bytes:v1:${hex}`;

// =============================================================================
// TEST 7: the accepted path
// =============================================================================

test("TEST 7: the accepted reveal runs reconcile exactly once and seals; the receipt's received-tape hashes are the committed ones", async (t) => {
  const { id, a, b } = await committedCase();
  const runs = spyReconcile(t);
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 400));
  assert.equal(runs(), 1, "reconcile ran once");
  assert.equal(r.body.ok, true);
  assert.equal(r.body.status, "VERDICT");
  assert.equal(r.body.verdict.summary, "MATCHED 5 of 5");
  assert.equal(r.body.pin, "pinned");

  const k = storedCase(id);
  assert.deepEqual(k, r.body.case, "the answer carries the case as written");
  assert.deepEqual(C.validateCase(k), { ok: true });
  assert.equal(k.status, "VERDICT");
  const receipt = k.verdict;
  assert.equal(receipt.kind, receipts.RECEIPT_KIND);
  // The received-tape hashes are the hashes inside the registered commitments.
  for (const [slot, p] of [["tape_a", a], ["tape_b", b]]) {
    assert.equal(receipt.tapes[slot].digest, RAW(p.tape_sha256), slot);
    assert.equal(receipt.tapes[slot].bytes, p.tape.length, slot);
    const reg = gh.read(PINS, C.registrationPath(id, p.role));
    assert.equal(C.commitmentSha256({ case_id: id, role: p.role, tape_sha256: receipt.tapes[slot].digest.slice(-64), salt: p.salt }),
      reg.commitment_sha256, `${slot}'s received hash recomputes role ${p.role}'s registered commitment`);
  }
  assert.equal(receipt.method.port_version, k.policy_version);
  assert.equal(receipt.compared_at, "2026-10-10T09:00:00Z", "the service clock");
  assert.deepEqual(k.reveals, {
    a: { tape_sha256: a.tape_sha256, salt_sha256: C.saltSha256(a.salt), revealed_at: "2026-10-10T09:00:00Z" },
    b: { tape_sha256: b.tape_sha256, salt_sha256: C.saltSha256(b.salt), revealed_at: "2026-10-10T09:00:00Z" },
  });
  assert.equal(k.records, 1);
  assert.equal(k.cross_reference, null);
  assert.deepEqual(k.commitments.a, C.commitmentEntry(gh.read(PINS, C.registrationPath(id, "a"))), "the commitments are untouched");

  // EXACTLY AS ?op=reconcile: the same two tapes (role a's as agent_tape, the
  // first argument), the same clock and key, give the same verdict and the
  // same signed receipt, byte for byte.
  const direct = makeRes();
  await R.handleReconcile(makeReq({ method: "POST", query: { op: "reconcile" }, headers: { "content-type": "application/json", "x-forwarded-for": freshIp() },
    body: { agent_tape_b64: a.tape.toString("base64"), tool_tape_b64: b.tape.toString("base64") } }), direct, { env: SIGNED, now: REVEAL_AT, keyDocument: KEYS_DOC });
  const viaReconcile = T._internal.pyLoads(direct._body, false);
  assert.equal(T.wireJson(r.body.verdict), T.wireJson(JSON.parse(T.wireJson(viaReconcile.get("verdict")))), "the verdict is ?op=reconcile's");
  assert.equal(T.wireJson(receipt), T.wireJson(JSON.parse(T.wireJson(viaReconcile.get("receipt")))), "the receipt is ?op=reconcile's");
  assert.deepEqual(receipts.verifyReceiptText(T.wireJson(receipt), RECEIPT_KEY.verifier), { ok: true, reason: "signed", signer: RECEIPT_KEY.verifier });

  // MUST-FAIL ARM: the tapes in the other order give a receipt whose tape_a
  // is role b's tape; the slot assertions above are what would catch it.
  const swapped = R.compare(b.tape, a.tape, { env: SIGNED, now: REVEAL_AT, keyDocument: KEYS_DOC }).receipt;
  assert.notEqual(swapped.tapes.tape_a.digest, RAW(a.tape_sha256));
});

test("TEST 7: an ALTERED pair seals as ALTERED with the first divergence in the receipt; through the real verify.js dispatch, this deployment refuses before comparing", async (t) => {
  const { id, a, b } = await committedCase({ tapeA: ALT_AGENT, tapeB: ALT_TOOL });
  const runs = spyReconcile(t);
  // The real dispatch reads its clock, its keys, its key document and its
  // commit from the process. Since Design I it seals only under a document
  // it can name: here no VERCEL_GIT_COMMIT_SHA is set (and the committed
  // document lists no reconcile key), so it refuses, typed, and compares
  // nothing, even with the reconcile signer set.
  const viaDispatch = makeRes();
  const realNow = Date.now;
  Date.now = () => Date.parse("2026-10-10T10:00:00Z");
  process.env[receipts.SIGNER_ENV] = RECEIPT_KEY.signer;
  try {
    await verifyHandler(req("case-reveal", revealBody(id, a, b)), viaDispatch);
  } finally {
    Date.now = realNow;
    delete process.env[receipts.SIGNER_ENV];
  }
  assert.equal(viaDispatch._status, 503, String(viaDispatch._body).slice(0, 300));
  assert.equal(parsed(viaDispatch).error_code, "document_unavailable");
  assert.equal(runs(), 0, "nothing compared");
  // The seal itself, on a deployment that carries the test document; its
  // clock is held at 10:00.
  const r = await reveal(revealBody(id, a, b), { now: Date.parse("2026-10-10T10:00:00Z") });
  const body = r.body;
  assert.equal(r.status, 201, JSON.stringify(body).slice(0, 300));
  assert.equal(runs(), 1);
  const k = storedCase(id);
  assert.equal(k.verdict.verdict.verdict, "ALTERED");
  assert.equal(k.verdict.verdict.at, 2);
  assert.equal(body.verdict.verdict, "ALTERED");
  assert.match(body.verdict.summary, /^ALTERED at call 2/);
  assert.equal(k.reveals.a.revealed_at, "2026-10-10T10:00:00Z");
  // GET on the op is a typed refusal, not verify's lookup
  const get = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "case-reveal" }, headers: { "x-forwarded-for": freshIp() } }), get);
  assert.equal(get._status, 405);
  assert.equal(get._body.error_code, "method_not_allowed");
});

test("TEST 7: the two tapes may come as JSON text, base64 or multipart parts; each seals the same receipt", async () => {
  const forms = {
    text: (id, a, b) => req("case-reveal", { ...revealBody(id, a, b, {}), tape_a_b64: undefined, tape_b_b64: undefined, tape_a: a.tape.toString("utf-8"), tape_b: b.tape.toString("utf-8") }),
    raw_json_string: (id, a, b) => req("case-reveal", JSON.stringify(revealBody(id, a, b))),
    multipart: (id, a, b) => {
      const boundary = "----arcaeonCASE42";
      const parts = [["case_id", id], ["reveals", JSON.stringify(revealBody(id, a, b).reveals)], ["tape_a", a.tape, "a.jsonl"], ["tape_b", b.tape, "b.jsonl"]];
      const chunks = [];
      for (const [name, data, filename] of parts) {
        chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"${filename ? `; filename="${filename}"` : ""}\r\n\r\n`, "latin1"));
        chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(data, "utf-8"));
        chunks.push(Buffer.from("\r\n", "latin1"));
      }
      chunks.push(Buffer.from(`--${boundary}--\r\n`, "latin1"));
      const r = makeRawReq({ method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-forwarded-for": freshIp() }, rawBody: Buffer.concat(chunks) });
      r.query = { op: "case-reveal" };
      return r;
    },
  };
  const receiptsSeen = new Set();
  for (const [name, make] of Object.entries(forms)) {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha(`form ${name}`) } });
    const body = make(id, a, b);
    if (body.body && typeof body.body === "object") {
      delete body.body.tape_a_b64;
      delete body.body.tape_b_b64;
    }
    const r = await reveal(null, { request: body });
    assert.equal(r.status, 201, `${name}: ${JSON.stringify(r.body).slice(0, 300)}`);
    const k = storedCase(id);
    assert.equal(k.verdict.tapes.tape_a.digest, RAW(a.tape_sha256), name);
    assert.equal(k.verdict.tapes.tape_b.digest, RAW(b.tape_sha256), name);
    receiptsSeen.add(T.wireJson(k.verdict.tapes));
  }
  assert.equal(receiptsSeen.size, 1, "every form bound the same two tapes");
});

test("SEAL: records is 2 only with a cross_reference sent with the reveal, recorded at the service clock; a caller's time is refused", async () => {
  const x = { operator: "second-operator.example", reference: "case-ref-0042", url: "https://second-operator.example/cases/0042" };
  const { id, a, b } = await committedCase();
  for (const forged of [{ ...x, recorded_at: "2026-01-01T00:00:00Z" }]) {
    const bad = await reveal(revealBody(id, a, b, { cross_reference: forged }));
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error_code, "unknown_field");
    assert.equal(bad.body.field, "cross_reference.recorded_at");
  }
  for (const [field, val] of [["url", "http://insecure.example/x"], ["url", "https://has space.example"], ["operator", ""], ["reference", "line\nbreak"]]) {
    const bad = await reveal(revealBody(id, a, b, { cross_reference: { ...x, [field]: val } }));
    assert.equal(bad.status, 400, `${field}=${JSON.stringify(val)}`);
    assert.equal(bad.body.error_code, "malformed_field");
    assert.equal(bad.body.field, `cross_reference.${field}`);
  }
  const r = await reveal(revealBody(id, a, b, { cross_reference: x }));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const k = storedCase(id);
  assert.equal(k.records, 2);
  assert.deepEqual(k.cross_reference, { ...x, recorded_at: "2026-10-10T09:00:00Z" });
  // and without one (also null), records is 1
  for (const extra of [{}, { cross_reference: null }]) {
    const c2 = await committedCase({ over: { scope_digest: sha(`no xref ${JSON.stringify(extra)}`) } });
    const r2 = await reveal(revealBody(c2.id, c2.a, c2.b, extra));
    assert.equal(r2.status, 201);
    assert.equal(storedCase(c2.id).records, 1);
    assert.equal(storedCase(c2.id).cross_reference, null);
  }
  // MUST-FAIL ARM: records 2 without a cross_reference is not a valid case
  assert.equal(C.validateCase({ ...storedCase(id), cross_reference: null }).code, "status_inconsistent");
});

// =============================================================================
// TEST 6: every refusal is typed, no verdict, nothing written, no reconcile
// =============================================================================

test("TEST 6: every reveal refusal is a typed 4xx (or a 503 for the store), carries no verdict, writes nothing and never invokes reconcile", async (t) => {
  const runs = spyReconcile(t);
  const plants = [];
  const plant = (name, status, code, setup) => plants.push({ name, status, code, setup });

  plant("not committed: only role a registered", 409, "not_committed", async () => {
    const o = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("half") }), NOW);
    const id = o._body.case_id;
    const a = party(id, "a", AGENT_TAPE);
    const b = party(id, "b", TOOL_TAPE);
    plantStamp(a.commitment_sha256);
    await call(H.handleCaseCommit, "case-commit", REG.signedBody({ case_id: id, role: "a", commitment_sha256: a.commitment_sha256 }), NOW);
    return revealBody(id, a, b);
  });
  plant("not committed: already sealed", 409, "not_committed", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("sealed twice") } });
    const first = await reveal(revealBody(id, a, b));
    assert.equal(first.status, 201);
    return revealBody(id, a, b);
  });
  plant("withdrawn", 409, "case_withdrawn", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("withdrawn") } });
    gh.seed(PINS, C.casePath(id), { v: 1, case_id: id, protocol_version: "case/1", status: "WITHDRAWN", opened_at: "2026-10-10T07:30:00Z",
      withdrawal: { by_role: "a", at: "2026-10-10T08:30:00Z", salt_sha256: sha("the withdrawing salt") }, limits: C.LIMITS.slice(), signed_by: null, sig: null,
      sig_reason: "withdrawn in this test" });
    return revealBody(id, a, b);
  });
  plant("unknown case", 404, "case_not_found", async () => {
    const { a, b } = await committedCase({ over: { scope_digest: sha("unknown") } });
    return revealBody("9".repeat(64), a, b);
  });
  plant("a wrong salt for role a", 409, "commitment_mismatch", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("salt") } });
    return revealBody(id, { ...a, salt: C.newSalt() }, b);
  });
  plant("a wrong tape hash for role b (and the matching tape)", 409, "commitment_mismatch", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("tape hash") } });
    const other = Buffer.concat([b.tape, Buffer.from("\n")]);
    return revealBody(id, a, { ...b, tape: other, tape_sha256: sha(other) });
  });
  plant("the substituted tape: reveals right, tape_a's bytes changed", 409, "tape_substituted", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("substituted") } });
    const body = revealBody(id, a, b);
    body.tape_a_b64 = Buffer.concat([a.tape, Buffer.from(" ")]).toString("base64");
    return body;
  });
  plant("the tapes in each other's slots", 409, "tape_substituted", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("slots") } });
    const body = revealBody(id, a, b);
    [body.tape_a_b64, body.tape_b_b64] = [body.tape_b_b64, body.tape_a_b64];
    return body;
  });
  plant("a projection that disagrees with its registration file", 503, "case_record_inconsistent", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("inconsistent") } });
    const k = storedCase(id);
    gh.seed(PINS, C.casePath(id), { ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, registered_at: "2026-10-10T08:00:01Z" } } });
    return revealBody(id, a, b);
  });
  plant("a registration file gone", 503, "case_record_inconsistent", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("file gone") } });
    gh.repos.get(PINS).delete(C.registrationPath(id, "b"));
    return revealBody(id, a, b);
  });
  plant("the stamp-size reveal path: role a's stamp now records a tape's size", 409, "stamp_size_mismatch", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("stamp size") } });
    gh.seed(STAMPS, stamp.stampPath(a.commitment_sha256), { kind: "file-stamp", v: 1, sha256: a.commitment_sha256, size: a.tape.length, stamped_at: "2026-10-10T07:45:00.123Z" });
    return revealBody(id, a, b);
  });
  plant("role b's stamp path touched by a second commit", 409, "stamp_history_ambiguous", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("stamp history") } });
    gh.addCommit(STAMPS, stamp.stampPath(b.commitment_sha256));
    return revealBody(id, a, b);
  });
  plant("role a's stamp re-dated", 503, "case_record_inconsistent", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("stamp redated") } });
    plantStamp(a.commitment_sha256, "2026-10-10T07:46:00.000Z");
    return revealBody(id, a, b);
  });
  plant("a side-named tape field", 400, "unknown_field", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("side names") } });
    const body = revealBody(id, a, b);
    body.agent_tape_b64 = body.tape_a_b64;
    delete body.tape_a_b64;
    return body;
  });
  plant("a caller's revealed_at", 400, "unknown_field", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("revealed_at") } });
    const body = revealBody(id, a, b);
    body.reveals.a.revealed_at = "2026-10-10T08:59:00Z";
    return body;
  });
  plant("a missing tape", 400, "missing_tape", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("missing tape") } });
    const body = revealBody(id, a, b);
    delete body.tape_b_b64;
    return body;
  });
  plant("a non-canonical base64 tape", 400, "malformed_base64", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("b64") } });
    return { ...revealBody(id, a, b), tape_a_b64: "YR==" };
  });
  plant("a missing reveal for role b", 400, "missing_field", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("missing reveal") } });
    const body = revealBody(id, a, b);
    delete body.reveals.b;
    return body;
  });
  plant("an already-parsed body over the cap", 413, "too_large", async () => {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha("too large") } });
    return { ...revealBody(id, a, b), tape_a: "x".repeat(R.BODY_MAX_BYTES), tape_a_b64: undefined };
  });

  for (const p of plants) {
    const body = await p.setup();
    const before = { writes: gh.putLog.length, runs: runs() };
    const r = await reveal(body);
    assert.equal(r.status, p.status, `${p.name}: ${JSON.stringify(r.body).slice(0, 300)}`);
    assert.equal(r.body.ok, false, p.name);
    assert.equal(r.body.error_code, p.code, `${p.name}: ${JSON.stringify(r.body).slice(0, 300)}`);
    assert.equal(typeof r.body.error, "string", p.name);
    assert.equal(r.body.verdict, undefined, `${p.name}: a refusal carries no verdict`);
    assert.equal(r.body.case, undefined, p.name);
    assert.equal(gh.putLog.length, before.writes, `${p.name}: nothing written`);
    assert.equal(runs(), before.runs, `${p.name}: reconcile was never invoked`);
  }
  assert.ok(plants.length >= 19);
  // the method and the media type, typed too
  const get = makeRes();
  await H.handleCaseReveal(makeReq({ method: "GET", headers: { "x-forwarded-for": freshIp() } }), get, { now: REVEAL_AT, env: SIGNED });
  assert.equal(get._status, 405);
  assert.equal(get._body.error_code, "method_not_allowed");
  const txt = await reveal(null, { request: makeReq({ method: "POST", headers: { "content-type": "text/plain", "x-forwarded-for": freshIp() }, body: "hi" }) });
  assert.equal(txt.status, 415);
  assert.equal(txt.body.error_code, "unsupported_media_type");
  assert.equal(runs(), 1, "only the one accepted reveal (the already-sealed plant's first) ever ran reconcile");
});

test("TEST 4 AND TEST 5, THE REVEAL HALVES: of fifty stamped candidates only the registered one reveals; A's tape and salt under B's role are refused, reconcile never invoked", async (t) => {
  const runs = spyReconcile(t);
  const o = await call(H.handleCaseOpen, "case-open", opening(), NOW);
  const id = o._body.case_id;
  const cands = [];
  for (let i = 0; i < 50; i += 1) {
    const tape = Buffer.concat([AGENT_TAPE, Buffer.from(i === 37 ? "" : `\n`.repeat(i + 1))]);
    const p = party(id, "a", i === 37 ? AGENT_TAPE : tape);
    plantStamp(p.commitment_sha256, new Date(Date.parse("2026-10-10T07:00:00Z") + i * 60000).toISOString());
    cands.push(p);
  }
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  assert.equal((await call(H.handleCaseCommit, "case-commit", REG.signedBody({ case_id: id, role: "a", commitment_sha256: cands[37].commitment_sha256 }), NOW))._status, 201);
  assert.equal((await call(H.handleCaseCommit, "case-commit", REG.signedBody({ case_id: id, role: "b", commitment_sha256: b.commitment_sha256 }), NOW))._status, 201);
  const writes = gh.putLog.length;
  for (const i of [0, 1, 36, 38, 49]) {
    const r = await reveal(revealBody(id, cands[i], b));
    assert.equal(r.status, 409, `candidate ${i}`);
    assert.equal(r.body.error_code, "commitment_mismatch", `candidate ${i}`);
    assert.equal(r.body.role, "a");
  }
  // TEST 5: valid commitments for both roles; each role's preimage under the other role
  const swapped = await reveal({ ...revealBody(id, b, cands[37]), tape_a_b64: TOOL_TAPE.toString("base64"), tape_b_b64: AGENT_TAPE.toString("base64") });
  assert.equal(swapped.status, 409);
  assert.equal(swapped.body.error_code, "commitment_mismatch");
  assert.equal(swapped.body.role, "a", "b's tape and salt do not recompute a's registration under role a");
  const halfSwap = await reveal({ ...revealBody(id, cands[37], cands[37]) });
  assert.equal(halfSwap.status, 409);
  assert.equal(halfSwap.body.error_code, "commitment_mismatch");
  assert.equal(halfSwap.body.role, "b", "A's tape and salt under role b");
  assert.equal(runs(), 0, "reconcile was never invoked");
  assert.equal(gh.putLog.length, writes);
  // control: the registered candidate and b's reveal seal
  const ok = await reveal(revealBody(id, cands[37], b));
  assert.equal(ok.status, 201, JSON.stringify(ok.body).slice(0, 300));
  assert.equal(runs(), 1);
});

test("REVEAL: policy_unavailable when the case's bound version is not the one this build runs; it never compares under another", async (t) => {
  const runs = spyReconcile(t);
  // (1) The port moved on after the case bound 0.1.0.
  const { id, a, b } = await committedCase();
  const real = T.PORT_VERSION;
  t.after(() => {
    T.PORT_VERSION = real;
  });
  T.PORT_VERSION = "0.2.0";
  const writes = gh.putLog.length;
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error_code, "policy_unavailable");
  assert.equal(r.body.policy_version, real);
  assert.equal(r.body.runnable_version, "0.2.0");
  T.PORT_VERSION = real;

  // (2) A case bound to a version this build never ran (planted whole: the
  // opening refuses it, so it can only be a stored record).
  const pre = C.caseIdPreimage({ ...opening(), policy_version: "0.0.9", scope_digest: sha("old port") });
  const kase = C.newCase({ ...pre, deadline: DEADLINE });
  const id2 = kase.case_id;
  const a2 = party(id2, "a", AGENT_TAPE);
  const b2 = party(id2, "b", TOOL_TAPE);
  const regs = {};
  for (const p of [a2, b2]) {
    plantStamp(p.commitment_sha256);
    regs[p.role] = C.registrationRecord({ case_id: id2, role: p.role, commitment_sha256: p.commitment_sha256, registered_at: "2026-10-10T08:00:00Z",
      stamp_commit: gh.commitsFor(STAMPS, stamp.stampPath(p.commitment_sha256))[0].sha, stamped_at: "2026-10-10T07:45:00.123Z",
      ...REG.keyFields({ case_id: id2, role: p.role, commitment_sha256: p.commitment_sha256 }) });
    gh.seed(PINS, C.registrationPath(id2, p.role), regs[p.role]);
  }
  const committed = { ...kase, commitments: { a: C.commitmentEntry(regs.a), b: C.commitmentEntry(regs.b) }, status: "COMMITTED" };
  assert.deepEqual(C.validateCase(committed), { ok: true }, "fixture: a valid COMMITTED case bound to 0.0.9");
  gh.seed(PINS, C.casePath(id2), committed);
  const r2 = await reveal(revealBody(id2, a2, b2));
  assert.equal(r2.status, 409, JSON.stringify(r2.body));
  assert.equal(r2.body.error_code, "policy_unavailable");
  assert.equal(r2.body.policy_version, "0.0.9");
  assert.equal(runs(), 0, "never compared");
  assert.equal(gh.putLog.length, writes, "nothing written");
  // MUST-FAIL ARM: the comparison would have run happily under this build's
  // version and stamped its own port version into the receipt.
  assert.equal(R.compare(a2.tape, b2.tape, { env: SIGNED, now: REVEAL_AT, keyDocument: KEYS_DOC }).receipt.method.port_version, real);
  assert.notEqual(real, "0.0.9");
  // control: the same case under its own version seals
  const ok = await reveal(revealBody(id, a, b));
  assert.equal(ok.status, 201);
});

// =============================================================================
// THE RECEIPT DEEP CHECK
// =============================================================================

test("RECEIPT CHECK: a tampered receipt is refused by name, and through the endpoint nothing is sealed", async (t) => {
  const { id, a, b } = await committedCase();
  const kase = storedCase(id);
  const revealedAt = "2026-10-10T09:00:00Z";
  const signer = receipts.loadSigner(SIGNED);
  const ctx = (over = {}) => ({ kase, tapeSha256: { a: a.tape_sha256, b: b.tape_sha256 }, tapeBytes: { a: a.tape.length, b: b.tape.length },
    revealedAt, signer, ...over });
  const fresh = () => R.compare(a.tape, b.tape, { env: SIGNED, now: REVEAL_AT, keyDocument: KEYS_DOC });
  const { result, receipt } = fresh();
  assert.deepEqual(S.checkReceipt(receipt, ctx({ result })), { ok: true }, "control: the real receipt passes");

  const resign = (r) => receipts.signReceipt({ ...r, sig: undefined, signer: undefined }, signer);
  const cases = {
    receipt_tape_a_mismatch: () => resign({ ...fresh().receipt, tapes: { ...receipt.tapes, tape_a: { ...receipt.tapes.tape_a, digest: RAW("0".repeat(64)) } } }),
    receipt_tape_b_mismatch: () => resign({ ...fresh().receipt, tapes: { ...receipt.tapes, tape_b: { ...receipt.tapes.tape_b, digest: RAW(a.tape_sha256) } } }),
    receipt_tape_size_mismatch: () => resign({ ...fresh().receipt, tapes: { ...receipt.tapes, tape_b: { ...receipt.tapes.tape_b, bytes: b.tape.length + 1 } } }),
    receipt_claim_altered: () => resign({ ...fresh().receipt, claim: "These two tapes are true." }),
    receipt_limits_altered: () => resign({ ...fresh().receipt, does_not_claim: receipt.does_not_claim.slice(1) }),
    receipt_policy_mismatch: () => resign({ ...fresh().receipt, method: { ...receipt.method, port_version: "0.0.9" } }),
    receipt_method_altered: () => resign({ ...fresh().receipt, method: { ...receipt.method, reference: { ...receipt.method.reference, reconcile_sha256: "0".repeat(64) } } }),
    receipt_verdict_mismatch: () => resign({ ...fresh().receipt, verdict: { ...receipt.verdict, verdict: "MISSING" } }),
    receipt_verdict_digest_mismatch: () => resign({ ...fresh().receipt, verdict_digest: `sha256:json-c14n:v1:${"0".repeat(64)}` }),
    receipt_time_mismatch: () => resign({ ...fresh().receipt, compared_at: "2026-10-10T09:00:01Z" }),
    receipt_unknown_field: () => resign({ ...fresh().receipt, anchored: true }),
    receipt_bad_signature: () => ({ ...fresh().receipt, sig: Buffer.alloc(64, 7).toString("base64") }),
    receipt_signer_mismatch: () => receipts.signReceipt({ ...fresh().receipt, sig: undefined, signer: undefined }, receipts.loadSigner({ [receipts.SIGNER_ENV]: CASE_KEY.signer })),
    receipt_not_a_reconcile_receipt: () => resign({ ...fresh().receipt, kind: "check" }),
  };
  for (const [reason, make] of Object.entries(cases)) {
    const bad = make();
    for (const k of Object.keys(bad)) if (bad[k] === undefined) delete bad[k];
    const got = S.checkReceipt(bad, ctx({ result }));
    assert.equal(got.ok, false, reason);
    assert.equal(got.reason, reason, `${reason}: got ${got.reason}`);
  }
  // Since red-team fix B nothing unsigned seals: no signer, or an unsigned
  // receipt, is receipt_unsigned, even when the two agree.
  const unsignedSigner = receipts.loadSigner({});
  assert.equal(S.checkReceipt(receipt, ctx({ result, signer: unsignedSigner })).reason, "receipt_unsigned");
  const unsignedReceipt = receipts.signReceipt(receipts.buildReceipt({ bytesA: a.tape, bytesB: b.tape, result, now: REVEAL_AT }), unsignedSigner);
  assert.equal(S.checkReceipt(unsignedReceipt, ctx({ result })).reason, "receipt_unsigned");
  assert.equal(S.checkReceipt(unsignedReceipt, ctx({ result, signer: unsignedSigner })).reason, "receipt_unsigned", "unsigned and keyless no longer seal");

  // Through the endpoint: a receipt builder that binds the wrong tape. The
  // signature is good; the binding is not; nothing is sealed.
  const runs = spyReconcile(t);
  const realBuild = receipts.buildReceipt;
  t.after(() => {
    receipts.buildReceipt = realBuild;
  });
  receipts.buildReceipt = (args) => realBuild({ ...args, bytesA: args.bytesB });
  const writes = gh.putLog.length;
  const r = await reveal(revealBody(id, a, b));
  receipts.buildReceipt = realBuild;
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(r.body.error_code, "internal_error");
  assert.equal(r.body.reason, "receipt_tape_a_mismatch");
  assert.equal(r.body.verdict, undefined);
  assert.equal(runs(), 1, "the comparison ran; its receipt was refused");
  // red-team fix E: the attempt, before the comparison, and its failure; nothing sealed, nothing pinned
  assert.deepEqual(gh.putLog.slice(writes).map((w) => w.path), [C.casePath(id), C.casePath(id)]);
  assert.equal(storedCase(id).status, "COMMITTED");
  assert.equal(storedCase(id).reveal_failure.reason, "receipt_check_failed");
  // control: the real builder seals
  assert.equal((await reveal(revealBody(id, a, b))).status, 201);
});

test("RECEIPT CHECK: the stored receipt is JSON that signs the same bytes; a call index past 2^53 - 1 cannot be stored and is refused", () => {
  const result = T.reconcileTapes(ALT_AGENT, ALT_TOOL);
  const signer = receipts.loadSigner(SIGNED);
  const receipt = receipts.signReceipt(receipts.buildReceipt({ bytesA: ALT_AGENT, bytesB: ALT_TOOL, result, now: REVEAL_AT }), signer);
  assert.equal(typeof receipt.verdict.at, "bigint", "fixture: the port keeps the call index as a BigInt");
  const st = S.storableReceipt(receipt);
  assert.equal(st.ok, true);
  assert.equal(st.receipt.verdict.at, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(st.receipt)), st.receipt, "plain JSON");
  assert.equal(receipts.verifyReceiptText(JSON.stringify(st.receipt), RECEIPT_KEY.verifier).ok, true, "the stored form verifies");
  // past 2^53 - 1 the stored form would be another number: refused
  const huge = { ...receipt, verdict: { ...receipt.verdict, at: 2n ** 60n } };
  assert.deepEqual(S.storableReceipt(huge), { ok: false, reason: "integer_beyond_json" });
  // MUST-FAIL ARM: what a plain conversion would store is not the signed value
  assert.notEqual(BigInt(Number(2n ** 60n + 1n)), 2n ** 60n + 1n);
});

// =============================================================================
// TEST 8: expiry, and the seal's two writes
// =============================================================================

test("TEST 8: registered before the deadline and revealed at or after it is expired, typed, never compared; one second before, it seals", async (t) => {
  const runs = spyReconcile(t);
  const { id, a, b } = await committedCase();
  const deadlineMs = Date.parse(DEADLINE);
  const writes = gh.putLog.length;
  for (const now of [deadlineMs, deadlineMs + 1, deadlineMs + 30 * 86400000]) {
    const r = await reveal(revealBody(id, a, b), { now });
    assert.equal(r.status, 409, String(now));
    assert.equal(r.body.error_code, "expired");
    assert.equal(r.body.status, "EXPIRED");
    assert.equal(r.body.deadline, DEADLINE);
  }
  assert.equal(runs(), 0);
  assert.equal(gh.putLog.length, writes);
  assert.equal(storedCase(id).status, "COMMITTED", "expiry writes nothing");
  // an OPEN case past its deadline reads EXPIRED too, not not_committed
  const o = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("open expired") }), NOW);
  const r2 = await reveal(revealBody(o._body.case_id, a, b), { now: deadlineMs });
  assert.equal(r2.body.error_code, "expired");
  // control: one second before the deadline
  const ok = await reveal(revealBody(id, a, b), { now: deadlineMs - 1000 });
  assert.equal(ok.status, 201, JSON.stringify(ok.body).slice(0, 300));
  assert.equal(storedCase(id).reveals.a.revealed_at, "2026-10-10T19:59:59Z");
  assert.equal(runs(), 1);
});

test("TEST 8: a pin that fails after the case write leaves the sealed case standing and pin: pending, computed from the pin's absence and stored nowhere", async () => {
  const { id, a, b } = await committedCase();
  const paths = S.pinPaths(id);
  assert.equal(paths.ns, `case/${id}`);
  gh.forceFailure(PINS, paths.seq, 1, 502);
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.pin, "commit_unrecorded");
  const k = storedCase(id);
  assert.equal(k.status, "VERDICT", "the case file stands");
  assert.deepEqual(C.validateCase(k), { ok: true });
  assert.deepEqual(Object.keys(k).sort(), [...C.TOP_LEVEL_FIELDS, "signed_under"].sort(), "no anchor or pin field in the case (and no reveal attempt: a sealed case is the seal)");
  assert.equal(gh.has(PINS, paths.seq), false);
  assert.equal(gh.has(PINS, paths.latest), false);
  assert.deepEqual(await S.anchorState(id, r.body.chain), { pin: "commit_unrecorded", reason: "not_pinned" }, "computed from the pin's absence");
  // MUST-FAIL ARM: storing the state in the case is refused by the schema
  assert.equal(C.validateCase({ ...k, anchor: "pending" }).code, "unknown_field");
  assert.equal(C.validateCase({ ...k, pin: "pending" }).code, "unknown_field");
});

test("TEST 8: a case write that fails leaves no pin and the case COMMITTED; the same reveal then seals", async (t) => {
  const runs = spyReconcile(t);
  const { id, a, b } = await committedCase();
  // red-team fix E: the case file's second PUT is the seal's (its first is the reveal's attempt)
  let puts = 0;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if ((o && o.method) === "PUT" && String(url).includes(`/contents/${C.casePath(id)}`) && ++puts === 2) gh.forceFailure(PINS, C.casePath(id), 1, 500);
    return viaMock(url, o);
  };
  let r;
  try {
    r = await reveal(revealBody(id, a, b));
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.equal(r.body.error_code, "case_seal_failed");
  assert.equal(r.body.verdict, undefined);
  assert.equal(storedCase(id).status, "COMMITTED");
  const pinFiles = [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith("pins/"));
  assert.deepEqual(pinFiles, [], "no pin of any kind");
  const ok = await reveal(revealBody(id, a, b));
  assert.equal(ok.status, 201);
  assert.equal(ok.body.pin, "pinned");
  assert.equal(runs(), 2);
});

test("TEST 8: a retry by case_id never changes the chain: after a failed pin, after a lost pointer, and on a repeat", async () => {
  const { id, a, b } = await committedCase();
  const paths = S.pinPaths(id);
  gh.forceFailure(PINS, paths.seq, 1, 502);
  const r = await reveal(revealBody(id, a, b), { now: REVEAL_AT });
  assert.equal(r.body.pin, "commit_unrecorded");
  const chain = r.body.chain;
  const k = storedCase(id);
  assert.equal(chain, sha(checkRecord.preimage(k)), "chain = sha256(json-c14n(case minus sig))");
  assert.equal(chain, S.caseChain(k));

  // the retry, an hour later
  const retry = await S.anchorCase(id, { now: REVEAL_AT + 3600000, keyDocument: KEYS_DOC });
  assert.equal(retry.ok, true);
  assert.equal(retry.pin, "pinned");
  assert.equal(retry.chain, chain, "the retry's chain is the seal's");
  const pinned = gh.read(PINS, paths.latest);
  assert.equal(pinned.chain, chain);
  assert.equal(pinned.namespace, `case/${id}`);
  assert.equal(pinned.rows, 3);
  assert.equal(pinned.seq, 1);
  assert.equal(pinned.record_kind, "case_seal");
  assert.deepEqual(gh.read(PINS, paths.seq), pinned, "the numbered record and the pointer are one record");
  assert.deepEqual(storedCase(id), k, "the sealed case was not touched");
  // a repeat writes nothing
  const writes = gh.putLog.length;
  const again = await S.anchorCase(id, { keyDocument: KEYS_DOC });
  assert.equal(again.pin, "pinned");
  assert.equal(again.existing, true);
  assert.equal(again.chain, chain);
  assert.equal(gh.putLog.length, writes);
  assert.equal((await S.anchorState(id, chain)).pin, "pinned");

  // a lost pointer: the numbered record landed, the pointer did not; the
  // retry adopts the record it finds, unchanged
  const c2 = await committedCase({ over: { scope_digest: sha("lost pointer") } });
  const p2 = S.pinPaths(c2.id);
  gh.forceFailure(PINS, p2.latest, 1, 502);
  const r2 = await reveal(revealBody(c2.id, c2.a, c2.b));
  assert.equal(r2.body.pin, "commit_unrecorded");
  const orphan = gh.read(PINS, p2.seq);
  assert.equal(orphan.chain, r2.body.chain);
  const retry2 = await S.anchorCase(c2.id, { now: REVEAL_AT + 7200000, keyDocument: KEYS_DOC });
  assert.equal(retry2.pin, "pinned");
  assert.equal(retry2.chain, r2.body.chain);
  assert.deepEqual(gh.read(PINS, p2.latest), orphan, "adopted as it was, its first pinned_at kept");

  // MUST-FAIL ARM: a retry that re-sealed (a fresh time, say) would pin
  // another chain; and another chain under the namespace is never written over.
  assert.notEqual(S.caseChain({ ...k, reveals: { a: { ...k.reveals.a, revealed_at: "2026-10-10T10:00:00Z" }, b: { ...k.reveals.b, revealed_at: "2026-10-10T10:00:00Z" } } }), chain);
  const c3 = await committedCase({ over: { scope_digest: sha("conflict") } });
  const p3 = S.pinPaths(c3.id);
  gh.forceFailure(PINS, p3.seq, 1, 502);
  const r3 = await reveal(revealBody(c3.id, c3.a, c3.b));
  assert.equal(r3.body.pin, "commit_unrecorded");
  // Item 2b: the squatter is a well-formed case_seal record (lib/_verdict.js
  // judgeCaseSeal) holding another chain, so it reads as a conflict; one
  // missing the type's auth fields reads as unreadable. Neither is written over.
  const squatter = { ...S._internal.pinRecord(c3.id, "e".repeat(64), Date.parse("2026-10-10T09:00:00Z")) };
  gh.seed(PINS, p3.seq, squatter);
  const w3 = gh.putLog.length;
  const retry3 = await S.anchorCase(c3.id, { keyDocument: KEYS_DOC });
  assert.equal(retry3.pin, "conflict");
  assert.equal(gh.putLog.length, w3, "nothing written over");
  assert.deepEqual(gh.read(PINS, p3.seq), squatter);
  const { auth_level, auth_note, ...partial } = squatter; // eslint-disable-line no-unused-vars
  gh.seed(PINS, p3.seq, partial);
  const retry3b = await S.anchorCase(c3.id, { keyDocument: KEYS_DOC });
  assert.equal(retry3b.pin, "unreadable");
  assert.equal(retry3b.reason, "case_seal_missing_field");
  assert.equal(gh.putLog.length, w3, "nothing written over");
  assert.deepEqual(gh.read(PINS, p3.seq), partial);
});

test("SEAL: a case is sealed once; a reveal that loses the race to another is refused and seals nothing", async () => {
  const { id, a, b } = await committedCase();
  const cpath = C.casePath(id);
  const viaMock = global.fetch;
  let inner = null;
  global.fetch = async (url, o) => {
    if (inner === null && o && o.method === "PUT" && String(url).endsWith(`/contents/${cpath}`)) {
      inner = "running";
      inner = await reveal(revealBody(id, a, b), { now: REVEAL_AT + 1000 });
    }
    return viaMock(url, o);
  };
  let outer;
  try {
    outer = await reveal(revealBody(id, a, b));
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(inner.status, 201, "the inner reveal sealed first");
  assert.equal(outer.status, 409, JSON.stringify(outer.body));
  assert.equal(outer.body.error_code, "not_committed");
  assert.equal(outer.body.status, "VERDICT");
  assert.equal(storedCase(id).reveals.a.revealed_at, "2026-10-10T09:00:01Z", "the winner's seal stands");
  assert.equal(gh.read(PINS, S.pinPaths(id).latest).chain, inner.body.chain);
});

// =============================================================================
// TEST 9: the signature
// =============================================================================

test("TEST 9: the sealed case verifies under lib/_check_record.js's rule with WITNESS_CASE_SIGNER_KEY; an unknown field is refused; any change breaks it", async () => {
  const { id, a, b } = await committedCase();
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 201);
  const k = storedCase(id);
  assert.equal(k.sig_reason, null);
  assert.equal(typeof k.sig, "string");
  assert.deepEqual(r.body.sealed_by, { name: "arcaeon.io/case-test/2026-10-10", verifier: CASE_KEY.verifier, alg: "ed25519" });
  // the rule, by hand: Ed25519 over json-c14n:v1 of the whole case minus sig
  const vk = checkpoint.parseVerifierKey(CASE_KEY.verifier);
  assert.equal(crypto.verify(null, checkRecord.preimage(k), vk.publicKey, Buffer.from(k.sig, "base64")), true);
  // the one signature rule: the sealed check, under the document the case names
  assert.equal((await S.sealedRecordReason(k, KEYS_DOC)).code, "valid_under_document");
  assert.equal(S.caseChain(k), r.body.chain);
  // the four limits and the receipt are inside the signed bytes
  const pre = checkRecord.preimage(k).toString("utf-8");
  for (const l of C.LIMITS) assert.ok(pre.includes(l), l);
  assert.ok(pre.includes(k.verdict.sig), "the receipt, signature and all");

  // what a reader holds a record to: the schema, then the sealed check
  const verdictOf = async (rec) => {
    const v = C.validateCase(rec);
    if (!v.ok) return v.code;
    const answer = await S.sealedRecordReason(rec, KEYS_DOC);
    return answer.code === "valid_under_document" ? "valid" : answer.reason;
  };
  // an unknown field is refused, before any signature is looked at
  assert.equal(await verdictOf({ ...k, anchor: "pending" }), "unknown_field");
  // a change anywhere breaks the signature, or the receipt's binding first
  const plants = {
    bad_signature: [
      { ...k, reveals: { ...k.reveals, b: { ...k.reveals.b, salt_sha256: sha("another salt") } } },
      { ...k, commitments: { ...k.commitments, a: { ...k.commitments.a, stamped_at: "2026-10-10T07:45:00.124Z" } } },
    ],
    // a relabelled party moves the case id, so the schema refuses it first
    case_id_mismatch: [{ ...k, party_b: { ...k.party_b, label: "tool-operator@example.net" } }],
    receipt_time_mismatch: [{ ...k, verdict: { ...k.verdict, compared_at: "2026-10-10T09:00:01Z" } }],
    receipt_tape_a_mismatch: [{ ...k, reveals: { a: { ...k.reveals.a, tape_sha256: k.reveals.b.tape_sha256 }, b: k.reveals.b } }],
  };
  for (const [reason, recs] of Object.entries(plants)) {
    for (const rec of recs) assert.equal(await verdictOf(rec), reason);
  }
  // the receipt key does not verify a case, and the case key does not verify a receipt
  assert.equal(S.signatureReason(k, RECEIPT_KEY.verifier).reason, "bad_signature");
  assert.equal(receipts.verifyReceiptText(T.wireJson(k.verdict), CASE_KEY.verifier).reason, "unknown_signer");
  // MUST-FAIL ARM: on a signed record an added field also breaks the
  // signature (it lands inside the preimage), so the unknown-field fence is
  // shown alone on a record no signature judges: an unsigned seal with an
  // extra field is refused unknown_field, never reported as merely unsigned.
  assert.equal(crypto.verify(null, checkRecord.preimage({ ...k, anchor: "pending" }), vk.publicKey, Buffer.from(k.sig, "base64")), false);
  // (item 2b: an unsigned case carries signed_by null, so the hand-unsigned copy does too)
  const unsignedWithExtra = { ...k, signed_by: null, sig: null, sig_reason: "unsigned in this test", anchor: "pending" };
  assert.equal(await verdictOf(unsignedWithExtra), "unknown_field");
  const { anchor, ...unsignedClean } = unsignedWithExtra; // eslint-disable-line no-unused-vars
  assert.equal(await verdictOf(unsignedClean), "unsigned_seal", "control: without the field it is an unsigned seal, which never verifies");
});

test("TEST 9: with no usable case key nothing is sealed (the one signature rule: an unsigned seal never verifies) and the refusal says why; the log key, the receipt key or an unparseable key is never used to sign", async () => {
  const variants = {
    unset: [{ [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, "case_key_unset", /WITNESS_CASE_SIGNER_KEY is not set/],
    receipt_key: [{ [S.CASE_SIGNER_ENV]: RECEIPT_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, "case_key_is_other_key", /reconcile receipt key/],
    log_key: [{ [S.CASE_SIGNER_ENV]: LOG_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, "case_key_is_other_key", /witness log's key/],
    unparseable: [{ [S.CASE_SIGNER_ENV]: "PRIVATE+KEY+nope", [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, "case_key_unparseable", /does not parse/],
  };
  for (const [name, [env, code, why]] of Object.entries(variants)) {
    const { id, a, b } = await committedCase({ over: { scope_digest: sha(`unsigned ${name}`) } });
    const before = storedCase(id);
    const r = await reveal(revealBody(id, a, b), { env });
    assert.equal(r.status, 503, `${name}: ${JSON.stringify(r.body).slice(0, 300)}`);
    assert.deepEqual([r.body.error_code, r.body.reason], ["case_signer_unavailable", code], name);
    assert.deepEqual(storedCase(id), before, `${name}: nothing sealed, nothing written`);
    const l = S.loadCaseSigner(env, { keyDocument: KEYS_DOC });
    assert.match(l.reason, why, name);
    assert.ok(!l.reason.includes("PRIVATE") && !JSON.stringify(r.body).includes("PRIVATE"), `${name}: the reason never quotes a key`);
  }
  // MUST-FAIL ARM: unsigned with no reason is not a valid case
  const { id, a, b } = await committedCase({ over: { scope_digest: sha("no reason") } });
  await reveal(revealBody(id, a, b), { env: {} });
  assert.equal(C.validateCase({ ...storedCase(id), sig_reason: null }).code, "sig_reason_missing");
});

// =============================================================================
// TEST 12: nothing kept
// =============================================================================

test("TEST 12: the reveal keeps no tape and no salt: no store write, no request and no log line carries one; the sealed case holds salt_sha256 only", async (t) => {
  const { id, a, b } = await committedCase();
  const requests = [];
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    requests.push(`${String(url)} ${o && o.body ? Buffer.from(JSON.parse(o.body).content || "", "base64").toString("utf-8") + o.body : ""}`);
    return viaMock(url, o);
  };
  const logged = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of Object.keys(orig)) console[k] = (...x) => logged.push(x.join(" "));
  t.after(() => {
    global.fetch = viaMock;
    Object.assign(console, orig);
  });
  // a refused reveal (a wrong salt) and an accepted one, both as tape text
  const asText = (p, q, saltA = p.salt) => ({ case_id: id, reveals: { a: { tape_sha256: p.tape_sha256, salt: saltA }, b: { tape_sha256: q.tape_sha256, salt: q.salt } },
    tape_a: p.tape.toString("utf-8"), tape_b: q.tape.toString("utf-8") });
  const wrongSalt = C.newSalt();
  const refused = await reveal(asText(a, b, wrongSalt));
  assert.equal(refused.body.error_code, "commitment_mismatch");
  gh.forceFailure(PINS, S.pinPaths(id).seq, 1, 502); // and a failed pin, which logs
  const r = await reveal(asText(a, b));
  assert.equal(r.status, 201);
  global.fetch = viaMock;
  Object.assign(console, orig);

  assert.ok(requests.length > 0 && requests.every((u) => u.startsWith("https://api.github.com/repos/")), "the store, and nothing else");
  assert.ok(logged.length > 0, "control: the failed pin was logged");
  const tapeLines = [a.tape, b.tape].flatMap((tp) => tp.toString("utf-8").split("\n").filter((l) => l)).map((l) => JSON.parse(l).req).filter(Boolean);
  assert.ok(tapeLines.length >= 5, "fixture: tape content to look for");
  const secrets = [a.salt, b.salt, wrongSalt, a.tape.toString("base64").slice(0, 60), ...tapeLines];
  const surfaces = { "store writes and reads": requests.join("\n"), "log lines": logged.join("\n"), "stored data": storedText() };
  for (const [where, text] of Object.entries(surfaces)) {
    for (const s of secrets) assert.ok(!text.includes(s), `${where} carry ${s.slice(0, 24)}`);
  }
  const stored = storedText();
  assert.ok(stored.includes(C.saltSha256(a.salt)) && stored.includes(C.saltSha256(b.salt)), "the sealed case holds salt_sha256");
  assert.ok(stored.includes(a.tape_sha256), "control: the scan sees the hashes that ARE stored");
  assert.notEqual(C.saltSha256(a.salt), sha(a.salt), "salt_sha256 hashes the salt's bytes, not its hex text");
  assert.equal(C.saltSha256(a.salt), sha(Buffer.from(a.salt, "hex")));
  assert.equal(r.res._headers["cache-control"], "no-store");
});

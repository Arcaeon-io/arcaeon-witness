// test/case_protocol.test.js — the case protocol, wiring item one: lib/_case.js
// (the arcaeon-case/1 schema, the case id rule, the commitment rule) and
// lib/_case_http.js (POST ?op=case-open and ?op=case-commit on api/verify.js).
//
// Numbered as in CASE_PROTOCOL_DESIGN_2026-10-10.md "Tests the worker writes":
// 1 (case id), 2 (commitment bytes), 3 (registration), 4 (many stamps, one
// commitment), 5 (role binding, the registration-time half) and 13 (function
// cap). Tests 6 to 12 belong to item two. Each test plants the failure it
// exists to catch; the break arms run a wrong implementation through the same
// check and demand it be caught. Every store is the in-memory mock: no network.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const T = require("../lib/_reconcile_tapes.js");
const { canonicalBytes } = require("../lib/_check_record.js");
const stamp = require("../lib/_stamp.js");
const verifyHandler = require("../api/verify.js");
const fixtures = require("./fixtures/case/c14n_cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

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

// Each request gets its own caller IP so the shared per-IP limiter never bites.
let ipSeq = 0;
function freshIp() {
  ipSeq += 1;
  return `10.88.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function req(op, body, extra = {}) {
  return makeReq({
    method: "POST",
    query: { op },
    headers: { "content-type": "application/json", "x-forwarded-for": freshIp(), ...(extra.headers || {}) },
    body,
  });
}
async function open(body, now = NOW) {
  const res = makeRes();
  await H.handleCaseOpen(req("case-open", body), res, { now });
  return res;
}
async function commit(body, now = NOW) {
  const res = makeRes();
  await H.handleCaseCommit(req("case-commit", body), res, { now });
  return res;
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
async function openCase(over) {
  const res = await open(opening(over));
  assert.equal(res._status, 201, JSON.stringify(res._body));
  return res._body.case_id;
}

// A stamp record exactly as lib/_stamp.js writes one, in the STAMPS repo.
function plantStamp(hash, stampedAt = "2026-10-10T07:45:00.123Z", repo = STAMPS) {
  gh.seed(repo, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: stampedAt });
}
// A party's local work: hash its tape, draw a salt, compute the commitment.
function party(caseId, role, tapeText, salt = C.newSalt()) {
  const tape_sha256 = sha(tapeText);
  return { role, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
function reg(caseId, p, role = p.role) {
  return { case_id: caseId, role, commitment_sha256: p.commitment_sha256 };
}
function storedCase(caseId) {
  return gh.read(PINS, C.casePath(caseId));
}
function storedText() {
  let out = "";
  for (const [, files] of gh.repos) for (const [, f] of files) out += f.content;
  return out;
}

// =============================================================================
// TEST 1: the case id
// =============================================================================

test("TEST 1: the case id is identical from both parties' inputs under canonical ordering (bytes written by Python json-c14n:v1)", () => {
  assert.equal(fixtures.canonicalizer.function, "arcaeon_ledger.artefact._canon_json");
  assert.equal(fixtures.policy_version, C.SUPPORTED_POLICY_VERSION, "the fixture was made for the port version this service runs");
  assert.ok(fixtures.case_ids.length >= 5);
  let inputs = 0;
  for (const c of fixtures.case_ids) {
    // each case carries both parties' inputs: each lists itself first
    const firsts = new Set(c.inputs.map((i) => i.party_a.label + "|" + i.party_a.side));
    assert.equal(firsts.size, 2, `${c.name}: the fixture holds both orders`);
    for (const inp of c.inputs) {
      inputs += 1;
      assert.ok(C.caseIdBytes(inp).equals(Buffer.from(c.preimage_b64, "base64")), `${c.name}: canonical bytes differ from Python's for ${JSON.stringify(inp)}`);
      assert.equal(C.deriveCaseId(inp), c.case_id, c.name);
    }
  }
  assert.ok(inputs >= 20, `only ${inputs} inputs checked`);
});

test("TEST 1: the id changes when any id field changes; the deadline and a sub-second difference do not move it", () => {
  const base = opening();
  const id = C.deriveCaseId(base);
  const changed = {
    policy_version: { ...base, policy_version: "0.1.1" },
    scope_digest: { ...base, scope_digest: sha("another scope") },
    "party_a.label": { ...base, party_a: { ...AGENT, label: "agent-operator@example.org" } },
    "party_b.label": { ...base, party_b: { ...TOOL, label: "tool-operator@example.org" } },
    "party_a.side": { ...base, party_a: { ...AGENT, side: "tool" } },
    "party_b.key_id added": { ...base, party_b: { ...TOOL, key_id: "ed25519:" + "B".repeat(43) + "=" } },
    opened_at: { ...base, opened_at: "2026-10-10T07:30:01Z" },
  };
  const seen = new Set([id]);
  for (const [what, o] of Object.entries(changed)) {
    const other = C.deriveCaseId(o);
    assert.notEqual(other, id, `changing ${what} must change the case id`);
    seen.add(other);
  }
  assert.equal(seen.size, Object.keys(changed).length + 1, "every change gives its own id");
  // key_id changed (not just added)
  const k1 = C.deriveCaseId({ ...base, party_b: { ...TOOL, key_id: "key-1" } });
  const k2 = C.deriveCaseId({ ...base, party_b: { ...TOOL, key_id: "key-2" } });
  assert.notEqual(k1, k2);
  // protocol_version is inside the preimage, and no other version derives an id under this rule
  assert.match(C.caseIdBytes(base).toString("utf-8"), /"protocol_version":"case\/1"/);
  assert.throws(() => C.deriveCaseId({ ...base, protocol_version: "case/2" }), (e) => e.code === "unsupported_protocol_version");
  // not in the id: the deadline, and anything below a second
  assert.equal(C.deriveCaseId({ ...base, deadline: "2027-01-01T00:00:00Z" }), id);
  assert.equal(C.deriveCaseId({ ...base, opened_at: "2026-10-10T07:30:00.999999Z" }), id);
  assert.equal(C.deriveCaseId({ ...base, opened_at: "2026-10-10T03:30:00-04:00" }), id);
});

test("TEST 1 BREAK ARMS: keeping the caller's order, sorting by UTF-16 code units, or skipping time normalization is caught by the fixture", () => {
  const python = (c) => Buffer.from(c.preimage_b64, "base64");
  const lift = (inp, parties, openedAt) =>
    canonicalBytes({
      protocol_version: inp.protocol_version, policy_version: inp.policy_version, scope_digest: inp.scope_digest,
      party_a: parties[0], party_b: parties[1], opened_at: openedAt,
    });
  const liars = {
    keeps_caller_order: (inp) => lift(inp, [inp.party_a, inp.party_b], C.normalizeUtcSeconds(inp.opened_at)),
    sorts_by_utf16_code_units: (inp) => {
      const ps = [inp.party_a, inp.party_b].slice().sort((p, q) => (p.label < q.label ? -1 : p.label > q.label ? 1 : p.side < q.side ? -1 : 1));
      return lift(inp, ps, C.normalizeUtcSeconds(inp.opened_at));
    },
    skips_time_normalization: (inp) => {
      const ps = C.canonicalParties(inp.party_a, inp.party_b);
      return lift(inp, [ps.party_a, ps.party_b], inp.opened_at);
    },
  };
  const caughtOn = {};
  for (const [name, liar] of Object.entries(liars)) {
    caughtOn[name] = [];
    for (const c of fixtures.case_ids) for (const inp of c.inputs) if (!liar(inp).equals(python(c))) caughtOn[name].push(c.name);
    assert.ok(caughtOn[name].length > 0, `${name} was not caught by any fixture input`);
  }
  assert.ok(caughtOn.sorts_by_utf16_code_units.includes("astral_label_code_point_order"), "the astral label case catches a UTF-16 sort");
  assert.ok(caughtOn.skips_time_normalization.includes("offset_crosses_the_day"), "the offset case catches a skipped normalization");
  // control: the real derivation is caught nowhere
  for (const c of fixtures.case_ids) for (const inp of c.inputs) assert.ok(C.caseIdBytes(inp).equals(python(c)));
});

test("TEST 1: an opening the rule cannot derive one id from is refused, typed", () => {
  const code = (fn) => {
    try {
      fn();
    } catch (e) {
      assert.ok(e instanceof C.CaseError, `not a CaseError: ${e && e.message}`);
      return `${e.code}@${e.field}`;
    }
    return "accepted";
  };
  const v = (over) => () => C.validateOpening(opening(over));
  assert.equal(code(v({ party_b: { ...AGENT, key_id: "k" } })), "parties_not_distinct@party_b", "same label and side cannot be ordered, key_id or not");
  assert.equal(code(v({ deadline: "2026-10-10T07:30:00Z" })), "deadline_not_after_opened_at@deadline");
  assert.equal(code(v({ opened_at: "2026-10-10T07:30:00" })), "malformed_field@opened_at", "a time with no zone is not a UTC time");
  assert.equal(code(v({ opened_at: "2026-02-30T07:30:00Z" })), "malformed_field@opened_at");
  assert.equal(code(v({ opened_at: 1760081400 })), "malformed_field@opened_at");
  assert.equal(code(v({ party_a: { ...AGENT, label: "bad\ud800label" } })), "malformed_field@party_a.label", "a lone surrogate cannot be encoded by json-c14n:v1");
  assert.equal(code(v({ party_a: { ...AGENT, label: "line\nbreak" } })), "malformed_field@party_a.label");
  assert.equal(code(v({ party_a: { ...AGENT, label: "" } })), "malformed_field@party_a.label");
  assert.equal(code(v({ party_a: { ...AGENT, side: "observer" } })), "malformed_field@party_a.side");
  assert.equal(code(v({ party_a: { ...AGENT, role: "a" } })), "unknown_field@party_a.role");
  assert.equal(code(v({ party_a: { ...AGENT, key_id: null } })), "malformed_field@party_a.key_id", "no key id is an absent key, never null");
  assert.equal(code(v({ case_id: "0".repeat(64) })), "unknown_field@case_id");
  assert.equal(code(v({ scope_digest: "AB".repeat(32) })), "malformed_field@scope_digest");
  assert.equal(code(v({ policy_version: "9.9.9" })), "unsupported_policy_version@policy_version");
  assert.equal(code(v({ protocol_version: "case/2" })), "unsupported_protocol_version@protocol_version");
  const missing = opening();
  delete missing.deadline;
  assert.equal(code(() => C.validateOpening(missing)), "missing_field@deadline");
  assert.equal(code(v({})), "accepted", "control: the unmodified opening is accepted");
});

test("TEST 1 THROUGH THE ENDPOINT: each party opening with itself first gets one case id; the second open is case_exists", async () => {
  const fromTool = await open(opening({ party_a: { ...TOOL }, party_b: { ...AGENT } }));
  assert.equal(fromTool._status, 201, JSON.stringify(fromTool._body));
  assert.equal(fromTool._body.ok, true);
  assert.equal(fromTool._body.parties_reordered, true, "the tool listed itself first and is told it was reordered");
  const id = fromTool._body.case_id;
  const k = storedCase(id);
  assert.deepEqual(k.party_a, AGENT, "role a is the party that sorts first");
  assert.deepEqual(k.party_b, TOOL);
  assert.equal(k.status, "OPEN");
  assert.deepEqual(k.commitments, { a: null, b: null });
  assert.deepEqual(k.limits, C.LIMITS.slice());
  assert.equal(k.sig, null);
  assert.equal(k.sig_reason, C.UNSEALED_SIG_REASON);
  assert.deepEqual(C.validateCase(k), { ok: true });
  assert.equal(C.deriveCaseId(k), id, "the stored case derives its own id");
  const writes = gh.putLog.length;

  // the agent's own input: itself first, the time written in its own zone
  const fromAgent = await open(opening({ opened_at: "2026-10-10T09:30:00+02:00" }));
  assert.equal(fromAgent._status, 409);
  assert.equal(fromAgent._body.error_code, "case_exists");
  assert.equal(fromAgent._body.case_id, id, "same opening, same id");
  assert.equal(gh.putLog.length, writes, "the duplicate wrote nothing");
  assert.deepEqual(storedCase(id), k, "the first case is untouched");
});

// =============================================================================
// TEST 2: the commitment
// =============================================================================

test("TEST 2: the commitment's canonical bytes are byte-identical to Python json-c14n:v1, and the hash recomputes", () => {
  assert.equal(fixtures.commitments.length, 4);
  for (const c of fixtures.commitments) {
    assert.equal(c.input.case_id, fixtures.case_ids[0].case_id, "the commitments are for a fixture case");
    const mine = C.commitmentBytes(c.input);
    assert.ok(mine.equals(Buffer.from(c.bytes_b64, "base64")), `${c.name}: Node bytes ${mine.toString()} != Python bytes ${c.bytes_text}`);
    assert.equal(C.commitmentSha256(c.input), c.commitment_sha256, c.name);
    assert.equal(mine.length, c.length);
    assert.equal(mine.length, C.COMMITMENT_BYTES_LENGTH, "a case/1 commitment preimage is always this long");
  }
  // The repo's other json-c14n:v1 implementation (the reconcile receipt's)
  // gives the same bytes on every fixture preimage.
  for (const c of fixtures.case_ids) assert.ok(T.c14nBytes(C.caseIdPreimage(c.inputs[0])).equals(Buffer.from(c.preimage_b64, "base64")), c.name);
  for (const c of fixtures.commitments) assert.ok(T.c14nBytes(C.commitmentPreimage(c.input)).equals(Buffer.from(c.bytes_b64, "base64")), c.name);
});

test("TEST 2: a changed salt, tape hash, role or case id gives a different commitment", () => {
  const by = Object.fromEntries(fixtures.commitments.map((c) => [c.name, c]));
  const base = by.role_a;
  assert.equal(by.role_a_salt_changed.input.tape_sha256, base.input.tape_sha256);
  assert.notEqual(by.role_a_salt_changed.input.salt, base.input.salt);
  assert.notEqual(C.commitmentSha256(by.role_a_salt_changed.input), base.commitment_sha256, "salt");
  assert.notEqual(C.commitmentSha256(by.role_a_tape_changed.input), base.commitment_sha256, "tape hash");
  assert.notEqual(C.commitmentSha256(by.role_b_same_tape_and_salt.input), base.commitment_sha256, "role");
  assert.notEqual(C.commitmentSha256({ ...base.input, case_id: fixtures.case_ids[1].case_id }), base.commitment_sha256, "case id");
  // one changed hex digit of the salt is enough
  const flipped = base.input.salt.slice(0, 63) + (base.input.salt[63] === "0" ? "1" : "0");
  assert.notEqual(C.commitmentSha256({ ...base.input, salt: flipped }), base.commitment_sha256);
  // and the same inputs give the same commitment every time
  assert.equal(C.commitmentSha256({ ...base.input }), base.commitment_sha256);
});

test("TEST 2 BREAK ARMS: a commitment carrying a manifest hash, or serialized unsorted, is not the commitment; bad inputs are refused", () => {
  const c = fixtures.commitments[0];
  const python = Buffer.from(c.bytes_b64, "base64");
  const pre = C.commitmentPreimage(c.input);
  assert.ok(!canonicalBytes({ ...pre, manifest_sha256: sha("manifest") }).equals(python), "a manifest hash in the preimage is caught");
  assert.ok(!Buffer.from(JSON.stringify(pre), "utf-8").equals(python), "insertion-order JSON is caught");
  assert.ok(canonicalBytes(pre).equals(python), "control: the real preimage matches");
  const refused = (input) => {
    try {
      C.commitmentSha256(input);
    } catch (e) {
      return e instanceof C.CaseError ? `${e.code}@${e.field}` : "threw";
    }
    return "accepted";
  };
  assert.equal(refused({ ...c.input, manifest_sha256: sha("m") }), "unknown_field@manifest_sha256", "a manifest hash is refused, not ignored");
  assert.equal(refused({ ...c.input, role: "c" }), "bad_role@role");
  assert.equal(refused({ ...c.input, salt: c.input.salt.toUpperCase() }), "malformed_field@salt");
  assert.equal(refused({ ...c.input, salt: c.input.salt.slice(2) }), "malformed_field@salt", "a salt is 32 bytes");
  assert.equal(refused({ ...c.input, tape_sha256: "" }), "malformed_field@tape_sha256");
  assert.equal(refused({ ...c.input, protocol_version: "case/2" }), "unsupported_protocol_version@protocol_version");
  assert.equal(refused({ ...c.input, protocol_version: "case/1" }), "accepted");
});

// =============================================================================
// TEST 3: registration
// =============================================================================

test("TEST 3: a second registration for the same role is refused role_already_committed; the first one stands", async () => {
  const id = await openCase();
  const first = party(id, "a", "agent tape, the one committed\n");
  const second = party(id, "a", "agent tape, a different one\n");
  plantStamp(first.commitment_sha256);
  plantStamp(second.commitment_sha256);

  const ok = await commit(reg(id, first));
  assert.equal(ok._status, 201, JSON.stringify(ok._body));
  assert.equal(ok._body.ok, true);
  assert.equal(ok._body.status, "OPEN");
  const writes = gh.putLog.length;

  const again = await commit(reg(id, second));
  assert.equal(again._status, 409);
  assert.equal(again._body.ok, false);
  assert.equal(again._body.error_code, "role_already_committed");
  assert.equal(again._body.registered.commitment_sha256, first.commitment_sha256);
  // the same registration a second time is a second registration too
  const replay = await commit(reg(id, first));
  assert.equal(replay._status, 409);
  assert.equal(replay._body.error_code, "role_already_committed");

  assert.equal(gh.putLog.length, writes, "a refused registration writes nothing");
  assert.equal(gh.read(PINS, C.registrationPath(id, "a")).commitment_sha256, first.commitment_sha256);
  assert.equal(storedCase(id).commitments.a.commitment_sha256, first.commitment_sha256);
});

test("TEST 3: a registration at or after the deadline is refused late_commitment and writes nothing", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  plantStamp(a.commitment_sha256);
  const deadlineMs = Date.parse(DEADLINE);
  const writes = gh.putLog.length;
  for (const now of [deadlineMs, deadlineMs + 1, deadlineMs + 86400000]) {
    const late = await commit(reg(id, a), now);
    assert.equal(late._status, 409, String(now));
    assert.equal(late._body.error_code, "late_commitment");
    assert.equal(late._body.deadline, DEADLINE);
  }
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
  // control: one second before the deadline is in time
  const inTime = await commit(reg(id, a), deadlineMs - 1000);
  assert.equal(inTime._status, 201, JSON.stringify(inTime._body));
  assert.equal(inTime._body.registration.registered_at, "2026-10-10T19:59:59Z");
});

test("TEST 3: a commitment hash with no stamp is refused no_commitment and writes nothing; a stamp-shaped file in the pins repo does not count", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  const writes = gh.putLog.length;
  const none = await commit(reg(id, a));
  assert.equal(none._status, 404);
  assert.equal(none._body.error_code, "no_commitment");
  // planted in the WRONG repository: the read is the stamp read path, the stamps repo only
  plantStamp(a.commitment_sha256, "2026-10-10T07:45:00.123Z", PINS);
  const wrongRepo = await commit(reg(id, a));
  assert.equal(wrongRepo._status, 404);
  assert.equal(wrongRepo._body.error_code, "no_commitment");
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
  // control: stamped where stamps live, it registers
  plantStamp(a.commitment_sha256);
  assert.equal((await commit(reg(id, a)))._status, 201);
});

test("TEST 3: stamp fields come from the fetched stamp record; a caller's stamped_at, commit or record_url is refused, never used", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  const STAMPED = "2026-10-10T07:41:17.456Z"; // distinct from every clock in this test
  plantStamp(a.commitment_sha256, STAMPED);
  const writes = gh.putLog.length;
  for (const forged of [
    { stamped_at: "2026-01-01T00:00:00.000Z" },
    { stamp_commit: "f".repeat(40) },
    { commit: "f".repeat(40) },
    { record_url: "https://github.com/x/y/blob/main/stamps/aa/x.json" },
    { registered_at: "2026-10-10T00:00:00Z" },
  ]) {
    const res = await commit({ ...reg(id, a), ...forged });
    const field = Object.keys(forged)[0];
    assert.equal(res._status, 400, field);
    assert.equal(res._body.error_code, "unknown_field", field);
    assert.equal(res._body.field, field);
  }
  assert.equal(gh.putLog.length, writes, "a forged field writes nothing");

  const ok = await commit(reg(id, a));
  assert.equal(ok._status, 201, JSON.stringify(ok._body));
  const r = gh.read(PINS, C.registrationPath(id, "a"));
  assert.deepEqual(Object.keys(r).sort(), [...C.REGISTRATION_FIELDS].sort());
  assert.equal(r.kind, "case-commitment");
  assert.equal(r.stamped_at, STAMPED, "stamped_at is the fetched record's, verbatim");
  assert.equal(r.registered_at, "2026-10-10T08:00:00Z", "registered_at is this service's clock");
  assert.equal(r.stamp_commit, null, "the stamp record carries no commit, so none is recorded");
  assert.deepEqual(storedCase(id).commitments.a, {
    commitment_sha256: a.commitment_sha256, registered_at: "2026-10-10T08:00:00Z", stamp_commit: null, stamped_at: STAMPED,
  });
});

test("TEST 3: a stored stamp that is not a file-stamp for this hash is refused, not trusted, and writes nothing", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  const plants = {
    not_a_file_stamp: { kind: "pin", v: 1, sha256: a.commitment_sha256, size: 1, stamped_at: "2026-10-10T07:00:00.000Z" },
    unknown_stamp_version: { kind: "file-stamp", v: 2, sha256: a.commitment_sha256, size: 1, stamped_at: "2026-10-10T07:00:00.000Z" },
    sha256_mismatch: { kind: "file-stamp", v: 1, sha256: "e".repeat(64), size: 1, stamped_at: "2026-10-10T07:00:00.000Z" },
    stamped_at_unreadable: { kind: "file-stamp", v: 1, sha256: a.commitment_sha256, size: 1, stamped_at: "yesterday" },
  };
  const writes = gh.putLog.length;
  for (const [reason, rec] of Object.entries(plants)) {
    gh.seed(STAMPS, stamp.stampPath(a.commitment_sha256), rec);
    const res = await commit(reg(id, a));
    assert.equal(res._status, 503, reason);
    assert.equal(res._body.error_code, "stamp_record_unreadable", reason);
    assert.equal(res._body.reason, reason);
  }
  assert.equal(gh.putLog.length, writes);
});

test("TEST 3: a role not a or b, an unknown case, a case not OPEN or COMMITTED, a damaged case: each typed, none writes", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  plantStamp(a.commitment_sha256);
  const writes = gh.putLog.length;
  for (const role of ["c", "A", "", 1, null]) {
    const res = await commit({ ...reg(id, a), role });
    assert.equal(res._status, 400, String(role));
    assert.equal(res._body.error_code, "bad_role");
  }
  const unknown = await commit({ ...reg(id, a), case_id: "9".repeat(64) });
  assert.equal(unknown._status, 404);
  assert.equal(unknown._body.error_code, "case_not_found");

  // A VERDICT case and a WITHDRAWN (redacted) case, both valid records.
  const opened = C.validateOpening(opening({ scope_digest: sha("verdict case") })).opening;
  const vid = C.deriveCaseId(opened);
  const entry = (h) => ({ commitment_sha256: h, registered_at: "2026-10-10T07:50:00Z", stamp_commit: null, stamped_at: "2026-10-10T07:49:00.000Z" });
  const reveal = { tape_sha256: sha("t"), salt_sha256: sha("s"), revealed_at: "2026-10-10T08:10:00Z" };
  const verdictCase = { ...C.newCase(opened, vid), commitments: { a: entry(sha("1")), b: entry(sha("2")) }, reveals: { a: reveal, b: reveal },
    verdict: { kind: "arcaeon-reconcile-receipt" }, status: "VERDICT" };
  assert.deepEqual(C.validateCase(verdictCase), { ok: true }, "fixture: the planted VERDICT case is a valid record");
  gh.seed(PINS, C.casePath(vid), verdictCase);
  const wid = C.deriveCaseId(C.validateOpening(opening({ scope_digest: sha("withdrawn case") })).opening);
  const withdrawn = { v: 1, case_id: wid, protocol_version: "case/1", status: "WITHDRAWN", opened_at: "2026-10-10T07:30:00Z",
    withdrawal: { by_role: "b", at: "2026-10-10T07:55:00Z" }, limits: C.LIMITS.slice(), sig: null, sig_reason: "unsigned in this test" };
  assert.deepEqual(C.validateCase(withdrawn), { ok: true }, "fixture: the planted WITHDRAWN record is valid");
  gh.seed(PINS, C.casePath(wid), withdrawn);
  for (const [cid, status] of [[vid, "VERDICT"], [wid, "WITHDRAWN"]]) {
    const h = party(cid, "a", "agent tape\n");
    plantStamp(h.commitment_sha256);
    const res = await commit(reg(cid, h));
    assert.equal(res._status, 409, status);
    assert.equal(res._body.error_code, "case_not_open");
    assert.equal(res._body.status, status);
  }

  // A stored case with a field the schema does not know is not read as a case.
  const did = C.deriveCaseId(C.validateOpening(opening({ scope_digest: sha("damaged case") })).opening);
  const damaged = { ...C.newCase(C.validateOpening(opening({ scope_digest: sha("damaged case") })).opening, did), anchor: "pending" };
  gh.seed(PINS, C.casePath(did), damaged);
  const d = party(did, "a", "agent tape\n");
  plantStamp(d.commitment_sha256);
  const dres = await commit(reg(did, d));
  assert.equal(dres._status, 503);
  assert.equal(dres._body.error_code, "case_record_unreadable");
  assert.equal(dres._body.reason, "case_unknown_field");

  assert.equal(gh.putLog.length, writes, "no refusal wrote anything");
});

test("TEST 3: a malformed request is a typed 4xx, never a 500 and never a write", async () => {
  const writes = gh.putLog.length;
  const raw = async (handler, body, headers) => {
    const res = makeRes();
    await handler(makeReq({ method: "POST", headers: { "x-forwarded-for": freshIp(), ...headers }, body }), res, { now: NOW });
    return res;
  };
  const cases = [
    [{ "content-type": "application/json" }, "{not json", 400, "malformed_json"],
    [{ "content-type": "text/plain" }, "{}", 415, "unsupported_media_type"],
    [{ "content-type": "application/json" }, null, 400, "malformed_body"],
    [{ "content-type": "application/json" }, [], 400, "not_an_object"],
    [{ "content-type": "application/json", "content-length": "999999" }, {}, 413, "too_large"],
    [{ "content-type": "application/json" }, {}, 400, "missing_field"],
  ];
  for (const handler of [H.handleCaseOpen, H.handleCaseCommit]) {
    for (const [headers, body, status, code] of cases) {
      const res = await raw(handler, body, headers);
      assert.equal(res._status, status, `${handler.name} ${code}`);
      assert.equal(res._body.ok, false);
      assert.equal(res._body.error_code, code, `${handler.name}: ${JSON.stringify(res._body)}`);
    }
    const get = makeRes();
    await handler(makeReq({ method: "GET", headers: { "x-forwarded-for": freshIp() } }), get, { now: NOW });
    assert.equal(get._status, 405);
    assert.equal(get._body.error_code, "method_not_allowed");
  }
  // the clock rules of an opening
  const future = await open(opening({ opened_at: "2026-10-10T08:05:01Z" }));
  assert.equal(future._status, 400);
  assert.equal(future._body.error_code, "future_dated");
  const passed = await open(opening({ opened_at: "2026-10-09T07:00:00Z", deadline: "2026-10-10T07:59:59Z" }));
  assert.equal(passed._status, 400);
  assert.equal(passed._body.error_code, "deadline_passed");
  assert.equal(gh.putLog.length, writes);
});

test("TEST 3, TWO WRITES: a registration whose case update fails is recorded and says so; the same registration completes it, a different one is refused", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  const other = party(id, "a", "another agent tape\n");
  plantStamp(a.commitment_sha256);
  plantStamp(other.commitment_sha256);
  gh.forceFailure(PINS, C.casePath(id), 1, 500);

  const broken = await commit(reg(id, a));
  assert.equal(broken._status, 503);
  assert.equal(broken._body.error_code, "case_update_failed");
  assert.equal(broken._body.registration_recorded, true);
  assert.equal(gh.read(PINS, C.registrationPath(id, "a")).commitment_sha256, a.commitment_sha256, "the registration file landed");
  assert.equal(storedCase(id).commitments.a, null, "the case object did not");

  // the registration file is the authority: a different hash is refused before the case shows anything
  const swap = await commit(reg(id, other));
  assert.equal(swap._status, 409);
  assert.equal(swap._body.error_code, "role_already_committed");
  assert.equal(swap._body.registered.commitment_sha256, a.commitment_sha256);

  // the same registration completes it, even after the deadline: it was received before
  const late = Date.parse(DEADLINE) + 3600000;
  const done = await commit(reg(id, a), late);
  assert.equal(done._status, 200, JSON.stringify(done._body));
  assert.equal(done._body.existing, true);
  assert.equal(storedCase(id).commitments.a.registered_at, "2026-10-10T08:00:00Z", "the first write's time, not the retry's");
  assert.deepEqual(C.validateCase(storedCase(id)), { ok: true });
});

test("TEST 3: both roles registered -> COMMITTED, and a registration that lands between another's read and write is merged, not overwritten", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  const b = party(id, "b", "tool tape\n");
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const cpath = C.casePath(id);
  const viaMock = global.fetch;
  let bStatus = null;
  global.fetch = async (url, o) => {
    // Role a's case update is about to be sent with the sha it read; land
    // role b's whole registration first, so a's PUT is stale.
    if (bStatus === null && o && o.method === "PUT" && String(url).endsWith(`/contents/${cpath}`)) {
      bStatus = "running";
      bStatus = (await commit(reg(id, b)))._status;
    }
    return viaMock(url, o);
  };
  let resA;
  try {
    resA = await commit(reg(id, a));
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(bStatus, 201, "role b registered in between");
  assert.equal(resA._status, 201, JSON.stringify(resA._body));
  assert.equal(resA._body.status, "COMMITTED");
  const k = storedCase(id);
  assert.equal(k.status, "COMMITTED");
  assert.equal(k.commitments.a.commitment_sha256, a.commitment_sha256);
  assert.equal(k.commitments.b.commitment_sha256, b.commitment_sha256, "b's registration was not overwritten by a's stale write");
  assert.deepEqual(C.validateCase(k), { ok: true });
});

// =============================================================================
// TEST 4: many stamps, one commitment (Gemini)
// =============================================================================

test("TEST 4: fifty stamped hashes for one role; only the first REGISTERED counts and every later registration is refused", async () => {
  const id = await openCase();
  const cands = [];
  for (let i = 0; i < 50; i += 1) {
    const p = party(id, "a", `agent tape variant ${i}\n`);
    // stamped in order, a minute apart: index 0 is the earliest stamp
    plantStamp(p.commitment_sha256, new Date(Date.parse("2026-10-10T07:00:00Z") + i * 60000).toISOString());
    cands.push(p);
  }
  assert.equal(new Set(cands.map((p) => p.commitment_sha256)).size, 50);
  const FIRST = 37; // not the earliest stamp: registration order is what counts
  const ok = await commit(reg(id, cands[FIRST]));
  assert.equal(ok._status, 201, JSON.stringify(ok._body));
  const writes = gh.putLog.length;
  for (let i = 0; i < 50; i += 1) {
    if (i === FIRST) continue;
    const res = await commit(reg(id, cands[i]));
    assert.equal(res._status, 409, `candidate ${i}`);
    assert.equal(res._body.error_code, "role_already_committed", `candidate ${i}`);
  }
  assert.equal(gh.putLog.length, writes, "49 refusals, 0 writes");
  const registered = storedCase(id).commitments.a.commitment_sha256;
  assert.equal(registered, cands[FIRST].commitment_sha256);
  assert.equal(gh.read(PINS, C.registrationPath(id, "a")).commitment_sha256, registered);
  // The comparison the joint reveal (item two) makes: only the registered
  // candidate's tape and salt recompute the registered commitment. Every
  // other one would be commitment_mismatch.
  const recomputesIt = cands.filter((p) => C.commitmentSha256({ case_id: id, role: "a", tape_sha256: p.tape_sha256, salt: p.salt }) === registered);
  assert.deepEqual(recomputesIt, [cands[FIRST]]);
  // and role b is untouched by all of it
  const b = party(id, "b", "tool tape\n");
  plantStamp(b.commitment_sha256);
  const resB = await commit(reg(id, b));
  assert.equal(resB._status, 201);
  assert.equal(resB._body.status, "COMMITTED");
});

// =============================================================================
// TEST 5: role binding, the registration-time half (GPT)
// =============================================================================

test("TEST 5: a commitment registered to role a cannot be registered to role b", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  plantStamp(a.commitment_sha256);
  assert.equal((await commit(reg(id, a)))._status, 201);
  const writes = gh.putLog.length;
  const asB = await commit(reg(id, a, "b"));
  assert.equal(asB._status, 409);
  assert.equal(asB._body.error_code, "commitment_registered_to_other_role");
  assert.equal(asB._body.other_role, "a");
  assert.equal(gh.putLog.length, writes, "nothing written for b");
  assert.equal(gh.has(PINS, C.registrationPath(id, "b")), false);
  assert.equal(storedCase(id).commitments.b, null);
  assert.equal(storedCase(id).status, "OPEN");
});

test("TEST 5, STATED LIMIT: into an empty b slot a role-a commitment registers (the service sees a hash, not its role); it is bound to b and can never recompute there", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  plantStamp(a.commitment_sha256);
  const asB = await commit(reg(id, a, "b"));
  assert.equal(asB._status, 201, "registration cannot read the role inside a hash");
  const r = gh.read(PINS, C.registrationPath(id, "b"));
  assert.equal(r.role, "b", "the role is bound in the record");
  assert.equal(storedCase(id).commitments.b.commitment_sha256, a.commitment_sha256);
  // The reveal-time half (item two): recomputed under the REGISTERED role, the
  // preimage that says "a" does not give the registered hash.
  const underB = C.commitmentSha256({ case_id: id, role: "b", tape_sha256: a.tape_sha256, salt: a.salt });
  const underA = C.commitmentSha256({ case_id: id, role: "a", tape_sha256: a.tape_sha256, salt: a.salt });
  assert.notEqual(underB, r.commitment_sha256, "a role-a preimage cannot match a role-b registration");
  assert.equal(underA, r.commitment_sha256);
  // and once it holds b, it cannot also take a
  const asA = await commit(reg(id, a, "a"));
  assert.equal(asA._status, 409);
  assert.equal(asA._body.error_code, "commitment_registered_to_other_role");
});

test("TEST 5: no tape and no salt is held anywhere, and a registration that carries a salt is refused", async () => {
  const id = await openCase();
  const a = party(id, "a", "agent tape\n");
  const b = party(id, "b", "tool tape\n");
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const salted = await commit({ ...reg(id, a), salt: a.salt });
  assert.equal(salted._status, 400);
  assert.equal(salted._body.error_code, "unknown_field");
  const taped = await commit({ ...reg(id, a), tape_sha256: a.tape_sha256 });
  assert.equal(taped._status, 400);
  assert.equal(taped._body.error_code, "unknown_field");
  assert.equal((await commit(reg(id, a)))._status, 201);
  assert.equal((await commit(reg(id, b)))._status, 201);
  const all = storedText();
  for (const secret of [a.salt, b.salt, a.tape_sha256, b.tape_sha256, "agent tape", "tool tape"]) {
    assert.ok(!all.includes(secret), `stored data holds ${secret.slice(0, 16)}`);
  }
  assert.ok(all.includes(a.commitment_sha256), "control: the scan sees what IS stored");
});

// =============================================================================
// SCHEMA (item one, part A): the case object refuses what it does not know
// =============================================================================

test("SCHEMA: an unknown field, an altered limit, a stored EXPIRED, a wrong id, a reordered party or an unexplained null sig is refused", () => {
  const opened = C.validateOpening(opening()).opening;
  const good = C.newCase(opened);
  assert.deepEqual(C.validateCase(good), { ok: true });
  const plants = {
    unknown_field: { ...good, anchor: "pending" },
    limits_altered: { ...good, limits: C.LIMITS.slice(0, 3) },
    malformed_field: { ...good, status: "EXPIRED" },
    case_id_mismatch: { ...good, case_id: "0".repeat(64) },
    parties_not_canonical: { ...good, party_a: good.party_b, party_b: good.party_a },
    sig_reason_missing: { ...good, sig_reason: null },
    status_inconsistent: { ...good, status: "COMMITTED" },
    missing_field: (() => { const x = { ...good }; delete x.records; return x; })(),
    unknown_version: { ...good, v: 2 },
  };
  for (const [code, rec] of Object.entries(plants)) {
    const r = C.validateCase(rec);
    assert.equal(r.ok, false, code);
    assert.equal(r.code, code, `${code}: got ${JSON.stringify(r)}`);
  }
  // a redacted withdrawal that still carries a label is not the redacted form
  const withdrawn = { v: 1, case_id: good.case_id, protocol_version: "case/1", status: "WITHDRAWN", opened_at: good.opened_at,
    withdrawal: { by_role: "a", at: "2026-10-10T07:40:00Z" }, limits: C.LIMITS.slice(), sig: null, sig_reason: "x" };
  assert.deepEqual(C.validateCase(withdrawn), { ok: true });
  assert.equal(C.validateCase({ ...withdrawn, party_a: good.party_a }).code, "unknown_field");
  assert.equal(C.validateCase({ ...withdrawn, commitments: good.commitments }).code, "unknown_field");
});

// =============================================================================
// TEST 13: function cap
// =============================================================================

test("TEST 13: api/ still has twelve files, none of them a case function, and verify.js dispatches both case ops", async () => {
  const apiDir = path.join(__dirname, "..", "api");
  const fns = fs.readdirSync(apiDir).filter((f) => f.endsWith(".js") && !f.startsWith("_"));
  assert.equal(fns.length, 12, fns.join(", "));
  assert.equal(fs.readdirSync(apiDir).length, 12, "nothing else was added to api/ either");
  assert.ok(!fns.some((f) => /case/i.test(f)), fns.join(", "));

  // Through the real dispatch, on the real clock.
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
  const o = opening({ opened_at: iso(now - 60000), deadline: iso(now + 86400000), scope_digest: sha("routing") });
  const resOpen = makeRes();
  await verifyHandler(req("case-open", o), resOpen);
  assert.equal(resOpen._status, 201, JSON.stringify(resOpen._body));
  const id = resOpen._body.case_id;
  const a = party(id, "a", "agent tape\n");
  plantStamp(a.commitment_sha256, new Date(now - 30000).toISOString());
  const resCommit = makeRes();
  await verifyHandler(req("case-commit", reg(id, a)), resCommit);
  assert.equal(resCommit._status, 201, JSON.stringify(resCommit._body));
  assert.equal(gh.read(PINS, C.registrationPath(id, "a")).commitment_sha256, a.commitment_sha256);
  // a GET to a case op is a typed refusal, not verify's single-item lookup
  const resGet = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "case-commit" }, headers: { "x-forwarded-for": freshIp() } }), resGet);
  assert.equal(resGet._status, 405);
  assert.equal(resGet._body.error_code, "method_not_allowed");
});

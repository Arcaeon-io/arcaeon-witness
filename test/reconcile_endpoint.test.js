// test/reconcile_endpoint.test.js — POST /api/reconcile (api/verify.js
// ?op=reconcile, lib/_reconcile_http.js) and GET /reconcile.
//
// Failure-first, the house way: most tests hand the endpoint a bad request or
// a bad pair of tapes and demand the right refusal or the right non-green
// verdict. Break arms: a lying reconcile that always says MATCHED, a forged
// call id, a truncated tape. Every refusal is a typed 4xx, never a 500.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const verifyHandler = require("../api/verify.js");
const T = require("../lib/_reconcile_tapes.js");
const H = require("../lib/_reconcile_http.js");
const checkpoint = require("../lib/_checkpoint.js");
const receipts = require("../lib/_reconcile_receipt.js");
const fixtures = require("./fixtures/reconcile/cases.json");

const { pyLoads, pyDumps, chainOf } = T._internal;

// Each test gets its own caller IP so the shared per-IP limiter never bites.
let ipSeq = 0;
function freshIp() {
  ipSeq += 1;
  return `10.77.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}

function jsonReq(body, headers = {}) {
  return makeReq({
    method: "POST",
    query: { op: "reconcile" },
    headers: { "content-type": "application/json", "x-forwarded-for": freshIp(), ...headers },
    body,
  });
}

async function call(req) {
  const res = makeRes();
  await verifyHandler(req, res);
  let parsed = res._body;
  if (typeof parsed === "string" && /json/.test(String(res._headers["content-type"] || ""))) {
    parsed = JSON.parse(parsed);
  }
  return { res, status: res._status, body: parsed, raw: res._body };
}

function caseNamed(re) {
  const c = fixtures.cases.find((x) => re.test(x.name) && x.python);
  assert.ok(c, `fixture has a case matching ${re}`);
  return c;
}

// An honest cross-repo pair: the adapter's agent tape and call_proxy's tool
// tape from the receipt repo's clean cross-repo run (MATCHED 5 of 5).
const CLEAN = caseNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/);
const AGENT = Buffer.from(CLEAN.a_b64, "base64");
const TOOL = Buffer.from(CLEAN.b_b64, "base64");

// Re-chain a tape after editing its rows, the way Ledger.append writes a row
// (json.dumps(obj, ensure_ascii=False), keys in insertion order). The chain
// function is the port's, which the conformance suite holds to the Python's.
function rewrite(buf, edit) {
  const rows = buf.toString("utf-8").split("\n").filter((l) => l.trim()).map((l) => pyLoads(l, false));
  const edited = edit(rows);
  let prev = "genesis";
  const out = [];
  for (const r of edited) {
    r.delete("chain");
    const c = chainOf(prev, r);
    r.set("chain", c);
    prev = c;
    out.push(pyDumps(r, { sortKeys: false, itemSep: ", ", keySep: ": ", ascii: false, allowNan: true }));
  }
  return Buffer.from(out.join("\n") + "\n", "utf-8");
}

// -- the green is reachable -----------------------------------------------------

test("POSITIVE CONTROL: the clean cross-repo pair is MATCHED 5 of 5, as reconcile.py said", async () => {
  const { status, body } = await call(jsonReq({ agent_tape: AGENT.toString("utf-8"), tool_tape: TOOL.toString("utf-8") }));
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.verdict.verdict, "MATCHED");
  assert.equal(body.verdict.summary, "MATCHED 5 of 5");
  assert.equal(JSON.parse(CLEAN.python).summary, "MATCHED 5 of 5");
});

test("CONFORMANCE THROUGH THE ENDPOINT: the verdict field is reconcile.py's dict, byte for byte, on every fixture pair", async () => {
  let n = 0;
  for (const c of fixtures.cases) {
    assert.equal(typeof c.python, "string", c.name);
    const req = jsonReq({ agent_tape_b64: c.a_b64, tool_tape_b64: c.b_b64 });
    const { status, raw } = await call(req);
    assert.equal(status, 200, c.name);
    const verdict = pyLoads(raw, false).get("verdict");
    const mine = pyDumps(verdict, { sortKeys: true, itemSep: ",", keySep: ":", ascii: true, allowNan: false });
    assert.equal(mine, c.python, c.name);
    n += 1;
  }
  assert.ok(n > 400, `only ${n} cases went through the endpoint`);
});

test("CONTRACT: the answer names the first divergence and every finding, and carries reconcile.py's limits", async () => {
  const c = caseNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_answer_changed0: agent vs tool$/);
  const { body } = await call(jsonReq({ agent_tape_b64: c.a_b64, tool_tape_b64: c.b_b64 }));
  assert.equal(body.verdict.verdict, "ALTERED");
  assert.equal(body.verdict.at, 2);
  assert.match(body.verdict.summary, /^ALTERED at call 2: call 2: same request, different response/);
  assert.equal(body.verdict.findings[0].at, 2);
  assert.deepEqual(body.verdict.limits, T.LIMITS);
  assert.deepEqual(body.service_limits, H.SERVICE_LIMITS);
  assert.ok(body.service_limits.some((s) => /operator-owned tape is not an outside witness/.test(s)));
  assert.ok(body.service_limits.some((s) => /saw only the two tapes submitted/.test(s)));
});

// -- break arms -------------------------------------------------------------------

test("BREAK ARM: a lying reconcile that always says MATCHED is caught by the endpoint conformance check", async (t) => {
  const real = T.reconcileTapes;
  t.after(() => { T.reconcileTapes = real; });
  T.reconcileTapes = (a, b) => ({ ...real(a, b), verdict: "MATCHED", summary: "MATCHED 0 of 0", at: null, side: null,
    findings: [], could_not_look: [], exit_code: 0 });
  let caught = 0;
  for (const c of fixtures.cases) {
    if (!c.python || JSON.parse(c.python).verdict === "MATCHED") continue;
    const { raw } = await call(jsonReq({ agent_tape_b64: c.a_b64, tool_tape_b64: c.b_b64 }));
    const v = pyLoads(raw, false).get("verdict");
    if (pyDumps(v, { sortKeys: true, itemSep: ",", keySep: ":", ascii: true, allowNan: false }) !== c.python) caught += 1;
  }
  assert.ok(caught > 100, `the liar was caught on only ${caught} cases`);
});

test("BREAK ARM: a forged call index, not re-chained, is ALTERED at that row (the chain breaks)", async () => {
  const lines = AGENT.toString("utf-8").split("\n");
  lines[2] = lines[2].replace(/"idx": 3\b/, '"idx": 4');
  assert.ok(lines[2].includes('"idx": 4'), "the forgery landed");
  const { body } = await call(jsonReq({ agent_tape: lines.join("\n"), tool_tape: TOOL.toString("utf-8") }));
  assert.equal(body.verdict.verdict, "ALTERED");
  assert.equal(body.verdict.at, 3);
  assert.equal(body.verdict.side, "agent");
  assert.match(body.verdict.reason, /line 3: chain mismatch/);
});

test("BREAK ARM: a forged call index, re-chained so the chain verifies, is still caught by the index walk", async () => {
  const forged = rewrite(AGENT, (rows) => {
    rows[2].set("idx", 4n); // call 3 claims to be call 4
    return rows;
  });
  const { body } = await call(jsonReq({ agent_tape_b64: forged.toString("base64"), tool_tape_b64: TOOL.toString("base64") }));
  assert.notEqual(body.verdict.verdict, "MATCHED");
  assert.equal(body.verdict.verdict, "MISSING");
  assert.equal(body.verdict.at, 3);
  assert.match(body.verdict.reason, /agent tape skips from call 2 to call 4/);
  // a duplicated index, re-chained
  const dup = rewrite(AGENT, (rows) => { rows[3].set("idx", 3n); return rows; });
  const d = (await call(jsonReq({ agent_tape_b64: dup.toString("base64"), tool_tape_b64: TOOL.toString("base64") }))).body;
  assert.equal(d.verdict.verdict, "ALTERED");
  assert.match(d.verdict.reason, /records call 3 twice/);
});

test("BREAK ARM: a boolean or float call index is not a call index (COULD NOT LOOK, never MATCHED)", async () => {
  for (const bad of [true, new T._internal.PyFloat(1)]) {
    const forged = rewrite(AGENT, (rows) => { rows[0].set("idx", bad); return rows; });
    const { body } = await call(jsonReq({ agent_tape_b64: forged.toString("base64"), tool_tape_b64: TOOL.toString("base64") }));
    assert.equal(body.verdict.verdict, "COULD_NOT_LOOK");
    assert.match(body.verdict.reason, /row 1 is not an arcaeon-tape\/1 row/);
  }
});

test("BREAK ARM: an answer paired to an invalid-id call on one tape only is MISSING (the response), not MATCHED", async () => {
  // The tool side keeps call 2 as invalid_id (resp null) while the agent tape
  // recorded an answer: the old mis-pairing, now visible.
  const forged = rewrite(TOOL, (rows) => {
    rows[1].set("rpc_id", "true").set("resp", null).set("status", "invalid_id");
    return rows;
  });
  const { body } = await call(jsonReq({ agent_tape_b64: AGENT.toString("base64"), tool_tape_b64: forged.toString("base64") }));
  assert.equal(body.verdict.verdict, "MISSING");
  assert.equal(body.verdict.at, 2);
  assert.equal(body.verdict.side, "tool");
});

test("LIMIT, STATED: a re-numbered rpc_id alone still MATCHES (ids are outside both digests; a relay may renumber)", async () => {
  const renum = rewrite(TOOL, (rows) => { rows[0].set("rpc_id", "999"); return rows; });
  const { body } = await call(jsonReq({ agent_tape_b64: AGENT.toString("base64"), tool_tape_b64: renum.toString("base64") }));
  assert.equal(body.verdict.verdict, "MATCHED");
});

test("BREAK ARM: a truncated tape is caught: rows cut is MISSING, a row cut mid-line is ALTERED", async () => {
  const lines = TOOL.toString("utf-8").split("\n").filter((l) => l);
  const cut = lines.slice(0, 3).join("\n") + "\n";
  const a = (await call(jsonReq({ agent_tape: AGENT.toString("utf-8"), tool_tape: cut }))).body;
  assert.equal(a.verdict.verdict, "MISSING");
  assert.equal(a.verdict.at, 4);
  assert.equal(a.verdict.side, "tool");

  const torn = TOOL.subarray(0, TOOL.length - 40);
  const b = (await call(jsonReq({ agent_tape_b64: AGENT.toString("base64"), tool_tape_b64: torn.toString("base64") }))).body;
  assert.equal(b.verdict.verdict, "ALTERED");
  assert.match(b.verdict.reason, /tool tape does not verify \(line 5: unparseable\)/);
});

test("LIMIT, STATED: both tapes cut at the same call still MATCH, and the answer says a pin was not checked", async () => {
  const al = AGENT.toString("utf-8").split("\n").filter((l) => l).slice(0, 3).join("\n");
  const tl = TOOL.toString("utf-8").split("\n").filter((l) => l).slice(0, 3).join("\n");
  const { body } = await call(jsonReq({ agent_tape: al, tool_tape: tl }));
  assert.equal(body.verdict.verdict, "MATCHED");
  assert.ok(body.service_limits.some((s) => /No witness pin was checked/.test(s)));
  assert.ok(body.receipt.does_not_claim.some((s) => /No witness pin was checked/.test(s)));
});

// -- size caps --------------------------------------------------------------------

test("SIZE CAP: a tape over the per-tape cap is refused 413 tape_too_large, before any comparison", async (t) => {
  const real = T.reconcileTapes;
  let ran = false;
  T.reconcileTapes = (...a) => { ran = true; return real(...a); };
  t.after(() => { T.reconcileTapes = real; });
  const big = "x".repeat(H.TAPE_MAX_BYTES + 1);
  const { status, body } = await call(jsonReq({ agent_tape: big, tool_tape: "" }));
  assert.equal(status, 413);
  assert.equal(body.error_code, "tape_too_large");
  assert.equal(body.cap_bytes, H.TAPE_MAX_BYTES);
  assert.equal(ran, false);
  const exact = await call(jsonReq({ agent_tape: "x".repeat(H.TAPE_MAX_BYTES), tool_tape: "" }));
  assert.equal(exact.status, 200, "exactly at the cap is compared");
});

test("SIZE CAP: a declared body over the cap is refused 413 too_large without reading it", async () => {
  const { status, body } = await call(jsonReq({ agent_tape: "", tool_tape: "" }, { "content-length": String(H.BODY_MAX_BYTES + 1) }));
  assert.equal(status, 413);
  assert.equal(body.error_code, "too_large");
});

test("SIZE CAP: a streamed body that runs past the cap is refused 413 too_large", async () => {
  const raw = Buffer.alloc(H.BODY_MAX_BYTES + 10, 0x61);
  const req = makeRawReq({ method: "POST", headers: { "content-type": "multipart/form-data; boundary=x", "x-forwarded-for": freshIp() }, rawBody: raw });
  req.query = { op: "reconcile" };
  const { status, body } = await call(req);
  assert.equal(status, 413);
  assert.equal(body.error_code, "too_large");
});

// -- malformed input gives a typed reason, never a 500 ------------------------------

const MALFORMED = [
  ["an array body", [1, 2], 400, "malformed_body"],
  ["a missing tool tape", { agent_tape: "" }, 400, "missing_tape"],
  ["a missing agent tape", { tool_tape: "" }, 400, "missing_tape"],
  ["a number for a tape", { agent_tape: 5, tool_tape: "" }, 400, "malformed_field"],
  ["an object for a tape", { agent_tape: { a: 1 }, tool_tape: "" }, 400, "malformed_field"],
  ["a null tape", { agent_tape: null, tool_tape: "" }, 400, "malformed_field"],
  ["bad base64", { agent_tape_b64: "@@@@", tool_tape: "" }, 400, "malformed_base64"],
  ["non-canonical base64", { agent_tape_b64: "YR==", tool_tape: "" }, 400, "malformed_base64"],
  ["both text and base64", { agent_tape: "", agent_tape_b64: "", tool_tape: "" }, 400, "ambiguous_tape"],
  ["an unknown field", { agent_tape: "", tool_tape: "", extra: 1 }, 400, "unknown_field"],
  ["a pin", { agent_tape: "", tool_tape: "", pin: "{}" }, 400, "pins_not_supported"],
];
for (const [what, body, status, code] of MALFORMED) {
  test(`MALFORMED: ${what} -> ${status} ${code}`, async () => {
    const r = await call(jsonReq(body));
    assert.equal(r.status, status);
    assert.equal(r.body.ok, false);
    assert.equal(r.body.error_code, code);
    assert.equal(r.body.verdict, undefined, "a refusal carries no verdict");
  });
}

test("MALFORMED: a body the platform could not parse as JSON -> 400 malformed_json", async () => {
  const req = jsonReq(null);
  Object.defineProperty(req, "body", { get() { throw new SyntaxError("Unexpected token"); } });
  const r = await call(req);
  assert.equal(r.status, 400);
  assert.equal(r.body.error_code, "malformed_json");
});

test("MALFORMED: raw non-JSON bytes under application/json -> 400 malformed_json", async () => {
  const req = makeRawReq({ method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": freshIp() }, rawBody: Buffer.from("{nope") });
  req.query = { op: "reconcile" };
  const r = await call(req);
  assert.equal(r.status, 400);
  assert.equal(r.body.error_code, "malformed_json");
});

test("MALFORMED: an unsupported content type -> 415, and GET -> 405", async () => {
  const r = await call(makeReq({ method: "POST", query: { op: "reconcile" }, headers: { "content-type": "text/plain", "x-forwarded-for": freshIp() }, body: "hi" }));
  assert.equal(r.status, 415);
  assert.equal(r.body.error_code, "unsupported_media_type");
  const g = await call(makeReq({ method: "GET", query: { op: "reconcile" } }));
  assert.equal(g.status, 405);
  assert.equal(g.body.error_code, "method_not_allowed");
});

test("MALFORMED TAPES ARE ANSWERS: 400 random byte strings as tapes always get a 200 verdict, never a throw", async () => {
  let seed = 20260923;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
  const pieces = ["{", "}", "[", "]", '"', ":", ",", "\n", "\r", "\\u", "\\ud800", "NaN", "1e400", "-", "0",
    '"idx"', '"chain"', '"side": "agent"', '"tape": "arcaeon-tape/1"', " ", "\xef\xbb\xbf", "null", "true"];
  const verdicts = new Set();
  for (let i = 0; i < 400; i++) {
    const make = () => {
      let s = "";
      const n = Math.floor(rnd() * 40);
      for (let k = 0; k < n; k++) s += rnd() < 0.7 ? pieces[Math.floor(rnd() * pieces.length)] : String.fromCharCode(Math.floor(rnd() * 256));
      return Buffer.from(s, "latin1");
    };
    const a = rnd() < 0.3 ? AGENT : make();
    const b = rnd() < 0.3 ? TOOL : make();
    const r = await call(jsonReq({ agent_tape_b64: a.toString("base64"), tool_tape_b64: b.toString("base64") }));
    assert.equal(r.status, 200, `case ${i}`);
    verdicts.add(r.body.verdict.verdict);
  }
  for (const v of verdicts) assert.ok(["MATCHED", "MISSING", "ALTERED", "COULD_NOT_LOOK"].includes(v), v);
  assert.ok(verdicts.has("ALTERED") && verdicts.size >= 2, [...verdicts].join(","));
});

test("MALFORMED TAPES ARE ANSWERS: 100,000 nested brackets is COULD NOT LOOK, not a stack overflow", async () => {
  const deep = "[".repeat(100000) + "]".repeat(100000);
  const r = await call(jsonReq({ agent_tape: deep, tool_tape: TOOL.toString("utf-8") }));
  assert.equal(r.status, 200);
  assert.equal(r.body.verdict.verdict, "COULD_NOT_LOOK");
  assert.match(r.body.verdict.reason, /nested deeper than 512 levels/);
});

// -- multipart ----------------------------------------------------------------------

function multipart(parts, boundary = "----arcaeonTEST42") {
  const chunks = [];
  for (const [name, data, filename] of parts) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"` +
      (filename ? `; filename="${filename}"` : "") + "\r\nContent-Type: application/octet-stream\r\n\r\n", "latin1"));
    chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(data, "utf-8"));
    chunks.push(Buffer.from("\r\n", "latin1"));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`, "latin1"));
  const req = makeRawReq({ method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-forwarded-for": freshIp() }, rawBody: Buffer.concat(chunks) });
  req.query = { op: "reconcile" };
  return req;
}

test("MULTIPART: two file parts carry the exact bytes (a CRLF tape still MATCHES, as reconcile.py reads it)", async () => {
  const crlf = Buffer.from(TOOL.toString("latin1").replace(/\n/g, "\r\n"), "latin1");
  const r = await call(multipart([["agent_tape", AGENT, "agent.tape.jsonl"], ["tool_tape", crlf, "tool.tape.jsonl"]]));
  assert.equal(r.status, 200);
  assert.equal(r.body.verdict.summary, "MATCHED 5 of 5");
  assert.equal(r.body.receipt.tapes.tape_b.bytes, crlf.length, "the receipt binds the bytes as sent, CRLF and all");
});

test("MULTIPART: a duplicate part, a missing part and a boundary-less body are typed refusals", async () => {
  const dup = await call(multipart([["agent_tape", AGENT], ["agent_tape", AGENT], ["tool_tape", TOOL]]));
  assert.equal(dup.status, 400);
  assert.equal(dup.body.error_code, "duplicate_field");
  const miss = await call(multipart([["agent_tape", AGENT]]));
  assert.equal(miss.body.error_code, "missing_tape");
  const req = makeRawReq({ method: "POST", headers: { "content-type": "multipart/form-data", "x-forwarded-for": freshIp() }, rawBody: Buffer.from("x") });
  req.query = { op: "reconcile" };
  const nob = await call(req);
  assert.equal(nob.status, 400);
  assert.equal(nob.body.error_code, "malformed_multipart");
});

// -- nothing kept -------------------------------------------------------------------

test("NO PERSISTENCE: a comparison makes no network call and logs nothing of the tapes", async (t) => {
  const realFetch = global.fetch;
  let fetched = 0;
  global.fetch = async () => { fetched += 1; throw new Error("no network in reconcile"); };
  const logged = [];
  const orig = { log: console.log, error: console.error, warn: console.warn };
  for (const k of Object.keys(orig)) console[k] = (...a) => logged.push(a.join(" "));
  t.after(() => { global.fetch = realFetch; Object.assign(console, orig); });
  const r = await call(jsonReq({ agent_tape: AGENT.toString("utf-8"), tool_tape: TOOL.toString("utf-8") }));
  assert.equal(r.status, 200);
  assert.equal(fetched, 0);
  const firstReq = JSON.parse(AGENT.toString("utf-8").split("\n")[0]).req;
  assert.ok(!logged.join("\n").includes(firstReq));
  assert.equal(r.res._headers["cache-control"], "no-store");
});

test("RATE LIMIT: the endpoint spends the same per-IP budget as /api/verify and refuses 429 past it", async () => {
  const ip = "10.99.99.99";
  let last;
  for (let i = 0; i < 31; i++) {
    last = await call(makeReq({ method: "POST", query: { op: "reconcile" },
      headers: { "content-type": "application/json", "x-forwarded-for": ip }, body: { agent_tape: "", tool_tape: "" } }));
  }
  assert.equal(last.status, 429);
  assert.equal(last.body.error_code, "rate_limited");
});

test("PERFORMANCE: two 1 MB tapes that share nothing are answered well inside the function's 30 s", async () => {
  const rowsOf = (side, salt) => {
    const out = [];
    let prev = "genesis";
    let size = 0;
    for (let k = 1; size < H.TAPE_MAX_BYTES - 400; k++) {
      const r = new Map([["evt", "tape_call"], ["tape", "arcaeon-tape/1"], ["side", side], ["idx", BigInt(k)],
        ["req", `sha256:json-c14n:v1:${salt}${k}`], ["resp", null]]);
      const c = chainOf(prev, r);
      r.set("chain", c);
      prev = c;
      const line = pyDumps(r, { sortKeys: false, itemSep: ", ", keySep: ": ", ascii: false, allowNan: true });
      size += line.length + 1;
      out.push(line);
    }
    return out.join("\n") + "\n";
  };
  const a = rowsOf("agent", "a");
  const b = rowsOf("tool", "b");
  const t0 = Date.now();
  const r = await call(jsonReq({ agent_tape: a, tool_tape: b }));
  const ms = Date.now() - t0;
  assert.equal(r.status, 200);
  assert.equal(r.body.verdict.verdict, "ALTERED");
  assert.ok(ms < 15000, `took ${ms} ms`);
});

// -- the page and the routing ----------------------------------------------------------

test("PAGE: GET /reconcile serves the static page with the legend and the honest limits", async () => {
  const r = await call(makeReq({ method: "GET", query: { op: "reconcile-page" } }));
  assert.equal(r.status, 200);
  assert.match(r.res._headers["content-type"], /^text\/html/);
  const html = r.raw;
  for (const w of ["MATCHED n of n", "MISSING at call k", "ALTERED at call k", "COULD NOT LOOK"]) assert.ok(html.includes(w), w);
  assert.ok(html.includes("An operator-owned tape is not an outside witness."));
  assert.ok(html.includes("The service saw only what was submitted."));
  assert.ok(html.includes('fetch("/api/reconcile"'));
  const post = await call(makeReq({ method: "POST", query: { op: "reconcile-page" } }));
  assert.equal(post.status, 405);
});

test("PAGE: the script renders untrusted tape text with textContent only", () => {
  const html = require("../lib/_reconcile_page.js").HTML;
  const script = html.slice(html.indexOf("<script>"), html.indexOf("</script>"));
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/.test(script));
  const src = fs.readFileSync(path.join(__dirname, "..", "lib", "_reconcile_page.js"), "utf8");
  const body = src.slice(src.indexOf("const HTML = `") + 14, src.lastIndexOf("`;"));
  assert.ok(!body.includes("`") && !body.includes("${"), "the page holds no template-literal syntax");
});

test("ROUTING: vercel.json rewrites /api/reconcile and /reconcile onto api/verify.js, and api/ stays at 12 functions", () => {
  const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "vercel.json"), "utf8"));
  const rw = Object.fromEntries(cfg.rewrites.map((r) => [r.source, r.destination]));
  assert.equal(rw["/api/reconcile"], "/api/verify?op=reconcile");
  assert.equal(rw["/reconcile"], "/api/verify?op=reconcile-page");
  const fns = fs.readdirSync(path.join(__dirname, "..", "api")).filter((f) => f.endsWith(".js") && !f.startsWith("_"));
  assert.equal(fns.length, 12, `api/ holds ${fns.length} functions; the Hobby cap is 12`);
});

test("RECEIPT, END TO END: the saved answer verifies against the signer, and a doctored verdict beside it does not", async () => {
  const key = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-09-23");
  const req = jsonReq({ agent_tape: AGENT.toString("utf-8"), tool_tape: TOOL.toString("utf-8") });
  const res = makeRes();
  await H.handleReconcile(req, res, { env: { [receipts.SIGNER_ENV]: key.signer } });
  const saved = res._body;
  assert.deepEqual(receipts.verifyReceiptText(saved, key.verifier), { ok: true, reason: "signed", signer: key.verifier });
  const doctored = saved.replace('"summary":"MATCHED 5 of 5"', '"summary":"MATCHED 6 of 6"');
  assert.notEqual(doctored, saved);
  assert.equal(receipts.verifyReceiptText(doctored, key.verifier).reason, "verdict_does_not_match_receipt");
});

// test/rfc3161.test.js — lib/_rfc3161.js (an RFC 3161 time stamp request
// builder and response reader, Node's own modules only) and
// tools/tsa_stamp.js (stamp one file at DigiCert's free time stamp server and
// check the answer with stock openssl).
//
// No live time stamp server is reached. Every token here comes from a LOCAL
// test authority made with stock `openssl ts -reply` (a throwaway CA and TSA
// certificate created per run in a temp directory), and every check that
// matters is made by stock `openssl ts -verify`, not by our own reader. Our
// request bytes are compared with what `openssl ts -query` writes for the same
// file. These tests need the `openssl` command line; it is on this repo's
// test machines (OpenSSL 3), and a machine without it skips them by name.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { spawnSync, spawn } = require("node:child_process");

const TOOL = path.join(__dirname, "..", "tools", "tsa_stamp.js");
const HAS_OPENSSL = spawnSync("openssl", ["version"], { encoding: "utf8" }).status === 0;
const skip = HAS_OPENSSL ? false : "the openssl command line is not installed";

function ossl(args, opts = {}) {
  const r = spawnSync("openssl", args, { encoding: opts.encoding === null ? null : "utf8", ...opts });
  return r;
}

// A throwaway test time stamp authority: root CA + TSA cert with the
// critical timeStamping extended key usage RFC 3161 requires.
function makeAuthority() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-test-"));
  fs.writeFileSync(path.join(dir, "tsa.cnf"), [
    "[ tsa ]", "default_tsa = tsa_config1",
    "[ tsa_config1 ]", "dir = .", `serial = ${path.join(dir, "serial")}`, "crypto_device = builtin",
    "signer_digest = sha256", "default_policy = 1.2.3.4.1", "digests = sha256",
    "accuracy = secs:1", "ordering = yes", "tsa_name = no", "ess_cert_id_chain = no", "ess_cert_id_alg = sha256",
    "[ v3_tsa ]", "basicConstraints = CA:FALSE", "keyUsage = critical, digitalSignature",
    "extendedKeyUsage = critical, timeStamping", "",
  ].join("\n"));
  fs.writeFileSync(path.join(dir, "serial"), "01\n");
  const p = (n) => path.join(dir, n);
  const steps = [
    ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", p("ca.key"), "-out", p("ca.crt"), "-days", "2", "-subj", "/CN=arcaeon test root"],
    ["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", p("tsa.key"), "-out", p("tsa.csr"), "-subj", "/CN=arcaeon test tsa"],
    ["x509", "-req", "-in", p("tsa.csr"), "-CA", p("ca.crt"), "-CAkey", p("ca.key"), "-CAcreateserial", "-out", p("tsa.crt"), "-days", "2", "-extfile", p("tsa.cnf"), "-extensions", "v3_tsa"],
  ];
  for (const s of steps) {
    const r = ossl(s);
    assert.equal(r.status, 0, `openssl ${s[0]} failed: ${r.stderr}`);
  }
  return {
    dir,
    caFile: p("ca.crt"),
    tsaCert: p("tsa.crt"),
    // Answer a request (DER bytes) the way a TSA would.
    reply(reqDer) {
      const q = path.join(dir, `q-${crypto.randomBytes(4).toString("hex")}.tsq`);
      const r = path.join(dir, `r-${crypto.randomBytes(4).toString("hex")}.tsr`);
      fs.writeFileSync(q, reqDer);
      const out = ossl(["ts", "-reply", "-queryfile", q, "-signer", p("tsa.crt"), "-inkey", p("tsa.key"), "-config", p("tsa.cnf"), "-out", r]);
      assert.ok(fs.existsSync(r), `openssl ts -reply failed: ${out.stderr}`);
      return fs.readFileSync(r);
    },
  };
}

function tmpFile(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-data-"));
  const f = path.join(dir, "2026-11-22T20-head.txt");
  fs.writeFileSync(f, content);
  return f;
}

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest();

// ---- the request ----

test("REQUEST: without a nonce, our bytes equal `openssl ts -query -sha256 -cert -no_nonce` for the same file", { skip }, () => {
  const rfc = require("../lib/_rfc3161.js");
  const f = tmpFile("0123456789abcdef0123456789abcdef01234567 2026-11-22T20:00:00Z\n");
  const theirs = ossl(["ts", "-query", "-data", f, "-sha256", "-cert", "-no_nonce"], { encoding: null }).stdout;
  const ours = rfc.buildRequest({ hash: sha256(fs.readFileSync(f)), nonce: null, certReq: true });
  assert.equal(ours.toString("hex"), Buffer.from(theirs).toString("hex"));
});

test("REQUEST: with a nonce, openssl reads our request back as sha256 of the file, our nonce, certificate required", { skip }, () => {
  const rfc = require("../lib/_rfc3161.js");
  const f = tmpFile("head\n");
  const nonce = rfc.makeNonce();
  const der = rfc.buildRequest({ hash: sha256(fs.readFileSync(f)), nonce, certReq: true });
  const q = path.join(path.dirname(f), "mine.tsq");
  fs.writeFileSync(q, der);
  const text = ossl(["ts", "-query", "-in", q, "-text"]).stdout;
  assert.match(text, /Hash Algorithm: sha256/);
  assert.match(text, /Certificate required: yes/);
  const printed = text.match(/Nonce: 0x([0-9A-Fa-f]+)/);
  assert.ok(printed, `openssl printed no nonce: ${text}`);
  // Compared as numbers: whether a leading zero nibble is printed is openssl's choice.
  assert.equal(BigInt(`0x${printed[1]}`), BigInt(`0x${nonce.toString("hex")}`));
});

test("REQUEST: a hash that is not 32 bytes is refused (sha256 only)", () => {
  const rfc = require("../lib/_rfc3161.js");
  assert.throws(() => rfc.buildRequest({ hash: Buffer.alloc(20), nonce: null }), /32 bytes/);
});

// ---- the response ----

test("RESPONSE: a granted token from a stock openssl TSA reads back with our imprint, our nonce and its time", { skip }, () => {
  const rfc = require("../lib/_rfc3161.js");
  const tsa = makeAuthority();
  const hash = sha256(Buffer.from("anchor text\n"));
  const nonce = rfc.makeNonce();
  const resp = rfc.parseResponse(tsa.reply(rfc.buildRequest({ hash, nonce, certReq: true })));
  assert.equal(resp.status, 0);
  assert.equal(resp.granted, true);
  assert.equal(resp.tst.hashAlgorithm, "sha256");
  assert.equal(resp.tst.hashedMessage, hash.toString("hex"));
  assert.equal(resp.tst.nonce, nonce.toString("hex").replace(/^0+/, ""));
  assert.equal(resp.tst.policy, "1.2.3.4.1");
  assert.match(resp.tst.genTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/);
  assert.ok(Math.abs(Date.parse(resp.tst.genTime) - Date.now()) < 5 * 60_000, "the authority's time is now");
  assert.deepEqual(rfc.checkResponse(resp, { hash, nonce }).problems, []);
});

test("RESPONSE: a token for a different file is named as an imprint mismatch", { skip }, () => {
  const rfc = require("../lib/_rfc3161.js");
  const tsa = makeAuthority();
  const nonce = rfc.makeNonce();
  const resp = rfc.parseResponse(tsa.reply(rfc.buildRequest({ hash: sha256(Buffer.from("other")), nonce })));
  const c = rfc.checkResponse(resp, { hash: sha256(Buffer.from("mine")), nonce });
  assert.equal(c.ok, false);
  assert.match(c.problems.join("\n"), /imprint/);
});

test("RESPONSE: a token answering someone else's nonce is named (a replayed answer)", { skip }, () => {
  const rfc = require("../lib/_rfc3161.js");
  const tsa = makeAuthority();
  const hash = sha256(Buffer.from("mine"));
  const resp = rfc.parseResponse(tsa.reply(rfc.buildRequest({ hash, nonce: rfc.makeNonce() })));
  const c = rfc.checkResponse(resp, { hash, nonce: rfc.makeNonce() });
  assert.equal(c.ok, false);
  assert.match(c.problems.join("\n"), /nonce/);
});

test("RESPONSE: a rejection status is read as not granted, with no token", () => {
  const rfc = require("../lib/_rfc3161.js");
  // TimeStampResp { PKIStatusInfo { status rejection(2) } }
  const rejection = Buffer.from("30053003020102", "hex");
  const resp = rfc.parseResponse(rejection);
  assert.equal(resp.status, 2);
  assert.equal(resp.granted, false);
  assert.equal(resp.tst, null);
  const c = rfc.checkResponse(resp, { hash: Buffer.alloc(32), nonce: null });
  assert.equal(c.ok, false);
  assert.match(c.problems.join("\n"), /status 2 \(rejection\)/);
});

test("RESPONSE: bytes that are not a time stamp response fail closed, naming where", () => {
  const rfc = require("../lib/_rfc3161.js");
  for (const bad of [Buffer.alloc(0), Buffer.from("<html>busy</html>"), Buffer.from("3082ffff00", "hex"), Buffer.from("3003020100", "hex").subarray(0, 4)]) {
    assert.throws(() => rfc.parseResponse(bad), (err) => err instanceof rfc.Rfc3161Error && typeof err.where === "string");
  }
});

// ---- the tool, end to end against a local authority over HTTP ----

function serveAuthority(tsa, { mangle = null } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method, type: req.headers["content-type"] });
      let body = tsa.reply(Buffer.concat(chunks));
      if (mangle) body = mangle(body);
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, seen, url: `http://127.0.0.1:${server.address().port}/` })));
}

function runTool(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [TOOL, ...args, "--json"], { env: { PATH: process.env.PATH } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => {
      let summary = null;
      try { summary = JSON.parse(stdout); } catch (_) { /* reported by the assert */ }
      resolve({ status, summary, stdout, stderr });
    });
  });
}

test("TOOL: stamps a file, keeps the request and the token, and stock `openssl ts -verify` says OK", { skip }, async () => {
  const tsa = makeAuthority();
  const { server, seen, url } = await serveAuthority(tsa);
  try {
    const f = tmpFile("0123456789abcdef0123456789abcdef01234567 2026-11-22T20:00:00Z\n");
    const out = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-out-"));
    const r = await runTool(["--file", f, "--out", out, "--tsa-url", url, "--ca-file", tsa.caFile, "--untrusted", tsa.tsaCert]);
    assert.equal(r.status, 0, r.stderr || r.stdout);
    assert.equal(r.summary.verdict, "VERIFIED");
    assert.equal(r.summary.openssl_verify, "Verification: OK");
    assert.deepEqual(seen, [{ method: "POST", type: "application/timestamp-query" }]);
    const tsr = path.join(out, `${path.basename(f)}.tsr`);
    assert.ok(fs.existsSync(tsr) && fs.existsSync(path.join(out, `${path.basename(f)}.tsq`)));
    // The kept token checks again later with stock openssl alone, no tool.
    const again = ossl(["ts", "-verify", "-data", f, "-in", tsr, "-CAfile", tsa.caFile, "-untrusted", tsa.tsaCert]);
    assert.match(again.stdout + again.stderr, /Verification: OK/);
    assert.equal(r.summary.sha256, sha256(fs.readFileSync(f)).toString("hex"));
  } finally {
    server.close();
  }
});

test("TOOL: a token from an authority the CA file does not trust is BROKEN, by openssl's own check", { skip }, async () => {
  const tsa = makeAuthority();
  const stranger = makeAuthority();
  const { server, url } = await serveAuthority(tsa);
  try {
    const f = tmpFile("head\n");
    const out = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-out-"));
    const r = await runTool(["--file", f, "--out", out, "--tsa-url", url, "--ca-file", stranger.caFile, "--untrusted", tsa.tsaCert]);
    assert.equal(r.status, 2, r.stderr || r.stdout);
    assert.equal(r.summary.verdict, "BROKEN");
    assert.doesNotMatch(String(r.summary.openssl_verify), /Verification: OK/);
  } finally {
    server.close();
  }
});

test("TOOL: an answer that is not a time stamp response is BROKEN and names why", { skip }, async () => {
  const tsa = makeAuthority();
  const { server, url } = await serveAuthority(tsa, { mangle: () => Buffer.from("<html>service busy</html>") });
  try {
    const f = tmpFile("head\n");
    const out = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-out-"));
    const r = await runTool(["--file", f, "--out", out, "--tsa-url", url, "--ca-file", tsa.caFile]);
    assert.equal(r.status, 2, r.stderr || r.stdout);
    assert.equal(r.summary.verdict, "BROKEN");
    assert.match(r.summary.problems.join("\n"), /not a time stamp response/);
  } finally {
    server.close();
  }
});

test("TOOL: an authority that cannot be reached is COULD NOT LOOK, never VERIFIED", { skip }, async () => {
  const f = tmpFile("head\n");
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-out-"));
  const r = await runTool(["--file", f, "--out", out, "--tsa-url", "http://127.0.0.1:9/"]);
  assert.equal(r.status, 3, r.stderr || r.stdout);
  assert.equal(r.summary.verdict, "COULD NOT LOOK");
});

test("TOOL: only DigiCert's free server (or a local test server) is used; any other time stamp service is refused", async () => {
  const f = tmpFile("head\n");
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tsa-out-"));
  for (const url of ["https://paid-tsa.example.com/", "http://timestamp.digicert.com.example.org/", "ftp://timestamp.digicert.com/"]) {
    const r = await runTool(["--file", f, "--out", out, "--tsa-url", url]);
    assert.equal(r.status, 1, `${url}: ${r.stdout}`);
    assert.match(r.stderr, /free list/);
  }
  const help = await runTool(["--help"]);
  assert.match(help.stderr, /timestamp\.digicert\.com/);
  assert.deepEqual(fs.readdirSync(out), [], "nothing is written for a refused service");
});

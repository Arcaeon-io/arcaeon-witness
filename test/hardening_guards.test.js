// test/hardening_guards.test.js — guards that no test held (2026-11-22 sweep).
//
// Method: each guard below was deleted or loosened in turn and the WHOLE suite
// run; every one of these survived (832 of 832 still passed). Some were
// covered by a later check by accident: the CRLF checkpoint case was refused,
// but by the origin regex, not the CR rule, so the test passed for the wrong
// reason. Each test here asserts the guard's OWN reason, so removing the guard
// fails it, whatever else happens to catch the input today.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const cp = require("../lib/_checkpoint.js");
const lt = require("../lib/_logtree.js");
const store = require("../lib/_store.js");
const rfc = require("../lib/_rfc3161.js");
const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");

const ROOT = crypto.createHash("sha256").update("a root").digest();
const TEXT = `${lt.LOG_ORIGIN}\n56\n${ROOT.toString("base64")}\n`;

// ---- lib/_checkpoint.js ----

test("CHECKPOINT: a CR byte anywhere is refused by the CR rule itself, not by whatever line it lands in", () => {
  const { signer } = cp.generateKey("arcaeon.io/test");
  const signed = cp.signCheckpoint(TEXT, signer);
  for (const [name, text] of Object.entries({
    "CRLF endings": TEXT.replace(/\n/g, "\r\n"),
    "CR at the end of a signature line": signed.replace(/\n$/, "\r\n"),
    "CR at the end of the root line": TEXT.replace(/=\n$/, "=\r\n"),
  })) {
    const r = cp.parseCheckpoint(text);
    assert.equal(r.ok, false, name);
    assert.equal(r.detail, "CR byte in note", name);
  }
});

test("CHECKPOINT: a size past 15 digits is refused: it cannot be held exactly, and 9007199254740993 would read as ...992", () => {
  const at = (size) => cp.parseCheckpoint(`${lt.LOG_ORIGIN}\n${size}\n${ROOT.toString("base64")}\n`);
  assert.equal(at("999999999999999").ok, true, "15 digits is the ceiling and is exact");
  for (const size of ["1000000000000000", "9007199254740993", "1".repeat(40)]) {
    const r = at(size);
    assert.equal(r.ok, false, size);
    assert.equal(r.detail, "size", size);
  }
});

test("CHECKPOINT: a signature line with the key's hash under a DIFFERENT name is not this key's signature", () => {
  const { signer, verifier } = cp.generateKey("arcaeon.io/test");
  const signed = cp.signCheckpoint(TEXT, signer);
  assert.equal(cp.verifyCheckpointSignature(signed, verifier).ok, true);
  // Same 4-byte hash and the same valid signature bytes, another name.
  const renamed = signed.replace("— arcaeon.io/test ", "— someone.else/key ");
  assert.notEqual(renamed, signed);
  const r = cp.verifyCheckpointSignature(renamed, verifier);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_signature_for_key", "a name is part of a key; a line naming another key is someone else's line");
});

// ---- lib/_store.js ----

test("KEYS: a WITNESS_KEYS entry with an empty prefix binds the key to nothing (never a wildcard)", () => {
  const saved = process.env.WITNESS_KEYS;
  try {
    for (const raw of ["k1:", "k1: ", "k1:,k2:demo-"]) {
      process.env.WITNESS_KEYS = raw;
      assert.equal(store.keyPrefixFor("k1"), null, `${JSON.stringify(raw)} must not grant k1 anything`);
    }
    process.env.WITNESS_KEYS = "k1:,k2:demo-";
    assert.equal(store.keyPrefixFor("k2"), "demo-", "the other entry still works");
  } finally {
    if (saved === undefined) delete process.env.WITNESS_KEYS;
    else process.env.WITNESS_KEYS = saved;
  }
});

test("PIN: rows above the 1e12 domain bound are refused 400 before anything is written, even when exactly representable", async () => {
  const saved = process.env.WITNESS_KEYS;
  process.env.WITNESS_KEYS = "hardenkey:demo-";
  const gh = new MockGitHubStore();
  const restore = install(gh);
  try {
    const pin = require("../api/pin.js");
    for (const rows of [1e12 + 1, 2 ** 52, Number.MAX_SAFE_INTEGER]) {
      const res = makeRes();
      await pin(makeReq({ method: "POST", headers: { authorization: "Bearer hardenkey" }, body: { namespace: "demo-bound", rows, chain: "aabbccdd" } }), res);
      assert.equal(res._status, 400, `rows=${rows}: ${JSON.stringify(res._body)}`);
      assert.match(String(res._body.error), /rows/);
    }
    assert.deepEqual(gh.putLog, [], "a refused pin writes nothing (a bricked namespace cannot be undone)");
  } finally {
    restore();
    if (saved === undefined) delete process.env.WITNESS_KEYS;
    else process.env.WITNESS_KEYS = saved;
  }
});

// ---- lib/_rfc3161.js ----

// A granted response's outer shell with a token-shaped body is not needed to
// reach these two checks: they guard the outermost value.
const REJECTION = Buffer.from("30053003020102", "hex");

test("RFC 3161: a response cut short is refused as truncated, by the length rule", () => {
  assert.equal(rfc.parseResponse(REJECTION).status, 2, "the whole response reads");
  try {
    rfc.parseResponse(REJECTION.subarray(0, REJECTION.length - 1));
    assert.fail("a truncated response was read");
  } catch (err) {
    assert.ok(err instanceof rfc.Rfc3161Error);
    assert.match(err.reason, /truncated/);
  }
});

test("RFC 3161: bytes after the response are refused, not ignored", () => {
  try {
    rfc.parseResponse(Buffer.concat([REJECTION, Buffer.from([0x00])]));
    assert.fail("trailing bytes were ignored");
  } catch (err) {
    assert.ok(err instanceof rfc.Rfc3161Error);
    assert.match(err.reason, /trailing bytes/);
  }
});

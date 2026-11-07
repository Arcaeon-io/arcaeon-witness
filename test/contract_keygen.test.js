// test/contract_keygen.test.js: tools/contract_keygen.js makes the
// witness's contract key offline. The seed goes to the named file and
// nowhere else; the statement it writes is one lib/_contract_key.js loads;
// an existing file is refused and left as it was.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const contractKey = require("../lib/_contract_key.js");
const c = require("../lib/_contract.js");

const TOOL = path.join(__dirname, "..", "tools", "contract_keygen.js");
const run = (args) => spawnSync(process.execPath, [TOOL, ...args], { encoding: "utf8" });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "contract-keygen-"));

test("writes the seed only to --out, and a statement and note that load as the witness key", () => {
  const dir = tmp();
  const out = path.join(dir, "contract.seed");
  const r = run(["--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const seed = fs.readFileSync(out, "utf8");
  assert.match(seed, /^[0-9a-f]{64}$/);
  if (process.platform !== "win32") assert.equal(fs.statSync(out).mode & 0o077, 0, "the seed file is the owner's only");
  for (const stream of [r.stdout, r.stderr]) assert.equal(stream.includes(seed), false, "the seed is never printed");
  const statement = fs.readFileSync(`${out}.statement.json`, "utf8");
  const note = fs.readFileSync(`${out}.recovery.txt`, "utf8");
  assert.equal(note.includes(seed), false, "the recovery note holds nothing secret");
  const keyId = c.keyId(c.publicRaw(c.privateFromSeed(seed)));
  assert.ok(r.stdout.includes(keyId));
  assert.ok(note.includes(keyId));
  const loaded = contractKey.load({
    WITNESS_CONTRACT_SEED: seed,
    WITNESS_CONTRACT_KEY_ID: keyId,
    WITNESS_CONTRACT_STATEMENT: statement,
  });
  assert.equal(loaded.keyId, keyId);
  assert.equal(loaded.statementBytes.toString("utf8"), statement);
});

test("an existing file is refused and left untouched", () => {
  const dir = tmp();
  const out = path.join(dir, "contract.seed");
  fs.writeFileSync(out, "keep me");
  const r = run(["--out", out]);
  assert.notEqual(r.status, 0);
  assert.equal(fs.readFileSync(out, "utf8"), "keep me");
  assert.equal(fs.existsSync(`${out}.statement.json`), false);
});

test("without --out it writes nothing and says what is missing", () => {
  const r = run([]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /--out/);
});

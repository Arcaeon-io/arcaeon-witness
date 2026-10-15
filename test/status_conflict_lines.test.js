// test/status_conflict_lines.test.js — B080: the status data carries one plain
// line per observed conflict, saying what it was and how it resolved, and the
// HTML page and the JSON twin print that same line. Fixture conflicts are
// seeded into the mock pin repo; nothing touches the network.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const statusHandler = require("../api/status.js");
const { gatherStatusData, conflictLine } = require("../lib/_status_data.js");

const REPO = process.env.GITHUB_PIN_REPO;
let gh, restore;

const REFUSED = {
  observed_at: "2026-09-20T10:00:00.000Z",
  claimed: { namespace: "acme-prod", rows: 40, chain: "deadbeefdeadbeef" },
  accepted_head: { rows: 40, chain: "cafebabecafebabe", seq: 7 },
  auth_result: "key-valid-for-namespace",
  verdict: "head-conflict: same rows, different chain (re-mint signature)",
};
const SEALED = {
  observed_at: "2026-09-21T11:00:00.000Z",
  claimed: { namespace: "acme-prod", rows: 41, chain: "0123456789abcdef" },
  accepted_head: { rows: 41, chain: "fedcba9876543210" },
  auth_result: "key-valid-for-namespace",
  verdict: "head-conflict: same rows, different chain (re-mint signature)",
  detected_by: "batch sealer (§6.3 same-batch re-check)",
  batch_id: "000000012",
};

beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  gh.seed(REPO, "pins/acme-prod/latest.json", {
    namespace: "acme-prod", rows: 41, chain: "fedcba9876543210", seq: 8,
    pinned_at: new Date().toISOString(), cadence_hours: 24,
    next_pin_due_by: new Date(Date.now() + 3600e3).toISOString(),
  });
  gh.seed(REPO, "observations/acme-prod/2026-09-20T10-00-00-000Z.json", REFUSED);
  gh.seed(REPO, "observations/acme-prod/2026-09-21T11-00-00-000Z.json", SEALED);
});
afterEach(() => restore());

const EXPECT_REFUSED =
  "2026-09-20T10:00:00.000Z: namespace acme-prod at rows=40 was offered chain deadbeefdead while the accepted head at those rows is chain cafebabecafe (same rows, different chain). How it resolved: the pin was refused with a 409 and recorded here; the accepted head (seq 7) was kept unchanged.";
const EXPECT_SEALED =
  "2026-09-21T11:00:00.000Z: namespace acme-prod at rows=41 was offered chain 0123456789ab while the accepted head at those rows is chain fedcba987654 (same rows, different chain). How it resolved: found at seal time in batch 000000012; the later leaf was dropped from that batch and the accepted head did not change.";

test("LINE: a fixture conflict renders as one plain sentence: what it was, then how it resolved", () => {
  assert.equal(conflictLine(REFUSED), EXPECT_REFUSED);
  assert.equal(conflictLine(SEALED), EXPECT_SEALED);
  for (const line of [EXPECT_REFUSED, EXPECT_SEALED]) {
    assert.equal(line.includes("\n"), false, "one line per conflict");
    assert.equal(/[–—]/.test(line), false, "no em or en dashes in visitor copy");
  }
});

test("LINE: an unreadable record says it could not be read, never a guessed story", () => {
  const line = conflictLine(null);
  assert.match(line, /could not be read/);
  assert.match(line, /unknown/);
});

test("LINE: a record without a known resolution says so", () => {
  assert.match(conflictLine({ observed_at: "t", claimed: { namespace: "n", rows: 1, chain: "a" }, accepted_head: { chain: "b" } }),
    /How it resolved: not recorded in this file\.$/);
});

test("DATA: gatherStatusData carries one line per observed conflict, newest first", async () => {
  const data = await gatherStatusData();
  assert.equal(data.obsCount, 2);
  assert.deepEqual(data.conflictLines.map((c) => c.line), [EXPECT_SEALED, EXPECT_REFUSED]);
  for (const c of data.conflictLines) assert.match(c.url, /observations\/acme-prod\//);
});

test("RENDER: the HTML page and the JSON twin print the same lines", async () => {
  const pageRes = makeRes();
  await statusHandler(makeReq({ method: "GET", query: {} }), pageRes);
  const html = typeof pageRes._body === "string" ? pageRes._body : String(pageRes._text || "");
  // The page escapes text; these fixture lines contain nothing that escaping changes.
  assert.ok(html.includes(EXPECT_REFUSED), "HTML carries the refused-conflict line");
  assert.ok(html.includes(EXPECT_SEALED), "HTML carries the seal-time conflict line");

  const jsonRes = makeRes();
  await statusHandler(makeReq({ method: "GET", query: { format: "json" } }), jsonRes);
  let body = jsonRes._body !== undefined ? jsonRes._body : jsonRes._text;
  if (typeof body === "string") body = JSON.parse(body);
  assert.deepEqual(body.conflict_observations.lines, [EXPECT_SEALED, EXPECT_REFUSED]);
});

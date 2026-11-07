// test/witness_log_health.test.js: the witness log alert (owner item 3).
// Red names its field when a UTC day has no checkpoint and no gap record, or
// when the newest outside cosignature is over 36 hours old (or absent); a red
// makes the board degraded; an unreadable listing is cannot_determine, never
// current.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const wl = require("../lib/_witness_log_health.js");
const realStore = require("../lib/_store.js");
const statusData = require("../lib/_status_data.js");

const H = 3600000;
const at = (iso) => Date.parse(iso);
const OUTSIDE = "— other.example/witness AAAABBBB\n";
const OURS = "— arcaeon.io/witness-log/2026-09-22 CXZd7JnWTM3+vh857yu=\n";

// The live record as of 2026-11-07: genesis 09-23, missed 09-24, 10-23, 11-05.
function liveDays() {
  const days = ["2026-09-23"];
  for (let t = at("2026-09-25T00:00:00Z"); t <= at("2026-11-06T00:00:00Z"); t += 24 * H) days.push(new Date(t).toISOString().slice(0, 10));
  return days.filter((d) => d !== "2026-10-23" && d !== "2026-11-05");
}

test("the live record today: red on missing_days (the three days) and on outside_cosignature (none yet)", () => {
  const r = wl.judgeWitnessLog({ checkpointDays: liveDays(), declared: new Set(), newestCosigned: null, nowMs: at("2026-11-07T12:00:00Z") });
  assert.equal(r.status, "red");
  assert.deepEqual(r.missing_days, ["2026-09-24", "2026-10-23", "2026-11-05"]);
  assert.deepEqual(r.red.map((x) => x.field), ["missing_days", "outside_cosignature"]);
  assert.match(r.red[0].reason, /2026-11-05/);
});

test("declared misses are listed but not red; a fresh outside cosignature is current", () => {
  const r = wl.judgeWitnessLog({
    checkpointDays: liveDays(),
    declared: new Set(["2026-09-24", "2026-10-23", "2026-11-05"]),
    newestCosigned: { day: "2026-11-06", names: ["other.example/witness"] },
    nowMs: at("2026-11-07T11:00:00Z"),
  });
  assert.equal(r.status, "current", JSON.stringify(r.red));
  assert.deepEqual(r.missed_days_declared, ["2026-09-24", "2026-10-23", "2026-11-05"]);
  assert.deepEqual(r.missing_days, []);
});

test("36 hours from the start of the cosigned day is the line; today is not judged until it ends", () => {
  const base = { checkpointDays: ["2026-11-05"], declared: new Set(), newestCosigned: { day: "2026-11-05", names: ["x"] } };
  assert.equal(wl.judgeWitnessLog({ ...base, nowMs: at("2026-11-06T11:59:00Z") }).status, "current");
  const late = wl.judgeWitnessLog({ ...base, nowMs: at("2026-11-06T12:01:00Z") });
  assert.equal(late.status, "red");
  assert.deepEqual(late.red.map((x) => x.field), ["outside_cosignature"]);
  // 11/06 is not over at 12:01 on 11/06, so its missing checkpoint is not red yet
  assert.deepEqual(late.missing_days, []);
  const nextDay = wl.judgeWitnessLog({ ...base, newestCosigned: { day: "2026-11-07", names: ["x"] }, checkpointDays: ["2026-11-05", "2026-11-07"], nowMs: at("2026-11-07T10:00:00Z") });
  assert.deepEqual(nextDay.missing_days, ["2026-11-06"]);
});

test("only outside, well formed lines count as cosignatures", () => {
  assert.deepEqual(wl.outsideCosigners(OURS + OUTSIDE + "- other.example/w AAAA\nnot a line\n"), ["other.example/witness"]);
  assert.deepEqual(wl.outsideCosigners(OURS), []);
  assert.deepEqual(wl.outsideCosigners(""), []);
});

function stub({ listing, gaps = [], gapThrows = false, cosign = {}, gapDocs = {} }) {
  const saved = {};
  for (const k of ["repoReachable", "listDir", "getFile", "getRawFile", "getTree"]) saved[k] = realStore[k];
  const today = new Date().toISOString().slice(0, 10);
  realStore.repoReachable = async () => true;
  realStore.listDir = async (dir) => {
    if (dir === "log/checkpoints") {
      if (listing instanceof Error) throw listing;
      return listing.map((name) => ({ type: "file", name }));
    }
    if (dir === "log/gaps") {
      if (gapThrows) throw new Error("github GET log/gaps -> 500");
      return gaps.map((name) => ({ type: "file", name }));
    }
    if (dir === "anchors") return [{ type: "file", name: `${today}-head.txt` }, { type: "file", name: `${today}-head.txt.ots` }];
    return [{ type: "dir", name: "acme-prod" }];
  };
  realStore.getRawFile = async (p) => {
    const m = /log\/checkpoints\/(.+)\.cosignatures$/.exec(p);
    if (m) return cosign[m[1]] !== undefined ? { text: cosign[m[1]] } : null;
    return { text: `deadbeef ${new Date().toISOString()}` };
  };
  realStore.getFile = async (p) => {
    const g = /^log\/gaps\/(.+)$/.exec(p);
    if (g) return gapDocs[g[1]] ? { json: gapDocs[g[1]] } : null;
    if (p === "pins/acme-prod/latest.json") {
      return { json: { namespace: "acme-prod", rows: 5, chain: "c".repeat(32), pinned_at: new Date().toISOString(), seq: 5, next_pin_due_by: new Date(Date.now() + 86400000).toISOString() } };
    }
    return null;
  };
  realStore.getTree = async () => [];
  return () => Object.assign(realStore, saved);
}

const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);

test("board: a missing day makes the status degraded and names the field; the gap record clears it", async () => {
  let restore = stub({ listing: [`${day(-2)}.txt`, `${day(0)}.txt`, `${day(0)}.cosignatures`], cosign: { [day(0)]: OUTSIDE } });
  try {
    const d = await statusData.gatherStatusData();
    assert.equal(d.witnessLog.status, "red");
    assert.deepEqual(d.witnessLog.red.map((x) => x.field), ["missing_days"]);
    assert.deepEqual(d.witnessLog.missing_days, [day(-1)]);
    assert.equal(d.degraded, true);
    assert.equal(statusData.overallWord(d), "degraded");
  } finally {
    restore();
  }
  restore = stub({
    listing: [`${day(-2)}.txt`, `${day(0)}.txt`, `${day(0)}.cosignatures`],
    cosign: { [day(0)]: OUTSIDE },
    gaps: [`${day(0)}.json`],
    gapDocs: { [`${day(0)}.json`]: { missed_days: [day(-1)] } },
  });
  try {
    const d = await statusData.gatherStatusData();
    assert.equal(d.witnessLog.status, "current", JSON.stringify(d.witnessLog));
    assert.deepEqual(d.witnessLog.missed_days_declared, [day(-1)]);
    assert.equal(statusData.overallWord(d), "ok");
  } finally {
    restore();
  }
});

test("board: only our own signature on file is red; an unreadable gap listing declares nothing; an unreadable log is cannot_determine", async () => {
  let restore = stub({ listing: [`${day(0)}.txt`, `${day(0)}.cosignatures`], cosign: { [day(0)]: OURS } });
  try {
    const d = await statusData.gatherStatusData();
    assert.deepEqual(d.witnessLog.red.map((x) => x.field), ["outside_cosignature"]);
    assert.equal(d.degraded, true);
  } finally {
    restore();
  }
  restore = stub({ listing: [`${day(-2)}.txt`, `${day(0)}.txt`, `${day(0)}.cosignatures`], cosign: { [day(0)]: OUTSIDE }, gapThrows: true });
  try {
    const d = await statusData.gatherStatusData();
    assert.equal(d.witnessLog.status, "red", "a day is not declared by a listing nobody could read");
    assert.match(d.witnessLog.error, /gap records/);
  } finally {
    restore();
  }
  for (const listing of [new Error("github GET log/checkpoints -> 502"), []]) {
    restore = stub({ listing });
    try {
      const d = await statusData.gatherStatusData();
      assert.equal(d.witnessLog.status, "cannot_determine");
      assert.equal(d.overallOk, false);
      assert.equal(statusData.overallWord(d), "indeterminate");
    } finally {
      restore();
    }
  }
});

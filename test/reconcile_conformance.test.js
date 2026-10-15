// test/reconcile_conformance.test.js — lib/_reconcile_tapes.js against the
// REAL arcaeon_ledger.reconcile, case by case, byte for byte.
//
// Every expected answer in test/fixtures/reconcile/cases.json was written by
// reconcile.py itself (the hardened one: it never raises, so every case has an
// answer, COULD NOT LOOK with a bracketed cause included) (test/fixtures/reconcile/make_fixtures.py): the cross-
// repo tapes the adapter and call_proxy suites leave behind (FIFO duplicate
// ids, invalid ids, a 202 answered later, gzip/deflate answers), the ledger's
// own reconcile cases, edge inputs where a naive port lies, and seeded fuzz.
// The port's answer, serialized the way the fixture's Python answer was
// (json.dumps(d, sort_keys=True, ensure_ascii=True, separators=(",", ":"))),
// must be the same string.
//
// Break arm: a reconcile that always says MATCHED is run through the same
// checker and must be caught; so must one that files every ALTERED as MISSING.
// A conformance suite never watched failing has not been shown to test anything.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fixtures = require("./fixtures/reconcile/cases.json");
const R = require("../lib/_reconcile_tapes.js");

function bytesOf(b64) {
  return Buffer.from(b64, "base64");
}

// A Python answer for two tapes of one side.
const sameSide = (python) => /both tapes are (agent|tool)-side tapes/.test(python);
// The port's answer and Python's differ only in counts, the port's holding
// both tapes' counts by tape and Python's the second's by side.
function sameButCounts(mine, python, got) {
  const m = JSON.parse(mine);
  const p = JSON.parse(python);
  const pc = p.counts;
  delete m.counts;
  delete p.counts;
  if (JSON.stringify(m) !== JSON.stringify(p)) return false;
  const keys = Object.keys(got.counts).sort();
  return keys.join() === "tape_a,tape_b" && Object.keys(pc).length === 1 && Object.values(pc)[0] === got.counts.tape_b;
}

// Returns the list of disagreements between a reconcile function and the fixture.
function disagreements(reconcileFn, cases = fixtures.cases) {
  const bad = [];
  for (const c of cases) {
    let got;
    try {
      got = reconcileFn(bytesOf(c.a_b64), bytesOf(c.b_b64));
    } catch (e) {
      bad.push({ name: c.name, why: `port threw ${e && e.message}` });
      continue;
    }
    if (typeof c.python !== "string") {
      bad.push({ name: c.name, why: "fixture case has no reconcile.py answer" });
      continue;
    }
    const mine = R.conformanceJson(got);
    if (mine === c.python) continue;
    // THE ONE DIVERGENCE (unit R-WIDE, C8, the architect's ruling): for two
    // tapes of one side, reconcile.py keys counts by side and keeps one; the
    // port keeps both, by tape. Everything else must still be the same.
    if (sameSide(c.python) && sameButCounts(mine, c.python, got)) continue;
    bad.push({ name: c.name, why: "differs", mine, python: c.python });
  }
  return bad;
}

test("CONFORMANCE: the fixture was made from the reconcile.py this port names", () => {
  assert.equal(fixtures.reference.package, R.REFERENCE.package);
  assert.equal(fixtures.reference.version, R.REFERENCE.version);
  assert.equal(fixtures.reference.reconcile_sha256, R.REFERENCE.reconcile_sha256);
  assert.equal(fixtures.reference.ledger_init_sha256, R.REFERENCE.ledger_init_sha256);
});

test("CONFORMANCE: the fixture covers every source it claims", () => {
  const by = {};
  for (const c of fixtures.cases) by[c.source] = (by[c.source] || 0) + 1;
  for (const s of ["crossrepo", "ledger", "edge", "fuzz"]) assert.ok(by[s] > 0, `no ${s} cases`);
  const verdicts = new Set(fixtures.cases.filter((c) => c.python).map((c) => JSON.parse(c.python).verdict));
  for (const v of ["MATCHED", "MISSING", "ALTERED", "COULD_NOT_LOOK"]) assert.ok(verdicts.has(v), `no ${v} case`);
  const names = fixtures.cases.filter((c) => c.source === "crossrepo").map((c) => c.name).join("\n");
  // The runs the tapes came from (pytest cuts a basetemp dir name at 30
  // characters, hence the stems): the two-recorder cross-repo chains, FIFO
  // duplicate ids, invalid ids, a 202 answered later, compressed answers.
  for (const run of ["test_cross_repo_adapter_tape_a", "test_cross_repo_no_bridge_matc", "test_cross_repo_duplicate_ids_",
    "test_cross_repo_invalid_ids", "test_cross_repo_a_202_answered", "test_a_compressed_answer_is_re",
    "test_a_202_answered_later_on_t", "test_duplicate_ids_in_a_batch_", "test_invalid_ids_are_taped_inv"]) {
    assert.ok(names.includes(run), `no tape harvested from a ${run} run`);
  }
  assert.ok(/test_cross_repo[^\n]*: agent vs tool/.test(names), "cross-repo agent/tool pairs are present");
});

for (const source of ["crossrepo", "ledger", "edge", "fuzz"]) {
  test(`CONFORMANCE: every ${source} case gives reconcile.py's answer, byte for byte`, () => {
    const cases = fixtures.cases.filter((c) => c.source === source);
    const bad = disagreements(R.reconcileTapes, cases);
    assert.deepEqual(bad.slice(0, 3), [], `${bad.length} of ${cases.length} ${source} cases disagree`);
  });
}

test("CONFORMANCE: every case carries reconcile.py's answer; none is excused", () => {
  for (const c of fixtures.cases) {
    assert.equal(typeof c.python, "string", c.name);
    assert.ok(!("python_raises" in c) && !("port_expect" in c), `${c.name} is excused from byte-for-byte`);
  }
});

test("CONFORMANCE: the three inputs 0.8.0 raised on, and the 512 bound, are COULD NOT LOOK in the Python's words", () => {
  const expect = {
    dup_key_then_junk: /^tape_a line 2 holds a duplicate key and does not parse \[duplicate_key_unparseable\]$/,
    "row_wrapped_in_U+000B": /^tape_a row 2 verifies but does not read a second time \(whitespace json\.loads does not strip\) \[whitespace_outside_json\]$/,
    nested_522_both: /^tape_a line 1 is nested deeper than 512 levels \[nesting_too_deep\]$/,
    line_arrays_513: /is nested deeper than 512 levels \[nesting_too_deep\]$/,
    int_4301_digits_then_deep_600: /is nested deeper than 512 levels \[nesting_too_deep\]$/,
  };
  for (const [name, re] of Object.entries(expect)) {
    const c = fixtures.cases.find((x) => x.name === name);
    assert.ok(c, `fixture has ${name}`);
    const py = JSON.parse(c.python);
    assert.equal(py.verdict, "COULD_NOT_LOOK", name);
    assert.match(py.reason, re, name);
    const got = R.reconcileTapes(bytesOf(c.a_b64), bytesOf(c.b_b64));
    assert.equal(R.conformanceJson(got), c.python, name);
  }
  // inside the bound nothing is refused
  for (const name of ["line_arrays_512", "line_objects_512", "nested_510_both", "line_brackets_in_string_600",
    "line_syntax_error_before_600", "line_unclosed_512_then_junk"]) {
    const c = fixtures.cases.find((x) => x.name === name);
    assert.ok(c, `fixture has ${name}`);
    assert.ok(!c.python.includes("nesting_too_deep"), name);
  }
  // No case says the reference raises any more.
  for (const c of fixtures.cases) assert.ok(!c.python.includes("reference implementation"), c.name);
});

// -- break arms ---------------------------------------------------------------

function alwaysMatched(a, b) {
  const r = R.reconcileTapes(a, b);
  return { ...r, verdict: "MATCHED", summary: `MATCHED ${r.matched} of ${r.matched}`, at: null, side: null,
    findings: [], could_not_look: [], exit_code: 0 };
}

function alteredFiledAsMissing(a, b) {
  const r = R.reconcileTapes(a, b);
  if (r.verdict !== "ALTERED") return r;
  return { ...r, verdict: "MISSING", summary: r.summary.replace(/^ALTERED/, "MISSING") };
}

test("BREAK ARM: a lying reconcile that always says MATCHED is caught", () => {
  const bad = disagreements(alwaysMatched);
  const nonGreen = fixtures.cases.filter((c) => JSON.parse(c.python).verdict !== "MATCHED").length;
  assert.ok(nonGreen > 100, "enough non-green cases to catch it");
  assert.equal(bad.length, nonGreen, "every non-green case catches the liar");
});

test("BREAK ARM: a reconcile that files every ALTERED as MISSING is caught", () => {
  const bad = disagreements(alteredFiledAsMissing);
  assert.ok(bad.length > 20, `only ${bad.length} cases caught it`);
});

test("BREAK ARM: a port that parses with JSON.parse (floats lose their type) is caught", () => {
  // The obvious shortcut: read `idx: 1.0` as the call index 1. Python does not.
  const c = fixtures.cases.find((x) => x.name === "idx_float_rechained");
  assert.ok(c, "fixture has the float-idx case");
  assert.equal(JSON.parse(c.python).verdict, "COULD_NOT_LOOK");
  const got = R.reconcileTapes(bytesOf(c.a_b64), bytesOf(c.b_b64));
  assert.equal(R.conformanceJson(got), c.python);
});

test("R-WIDE C8: two tapes of one side keep both counts, by tape; reconcile.py's answer keeps only the second's, by side", () => {
  const same = fixtures.cases.filter((c) => c.python && sameSide(c.python));
  assert.ok(same.length >= 3, "fixture: same-side cases");
  for (const c of same) {
    const got = R.reconcileTapes(bytesOf(c.a_b64), bytesOf(c.b_b64));
    assert.deepEqual(Object.keys(got.counts).sort(), ["tape_a", "tape_b"], c.name);
    assert.equal(Object.keys(JSON.parse(c.python).counts).length, 1, `${c.name}: Python keeps one`);
  }
  // control: one tape of each side is keyed by side, as reconcile.py keys it
  const mixed = fixtures.cases.find((c) => c.python && !sameSide(c.python) && Object.keys(JSON.parse(c.python).counts).length === 2);
  const got = R.reconcileTapes(bytesOf(mixed.a_b64), bytesOf(mixed.b_b64));
  assert.deepEqual(Object.keys(got.counts).sort(), Object.keys(JSON.parse(mixed.python).counts).sort());
});

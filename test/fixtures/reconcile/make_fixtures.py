#!/usr/bin/env python3
"""make_fixtures.py: build test/fixtures/reconcile/cases.json, the cases
test/reconcile_conformance.test.js replays against lib/_reconcile_tapes.js.

Every expected answer here is written by the REAL arcaeon_ledger.reconcile, run
in this process over the exact bytes stored in the case. The Node port has to
produce the same JSON, byte for byte, under the same serializer:

    json.dumps(result.to_dict(), sort_keys=True, ensure_ascii=True,
               separators=(",", ":"))

A port that agrees with itself cannot bless a fixture.

Sources, in order:
  1. crossrepo: the tapes the existing cross-repo suites write. The receipt
     repo's tests/test_call_proxy_tape.py (adapter agent tape against
     call_proxy tool tape, incl. FIFO duplicate ids, invalid ids, 202 answered
     later, gzip/deflate answers) and the ledger repo's
     adapter/test_http_forward.py and adapter/test_tape.py are run with pytest
     --basetemp, and every tape they leave behind is harvested. Pairs found in
     one directory are one case; a lone tape is replayed against an empty tape
     and against itself.
  2. ledger: every case in arcaeon-ledger's test_reconcile.py that takes two
     tapes and no pin (imported, not copied).
  3. edge: inputs where a naive port lies (floats, NaN, huge ints, lone
     surrogates, duplicate keys, BOM, CRLF, invalid UTF-8, Python-only
     whitespace, a float or boolean idx, the 4300-digit int limit), the three
     inputs on which reconcile.py 0.8.0 raised (duplicate key then junk,
     whitespace json.loads does not strip, nesting past the C guard), which
     the hardened reconcile.py answers COULD NOT LOOK, and the 512-level
     nesting bound it shares with the port.
  4. fuzz: seeded mutations of honest pairs (drop, duplicate, swap, truncate,
     edit with and without re-chaining, junk lines, side swaps ...).

The reference is the HARDENED reconcile.py (arcaeon-ledger branch
reconcile-hardening-2026-09-23, sha256 REFERENCE_SHA256 below): it never
raises, so every case carries a `python` answer and the port must give the same
bytes, including the COULD NOT LOOK reasons ending [nesting_too_deep],
[duplicate_key_unparseable] and [whitespace_outside_json]. If reconcile.py
raises anyway, this script stops: that is a bug to report, not a case.

    ARCAEON_LEDGER_REPO=<arcaeon-ledger checkout> ARCAEON_RECEIPT_REPO=<arcaeon-receipt checkout> \\
        py test/fixtures/reconcile/make_fixtures.py

Without ARCAEON_LEDGER_REPO it looks for a sibling arcaeon-ledger-rel080, then
arcaeon-ledger, and takes the first whose reconcile.py has REFERENCE_SHA256.
Rerun it when reconcile.py changes; the conformance test refuses a fixture made
from a different reconcile.py than the port names.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "cases.json"
ROOT = HERE.parents[2]

# The hardened reconcile.py (arcaeon-ledger a31402f, branch
# reconcile-hardening-2026-09-23), CRLF folded to LF. lib/_reconcile_tapes.js
# REFERENCE.reconcile_sha256 names the same digest.
REFERENCE_SHA256 = "42e8231b5289ca6ea835634e6049d490b786a400b1cd341e9786e4d42632a918"


def lf_sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _find_ledger() -> Path:
    env = os.environ.get("ARCAEON_LEDGER_REPO")
    cands = [Path(env)] if env else [ROOT.parent / "arcaeon-ledger-rel080", ROOT.parent / "arcaeon-ledger"]
    for c in cands:
        p = c / "arcaeon_ledger" / "reconcile.py"
        if p.exists() and lf_sha256(p) == REFERENCE_SHA256:
            return c
    sys.exit(f"no arcaeon-ledger checkout with the hardened reconcile.py (sha256 {REFERENCE_SHA256}) "
             f"among {[str(c) for c in cands]}; set ARCAEON_LEDGER_REPO")


LEDGER = _find_ledger()
RECEIPT = Path(os.environ.get("ARCAEON_RECEIPT_REPO", ROOT.parent / "arcaeon-receipt"))
sys.path.insert(0, str(LEDGER))

import arcaeon_ledger as L  # noqa: E402
import arcaeon_ledger.reconcile as R  # noqa: E402
from arcaeon_ledger import digest_json  # noqa: E402

MAX_DEPTH = R.MAX_DEPTH  # 512, the same as lib/_reconcile_tapes.js MAX_DEPTH


def expect_of(a: bytes, b: bytes) -> dict:
    """Run the real reconcile over these bytes, in files, and record its answer."""
    with tempfile.TemporaryDirectory() as d:
        pa, pb = Path(d) / "a.tape.jsonl", Path(d) / "b.tape.jsonl"
        pa.write_bytes(a)
        pb.write_bytes(b)
        r = R.reconcile(pa, pb)  # the hardened reconcile never raises; if it does, stop
        out = r.to_dict()
        text = json.dumps(out, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        if d in text or "a.tape.jsonl" in text or "b.tape.jsonl" in text:
            return {"skip": "the answer names a local path"}
        return {"python": text}


CASES: list = []
SEEN: set = set()


def add(source: str, name: str, a: bytes, b: bytes, note: str = "") -> None:
    key = hashlib.sha256(a + b"\x00|\x00" + b).hexdigest()
    if key in SEEN:
        return
    SEEN.add(key)
    exp = expect_of(a, b)
    if "skip" in exp:
        return
    case = {"source": source, "name": name,
            "a_b64": base64.b64encode(a).decode(), "b_b64": base64.b64encode(b).decode()}
    case.update(exp)
    if note:
        case["note"] = note
    CASES.append(case)


# -- writing tapes -----------------------------------------------------------

def chained(rows, ascii_=False, ts=True) -> bytes:
    """Lines exactly as Ledger.append writes them (json.dumps(obj, ensure_ascii=False)),
    with the library's own _chain. ascii_=True writes escapes (for lone surrogates)."""
    prev = "genesis"
    out = []
    for i, r in enumerate(rows):
        obj = dict(r)
        if ts:
            obj.setdefault("ts", f"2026-09-23T00:00:{i % 60:02d}Z")
        c = L._chain(prev, obj)
        obj["chain"] = c
        prev = c
        out.append(json.dumps(obj, ensure_ascii=ascii_))
    return ("\n".join(out) + ("\n" if out else "")).encode("utf-8", "surrogatepass")


def req(n):
    return digest_json({"name": "echo", "arguments": {"text": f"call {n}"}})


def resp(n, tag=""):
    return digest_json({"result": {"content": [{"type": "text", "text": f"call {n}{tag}"}]}})


def row(side, idx, rq, rs, status="ok", **extra):
    r = {"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side, "ns": f"demo-{side}",
         "idx": idx, "tool": "echo", "rpc_id": str(idx), "req": rq, "resp": rs,
         "status": status if rs is not None else "unanswered"}
    r.update(extra)
    return r


def honest(side, n):
    return [row(side, k, req(k), resp(k)) for k in range(1, n + 1)]


# -- 1. cross-repo tapes ------------------------------------------------------

def crossrepo() -> None:
    base = Path(tempfile.mkdtemp(prefix="reconcile-crossrepo-"))
    env = dict(os.environ)
    env["ARCAEON_LEDGER_REPO"] = str(LEDGER)
    env["ARCAEON_RECEIPT_REPO"] = str(RECEIPT)
    env["PYTHONPATH"] = os.pathsep.join([str(LEDGER), str(LEDGER / "adapter"), str(RECEIPT),
                                         env.get("PYTHONPATH", "")])
    runs = []
    if (RECEIPT / "tests" / "test_call_proxy_tape.py").exists():
        runs.append((RECEIPT, "tests/test_call_proxy_tape.py", "receipt"))
    for rel in ("adapter/test_http_forward.py", "adapter/test_tape.py"):
        if (LEDGER / rel).exists():
            runs.append((LEDGER, rel, "ledger"))
    for cwd, rel, tag in runs:
        bt = base / f"{tag}-{Path(rel).stem}"
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            rel, f"--basetemp={bt}"],
                           cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
        tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
        print(f"  pytest {tag}:{rel} -> exit {p.returncode}: {tail[0]}")
    n0 = len(CASES)
    for d in sorted({t.parent for t in base.rglob("*.tape.jsonl")}):
        tapes = sorted(d.glob("*.tape.jsonl"))
        rel = str(d.relative_to(base)).replace("\\", "/")
        agent = d / "agent.tape.jsonl"
        tool = d / "tool.tape.jsonl"
        if agent.exists() and tool.exists():
            add("crossrepo", f"{rel}: agent vs tool", agent.read_bytes(), tool.read_bytes())
            add("crossrepo", f"{rel}: tool vs agent", tool.read_bytes(), agent.read_bytes())
        for t in tapes:
            if t in (agent, tool) and agent.exists() and tool.exists():
                continue
            add("crossrepo", f"{rel}/{t.name} vs empty", t.read_bytes(), b"")
            add("crossrepo", f"{rel}/{t.name} vs itself", t.read_bytes(), t.read_bytes())
    print(f"  crossrepo cases: {len(CASES) - n0}")
    shutil.rmtree(base, ignore_errors=True)


# -- 2. the ledger's own reconcile cases -------------------------------------

def ledger_cases() -> None:
    import test_reconcile as TR
    captured = []
    real = R.reconcile

    def capture(a, b, *, pins=None, pin_path=None):
        captured.append((Path(a), Path(b), pin_path))
        return real(a, b, pins=pins, pin_path=pin_path)

    n0 = len(CASES)
    builders = list(TR.FAILURE_CASES) + list(TR.CNL_CASES)
    builders.append(("control_matched_6", lambda d: TR.run(d, *TR.pair(d, 6))))
    builders.append(("control_matched_swapped", lambda d: TR.run(d, *TR.pair(d, 4), swap=True)))
    builders.append(("limit_truncation_in_agreement", lambda d: TR.run(d, TR.pair(d)[0][:3], TR.pair(d)[1][:3])))
    R.reconcile = capture
    try:
        for b in builders:
            name, fn = (b if isinstance(b, tuple) else (b.__name__, b))
            captured.clear()
            with tempfile.TemporaryDirectory() as d:
                try:
                    fn(Path(d))
                except Exception as e:
                    print(f"  ledger case {name} raised while building: {e}")
                    continue
                if not captured:
                    continue
                a, bb, pin_path = captured[-1]
                if pin_path is not None or not a.is_file() or not bb.is_file():
                    continue  # pins and missing/directory tapes are not endpoint inputs
                R.reconcile = real
                try:
                    add("ledger", name, a.read_bytes(), bb.read_bytes())
                finally:
                    R.reconcile = capture
    finally:
        R.reconcile = real
    print(f"  ledger cases: {len(CASES) - n0}")


# -- 3. edge cases -------------------------------------------------------------

def edge() -> None:
    n0 = len(CASES)
    A, T = honest("agent", 3), honest("tool", 3)
    a, t = chained(A), chained(T)
    add("edge", "control_matched_3", a, t)
    add("edge", "empty_vs_empty", b"", b"")
    add("edge", "blank_lines_only", b"\n\n  \n", b"\r\n")

    # the chain serializer: floats, huge ints, unicode, escapes
    def rich(side):
        out = []
        for k in range(1, 5):
            out.append(row(side, k, req(k), resp(k), elapsed=[0.1, 1e-07, 1e16, 1e17, -0.0][k],
                           big=10 ** 30, neg=-(10 ** 25), tool="écho ✓ 雪 😀",
                           note="quote \" slash \\ nl \n tab \t ctl \x01 del \x7f",
                           nested={"z": [1, 2.5, None, True], "a": {"é": 1, "😀": 2, "￿": 3}},
                           u2028="a b\u0085c"))
        return out
    add("edge", "rich_values_matched", chained(rich("agent")), chained(rich("tool")))
    rt = chained(rich("tool")).replace("雪".encode(), "雨".encode(), 1)
    add("edge", "rich_values_edited", chained(rich("agent")), rt)

    # NaN / Infinity in a row: Python reads and chains them
    nan_a = [dict(r, score=float("nan"), hi=float("inf"), lo=float("-inf")) for r in A]
    nan_t = [dict(r, score=float("nan"), hi=float("inf"), lo=float("-inf")) for r in T]
    add("edge", "nan_infinity_rows_matched", chained(nan_a), chained(nan_t))
    add("edge", "float_overflow_token", chained(A).replace(b'"idx": 2,', b'"idx": 2, "x": 1e400,', 1), t)

    # lone surrogates, written as escapes and chained with surrogatepass
    ls_a = [dict(r, weird="\ud800 lone \udfff") for r in A]
    ls_t = [dict(r, weird="\ud800 lone \udfff") for r in T]
    add("edge", "lone_surrogates_matched", chained(ls_a, ascii_=True), chained(ls_t, ascii_=True))
    ls_t2 = [dict(r) for r in T]
    ls_t2[1]["req"] = "\udc00" + ls_t2[1]["req"]
    add("edge", "lone_surrogate_in_req_altered", chained(A), chained(ls_t2, ascii_=True))
    add("edge", "surrogate_pair_escapes", chained([dict(r, e="😀") for r in A], ascii_=True),
        chained([dict(r, e="😀") for r in T], ascii_=False))

    # the 4300-digit int limit
    for nd in (4300, 4301):
        for sign in ("", "-"):
            big = (sign + "7" * nd).encode()
            add("edge", f"int_{sign or '+'}{nd}_digits", a.replace(b'"idx": 1,', b'"idx": 1, "big": ' + big + b",", 1), t)

    # duplicate keys
    lines = a.split(b"\n")
    for name, l1 in [
        ("dup_key_top", lines[1].replace(b'{"evt"', b'{"idx": 9, "evt"', 1)),
        ("dup_key_nested", lines[1].replace(b'{"evt"', b'{"n": {"q": 1, "q": 2}, "evt"', 1)),
        ("dup_key_nonascii", lines[1].replace(b'{"evt"', "{\"é'\\\"\": 1, \"é'\\\"\": 2, \"evt\"".encode(), 1)),
        ("dup_key_in_array", b'[{"a": 1, "a": 2}]'),
        ("dup_key_then_junk", b'{"a": 1, "a": 2} x'),
    ]:
        ls = list(lines)
        ls[1] = l1
        add("edge", name, b"\n".join(ls), t)

    # text decoding: BOM, CRLF, lone CR, invalid UTF-8
    add("edge", "bom_on_tool_tape", a, b"\xef\xbb\xbf" + t)
    add("edge", "crlf_matched", a.replace(b"\n", b"\r\n"), t.replace(b"\n", b"\r\n"))
    add("edge", "lone_cr_separators", a.replace(b"\n", b"\r"), t)
    for i, junk in enumerate([b"\xed\xa0\x80", b"\xc0\x80", b"\xe2\x82", b"\xf4\x90\x80\x80",
                              b"\xf0\x9f\x98", b"\xff\xfe", b"\x80abc"]):
        add("edge", f"invalid_utf8_{i}", a.replace(b'"tool": "echo"', b'"tool": "ec' + junk + b'ho"', 2), t)
        add("edge", f"invalid_utf8_line_{i}", a + junk + b"\n", t)
        # Chained over what errors="replace" reads, written as the raw bad bytes:
        # verifies ONLY if the port replaces exactly as CPython does.
        seen_as = junk.decode("utf-8", "replace")
        rows = [dict(r, tool="ec" + seen_as + "ho") for r in A]
        raw = chained(rows).replace(("ec" + seen_as + "ho").encode(), b"ec" + junk + b"ho")
        add("edge", f"invalid_utf8_rechained_{i}", raw, t)

    # whitespace str.strip() removes and json.loads does not
    for i, ws in enumerate(["\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", " ", "　", "﻿"]):
        wb = ws.encode()
        ls = list(lines)
        ls[1] = wb + ls[1] + wb
        add("edge", f"row_wrapped_in_U+{ord(ws):04X}", b"\n".join(ls), t)
        add("edge", f"blank_line_of_U+{ord(ws):04X}", a + wb + b"\n", t)
    add("edge", "row_with_spaces_and_tabs", b"\n".join([b" \t" + x + b"\t " if x else x for x in lines]), t)

    # the tape-row predicate
    for name, rep in [("idx_float", b'"idx": 1.0'), ("idx_true", b'"idx": true'), ("idx_string", b'"idx": "1"'),
                      ("idx_zero", b'"idx": 0'), ("idx_negative", b'"idx": -1'), ("idx_exp", b'"idx": 1e0'),
                      ("idx_huge", b'"idx": 100000000000000000000000000000')]:
        rows = [dict(r) for r in A]
        raw = chained(rows).replace(b'"idx": 1', rep, 1)
        add("edge", f"{name}_not_rechained", raw, t)
        try:
            val = json.loads(rep.split(b": ", 1)[1])
            rows[0]["idx"] = val
            add("edge", f"{name}_rechained", chained(rows), t)
        except Exception:
            pass
    rows = [dict(r) for r in A]
    rows[1]["resp"] = 5
    add("edge", "resp_number_rechained", chained(rows), t)
    rows = [dict(r) for r in A]
    rows[1]["req"] = None
    add("edge", "req_null_rechained", chained(rows), t)
    rows = [dict(r) for r in A]
    del rows[2]["resp"]
    add("edge", "resp_absent_rechained", chained(rows), chained([dict(r, resp=None) if r["idx"] == 3 else r for r in T]))
    rows = [dict(r) for r in A]
    rows[1]["side"] = "tool"
    add("edge", "mixed_sides_rechained", chained(rows), t)
    add("edge", "same_side_twice", a, a)
    add("edge", "not_a_tape_row", chained([{"evt": "tool_call", "x": 1}]), t)
    add("edge", "chain_null", a.replace(b'"chain": "', b'"chainX": "', 1), t)
    add("edge", "chain_number", chained(A).replace(b'"chain": "', b'"chain": 5, "c": "', 1), t)
    add("edge", "top_level_array_line", a + b"[1, 2]\n", t)
    add("edge", "top_level_string_line", b'"hello"\n' + a, t)
    add("edge", "unchained_prechain_row", json.dumps(A[0]).encode() + b"\n" + a, t)
    add("edge", "unchained_row_after_chain", a + json.dumps(A[0]).encode() + b"\n", t)
    add("edge", "trailing_comma", a.replace(b'"status": "ok"', b'"status": "ok",', 1), t)
    add("edge", "leading_zero_number", a.replace(b'"idx": 2', b'"idx": 02', 1), t)
    add("edge", "control_char_in_string", a.replace(b'"tool": "echo"', b'"tool": "ec\x01ho"', 1), t)
    add("edge", "bad_escape", a.replace(b"demo-agent", b"demo\\xagent", 1), t)
    add("edge", "bad_u_escape", a.replace(b"demo-agent", b"demo\\u12G4agent", 1), t)
    add("edge", "high_surrogate_then_bad_u", chained(A).replace(b"demo-agent", b"demo\\ud800\\u12G4agent", 1), t)

    # nesting: within the port's depth, and past it (the port refuses)
    for depth in (100, MAX_DEPTH - 2, MAX_DEPTH + 10):
        deep = [dict(r, deep=json.loads("[" * depth + "]" * depth)) for r in A]
        add("edge", f"nested_{depth}_both", chained(deep), chained([dict(r, deep=json.loads("[" * depth + "]" * depth)) for r in T]))

    # The 512-level bound, line by line, as the hardened reconcile.py counts it:
    # the deepest nesting the parser opens before it stops (the end when the
    # line parses, the error position when it does not, the whole line when the
    # stop is a 4300-digit int). Brackets inside strings do not count.
    def deep_obj(depth):
        return ('{"k":' * depth + "1" + "}" * depth).encode()

    def deep_mixed(depth):
        return ('[{"k":' * (depth // 2) + "[" * (depth % 2) + "1" + "]" * (depth % 2) + "}]" * (depth // 2)).encode()
    for d in (MAX_DEPTH, MAX_DEPTH + 1):
        add("edge", f"line_arrays_{d}", a + b"[" * d + b"]" * d + b"\n", t)
        add("edge", f"line_objects_{d}", a + deep_obj(d) + b"\n", t)
        add("edge", f"line_mixed_{d}", a + deep_mixed(d) + b"\n", t)
    add("edge", "line_brackets_in_string_600", a + b'{"s": "' + b"[" * 600 + b'"}\n', t)
    add("edge", "line_syntax_error_before_600", a + b"[1,,]" + b"[" * 600 + b"\n", t)
    add("edge", "line_unclosed_513", a + b"[" * 513 + b"\n", t)
    add("edge", "line_unclosed_512_then_junk", a + b"[" * 512 + b"x" + b"[" * 100 + b"\n", t)
    add("edge", "line_deep_600_then_syntax_error", a + b"[" * 600 + b"1,,\n", t)
    add("edge", "deep_first_wins_over_dup", a + b"[" * 600 + b"\n" + b'{"a":1,"a":2} x\n', t)
    add("edge", "dup_first_wins_over_deep", a + b'{"a":1,"a":2} x\n' + b"[" * 600 + b"\n", t)
    add("edge", "dup_key_then_deep_same_line", a + b'[{"a":1,"a":2},' + b"[" * 600 + b"\n", t)
    add("edge", "deep_in_tool_tape_only", a, t + b"[" * 600 + b"]" * 600 + b"\n")
    add("edge", "deep_line_after_blank_lines", a + b"\n\n  \n" + b"[" * 600 + b"\n", t)
    add("edge", "deep_line_wrapped_in_U+000B", a + b"\x0b" + b"[" * 600 + b"]" * 600 + b"\x0b\n", t)
    # A 4300+-digit int stops json.loads with a plain ValueError, not a
    # JSONDecodeError: reconcile.py then counts the WHOLE line.
    for nd in (4300, 4301):
        big = b"7" * nd
        add("edge", f"int_{nd}_digits_then_deep_600", a + b"[" + big + b"," + b"[" * 600 + b"]" * 600 + b"]\n", t)
        add("edge", f"int_{nd}_digits_then_junk_then_deep_600", a + b"[" + big + b",,x" + b"[" * 600 + b"\n", t)
    add("edge", "deep_600_then_int_4301", a + b"[" + b"[" * 600 + b"]" * 600 + b"," + b"7" * 4301 + b"]\n", t)

    # swap the argument order on a finding
    add("edge", "altered_swapped", t, chained([dict(r, resp=resp(r["idx"], "!")) if r["idx"] == 2 else r for r in A]))
    print(f"  edge cases: {len(CASES) - n0}")


# -- 4. seeded fuzz ------------------------------------------------------------

def fuzz(n: int, seed: int = 20260923) -> None:
    rnd = random.Random(seed)
    n0 = len(CASES)

    def mutate_rows(rows, side):
        rows = [dict(r) for r in rows]
        op = rnd.choice(["drop", "dup", "swap", "edit_resp", "edit_req", "null_resp", "renumber",
                         "extra", "rpc_id", "none"])
        if not rows:
            return rows, op
        k = rnd.randrange(len(rows))
        if op == "drop":
            rows.pop(k)
        elif op == "dup":
            rows.insert(k, dict(rows[k]))
        elif op == "swap" and len(rows) > 1:
            j = rnd.randrange(len(rows))
            rows[k], rows[j] = rows[j], rows[k]
        elif op == "edit_resp":
            rows[k]["resp"] = resp(rows[k]["idx"], "!")
        elif op == "edit_req":
            rows[k]["req"] = req(1000 + k)
        elif op == "null_resp":
            rows[k]["resp"] = None
            rows[k]["status"] = "unanswered"
        elif op == "renumber":
            rows[k]["idx"] = rnd.choice([0, 1, rows[k]["idx"] + 1, rows[k]["idx"] + 5, rows[k]["idx"] - 1])
        elif op == "extra":
            m = 500 + k
            rows.insert(k, row(side, rows[k]["idx"], req(m), resp(m)))
        elif op == "rpc_id":
            rows[k]["rpc_id"] = rnd.choice(["true", "99", None, '{"k":1}'])
        return rows, op

    def mutate_bytes(data):
        op = rnd.choice(["truncate", "flip_hex", "drop_line", "dup_line", "swap_lines", "junk_line",
                         "blank_lines", "crlf", "none", "none"])
        lines = data.split(b"\n")
        if op == "truncate" and data:
            data = data[:rnd.randrange(len(data))]
        elif op == "flip_hex" and b'"resp": "sha256' in data:
            pos = data.rfind(b'"resp": "sha256') + 40 + rnd.randrange(20)
            ch = data[pos:pos + 1]
            data = data[:pos] + (b"0" if ch != b"0" else b"1") + data[pos + 1:]
        elif op == "drop_line" and len(lines) > 1:
            lines.pop(rnd.randrange(len(lines) - 1))
            data = b"\n".join(lines)
        elif op == "dup_line" and len(lines) > 1:
            k = rnd.randrange(len(lines) - 1)
            lines.insert(k, lines[k])
            data = b"\n".join(lines)
        elif op == "swap_lines" and len(lines) > 2:
            i, j = rnd.randrange(len(lines) - 1), rnd.randrange(len(lines) - 1)
            lines[i], lines[j] = lines[j], lines[i]
            data = b"\n".join(lines)
        elif op == "junk_line":
            lines.insert(rnd.randrange(len(lines)), rnd.choice([b"{}", b"not json", b"[]", b"null", b'{"chain": 1}']))
            data = b"\n".join(lines)
        elif op == "blank_lines":
            data = data.replace(b"\n", b"\n\n  \n", 1)
        elif op == "crlf":
            data = data.replace(b"\n", b"\r\n")
        return data, op

    for i in range(n):
        na, nt = rnd.randint(0, 6), rnd.randint(0, 6)
        common = rnd.randint(0, 6)
        A = honest("agent", common if rnd.random() < 0.7 else na)
        T = honest("tool", common if rnd.random() < 0.7 else nt)
        ops = []
        if rnd.random() < 0.6:
            A, op = mutate_rows(A, "agent")
            ops.append("a:" + op)
        if rnd.random() < 0.6:
            T, op = mutate_rows(T, "tool")
            ops.append("t:" + op)
        a, t = chained(A), chained(T)
        if rnd.random() < 0.35:
            a, op = mutate_bytes(a)
            ops.append("a:" + op)
        if rnd.random() < 0.35:
            t, op = mutate_bytes(t)
            ops.append("t:" + op)
        if rnd.random() < 0.2:
            a, t = t, a
            ops.append("swap_args")
        add("fuzz", f"fuzz_{i:03d} {' '.join(ops) or 'honest'}", a, t)
    print(f"  fuzz cases: {len(CASES) - n0}")


def main() -> int:
    print(f"reference: {LEDGER}")
    crossrepo()
    ledger_cases()
    edge()
    fuzz(int(os.environ.get("RECONCILE_FUZZ_CASES", "260")))
    doc = {
        "generated_by": "test/fixtures/reconcile/make_fixtures.py",
        "reference": {
            "package": "arcaeon-ledger",
            "version": L.__version__,
            "reconcile_sha256": lf_sha256(LEDGER / "arcaeon_ledger" / "reconcile.py"),
            "ledger_init_sha256": lf_sha256(LEDGER / "arcaeon_ledger" / "__init__.py"),
            "python": sys.version.split()[0],
        },
        "serializer": 'json.dumps(result.to_dict(), sort_keys=True, ensure_ascii=True, separators=(",", ":"))',
        "cases": CASES,
    }
    OUT.write_text(json.dumps(doc, indent=0, ensure_ascii=True) + "\n", encoding="utf-8")
    by = {}
    for c in CASES:
        by[c["source"]] = by.get(c["source"], 0) + 1
    print(f"{len(CASES)} cases {by} -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

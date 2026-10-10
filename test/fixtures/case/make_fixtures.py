#!/usr/bin/env python3
"""make_fixtures.py: build test/fixtures/case/c14n_cases.json, the bytes
test/case_protocol.test.js (tests 1 and 2) holds lib/_case.js to.

Every canonical byte string in the fixture is written by the REAL
json-c14n:v1 canonicalizer, arcaeon_ledger.artefact._canon_json:

    json.dumps(value, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False, allow_nan=False).encode("utf-8")

loaded from an arcaeon-ledger checkout and run in this process. The case id
rule's two extra steps are written here independently of the Node code, from
the design's words (CASE_PROTOCOL_DESIGN_2026-10-10.md, version 2):

  * parties "in canonical order (sorted by `label`, then `side`)": Python's
    own tuple ordering on (label, side), which compares str by code point;
  * opened_at "normalized to UTC seconds": parsed, moved to UTC with
    datetime, fraction dropped, written YYYY-MM-DDTHH:MM:SSZ.

Each case id case lists several inputs that describe the SAME opening (the
two parties in either order, opened_at with a fraction or an offset); this
script derives every one and stops if they do not give one preimage. A port
that agrees with itself cannot bless a fixture.

    ARCAEON_LEDGER_REPO=<arcaeon-ledger checkout> py -B test/fixtures/case/make_fixtures.py

Without ARCAEON_LEDGER_REPO it looks for a sibling arcaeon-ledger-rel080, then
arcaeon-ledger. artefact.py is loaded on its own (no package import) with
bytecode writing off, so nothing is written into the ledger checkout.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import inspect
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
OUT = HERE / "c14n_cases.json"
ROOT = HERE.parents[2]


def _find_artefact() -> Path:
    env = os.environ.get("ARCAEON_LEDGER_REPO")
    cands = [Path(env)] if env else [ROOT.parent / "arcaeon-ledger-rel080", ROOT.parent / "arcaeon-ledger"]
    for c in cands:
        p = c / "arcaeon_ledger" / "artefact.py"
        if p.is_file():
            return p
    raise SystemExit(f"no arcaeon_ledger/artefact.py under {', '.join(str(c) for c in cands)}")


ARTEFACT = _find_artefact()
_spec = importlib.util.spec_from_file_location("_case_fixture_artefact", ARTEFACT)
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)
canon = _mod._canon_json

PROTOCOL_VERSION = "case/1"
POLICY_VERSION = "0.1.0"  # lib/_reconcile_tapes.js PORT_VERSION, as the receipt reports it

ISO_IN = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))")


def utc_seconds(s: str) -> str:
    m = ISO_IN.fullmatch(s)
    if not m:
        raise SystemExit(f"fixture input {s!r} is not an accepted time form")
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    if m.group(8) == "Z":
        tz = timezone.utc
    else:
        sign = -1 if m.group(9) == "-" else 1
        tz = timezone(sign * timedelta(hours=int(m.group(10)), minutes=int(m.group(11))))
    return datetime(y, mo, d, h, mi, se, tzinfo=tz).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_party(p: dict) -> dict:
    out = {"side": p["side"], "label": p["label"]}
    if "key_id" in p:
        out["key_id"] = p["key_id"]
    return out


def case_id_preimage(inp: dict) -> dict:
    a, b = clean_party(inp["party_a"]), clean_party(inp["party_b"])
    ka, kb = (a["label"], a["side"]), (b["label"], b["side"])
    if ka == kb:
        raise SystemExit("fixture parties cannot be ordered")
    first, second = (a, b) if ka < kb else (b, a)
    return {
        "protocol_version": inp["protocol_version"],
        "policy_version": inp["policy_version"],
        "scope_digest": inp["scope_digest"],
        "party_a": first,
        "party_b": second,
        "opened_at": utc_seconds(inp["opened_at"]),
    }


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def opening(pa: dict, pb: dict, opened_at: str, scope: str) -> dict:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "policy_version": POLICY_VERSION,
        "scope_digest": scope,
        "party_a": pa,
        "party_b": pb,
        "opened_at": opened_at,
    }


def variants(pa: dict, pb: dict, times: list[str], scope: str) -> list[dict]:
    """Both parties' inputs: each party lists itself first, under each time form."""
    out = []
    for t in times:
        out.append(opening(pa, pb, t, scope))
        out.append(opening(pb, pa, t, scope))
    return out


SCOPE_1 = sha(b"scope manifest one\n")
SCOPE_2 = sha(b"scope manifest two\n")

CASE_ID_CASES = [
    ("plain_ascii",
     {"side": "agent", "label": "alice@example.com"}, {"side": "tool", "label": "bob-tools"},
     ["2026-10-10T07:00:00Z", "2026-10-10T07:00:00.999Z", "2026-10-10T09:00:00+02:00", "2026-10-10T02:00:00.5-05:00"],
     SCOPE_1),
    ("same_label_ordered_by_side",
     {"side": "tool", "label": "acme"}, {"side": "agent", "label": "acme"},
     ["2026-10-10T12:34:56Z", "2026-10-10T12:34:56.123456789Z"],
     SCOPE_2),
    ("non_ascii_quote_backslash_key_id",
     {"side": "agent", "label": "Zoë \"the agent\" \\ ops", "key_id": "ed25519:" + "A" * 43 + "="},
     {"side": "tool", "label": "東京-tool"},
     ["2026-10-10T07:00:00Z", "2026-10-10T16:00:00+09:00"],
     SCOPE_1),
    # U+FF21 sorts BEFORE U+1F600 by code point (Python, json-c14n); a JS `<`
    # on UTF-16 code units puts the emoji first (0xD83D < 0xFF21).
    ("astral_label_code_point_order",
     {"side": "agent", "label": "\U0001F600-agent"}, {"side": "tool", "label": "Ａ-tool"},
     ["2026-10-10T07:00:00Z"],
     SCOPE_2),
    ("offset_crosses_the_day",
     {"side": "agent", "label": "agent-x", "key_id": "key-1"}, {"side": "tool", "label": "tool-y", "key_id": "key-2"},
     ["2026-10-10T20:00:00Z", "2026-10-11T01:30:00+05:30", "2026-10-10T15:00:00.000-05:00"],
     SCOPE_1),
]


def build_case_ids() -> list[dict]:
    out = []
    for name, pa, pb, times, scope in CASE_ID_CASES:
        ins = variants(pa, pb, times, scope)
        pres = [canon(case_id_preimage(i)) for i in ins]
        if len(set(pres)) != 1:
            raise SystemExit(f"{name}: the inputs do not derive one preimage")
        b = pres[0]
        out.append({
            "name": name,
            "inputs": ins,
            "preimage_b64": base64.b64encode(b).decode("ascii"),
            "preimage_text": b.decode("utf-8"),
            "case_id": sha(b),
        })
    return out


def commitment(case_id: str, role: str, tape_sha256: str, salt: str) -> dict:
    return {"case_id": case_id, "role": role, "tape_sha256": tape_sha256, "salt": salt,
            "protocol_version": PROTOCOL_VERSION}


def build_commitments(case_id: str) -> list[dict]:
    tape_a = sha(b'{"agent tape":"row 1"}\n')
    tape_b = sha(b'{"tool tape":"row 1"}\n')
    salt_1 = sha(b"salt one")
    salt_2 = sha(b"salt two")
    cases = [
        ("role_a", "a", tape_a, salt_1),
        ("role_b_same_tape_and_salt", "b", tape_a, salt_1),
        ("role_a_salt_changed", "a", tape_a, salt_2),
        ("role_a_tape_changed", "a", tape_b, salt_1),
    ]
    out = []
    for name, role, tape, salt in cases:
        pre = commitment(case_id, role, tape, salt)
        b = canon(pre)
        inp = {k: v for k, v in pre.items() if k != "protocol_version"}
        out.append({
            "name": name,
            "input": inp,
            "bytes_b64": base64.b64encode(b).decode("ascii"),
            "bytes_text": b.decode("utf-8"),
            "length": len(b),
            "commitment_sha256": sha(b),
        })
    if len({c["commitment_sha256"] for c in out}) != len(out):
        raise SystemExit("two commitment cases share a hash")
    return out


def main() -> None:
    case_ids = build_case_ids()
    doc = {
        "generator": "test/fixtures/case/make_fixtures.py",
        "canonicalizer": {
            "function": "arcaeon_ledger.artefact._canon_json",
            "ledger_checkout": ARTEFACT.parents[1].name,
            "artefact_sha256_lf": sha(ARTEFACT.read_bytes().replace(b"\r\n", b"\n")),
            "canon_json_source_sha256": sha(inspect.getsource(canon).encode("utf-8")),
            "python": "%d.%d.%d" % sys.version_info[:3],
        },
        "protocol_version": PROTOCOL_VERSION,
        "policy_version": POLICY_VERSION,
        "case_ids": case_ids,
        "commitments": build_commitments(case_ids[0]["case_id"]),
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(doc['case_ids'])} case id cases, {len(doc['commitments'])} commitment cases")


if __name__ == "__main__":
    main()

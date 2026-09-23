// _reconcile_tapes.js — a faithful Node port of arcaeon_ledger.reconcile
// (arcaeon-ledger 0.8.0, arcaeon_ledger/reconcile.py) plus the part of
// arcaeon_ledger.verify_file(strict=True) it depends on. Underscore prefix =
// not routed as a serverless function by Vercel.
//
// WHY A PORT AND NOT A SHELL-OUT TO THE PYTHON
// ------------------------------------------
// The witness API runs on Vercel's Node runtime. That runtime does not promise
// a Python interpreter, and api/ is at the Hobby plan's 12-function cap, so a
// second (Python) function is not available either. A port that is checked
// against the Python on every case is the only honest option: test/
// reconcile_conformance.test.js replays cases whose expected answer was
// written by the real reconcile.py (test/fixtures/reconcile/make_fixtures.py)
// and demands the SAME JSON, byte for byte, under Python's own serializer.
//
// WHAT THE PORT HAS TO REPRODUCE (each one a place a naive port lies)
// -------------------------------------------------------------------
//   * Reading bytes the way Path.read_text(encoding="utf-8", errors="replace")
//     does: invalid UTF-8 becomes U+FFFD, a BOM is KEPT (Python's utf-8 codec
//     keeps it, TextDecoder strips it unless told not to), and \r\n / \r fold
//     to \n (universal newlines).
//   * Python's str.strip() (str.isspace), not String#trim: trim strips U+FEFF
//     and leaves U+001C..U+001F and U+0085 alone; Python does the opposite.
//   * Python's json.loads, not JSON.parse: ints stay arbitrary-precision
//     (BigInt here), `1` and `1.0` stay different types (a float `idx` is not
//     a call index), NaN / Infinity / -Infinity are accepted, raw control
//     characters in strings are refused, a lone \ud800 escape survives as a
//     lone surrogate, an int longer than 4300 digits is refused (CPython's
//     int_max_str_digits), and a duplicate key is a named break in the strict
//     read, raised when its object CLOSES (inner objects first).
//   * The chain: sha256(prev + json.dumps(row_without_chain, sort_keys=True,
//     ensure_ascii=False)) with Python's DEFAULT ", " / ": " separators,
//     Python's float repr, keys in code-point order, and the text encoded
//     UTF-8 with surrogatepass, first 32 hex characters.
//
// WHERE THIS PORT DOES NOT FOLLOW THE PYTHON, AND WHAT IT SAYS INSTEAD
// --------------------------------------------------------------------
// Three inputs make reconcile.py itself raise instead of answering (found
// while building this port; reported, not fixed here, because the reference
// is a released package in another repo):
//   1. a line whose strict read finds a duplicate key and whose plain read
//      then fails (e.g. `{"a":1,"a":2} x`): verify_file's except-handler
//      calls _loads again and the JSONDecodeError escapes;
//   2. a row that verifies but carries leading/trailing whitespace that
//      str.strip() removes and json.loads does not (\x0b, \x0c, \x1c-\x1f,
//      \x85, U+2028 ...): _load's second read raises;
//   3. a row nested deeper than CPython's C recursion guard in _peek_side,
//      which catches ValueError but not RecursionError.
// For each of these the port answers COULD NOT LOOK and says why. It never
// turns a crash into a MATCHED, a MISSING or an ALTERED.
// And one input it refuses on its own: a row nested deeper than MAX_DEPTH.
// CPython's own limit is a C-stack guard that moves with the platform and the
// Python version (measured 16,912 nested arrays and 14,310 nested objects on
// Python 3.14.3 / Windows), so no fixed number reproduces it. A tape row is
// flat; anything that deep is COULD NOT LOOK here, never a guess.
//
// Pins (`reconcile --pin`) are NOT ported in this slice: the pin file's
// refusal messages are CPython's JSONDecodeError text and Python repr() of
// arbitrary values, and a pin submitted to a public service is only as good
// as whoever submitted it. The endpoint refuses a pin rather than ignoring it.

"use strict";

const crypto = require("node:crypto");

const PORT_VERSION = "0.1.0";
const REFERENCE = Object.freeze({
  package: "arcaeon-ledger",
  version: "0.8.0",
  module: "arcaeon_ledger/reconcile.py",
  // sha256 of reconcile.py and of arcaeon_ledger/__init__.py (verify_file,
  // chain_at, _chain) at the release-ledger-0.8.0 tip this port was built and
  // checked against. make_fixtures.py records the same two digests into the
  // fixture file (CRLF folded to LF, i.e. the git blob), and the conformance
  // test refuses a fixture made from different sources.
  reconcile_sha256: "20806e33353ee232c18f1d42d4b938119dedd65befa0e9a109994afbfc0bfef5",
  ledger_init_sha256: "120f1bc9d9f717d6c1feb1a070561aedfdf817b027c16d496f5e2caaa832f63d",
});

const TAPE_FORMAT = "arcaeon-tape/1";
const SIDES = Object.freeze(["agent", "tool"]);

const MATCHED = "MATCHED";
const MISSING = "MISSING";
const ALTERED = "ALTERED";
const COULD_NOT_LOOK = "COULD_NOT_LOOK";
const EXIT_CODES = Object.freeze({ MATCHED: 0, MISSING: 1, ALTERED: 1, COULD_NOT_LOOK: 2 });

// reconcile.py LIMITS, verbatim. Carried in every result.
const LIMITS = Object.freeze([
  "MATCHED means two recorders agree; a colluding agent side and tool side can " +
    "write two agreeing tapes of a lie.",
  "A call that crossed neither instrumented seam leaves no row on either tape; " +
    "an agent that never calls, or calls through an unwrapped channel, is invisible here.",
  "Digests compare content (canonical JSON), not bytes: a meaning-preserving " +
    "re-serialization in transit is MATCHED by design.",
  "Without a witness pin, both tapes truncated or rewritten in agreement still " +
    "match; a pin bounds that to the rows written after it.",
]);

const GENESIS = "genesis";
const CHAIN_LEN = 32;
const MAX_INT_DIGITS = 4300; // CPython sys.int_info.default_max_str_digits
const MAX_DEPTH = 512;

// ---------------------------------------------------------------------------
// value types that keep Python's distinctions
// ---------------------------------------------------------------------------
class PyFloat {
  constructor(v) { this.v = v; }
}

class ParseError extends Error {}
class DuplicateKeyError extends Error {
  constructor(key) { super("duplicate key"); this.key = key; }
}
// Input the reference would read (or crash on) but this port will not guess at.
class CannotReproduce extends Error {}

// ---------------------------------------------------------------------------
// bytes -> text, the way Path.read_text(encoding="utf-8", errors="replace") does
// ---------------------------------------------------------------------------
function decodeText(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(bytes);
  return text.replace(/\r\n|\r/g, "\n");
}

// str.isspace() for the characters str.strip() removes.
const PY_WS_CLASS = "\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_STRIP_RE = new RegExp(`^[${PY_WS_CLASS}]+|[${PY_WS_CLASS}]+$`, "g");
function pyStrip(s) {
  return s.replace(PY_STRIP_RE, "");
}

// ---------------------------------------------------------------------------
// json.loads, CPython's C scanner semantics
// ---------------------------------------------------------------------------
function isDigit(c) {
  return c >= "0" && c <= "9";
}
const HEX4 = /^[0-9a-fA-F]{4}$/;

// strictDup: raise DuplicateKeyError when an object closes holding a key twice
// (arcaeon_ledger._loads_strict's object_pairs_hook). Otherwise last one wins,
// at the first one's position (a dict update, and a Map#set).
function pyLoads(text, strictDup) {
  const n = text.length;
  let i = 0;
  let depth = 0;

  function skipWs() {
    while (i < n) {
      const c = text[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i++;
      else break;
    }
  }
  function fail(msg) {
    throw new ParseError(`${msg} at ${i}`);
  }
  function enter() {
    depth++;
    if (depth > MAX_DEPTH) throw new CannotReproduce(`nested deeper than ${MAX_DEPTH} levels`);
  }
  function value() {
    if (i >= n) fail("Expecting value");
    const c = text[i];
    if (c === '"') return string();
    if (c === "{") return object();
    if (c === "[") return array();
    if (c === "n" && text.startsWith("null", i)) { i += 4; return null; }
    if (c === "t" && text.startsWith("true", i)) { i += 4; return true; }
    if (c === "f" && text.startsWith("false", i)) { i += 5; return false; }
    if (c === "N" && text.startsWith("NaN", i)) { i += 3; return new PyFloat(NaN); }
    if (c === "I" && text.startsWith("Infinity", i)) { i += 8; return new PyFloat(Infinity); }
    if (c === "-" && text.startsWith("-Infinity", i)) { i += 9; return new PyFloat(-Infinity); }
    return number();
  }
  function number() {
    const start = i;
    let j = i;
    if (text[j] === "-") j++;
    if (j < n && text[j] >= "1" && text[j] <= "9") {
      j++;
      while (j < n && isDigit(text[j])) j++;
    } else if (text[j] === "0") {
      j++;
    } else {
      fail("Expecting value");
    }
    let isFloat = false;
    if (text[j] === "." && j + 1 < n && isDigit(text[j + 1])) {
      isFloat = true;
      j += 2;
      while (j < n && isDigit(text[j])) j++;
    }
    if (text[j] === "e" || text[j] === "E") {
      let k = j + 1;
      if (text[k] === "+" || text[k] === "-") k++;
      if (k < n && isDigit(text[k])) {
        while (k < n && isDigit(text[k])) k++;
        isFloat = true;
        j = k;
      }
    }
    const raw = text.slice(start, j);
    i = j;
    if (isFloat) return new PyFloat(Number(raw));
    const digits = raw[0] === "-" ? raw.length - 1 : raw.length;
    if (digits > MAX_INT_DIGITS) fail("Exceeds the limit (4300 digits) for integer string conversion");
    return BigInt(raw);
  }
  function string() {
    i++; // opening quote
    let out = "";
    let chunkStart = i;
    for (;;) {
      if (i >= n) fail("Unterminated string");
      const c = text[i];
      const code = text.charCodeAt(i);
      if (c === '"') {
        out += text.slice(chunkStart, i);
        i++;
        return out;
      }
      if (code < 0x20) fail("Invalid control character");
      if (c !== "\\") {
        i++;
        continue;
      }
      out += text.slice(chunkStart, i);
      i++;
      if (i >= n) fail("Unterminated string");
      const e = text[i];
      if (e === '"') out += '"';
      else if (e === "\\") out += "\\";
      else if (e === "/") out += "/";
      else if (e === "b") out += "\b";
      else if (e === "f") out += "\f";
      else if (e === "n") out += "\n";
      else if (e === "r") out += "\r";
      else if (e === "t") out += "\t";
      else if (e === "u") {
        const hex = text.slice(i + 1, i + 5);
        if (!HEX4.test(hex)) fail("Invalid \\uXXXX escape");
        const cu = parseInt(hex, 16);
        i += 4;
        // A high surrogate followed by "\u" + a low surrogate joins into one
        // code point in Python; in UTF-16 the two units ARE that code point.
        // A high surrogate followed by "\u" + bad hex is an error in Python.
        if (cu >= 0xd800 && cu <= 0xdbff && text[i + 1] === "\\" && text[i + 2] === "u") {
          const hex2 = text.slice(i + 3, i + 7);
          if (!HEX4.test(hex2)) {
            i += 2;
            fail("Invalid \\uXXXX escape");
          }
        }
        out += String.fromCharCode(cu);
      } else {
        fail("Invalid \\escape");
      }
      i++;
      chunkStart = i;
    }
  }
  function object() {
    enter();
    i++; // {
    const pairs = [];
    skipWs();
    if (text[i] === "}") {
      i++;
      depth--;
      return new Map();
    }
    for (;;) {
      if (text[i] !== '"') fail("Expecting property name enclosed in double quotes");
      const key = string();
      skipWs();
      if (text[i] !== ":") fail("Expecting ':' delimiter");
      i++;
      skipWs();
      pairs.push([key, value()]);
      skipWs();
      if (text[i] === "}") {
        i++;
        break;
      }
      if (text[i] !== ",") fail("Expecting ',' delimiter");
      i++;
      skipWs();
    }
    depth--;
    const m = new Map();
    for (const [k, v] of pairs) {
      if (strictDup && m.has(k)) throw new DuplicateKeyError(k);
      m.set(k, v);
    }
    return m;
  }
  function array() {
    enter();
    i++; // [
    const arr = [];
    skipWs();
    if (text[i] === "]") {
      i++;
      depth--;
      return arr;
    }
    for (;;) {
      arr.push(value());
      skipWs();
      if (text[i] === "]") {
        i++;
        break;
      }
      if (text[i] !== ",") fail("Expecting ',' delimiter");
      i++;
      skipWs();
    }
    depth--;
    return arr;
  }

  // json.loads(str): a leading BOM is refused outright, then whitespace, one
  // value, whitespace, end.
  if (text.charCodeAt(0) === 0xfeff) fail("Unexpected UTF-8 BOM");
  skipWs();
  const v = value();
  skipWs();
  if (i !== n) fail("Extra data");
  return v;
}

// ---------------------------------------------------------------------------
// json.dumps, Python's shapes
// ---------------------------------------------------------------------------
// CPython float repr (shortest round-trip digits, repr layout).
function pyFloatRepr(v) {
  if (Number.isNaN(v)) return "NaN";
  if (v === Infinity) return "Infinity";
  if (v === -Infinity) return "-Infinity";
  if (v === 0) return Object.is(v, -0) ? "-0.0" : "0.0";
  const neg = v < 0;
  const m = /^(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(Math.abs(v).toExponential());
  const digits = m[1] + (m[2] || "");
  const e = parseInt(m[3], 10);
  const decpt = e + 1;
  let body;
  if (decpt > 16 || decpt <= -4) {
    const mant = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    body = `${mant}e${e < 0 ? "-" : "+"}${String(Math.abs(e)).padStart(2, "0")}`;
  } else if (decpt <= 0) {
    body = `0.${"0".repeat(-decpt)}${digits}`;
  } else if (decpt >= digits.length) {
    body = `${digits}${"0".repeat(decpt - digits.length)}.0`;
  } else {
    body = `${digits.slice(0, decpt)}.${digits.slice(decpt)}`;
  }
  return neg ? `-${body}` : body;
}

const SHORT_ESC = { '"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f" };

// ensure_ascii=False: escape only what Python escapes; lone surrogates stay.
function pyStr(s) {
  let out = '"';
  let start = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    const code = s.charCodeAt(k);
    let esc = null;
    if (c in SHORT_ESC) esc = SHORT_ESC[c];
    else if (code < 0x20) esc = `\\u${code.toString(16).padStart(4, "0")}`;
    if (esc !== null) {
      out += s.slice(start, k) + esc;
      start = k + 1;
    }
  }
  return `${out}${s.slice(start)}"`;
}

// ensure_ascii=True: every non-ASCII UTF-16 unit as \uXXXX (lowercase), the
// way Python writes it (astral characters as their surrogate pair).
function pyStrAscii(s) {
  let out = '"';
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    const code = s.charCodeAt(k);
    if (c in SHORT_ESC) out += SHORT_ESC[c];
    else if (code < 0x20 || code > 0x7e) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += c;
  }
  return `${out}"`;
}

function compareCodePoints(a, b) {
  const A = Array.from(a);
  const B = Array.from(b);
  const len = Math.min(A.length, B.length);
  for (let k = 0; k < len; k++) {
    const x = A[k].codePointAt(0);
    const y = B[k].codePointAt(0);
    if (x !== y) return x - y;
  }
  return A.length - B.length;
}

// json.dumps over values from pyLoads AND over plain result objects.
//   opts.sortKeys, opts.itemSep (", " or ","), opts.keySep (": " or ":"),
//   opts.ascii (ensure_ascii), opts.allowNan.
function pyDumps(value, opts) {
  const str = opts.ascii ? pyStrAscii : pyStr;
  function walk(v) {
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "string") return str(v);
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number") {
      if (!Number.isInteger(v)) throw new TypeError("a plain JS number here must be an integer");
      return String(v);
    }
    if (v instanceof PyFloat) {
      if (!opts.allowNan && !Number.isFinite(v.v)) throw new ParseError("Out of range float values are not JSON compliant");
      return pyFloatRepr(v.v);
    }
    if (Array.isArray(v)) return `[${v.map(walk).join(opts.itemSep)}]`;
    const entries = v instanceof Map ? Array.from(v.entries()) : Object.entries(v);
    if (opts.sortKeys) entries.sort((x, y) => compareCodePoints(x[0], y[0]));
    return `{${entries.map(([k, x]) => `${str(k)}${opts.keySep}${walk(x)}`).join(opts.itemSep)}}`;
  }
  return walk(value);
}

const CHAIN_DUMPS = Object.freeze({ sortKeys: true, itemSep: ", ", keySep: ": ", ascii: false, allowNan: true });
const C14N_DUMPS = Object.freeze({ sortKeys: true, itemSep: ",", keySep: ":", ascii: false, allowNan: false });

// str.encode("utf-8", "surrogatepass").
function utf8Surrogatepass(s) {
  const out = [];
  for (let k = 0; k < s.length; k++) {
    let cp = s.charCodeAt(k);
    if (cp >= 0xd800 && cp <= 0xdbff && k + 1 < s.length) {
      const lo = s.charCodeAt(k + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        k++;
      }
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return Buffer.from(out);
}

function hasLoneSurrogate(s) {
  return /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);
}

// arcaeon_ledger._chain
function chainOf(prev, obj) {
  const body = new Map();
  for (const [k, v] of obj) if (k !== "chain") body.set(k, v);
  const text = String(prev) + pyDumps(body, CHAIN_DUMPS);
  return crypto.createHash("sha256").update(utf8Surrogatepass(text)).digest("hex").slice(0, CHAIN_LEN);
}

// ---------------------------------------------------------------------------
// repr() of a str, for "duplicate key 'k'" (DuplicateKeyError's message)
// ---------------------------------------------------------------------------
// str.isprintable(): not printable = Cc, Cf, Cs, Co, Cn, Zl, Zp, Zs except
// the ASCII space. (Unicode-version drift between CPython's database and V8's
// is a residual edge for code points assigned very recently.)
const NON_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;
function pyReprStr(s) {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === quote || ch === "\\") out += `\\${ch}`;
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (cp < 0x20 || cp === 0x7f) out += `\\x${cp.toString(16).padStart(2, "0")}`;
    else if (cp < 0x7f) out += ch;
    else if (ch !== " " && NON_PRINTABLE.test(ch)) {
      if (cp <= 0xff) out += `\\x${cp.toString(16).padStart(2, "0")}`;
      else if (cp <= 0xffff) out += `\\u${cp.toString(16).padStart(4, "0")}`;
      else out += `\\U${cp.toString(16).padStart(8, "0")}`;
    } else out += ch;
  }
  return out + quote;
}

// ---------------------------------------------------------------------------
// verify_file(path, strict=True), the fields reconcile reads
// ---------------------------------------------------------------------------
function isPlainMap(v) {
  return v instanceof Map;
}

// Returns {ok: true|false|null, rows, first_break, verified_scope, cannot}.
// `cannot` is set when the reference would raise, or the port will not guess.
function verifyStrict(lines) {
  const res = { ok: true, rows: 0, chained: 0, first_break: null, breaks: 0, verified_scope: "full", cannot: null };
  let prev = GENESIS;
  for (let idx = 0; idx < lines.length; idx++) {
    const i = idx + 1;
    const raw = pyStrip(lines[idx]);
    if (!raw) continue;
    let obj;
    try {
      obj = pyLoads(raw, true);
    } catch (e) {
      if (e instanceof CannotReproduce) {
        res.cannot = `line ${i} is ${e.message}; this service does not guess how the reference reads it`;
        return res;
      }
      if (e instanceof DuplicateKeyError) {
        res.ok = false;
        res.breaks += 1;
        res.first_break = res.first_break || `line ${i}: duplicate key ${pyReprStr(e.key)}`;
        try {
          obj = pyLoads(raw, false);
        } catch (e2) {
          // arcaeon_ledger.verify_file re-reads this line inside its except
          // handler and the error escapes: the reference raises here.
          res.cannot = `line ${i} holds a duplicate key and does not parse; the reference ` +
            `implementation raises on this line instead of answering`;
          return res;
        }
      } else {
        res.ok = false;
        res.breaks += 1;
        res.first_break = res.first_break || `line ${i}: unparseable`;
        continue;
      }
    }
    if (!isPlainMap(obj)) {
      res.ok = false;
      res.breaks += 1;
      res.first_break = res.first_break || `line ${i}: not a JSON object`;
      continue;
    }
    res.rows += 1;
    const claimed = obj.has("chain") ? obj.get("chain") : null;
    obj.delete("chain");
    if (claimed === null) {
      res.ok = false;
      res.breaks += 1;
      res.first_break = res.first_break || (res.chained
        ? `line ${i}: unchained row after chain began`
        : `line ${i}: unchained (prechain) row rejected in strict mode`);
      continue;
    }
    if (typeof claimed !== "string") {
      res.ok = false;
      res.breaks += 1;
      res.first_break = res.first_break || `line ${i}: non-string chain value`;
      prev = "";
      res.chained += 1;
      continue;
    }
    const want = chainOf(prev, obj);
    if (claimed !== want) {
      res.ok = false;
      res.breaks += 1;
      res.first_break = res.first_break || `line ${i}: chain mismatch`;
    }
    prev = claimed;
    res.chained += 1;
  }
  if (res.rows === 0 && res.ok) {
    res.ok = null;
    res.verified_scope = "empty";
  }
  return res;
}

// ---------------------------------------------------------------------------
// reconcile.py, rule for rule
// ---------------------------------------------------------------------------
function finding(verdict, at, side, reason, indexSide = null) {
  return { verdict, at, side, reason, index_side: indexSide };
}
function findingDict(f) {
  return { verdict: f.verdict, at: f.at, side: f.side, index_side: f.index_side, reason: f.reason };
}

function isTapeRow(row) {
  if (!isPlainMap(row)) return false;
  const idx = row.get("idx");
  const side = row.get("side");
  const resp = row.has("resp") ? row.get("resp") : null;
  return row.get("evt") === "tape_call" && row.get("tape") === TAPE_FORMAT &&
    typeof side === "string" && SIDES.includes(side) &&
    typeof idx === "bigint" && idx >= 1n &&
    typeof row.get("req") === "string" &&
    (resp === null || typeof resp === "string");
}

function peekSide(lines) {
  for (const raw of lines) {
    let row;
    try {
      row = pyLoads(raw, false);
    } catch (e) {
      if (e instanceof CannotReproduce) throw e;
      continue;
    }
    if (isPlainMap(row)) {
      const s = row.get("side");
      if (typeof s === "string" && SIDES.includes(s)) return s;
    }
  }
  return null;
}

function loadTape(label, bytes, findings) {
  const t = { label, side: null, ns: null, rows: [], calls: [], broken: false, cnl: null };
  Object.defineProperty(t, "name", { get() { return this.side || this.label; }, enumerable: false });
  const text = decodeText(bytes);
  const lines = text.split("\n");
  const res = verifyStrict(lines);
  if (res.cannot) {
    t.cnl = `${label} ${res.cannot}`;
    return t;
  }
  if (res.ok === null && res.verified_scope === "empty") return t;
  if (res.ok !== true) {
    const fb = res.first_break || "chain does not verify";
    try {
      t.side = peekSide(lines);
    } catch (e) {
      t.cnl = `${label} holds a row ${e.message} while its side is read; the reference ` +
        `implementation can raise here instead of answering`;
      return t;
    }
    const m = /line (\d+)/.exec(fb);
    t.broken = true;
    findings.push(finding(ALTERED, m ? BigInt(m[1]) : null, t.name,
      `${t.name} tape does not verify (${fb}); a tape that was ` +
        "edited after it was written cannot be reconciled", t.name));
    return t;
  }
  let n = 0;
  for (const ln of lines) {
    if (!pyStrip(ln)) continue;
    n += 1;
    let row;
    try {
      row = pyLoads(ln, false);
    } catch (e) {
      t.cnl = `${label} row ${n} verifies but does not read a second time (whitespace json.loads ` +
        "does not strip); the reference implementation raises on this tape instead of answering";
      return t;
    }
    if (!isTapeRow(row)) {
      t.cnl = `${label} row ${n} is not an ${TAPE_FORMAT} row`;
      return t;
    }
    const side = row.get("side");
    if (t.side === null) {
      t.side = side;
      t.ns = row.has("ns") ? row.get("ns") : null;
    } else if (side !== t.side) {
      t.cnl = `${label} mixes sides (${t.side} and ${side}) at row ${n}`;
      return t;
    }
    t.rows.push({ idx: row.get("idx"), req: row.get("req"), resp: row.has("resp") ? row.get("resp") : null });
  }
  return t;
}

function walkIndex(t, findings) {
  let expect = 1n;
  for (const row of t.rows) {
    const k = row.idx;
    if (k === expect) {
      t.calls.push(row);
      expect += 1n;
    } else if (k > expect) {
      findings.push(finding(MISSING, expect, t.name,
        `${t.name} tape skips from call ${expect - 1n} to call ${k}: ` +
          `calls ${expect}..${k - 1n} were allocated and never written`, t.name));
      t.calls.push(row);
      expect = k + 1n;
    } else if (t.calls.length && k === t.calls[t.calls.length - 1].idx) {
      findings.push(finding(ALTERED, k, t.name,
        `${t.name} tape records call ${k} twice; one index, two rows`, t.name));
    } else {
      findings.push(finding(ALTERED, k, t.name,
        `${t.name} tape has call ${k} after call ${expect - 1n}: index out of order`, t.name));
    }
  }
}

function pyNone(v) {
  return v === null ? "None" : v;
}

function align(A, T, findings) {
  let i = 0;
  let j = 0;
  let matched = 0;
  const onlyA = [];
  const onlyT = [];
  while (i < A.length && j < T.length) {
    const a = A[i];
    const t = T[j];
    if (a.req === t.req) {
      if (a.resp === t.resp) {
        matched += 1;
      } else if (a.resp === null || t.resp === null) {
        const short = a.resp === null ? "agent" : "tool";
        findings.push(finding(MISSING, a.idx, short,
          `call ${a.idx}'s response is on one tape and not the other (${short} tape has none)`, "agent"));
      } else {
        findings.push(finding(ALTERED, a.idx, null,
          `call ${a.idx}: same request, different response: the agent saw ${pyNone(a.resp)}, ` +
            `the tool sent ${pyNone(t.resp)}`, "agent"));
      }
      i += 1;
      j += 1;
      continue;
    }
    let da = null;
    for (let d = 1; d < A.length - i; d++) if (A[i + d].req === t.req) { da = d; break; }
    let dt = null;
    for (let d = 1; d < T.length - j; d++) if (T[j + d].req === a.req) { dt = d; break; }
    if (da === null && dt === null) {
      findings.push(finding(ALTERED, a.idx, null,
        `call ${a.idx}: the request differs: the agent sent ${a.req}, the tool received ${t.req}`, "agent"));
      i += 1;
      j += 1;
    } else if (dt === null || (da !== null && da <= dt)) {
      onlyA.push(...A.slice(i, i + da));
      i += da;
    } else {
      onlyT.push(...T.slice(j, j + dt));
      j += dt;
    }
  }
  onlyA.push(...A.slice(i));
  onlyT.push(...T.slice(j));
  for (const x of onlyA.slice()) {
    const y = onlyT.find((r) => r.req === x.req);
    if (y === undefined) continue;
    onlyA.splice(onlyA.indexOf(x), 1);
    onlyT.splice(onlyT.indexOf(y), 1);
    findings.push(finding(ALTERED, x.idx, null,
      `call ${x.idx} is on both tapes at different places (agent call ${x.idx}, tool call ${y.idx}): ` +
        "the order was altered", "agent"));
  }
  for (const x of onlyA) {
    findings.push(finding(MISSING, x.idx, "tool",
      `call ${x.idx} is on the agent tape and not on the tool tape`, "agent"));
  }
  for (const y of onlyT) {
    findings.push(finding(MISSING, y.idx, "agent",
      `tool call ${y.idx} is on the tool tape and not on the agent tape`, "tool"));
  }
  return matched;
}

function atKey(f) {
  return f.at !== null ? f.at : 0n;
}

function headline(findings) {
  let first = findings[0];
  for (const f of findings.slice(1)) {
    const a = atKey(f);
    const b = atKey(first);
    const va = f.verdict === ALTERED ? 0 : 1;
    const vb = first.verdict === ALTERED ? 0 : 1;
    if (a < b || (a === b && va < vb)) first = f;
  }
  const twins = new Set(findings
    .filter((f) => f.verdict === first.verdict && f.at === first.at && f.side)
    .map((f) => f.side));
  if (twins.has("agent") && twins.has("tool")) {
    return finding(first.verdict, first.at, "both", `${first.reason} (both tapes)`, first.index_side);
  }
  return first;
}

function summaryOf(r) {
  if (r.verdict === MATCHED) return `MATCHED ${r.matched} of ${r.matched}`;
  if (r.verdict === COULD_NOT_LOOK) return `COULD NOT LOOK: ${r.reason}`;
  const where = r.at !== null ? ` at call ${r.at}` : "";
  const who = r.side ? ` (${r.side} tape)` : "";
  return `${r.verdict}${where}${who}: ${r.reason}`;
}

// reconcile(tape_a, tape_b) with no pins. Arguments are Buffers (or
// Uint8Arrays) holding each tape's bytes exactly as submitted. Returns the
// same dict Reconciliation.to_dict() returns, key for key; integers that can
// exceed a double (`at`) are BigInt.
function reconcileTapes(bytesA, bytesB) {
  const findings = [];
  const cnl = [];
  const tapes = [loadTape("tape_a", bytesA, findings), loadTape("tape_b", bytesB, findings)];
  for (const t of tapes) if (t.cnl) cnl.push(t.cnl);

  const readable = tapes.filter((t) => !t.cnl && !t.broken);
  for (const t of readable) walkIndex(t, findings);

  let agent = tapes.find((t) => t.side === "agent") || null;
  let tool = tapes.find((t) => t.side === "tool") || null;
  const sides = tapes.map((t) => t.side).filter((s) => s);
  if (sides.length === 2 && sides[0] === sides[1]) {
    cnl.push(`both tapes are ${sides[0]}-side tapes; reconcile needs one of each`);
    agent = tool = null;
  }
  if (readable.length === 2 && agent === null && tool !== null) {
    agent = readable.find((t) => t !== tool && t.side === null);
  } else if (readable.length === 2 && tool === null && agent !== null) {
    tool = readable.find((t) => t !== agent && t.side === null);
  }
  if (readable.length === 2 && !tapes[0].rows.length && !tapes[1].rows.length) {
    cnl.push("both tapes are empty: an idle agent and a silent recorder look identical");
  }

  let matched = 0;
  const canAlign = agent != null && tool != null && readable.includes(agent) && readable.includes(tool) &&
    (agent.rows.length > 0 || tool.rows.length > 0);
  if (canAlign) {
    agent.side = "agent";
    tool.side = "tool";
    matched = align(agent.calls, tool.calls, findings);
  }

  const counts = {};
  for (const t of tapes) counts[t.name] = t.rows.length;

  const sorted = findings.slice().sort((x, y) => {
    const a = x.at === null || x.at === 0n ? 0n : x.at;
    const b = y.at === null || y.at === 0n ? 0n : y.at;
    if (a !== b) return a < b ? -1 : 1;
    return x.verdict < y.verdict ? -1 : x.verdict > y.verdict ? 1 : 0;
  });

  const r = { verdict: MATCHED, at: null, side: null, reason: "", matched };
  if (findings.length) {
    const h = headline(findings);
    r.verdict = h.verdict;
    r.at = h.at;
    r.side = h.side;
    r.reason = h.reason;
  } else if (cnl.length || !canAlign) {
    r.verdict = COULD_NOT_LOOK;
    r.reason = cnl.length ? cnl[0] : "the two tapes could not be paired";
  } else {
    r.reason = `${matched} calls on each tape, same digests`;
  }
  return {
    verdict: r.verdict,
    summary: summaryOf(r),
    at: r.at,
    side: r.side,
    reason: r.reason,
    matched: r.matched,
    counts,
    findings: sorted.map(findingDict),
    could_not_look: cnl.slice(),
    pins_checked: [],
    limits: LIMITS.slice(),
    exit_code: EXIT_CODES[r.verdict],
  };
}

// ---------------------------------------------------------------------------
// serializations of a result
// ---------------------------------------------------------------------------
// The conformance form: json.dumps(d, sort_keys=True, ensure_ascii=True,
// separators=(",", ":")). ASCII, so it is identical bytes on both sides and
// safe for any lone surrogate a hostile tape put into a reason.
function conformanceJson(result) {
  return pyDumps(result, { sortKeys: true, itemSep: ",", keySep: ":", ascii: true, allowNan: false });
}

// The wire form: key order as to_dict() writes it, ASCII-escaped.
function wireJson(value) {
  return pyDumps(value, { sortKeys: false, itemSep: ",", keySep: ":", ascii: true, allowNan: false });
}

// json-c14n:v1 bytes (arcaeon_ledger.artefact._canon_json): compact, sorted,
// ensure_ascii=False, allow_nan=False, strict UTF-8. Returns null when the
// value holds a lone surrogate (Python's strict UTF-8 encode raises there).
function c14nBytes(value) {
  const text = pyDumps(value, C14N_DUMPS);
  if (hasLoneSurrogate(text)) return null;
  return Buffer.from(text, "utf-8");
}

function digestC14n(value) {
  const b = c14nBytes(value);
  if (b === null) return null;
  return `sha256:json-c14n:v1:${crypto.createHash("sha256").update(b).digest("hex")}`;
}

function digestBytes(buf) {
  return `sha256:raw-bytes:v1:${crypto.createHash("sha256").update(buf).digest("hex")}`;
}

module.exports = {
  PORT_VERSION,
  REFERENCE,
  TAPE_FORMAT,
  SIDES,
  MATCHED,
  MISSING,
  ALTERED,
  COULD_NOT_LOOK,
  EXIT_CODES,
  LIMITS,
  MAX_DEPTH,
  reconcileTapes,
  conformanceJson,
  wireJson,
  c14nBytes,
  digestC14n,
  digestBytes,
  // exported for the tests that pin each piece against the Python
  _internal: { pyLoads, pyDumps, pyStrip, pyFloatRepr, pyReprStr, decodeText, chainOf, verifyStrict,
    utf8Surrogatepass, PyFloat, CHAIN_DUMPS },
};

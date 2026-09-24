// _reconcile_page.js — the static page served at /reconcile (vercel.json
// rewrite -> /api/verify?op=reconcile-page). Underscore prefix = not routed.
//
// A constant string, not a file read at request time: a module the function
// requires is always in the deployment bundle, while a file read by path
// depends on the bundler tracing it. The page is the same bytes on every
// request; the style is completeness.html's (velouria projects/arcaeon_site,
// branch completeness-page), so the two tapes pages read as one family.
//
// The page posts the two tapes to /api/reconcile (same origin) and renders the
// answer with textContent only: a tape is untrusted input and nothing from it
// is ever parsed as HTML. A file picked from disk is sent as base64, so its
// exact bytes (BOM, CRLF, invalid UTF-8) reach the comparison; pasted text is
// sent as text.
//
// The script below uses no backquotes and no "${", so this template literal
// holds it verbatim; test/reconcile_page.test.js checks both.

"use strict";

const brandMark = require("./_brand_mark.js");

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two Tapes Verdict</title>
<!--arc:favicon-->
<meta name="description" content="Paste the agent side's tape and the tool side's tape of the same calls. The witness service lines them up and answers MATCHED, MISSING, ALTERED, or COULD NOT LOOK, with a signed receipt. The tapes are not stored.">
<style>
  :root {
    color-scheme: dark light;
    --bg: #0b0c0e;
    --panel: #141619;
    --panel-2: #191c1f;
    --border: #2a2d31;
    --text: #e6e8eb;
    --muted: #9aa0a6;
    --accent: #6ee7b7;
    --accent-strong: #34d399;
    --fail: #f87171;
    --warn: #fbbf24;
    --link: #8ab4f8;
    --mono-bg: #0f1113;
    --mono-border: #2f3338;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #f6f7f8;
      --panel: #ffffff;
      --panel-2: #f0f1f3;
      --border: #dcdfe3;
      --text: #1b1d1f;
      --muted: #5b6066;
      --accent: #0a7d4c;
      --accent-strong: #056238;
      --fail: #b3261e;
      --warn: #8a5a00;
      --link: #1a56b0;
      --mono-bg: #f0f1f3;
      --mono-border: #d7dade;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  }
  main { max-width: 880px; margin: 0 auto; padding: 32px 16px 80px; }
  h1 { font-size: 20px; font-weight: 700; margin: 0 0 4px; letter-spacing: 0.01em; }
  .subtitle { color: var(--muted); font-size: 13.5px; margin: 0 0 28px; }
  h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--muted); margin: 0 0 10px; font-weight: 600;
  }
  section.panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 18px 20px; margin-bottom: 16px;
  }
  code, .mono, textarea, pre {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    font-size: 13px;
  }
  .inputs { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  @media (max-width: 720px) { .inputs { grid-template-columns: 1fr; } }
  .slot {
    border: 1px dashed var(--border); border-radius: 8px; padding: 12px 14px;
    font-size: 13px; color: var(--muted); min-width: 0;
  }
  .slot strong { color: var(--text); display: block; margin-bottom: 4px; }
  .slot .picked { word-break: break-all; margin-top: 6px; color: var(--text); }
  textarea {
    width: 100%; min-height: 140px; margin-top: 8px; resize: vertical;
    background: var(--mono-bg); color: var(--text); border: 1px solid var(--mono-border);
    border-radius: 6px; padding: 8px;
  }
  .row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  button {
    font: inherit; font-size: 13.5px; font-weight: 600; padding: 8px 16px;
    border-radius: 6px; border: 1px solid var(--border); background: var(--panel-2);
    color: var(--text); cursor: pointer;
  }
  button.primary { background: var(--accent-strong); border-color: var(--accent-strong); color: #06120c; }
  button:hover { filter: brightness(1.08); }
  button:disabled { opacity: 0.6; cursor: default; }
  input[type=file] { display: block; margin-top: 8px; max-width: 100%; font-size: 12.5px; color: var(--muted); }
  .verdict { display: flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 700; margin-bottom: 6px; flex-wrap: wrap; }
  .verdict .tag { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; letter-spacing: 0.04em; }
  .tag.pass { background: color-mix(in srgb, var(--accent) 20%, transparent); color: var(--accent-strong); border: 1px solid var(--accent-strong); }
  .tag.fail { background: color-mix(in srgb, var(--fail) 18%, transparent); color: var(--fail); border: 1px solid var(--fail); }
  .tag.neutral { background: var(--panel-2); color: var(--muted); border: 1px solid var(--border); }
  .reason { color: var(--muted); font-size: 13.5px; word-break: break-word; }
  ul.plain { margin: 4px 0; padding-left: 20px; }
  ul.plain li { margin: 4px 0; }
  table.checks { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.checks th, table.checks td { border-bottom: 1px solid var(--border); text-align: left; padding: 6px 10px; vertical-align: top; }
  table.checks th { color: var(--muted); font-weight: 600; }
  table.checks td { word-break: break-word; }
  .table-wrap { overflow-x: auto; }
  pre.receipt {
    background: var(--mono-bg); border: 1px solid var(--mono-border); border-radius: 6px;
    padding: 10px 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 8px 0 0;
  }
  .notice {
    border: 1px solid var(--warn); background: color-mix(in srgb, var(--warn) 10%, transparent);
    border-radius: 6px; padding: 10px 14px; font-size: 13.5px; margin: 8px 0;
  }
  a { color: var(--link); }
  footer { color: var(--muted); font-size: 12px; margin-top: 40px; text-align: center; }
  .arc-head { display: flex; align-items: center; gap: 10px; margin: 0 0 18px; }
  .arc-word { color: var(--text); font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; }
  footer .arc-footer { margin: 0 0 8px; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
<main>
  <header class="arc-head"><!--arc:header-mark--><span class="arc-word">Arcaeon</span></header>
  <h1>Two tapes verdict</h1>
  <p class="subtitle">
    Both ends of a tool call can keep their own tape: the agent side writes down every
    call it sent and every answer it got, the tool side every call it received and every
    answer it sent. Paste both tapes here and the witness service lines them up, call by
    call, and signs a receipt of what it found. The tapes are sent to the service for
    this one comparison and are not stored.
  </p>

  <section class="panel">
    <h2>The tapes</h2>
    <div class="inputs">
      <div class="slot">
        <strong>Agent side's tape</strong>
        The <code>arcaeon-tape/1</code> file the adapter writes with <code>--tape</code>.
        <textarea id="text-a" spellcheck="false" placeholder='{"evt": "tape_call", "tape": "arcaeon-tape/1", "side": "agent", ...}'></textarea>
        <input type="file" id="file-a" accept=".jsonl,.json,.txt,application/json">
        <div class="picked mono" id="picked-a"></div>
      </div>
      <div class="slot">
        <strong>Tool side's tape</strong>
        The same calls as the tool side saw them (call_proxy <code>--tape</code>, or the adapter with <code>--side tool</code>).
        <textarea id="text-b" spellcheck="false" placeholder='{"evt": "tape_call", "tape": "arcaeon-tape/1", "side": "tool", ...}'></textarea>
        <input type="file" id="file-b" accept=".jsonl,.json,.txt,application/json">
        <div class="picked mono" id="picked-b"></div>
      </div>
    </div>
    <div class="row" style="margin-top:14px;">
      <button id="run-btn" class="primary" type="button">Line them up</button>
      <button id="clear-btn" type="button">Clear</button>
      <span class="reason" id="status"></span>
    </div>
  </section>

  <section id="results" class="panel" hidden>
    <h2>Verdict</h2>
    <div id="verdict" class="verdict"></div>
    <div class="reason" id="verdict-reason"></div>
    <div id="section-findings" hidden>
      <h2 style="margin-top:16px;">Every finding</h2>
      <div class="table-wrap"><table class="checks" id="findings-table"></table></div>
    </div>
    <div id="section-cnl" hidden>
      <h2 style="margin-top:16px;">What could not be looked at</h2>
      <ul class="plain" id="cnl-list"></ul>
    </div>
    <p class="reason" id="counts-line" style="margin-top:12px;"></p>
    <h2 style="margin-top:16px;">Receipt</h2>
    <p class="reason" id="receipt-line"></p>
    <div class="row"><button id="save-btn" type="button">Save verdict and receipt</button></div>
    <pre class="receipt" id="receipt-json"></pre>
  </section>

  <section id="refused" class="panel" hidden>
    <h2>Not compared</h2>
    <div class="notice" id="refused-text"></div>
  </section>

  <section class="panel">
    <h2>The four answers</h2>
    <ul class="plain">
      <li><strong>MATCHED n of n.</strong> Every call on either tape is on the other one, with the same request and the same answer.</li>
      <li><strong>MISSING at call k.</strong> Call k is on one tape and not the other, or its answer reached one side only. The answer names the short tape.</li>
      <li><strong>ALTERED at call k.</strong> Both tapes have call k and they disagree about it, or a tape contradicts itself: edited after it was written, or a call number used twice or out of order.</li>
      <li><strong>COULD NOT LOOK.</strong> A tape is empty on both sides, is not a tape, holds two sides at once, or holds something the comparison will not guess about. That is never a pass.</li>
    </ul>
    <p class="reason">The first divergence is the headline; the table lists every one. The rules are those of <code>arcaeon-ledger reconcile</code> (arcaeon-ledger 0.8.0), and the service is checked against that command, case by case.</p>
  </section>

  <section class="panel" id="limits">
    <h2>What this does not prove</h2>
    <ul class="plain">
      <li><strong>The service saw only what was submitted.</strong> It did not see the calls, the agent or the tool. It compared two files someone chose to send, and the receipt says exactly that: these two tapes, as submitted, compared like this at this time.</li>
      <li><strong>An operator-owned tape is not an outside witness.</strong> If one party runs both ends, MATCHED means two of its own recorders agree. That catches relays, gateways and bugs in between; it is not independent evidence, and a party that wants a false story can write two tapes that match.</li>
      <li><strong>A call nobody recorded leaves no trace.</strong> If an agent never makes a call, or makes it through a channel with no tape on it, neither tape shows anything.</li>
      <li><strong>No witness pin is checked here.</strong> Two tapes cut at the same point still match each other. The pin, a counter held by a third party, is what catches that; hold the tapes against it with <code>arcaeon-ledger reconcile agent.tape.jsonl tool.tape.jsonl --pin pin.json</code>.</li>
      <li><strong>It compares content, not bytes.</strong> A relay that rewrites a message without changing what it says still matches, on purpose.</li>
    </ul>
  </section>

  <footer><p class="arc-footer"><!--arc:footer-mark--></p>reconcile &middot; the tapes go to the witness service for one comparison and are not kept</footer>
</main>

<script>
"use strict";
(function () {
  var picked = { a: null, b: null };
  var lastReceipt = null;
  var lastRaw = null;

  function el(id) { return document.getElementById(id); }
  function text(node, s) { node.textContent = s; return node; }
  function make(tag, s) { var n = document.createElement(tag); if (s !== undefined) { n.textContent = s; } return n; }

  function toB64(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  function pick(which) {
    var input = el("file-" + which);
    input.addEventListener("change", function () {
      var f = input.files && input.files[0];
      if (!f) { return; }
      f.arrayBuffer().then(function (buf) {
        picked[which] = { name: f.name, b64: toB64(buf), size: buf.byteLength };
        text(el("picked-" + which), f.name + " (" + buf.byteLength + " bytes, sent exactly as read)");
        el("text-" + which).value = "";
      });
    });
    el("text-" + which).addEventListener("input", function () {
      if (picked[which]) { picked[which] = null; text(el("picked-" + which), ""); input.value = ""; }
    });
  }
  pick("a");
  pick("b");

  function body() {
    var out = {};
    if (picked.a) { out.agent_tape_b64 = picked.a.b64; } else { out.agent_tape = el("text-a").value; }
    if (picked.b) { out.tool_tape_b64 = picked.b.b64; } else { out.tool_tape = el("text-b").value; }
    return out;
  }

  function tagClass(v) {
    if (v === "MATCHED") { return "pass"; }
    if (v === "MISSING" || v === "ALTERED") { return "fail"; }
    return "neutral";
  }
  function word(v) { return v === "COULD_NOT_LOOK" ? "COULD NOT LOOK" : v; }

  function render(ans) {
    el("refused").hidden = true;
    el("results").hidden = false;
    var v = ans.verdict;
    var box = el("verdict");
    box.textContent = "";
    var tag = make("span", word(v.verdict));
    tag.className = "tag " + tagClass(v.verdict);
    box.appendChild(tag);
    box.appendChild(make("span", v.summary));
    text(el("verdict-reason"), v.verdict === "MATCHED" ? "" : v.reason);

    var table = el("findings-table");
    table.textContent = "";
    el("section-findings").hidden = !v.findings.length;
    if (v.findings.length) {
      var head = make("tr");
      ["answer", "call", "short / contradicting tape", "numbered by", "why"].forEach(function (h) { head.appendChild(make("th", h)); });
      table.appendChild(head);
      v.findings.forEach(function (f) {
        var tr = make("tr");
        [word(f.verdict), f.at === null ? "" : String(f.at), f.side || "", f.index_side || "", f.reason].forEach(function (c) {
          tr.appendChild(make("td", c));
        });
        table.appendChild(tr);
      });
    }
    var cnl = el("cnl-list");
    cnl.textContent = "";
    el("section-cnl").hidden = !v.could_not_look.length;
    v.could_not_look.forEach(function (c) { cnl.appendChild(make("li", c)); });

    var counts = Object.keys(v.counts).map(function (k) { return k + ": " + v.counts[k] + " rows"; }).join(", ");
    text(el("counts-line"), "Rows on each tape: " + (counts || "none") + ". Calls matched: " + v.matched + ".");

    var r = ans.receipt;
    lastReceipt = r;
    text(el("receipt-line"), r.sig
      ? "Signed by " + r.signer.name + " (verifier " + r.signer.verifier + "). It binds the sha256 of each tape as you sent it and this verdict, and it lists what it does not claim."
      : "Unsigned: " + (r.unsigned_reason || "no signer") + ". The verdict above is unchanged; only the signature is missing.");
    text(el("receipt-json"), JSON.stringify(r, null, 1));
  }

  function refused(status, ans) {
    el("results").hidden = true;
    el("refused").hidden = false;
    var msg = (ans && ans.error) ? ans.error : ("the service answered HTTP " + status);
    text(el("refused-text"), (ans && ans.error_code ? ans.error_code + ": " : "") + msg);
  }

  el("run-btn").addEventListener("click", function () {
    var btn = el("run-btn");
    btn.disabled = true;
    text(el("status"), "comparing...");
    fetch("/api/reconcile", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body())
    }).then(function (r) {
      return r.text().then(function (t) {
        var ans = null;
        try { ans = JSON.parse(t); } catch (e) { ans = null; }
        if (r.ok && ans && ans.ok) { lastRaw = t; render(ans); } else { refused(r.status, ans); }
      });
    }).catch(function () {
      refused(0, { error_code: "unreachable", error: "COULD NOT LOOK: the witness service could not be reached" });
    }).then(function () {
      btn.disabled = false;
      text(el("status"), "");
    });
  });

  el("clear-btn").addEventListener("click", function () {
    ["a", "b"].forEach(function (w) {
      picked[w] = null;
      el("text-" + w).value = "";
      el("file-" + w).value = "";
      text(el("picked-" + w), "");
    });
    el("results").hidden = true;
    el("refused").hidden = true;
  });

  el("save-btn").addEventListener("click", function () {
    if (!lastRaw || !lastReceipt) { return; }
    // The service's answer exactly as it arrived (verdict + receipt), so the
    // signature checks over the same bytes the service signed.
    var blob = new Blob([lastRaw], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "reconcile-receipt-" + String(lastReceipt.compared_at).replace(/[:]/g, "") + ".json";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  });
})();
</script>
</body>
</html>
`;

// The mark and the favicon link go in by placeholder rather than by "${"
// interpolation, so the page literal above stays free of template syntax
// (test/reconcile_endpoint.test.js checks that). One copy of the mark:
// lib/_brand_mark.js. Dark page with a light media flip, so "dark-auto".
function brand(html) {
  const fill = [
    ["<!--arc:favicon-->", brandMark.FAVICON_LINK],
    ["<!--arc:header-mark-->", brandMark.headerMark("dark-auto")],
    ["<!--arc:footer-mark-->", brandMark.footerMark("dark-auto")],
  ];
  let out = html;
  for (const [slot, svg] of fill) {
    if (out.split(slot).length !== 2) throw new Error(`_reconcile_page: slot ${slot} must appear once`);
    out = out.replace(slot, () => svg);
  }
  return out;
}

module.exports = { HTML: brand(HTML) };

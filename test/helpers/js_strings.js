// test/helpers/js_strings.js — unit R-FGf (M1): the string literals of a
// JavaScript source, with their line numbers, for the refuse-words check
// over what this service can send. Comments and code (identifiers such as
// sealHolds, codes such as pin_holds_another_chain, which a word boundary
// does not split anyway) are not string literals, so they are not returned.
//
// A small lexer, not a parser: it knows comments, the three quote forms
// (a template's ${...} is lexed as code, its literal chunks returned), and a
// regular expression literal, told from division by the token before it.
// The repository has no dependencies on purpose (package.json), so no
// parser is borrowed.
"use strict";

const REGEX_AFTER_WORDS = new Set(["return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await"]);
const REGEX_AFTER_PUNCT = new Set(["(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^"]);

// -> [{line, text}] for every string literal and template chunk in `src`
function stringLiterals(src) {
  const out = [];
  let i = 0;
  let line = 1;
  // the last significant token: a punctuator character, or a word
  let prev = "(";
  const n = src.length;

  function readQuoted(q) {
    const startLine = line;
    let text = "";
    i += 1;
    while (i < n && src[i] !== q) {
      if (src[i] === "\\") {
        text += src.slice(i, i + 2);
        if (src[i + 1] === "\n") line += 1;
        i += 2;
        continue;
      }
      if (src[i] === "\n") line += 1;
      text += src[i];
      i += 1;
    }
    i += 1;
    out.push({ line: startLine, text });
  }

  function readTemplate() {
    let startLine = line;
    let text = "";
    i += 1;
    while (i < n && src[i] !== "`") {
      if (src[i] === "\\") {
        text += src.slice(i, i + 2);
        if (src[i + 1] === "\n") line += 1;
        i += 2;
        continue;
      }
      if (src[i] === "$" && src[i + 1] === "{") {
        out.push({ line: startLine, text });
        text = "";
        i += 2;
        lexCode("}");
        i += 1; // the closing brace
        startLine = line;
        continue;
      }
      if (src[i] === "\n") line += 1;
      text += src[i];
      i += 1;
    }
    i += 1;
    out.push({ line: startLine, text });
  }

  function readRegex() {
    i += 1;
    let inClass = false;
    while (i < n) {
      const ch = src[i];
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch === "\n") break; // not a regex after all: give up on the line
      if (inClass) {
        if (ch === "]") inClass = false;
      } else if (ch === "[") {
        inClass = true;
      } else if (ch === "/") {
        i += 1;
        break;
      }
      i += 1;
    }
    while (i < n && /[a-z]/i.test(src[i])) i += 1; // flags
  }

  // Lex code until the unmatched `close` (a template's "}") or the end.
  function lexCode(close) {
    let depth = 0;
    while (i < n) {
      const ch = src[i];
      const next = src[i + 1];
      if (ch === "\n") {
        line += 1;
        i += 1;
        continue;
      }
      if (/\s/.test(ch)) {
        i += 1;
        continue;
      }
      if (ch === "/" && next === "/") {
        while (i < n && src[i] !== "\n") i += 1;
        continue;
      }
      if (ch === "/" && next === "*") {
        const end = src.indexOf("*/", i + 2);
        const stop = end === -1 ? n : end + 2;
        for (let k = i; k < stop; k += 1) if (src[k] === "\n") line += 1;
        i = stop;
        continue;
      }
      if (ch === "'" || ch === "\"") {
        readQuoted(ch);
        prev = "a"; // a value
        continue;
      }
      if (ch === "`") {
        readTemplate();
        prev = "a";
        continue;
      }
      if (ch === "/") {
        if (REGEX_AFTER_PUNCT.has(prev) || REGEX_AFTER_WORDS.has(prev)) {
          readRegex();
          prev = "a";
        } else {
          i += 1;
          prev = "/";
        }
        continue;
      }
      if (/[A-Za-z_$0-9]/.test(ch)) {
        let w = "";
        while (i < n && /[A-Za-z_$0-9]/.test(src[i])) {
          w += src[i];
          i += 1;
        }
        prev = w;
        continue;
      }
      if (close && ch === "{") depth += 1;
      if (close && ch === "}") {
        if (depth === 0) return;
        depth -= 1;
      }
      // `)` and `]` end a value: a slash after them divides
      prev = ch === ")" || ch === "]" ? "a" : ch;
      i += 1;
    }
  }

  if (src.startsWith("#!")) while (i < n && src[i] !== "\n") i += 1;
  lexCode(null);
  return out;
}

// Every .js, .mjs and .cjs file under `dir`, its subdirectories included
// (unit R-PAGEf, m5: the tools/ scan walks them). -> absolute paths.
function jsFilesUnder(dir) {
  const fs = require("node:fs");
  const path = require("node:path");
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...jsFilesUnder(p));
    else if (/\.(js|mjs|cjs)$/.test(e.name)) out.push(p);
  }
  return out;
}

module.exports = { stringLiterals, jsFilesUnder };

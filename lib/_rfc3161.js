// lib/_rfc3161.js — an RFC 3161 time stamp REQUEST builder and RESPONSE reader,
// in Node's own modules only (this repo has no dependencies, README "Layout").
//
// What it is for: an outside clock beside the Bitcoin anchor. A time stamp
// authority (DigiCert's free server, http://timestamp.digicert.com) signs
// "this hash existed at time T" with its own certificate. The request is
// sha256 only, with a random nonce, asking for the authority's certificate
// in the answer.
//
// What it does NOT do: check the signature or the certificate chain. That is
// stock `openssl ts -verify` (tools/tsa_stamp.js runs it, and anyone can run
// it again on the kept .tsr with no code of ours). This reader only pulls out
// the fields a person needs to see (status, the hashed message, the nonce,
// the authority's time) and compares the first two with what was asked, so
// an answer for another file or another request is named before openssl is
// even asked. It fails closed: anything it cannot read throws Rfc3161Error
// naming where.
//
// Shapes (RFC 3161 section 2.4, RFC 5652 for the token):
//   TimeStampReq  ::= SEQUENCE { version 1, messageImprint, reqPolicy OPTIONAL,
//                                nonce INTEGER OPTIONAL, certReq BOOLEAN DEFAULT FALSE, ... }
//   MessageImprint::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
//   TimeStampResp ::= SEQUENCE { PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
//   ContentInfo   ::= SEQUENCE { id-signedData, [0] EXPLICIT SignedData }
//   SignedData    ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
//   encapContent  ::= SEQUENCE { id-ct-TSTInfo, [0] EXPLICIT OCTET STRING (TSTInfo DER) }
//   TSTInfo       ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
//                                accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, ... }
"use strict";

const crypto = require("crypto");

const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const HASH_NAMES = { [OID_SHA256]: "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512" };
const STATUS_NAMES = ["granted", "grantedWithMods", "rejection", "waiting", "revocationWarning", "revocationNotification"];

class Rfc3161Error extends Error {
  constructor(where, reason) {
    super(`${where}: ${reason}`);
    this.where = where;
    this.reason = reason;
  }
}

// ---- DER writing ----

function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function encodeOid(oid) {
  const parts = oid.split(".").map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) {
    const stack = [p & 0x7f];
    for (let v = Math.floor(p / 128); v > 0; v = Math.floor(v / 128)) stack.unshift((v & 0x7f) | 0x80);
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

// A positive INTEGER from big-endian bytes, minimally encoded.
function encodeUnsigned(bytes) {
  let b = Buffer.from(bytes);
  while (b.length > 1 && b[0] === 0x00 && b[1] < 0x80) b = b.subarray(1);
  if (b[0] >= 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return tlv(0x02, b);
}

// 8 random bytes, first byte 0x01..0x7f: positive and already minimal, so the
// nonce reads back byte for byte the same in every tool that prints it.
function makeNonce() {
  const n = crypto.randomBytes(8);
  n[0] = (n[0] & 0x7f) | 0x01;
  return n;
}

function buildRequest({ hash, nonce = null, certReq = true } = {}) {
  if (!Buffer.isBuffer(hash) || hash.length !== 32) {
    throw new Rfc3161Error("request", "the hash must be 32 bytes (sha256 only)");
  }
  const algId = tlv(0x30, Buffer.concat([encodeOid(OID_SHA256), Buffer.from([0x05, 0x00])]));
  const imprint = tlv(0x30, Buffer.concat([algId, tlv(0x04, hash)]));
  const parts = [Buffer.from([0x02, 0x01, 0x01]), imprint];
  if (nonce) parts.push(encodeUnsigned(nonce));
  if (certReq) parts.push(Buffer.from([0x01, 0x01, 0xff]));
  return tlv(0x30, Buffer.concat(parts));
}

// ---- DER reading (definite lengths only, as DER requires) ----

function readTlv(buf, offset, where) {
  if (offset + 2 > buf.length) throw new Rfc3161Error(where, "truncated");
  const tag = buf[offset];
  let len = buf[offset + 1];
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Rfc3161Error(where, "unsupported length form");
    if (start + n > buf.length) throw new Rfc3161Error(where, "truncated length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  const end = start + len;
  if (end > buf.length) throw new Rfc3161Error(where, "truncated content");
  return { tag, start, end, content: buf.subarray(start, end) };
}

// The children of a constructed value, in order.
function children(node, where) {
  // Read against the parent's buffer so offsets stay absolute.
  const out = [];
  let off = node.start;
  while (off < node.end) {
    const c = readTlv(node.buf, off, where);
    c.buf = node.buf;
    if (c.end > node.end) throw new Rfc3161Error(where, "child runs past its parent");
    out.push(c);
    off = c.end;
  }
  return out;
}

function expect(node, tag, where) {
  if (!node || node.tag !== tag) {
    throw new Rfc3161Error(where, `expected tag 0x${tag.toString(16)}, found ${node ? `0x${node.tag.toString(16)}` : "nothing"}`);
  }
  return node;
}

function decodeOid(node, where) {
  expect(node, 0x06, where);
  const b = node.content;
  if (!b.length) throw new Rfc3161Error(where, "empty object identifier");
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

function decodeUnsignedHex(node, where) {
  expect(node, 0x02, where);
  const hex = node.content.toString("hex").replace(/^(00)+/, "");
  return hex.replace(/^0+(?=.)/, "") || "0";
}

function decodeGeneralizedTime(node, where) {
  expect(node, 0x18, where);
  const s = node.content.toString("latin1");
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/);
  if (!m) throw new Rfc3161Error(where, `unreadable time ${JSON.stringify(s)}`);
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] || ""}Z`;
}

function root(buf, where) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) throw new Rfc3161Error(where, "no bytes");
  const n = readTlv(buf, 0, where);
  n.buf = buf;
  if (n.end !== buf.length) throw new Rfc3161Error(where, "trailing bytes after the response");
  return n;
}

function parseTstInfo(der) {
  const top = expect(root(der, "TSTInfo"), 0x30, "TSTInfo");
  const f = children(top, "TSTInfo");
  const imprint = children(expect(f[2], 0x30, "TSTInfo.messageImprint"), "TSTInfo.messageImprint");
  const alg = children(expect(imprint[0], 0x30, "TSTInfo.messageImprint.hashAlgorithm"), "TSTInfo.messageImprint.hashAlgorithm");
  const hashOid = decodeOid(alg[0], "TSTInfo.messageImprint.hashAlgorithm");
  let nonce = null;
  for (const c of f.slice(5)) {
    if (c.tag === 0x02) { nonce = decodeUnsignedHex(c, "TSTInfo.nonce"); break; }
  }
  return {
    version: Number(decodeUnsignedHex(f[0], "TSTInfo.version")),
    policy: decodeOid(f[1], "TSTInfo.policy"),
    hashAlgorithm: HASH_NAMES[hashOid] || hashOid,
    hashedMessage: expect(imprint[1], 0x04, "TSTInfo.messageImprint.hashedMessage").content.toString("hex"),
    serial: decodeUnsignedHex(f[3], "TSTInfo.serialNumber"),
    genTime: decodeGeneralizedTime(f[4], "TSTInfo.genTime"),
    nonce,
  };
}

function parseResponse(buf) {
  let top;
  try {
    top = expect(root(buf, "TimeStampResp"), 0x30, "TimeStampResp");
  } catch (err) {
    if (err instanceof Rfc3161Error) throw new Rfc3161Error("TimeStampResp", `not a time stamp response (${err.reason})`);
    throw err;
  }
  const parts = children(top, "TimeStampResp");
  const statusInfo = children(expect(parts[0], 0x30, "TimeStampResp.status"), "TimeStampResp.status");
  const status = Number(decodeUnsignedHex(statusInfo[0], "TimeStampResp.status.status"));
  const granted = status === 0 || status === 1;
  if (!parts[1]) {
    return { status, statusName: STATUS_NAMES[status] || "unknown", granted, tst: null };
  }
  const ci = children(expect(parts[1], 0x30, "timeStampToken"), "timeStampToken");
  if (decodeOid(ci[0], "timeStampToken.contentType") !== OID_SIGNED_DATA) {
    throw new Rfc3161Error("timeStampToken.contentType", "not signed data");
  }
  const explicit = children(expect(ci[1], 0xa0, "timeStampToken.content"), "timeStampToken.content");
  const sd = children(expect(explicit[0], 0x30, "SignedData"), "SignedData");
  const encap = children(expect(sd[2], 0x30, "SignedData.encapContentInfo"), "SignedData.encapContentInfo");
  if (decodeOid(encap[0], "encapContentInfo.eContentType") !== OID_TST_INFO) {
    throw new Rfc3161Error("encapContentInfo.eContentType", "not TSTInfo");
  }
  const eContent = children(expect(encap[1], 0xa0, "encapContentInfo.eContent"), "encapContentInfo.eContent");
  const octets = expect(eContent[0], 0x04, "encapContentInfo.eContent");
  // SignedData after encapContentInfo: [0] IMPLICIT certificates OPTIONAL,
  // [1] IMPLICIT crls OPTIONAL, then signerInfos SET.
  let certificates = [];
  let rest = sd.slice(3);
  if (rest[0] && rest[0].tag === 0xa0) {
    certificates = children(rest[0], "SignedData.certificates")
      .filter((c) => c.tag === 0x30)
      .map((c) => Buffer.from(c.buf.subarray(c.start - headerLength(c), c.end)));
    rest = rest.slice(1);
  }
  if (rest[0] && rest[0].tag === 0xa1) rest = rest.slice(1);
  const signerInfos = children(expect(rest[0], 0x31, "SignedData.signerInfos"), "SignedData.signerInfos");
  if (signerInfos.length !== 1) {
    throw new Rfc3161Error("SignedData.signerInfos", `expected exactly one signer, found ${signerInfos.length}`);
  }
  return {
    status,
    statusName: STATUS_NAMES[status] || "unknown",
    granted,
    tst: parseTstInfo(Buffer.from(octets.content)),
    signer: signerIdentifier(signerInfos[0]),
    certificates,
  };
}

// The bytes of a value's tag and length, so a child can be cut out whole.
function headerLength(node) {
  const len = node.end - node.start;
  return 1 + derLength(len).length;
}

// SignerInfo.sid: the signer named by issuer and serial number (CMS
// version 1), or by subject key identifier [0] (version 3). Returned as raw
// bytes, compared byte for byte, never as printed text.
function signerIdentifier(signerInfo) {
  const f = children(expect(signerInfo, 0x30, "SignerInfo"), "SignerInfo");
  const sid = f[1];
  if (sid && sid.tag === 0x80) {
    return { kind: "subject_key_identifier", keyId: Buffer.from(sid.content).toString("hex") };
  }
  const ias = children(expect(sid, 0x30, "SignerInfo.sid"), "SignerInfo.sid");
  const issuer = expect(ias[0], 0x30, "SignerInfo.sid.issuer");
  return {
    kind: "issuer_and_serial",
    issuer: Buffer.from(issuer.buf.subarray(issuer.start - headerLength(issuer), issuer.end)).toString("hex"),
    serial: decodeUnsignedHex(ias[1], "SignerInfo.sid.serialNumber"),
  };
}

// A certificate's issuer (raw Name bytes) and serial, for matching a signer.
// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL,
// serialNumber, signature, issuer, ... }, ... }
function certificateIssuerSerial(der) {
  const cert = children(expect(root(der, "Certificate"), 0x30, "Certificate"), "Certificate");
  let tbs = children(expect(cert[0], 0x30, "Certificate.tbsCertificate"), "Certificate.tbsCertificate");
  if (tbs[0] && tbs[0].tag === 0xa0) tbs = tbs.slice(1);
  const issuer = expect(tbs[2], 0x30, "Certificate.issuer");
  return {
    issuer: Buffer.from(issuer.buf.subarray(issuer.start - headerLength(issuer), issuer.end)).toString("hex"),
    serial: decodeUnsignedHex(tbs[0], "Certificate.serialNumber"),
  };
}

// The one certificate among `candidates` (DER buffers) that the token's
// signer names. Returns { cert } or { problem }.
function findSignerCertificate(resp, candidates) {
  if (!resp.signer || resp.signer.kind !== "issuer_and_serial") {
    return { problem: "the token names its signer by key identifier; only issuer and serial number are matched here" };
  }
  const matches = [];
  for (const der of candidates) {
    let id;
    try { id = certificateIssuerSerial(der); } catch (_) { continue; }
    if (id.issuer === resp.signer.issuer && id.serial === resp.signer.serial) matches.push(der);
  }
  const unique = [...new Map(matches.map((d) => [d.toString("hex"), d])).values()];
  if (unique.length === 0) return { problem: "the signing certificate is not in the token or the --untrusted file" };
  if (unique.length > 1) return { problem: "more than one different certificate claims the signer's issuer and serial number" };
  return { cert: unique[0] };
}

// Compare an answer with what was asked. The signature is openssl's job.
function checkResponse(resp, { hash, nonce }) {
  const problems = [];
  if (!resp.granted) {
    problems.push(`the authority did not grant the stamp: status ${resp.status} (${resp.statusName})`);
  } else if (!resp.tst) {
    problems.push("the authority granted the stamp but sent no token");
  } else {
    if (resp.tst.hashAlgorithm !== "sha256") problems.push(`the token's imprint is ${resp.tst.hashAlgorithm}, not sha256`);
    if (resp.tst.hashedMessage !== Buffer.from(hash).toString("hex")) {
      problems.push("the token's imprint is not the sha256 of this file (an answer for something else)");
    }
    const asked = nonce ? decodeUnsignedHex({ tag: 0x02, content: Buffer.from(nonce) }, "nonce") : null;
    if (asked !== resp.tst.nonce) {
      problems.push(`the token's nonce (${resp.tst.nonce}) is not the one asked (${asked}): not an answer to this request`);
    }
  }
  return { ok: problems.length === 0, problems };
}

module.exports = {
  buildRequest,
  parseResponse,
  checkResponse,
  makeNonce,
  certificateIssuerSerial,
  findSignerCertificate,
  Rfc3161Error,
  OID_SHA256,
};

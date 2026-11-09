import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import snippet from "../cf_ctreq.js";

// Minimal DER builders; certificates are structurally valid X.509 but have fake signatures.
const tlv = (tag, content) => {
  const body = Buffer.from(content);
  const n = body.length;
  const header = n < 0x80 ? [tag, n] : n < 0x100 ? [tag, 0x81, n] : [tag, 0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from(header), body]);
};
const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const ctOid = (last) => [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, last]; // 1.3.6.1.4.1.11129.2.4.<last>
const OID_EKU = [0x55, 0x1d, 0x25];
const ext = (oid, critical, value) =>
  seq(tlv(0x06, oid), critical ? tlv(0x01, [0xff]) : Buffer.alloc(0), tlv(0x04, value));
const POISON_EXT = ext(ctOid(3), true, [0x05, 0x00]);

function makeCert({ extensions, subject = Buffer.alloc(100, 0x61) } = {}) {
  const alg = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
  const name = (cn) => seq(tlv(0x31, seq(tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x0c, cn))));
  const time = tlv(0x17, Buffer.from("260101000000Z"));
  const tbs = seq(
    tlv(0xa0, tlv(0x02, [2])),
    tlv(0x02, [1]),
    alg,
    name("Test CA"),
    seq(time, time),
    name(subject),
    seq(alg, tlv(0x03, [0, ...Array(32).fill(1)])),
    extensions ? tlv(0xa3, seq(...extensions)) : Buffer.alloc(0),
  );
  return seq(tbs, alg, tlv(0x03, [0, ...Array(64).fill(2)]));
}

const b64 = (buf) => buf.toString("base64");
// A CA certificate whose subject matches the issuer of the other fixtures.
const makeCA = (extensions) => makeCert({ extensions, subject: Buffer.from("Test CA") });
// A valid outer SEQUENCE header around filler, for tests that don't need a parseable certificate.
const der = (content) => Buffer.from([0x30, 0x82, content.length >> 8, content.length & 0xff, ...content]);

const CERT = b64(makeCert());
const PRECERT = b64(makeCert({ extensions: [POISON_EXT] }));
const NONCRITICAL = b64(makeCert({ extensions: [ext(ctOid(3), false, [0x05, 0x00])] }));
const ISSUER = b64(makeCA());

// With CTREQ_LOG_URL set (e.g. https://ct.example.com/2026h1), requests that the local snippet
// rejects are also sent to that deployed log, which must reject them identically. Anything the
// snippet would forward is skipped, so nothing is ever submitted to the log.
const networkFetch = globalThis.fetch;
if (process.env.CTREQ_LOG_URL) {
  const base = new URL(process.env.CTREQ_LOG_URL);
  let liveTest;
  beforeEach((t) => {
    liveTest = t;
  });
  const local = snippet.fetch;
  snippet.fetch = async (req) => {
    const localRes = await local.call(snippet, req.clone());
    const reason = localRes.headers.get("X-CTreq-Reject");
    if (reason === null) {
      liveTest.diagnostic(`not sent to the log (it would be forwarded): ${req.method} ${new URL(req.url).pathname}`);
      return localRes;
    }
    const url = new URL(base.pathname.replace(/\/$/, "") + new URL(req.url).pathname, base);
    const headers = new Headers(req.headers);
    headers.delete("Content-Length");
    let body;
    if (req.method !== "GET" && req.method !== "HEAD") {
      body = await req.clone().text();
      // A declared Content-Length larger than the body is reproduced by padding the body.
      const missing = Number(req.headers.get("Content-Length")) - Buffer.byteLength(body);
      if (missing > 0) body += " ".repeat(missing);
    }
    const liveRes = await networkFetch(url, { method: req.method, headers, body, redirect: "manual" });
    assert.equal(liveRes.headers.get("X-CTreq-Reject"), reason, `${req.method} ${url} responded ${liveRes.status}`);
    assert.equal(liveRes.status, localRes.status, `${req.method} ${url}`);
    liveTest.diagnostic(`sent to the log: ${req.method} ${url} => ${liveRes.status} ${reason}`);
    return liveRes;
  };
}

// Print each submitted chain as decoded by openssl under `npm test --verbose` (npm sets
// npm_config_loglevel) or with CTREQ_VERBOSE set.
if (process.env.CTREQ_VERBOSE || ["verbose", "silly"].includes(process.env.npm_config_loglevel)) {
  const labels = new Map([[CERT, "CERT"], [PRECERT, "PRECERT"], [NONCRITICAL, "NONCRITICAL"], [ISSUER, "ISSUER"]]);
  const shown = new Set();
  const pending = [];
  // Test diagnostics are reported next to the test's result, unlike console output.
  afterEach((t) => {
    if (pending.length) t.diagnostic(pending.splice(0).join("\n\n") + "\n");
  });
  let unnamed = 0;
  const hexDump = (buf) => Array.from({ length: Math.ceil(buf.length / 16) }, (_, row) => {
    const bytes = buf.subarray(row * 16, row * 16 + 16);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(bytes, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    return `${(row * 16).toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  |${ascii}|`;
  }).join("\n");
  const STRICT_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  // Shown only the first time a certificate appears, since decode() is.
  const describeFailure = (entry, reason) => {
    const lines = ["openssl cannot parse this certificate: " + reason, "base64:", ...(entry.match(/[\s\S]{1,64}/g) ?? ["(empty)"])];
    if (STRICT_BASE64.test(entry)) {
      const bytes = Buffer.from(entry, "base64");
      lines.push(`hex (${bytes.length} bytes):`, bytes.length ? hexDump(bytes) : "(empty)");
    } else {
      lines.push("(not valid base64, so no hex dump)");
    }
    return lines.join("\n");
  };
  const decode = (entry) => {
    const r = spawnSync("openssl", ["x509", "-inform", "DER", "-text", "-noout", "-certopt", "no_pubkey,no_sigdump"], { input: Buffer.from(entry, "base64") });
    return r.status === 0 ? r.stdout.toString().trimEnd() : describeFailure(entry, r.stderr?.toString().trim() || r.error?.message);
  };
  const realFetch = snippet.fetch;
  snippet.fetch = async (req) => {
    const out = [`${req.method} ${new URL(req.url).pathname}`];
    let chain;
    try {
      chain = JSON.parse(await req.clone().text()).chain;
    } catch {}
    for (const [i, entry] of (Array.isArray(chain) ? chain : []).entries()) {
      if (typeof entry !== "string") {
        out.push(`chain[${i}]: not a string`);
        continue;
      }
      if (!labels.has(entry)) labels.set(entry, "cert#" + ++unnamed);
      out.push(`chain[${i}]: ${labels.get(entry)}${shown.has(entry) ? " (decoded above)" : ""}`);
      if (!shown.has(entry)) out.push(decode(entry));
      shown.add(entry);
    }
    const res = await realFetch.call(snippet, req);
    out.push(`=> ${res.status} ${res.headers.get("X-CTreq-Reject") ?? "forwarded"}`);
    pending.push(out.join("\n"));
    return res;
  };
}

let forwarded;
beforeEach(() => {
  forwarded = null;
  globalThis.fetch = async (req) => {
    forwarded = { method: req.method, url: req.url, body: req.method === "POST" ? await req.text() : null };
    return new Response("origin", { status: 200 });
  };
});

function post(path, body) {
  return new Request("https://log.example.com" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

test("certificate to add-chain is forwarded", async () => {
  const body = JSON.stringify({ chain: [CERT, ISSUER] });
  const res = await snippet.fetch(post("/2026h1/ct/v1/add-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

test("precertificate to add-pre-chain is forwarded", async () => {
  const body = JSON.stringify({ chain: [PRECERT, ISSUER] });
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

test("precertificate to add-chain is rejected", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [PRECERT] }));
  assert.equal(res.status, 400);
  assert.equal(forwarded, null);
});

test("certificate to add-pre-chain is rejected", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [CERT, ISSUER] }));
  assert.equal(res.status, 400);
  assert.equal(forwarded, null);
});

test("poison extension in a later certificate does not affect classification", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [CERT, b64(makeCA([POISON_EXT]))] }));
  assert.equal(res.status, 200);
});

test("issuer that does not match the second certificate's subject is rejected", async () => {
  const otherCA = b64(makeCert({ subject: Buffer.from("Other CA") }));
  for (const [path, first] of [["/ct/v1/add-chain", CERT], ["/ct/v1/add-pre-chain", PRECERT]]) {
    const res = await snippet.fetch(post(path, { chain: [first, otherCA, ISSUER] }));
    assert.equal(res.status, 400, path);
  }
  assert.equal(forwarded, null);
});

test("issuer mismatch deeper in the chain is rejected", async () => {
  const otherCA = b64(makeCert({ subject: Buffer.from("Other CA") }));
  // ISSUER's issuer is "Test CA", but the next certificate's subject is "Other CA".
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [CERT, ISSUER, otherCA] }));
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("X-CTreq-Reject"), "issuer-mismatch");
  assert.equal(forwarded, null);
});

test("certificate without parseable names is rejected in any position", async () => {
  const noNames = b64(seq(seq(tlv(0x02, [1]), tlv(0x04, Array(150).fill(0))), seq(tlv(0x06, [0x2a])), tlv(0x03, [0])));
  for (const chain of [[noNames], [noNames, ISSUER], [CERT, noNames]]) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", { chain }));
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("X-CTreq-Reject"), "cert-unparseable");
  }
  assert.equal(forwarded, null);
});

test("non-critical poison extension is rejected", async () => {
  for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
    const res = await snippet.fetch(post(path, { chain: [NONCRITICAL] }));
    assert.equal(res.status, 400, path);
  }
  assert.equal(forwarded, null);
});

test("poison bytes outside the extensions are not treated as poison", async () => {
  const lookalike = b64(makeCert({ subject: Buffer.concat([Buffer.alloc(50, 0x61), POISON_EXT]) }));
  let res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [lookalike] }));
  assert.equal(res.status, 200);
  res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [lookalike] }));
  assert.equal(res.status, 400);
});

test("poison extension with a non-NULL value is rejected", async () => {
  const wrongValue = b64(makeCert({ extensions: [ext(ctOid(3), true, [0x30, 0x00])] }));
  for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
    const res = await snippet.fetch(post(path, { chain: [wrongValue] }));
    assert.equal(res.status, 400, path);
  }
  assert.equal(forwarded, null);
});

test("poison together with an embedded SCT list is rejected", async () => {
  const sctList = ext(ctOid(2), false, [0x04, 0x00]);
  const both = b64(makeCert({ extensions: [POISON_EXT, sctList] }));
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [both, ISSUER] }));
  assert.equal(res.status, 400);
  assert.equal(forwarded, null);
  const sctOnly = b64(makeCert({ extensions: [sctList] }));
  assert.equal((await snippet.fetch(post("/ct/v1/add-chain", { chain: [sctOnly, ISSUER] }))).status, 200);
});

test("precertificate signing certificate is rejected as the issuer on add-chain only", async () => {
  const eku = (...oids) => ext(OID_EKU, false, seq(...oids.map((o) => tlv(0x06, o))));
  const serverAuth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
  const psc = b64(makeCA([eku(serverAuth, ctOid(4))]));
  const plainEku = b64(makeCA([eku(serverAuth)]));
  let res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [CERT, psc] }));
  assert.equal(res.status, 400);
  assert.equal(forwarded, null);
  res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [PRECERT, psc, ISSUER] }));
  assert.equal(res.status, 200);
  res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [CERT, plainEku] }));
  assert.equal(res.status, 200);
});

test("unparseable certificates are rejected in any position", async () => {
  const garbage = b64(der(Array(160).fill(0xab)));
  const badExtension = b64(makeCert({ extensions: [seq(tlv(0x04, [1]), tlv(0x04, [2]))] }));
  for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
    for (const first of [garbage, badExtension]) {
      const res = await snippet.fetch(post(path, { chain: [first] }));
      assert.equal(res.status, 400, path);
    }
  }
  for (const chain of [[CERT, garbage], [CERT, ISSUER, badExtension]]) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", { chain }));
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("X-CTreq-Reject"), "cert-unparseable");
  }
  assert.equal(forwarded, null);
});

test("every rejection carries an X-CTreq-Reject reason", async () => {
  const ADD = "/ct/v1/add-chain";
  const PRE = "/ct/v1/add-pre-chain";
  const psc = b64(makeCA([ext(OID_EKU, false, seq(tlv(0x06, ctOid(4))))]));
  const sctList = ext(ctOid(2), false, [0x04, 0x00]);
  const poisonAndSct = b64(makeCert({ extensions: [POISON_EXT, sctList] }));
  const otherCA = b64(makeCert({ subject: Buffer.from("Other CA") }));
  const bigLength = post(ADD, { chain: [CERT] });
  bigLength.headers.set("Content-Length", String(128 * 1024 + 1));
  const textPlain = new Request("https://log.example.com" + ADD, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: "x",
  });
  const cases = {
    "method-not-allowed": new Request("https://log.example.com" + ADD),
    "unsupported-media-type": textPlain,
    "body-too-large": bigLength,
    "invalid-json": post(ADD, "not json"),
    "chain-missing": post(ADD, "{}"),
    "chain-too-long": post(ADD, { chain: Array(11).fill(CERT) }),
    "entry-not-base64": post(ADD, { chain: ["!!!"] }),
    "entry-too-short": post(ADD, { chain: [b64(der(Array(100).fill(0xab)))] }),
    "entry-not-der": post(ADD, { chain: [b64(Buffer.from([0x31, 0x82, 0x00, 0xa0, ...Array(160).fill(0xab)]))] }),
    "cert-unparseable": post(ADD, { chain: [b64(der(Array(160).fill(0xab)))] }),
    "poison-invalid": post(ADD, { chain: [NONCRITICAL] }),
    "poison-with-sct-list": post(PRE, { chain: [poisonAndSct, ISSUER] }),
    "precert-on-add-chain": post(ADD, { chain: [PRECERT] }),
    "cert-on-add-pre-chain": post(PRE, { chain: [CERT] }),
    "psc-on-add-chain": post(ADD, { chain: [CERT, psc] }),
    "issuer-mismatch": post(ADD, { chain: [CERT, otherCA] }),
  };
  for (const [reason, req] of Object.entries(cases)) {
    const res = await snippet.fetch(req);
    assert.notEqual(res.status, 200, reason);
    assert.equal(res.headers.get("X-CTreq-Reject"), reason);
    assert.equal(res.headers.get("Content-Type"), "application/problem+json", reason);
    const problem = await res.json();
    assert.equal(problem.type, "https://github.com/sectigo/CF_CTreq#" + reason);
    assert.equal(problem.status, res.status, reason);
    assert.equal(typeof problem.title, "string", reason);
  }
  assert.equal(forwarded, null);
});

test("malformed requests are rejected", async () => {
  for (const body of ["not json", "{}", '{"chain":[]}', '{"chain":[1]}', '{"chain":["!!!"]}']) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(res.status, 400, body);
  }
  assert.equal(forwarded, null);
});

test("chain shape violations are rejected", async () => {
  const SHORT = b64(der(Array(100).fill(0xab)));
  assert.ok(CERT.endsWith("="), "fixture must need base64 padding");
  const bodies = {
    "too many entries": { chain: Array(11).fill(CERT) },
    "non-string later entry": { chain: [CERT, 1] },
    "invalid base64 later entry": { chain: [CERT, "!!!"] },
    "URL-safe base64": { chain: [CERT.replace(/\+/g, "-").replace(/\//g, "_") + "-_"] },
    "unpadded base64": { chain: [CERT.replace(/=+$/, "")] },
    "short first entry": { chain: [SHORT] },
    "short later entry": { chain: [CERT, SHORT] },
    "empty later entry": { chain: [CERT, ""] },
  };
  for (const [name, body] of Object.entries(bodies)) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(res.status, 400, name);
  }
  assert.equal(forwarded, null);
});

test("entries that are not a DER SEQUENCE of the declared length are rejected", async () => {
  const filler = Array(160).fill(0xab);
  const entries = {
    "wrong tag": [0x31, 0x82, 0x00, 0xa0, ...filler],
    "length too large": [0x30, 0x82, 0x00, 0xa1, ...filler],
    "length too small": [0x30, 0x82, 0x00, 0x9f, ...filler],
    "indefinite length": [0x30, 0x80, ...filler],
    "oversized length-of-length": [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0xa0, ...filler],
  };
  for (const [name, bytes] of Object.entries(entries)) {
    const b64 = Buffer.from(bytes).toString("base64");
    for (const chain of [[b64], [CERT, b64]]) {
      const res = await snippet.fetch(post("/ct/v1/add-chain", { chain }));
      assert.equal(res.status, 400, name);
    }
  }
  assert.equal(forwarded, null);
});

test("one-byte long-form DER length is accepted", async () => {
  const buf = makeCert({ subject: Buffer.alloc(20, 0x61) });
  assert.equal(buf[1], 0x81);
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(buf)] }));
  assert.equal(res.status, 200);
});

test("maximum chain length and extra top-level fields are accepted", async () => {
  const body = JSON.stringify({ chain: [CERT, ...Array(9).fill(ISSUER)], extra: true });
  const res = await snippet.fetch(post("/ct/v1/add-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

test("non-POST requests to the endpoints get 405", async () => {
  for (const method of ["GET", "PUT", "DELETE", "OPTIONS"]) {
    for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
      const res = await snippet.fetch(new Request("https://log.example.com" + path, { method }));
      assert.equal(res.status, 405, method + " " + path);
      assert.equal(res.headers.get("Allow"), "POST");
    }
  }
  assert.equal(forwarded, null);
});

test("non-JSON Content-Type gets 415", async () => {
  for (const contentType of ["text/plain", "application/x-www-form-urlencoded", null]) {
    const headers = contentType ? { "Content-Type": contentType } : {};
    const req = new Request("https://log.example.com/ct/v1/add-chain", {
      method: "POST",
      headers,
      body: new Uint8Array([0x7b, 0x7d]),
    });
    if (!contentType) req.headers.delete("Content-Type");
    const res = await snippet.fetch(req);
    assert.equal(res.status, 415, String(contentType));
  }
  assert.equal(forwarded, null);
});

test("Content-Type parameters and case are accepted", async () => {
  const req = new Request("https://log.example.com/ct/v1/add-chain", {
    method: "POST",
    headers: { "Content-Type": "Application/JSON; charset=utf-8" },
    body: JSON.stringify({ chain: [CERT, ISSUER] }),
  });
  const res = await snippet.fetch(req);
  assert.equal(res.status, 200);
});

test("oversized Content-Length gets 413 without reading the body", async () => {
  const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
  req.headers.set("Content-Length", String(128 * 1024 + 1));
  let read = false;
  req.text = async () => { read = true; return ""; };
  const res = await snippet.fetch(req);
  assert.equal(res.status, 413);
  assert.equal(read, false);
  assert.equal(forwarded, null);
});

test("Content-Length at the limit is accepted", async () => {
  const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
  req.headers.set("Content-Length", String(128 * 1024));
  const res = await snippet.fetch(req);
  assert.equal(res.status, 200);
});

test("other requests pass through untouched", async () => {
  let res = await snippet.fetch(new Request("https://log.example.com/ct/v1/get-sth"));
  assert.equal(res.status, 200);
  assert.equal(forwarded.method, "GET");
  res = await snippet.fetch(post("/ct/v1/other", "xyz"));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, "xyz");
});

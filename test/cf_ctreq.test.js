import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

// CTREQ_ENVIRONMENT selects CONFIG.environment ("sunlight", "tesseract", "trillian", or "common")
// for the snippet under test; by default, the snippet's own setting is tested. Another
// setting is applied to a copy of the source, so that CONFIG needn't be exported.
const SOURCE = readFileSync(new URL("../cf_ctreq.js", import.meta.url), "utf8");
const CONFIG_ENVIRONMENT = /^(\s*environment: )"([a-z]*)"/m;
assert.match(SOURCE, CONFIG_ENVIRONMENT, "cf_ctreq.js must set CONFIG.environment to a string literal");
async function loadSnippet(environment) {
  const source = SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(environment)}`);
  return (await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"))).default;
}
const ENVIRONMENT = process.env.CTREQ_ENVIRONMENT || SOURCE.match(CONFIG_ENVIRONMENT)[2];
const snippet = process.env.CTREQ_ENVIRONMENT ? await loadSnippet(ENVIRONMENT) : (await import("../cf_ctreq.js")).default;
// Returns the expected value for the environment under test.
const expected = (byEnvironment) => {
  assert.ok(Object.hasOwn(byEnvironment, ENVIRONMENT), `no expectation for environment ${ENVIRONMENT}`);
  return byEnvironment[ENVIRONMENT];
};

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

// version is the content of the [0] version INTEGER (default v3), or null to omit it (v1);
// versionField replaces the whole [0] field. beforeExtensions and afterExtensions are
// raw bytes placed around the [3] extensions field, which extensionsField replaces.
function makeCert({ extensions, subject = Buffer.alloc(100, 0x61), version = [2], versionField, beforeExtensions = [], extensionsField, afterExtensions = [] } = {}) {
  const alg = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
  const name = (cn) => seq(tlv(0x31, seq(tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x0c, cn))));
  const time = tlv(0x17, Buffer.from("260101000000Z"));
  const tbs = seq(
    versionField ? Buffer.from(versionField) : version === null ? Buffer.alloc(0) : tlv(0xa0, tlv(0x02, version)),
    tlv(0x02, [1]),
    alg,
    name("Test CA"),
    seq(time, time),
    name(subject),
    seq(alg, tlv(0x03, [0, ...Array(32).fill(1)])),
    Buffer.from(beforeExtensions),
    extensionsField ? Buffer.from(extensionsField) : extensions ? tlv(0xa3, seq(...extensions)) : Buffer.alloc(0),
    Buffer.from(afterExtensions),
  );
  return seq(tbs, alg, tlv(0x03, [0, ...Array(64).fill(2)]));
}

const b64 = (buf) => buf.toString("base64");
// A CA certificate whose subject matches the issuer of the other fixtures.
const makeCA = (extensions) => makeCert({ extensions, subject: Buffer.from("Test CA") });
// A valid outer SEQUENCE header around filler, for tests that don't need a parseable certificate.
const der = (content) => tlv(0x30, content);

const CERT = b64(makeCert());
const PRECERT = b64(makeCert({ extensions: [POISON_EXT] }));
const NONCRITICAL = b64(makeCert({ extensions: [ext(ctOid(3), false, [0x05, 0x00])] }));
const ISSUER = b64(makeCA());

// Requests whose body is streamed without a Content-Length (see postStream).
const streamed = new WeakSet();

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
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    // Copy the body before the snippet reads it: in Node, a clone can't be read once its
    // twin has been cancelled part-way, as the snippet does with an oversized body.
    const bytes = hasBody ? new Uint8Array(await req.clone().arrayBuffer()) : null;
    const localRes = await local.call(snippet, req);
    const reason = localRes.headers.get("X-CTreq-Reject");
    if (reason === null) {
      liveTest.diagnostic(`not sent to the log (it would be forwarded): ${req.method} ${new URL(req.url).pathname}`);
      return localRes;
    }
    const url = new URL(base.pathname.replace(/\/$/, "") + new URL(req.url).pathname, base);
    const headers = new Headers(req.headers);
    headers.delete("Content-Length");
    let body;
    let duplex;
    if (hasBody) {
      if (streamed.has(req)) {
        // Sent as a stream, so that it reaches the log without a Content-Length too.
        body = new Blob([bytes]).stream();
        duplex = "half";
      } else {
        // A declared Content-Length larger than the body is reproduced by padding the body.
        const missing = Number(req.headers.get("Content-Length")) - bytes.length;
        body = missing > 0 ? new Blob([bytes, " ".repeat(missing)]) : bytes;
      }
    }
    const liveRes = await networkFetch(url, { method: req.method, headers, body, duplex, redirect: "manual" });
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
    const bytes = req.method === "POST" ? new Uint8Array(await req.arrayBuffer()) : null;
    forwarded = { method: req.method, url: req.url, bytes, body: bytes && new TextDecoder().decode(bytes) };
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

// The snippet's rejection reason for a response, or "forwarded" if the origin answered.
const outcome = (res) => res.headers.get("X-CTreq-Reject") ?? (res.status === 200 ? "forwarded" : `status ${res.status}`);

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

test("poison together with an embedded SCT list is forwarded, as the origin accepts it", async () => {
  const sctList = ext(ctOid(2), false, [0x04, 0x00]);
  const body = JSON.stringify({ chain: [b64(makeCert({ extensions: [POISON_EXT, sctList] })), ISSUER] });
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

test("precertificate signing certificate as the issuer is only rejected by Sunlight, on add-pre-chain", async () => {
  const eku = (...oids) => ext(OID_EKU, false, seq(...oids.map((o) => tlv(0x06, o))));
  const serverAuth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
  const psc = b64(makeCA([eku(serverAuth, ctOid(4))]));
  assert.equal(outcome(await snippet.fetch(post("/ct/v1/add-chain", { chain: [CERT, psc] }))), "forwarded");
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [PRECERT, psc, ISSUER] }));
  assert.equal(outcome(res), expected({ tesseract: "forwarded", sunlight: "psc-not-supported", trillian: "forwarded", common: "forwarded" }));
  // Only an extended key usage extension that Sunlight can parse counts.
  const unparseableEku = b64(makeCA([ext(OID_EKU, false, seq(tlv(0x06, ctOid(4)), Buffer.from([0x05, 0x00])))]));
  assert.equal(outcome(await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [PRECERT, unparseableEku] }))), "forwarded");
});

test("extensions in v1 and v2 certificates are only read by Sunlight and Trillian", async () => {
  const malformed = seq(tlv(0x04, [1]), tlv(0x04, [2]));
  // v1 (no version field, or explicitly 0) and v2.
  for (const version of [null, [0], [1]]) {
    const label = JSON.stringify(version);
    const poisoned = b64(makeCert({ version, extensions: [POISON_EXT] }));
    let res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [poisoned, ISSUER] }));
    assert.equal(outcome(res), expected({ tesseract: "forwarded", sunlight: "precert-on-add-chain", trillian: "precert-on-add-chain", common: "forwarded" }), label);
    res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [poisoned, ISSUER] }));
    assert.equal(outcome(res), expected({ tesseract: "cert-on-add-pre-chain", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }), label);
    res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(makeCert({ version, extensions: [malformed] })), ISSUER] }));
    assert.equal(outcome(res), expected({ tesseract: "forwarded", sunlight: "cert-unparseable", trillian: "cert-unparseable", common: "forwarded" }), label);
  }
});

test("unknown or malformed certificate versions are only rejected by TesseraCT", async () => {
  // v4, negative, and non-minimally encoded.
  for (const version of [[3], [0xff], [0x00, 0x02]]) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(makeCert({ version })), ISSUER] }));
    assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }), JSON.stringify(version));
  }
});

const NULL = [0x05, 0x00];

test("structures that Go's crypto/x509 tolerates around the extensions are accepted", async () => {
  const precerts = {
    "element after extnValue": makeCert({ extensions: [seq(tlv(0x06, ctOid(3)), tlv(0x01, [0xff]), tlv(0x04, NULL), Buffer.from(NULL))] }),
    "data after the SEQUENCE inside [3]": makeCert({ extensionsField: tlv(0xa3, Buffer.concat([seq(POISON_EXT), Buffer.from(NULL)])) }),
    "malformed data after [3]": makeCert({ extensions: [POISON_EXT], afterExtensions: [0xff, 0xff, 0xff] }),
    "unique IDs before [3]": makeCert({ extensions: [POISON_EXT], beforeExtensions: [...tlv(0x81, [0, 1]), ...tlv(0x82, [0, 2])] }),
  };
  for (const [name, cert] of Object.entries(precerts)) {
    const body = JSON.stringify({ chain: [b64(cert), ISSUER] });
    forwarded = null;
    const res = await snippet.fetch(post("/ct/v1/add-pre-chain", body));
    assert.equal(res.status, 200, name);
    assert.equal(forwarded.body, body, name);
    assert.equal((await snippet.fetch(post("/ct/v1/add-chain", body))).headers.get("X-CTreq-Reject"), "precert-on-add-chain", name);
  }
});

test("extensions are only read where Go's crypto/x509 looks for them", async () => {
  // Go only looks for [3] directly after the public key and the optional unique IDs.
  const cert = b64(makeCert({ extensions: [POISON_EXT], beforeExtensions: NULL }));
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [cert, ISSUER] }));
  assert.equal(res.status, 200);
  forwarded = null;
  const pre = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [cert, ISSUER] }));
  assert.equal(pre.headers.get("X-CTreq-Reject"), "cert-on-add-pre-chain");
});

test("malformed fields that the origin's X.509 parser reads are rejected", async () => {
  const certs = {
    "extension list element that isn't a SEQUENCE": makeCert({ extensionsField: tlv(0xa3, seq(POISON_EXT, Buffer.from(NULL))) }),
    "malformed [3]": makeCert({ extensionsField: Buffer.from([0xa3, 0x7f]) }),
    "malformed issuerUniqueID": makeCert({ beforeExtensions: [0x81, 0x7f] }),
    "missing subjectPublicKeyInfo": seq(seq(tlv(0xa0, tlv(0x02, [2])), tlv(0x02, [1]), seq(), seq(), seq(), seq(Buffer.alloc(120))), seq()),
  };
  for (const [name, cert] of Object.entries(certs)) {
    for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
      const res = await snippet.fetch(post(path, { chain: [b64(cert), ISSUER] }));
      assert.equal(res.headers.get("X-CTreq-Reject"), "cert-unparseable", `${name} on ${path}`);
    }
  }
  assert.equal(forwarded, null);
});

test("duplicate extensions are only rejected by TesseraCT", async () => {
  const duplicated = b64(makeCert({ extensions: [POISON_EXT, POISON_EXT] }));
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [duplicated, ISSUER] }));
  assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }));
});

test("thousands of extensions are checked well within a Snippet's 5 ms limit", async () => {
  // Distinct OIDs 1.2.<k>, so that the duplicate check has to compare them all.
  const arc = (k) => (k < 128 ? [k] : [0x80 | (k >> 7), k & 0x7f]);
  const many = b64(makeCert({ extensions: Array.from({ length: 7000 }, (_, k) => ext([0x2a, ...arc(k)], false, [])) }));
  const request = () => snippet.fetch(post("/ct/v1/add-chain", { chain: [many] }));
  await request();
  const start = performance.now();
  const res = await request();
  const elapsed = performance.now() - start;
  assert.equal(outcome(res), "forwarded");
  // About 1 ms when the duplicate check uses a Set, but ~100 ms when it compared every
  // pair of extensions; generous, so as not to fail on a slow machine.
  assert.ok(elapsed < 40, `took ${elapsed.toFixed(1)} ms`);
});

test("extension OIDs are decoded as the origin's X.509 parser decodes them", async () => {
  // The poison OID with its 11129 arc (0xd6 0x79) padded with a leading 0x80 byte,
  // which only certificate-transparency-go's x509 (Sunlight, Trillian) accepts.
  const paddedPoison = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x80, 0xd6, 0x79, 0x02, 0x04, 0x03];
  const padded = b64(makeCert({ extensions: [ext(paddedPoison, true, NULL)] }));
  let res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [padded, ISSUER] }));
  assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }));
  res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [padded, ISSUER] }));
  assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "precert-on-add-chain", trillian: "precert-on-add-chain", common: "cert-unparseable" }));
  // A padded valid poison extension is the one checked, not a later canonical one.
  const both = b64(makeCert({ extensions: [ext(paddedPoison, true, NULL), ext(ctOid(3), false, NULL)] }));
  res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [both, ISSUER] }));
  assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }));
  // An empty OID, which only certificate-transparency-go's x509 accepts (when it retries laxly).
  res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(makeCert({ extensions: [ext([], false, NULL)] })), ISSUER] }));
  assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }));
  // Arcs that both parsers reject: 2^31, longer than 5 bytes, and truncated; and 2^31 - 1, which both accept.
  const arcs = { "2^31": [0x2b, 0x88, 0x80, 0x80, 0x80, 0x00], "6 bytes": [0x2b, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], truncated: [0x2b, 0x86] };
  for (const [name, oid] of Object.entries(arcs)) {
    res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(makeCert({ extensions: [ext(oid, false, NULL)] })), ISSUER] }));
    assert.equal(outcome(res), "cert-unparseable", name);
  }
  res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(makeCert({ extensions: [ext([0x2b, 0x87, 0xff, 0xff, 0xff, 0x7f], false, NULL)] })), ISSUER] }));
  assert.equal(outcome(res), "forwarded", "2^31 - 1");
  // Sunlight also recognises a padded OID in a Precertificate Signing Certificate's
  // extended key usage. (TesseraCT rejects one, but the snippet doesn't parse its contents.)
  const paddedCT = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x80, 0xd6, 0x79, 0x02, 0x04, 0x04];
  const psc = b64(makeCA([ext(OID_EKU, false, seq(tlv(0x06, paddedCT)))]));
  res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [PRECERT, psc] }));
  assert.equal(outcome(res), expected({ tesseract: "forwarded", sunlight: "psc-not-supported", trillian: "forwarded", common: "forwarded" }));
});

test("explicitly tagged fields are parsed as the origin's X.509 parser parses them", async () => {
  // certificate-transparency-go's encoding/asn1 (Sunlight, Trillian) ignores the length
  // of the [0] and [3] wrappers, reading the element after the header instead.
  const want = (tesseract, ctgo) => expected({ tesseract, sunlight: ctgo, trillian: ctgo, common: tesseract === "forwarded" || ctgo === "forwarded" ? "forwarded" : tesseract });
  const cases = [
    ["[0] longer than its INTEGER", "add-chain", makeCert({ versionField: [0xa0, 0x7f, 0x02, 0x01, 0x02] }), want("cert-unparseable", "forwarded")],
    ["[3] longer than its SEQUENCE", "add-pre-chain", makeCert({ extensionsField: Buffer.concat([Buffer.from([0xa3, 0x7f]), seq(POISON_EXT)]) }), want("cert-unparseable", "forwarded")],
    ["[3] shorter than its SEQUENCE", "add-pre-chain", makeCert({ extensionsField: Buffer.concat([Buffer.from([0xa3, 0x01]), seq(POISON_EXT)]) }), want("cert-unparseable", "forwarded")],
    // ... and treats [3] as absent if that element isn't a SEQUENCE.
    ["[3] containing a NULL", "add-chain", makeCert({ extensionsField: tlv(0xa3, NULL) }), want("cert-unparseable", "forwarded")],
    // It parses the header of whatever follows the public key, and rejects the
    // certificate if it is malformed, or (for the explicitly tagged [3]) if nothing
    // follows it, but Go's crypto/x509 (TesseraCT) only checks its first byte.
    ["malformed header after the public key", "add-chain", makeCert({ afterExtensions: [0x04, 0x85] }), want("forwarded", "cert-unparseable")],
    ["empty element at the end of the TBSCertificate", "add-chain", makeCert({ afterExtensions: NULL }), want("forwarded", "cert-unparseable")],
    ["empty [3]", "add-chain", makeCert({ extensionsField: [0xa3, 0x00, ...NULL] }), want("cert-unparseable", "cert-unparseable")],
  ];
  for (const [name, endpoint, cert, outcomeWanted] of cases) {
    const res = await snippet.fetch(post(`/ct/v1/${endpoint}`, { chain: [b64(cert), ISSUER] }));
    assert.equal(outcome(res), outcomeWanted, name);
  }
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
  const otherCA = b64(makeCert({ subject: Buffer.from("Other CA") }));
  const bigLength = post(ADD, { chain: [CERT] });
  bigLength.headers.set("Content-Length", String(128 * 1024 + 1));
  const cases = {
    "method-not-allowed": new Request("https://log.example.com" + ADD),
    "body-too-large": bigLength,
    "invalid-json": post(ADD, "not json"),
    "chain-missing": post(ADD, "{}"),
    "chain-too-long": post(ADD, { chain: Array(11).fill(CERT) }),
    "entry-not-base64": post(ADD, { chain: ["!!!"] }),
    "entry-too-short": post(ADD, { chain: [b64(der(Array(100).fill(0xab)))] }),
    "entry-not-der": post(ADD, { chain: [b64(Buffer.from([0x31, 0x81, 0xa0, ...Array(160).fill(0xab)]))] }),
    "cert-unparseable": post(ADD, { chain: [b64(der(Array(160).fill(0xab)))] }),
    "poison-invalid": post(ADD, { chain: [NONCRITICAL] }),
    "precert-on-add-chain": post(ADD, { chain: [PRECERT] }),
    "cert-on-add-pre-chain": post(PRE, { chain: [CERT] }),
    "issuer-mismatch": post(ADD, { chain: [CERT, otherCA] }),
  };
  if (ENVIRONMENT === "sunlight") {
    const psc = b64(makeCA([ext(OID_EKU, false, seq(tlv(0x06, ctOid(4))))]));
    cases["psc-not-supported"] = post(PRE, { chain: [PRECERT, psc, ISSUER] });
  }
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

test("rejections of a chain entry identify it in the problem's detail", async () => {
  const ADD = "/ct/v1/add-chain";
  const otherCA = b64(makeCert({ subject: Buffer.from("Other CA") }));
  const cases = [
    [post(ADD, { chain: [CERT, "!!!"] }), "entry-not-base64", "chain[1] is not a string of standard, padded base64"],
    [post(ADD, { chain: [CERT, ISSUER, b64(der(Array(100).fill(0xab)))] }), "entry-too-short", "chain[2] is 102 bytes long, fewer than 128"],
    [post(ADD, { chain: [CERT, b64(Buffer.from([0x31, 0x81, 0xa0, ...Array(160).fill(0xab)]))] }), "entry-not-der", "chain[1] is not a DER SEQUENCE of the declared length"],
    [post(ADD, { chain: [CERT, b64(der(Array(160).fill(0xab)))] }), "cert-unparseable", "chain[1] cannot be parsed as an X.509 certificate"],
    [post(ADD, { chain: [CERT, ISSUER, otherCA] }), "issuer-mismatch", "the issuer of chain[1] does not match the subject of chain[2]"],
  ];
  for (const [req, reason, detail] of cases) {
    const res = await snippet.fetch(req);
    assert.equal(res.headers.get("X-CTreq-Reject"), reason);
    const problem = await res.json();
    assert.equal(problem.detail, detail, reason);
  }
  // Other rejections have no detail.
  const res = await snippet.fetch(post(ADD, "not json"));
  assert.equal((await res.json()).detail, undefined);
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
    "wrong tag": [0x31, 0x81, 0xa0, ...filler],
    "length too large": [0x30, 0x81, 0xa1, ...filler],
    "length too small": [0x30, 0x81, 0x9f, ...filler],
    "indefinite length": [0x30, 0x80, ...filler],
    "oversized length-of-length": [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0xa0, ...filler],
    "length with a leading zero byte": [0x30, 0x82, 0x00, 0xa0, ...filler],
    "long form for a short length": [0x30, 0x81, 0x7f, ...filler.slice(0, 0x7f)],
  };
  for (const [name, bytes] of Object.entries(entries)) {
    const b64 = Buffer.from(bytes).toString("base64");
    for (const chain of [[b64], [CERT, b64]]) {
      const res = await snippet.fetch(post("/ct/v1/add-chain", { chain }));
      assert.equal(res.status, 400, name);
      assert.equal(res.headers.get("X-CTreq-Reject"), "entry-not-der", name);
    }
  }
  assert.equal(forwarded, null);
});

test("non-minimal DER length inside a certificate is rejected", async () => {
  const cert = makeCert();
  const tbs = cert.subarray(4);
  assert.deepEqual([cert[1], tbs[0], tbs[1]], [0x82, 0x30, 0x81], "fixture's TBSCertificate must use a one-byte long-form length");
  // Re-encode the TBSCertificate's length with a leading zero byte.
  const padded = seq(Buffer.from([0x30, 0x82, 0x00, tbs[2]]), tbs.subarray(3));
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(padded)] }));
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("X-CTreq-Reject"), "cert-unparseable");
  assert.equal(forwarded, null);
});

test("extension critical flag must be 0x00 or 0xFF", async () => {
  const flagged = (flag) => b64(makeCert({ extensions: [seq(tlv(0x06, ctOid(3)), tlv(0x01, [flag]), tlv(0x04, [0x05, 0x00]))] }));
  let res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [flagged(0x01), ISSUER] }));
  assert.equal(res.headers.get("X-CTreq-Reject"), "cert-unparseable");
  res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [flagged(0x00), ISSUER] }));
  assert.equal(res.headers.get("X-CTreq-Reject"), "poison-invalid");
  assert.equal(forwarded, null);
  res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [flagged(0xff), ISSUER] }));
  assert.equal(res.status, 200);
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

test("non-POST requests to the endpoints get 405, except OPTIONS for Sunlight", async () => {
  const allow = expected({ tesseract: "POST", sunlight: "OPTIONS, POST", trillian: "POST", common: "OPTIONS, POST" });
  for (const method of ["GET", "PUT", "DELETE", "OPTIONS"]) {
    for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
      forwarded = null;
      const res = await snippet.fetch(new Request("https://log.example.com" + path, { method }));
      if (method === "OPTIONS" && ["sunlight", "common"].includes(ENVIRONMENT)) {
        // Sunlight answers CORS preflight requests itself.
        assert.equal(res.status, 200, method + " " + path);
        assert.equal(forwarded.method, "OPTIONS");
        continue;
      }
      assert.equal(res.status, 405, method + " " + path);
      assert.equal(res.headers.get("Allow"), allow);
      assert.equal(forwarded, null);
    }
  }
});

test("rejections allow any origin, as Sunlight's responses do, if Sunlight may be the origin", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-chain", "not json"));
  assert.equal(res.headers.get("Access-Control-Allow-Origin"), expected({ tesseract: null, sunlight: "*", trillian: null, common: "*" }));
  // Except 405 responses, which Sunlight's router sends without it.
  const wrongMethod = await snippet.fetch(new Request("https://log.example.com/ct/v1/add-chain", { method: "GET" }));
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("Access-Control-Allow-Origin"), null);
});

test("environments differ only as documented", async () => {
  const snippets = Object.fromEntries(await Promise.all(["tesseract", "sunlight", "trillian", "common"].map(async (e) => [e, await loadSnippet(e)])));
  const outcomes = async (makeRequest) =>
    Object.fromEntries(await Promise.all(Object.entries(snippets).map(async ([e, s]) => [e, outcome(await s.fetch(makeRequest()))])));
  const v1Poisoned = b64(makeCert({ version: null, extensions: [POISON_EXT] }));
  const psc = b64(makeCA([ext(OID_EKU, false, seq(tlv(0x06, ctOid(4))))]));
  const cases = [
    [() => new Request("https://log.example.com/ct/v1/add-chain", { method: "OPTIONS" }), { tesseract: "method-not-allowed", sunlight: "forwarded", trillian: "method-not-allowed", common: "forwarded" }],
    [() => post("/ct/v1/add-chain", { chain: [b64(makeCert({ version: [3] }))] }), { tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }],
    [() => post("/ct/v1/add-pre-chain", { chain: [b64(makeCert({ extensions: [POISON_EXT, POISON_EXT] }))] }), { tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }],
    [() => post("/ct/v1/add-chain", { chain: [v1Poisoned] }), { tesseract: "forwarded", sunlight: "precert-on-add-chain", trillian: "precert-on-add-chain", common: "forwarded" }],
    [() => post("/ct/v1/add-pre-chain", { chain: [v1Poisoned] }), { tesseract: "cert-on-add-pre-chain", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }],
    [() => post("/ct/v1/add-pre-chain", { chain: [PRECERT, psc, ISSUER] }), { tesseract: "forwarded", sunlight: "psc-not-supported", trillian: "forwarded", common: "forwarded" }],
    // Rejected the same way by all the origins.
    [() => post("/ct/v1/add-chain", { chain: [PRECERT] }), { tesseract: "precert-on-add-chain", sunlight: "precert-on-add-chain", trillian: "precert-on-add-chain", common: "precert-on-add-chain" }],
    // Rejected by all the origins, but for different reasons: common reports TesseraCT's.
    [() => post("/ct/v1/add-pre-chain", { chain: [b64(makeCert({ extensions: [ext(ctOid(3), false, [0x05, 0x00]), POISON_EXT] }))] }), { tesseract: "cert-unparseable", sunlight: "poison-invalid", trillian: "poison-invalid", common: "cert-unparseable" }],
  ];
  for (const [makeRequest, want] of cases) {
    const req = makeRequest();
    assert.deepEqual(await outcomes(makeRequest), want, `${req.method} ${new URL(req.url).pathname}`);
  }
  await assert.rejects(loadSnippet("ctfe"), /CONFIG.environment must be "sunlight", "tesseract", "trillian", or "common", not "ctfe"/);
});

test("any or no Content-Type is accepted, as the origin does not check it", async () => {
  const body = JSON.stringify({ chain: [CERT, ISSUER] });
  for (const contentType of ["application/json", "Application/JSON; charset=utf-8", "text/plain", "application/x-www-form-urlencoded", null]) {
    const headers = contentType ? { "Content-Type": contentType } : {};
    const req = new Request("https://log.example.com/ct/v1/add-chain", {
      method: "POST",
      headers,
      body: new TextEncoder().encode(body),
    });
    assert.equal(req.headers.get("Content-Type"), contentType);
    forwarded = null;
    const res = await snippet.fetch(req);
    assert.equal(res.status, 200, String(contentType));
    assert.equal(forwarded.body, body, String(contentType));
  }
});

test("oversized Content-Length gets 413 without reading the body", async () => {
  const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
  req.headers.set("Content-Length", String(128 * 1024 + 1));
  const res = await snippet.fetch(req);
  assert.equal(res.status, 413);
  assert.equal(req.bodyUsed, false);
  assert.equal(forwarded, null);
});

// A body sent in chunks, without a Content-Length.
function postStream(path, text, chunkSize = 16 * 1024) {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) return controller.close();
      controller.enqueue(bytes.slice(offset, (offset += chunkSize)));
    },
  });
  const req = new Request("https://log.example.com" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
    duplex: "half",
  });
  streamed.add(req);
  return req;
}

test("oversized body without a Content-Length gets 413", async () => {
  const body = JSON.stringify({ chain: [CERT, ISSUER], pad: "a".repeat(1024 * 1024) });
  const req = postStream("/ct/v1/add-chain", body);
  assert.equal(req.headers.get("Content-Length"), null);
  const res = await snippet.fetch(req);
  assert.equal(res.status, 413);
  assert.equal(res.headers.get("X-CTreq-Reject"), "body-too-large");
  assert.equal(forwarded, null);
});

test("body without a Content-Length at the limit is accepted and forwarded", async () => {
  const json = JSON.stringify({ chain: [CERT, ISSUER] });
  const body = json + " ".repeat(128 * 1024 - json.length);
  const res = await snippet.fetch(postStream("/ct/v1/add-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

const postBytes = (path, bytes) =>
  new Request("https://log.example.com" + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: bytes });

test("forwarded body is byte-identical to the submitted body", async () => {
  const json = new TextEncoder().encode(JSON.stringify({ chain: [CERT, ISSUER], extra: "\u00e9" }));
  // An invalid UTF-8 byte inside a string, which decoding as text would replace.
  const original = new Uint8Array([...json.slice(0, -2), 0xff, ...json.slice(-2)]);
  const res = await snippet.fetch(postBytes("/ct/v1/add-chain", original));
  assert.equal(res.status, 200);
  assert.deepEqual(forwarded.bytes, original);
});

test("body with a UTF-8 byte order mark is invalid JSON, as for the origin", async () => {
  const json = new TextEncoder().encode(JSON.stringify({ chain: [CERT, ISSUER] }));
  const res = await snippet.fetch(postBytes("/ct/v1/add-chain", new Uint8Array([0xef, 0xbb, 0xbf, ...json])));
  assert.equal(res.headers.get("X-CTreq-Reject"), "invalid-json");
  assert.equal(forwarded, null);
});

test("chain key is matched case-insensitively, as by the origin", async () => {
  for (const key of ["Chain", "CHAIN", "cHaIn"]) {
    const body = JSON.stringify({ [key]: [CERT, ISSUER] });
    forwarded = null;
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(res.status, 200, key);
    assert.equal(forwarded.body, body, key);
  }
  forwarded = null;
  // Only ASCII letters are folded: dotless i (U+0131) and a Cyrillic "а" (U+0430) don't match.
  for (const key of ["cha\u0131n", "ch\u0430in"]) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", { [key]: [CERT, ISSUER] }));
    assert.equal(res.headers.get("X-CTreq-Reject"), "chain-missing", key);
  }
  assert.equal(forwarded, null);
});

test("the last chain key is used, whatever its case, as by the origin", async () => {
  const bodies = {
    // The last key's chain is checked: a precertificate, rejected on add-chain.
    [`{"chain":[${JSON.stringify(CERT)},${JSON.stringify(ISSUER)}],"CHAIN":[${JSON.stringify(PRECERT)}]}`]: "precert-on-add-chain",
    [`{"Chain":[${JSON.stringify(PRECERT)}],"chain":[${JSON.stringify(CERT)},${JSON.stringify(ISSUER)}]}`]: "forwarded",
    // A repeated key, separated by one differing in case: the last occurrence counts.
    [`{"chain":[${JSON.stringify(PRECERT)}],"CHAIN":[${JSON.stringify(PRECERT)}],"chain":[${JSON.stringify(CERT)}]}`]: "forwarded",
    [`{"chain":[${JSON.stringify(CERT)}],"CHAIN":[${JSON.stringify(CERT)}],"chain":[${JSON.stringify(PRECERT)}]}`]: "precert-on-add-chain",
    // Keys in nested objects, and strings that merely look like keys, don't count.
    [`{"Chain":[${JSON.stringify(CERT)}],"x":{"chain":[${JSON.stringify(PRECERT)}]},"y":["chain",":"]}`]: "forwarded",
    // Escapes in keys and whitespace before the colon.
    [`{"chain":[${JSON.stringify(CERT)}], "\\u0043HAIN" \n : [${JSON.stringify(PRECERT)}]}`]: "precert-on-add-chain",
    // A null last chain, as Go sees it, is empty.
    [`{"chain":[${JSON.stringify(CERT)}],"Chain":null}`]: "chain-missing",
  };
  for (const [body, want] of Object.entries(bodies)) {
    forwarded = null;
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(outcome(res), want, body.replace(/"[A-Za-z0-9+/=]{100,}"/g, "…"));
    if (want === "forwarded") {
      assert.equal(forwarded.body, body);
    }
  }
});

test("line breaks in base64 chain entries are ignored, as by the origin", async () => {
  const wrap = (s, eol) => s.match(/.{1,64}/g).join(eol) + eol;
  for (const eol of ["\n", "\r\n", "\r"]) {
    const body = JSON.stringify({ chain: [wrap(CERT, eol), wrap(ISSUER, eol)] });
    forwarded = null;
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(res.status, 200, JSON.stringify(eol));
    assert.equal(forwarded.body, body);
  }
  forwarded = null;
  // Other whitespace is still rejected, as Go's base64 decoder does.
  for (const sep of [" ", "\t"]) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [wrap(CERT, sep)] }));
    assert.equal(res.headers.get("X-CTreq-Reject"), "entry-not-base64", JSON.stringify(sep));
  }
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

test("endpoint paths are matched after percent-decoding each segment, as by the origin", async () => {
  // Go's http.ServeMux routes these to the add-chain and add-pre-chain handlers.
  for (const path of ["/2026h1/ct/v1/add%2Dchain", "/ct/v1/%61dd-chain", "/%63t/%76%31/add-chain"]) {
    const res = await snippet.fetch(post(path, { chain: [PRECERT, ISSUER] }));
    assert.equal(res.headers.get("X-CTreq-Reject"), "precert-on-add-chain", path);
  }
  const res = await snippet.fetch(post("/ct/v1/add%2dpre%2Dchain", { chain: [CERT, ISSUER] }));
  assert.equal(res.headers.get("X-CTreq-Reject"), "cert-on-add-pre-chain");
  assert.equal(forwarded, null);
  // Go doesn't route these to either handler: an encoded "/" doesn't separate segments,
  // and invalid percent-encoding is rejected.
  for (const path of ["/ct%2Fv1/add-chain", "/ct/v1%2Fadd-chain", "/ct/v1/add-chain%zz", "/v1/add-chain", "/xct/v1/add-chain"]) {
    forwarded = null;
    const res = await snippet.fetch(post(path, "xyz"));
    assert.equal(res.status, 200, path);
    assert.equal(forwarded.body, "xyz", path);
  }
});

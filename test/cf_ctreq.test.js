import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { tlv, seq, ctOid, OID_EKU, ext, POISON_EXT, makeCert, b64, makeCA, der, CERT, PRECERT, NONCRITICAL, ISSUER, ED25519, ED25519_KEY, p256Key } from "./der.mjs";
import { certificatesIn, rootHashes } from "../tools/roots-hashes.mjs";
import { placeholders, withRoots, embeddedRoots, outputs, minify, build } from "../tools/build.mjs";
import { GOOGLE_MONITOR_LEAF, GOOGLE_MONITOR_INTERMEDIATE, GOOGLE_MONITOR_ROOT } from "./google-monitor.mjs";

// CTREQ_ENVIRONMENT selects CONFIG.environment ("sunlight", "tesseract", "trillian", or "common")
// for the snippet under test; by default, the snippet's own setting is tested. Another
// setting is applied to a copy of the source, so that CONFIG needn't be exported.
const SOURCE = readFileSync(new URL("../src/cf_ctreq.js", import.meta.url), "utf8");
// Every minified snippet: the generic dist/cf_ctreq.min.js, and one for each zone.
const OUTPUTS = outputs(SOURCE).map((output) => ({ ...output, code: readFileSync(new URL(`../${output.file}`, import.meta.url), "utf8") }));
const minifying = process.env.CTREQ_MINIFIED === "1";
const CONFIG_ENVIRONMENT = /^(\s*environment: )"([a-z]*)"/m;
assert.match(SOURCE, CONFIG_ENVIRONMENT, "cf_ctreq.js must set CONFIG.environment to a string literal");
// Each load is a new module (as modules are cached by URL), with its own state.
let loads = 0;
async function loadSource(source) {
  if (minifying) {
    source = await minify(source);
  }
  source += `\n// ${++loads}\n`;
  return (await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"))).default;
}
async function loadSnippet(environment) {
  return loadSource(SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(environment)}`));
}
const ENVIRONMENT = process.env.CTREQ_ENVIRONMENT || SOURCE.match(CONFIG_ENVIRONMENT)[2];
// The loaded module is never modified, so that it is always the local snippet. Tests use
// `snippet`, which the wrappers below may replace.
const localSnippet = process.env.CTREQ_ENVIRONMENT ? await loadSnippet(ENVIRONMENT) : (await import(minifying ? "../dist/cf_ctreq.min.js" : "../src/cf_ctreq.js")).default;
let snippet = localSnippet;
// Returns the expected value for the environment under test.
const expected = (byEnvironment) => {
  assert.ok(Object.hasOwn(byEnvironment, ENVIRONMENT), `no expectation for environment ${ENVIRONMENT}`);
  return byEnvironment[ENVIRONMENT];
};
// The largest body that some origin in the environment accepts by default.
const MAX_BODY = expected({ sunlight: 128 * 1024, tesseract: 512 * 1024, trillian: 512000, common: 512 * 1024 });

// Requests whose body is streamed without a Content-Length (see postStream).
const streamed = new WeakSet();

// With CTREQ_LOG_URL set (e.g. https://ct.example.com/2026h1), requests that the local snippet
// rejects are also sent to that deployed log, which must reject them identically. Anything the
// snippet would forward is skipped, so nothing is ever submitted to the log.
// Tests of requests to other logs than the deployed one use localSnippet instead.
const networkFetch = globalThis.fetch;
if (process.env.CTREQ_LOG_URL) {
  const base = new URL(process.env.CTREQ_LOG_URL);
  let liveTest;
  beforeEach((t) => {
    liveTest = t;
  });
  const local = snippet;
  const live = async (req) => {
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    // Copy the body before the snippet reads it: in Node, a clone can't be read once its
    // twin has been cancelled part-way, as the snippet does with an oversized body.
    const bytes = hasBody ? new Uint8Array(await req.clone().arrayBuffer()) : null;
    const localRes = await local.fetch(req);
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
  snippet = { fetch: live };
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
  const inner = snippet;
  const verbose = async (req) => {
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
    const res = await inner.fetch(req);
    out.push(`=> ${res.status} ${res.headers.get("X-CTreq-Reject") ?? "forwarded"}`);
    pending.push(out.join("\n"));
    return res;
  };
  snippet = { fetch: verbose };
}

// The snippet's only subrequest is to forward a request, which is recorded in forwarded.
let forwarded;
beforeEach(() => {
  forwarded = null;
  globalThis.fetch = async (req) => {
    assert.ok(req instanceof Request, `the snippet fetched ${req}`);
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

const postBytes = (path, bytes) =>
  new Request("https://log.example.com" + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: bytes });

// A CA certificate with the given subject and issuer names.
const ca = (subject, issuer = subject) => b64(makeCert({ subject: Buffer.from(subject), issuer }));
// The DER subject name of makeCert({ subject }), as the snippet compares it.
const nameDer = (cn) => seq(tlv(0x31, seq(tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x0c, Buffer.from(cn))))).toString("latin1");
const NULL = [0x05, 0x00];

// A list of accepted roots, as npm run build makes them, of the given base64 certificates.
const rootsList = (...roots) => rootHashes(roots.map((root) => Buffer.from(root, "base64")));
const LOG_ENVIRONMENTS = /^(\s*logEnvironments: )\[[\s\S]*?\n  \],$/m;
assert.match(SOURCE, LOG_ENVIRONMENTS, "cf_ctreq.js must set CONFIG.logEnvironments to a multi-line array");
const BLOCKED_KEY_NAMES = /^const BLOCKED_KEY_NAMES = new Uint32Array\(\[\n[\s\S]*?\n\]\)\.sort\(\);$/m;
assert.match(SOURCE, BLOCKED_KEY_NAMES, "cf_ctreq.js must define BLOCKED_KEY_NAMES as a multi-line Uint32Array");
// A snippet with the given CONFIG.logEnvironments (as source code), in the given environment,
// and with the given BLOCKED_KEY_NAMES (as a list of hashes, as rootsList() makes them), if any.
const logEnvironmentsSnippet = (logEnvironments, environment = ENVIRONMENT, blocked = undefined) => {
  let source = SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(environment)}`).replace(LOG_ENVIRONMENTS, `$1${logEnvironments},`);
  if (blocked !== undefined) {
    source = source.replace(BLOCKED_KEY_NAMES, `const BLOCKED_KEY_NAMES = new Uint32Array([${blocked.match(/.{8}/g).map((h) => `0x${h}`)}]).sort();`);
  }
  return loadSource(source);
};
// A fresh snippet whose CONFIG.logEnvironments gives each of the given logs (hostnames,
// optionally followed by a path) logEnvironment and a list of the given accepted roots (by
// default, ISSUER, the issuer of all the other fixtures), with environment as the default,
// and with the subject names of the given certificates as BLOCKED_KEY_NAMES, if any. These
// tests are never sent to a deployed log.
const rootsSnippet = (logs = ["log.example.com"], { environment = ENVIRONMENT, logEnvironment = environment, roots = [ISSUER], blocked } = {}) => {
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  return logEnvironmentsSnippet(`[${logs.map((log) => `[/^${escape(log)}\\//, ${JSON.stringify(logEnvironment)}, ${JSON.stringify(rootsList(...roots))}]`).join(", ")}]`, environment, blocked && rootsList(...blocked));
};

// Cloudflare limits a Snippet's CPU time, not its elapsed time, so this returns the least
// CPU time, in ms, that Node's main thread takes for run(prepare(i)) over several runs, so
// that garbage collection and other processes don't decide the result. prepare() isn't timed.
async function fastest(prepare, run, runs = 5) {
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const input = prepare(i);
    const start = process.threadCpuUsage();
    await run(input);
    const { user, system } = process.threadCpuUsage(start);
    best = Math.min(best, (user + system) / 1000);
  }
  return best;
}

describe("Routing and request methods", () => {
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
});

describe("Body size and forwarding", () => {
  test("oversized Content-Length gets 413 without reading the body", async () => {
    const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
    req.headers.set("Content-Length", String(MAX_BODY + 1));
    const res = await snippet.fetch(req);
    assert.equal(res.status, 413);
    assert.equal(req.bodyUsed, false);
    assert.equal(forwarded, null);
  });

  test("Content-Length at the limit is accepted", async () => {
    const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
    req.headers.set("Content-Length", String(MAX_BODY));
    const res = await snippet.fetch(req);
    assert.equal(res.status, 200);
  });

  test("a log-specific environment determines the Content-Length limit", async () => {
    const s = await rootsSnippet(["tiger2027h1.ct.sectigo.com"], { environment: "sunlight", logEnvironment: "trillian" });
    const certs = JSON.stringify({ chain: [CERT, ISSUER] });
    const maxLength = 128 * 1024;
    for (const [url, accepted] of [
      ["https://log.example.com/ct/v1/add-chain", false],
      ["https://tiger2027h1.ct.sectigo.com/ct/v1/add-chain", true],
    ]) {
      const req = new Request(url, { method: "POST", body: certs, headers: { "Content-Length": String(maxLength + 1) } });
      const res = await s.fetch(req);
      assert.equal(outcome(res), accepted ? "forwarded" : "body-too-large");
      assert.equal(req.bodyUsed, accepted);
    }
  });

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
    const body = json + " ".repeat(MAX_BODY - json.length);
    const res = await snippet.fetch(postStream("/ct/v1/add-chain", body));
    assert.equal(res.status, 200);
    assert.equal(forwarded.body, body);
  });

  test("body without a Content-Length one byte over the limit gets 413", async () => {
    const json = JSON.stringify({ chain: [CERT, ISSUER] });
    const res = await snippet.fetch(postStream("/ct/v1/add-chain", json + " ".repeat(MAX_BODY + 1 - json.length)));
    assert.equal(res.status, 413);
    assert.equal(forwarded, null);
  });

  test("CONFIG.maxBodyBytes overrides the origins' limits", async () => {
    const source = SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(ENVIRONMENT)}`).replace(/^(\s*maxBodyBytes: )null,/m, "$11000,");
    assert.notEqual(source, SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(ENVIRONMENT)}`), "CONFIG.maxBodyBytes must be null");
    const limited = await loadSource(source);
    const json = JSON.stringify({ chain: [CERT] });
    const oversized = post("/ct/v1/add-chain", json);
    oversized.headers.set("Content-Length", "1001");
    const rejected = await limited.fetch(oversized);
    assert.equal(rejected.headers.get("X-CTreq-Reject"), "body-too-large");
    assert.equal(oversized.bodyUsed, false);
    assert.equal((await limited.fetch(postStream("/ct/v1/add-chain", json + " ".repeat(1000 - json.length)))).status, 200);
    const res = await limited.fetch(postStream("/ct/v1/add-chain", json + " ".repeat(1001 - json.length)));
    assert.equal(res.headers.get("X-CTreq-Reject"), "body-too-large");
  });

  test("forwarded body is byte-identical to the submitted body", async () => {
    const json = new TextEncoder().encode(JSON.stringify({ chain: [CERT, ISSUER], extra: "\u00e9" }));
    // An invalid UTF-8 byte inside a string, which decoding as text would replace.
    const original = new Uint8Array([...json.slice(0, -2), 0xff, ...json.slice(-2)]);
    const res = await snippet.fetch(postBytes("/ct/v1/add-chain", original));
    assert.equal(res.status, 200);
    assert.deepEqual(forwarded.bytes, original);
  });
});

describe("JSON and chain entries", () => {
  test("malformed requests are rejected", async () => {
    for (const body of ["not json", "{}", '{"chain":[]}', '{"chain":[1]}', '{"chain":["!!!"]}']) {
      const res = await snippet.fetch(post("/ct/v1/add-chain", body));
      assert.equal(res.status, 400, body);
    }
    assert.equal(forwarded, null);
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

  test("chain shape violations are rejected", async () => {
    const SHORT = b64(der(Array(100).fill(0xab)));
    assert.ok(CERT.endsWith("="), "fixture must need base64 padding");
    const bodies = {
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

  test("chains of more than 10 entries are forwarded without being checked", async () => {
    // Rejected with 10 entries, for an entry that isn't base64 and for not leading to a root.
    for (const [chain, reason] of [[[...Array(9).fill(CERT), "!!!"], "entry-not-base64"], [Array(10).fill(b64(makeCert({ issuer: "Unknown CA", subject: Buffer.from("Unknown CA") }))), "root-not-accepted"]]) {
      const s = reason === "root-not-accepted" ? await rootsSnippet() : snippet;
      let res = await s.fetch(post("/ct/v1/add-chain", { chain }));
      assert.equal(outcome(res), reason);
      // But forwarded byte for byte with 11, or many more.
      for (const extra of [[CERT], Array(1000).fill("!!!")]) {
        const body = JSON.stringify({ chain: [...chain, ...extra] });
        forwarded = null;
        res = await s.fetch(post("/ct/v1/add-pre-chain", body));
        assert.equal(outcome(res), "forwarded");
        assert.equal(forwarded.body, body);
      }
    }
  });

  test("maximum chain length and extra top-level fields are accepted", async () => {
    const body = JSON.stringify({ chain: [CERT, ...Array(9).fill(ISSUER)], extra: true });
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(res.status, 200);
    assert.equal(forwarded.body, body);
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

  test("one-byte long-form DER length is accepted", async () => {
    const buf = makeCert({ subject: Buffer.alloc(20, 0x61) });
    assert.equal(buf[1], 0x81);
    const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(buf)] }));
    assert.equal(res.status, 200);
  });
});

describe("X.509 certificate parsing", () => {
  test("certificate without parseable names is rejected in any position", async () => {
    const noNames = b64(seq(seq(tlv(0x02, [1]), tlv(0x04, Array(150).fill(0))), seq(tlv(0x06, [0x2a])), tlv(0x03, [0])));
    for (const chain of [[noNames], [noNames, ISSUER], [CERT, noNames]]) {
      const res = await snippet.fetch(post("/ct/v1/add-chain", { chain }));
      assert.equal(res.status, 400);
      assert.equal(res.headers.get("X-CTreq-Reject"), "cert-unparseable");
    }
    assert.equal(forwarded, null);
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

  test("unknown or malformed certificate versions are only rejected by TesseraCT", async () => {
    // v4, negative, and non-minimally encoded.
    for (const version of [[3], [0xff], [0x00, 0x02]]) {
      const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [b64(makeCert({ version })), ISSUER] }));
      assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }), JSON.stringify(version));
    }
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

  test("duplicate extensions are only rejected by TesseraCT", async () => {
    const duplicated = b64(makeCert({ extensions: [POISON_EXT, POISON_EXT] }));
    const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [duplicated, ISSUER] }));
    assert.equal(outcome(res), expected({ tesseract: "cert-unparseable", sunlight: "forwarded", trillian: "forwarded", common: "forwarded" }));
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

  test("signature algorithms inside and after the TBSCertificate must be identical", async () => {
    const ecdsaSHA384 = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]));
    const withNullParameters = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]), Buffer.from(NULL));
    for (const [name, outerAlgorithm] of [["different algorithm", ecdsaSHA384], ["same algorithm with parameters", withNullParameters], ["not a SEQUENCE", Buffer.from(NULL)]]) {
      for (const [path, chain] of [["/ct/v1/add-chain", [b64(makeCert({ outerAlgorithm })), ISSUER]], ["/ct/v1/add-pre-chain", [b64(makeCert({ extensions: [POISON_EXT], outerAlgorithm })), ISSUER]], ["/ct/v1/add-chain", [CERT, ISSUER, b64(makeCert({ subject: Buffer.from("Test CA"), outerAlgorithm }))]]]) {
        const res = await snippet.fetch(post(path, { chain }));
        assert.equal(outcome(res), "cert-unparseable", `${name} on ${path}`);
      }
    }
    assert.equal(forwarded, null);
  });

  test("Sunlight rejects key and signature algorithms other than RSA and ECDSA", async () => {
    const sunlightOnly = (reason) => expected({ tesseract: "forwarded", sunlight: reason, trillian: "forwarded", common: "forwarded" });
    const rsa = (n) => seq(tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, n]), Buffer.from(NULL));
    const issuer = (options) => b64(makeCert({ subject: Buffer.from("Test CA"), ...options }));
    const cases = [
      ["Ed25519 key", [b64(makeCert({ publicKey: ED25519_KEY })), ISSUER], sunlightOnly("algorithm-unsupported"), "chain[0] has a public key algorithm other than RSA or ECDSA"],
      ["Ed25519 signature on the issuer", [CERT, issuer({ algorithm: ED25519 })], sunlightOnly("algorithm-unsupported"), "chain[1] has a signature algorithm other than RSA or ECDSA"],
      // certificate-transparency-go's x509 reads an empty OID laxly, as no algorithm.
      ["empty key algorithm OID", [b64(makeCert({ publicKey: seq(seq(tlv(0x06, [])), tlv(0x03, [0, 1])) })), ISSUER], sunlightOnly("algorithm-unsupported"), "chain[0] has a public key algorithm other than RSA or ECDSA"],
      ["RSA key and signature", [b64(makeCert({ publicKey: seq(rsa(1), tlv(0x03, [0, 1])), algorithm: rsa(11) })), ISSUER], "forwarded"],
      // RSASSA-PSS is only RSA with parameters that it supports, which aren't checked.
      ["RSASSA-PSS with unsupported parameters", [b64(makeCert({ algorithm: rsa(10) })), ISSUER], "forwarded"],
      ["SHA-1 with RSA (ISO OID)", [b64(makeCert({ algorithm: seq(tlv(0x06, [0x2b, 0x0e, 0x03, 0x02, 0x1d])) })), ISSUER], "forwarded"],
      // It decodes a padded OID as if it were minimally encoded.
      ["padded id-ecPublicKey", [b64(makeCert({ publicKey: p256Key([0x2a, 0x86, 0x48, 0x80, 0xce, 0x3d, 0x02, 0x01]) })), ISSUER], "forwarded"],
      // An algorithm that isn't clearly an OID is left to the origin.
      ["key algorithm that isn't an OID", [b64(makeCert({ publicKey: seq(seq(Buffer.from(NULL)), tlv(0x03, [0, 1])) })), ISSUER], "forwarded"],
    ];
    for (const [name, chain, want, detail] of cases) {
      const res = await snippet.fetch(post("/ct/v1/add-chain", { chain }));
      assert.equal(outcome(res), want, name);
      if (want === "algorithm-unsupported") {
        assert.equal((await res.json()).detail, detail, name);
      }
    }
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
});

describe("Certificate and chain validation", () => {
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
});

describe("Accepted roots", () => {
  test("the accepted roots are only checked for logs that CONFIG.logEnvironments gives a list of them", async () => {
    const s = await logEnvironmentsSnippet(`[
      [/^checked\\.example\\.com\\//, ${JSON.stringify(ENVIRONMENT)}, ${JSON.stringify(rootsList(ISSUER))}],
      [/^placeholder\\.example\\.com\\//, ${JSON.stringify(ENVIRONMENT)}, "https://roots.example.net/accepted-roots.pem"],
      [/^empty\\.example\\.com\\//, ${JSON.stringify(ENVIRONMENT)}, ""],
      [/^null\\.example\\.com\\//, ${JSON.stringify(ENVIRONMENT)}, null],
      [/^omitted\\.example\\.com\\//, ${JSON.stringify(ENVIRONMENT)}],
    ]`);
    const unknownRoot = JSON.stringify({ chain: [b64(makeCert({ issuer: "Unknown CA" }))] });
    // A placeholder that npm run build hasn't replaced isn't checked, and nor are logs that
    // use CONFIG.environment (as no entry matches them).
    for (const log of ["placeholder", "empty", "null", "omitted", "default"]) {
      const res = await s.fetch(new Request(`https://${log}.example.com/ct/v1/add-chain`, { method: "POST", body: unknownRoot }));
      assert.equal(outcome(res), "forwarded", log);
    }
    const res = await s.fetch(new Request("https://checked.example.com/ct/v1/add-chain", { method: "POST", body: unknownRoot }));
    assert.equal(outcome(res), "root-not-accepted");
    for (const roots of ["roots.pem", "1a2b3c4", "1a2b3c4d5", "1A2B3C4D", 42]) {
      await assert.rejects(
        logEnvironmentsSnippet(`[[/^ct\\.example\\.com\\//, "trillian", ${JSON.stringify(roots)}]]`),
        /CONFIG.logEnvironments\[0\]'s accepted roots must be a list from ACCEPTED_ROOTS, "" or null/,
        String(roots),
      );
    }
  });

  test("the chain must lead to an accepted root, whose subject is the issuer of any certificate in it", async () => {
    // leaf <- A <- B, issued by C.
    const leaf = b64(makeCert({ issuer: "A" }));
    const chain = [leaf, ca("A", "B"), ca("B", "C")];
    const roots = { a: ca("A"), b: ca("B"), c: ca("C"), x: ca("X") };
    const s = await logEnvironmentsSnippet(`[${Object.entries(roots).map(([log, root]) => `[/^${log}\\.example\\.com\\//, ${JSON.stringify(ENVIRONMENT)}, ${JSON.stringify(rootsList(root))}]`).join(", ")}]`);
    const check = async (log, chain) => outcome(await s.fetch(new Request(`https://${log}.example.com/ct/v1/add-chain`, { method: "POST", body: JSON.stringify({ chain }) })));
    for (const [log, want] of Object.entries({ a: "forwarded", b: "forwarded", c: "forwarded", x: "root-not-accepted" })) {
      assert.equal(await check(log, chain), want, log);
    }
    assert.equal(await check("b", chain.slice(0, 2)), "forwarded");
    assert.equal(await check("c", chain.slice(0, 2)), "root-not-accepted");
    // A chain that is just a root, whatever its issuer.
    assert.equal(await check("x", [ca("X", "Y")]), "forwarded");
    assert.equal(await check("x", [ca("Y", "X")]), "forwarded");
    assert.equal(await check("x", [ca("Y", "Z")]), "root-not-accepted");
    // Names are compared byte for byte.
    assert.equal(await check("a", [b64(makeCert({ issuer: "a" }))]), "root-not-accepted");

    const res = await s.fetch(new Request("https://x.example.com/ct/v1/add-chain", { method: "POST", body: JSON.stringify({ chain }) }));
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { type: "https://github.com/sectigo/CF_CTreq#root-not-accepted", title: "chain does not lead to a root that this log accepts", status: 400 });
  });

  test("once a certificate's issuer is an accepted root, no more are looked up", async () => {
    const s = await rootsSnippet(undefined, { roots: [ca("A"), ca("B"), ca("C")] });
    const chain = [b64(makeCert({ issuer: "A" })), ca("A", "B"), ca("B", "C")];
    const submit = () => s.fetch(new Request("https://log.example.com/ct/v1/add-chain", { method: "POST", body: JSON.stringify({ chain }) }));
    // The snippet only uses Math.imul to hash names, once per byte, so this counts the
    // bytes of the names that it looks up. A, B and C's names have the same length.
    const imul = Math.imul;
    let bytes = 0;
    Math.imul = (a, b) => (bytes++, imul(a, b));
    let res;
    try {
      res = await submit();
    } finally {
      Math.imul = imul;
    }
    assert.equal(outcome(res), "forwarded");
    // Only A, once per origin in the environment.
    assert.equal(bytes, nameDer("A").length * expected({ sunlight: 1, tesseract: 1, trillian: 1, common: 3 }));
  });

  test("common only rejects a chain that doesn't lead to an accepted root if every origin rejects it", async () => {
    // TesseraCT rejects the version; Sunlight and Trillian accept it, unless it doesn't lead
    // to an accepted root.
    const chain = JSON.stringify({ chain: [b64(makeCert({ version: [3] })), ISSUER] });
    for (const [roots, want] of [[ISSUER, "forwarded"], [ca("Other CA"), "cert-unparseable"]]) {
      const s = await rootsSnippet(undefined, { environment: "common", roots: [roots] });
      assert.equal(outcome(await s.fetch(post("/ct/v1/add-chain", chain))), want);
    }
  });

  test("a chain that needs a certificate with a blocked key is rejected, wherever it needs it", async () => {
    // R is the accepted root, and B's key is blocked.
    const s = await rootsSnippet(undefined, { roots: [ca("R")], blocked: [ca("B")] });
    const submit = async (chain) => {
      const res = await s.fetch(post("/ct/v1/add-chain", { chain }));
      return [outcome(res), outcome(res) === "forwarded" ? undefined : (await res.json()).detail];
    };
    const issuedBy = (issuer) => b64(makeCert({ issuer }));
    // Issued under the blocked key's name, with B cross-signed by R.
    assert.deepEqual(await submit([issuedBy("B"), ca("B", "R")]), ["key-blocked", "the issuer of chain[0] has a blocked key"]);
    assert.deepEqual(await submit([issuedBy("B")]), ["root-not-accepted", undefined]);
    // An intermediate issued under it.
    assert.deepEqual(await submit([issuedBy("I"), ca("I", "B"), ca("B", "R")]), ["key-blocked", "the issuer of chain[1] has a blocked key"]);
    // Not if the chain reaches the root first, so that the rest of it isn't needed.
    assert.deepEqual(await submit([issuedBy("I"), ca("I", "R"), ca("R", "B")]), ["forwarded", undefined]);
    // Nor if another certificate in the chain might lead to the root instead.
    assert.deepEqual(await submit([issuedBy("I"), ca("I", "B"), ca("B", "I"), ca("I", "R")]), ["forwarded", undefined]);
    // Nor if the blocked key's name is also an accepted root's.
    const rootToo = await rootsSnippet(undefined, { roots: [ca("B")], blocked: [ca("B")] });
    assert.equal(outcome(await rootToo.fetch(post("/ct/v1/add-chain", { chain: [issuedBy("B")] }))), "forwarded");
    // Nor for logs without a list of accepted roots, for which it isn't known where the chain
    // ends.
    const unlisted = await logEnvironmentsSnippet("[]", ENVIRONMENT, rootsList(ca("B")));
    assert.equal(outcome(await unlisted.fetch(post("/ct/v1/add-chain", { chain: [issuedBy("B"), ca("B", "R")] }))), "forwarded");
  });

  test("tools/roots-hashes.mjs lists the same roots from a get-roots response or a PEM bundle", () => {
    const roots = [ca("A"), ca("B", "A"), ISSUER, ISSUER];
    const pem = roots.map((root) => `# A comment\n-----BEGIN CERTIFICATE-----\n${root.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`).join("");
    const fromJson = certificatesIn(JSON.stringify({ certificates: roots }));
    assert.deepEqual(certificatesIn(pem), fromJson);
    // Sorted and without duplicates, 8 hex digits per root.
    const hashes = rootHashes(fromJson).match(/.{8}/g);
    assert.equal(hashes.length, 3);
    assert.deepEqual(hashes, [...hashes].sort());
    for (const hash of hashes) assert.match(hash, /^[0-9a-f]{8}$/);
  });

  test("npm run build replaces each placeholder in ACCEPTED_ROOTS with its list", async () => {
    const pem = (name) => `https://raw.githubusercontent.com/sectigo/CTLogs/main/pem/${name}-ca-roots.pem`;
    const names = ["monument", "billboard", "standee", "dumbo", "tigger"];
    assert.deepEqual(placeholders(SOURCE), names.map(pem));
    // Each list has ISSUER, and a root of its own.
    const s = await loadSource(withRoots(SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(ENVIRONMENT)}`), names.map((name) => rootsList(ISSUER, ca(name)))));
    const submit = async (log, issuer) => outcome(await s.fetch(new Request(`https://${log}/ct/v1/add-chain`, { method: "POST", body: JSON.stringify({ chain: [b64(makeCert({ issuer }))] }) })));
    for (const [log, list] of Object.entries({
      "tiger2027h1.ct.sectigo.com": "monument",
      "elephant2026h2.ct.sectigo.com": "monument",
      "monument2027h1.sub.ct.sectigo.com": "monument",
      "statue2028h2.sub.ct.sectigo.com": "monument",
      "billboard.sub.ct.sectigo.com": "billboard",
      "standee.sub.ctlabs.sectigo.com": "standee",
      "dumbo.ctlabs.sectigo.com": "dumbo",
      "tigger2026.ctlabs.sectigo.com": "tigger",
    })) {
      assert.equal(await submit(log, "Test CA"), "forwarded", log);
      for (const name of names) {
        assert.equal(await submit(log, name), name === list ? "forwarded" : "root-not-accepted", `${log} ${name}`);
      }
    }
    // Other logs don't check the roots.
    assert.equal(await submit("log.example.com", "Unknown CA"), "forwarded");
    assert.throws(() => withRoots(SOURCE, []), /expected 5 lists of accepted roots, not 0/);
  });

  test("the minified snippets have the accepted roots of Sectigo's logs in their zones", async () => {
    assert.deepEqual(OUTPUTS.map(({ zone, file }) => [zone, file]), [
      ["", "dist/cf_ctreq.min.js"],
      ["ct.sectigo.com", "dist/cf_ctreq.ct.sectigo.com.min.js"],
      ["ctlabs.sectigo.com", "dist/cf_ctreq.ctlabs.sectigo.com.min.js"],
    ]);
    const google = JSON.stringify({ chain: [GOOGLE_MONITOR_LEAF, GOOGLE_MONITOR_INTERMEDIATE, GOOGLE_MONITOR_ROOT] });
    const unknownRoot = JSON.stringify({ chain: [b64(makeCert({ issuer: "Unknown CA" }))] });
    for (const { zone, file, code } of OUTPUTS) {
      assert.equal(embeddedRoots(code).length, { "": 0, "ct.sectigo.com": 2, "ctlabs.sectigo.com": 3 }[zone], file);
      const s = (await import(`../${file}`)).default;
      const submit = async (log, body) => outcome(await s.fetch(new Request(`https://${log}/ct/v1/add-chain`, { method: "POST", body })));
      // Google's CT log monitoring root is one of the production logs' roots.
      assert.equal(await submit("tiger2027h1.ct.sectigo.com", google), "forwarded", file);
      assert.equal(await submit("tiger2027h1.ct.sectigo.com", unknownRoot), zone === "ct.sectigo.com" ? "root-not-accepted" : "forwarded", file);
      assert.equal(await submit("dumbo.ctlabs.sectigo.com", unknownRoot), zone === "ctlabs.sectigo.com" ? "root-not-accepted" : "forwarded", file);
    }
  });

  test("each zone's snippet has only the logs in that zone, and their lists, and the generic one has none", { skip: !minifying }, async () => {
    const pem = (name) => `https://raw.githubusercontent.com/sectigo/CTLogs/main/pem/${name}-ca-roots.pem`;
    const LOGS = {
      "ct.sectigo.com": { "tiger2027h1.ct.sectigo.com": "monument", "elephant2026h2.ct.sectigo.com": "monument", "monument2027h1.sub.ct.sectigo.com": "monument", "statue2028h2.sub.ct.sectigo.com": "monument", "billboard.sub.ct.sectigo.com": "billboard" },
      "ctlabs.sectigo.com": { "standee.sub.ctlabs.sectigo.com": "standee", "dumbo.ctlabs.sectigo.com": "dumbo", "tigger2026.ctlabs.sectigo.com": "tigger" },
    };
    const source = SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(ENVIRONMENT)}`);
    for (const [zone, logs] of [...Object.entries(LOGS), ["", {}]]) {
      let used;
      // Each list has ISSUER, and a root named after its placeholder's bundle.
      const code = await build(source, zone, async (urls) => {
        used = urls;
        return urls.map((url) => rootsList(ISSUER, ca(url.split("/").at(-1).replace("-ca-roots.pem", ""))));
      });
      assert.deepEqual(used, [...new Set(Object.values(logs))].map(pem), zone);
      const s = (await import("data:text/javascript;base64," + Buffer.from(`${code}\n// ${zone}`).toString("base64"))).default;
      const submit = async (log, issuer) => outcome(await s.fetch(new Request(`https://${log}/ct/v1/add-chain`, { method: "POST", body: JSON.stringify({ chain: [b64(makeCert({ issuer }))] }) })));
      for (const [otherZone, otherLogs] of Object.entries(LOGS)) {
        for (const [log, list] of Object.entries(otherLogs)) {
          // The other zone's logs use CONFIG.environment, without checking the roots.
          assert.equal(await submit(log, list), "forwarded", `${zone}: ${log}`);
          assert.equal(await submit(log, "Unknown CA"), otherZone === zone ? "root-not-accepted" : "forwarded", `${zone}: ${log}`);
        }
      }
    }
  });

  test("hundreds of roots are looked up well within a Snippet's 5 ms limit", async () => {
    // 700 roots, more than any real log accepts.
    const names = Array.from({ length: 700 }, (_, i) => `Root CA ${i} `.padEnd(120, "x"));
    const s = await rootsSnippet(undefined, { roots: names.map((name) => ca(name)) });
    const chain = JSON.stringify({ chain: [b64(makeCert({ issuer: names.at(-1) }))] });
    const request = () => new Request("https://log.example.com/ct/v1/add-chain", { method: "POST", body: chain });
    const submit = async (req) => assert.equal(outcome(await s.fetch(req)), "forwarded");
    await submit(request());
    const time = await fastest(request, submit);
    assert.ok(time < 5, `took ${time.toFixed(1)} ms of CPU time`);
  });
});

describe("Origin environments and rejection responses", () => {
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
      [() => post("/ct/v1/add-chain", { chain: [CERT, b64(makeCert({ subject: Buffer.from("Test CA"), publicKey: ED25519_KEY }))] }), { tesseract: "forwarded", sunlight: "algorithm-unsupported", trillian: "forwarded", common: "forwarded" }],
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

  test("CONFIG.logEnvironments selects the environment by hostname and path", async () => {
    const load = (logEnvironments) => logEnvironmentsSnippet(logEnvironments);
    // OPTIONS is only answered by Sunlight, and an unknown version only rejected by TesseraCT.
    const v4 = b64(makeCert({ version: [3] }));
    const behaviour = async (s, base) => {
      const options = await s.fetch(new Request(`${base}ct/v1/add-chain`, { method: "OPTIONS" }));
      const post = await s.fetch(new Request(`${base}ct/v1/add-chain`, { method: "POST", body: JSON.stringify({ chain: [v4, ISSUER] }) }));
      return [outcome(options), outcome(post)];
    };
    const BEHAVIOUR = {
      trillian: ["method-not-allowed", "forwarded"],
      tesseract: ["method-not-allowed", "cert-unparseable"],
      sunlight: ["forwarded", "forwarded"],
      common: ["forwarded", "forwarded"],
    };
    const check = async (s, cases) => {
      for (const [base, environment] of Object.entries(cases)) {
        assert.deepEqual(await behaviour(s, base), BEHAVIOUR[environment ?? ENVIRONMENT], base);
      }
    };
    // Sectigo's logs, whatever CONFIG.environment is; anything else uses CONFIG.environment.
    // These requests are for many logs, so they're never sent to a deployed one.
    // The source's placeholders (which the minified snippets replace) leave the roots unchecked.
    await check(await loadSnippet(ENVIRONMENT), {
      "https://tiger2027h1.ct.sectigo.com/": "trillian",
      "https://elephant2026h2.ct.sectigo.com/": "trillian",
      "https://dumbo.ctlabs.sectigo.com/": "trillian",
      "https://tigger2026.ctlabs.sectigo.com/": "trillian",
      "https://monument2027h1.sub.ct.sectigo.com/": "tesseract",
      "https://billboard.sub.ct.sectigo.com/": "tesseract",
      "https://standee.sub.ctlabs.sectigo.com/": "tesseract",
      "https://statue2028h2.sub.ct.sectigo.com/": "tesseract",
      "https://monument2027h1.mon.ct.sectigo.com/": null,
      "https://mammoth2026h2.ct.sectigo.com/": null,
      "https://tiger2027h1.ct.sectigo.com.example.com/": null,
      "https://log.example.com/tiger2027h1.ct.sectigo.com/": null,
    });
    // The first matching pattern applies, and can match the path; a g flag doesn't make
    // matches depend on earlier requests.
    const custom = await load('[[/^ct\\.example\\.com\\/2026h2\\//, "sunlight"], [/^ct\\.example\\.com\\//g, "tesseract"]]');
    await check(custom, {
      "https://ct.example.com/2026h2/": "sunlight",
      "https://ct.example.com/2027h1/": "tesseract",
      "https://ct.example.com/2027h2/": "tesseract",
      "https://other.example.com/2026h2/": null,
    });
    await assert.rejects(load('[[/tiger/, "ctfe"]]'), /CONFIG.logEnvironments\[0\]'s environment must be "sunlight", "tesseract", "trillian", or "common", not "ctfe"/);
    await assert.rejects(load('[[/tiger/, "trillian"], ["tuscolo", "sunlight"]]'), /CONFIG.logEnvironments\[1\] must be \[regular expression, environment\] or \[regular expression, environment, accepted roots\]/);
  });

  test("every rejection carries an X-CTreq-Reject reason", async () => {
    const ADD = "/ct/v1/add-chain";
    const PRE = "/ct/v1/add-pre-chain";
    const otherCA = b64(makeCert({ subject: Buffer.from("Other CA") }));
    const bigLength = post(ADD, { chain: [CERT] });
    bigLength.headers.set("Content-Length", String(MAX_BODY + 1));
    const cases = {
      "method-not-allowed": new Request("https://log.example.com" + ADD),
      "body-too-large": bigLength,
      "invalid-json": post(ADD, "not json"),
      "chain-missing": post(ADD, "{}"),
      "entry-not-base64": post(ADD, { chain: ["!!!"] }),
      "entry-too-short": post(ADD, { chain: [b64(der(Array(100).fill(0xab)))] }),
      "entry-not-der": post(ADD, { chain: [b64(Buffer.from([0x31, 0x81, 0xa0, ...Array(160).fill(0xab)]))] }),
      "cert-unparseable": post(ADD, { chain: [b64(der(Array(160).fill(0xab)))] }),
      "poison-invalid": post(ADD, { chain: [NONCRITICAL] }),
      "precert-on-add-chain": post(ADD, { chain: [PRECERT] }),
      "cert-on-add-pre-chain": post(PRE, { chain: [CERT] }),
      "issuer-mismatch": post(ADD, { chain: [CERT, otherCA] }),
      "root-not-accepted": post(ADD, { chain: [b64(makeCert({ issuer: "Unknown CA" }))] }),
      "key-blocked": post(ADD, { chain: [b64(makeCert({ issuer: "Blocked CA" })), ca("Blocked CA", "Test CA")] }),
    };
    if (ENVIRONMENT === "sunlight") {
      const psc = b64(makeCA([ext(OID_EKU, false, seq(tlv(0x06, ctOid(4))))]));
      cases["psc-not-supported"] = post(PRE, { chain: [PRECERT, psc, ISSUER] });
      cases["algorithm-unsupported"] = post(ADD, { chain: [b64(makeCert({ publicKey: ED25519_KEY })), ISSUER] });
    }
    for (const [reason, req] of Object.entries(cases)) {
      const res = await (reason === "root-not-accepted" ? await rootsSnippet() : reason === "key-blocked" ? await rootsSnippet(undefined, { blocked: [ca("Blocked CA")] }) : snippet).fetch(req);
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

  test("rejections allow any origin, as Sunlight's responses do, if Sunlight may be the origin", async () => {
    const res = await snippet.fetch(post("/ct/v1/add-chain", "not json"));
    assert.equal(res.headers.get("Access-Control-Allow-Origin"), expected({ tesseract: null, sunlight: "*", trillian: null, common: "*" }));
    // Except 405 responses, which Sunlight's router sends without it.
    const wrongMethod = await snippet.fetch(new Request("https://log.example.com/ct/v1/add-chain", { method: "GET" }));
    assert.equal(wrongMethod.status, 405);
    assert.equal(wrongMethod.headers.get("Access-Control-Allow-Origin"), null);
  });
});

describe("Snippet size and performance", () => {
  test("the minified snippets fit within a Snippet's 32 KB size limit", () => {
    // Cloudflare limits a Snippet's total package size to 32 KB; 32,000 bytes leaves no doubt.
    for (const { file, code } of OUTPUTS) {
      const size = Buffer.byteLength(code);
      assert.ok(size <= 32000, `${file} is ${size} bytes`);
    }
  });

  test("the minified snippets match the current source and minifier settings", { skip: !minifying }, async () => {
    // With the lists of accepted roots that each has (as they're fetched by npm run build).
    for (const { zone, file, code } of OUTPUTS) {
      assert.equal(code.trimEnd(), await build(SOURCE, zone, async () => embeddedRoots(code)), file);
    }
  });

  test("thousands of extensions are checked well within a Snippet's 5 ms limit", async () => {
    // Distinct OIDs 1.2.<k>, so that the duplicate check has to compare them all.
    const arc = (k) => (k < 128 ? [k] : [0x80 | (k >> 7), k & 0x7f]);
    const many = b64(makeCert({ extensions: Array.from({ length: 7000 }, (_, k) => ext([0x2a, ...arc(k)], false, [])) }));
    const body = JSON.stringify({ chain: [many] });
    // The local snippet, so that the test's wrappers aren't timed; the chain is forwarded,
    // so it would never be sent to a deployed log anyway.
    const submit = async (req) => assert.equal(outcome(await localSnippet.fetch(req)), "forwarded");
    await submit(post("/ct/v1/add-chain", body));
    const time = await fastest(() => post("/ct/v1/add-chain", body), submit);
    // About 1 ms when the duplicate check uses a Set, but ~100 ms when it compared every
    // pair of extensions; generous, so as not to fail on a slow machine.
    assert.ok(time < 40, `took ${time.toFixed(1)} ms of CPU time`);
  });
});

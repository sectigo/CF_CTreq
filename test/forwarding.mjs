// Checks that the snippet deployed in front of a production log can forward a request to the
// log. Cloudflare fails a request with error 1201 ("Snippet tried to continue to origin multiple
// times") if a snippet makes more than one request to the origin, as v1.5.0 did by fetching
// get-roots from the log's own hostname and then forwarding the submission.
//
// It sends the log one of Google's CT log monitoring certificates, with its intermediate and
// root, but with the certificate's signature corrupted: the snippet forwards it, and the log
// rejects it, so nothing is logged. It passes only if the log answers with its own 400.
// Only production logs accept Google's monitoring root, so the log's get-roots is checked first.
//
// Usage: CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com npm run test:forwarding
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { GOOGLE_MONITOR_LEAF, GOOGLE_MONITOR_INTERMEDIATE, GOOGLE_MONITOR_ROOT } from "./google-monitor.mjs";
import { cloudflareError, describeBody } from "./cloudflare.mjs";
import { certificatesIn, rootsHashList } from "../tools/roots-hashes.mjs";

if (!process.env.CTREQ_LOG_URL) {
  console.error("Usage: CTREQ_LOG_URL=<production log URL> npm run test:forwarding, e.g. CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com");
  process.exit(2);
}
const log = new URL(process.env.CTREQ_LOG_URL);
const endpoint = (name) => new URL(log.pathname.replace(/\/$/, "") + "/ct/v1/" + name, log);

test(`a request that the snippet forwards reaches ${log.href}`, async (t) => {
  const roots = await fetch(endpoint("get-roots"));
  assert.equal(roots.status, 200, `get-roots: ${roots.status}`);
  const rootsText = await roots.text();
  assert.ok(JSON.parse(rootsText).certificates.includes(GOOGLE_MONITOR_ROOT), "this log doesn't accept Google's monitoring root (only production logs do), so it can't be used for this test");

  const leaf = Buffer.from(GOOGLE_MONITOR_LEAF, "base64");
  leaf[leaf.length - 1] ^= 0xff;
  const body = JSON.stringify({ chain: [leaf.toString("base64"), GOOGLE_MONITOR_INTERMEDIATE, GOOGLE_MONITOR_ROOT] });

  // The local snippet, with its own configuration for this log and the log's roots (if it
  // has a roots URL), must forward it.
  const rootsList = rootsHashList(certificatesIn(rootsText));
  const source = readFileSync(new URL("../cf_ctreq.js", import.meta.url), "utf8");
  const local = (await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"))).default;
  const networkFetch = globalThis.fetch;
  let forwarded = false;
  globalThis.fetch = async (req) => {
    if (!(req instanceof Request)) return new Response(rootsList);
    forwarded = true;
    return new Response(null, { status: 200 });
  };
  try {
    const res = await local.fetch(new Request(endpoint("add-chain"), { method: "POST", body }));
    assert.ok(forwarded, `the local snippet must forward the request, but it answered ${res.status} ${res.headers.get("X-CTreq-Reject")}`);
  } finally {
    globalThis.fetch = networkFetch;
  }

  const res = await fetch(endpoint("add-chain"), { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "manual" });
  const text = (await res.text()).trim();
  t.diagnostic(`sent to the log: POST ${endpoint("add-chain")} => ${res.status} ${describeBody(text)}`);
  assert.equal(cloudflareError(text), null, `Cloudflare failed the snippet: ${res.status} error ${cloudflareError(text)}`);
  assert.equal(res.headers.get("X-CTreq-Reject"), null, "the deployed snippet rejected a request that the local snippet forwards");
  assert.equal(res.status, 400, `expected the log's own rejection of the corrupted signature, but got ${res.status} ${describeBody(text)}`);
});

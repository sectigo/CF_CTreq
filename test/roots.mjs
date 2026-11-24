// Checks that the snippet deployed in front of the log identified by CTREQ_LOG_URL checks the
// log's accepted roots: it sends the log a chain that leads to no root, which the local snippet
// built for the log's zone (with the log's list of accepted roots) rejects with
// root-not-accepted, and passes only if the deployed snippet rejects it too. Were the snippet
// to forward it, the log would reject it itself (its issuer isn't a root, and its signature is
// invalid), so nothing is logged.
//
// Usage: CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com npm run test:roots
import { test } from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { b64, makeCert } from "./der.mjs";
import { cloudflareError, describeBody } from "./cloudflare.mjs";
import { outputFor } from "../tools/build.mjs";

if (!process.env.CTREQ_LOG_URL) {
  console.error("Usage: CTREQ_LOG_URL=<log URL> npm run test:roots, e.g. CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com");
  process.exit(2);
}
const log = new URL(process.env.CTREQ_LOG_URL);
const addChain = new URL(log.pathname.replace(/\/$/, "") + "/ct/v1/add-chain", log);

test(`a chain that leads to no accepted root is rejected by the snippet in front of ${log.href}`, async (t) => {
  const body = JSON.stringify({ chain: [b64(makeCert({ issuer: "CF_CTreq test: not a root" }))] });

  // The local snippet, as built for deployment in the log's zone, must reject it for this log.
  const source = readFileSync(new URL("../src/cf_ctreq.js", import.meta.url), "utf8");
  const zoned = outputFor(source, log.hostname);
  t.diagnostic(`checked with the local ${zoned.file}`);
  const local = (await import(`../${zoned.file}`)).default;
  const networkFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(null, { status: 200 });
  let reason;
  try {
    reason = (await local.fetch(new Request(addChain, { method: "POST", body }))).headers.get("X-CTreq-Reject");
  } finally {
    globalThis.fetch = networkFetch;
  }
  if (reason !== "root-not-accepted") {
    t.skip(`${zoned.file} has no list of accepted roots for ${log.hostname} (CTREQ_LOG_URL must be the log's own URL)`);
    return;
  }

  const res = await fetch(addChain, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "manual", signal: AbortSignal.timeout(60000) });
  const text = (await res.text()).trim();
  t.diagnostic(`sent to the log: POST ${addChain} => ${res.status} ${res.headers.get("X-CTreq-Reject") ?? describeBody(text)}`);
  assert.equal(cloudflareError(text), null, `Cloudflare failed the snippet: ${res.status} error ${cloudflareError(text)}`);
  assert.equal(res.headers.get("X-CTreq-Reject"), "root-not-accepted", `expected the snippet's rejection, but got ${res.status} ${describeBody(text)}: is the deployed snippet the current one for this zone?`);
  assert.equal(res.status, 400);
});

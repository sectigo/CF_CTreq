// Checks that the snippet deployed in front of the log identified by CTREQ_LOG_URL forwards real
// submissions to the log, rather than failing them (e.g. with Cloudflare error 1201, "Snippet
// tried to continue to origin multiple times") or rejecting them.
//
// It fetches the log's last (up to) 256 entries, and resubmits each one to the same log as the
// add-chain or add-pre-chain request that could have submitted it. The log already has them,
// so it should return their existing SCTs rather than adding entries (though TesseraCT's
// deduplication is best-effort, so a static-ct-api log might record a duplicate, which CT allows).
//
// Usage: CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com npm run test:resubmit
// A static-ct-api log that isn't in Google's log list also needs CTREQ_LOG_MONITORING_URL, e.g.
// CTREQ_LOG_URL=https://standee.sub.ctlabs.sectigo.com CTREQ_LOG_MONITORING_URL=https://standee.mon.ctlabs.sectigo.com
import { test } from "node:test";
import assert from "node:assert/strict";
import { recentEntries } from "./differential/replay.mjs";
import { cloudflareError, describeBody } from "./cloudflare.mjs";

const COUNT = 256;
const CONCURRENCY = 4;

if (!process.env.CTREQ_LOG_URL) {
  console.error("Usage: CTREQ_LOG_URL=<log URL> npm run test:resubmit, e.g. CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com");
  process.exit(2);
}
const log = new URL(process.env.CTREQ_LOG_URL);

test(`the log's last ${COUNT} entries, resubmitted to ${log.href}, reach the log`, async (t) => {
  const entries = await recentEntries(log.href, COUNT, process.env.CTREQ_LOG_MONITORING_URL);
  assert.ok(entries.length > 0, "the log has no entries to resubmit");

  const results = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      while (next < entries.length) {
        const { index, endpoint, body } = entries[next++];
        const url = new URL(log.pathname.replace(/\/$/, "") + `/ct/v1/${endpoint}`, log);
        const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "manual" });
        const text = (await res.text()).trim();
        results.push({ index, endpoint, status: res.status, reject: res.headers.get("X-CTreq-Reject"), cloudflare: cloudflareError(text), text });
      }
    }),
  );

  const counts = {};
  for (const r of results) {
    const outcome = r.cloudflare ? `Cloudflare error ${r.cloudflare}` : r.reject ? `rejected by the snippet (${r.reject})` : `${r.status} from the log`;
    counts[outcome] = (counts[outcome] ?? 0) + 1;
  }
  t.diagnostic(`resubmitted ${results.length} entries (indexes ${Math.min(...results.map((r) => r.index))}-${Math.max(...results.map((r) => r.index))}): ` + Object.entries(counts).map(([o, c]) => `${c} ${o}`).join(", "));
  for (const r of results.filter((r) => !r.cloudflare && !r.reject && r.status !== 200).slice(0, 5)) {
    t.diagnostic(`entry ${r.index} (${r.endpoint}): ${r.status} ${describeBody(r.text)}`);
  }

  const failed = results.filter((r) => r.cloudflare);
  assert.equal(failed.length, 0, `Cloudflare failed the snippet for ${failed.length} of ${results.length} entries, e.g. entry ${failed[0]?.index}: ${failed[0]?.status} error ${failed[0]?.cloudflare}`);
  const errors = results.filter((r) => r.status >= 500);
  assert.equal(errors.length, 0, `${errors.length} of ${results.length} entries got a server error, e.g. entry ${errors[0]?.index}: ${errors[0]?.status} ${describeBody(errors[0]?.text ?? "")}`);
  const rejected = results.filter((r) => r.reject);
  assert.equal(rejected.length, 0, `the snippet rejected ${rejected.length} entries that the log has already accepted, e.g. entry ${rejected[0]?.index} (${rejected[0]?.reject})`);
});

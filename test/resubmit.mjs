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
// CTREQ_RESUBMIT_CONCURRENCY sets how many are resubmitted at a time (default: 32). An entry
// that the log rate-limits (429) is retried after a delay, and if it is rate-limited again,
// fewer are resubmitted at a time.
import { test } from "node:test";
import assert from "node:assert/strict";
import { recentEntries } from "./differential/replay.mjs";
import { cloudflareError, describeBody } from "./cloudflare.mjs";

const COUNT = 256;
// A log can take several seconds to answer each one, but answers many at a time about as fast.
const CONCURRENCY = Number(process.env.CTREQ_RESUBMIT_CONCURRENCY || 32);
// How long to wait for the response to each resubmission.
const TIMEOUT_SECONDS = 60;
// How many times to retry an entry that the log rate-limits, and the longest delay before a retry.
const MAX_RETRIES = 6;
const MAX_DELAY_SECONDS = 60;

if (!process.env.CTREQ_LOG_URL) {
  console.error("Usage: CTREQ_LOG_URL=<log URL> npm run test:resubmit, e.g. CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com");
  process.exit(2);
}
if (!(Number.isInteger(CONCURRENCY) && CONCURRENCY > 0)) {
  console.error(`CTREQ_RESUBMIT_CONCURRENCY must be a positive integer, not ${process.env.CTREQ_RESUBMIT_CONCURRENCY}`);
  process.exit(2);
}
const log = new URL(process.env.CTREQ_LOG_URL);

test(`the log's last ${COUNT} entries, resubmitted to ${log.href}, reach the log`, async (t) => {
  const entries = await recentEntries(log.href, COUNT, process.env.CTREQ_LOG_MONITORING_URL);
  assert.ok(entries.length > 0, "the log has no entries to resubmit");

  // A log may take several seconds to answer each resubmission, so progress is reported as
  // it goes (test diagnostics are only shown at the end).
  const start = Date.now();
  const elapsed = () => `${Math.round((Date.now() - start) / 1000)} s`;
  console.error(`Resubmitting ${entries.length} entries to ${log.href}, ${CONCURRENCY} at a time...`);
  const results = [];
  let next = 0;
  // Only the first `concurrency` workers take new entries. It is halved when an entry is
  // rate-limited again after a delay, but at most once per delay, so that a burst of 429s
  // from the requests already in flight only counts once.
  let concurrency = CONCURRENCY;
  let reducedAt = 0;
  let retries = 0;
  const submit = async (url, body) => {
    try {
      const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_SECONDS * 1000) });
      const text = (await res.text()).trim();
      return { status: res.status, retryAfter: res.headers.get("Retry-After"), reject: res.headers.get("X-CTreq-Reject"), cloudflare: cloudflareError(text), text };
    } catch (err) {
      return { error: err.name === "TimeoutError" ? `no response within ${TIMEOUT_SECONDS} s` : err.message };
    }
  };
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async (_, worker) => {
      while (worker < concurrency && next < entries.length) {
        const { index, endpoint, body } = entries[next++];
        const url = new URL(log.pathname.replace(/\/$/, "") + `/ct/v1/${endpoint}`, log);
        let result = await submit(url, body);
        for (let attempt = 0; result.status === 429 && attempt < MAX_RETRIES; attempt++) {
          const delay = retryDelay(result.retryAfter, attempt);
          if (attempt > 0 && concurrency > 1 && Date.now() - reducedAt >= Math.max(delay, 1000)) {
            concurrency = Math.max(1, Math.floor(concurrency / 2));
            reducedAt = Date.now();
            console.error(`  still rate-limited after ${elapsed()}: now ${concurrency} at a time`);
          }
          retries++;
          await new Promise((resolve) => setTimeout(resolve, delay));
          result = await submit(url, body);
        }
        results.push({ index, endpoint, ...result });
        if (results.length % 16 === 0 || results.length === entries.length) {
          console.error(`  ${results.length}/${entries.length} in ${elapsed()}`);
        }
      }
    }),
  );

  const counts = {};
  for (const r of results) {
    const outcome = r.error ? r.error : r.cloudflare ? `Cloudflare error ${r.cloudflare}` : r.reject ? `rejected by the snippet (${r.reject})` : `${r.status} from the log`;
    counts[outcome] = (counts[outcome] ?? 0) + 1;
  }
  t.diagnostic(`resubmitted ${results.length} entries (indexes ${Math.min(...results.map((r) => r.index))}-${Math.max(...results.map((r) => r.index))}) in ${elapsed()}, with ${retries} retries after 429s, finishing ${concurrency} at a time: ` + Object.entries(counts).map(([o, c]) => `${c} ${o}`).join(", "));
  for (const r of results.filter((r) => !r.error && !r.cloudflare && !r.reject && r.status !== 200).slice(0, 5)) {
    t.diagnostic(`entry ${r.index} (${r.endpoint}): ${r.status} ${describeBody(r.text)}`);
  }

  const unanswered = results.filter((r) => r.error);
  assert.equal(unanswered.length, 0, `${unanswered.length} of ${results.length} entries got no response, e.g. entry ${unanswered[0]?.index}: ${unanswered[0]?.error}`);
  const limited = results.filter((r) => r.status === 429);
  assert.equal(limited.length, 0, `the log was still rate-limiting ${limited.length} of ${results.length} entries after ${MAX_RETRIES} retries; try a lower CTREQ_RESUBMIT_CONCURRENCY`);
  const failed = results.filter((r) => r.cloudflare);
  assert.equal(failed.length, 0, `Cloudflare failed the snippet for ${failed.length} of ${results.length} entries, e.g. entry ${failed[0]?.index}: ${failed[0]?.status} error ${failed[0]?.cloudflare}`);
  const errors = results.filter((r) => r.status >= 500);
  assert.equal(errors.length, 0, `${errors.length} of ${results.length} entries got a server error, e.g. entry ${errors[0]?.index}: ${errors[0]?.status} ${describeBody(errors[0]?.text ?? "")}`);
  const rejected = results.filter((r) => r.reject);
  assert.equal(rejected.length, 0, `the snippet rejected ${rejected.length} entries that the log has already accepted, e.g. entry ${rejected[0]?.index} (${rejected[0]?.reject})`);
});

// Returns the delay in milliseconds before retrying a rate-limited request: the log's
// Retry-After (in seconds, or an HTTP date), if any, else 1 s doubled for each earlier retry,
// with up to 50% added at random so that concurrent retries are spread out; at most
// MAX_DELAY_SECONDS.
function retryDelay(retryAfter, attempt) {
  let seconds = Number(retryAfter);
  if (retryAfter === null || retryAfter.trim() === "" || !Number.isFinite(seconds)) {
    const date = retryAfter === null ? NaN : Date.parse(retryAfter);
    seconds = Number.isNaN(date) ? 2 ** attempt * (1 + Math.random() / 2) : (date - Date.now()) / 1000;
  }
  return Math.min(Math.max(seconds, 0), MAX_DELAY_SECONDS) * 1000;
}

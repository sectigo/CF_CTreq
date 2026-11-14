// Fetches recent real entries from the CT logs in Google's log list (RFC 6962 logs with
// get-entries, and static-ct-api logs with data tiles and issuers), and rebuilds the
// add-chain or add-pre-chain request that each one's submitter could have sent: the
// certificate or precertificate followed by its chain, as the log recorded them.
//
// The differential runner uses these with --replay. Run on its own, it writes them as
// JSON lines ({"id", "endpoint", "body"}) to standard output:
//
//   node test/differential/replay.mjs > corpus.jsonl
//
// CTREQ_REPLAY_ENTRIES sets the number of entries per log (default 256), and
// CTREQ_REPLAY_LOGS limits the logs to those whose descriptions contain one of its
// comma-separated, case-insensitive substrings (e.g. "argon,tuscolo").

const LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const STATES = ["usable", "qualified"];
const CONCURRENCY = 8;

const realFetch = globalThis.fetch;

async function get(url, as = "json") {
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await realFetch(url, { headers: { "User-Agent": "CF_CTreq replay test (https://github.com/sectigo/CF_CTreq)" }, signal: AbortSignal.timeout(60000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return as === "json" ? await res.json() : as === "text" ? await res.text() : new Uint8Array(await res.arrayBuffer());
    } catch (err) {
      if (attempt === 3) throw new Error(`${url}: ${err.message}`);
      await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
    }
  }
}

// A reader for the TLS presentation language's big-endian integers and vectors.
class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }
  uint(n) {
    if (this.pos + n > this.bytes.length) throw new Error("truncated");
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + this.bytes[this.pos++];
    return v;
  }
  bytesOf(n) {
    if (this.pos + n > this.bytes.length) throw new Error("truncated");
    return this.bytes.subarray(this.pos, (this.pos += n));
  }
  vector(lengthBytes) {
    return this.bytesOf(this.uint(lengthBytes));
  }
  vectors(lengthBytes, itemLengthBytes) {
    const r = new Reader(this.vector(lengthBytes));
    const items = [];
    while (r.pos < r.bytes.length) items.push(r.vector(itemLengthBytes));
    return items;
  }
}

const X509_ENTRY = 0;
const PRECERT_ENTRY = 1;

// Reads a TimestampedEntry, returning its type and (for an x509_entry) its certificate.
function readTimestampedEntry(r) {
  r.uint(8);
  const type = r.uint(2);
  let cert = null;
  if (type === X509_ENTRY) cert = r.vector(3);
  else if (type === PRECERT_ENTRY) r.bytesOf(32), r.vector(3);
  else throw new Error(`unknown entry type ${type}`);
  r.vector(2);
  return { type, cert };
}

const request = (type, certs) => ({
  endpoint: type === X509_ENTRY ? "add-chain" : "add-pre-chain",
  body: JSON.stringify({ chain: certs.map((cert) => Buffer.from(cert).toString("base64")) }),
});

// RFC 6962 logs: the last `count` entries, from get-entries (which may return fewer
// entries than asked for, or none if the tree head is ahead of the replica serving
// them, in which case it tries earlier entries).
async function rfc6962Entries(url, count) {
  let { tree_size: size } = await get(`${url}ct/v1/get-sth`);
  const entries = [];
  for (let start = Math.max(0, size - count), retries = 3; start < size; ) {
    const res = await get(`${url}ct/v1/get-entries?start=${start}&end=${size - 1}`);
    if (!res.entries?.length) {
      if (entries.length) break;
      if (!retries-- || !start) throw new Error("get-entries returned no entries");
      (size = start), (start = Math.max(0, start - count));
      continue;
    }
    for (const { leaf_input, extra_data } of res.entries) {
      const leaf = new Reader(Buffer.from(leaf_input, "base64"));
      leaf.uint(2); // MerkleTreeLeaf version and leaf type
      const { type, cert } = readTimestampedEntry(leaf);
      const extra = new Reader(Buffer.from(extra_data, "base64"));
      const certs = [cert ?? extra.vector(3), ...extra.vectors(3, 3)];
      entries.push({ index: start, ...request(type, certs) });
      start++;
    }
  }
  return entries;
}

// Static CT API logs: the last full data tiles covering `count` entries (or the partial
// tile, if the log has fewer than 256 entries), with the issuers they refer to.
const tilePath = (n) => {
  const parts = [];
  do parts.unshift(String(n % 1000).padStart(3, "0")), (n = Math.floor(n / 1000));
  while (n > 0);
  return parts.map((p, i) => (i < parts.length - 1 ? "x" + p : p)).join("/");
};

async function staticEntries(url, count) {
  const size = Number((await get(`${url}checkpoint`, "text")).split("\n")[1]);
  const full = Math.floor(size / 256);
  const tiles = full ? Array.from({ length: Math.min(full, Math.ceil(count / 256)) }, (_, i) => [full - 1 - i, ""]) : size ? [[0, `.p/${size}`]] : [];
  const issuers = new Map();
  const issuer = (fingerprint) => {
    const hex = Buffer.from(fingerprint).toString("hex");
    if (!issuers.has(hex)) issuers.set(hex, get(`${url}issuer/${hex}`, "bytes"));
    return issuers.get(hex);
  };
  const entries = [];
  for (const [n, partial] of tiles.reverse()) {
    const r = new Reader(await get(`${url}tile/data/${tilePath(n)}${partial}`, "bytes"));
    for (let index = n * 256; r.pos < r.bytes.length; index++) {
      const { type, cert } = readTimestampedEntry(r);
      const leaf = cert ?? r.vector(3);
      const chain = r.vector(2);
      const fingerprints = Array.from({ length: chain.length / 32 }, (_, i) => chain.subarray(32 * i, 32 * i + 32));
      entries.push({ index, type, leaf, fingerprints });
    }
  }
  return Promise.all(
    entries.slice(-count).map(async ({ index, type, leaf, fingerprints }) => ({ index, ...request(type, [leaf, ...(await Promise.all(fingerprints.map(issuer)))]) })),
  );
}

async function pool(items, worker) {
  const results = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      while (next < items.length) {
        const i = next++;
        results[i] = await worker(items[i]);
      }
    }),
  );
  return results;
}

// Returns the requests ({id, endpoint, body}), and the logs that couldn't be read.
export async function replay({ entries = Number(process.env.CTREQ_REPLAY_ENTRIES || 256), logs: filter = process.env.CTREQ_REPLAY_LOGS, log = console.error } = {}) {
  const list = await get(LOG_LIST);
  const patterns = filter ? filter.toLowerCase().split(",").map((s) => s.trim()).filter(Boolean) : null;
  const logs = list.operators.flatMap((op) => [
    ...(op.logs ?? []).map((l) => ({ name: l.description, url: l.url, read: rfc6962Entries, state: l.state })),
    ...(op.tiled_logs ?? []).map((l) => ({ name: l.description, url: l.monitoring_url, read: staticEntries, state: l.state })),
  ]).filter((l) => STATES.some((s) => l.state?.[s]) && (!patterns || patterns.some((p) => l.name.toLowerCase().includes(p))));
  const failed = [];
  const results = await pool(logs, async ({ name, url, read }) => {
    try {
      const got = await read(url.endsWith("/") ? url : url + "/", entries);
      log(`${name}: ${got.length} entries`);
      return got.map(({ index, endpoint, body }) => ({ id: `${name} #${index}`, endpoint, body }));
    } catch (err) {
      log(`${name}: failed: ${err.message}`);
      failed.push({ name, error: err.message });
      return [];
    }
  });
  return { items: results.flat(), logs: logs.length, failed };
}

// Returns the requests ({index, endpoint, body}) for the last `count` entries of the log whose
// submission URL is `url`: a static-ct-api log is read from `monitoringUrl` or else from its
// monitoring URL in the log list, and any other log is read as an RFC 6962 log at `url`.
export async function recentEntries(url, count, monitoringUrl) {
  const slash = (u) => (u.endsWith("/") ? u : u + "/");
  if (monitoringUrl) return staticEntries(slash(monitoringUrl), count);
  const list = await get(LOG_LIST);
  const tiled = list.operators.flatMap((op) => op.tiled_logs ?? []).find((l) => slash(l.submission_url) === slash(url));
  return tiled ? staticEntries(slash(tiled.monitoring_url), count) : rfc6962Entries(slash(url), count);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { items, failed } = await replay();
  for (const item of items) process.stdout.write(JSON.stringify(item) + "\n");
  if (failed.length) process.exitCode = 1;
}

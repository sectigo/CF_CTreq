// Generates BLOCKED_KEY_NAMES in src/cf_ctreq.js: the subject names of the CA certificates
// whose keys TesseraCT, Sunlight and Trillian block by default. It reads their default lists
// of blocked keys (defaultBlockedSPKIs, the SHA-256 hashes of SubjectPublicKeyInfos) from
// their main branches, finds every certificate with each key in crt.sh, and checks that every
// certificate with each of those names has a blocked key (so that a name can stand for its
// key), before writing the names' hashes into src/cf_ctreq.js.
//
// Usage: npm run blocked-keys
// CRTSH_URL selects another crt.sh instance (default: https://crt.sh/).
import { readFileSync, writeFileSync } from "node:fs";
import { X509Certificate, createHash } from "node:crypto";
import { nameHash, subjectName } from "./roots-hashes.mjs";

const UPSTREAM = [
  "https://raw.githubusercontent.com/transparency-dev/tesseract/main/ctlog.go",
  "https://raw.githubusercontent.com/FiloSottile/sunlight/main/cmd/sunlight/sunlight.go",
  "https://raw.githubusercontent.com/google/certificate-transparency-go/master/trillian/ctfe/instance.go",
];
const CRTSH = new URL(process.env.CRTSH_URL || "https://crt.sh/");
const SOURCE = new URL("../src/cf_ctreq.js", import.meta.url);
const BLOCK = /^const BLOCKED_KEY_NAMES = new Uint32Array\(\[\n[\s\S]*?\n\]\)\.sort\(\);$/m;

async function get(url, attempts = 5) {
  for (let i = 1; ; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(60000) });
      if (res.ok) return await res.text();
      if (i >= attempts) throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      if (i >= attempts) throw new Error(`${url}: ${err.message}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 2000 * i));
  }
}
const crtsh = async (params) => JSON.parse(await get(new URL(`?${new URLSearchParams({ ...params, output: "json" })}`, CRTSH)));
const certificate = async (id) => new X509Certificate(await get(new URL(`?d=${id}`, CRTSH)));
const spkiHash = (cert) => createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("hex");

// The upstream projects' default lists, which must all be the same.
const lists = await Promise.all(UPSTREAM.map(async (url) => {
  const list = (await get(url)).match(/defaultBlockedSPKIs = \[\]string\{([^}]*)\}/)?.[1];
  if (list === undefined) throw new Error(`${url}: no defaultBlockedSPKIs`);
  return [...list.matchAll(/"([0-9a-f]{64})"/g)].map((m) => m[1]).sort();
}));
if (lists.some((list) => list.join() !== lists[0].join())) {
  throw new Error(`the upstream projects' defaultBlockedSPKIs differ: ${JSON.stringify(lists)}`);
}
const blocked = new Set(lists[0]);

// Every name with a blocked key, by its DER encoding.
const names = new Map();
for (const spki of blocked) {
  const entries = await crtsh({ spkisha256: spki });
  if (!entries.length) throw new Error(`crt.sh has no certificate with SPKI ${spki}`);
  for (const id of new Set(entries.map((e) => e.id))) {
    const cert = await certificate(id);
    if (spkiHash(cert) !== spki) throw new Error(`crt.sh certificate ${id} doesn't have SPKI ${spki}`);
    const name = Buffer.from(subjectName(cert.raw)).toString("hex");
    names.set(name, { subject: cert.subject.split("\n").join(", "), commonName: cert.subject.match(/^CN=(.*)$/m)?.[1] });
  }
}
// Every certificate with each name must have a blocked key.
for (const [name, { subject, commonName }] of names) {
  if (commonName === undefined) throw new Error(`${subject} has no common name to look it up by`);
  for (const id of new Set((await crtsh({ CN: commonName })).map((e) => e.id))) {
    const cert = await certificate(id);
    if (Buffer.from(subjectName(cert.raw)).toString("hex") === name && !blocked.has(spkiHash(cert))) {
      throw new Error(`crt.sh certificate ${id} has the name ${subject}, but not a blocked key, so names can't stand for blocked keys`);
    }
  }
}

const hashes = [...names].map(([name, { subject }]) => ({ subject, hash: nameHash(Buffer.from(name, "hex")) })).sort((a, b) => a.hash - b.hash);
if (new Set(hashes.map((n) => n.hash)).size !== hashes.length) {
  throw new Error("two of the names have the same hash");
}
const block = `const BLOCKED_KEY_NAMES = new Uint32Array([\n${hashes.map((n) => `  0x${n.hash.toString(16).padStart(8, "0")}, // ${n.subject}`).join("\n")}\n]).sort();`;
const source = readFileSync(SOURCE, "utf8");
if (!BLOCK.test(source)) throw new Error("src/cf_ctreq.js must define BLOCKED_KEY_NAMES as a multi-line Uint32Array");
writeFileSync(SOURCE, source.replace(BLOCK, block));
console.log(`${blocked.size} blocked keys, with ${names.size} names:\n${block}`);

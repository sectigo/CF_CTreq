// Builds the minified snippets from src/cf_ctreq.js, in dist/: cf_ctreq.<zone>.min.js for each
// Cloudflare zone that it names (see ZONE), with only that zone's logs, and the generic
// cf_ctreq.min.js, with no zone's. In each, each placeholder in ACCEPTED_ROOTS that is still used (the URL of a
// bundle of PEM certificates, or of a log's get-roots endpoint) is replaced by the list of
// those roots' hashes, and the result is minified with terser.config.json's settings.
//
// Usage: npm run build [-- --offline]
// --offline reuses the lists in the current minified snippets rather than fetching them,
// e.g. to rebuild them after changing only the code.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { certificatesIn, rootHashes } from "./roots-hashes.mjs";

const ACCEPTED_ROOTS = /^const ACCEPTED_ROOTS = \{\n[\s\S]*?\n\};$/m;
const PLACEHOLDER = /"(https?:\/\/[^"]+)"/g;
const ZONE = /^const ZONE = null;$/m;
// A list in a minified snippet (which has no other strings of hex digits).
const LIST = /"((?:[0-9a-f]{8})+)"/g;

// Returns the placeholder URLs in ACCEPTED_ROOTS, in order.
export function placeholders(source) {
  const block = source.match(ACCEPTED_ROOTS)?.[0];
  if (block === undefined) throw new Error("cf_ctreq.js must define ACCEPTED_ROOTS");
  return [...block.matchAll(PLACEHOLDER)].map((m) => m[1]);
}

// Returns the source with its placeholders replaced, in order, by the given lists.
export function withRoots(source, lists) {
  if (lists.length !== placeholders(source).length) throw new Error(`expected ${placeholders(source).length} lists of accepted roots, not ${lists.length}`);
  let i = 0;
  return source.replace(ACCEPTED_ROOTS, (block) => block.replace(PLACEHOLDER, () => JSON.stringify(lists[i++])));
}

// Returns the minified snippets to build: { zone, file }, zone being "" for the generic
// snippet, and file the snippet's path relative to the repository's root.
export function outputs(source) {
  if (!ZONE.test(source)) throw new Error("cf_ctreq.js must set ZONE to null");
  const zones = new Set([...source.matchAll(/\bZONE === "([^"]+)"/g)].map((m) => m[1]));
  return [{ zone: "", file: "dist/cf_ctreq.min.js" }, ...[...zones].map((zone) => ({ zone, file: `dist/cf_ctreq.${zone}.min.js` }))];
}

// Returns the minified snippet ({ zone, file }) to deploy for a log's hostname: its zone's,
// or else the generic one.
export const outputFor = (source, hostname) => outputs(source).filter(({ zone }) => zone === "" || hostname.endsWith(`.${zone}`)).at(-1);

// Returns the lists in a minified snippet, in order.
export const embeddedRoots = (minified) => [...minified.matchAll(LIST)].map((m) => m[1]);

export async function minify(source) {
  const { minify: terserMinify } = await import("terser");
  const options = JSON.parse(readFileSync(new URL("../terser.config.json", import.meta.url), "utf8"));
  return (await terserMinify(source, options)).code;
}

// Returns the minified snippet for a zone (see ZONE), with the lists that
// listsFor(urls) returns for the placeholders that it still uses. They must be in the same
// order in it as in ACCEPTED_ROOTS (wherever the minifier puts them), so that it can be
// rebuilt with them (with --offline).
export async function build(source, zone, listsFor) {
  const zoned = source.replace(ZONE, `const ZONE = ${JSON.stringify(zone)};`);
  const urls = placeholders(zoned);
  const probe = await minify(zoned);
  const used = urls.filter((url) => probe.includes(JSON.stringify(url)));
  const lists = await listsFor(used);
  if (lists.length !== used.length) throw new Error(`expected ${used.length} lists of accepted roots, not ${lists.length}`);
  const minified = await minify(withRoots(zoned, urls.map((url) => (used.includes(url) ? lists[used.indexOf(url)] : ""))));
  if (embeddedRoots(minified).join() !== lists.join()) {
    throw new Error("the minified lists of accepted roots aren't each included once, in the order of ACCEPTED_ROOTS");
  }
  return minified;
}

// Returns the list of the roots at a placeholder URL.
async function fetchRoots(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const certs = certificatesIn(await res.text());
  if (!certs.length) throw new Error(`${url}: no certificates found`);
  return rootHashes(certs);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const source = readFileSync(new URL("../src/cf_ctreq.js", import.meta.url), "utf8");
  const offline = process.argv.includes("--offline");
  const fetched = new Map();
  mkdirSync(new URL("../dist/", import.meta.url), { recursive: true });
  for (const { zone, file } of outputs(source)) {
    const path = new URL(`../${file}`, import.meta.url);
    const minified = await build(source, zone, async (urls) => {
      if (offline) {
        const lists = embeddedRoots(readFileSync(path, "utf8"));
        if (lists.length !== urls.length) throw new Error(`${file} has ${lists.length} lists of accepted roots, not ${urls.length}: run npm run build without --offline`);
        return lists;
      }
      for (const url of urls) if (!fetched.has(url)) fetched.set(url, fetchRoots(url));
      return Promise.all(urls.map((url) => fetched.get(url)));
    });
    writeFileSync(path, minified + "\n");
    const counts = embeddedRoots(minified).map((list) => list.length / 8);
    console.error(`${file}: ${Buffer.byteLength(minified) + 1} bytes, ${counts.length ? `${counts.join(" + ")} roots` : "no roots"}`);
  }
}

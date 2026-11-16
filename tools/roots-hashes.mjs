// Generates the list of a log's accepted roots that a roots URL in CONFIG.logEnvironments
// serves (see ROOTS_HEADER in cf_ctreq.js): the hashes of the roots' subject names, each
// followed by the subject name, for people to read.
//
// Usage: npm run roots-hashes -- <source> > roots.txt
// where <source> is the URL of a log's get-roots endpoint, or a file containing a get-roots
// response ({"certificates": [...]}) or a bundle of PEM certificates.
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";

export const ROOTS_HEADER = "CF_CTreq Accepted Roots v1";

// Returns the DER certificates in a get-roots response or a bundle of PEM certificates.
export function certificatesIn(text) {
  if (text.trimStart().startsWith("{")) {
    return JSON.parse(text).certificates.map((cert) => Buffer.from(cert, "base64"));
  }
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
}

// Returns the 32-bit FNV-1a hash of a DER certificate's subject name (including its tag and
// length), as cf_ctreq.js's nameHash() hashes the names in a chain.
export function subjectHash(der) {
  const tlv = (i) => {
    let length = der[i + 1];
    let offset = i + 2;
    if (length & 0x80) {
      const n = length & 0x7f;
      length = 0;
      for (let j = 0; j < n; j++) length = length * 256 + der[offset++];
    }
    if (offset + length > der.length) throw new Error("truncated certificate");
    return { tag: der[i], start: i, offset, end: offset + length };
  };
  const tbs = tlv(tlv(0).offset);
  let i = tbs.offset;
  if (der[i] === 0xa0) i = tlv(i).end; // version
  // serialNumber, signature, issuer, validity, subject.
  let field;
  for (const tag of [0x02, 0x30, 0x30, 0x30, 0x30]) {
    field = tlv(i);
    if (field.tag !== tag) throw new Error("not a certificate");
    i = field.end;
  }
  let h = 0x811c9dc5;
  for (let j = field.start; j < field.end; j++) h = Math.imul(h ^ der[j], 0x01000193);
  return h >>> 0;
}

// Returns the list for the given DER certificates, sorted by hash, with any comment lines.
export function rootsHashList(certs, comments = []) {
  const lines = certs.map((der) => {
    let name;
    try {
      name = new X509Certificate(der).subject.split("\n").join(", ");
    } catch {
      name = "(unreadable subject)";
    }
    return `${subjectHash(der).toString(16).padStart(8, "0")}  ${name}`;
  });
  return [ROOTS_HEADER, ...comments.map((c) => `# ${c}`), ...[...new Set(lines)].sort()].join("\n") + "\n";
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [source] = process.argv.slice(2);
  if (!source) {
    console.error("Usage: npm run roots-hashes -- <get-roots URL, or get-roots response or PEM bundle file> > roots.txt");
    process.exit(2);
  }
  let text;
  if (/^https?:\/\//.test(source)) {
    const res = await fetch(source);
    if (!res.ok) throw new Error(`${source}: HTTP ${res.status}`);
    text = await res.text();
  } else {
    text = readFileSync(source, "utf8");
  }
  const certs = certificatesIn(text);
  if (!certs.length) throw new Error(`${source}: no certificates found`);
  process.stdout.write(rootsHashList(certs, [`${certs.length} roots, from ${source}`]));
}

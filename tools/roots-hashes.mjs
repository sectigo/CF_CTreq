// Hashes lists of names for cf_ctreq.js: accepted roots (see ACCEPTED_ROOTS) and the names of
// blocked keys (see BLOCKED_KEY_NAMES).

// Returns the DER certificates in a get-roots response or a bundle of PEM certificates.
export function certificatesIn(text) {
  if (text.trimStart().startsWith("{")) {
    return JSON.parse(text).certificates.map((cert) => Buffer.from(cert, "base64"));
  }
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
}

// Returns a DER certificate's subject name (including its tag and length).
export function subjectName(der) {
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
  return der.subarray(field.start, field.end);
}

// Returns the 32-bit FNV-1a hash of a DER name, as cf_ctreq.js's nameHash() hashes the
// names in a chain.
export function nameHash(name) {
  let h = 0x811c9dc5;
  for (const byte of name) h = Math.imul(h ^ byte, 0x01000193);
  return h >>> 0;
}

// Returns the hash of a DER certificate's subject name.
export const subjectHash = (der) => nameHash(subjectName(der));

// Returns a list of names' hashes, as cf_ctreq.js has them: sorted, without duplicates, as
// 8 hex digits each.
export const hashList = (hashes) => [...new Set(hashes.map((h) => h.toString(16).padStart(8, "0")))].sort().join("");

// Returns a list of accepted roots, as tools/build.mjs writes it into the minified snippets: the
// hashes of the given DER certificates' subject names, sorted, as 8 hex digits each.
export const rootHashes = (certs) => hashList(certs.map(subjectHash));

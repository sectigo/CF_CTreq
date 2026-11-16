// Hashes lists of accepted roots for the minified snippets (see ACCEPTED_ROOTS in cf_ctreq.js).

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

// Returns a list of accepted roots, as tools/build.mjs writes it into the minified snippets: the
// hashes of the given DER certificates' subject names, sorted, as 8 hex digits each.
export function rootHashes(certs) {
  return [...new Set(certs.map((der) => subjectHash(der).toString(16).padStart(8, "0")))].sort().join("");
}

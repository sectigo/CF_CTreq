// Minimal DER builders, shared by the tests and the differential tests. Certificates
// are structurally valid X.509, but have fake signatures.
export const tlv = (tag, content) => {
  const body = Buffer.from(content);
  const n = body.length;
  const header = n < 0x80 ? [tag, n] : n < 0x100 ? [tag, 0x81, n] : n < 0x10000 ? [tag, 0x82, n >> 8, n & 0xff] : [tag, 0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from(header), body]);
};
export const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
export const ctOid = (last) => [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, last]; // 1.3.6.1.4.1.11129.2.4.<last>
export const OID_EKU = [0x55, 0x1d, 0x25];
export const ext = (oid, critical, value) =>
  seq(tlv(0x06, oid), critical ? tlv(0x01, [0xff]) : Buffer.alloc(0), tlv(0x04, value));
export const POISON_EXT = ext(ctOid(3), true, [0x05, 0x00]);

// version is the content of the [0] version INTEGER (default v3), or null to omit it (v1);
// versionField replaces the whole [0] field. beforeExtensions and afterExtensions are
// raw bytes placed around the [3] extensions field, which extensionsField replaces.
// outerAlgorithm replaces the signature algorithm after the TBSCertificate.
export function makeCert({ extensions, subject = Buffer.alloc(100, 0x61), version = [2], versionField, beforeExtensions = [], extensionsField, afterExtensions = [], outerAlgorithm } = {}) {
  const alg = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
  const name = (cn) => seq(tlv(0x31, seq(tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x0c, cn))));
  const time = tlv(0x17, Buffer.from("260101000000Z"));
  const tbs = seq(
    versionField ? Buffer.from(versionField) : version === null ? Buffer.alloc(0) : tlv(0xa0, tlv(0x02, version)),
    tlv(0x02, [1]),
    alg,
    name("Test CA"),
    seq(time, time),
    name(subject),
    seq(alg, tlv(0x03, [0, ...Array(32).fill(1)])),
    Buffer.from(beforeExtensions),
    extensionsField ? Buffer.from(extensionsField) : extensions ? tlv(0xa3, seq(...extensions)) : Buffer.alloc(0),
    Buffer.from(afterExtensions),
  );
  return seq(tbs, outerAlgorithm ? Buffer.from(outerAlgorithm) : alg, tlv(0x03, [0, ...Array(64).fill(2)]));
}

export const b64 = (buf) => buf.toString("base64");
// A CA certificate whose subject matches the issuer of the other fixtures.
export const makeCA = (extensions) => makeCert({ extensions, subject: Buffer.from("Test CA") });
// A valid outer SEQUENCE header around filler, for tests that don't need a parseable certificate.
export const der = (content) => tlv(0x30, content);

export const CERT = b64(makeCert());
export const PRECERT = b64(makeCert({ extensions: [POISON_EXT] }));
export const NONCRITICAL = b64(makeCert({ extensions: [ext(ctOid(3), false, [0x05, 0x00])] }));
export const ISSUER = b64(makeCA());

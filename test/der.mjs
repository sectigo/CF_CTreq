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
export const ECDSA_SHA256 = seq(tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
export const ED25519 = seq(tlv(0x06, [0x2b, 0x65, 0x70])); // 1.3.101.112
export const ID_EC_PUBLIC_KEY = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
// A P-256 key (with the given key algorithm OID): the curve's generator point, so that it
// is a valid point, which the origins' X.509 parsers require.
export const p256Key = (oid = ID_EC_PUBLIC_KEY) =>
  seq(
    seq(tlv(0x06, oid), tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])),
    tlv(0x03, [0, 0x04, ...Buffer.from("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", "hex")]),
  );
export const P256_KEY = p256Key();
export const ED25519_KEY = seq(ED25519, tlv(0x03, [0, ...Array(32).fill(1)]));
// An ECDSA key that isn't valid (the snippet only reads its algorithm), but is small, as
// some tests depend on the fixtures' sizes.
const TEST_KEY = seq(seq(tlv(0x06, ID_EC_PUBLIC_KEY)), tlv(0x03, [0, ...Array(33).fill(1)]));

// version is the content of the [0] version INTEGER (default v3), or null to omit it (v1);
// versionField replaces the whole [0] field. beforeExtensions and afterExtensions are
// raw bytes placed around the [3] extensions field, which extensionsField replaces.
// algorithm is the signature AlgorithmIdentifier (default ecdsa-with-SHA256), which
// outerAlgorithm replaces after the TBSCertificate. publicKey is the SubjectPublicKeyInfo
// (by default TEST_KEY).
export function makeCert({ extensions, issuer = "Test CA", subject = Buffer.alloc(100, 0x61), version = [2], versionField, beforeExtensions = [], extensionsField, afterExtensions = [], outerAlgorithm, algorithm = ECDSA_SHA256, publicKey = TEST_KEY } = {}) {
  const alg = Buffer.from(algorithm);
  const name = (cn) => seq(tlv(0x31, seq(tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x0c, cn))));
  const time = tlv(0x17, Buffer.from("260101000000Z"));
  const tbs = seq(
    versionField ? Buffer.from(versionField) : version === null ? Buffer.alloc(0) : tlv(0xa0, tlv(0x02, version)),
    tlv(0x02, [1]),
    alg,
    name(issuer),
    seq(time, time),
    name(subject),
    Buffer.from(publicKey),
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

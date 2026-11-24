// Generates a deterministic corpus of add-chain request bodies for the differential
// tests: random chains of certificates with structural variants (versions, padded
// and empty OIDs, poison and critical flag variants, Precertificate Signing
// Certificates, malformed and misplaced extensions, mismatched signature algorithms,
// Ed25519 keys and signatures, matching and mismatching names, bit flips), wrapped in
// JSON with chain key, escape, whitespace and BOM variants, and base64 variants.
import { tlv, seq, ctOid, OID_EKU, ext, makeCert as makeAnyCert, b64, ED25519, ED25519_KEY, P256_KEY } from "../der.mjs";

// Certificates have a valid P-256 key unless the options give another.
const makeCert = (options) => makeAnyCert({ publicKey: P256_KEY, ...options });
const ISSUER = b64(makeCert({ subject: Buffer.from("Test CA") }));

const NULL = [0x05, 0x00];
const SERVER_AUTH = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const ECDSA_SHA256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

export function generate({ seed = 1, count = 5000 } = {}) {
  // mulberry32
  let state = seed | 0;
  const rnd = (n) => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) % n;
  };
  const pick = (choices) => choices[rnd(choices.length)];
  // Inserts a leading 0x80 byte into one of an OID's arcs.
  const pad = (oid) => {
    const i = rnd(oid.length);
    return [...oid.slice(0, i), 0x80, ...oid.slice(i)];
  };
  const eku = () =>
    ext(rnd(5) ? OID_EKU : pad(OID_EKU), false, pick([
      seq(...pick([[ctOid(4)], [SERVER_AUTH, ctOid(4)], [SERVER_AUTH], [pad(ctOid(4))], [ctOid(4), []]]).map((o) => tlv(0x06, o))),
      seq(tlv(0x06, ctOid(4)), Buffer.from(NULL)),
      Buffer.concat([seq(tlv(0x06, ctOid(4))), Buffer.from(NULL)]),
    ]));
  const extension = () => {
    const r = rnd(12);
    if (r < 3) return ext(pick([ctOid(3), ctOid(3), pad(ctOid(3))]), pick([true, true, false]), pick([NULL, NULL, [0x30, 0x00]]));
    if (r < 5) return eku();
    if (r < 6) return ext(pick([[], [0x2b, 0x86], [0x2b, 0x88, 0x80, 0x80, 0x80, 0x00], [0x2b, 0x87, 0xff, 0xff, 0xff, 0x7f], [0x88, 0x37, 0x01]]), false, NULL);
    if (r < 7) return seq(tlv(0x06, ctOid(3)), tlv(0x01, pick([[0x01], [0x00], [0xff], [0xff, 0x00]])), tlv(0x04, NULL));
    if (r < 8) return seq(tlv(0x06, ctOid(3)), tlv(0x01, [0xff]), tlv(0x04, NULL), Buffer.from(pick([NULL, [0xff, 0xff]])));
    if (r < 9) return pick([seq(tlv(0x04, [1]), tlv(0x04, [2])), Buffer.from(NULL), seq()]);
    return ext([0x2a, rnd(100)], false, [0x04, 0x00]);
  };
  const certificate = (subject, issuer) => {
    const extensions = Array.from({ length: rnd(5) }, extension);
    if (rnd(6) === 0 && extensions.length) extensions.push(extensions[rnd(extensions.length)]);
    const options = { subject: Buffer.from(subject), version: pick([[2], [2], [2], null, [0], [1], [3], [0xff], [0x00, 0x02]]) };
    if (rnd(10) === 0) options.versionField = pick([[0xa0, 0x7f, 0x02, 0x01, 0x02], [0xa0, 0x03, 0x02, 0x01, 0x02], [0xa0, 0x00]]);
    if (extensions.length || rnd(3) === 0) {
      const list = seq(...extensions);
      options.extensionsField = pick([
        tlv(0xa3, list), tlv(0xa3, list), tlv(0xa3, list),
        Buffer.concat([Buffer.from([0xa3, 0x7f]), list]),
        Buffer.concat([Buffer.from([0xa3, 0x01]), list]),
        tlv(0xa3, Buffer.concat([list, Buffer.from(NULL)])),
        tlv(0xa3, NULL), Buffer.from([0xa3, 0x00, ...NULL]), Buffer.from([0xa3, 0x7f]),
      ]);
    }
    if (rnd(6) === 0) options.afterExtensions = pick([NULL, [0x04, 0x85], [0xff, 0xff, 0xff], [0xbf, 0x1f, 0x00]]);
    if (rnd(6) === 0) options.beforeExtensions = pick([NULL, [...tlv(0x81, [0, 1])], [...tlv(0x81, [0, 1]), ...tlv(0x82, [0, 2])], [0x81, 0x7f]]);
    if (rnd(12) === 0) options.outerAlgorithm = pick([seq(tlv(0x06, [...ECDSA_SHA256.slice(0, -1), 0x03])), seq(tlv(0x06, ECDSA_SHA256), Buffer.from(NULL)), Buffer.from(NULL)]);
    // Sunlight rejects certificates without an RSA or ECDSA key and signature.
    const ed25519 = rnd(12);
    if (ed25519 === 0 || ed25519 === 2) options.publicKey = ED25519_KEY;
    if (ed25519 === 1 || ed25519 === 2) options.algorithm = ED25519;
    let cert = makeCert(options);
    // makeCert's issuer is "Test CA": replace it with another 7-character name.
    if (issuer !== "Test CA") cert = Buffer.from(cert.toString("latin1").replace("Test CA", issuer), "latin1");
    if (rnd(8) === 0) {
      cert = Buffer.from(cert);
      for (let k = 1 + rnd(2); k > 0; k--) cert[rnd(cert.length)] ^= 1 << rnd(8);
    }
    return b64(cert);
  };
  const chain = () => {
    const certs = [];
    for (let k = 1 + rnd(3); k > 0; k--) {
      const subject = certs.length === 0 ? "a".repeat(1 + rnd(100)) : pick(["Test CA", "Test CA", "Other C"]);
      certs.push(certificate(subject, pick(["Test CA", "Test CA", "Other C"])));
    }
    return certs;
  };
  const preIssuerChain = () => {
    const precert = b64(makeCert({ extensions: [ext(pick([ctOid(3), pad(ctOid(3))]), true, NULL), ...(rnd(2) ? [extension()] : [])], version: pick([[2], null]) }));
    const issuer = b64(makeCert({ subject: Buffer.from("Test CA"), version: pick([[2], [2], null]), extensions: Array.from({ length: 1 + rnd(2) }, eku) }));
    return rnd(3) ? [precert, issuer] : [precert, issuer, ISSUER];
  };
  // A chain with no deliberate defects (other than possibly a padded poison OID, which
  // only Go's crypto/x509 rejects), so that most origins would accept it.
  const validChain = () => {
    const poisoned = rnd(2) === 0;
    const extensions = [...(poisoned ? [ext(pick([ctOid(3), ctOid(3), ctOid(3), pad(ctOid(3))]), true, NULL)] : []), ...Array.from({ length: rnd(3) }, (_, k) => ext([0x2a, 10 + k], k === 0 && rnd(2) === 0, [0x04, 0x00]))];
    const leaf = b64(makeCert({ extensions, subject: Buffer.alloc(1 + rnd(100), 0x61), version: pick([[2], [2], [2], null, [1]]) }));
    return rnd(2) ? [leaf] : [leaf, ISSUER];
  };
  const base64Variant = (s) =>
    pick([
      s, s, s, s,
      s.match(/.{1,64}/g).join(pick(["\n", "\r\n", "\r"])),
      s.replace(/=+$/, ""), s + "=", s.slice(0, -1),
      s.replace(/.$/, pick(["*", "-", "_", " "])),
    ]);
  const chainKey = () => {
    const key = [..."chain"].map((c) => (rnd(2) ? c.toUpperCase() : c));
    if (rnd(4) === 0) {
      const i = rnd(5);
      key[i] = "\\u" + key[i].charCodeAt(0).toString(16).padStart(4, "0");
    }
    return key.join("");
  };
  const body = (certs) => {
    if (rnd(3)) return JSON.stringify({ chain: certs });
    const members = [];
    for (let n = 1 + rnd(4); n > 0; n--) {
      const r = rnd(6);
      if (r === 0) members.push(`"x":{"chain":${JSON.stringify(chain())}}`);
      else if (r === 1) members.push(`"s":"\\"chain\\":[]"`);
      else if (r === 2) members.push(`"other":${JSON.stringify(Array.from({ length: rnd(20) }, () => "z".repeat(rnd(40))))}`);
      else members.push(`"${chainKey()}"${pick(["", " ", "\n "])}:${pick(["", " "])}${pick([JSON.stringify(certs), JSON.stringify(certs), "null", "[]", "5", JSON.stringify(chain())])}`);
    }
    if (rnd(3) === 0) members.push(`"chain":${JSON.stringify(certs)}`);
    const text = "{" + members.join(",") + "}";
    return pick([text, text, text, text, "\ufeff" + text, text + " ", text.slice(0, -1), "[" + JSON.stringify(certs) + "]", "null", ""]);
  };

  const items = [];
  for (let id = 0; id < count; id++) {
    const r = rnd(10);
    const certs = r === 0 ? preIssuerChain() : r < 4 ? validChain() : chain();
    let text = r === 1 ? JSON.stringify({ chain: certs.map(base64Variant) }) : body(certs);
    // Occasionally pad with whitespace to just within or just over an origin's body size limit.
    if (rnd(100) === 0) text += " ".repeat(Math.max(0, pick([128 * 1024, 512000, 512 * 1024]) + rnd(2) - Buffer.byteLength(text)));
    items.push({ id: String(id), body: text });
  }
  return items;
}

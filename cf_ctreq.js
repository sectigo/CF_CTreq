// CF_CTreq - Preprocessor for Certificate Transparency (CT) log API requests
// (RFC6962 and Static CT), implemented in JavaScript as a Cloudflare Snippet.
// Written by Rob Stradling.
// Copyright (C) 2026 Sectigo Limited.
//
// Requests to the add-chain and add-pre-chain endpoints must be POST (else 405) with
// a body (and any Content-Length) of at most CONFIG.maxBodyBytes (else 413). The body
// is parsed as the origin (Sunlight, TesseraCT, or Trillian, all using Go's
// encoding/json) would parse it: the "chain" key is matched case-insensitively, and
// line breaks in base64 are ignored. The chain must be a non-empty array of at most
// CONFIG.maxChainLength base64 strings, each decoding to at least CONFIG.minCertBytes
// and to a DER SEQUENCE whose declared length matches its actual length (else 400).
//
// Every certificate must then parse as X.509 down to its extensions (RFC 5280), as
// the origin's X.509 parser would parse it, else 400, and:
// - If the first certificate has the CT poison extension (RFC 6962 section 3.1) it
//   must be critical with a NULL value, and only add-pre-chain is permitted.
//   If it does not, only add-chain is permitted.
// - Sunlight only: a precertificate's issuer must not be a Precertificate Signing
//   Certificate.
// - Each certificate's issuer name must be byte-identical to the subject name of
//   the next certificate in the chain. Signatures are not verified.
// CONFIG.environment selects whose criteria apply: "sunlight", "tesseract", or
// "trillian" rejects what that origin would reject, and "common" only rejects what
// all of them would reject.
// Requests that pass these checks are forwarded to the origin unchanged.

const CONFIG = {
  // "sunlight", "tesseract", "trillian", or "common" (only reject what all of them
  // would reject).
  environment: "common",
  maxBodyBytes: 128 * 1024,
  maxChainLength: 10,
  minCertBytes: 128,
  // Prefix of the problem details "type" URI; the rejection reason code is appended.
  problemTypeBase: "https://github.com/sectigo/CF_CTreq#",
};

// How each origin differs, as far as it affects which requests it rejects:
// - x509: its X.509 parser, either Go's crypto/x509 ("go") or
//   certificate-transparency-go's x509 ("ctgo");
// - allowsOptions: it answers CORS preflight (OPTIONS) requests itself;
// - rejectsPrecertSigningCerts: it doesn't support Precertificate Signing Certificates;
// - allowsAnyOrigin: its responses have "Access-Control-Allow-Origin: *".
const ORIGINS = {
  sunlight: { x509: "ctgo", allowsOptions: true, rejectsPrecertSigningCerts: true, allowsAnyOrigin: true },
  tesseract: { x509: "go", allowsOptions: false, rejectsPrecertSigningCerts: false, allowsAnyOrigin: false },
  trillian: { x509: "ctgo", allowsOptions: false, rejectsPrecertSigningCerts: false, allowsAnyOrigin: false },
};
// The origins that must all reject a request for it to be rejected, for each
// environment.
const ENVIRONMENTS = {
  sunlight: [ORIGINS.sunlight],
  tesseract: [ORIGINS.tesseract],
  trillian: [ORIGINS.trillian],
  common: Object.values(ORIGINS),
};
// Fail at deployment, rather than on every request, if CONFIG.environment is wrong.
originsFor(CONFIG.environment);

function originsFor(environment) {
  if (!Object.hasOwn(ENVIRONMENTS, environment)) {
    const names = Object.keys(ENVIRONMENTS).map((e) => JSON.stringify(e));
    throw new Error(`CONFIG.environment must be ${names.slice(0, -1).join(", ")}, or ${names.at(-1)}, not ${JSON.stringify(environment)}`);
  }
  return ENVIRONMENTS[environment];
}

// OIDs in dotted form, as compared after decoding with oidString().
const OID_CT_POISON = "1.3.6.1.4.1.11129.2.4.3";
const OID_CT_PRECERT_SIGNING = "1.3.6.1.4.1.11129.2.4.4";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const NULL_VALUE = "\x05\x00";

// Standard, padded base64 (RFC 4648 section 4); atob() alone is more lenient. Go's
// decoder also skips CR and LF anywhere, so those are removed before testing this.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const LINE_BREAKS = /[\r\n]/g;
// Go's encoding/json matches keys to struct fields case-insensitively. The /i flag
// without /u folds ASCII letters only, which is all that Go folds onto "chain".
const CHAIN_KEY = /^chain$/i;

// Decodes the DER TLV header at index i of a binary string. Returns null if the
// header is malformed (including a length that is not minimally encoded, which Go's
// crypto/x509 rejects), or if the value would extend past end.
function derDecode(data, i, end = data.length) {
  if (i + 2 > end) {
    return null;
  }
  const tag = data.charCodeAt(i);
  if ((tag & 0x1f) === 0x1f) {
    return null; // High-tag-number form is not used by X.509.
  }
  let length = data.charCodeAt(i + 1);
  let offset = i + 2;
  if (length >= 0x80) {
    // 0x80 is indefinite length, which DER forbids; more than 4 length bytes is implausible.
    const n = length & 0x7f;
    if (n === 0 || n > 4 || offset + n > end || data.charCodeAt(offset) === 0) {
      return null;
    }
    length = 0;
    for (let j = 0; j < n; j++) {
      length = length * 256 + data.charCodeAt(offset++);
    }
    if (length < 0x80) {
      return null; // Should have used the short form.
    }
  }
  if (offset + length > end) {
    return null;
  }
  return { tag, length, offset, end: offset + length, start: i };
}

// Decodes all TLVs directly inside parent, or returns null if any is malformed.
function derChildren(data, parent) {
  const children = [];
  for (let i = parent.offset; i < parent.end; i = children.at(-1).end) {
    const child = derDecode(data, i, parent.end);
    if (child === null) {
      return null;
    }
    children.push(child);
  }
  return children;
}

// Decodes the contents of an OBJECT IDENTIFIER (as a binary string) into its dotted
// form, or returns null if the origin's X.509 parser would reject it. Both parsers
// reject an arc that is truncated, longer than 5 bytes, or 2^31 or more, but only Go's
// crypto/x509 rejects an empty OID or an arc that isn't minimally encoded (with a
// leading 0x80 byte): certificate-transparency-go's x509 reads such an arc as the
// same number, so e.g. a poison extension's OID needn't be encoded canonically.
function oidString(contents, origin) {
  if (contents.length === 0) {
    return origin.x509 === "go" ? null : "";
  }
  const arcs = [];
  let value = 0;
  let length = 0;
  for (let i = 0; i < contents.length; i++) {
    const byte = contents.charCodeAt(i);
    if ((length === 0 && byte === 0x80 && origin.x509 === "go") || ++length > 5) {
      return null;
    }
    value = value * 128 + (byte & 0x7f);
    if (byte < 0x80) {
      if (value > 0x7fffffff) {
        return null;
      }
      arcs.push(value);
      value = 0;
      length = 0;
    }
  }
  if (length !== 0) {
    return null; // Truncated.
  }
  // The first arc encodes the first two arcs (40 * first + second), the first being
  // 0, 1 or 2.
  const [both, ...rest] = arcs;
  return [both < 80 ? Math.floor(both / 40) : 2, both < 80 ? both % 40 : both - 80, ...rest].join(".");
}

// Parses the extensions inside a certificate's [3] wrapper into { oid, critical, value }
// entries (oid is in dotted form; value is the DER location of the extnValue
// contents), or returns null if they are malformed, as the origin's X.509 parser
// would. Only Go's crypto/x509 rejects two extensions of the same type.
function certExtensions(cert, wrapper, origin) {
  // As for both X.509 parsers, anything after the SEQUENCE inside [3] is ignored.
  const list = derDecode(cert, wrapper.offset, wrapper.end);
  const entries = list !== null && list.tag === 0x30 ? derChildren(cert, list) : null;
  if (entries === null) {
    return null;
  }
  const extensions = [];
  for (const entry of entries) {
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    // As for both X.509 parsers, anything after extnValue is ignored.
    const oid = entry.tag === 0x30 ? derDecode(cert, entry.offset, entry.end) : null;
    if (oid === null || oid.tag !== 0x06) {
      return null;
    }
    let critical = false;
    let i = oid.end;
    if (i < entry.end && cert.charCodeAt(i) === 0x01) {
      // Both X.509 parsers only accept 0x00 (FALSE) and 0xFF (TRUE).
      const flag = derDecode(cert, i, entry.end);
      const byte = flag?.length === 1 ? cert.charCodeAt(flag.offset) : -1;
      if (byte !== 0x00 && byte !== 0xff) {
        return null;
      }
      critical = byte === 0xff;
      i = flag.end;
    }
    const value = derDecode(cert, i, entry.end);
    const id = oidString(cert.slice(oid.offset, oid.end), origin);
    if (id === null || value === null || value.tag !== 0x04 || (origin.x509 === "go" && extensions.some((e) => e.oid === id))) {
      return null;
    }
    extensions.push({ oid: id, critical, value });
  }
  return extensions;
}

// Parses a certificate into { der, issuer, subject, extensions } (the names being DER
// encodings including headers), or returns null if the origin's X.509 parser would
// reject it. The TBSCertificate is read field by field, as far as the extensions, as
// both X.509 parsers read it: the optional unique IDs and extensions are only found
// directly after the public key, and anything after them is ignored. Go's crypto/x509
// (TesseraCT) only accepts v1, v2 and v3, and only reads the unique IDs from v2 and
// v3 certificates and the extensions from v3 certificates; certificate-transparency-go's
// x509 (Sunlight, Trillian) accepts any version and reads them regardless.
function parseCert(der, origin) {
  const root = derDecode(der, 0);
  const tbs = root && derDecode(der, root.offset, root.end);
  if (tbs === null || tbs.tag !== 0x30) {
    return null;
  }
  let i = tbs.offset;
  const peek = (tag) => i < tbs.end && der.charCodeAt(i) === tag;
  // Returns the next field and moves past it, or returns null if it is malformed or
  // doesn't have the given tag.
  const read = (tag) => {
    const field = peek(tag) ? derDecode(der, i, tbs.end) : null;
    if (field !== null) {
      i = field.end;
    }
    return field;
  };

  // version [0] EXPLICIT INTEGER DEFAULT v1 (0), which may also be encoded explicitly.
  let version = 0;
  if (peek(0xa0)) {
    const wrapper = read(0xa0);
    if (wrapper === null) {
      return null;
    }
    if (origin.x509 === "go") {
      const integer = derDecode(der, wrapper.offset, wrapper.end);
      if (integer === null || integer.tag !== 0x02 || integer.length !== 1 || integer.end !== wrapper.end) {
        return null;
      }
      version = der.charCodeAt(integer.offset);
      if (version > 2) {
        return null; // Unknown (v4 or later) or negative.
      }
    }
  }
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
  const fields = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30].map(read);
  if (fields.includes(null)) {
    return null;
  }
  const [, , issuer, , subject] = fields;
  let extensions = [];
  if (origin.x509 === "ctgo" || version >= 1) {
    // issuerUniqueID [1] and subjectUniqueID [2], both IMPLICIT and optional.
    if ((peek(0x81) && read(0x81) === null) || (peek(0x82) && read(0x82) === null)) {
      return null;
    }
    if ((origin.x509 === "ctgo" || version === 2) && peek(0xa3)) {
      const wrapper = read(0xa3);
      extensions = wrapper && certExtensions(der, wrapper, origin);
      if (extensions === null) {
        return null;
      }
    }
  }
  return {
    der,
    issuer: der.slice(issuer.start, issuer.end),
    subject: der.slice(subject.start, subject.end),
    extensions,
  };
}

// Returns whether a parsed certificate is a Precertificate Signing Certificate, as
// Sunlight (certificate-transparency-go's ct.IsPreIssuer) determines it: an extended
// key usage extension contains the CT precertificate signing OID. Only a cleanly
// parsed extension counts, so that this is never true when Sunlight's isn't.
function isPrecertSigningCert({ der, extensions }, origin) {
  return extensions.some((e) => {
    if (e.oid !== OID_EXT_KEY_USAGE) {
      return false;
    }
    const list = derDecode(der, e.value.offset, e.value.end);
    const oids = list !== null && list.tag === 0x30 && list.end === e.value.end ? derChildren(der, list) : null;
    const ids = oids?.map((o) => (o.tag === 0x06 ? oidString(der.slice(o.offset, o.end), origin) : null));
    return ids !== undefined && !ids.includes(null) && ids.includes(OID_CT_PRECERT_SIGNING);
  });
}

// A rejection, as the arguments of errorResponse().
const rejection = (reason, message, status = 400, headers = {}) => ({ reason, message, status, headers });

// Returns the rejection, if any, that the origin would make for a chain of DER
// certificates (each already known to be a DER SEQUENCE), or null if it would accept
// it as far as this snippet checks.
function chainRejection(origin, ders, isPreChainAPI) {
  const certs = [];
  for (const der of ders) {
    const parsed = parseCert(der, origin);
    if (parsed === null) {
      return rejection("cert-unparseable", "chain entry cannot be parsed as an X.509 certificate");
    }
    certs.push(parsed);
  }

  const { der: firstDer, extensions } = certs[0];
  // All the origins check the first poison extension, if there's more than one.
  const poison = extensions.find((e) => e.oid === OID_CT_POISON);
  if (poison !== undefined) {
    if (!poison.critical || firstDer.slice(poison.value.offset, poison.value.end) !== NULL_VALUE) {
      return rejection("poison-invalid", "CT poison extension must be critical and contain NULL");
    }
  }
  const hasPoison = poison !== undefined;
  if (hasPoison && !isPreChainAPI) {
    return rejection("precert-on-add-chain", "precertificate submitted to add-chain; use add-pre-chain");
  }
  if (!hasPoison && isPreChainAPI) {
    return rejection("cert-on-add-pre-chain", "certificate submitted to add-pre-chain; use add-chain");
  }
  // Sunlight doesn't support Precertificate Signing Certificates, as
  // c2sp.org/static-ct-api@v1.1.0 allows.
  if (origin.rejectsPrecertSigningCerts && hasPoison && certs.length > 1 && isPrecertSigningCert(certs[1], origin)) {
    return rejection("psc-not-supported", "precertificate signing certificates are not supported");
  }
  for (let i = 0; i + 1 < certs.length; i++) {
    if (certs[i].issuer !== certs[i + 1].subject) {
      return rejection("issuer-mismatch", "issuer of a certificate does not match the subject of the next certificate in the chain");
    }
  }
  return null;
}

// Returns true for an add-pre-chain path, false for an add-chain path, or null for any
// other path. As Go's http.ServeMux (used by the origin) does, each path segment is
// percent-decoded before matching, so e.g. "add%2Dchain" is add-chain, but
// "ct%2Fv1" is a single segment.
function isPreChainPath(pathname) {
  let segments;
  try {
    segments = pathname.split("/").slice(-3).map(decodeURIComponent);
  } catch {
    return null; // Invalid percent-encoding, which Go rejects.
  }
  const [ct, v1, endpoint] = segments;
  if (ct !== "ct" || v1 !== "v1") {
    return null;
  }
  return endpoint === "add-pre-chain" ? true : endpoint === "add-chain" ? false : null;
}

// Reads the request body as bytes, or returns null as soon as it exceeds maxBytes, so that
// a body without a Content-Length (e.g. chunked) is bounded too.
async function readBody(request, maxBytes) {
  const chunks = [];
  let total = 0;
  if (request.body !== null) {
    const reader = request.body.getReader();
    for (let r = await reader.read(); !r.done; r = await reader.read()) {
      total += r.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(r.value);
    }
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

// Rejections are RFC 9457 problem details (application/problem+json, itself JSON as
// RFC 6962 section 4 requires of all responses). The X-CTreq-Reject response header
// carries the same reason code so that rejections can be analysed in Cloudflare logs.
// If any of the environment's origins allows any origin in its responses (as Sunlight
// does, so that browsers can read them), rejections do too.
function errorResponse({ reason, message, status, headers }, origins) {
  const problem = { type: CONFIG.problemTypeBase + reason, title: message, status };
  const cors = origins.some((o) => o.allowsAnyOrigin) ? { "Access-Control-Allow-Origin": "*" } : {};
  return new Response(JSON.stringify(problem) + "\n", {
    status,
    headers: { "Content-Type": "application/problem+json", "X-CTreq-Reject": reason, ...cors, ...headers },
  });
}

// Returns the rejection, if any, for a request whose body hasn't been read yet. A
// method is only rejected if none of the environment's origins accepts it.
function methodRejection(origins, method) {
  const allowed = origins.some((o) => o.allowsOptions) ? ["OPTIONS", "POST"] : ["POST"];
  if (allowed.includes(method)) {
    return null;
  }
  return rejection("method-not-allowed", "method not allowed; use POST", 405, { Allow: allowed.join(", ") });
}

// Returns the rejection, if any, for a request body, or the chain's DER certificates
// (as binary strings) if the body should be checked further.
function bodyRejectionOrChain(body) {
  let json;
  try {
    // Keep any BOM so that JSON.parse rejects it, as Go's encoding/json does.
    json = JSON.parse(new TextDecoder("utf-8", { ignoreBOM: true }).decode(body));
  } catch {
    return rejection("invalid-json", "unable to parse request body");
  }
  const chainKeys = json !== null && typeof json === "object" ? Object.keys(json).filter((k) => CHAIN_KEY.test(k)) : [];
  // Go would use whichever such key comes last in the body, which JSON.parse can't
  // reveal when their cases differ, so a request with more than one is rejected.
  if (chainKeys.length > 1) {
    return rejection("chain-ambiguous", "more than one chain key, differing only in case");
  }
  const chain = chainKeys.length === 1 ? json[chainKeys[0]] : undefined;
  if (!Array.isArray(chain) || chain.length === 0) {
    return rejection("chain-missing", "chain is missing or empty");
  }
  if (chain.length > CONFIG.maxChainLength) {
    return rejection("chain-too-long", "chain has too many entries");
  }
  const ders = [];
  for (const entry of chain) {
    const base64 = typeof entry === "string" ? entry.replace(LINE_BREAKS, "") : null;
    if (base64 === null || !BASE64.test(base64)) {
      return rejection("entry-not-base64", "chain entries must be base64 strings");
    }
    // atob() returns a "binary string" (one char per byte).
    const der = atob(base64);
    if (der.length < CONFIG.minCertBytes) {
      return rejection("entry-too-short", "chain entry is too short to be a certificate");
    }
    const root = derDecode(der, 0);
    if (root === null || root.tag !== 0x30 || root.end !== der.length) {
      return rejection("entry-not-der", "chain entry is not a DER SEQUENCE of the declared length");
    }
    ders.push(der);
  }
  return ders;
}

export default {
  async fetch(request) {
    const origins = originsFor(CONFIG.environment);
    const isPreChainAPI = isPreChainPath(new URL(request.url).pathname);
    if (isPreChainAPI === null) {
      return fetch(request);
    }

    const methodRejected = methodRejection(origins, request.method);
    if (methodRejected !== null) {
      return errorResponse(methodRejected, origins);
    }
    if (request.method !== "POST") {
      return fetch(request);
    }

    const contentLength = request.headers.get("Content-Length");
    if (contentLength !== null && Number(contentLength) > CONFIG.maxBodyBytes) {
      return errorResponse(rejection("body-too-large", "request body too large", 413), origins);
    }
    const body = await readBody(request, CONFIG.maxBodyBytes);
    if (body === null) {
      return errorResponse(rejection("body-too-large", "request body too large", 413), origins);
    }

    const ders = bodyRejectionOrChain(body);
    if (!Array.isArray(ders)) {
      return errorResponse(ders, origins);
    }
    // Only reject if every origin in the environment would reject, reporting
    // TesseraCT's reason if it is one of them (else the first origin's).
    const rejections = origins.map((origin) => chainRejection(origin, ders, isPreChainAPI));
    if (rejections.every((r) => r !== null)) {
      return errorResponse(rejections[Math.max(0, origins.indexOf(ORIGINS.tesseract))], origins);
    }

    // The original body stream has been consumed, so forward a copy of its exact bytes.
    return fetch(new Request(request, { body }));
  },
};

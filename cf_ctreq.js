// CF_CTreq - Preprocessor for Certificate Transparency (CT) log API requests
// (RFC6962 and Static CT), implemented in JavaScript as a Cloudflare Snippet.
//
// Version 1.4.0.
//
// Written by Rob Stradling.
// Copyright (C) 2026 Sectigo Limited.
//
// Requests to the add-chain and add-pre-chain endpoints must be POST (else 405) with
// a body (and any Content-Length) no larger than the origin accepts (else 413). The body
// is parsed as the origin (Sunlight, TesseraCT, or Trillian, all using Go's
// encoding/json) would parse it: the "chain" key is matched case-insensitively, and
// line breaks in base64 are ignored. The chain must be a non-empty array (else 400);
// one of more than CONFIG.maxChainLength entries is forwarded without further checks.
// Otherwise, its entries must be base64 strings, each decoding to at least
// CONFIG.minCertBytes and to a DER SEQUENCE whose declared length matches its actual
// length (else 400).
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
// - The chain must lead to one of the log's accepted roots, as listed by the origin's
//   get-roots endpoint: the issuer name of one of its certificates (or the subject
//   name of the last) must have the same hash as a root's subject name. The list is
//   cached for CONFIG.rootsCacheSeconds; if it can't be fetched or read, this check is
//   skipped.
// CONFIG.environment selects whose criteria apply: "sunlight", "tesseract", or
// "trillian" rejects what that origin would reject, and "common" only rejects what
// all of them would reject. CONFIG.logEnvironments can select a different one for
// particular logs, identified by their hostnames and paths.
// Requests that pass these checks are forwarded to the origin unchanged.

const CONFIG = {
  // Default environment: "sunlight", "tesseract", "trillian", or "common" (only
  // reject what all of them would reject).
  environment: "common",
  // Environments for particular logs, as [regular expression, environment] pairs: a
  // request uses the environment of the first pair whose regular expression matches
  // its hostname followed by its path (e.g. "tiger2027h1.ct.sectigo.com/ct/v1/add-chain"),
  // or else the default environment.
  logEnvironments: [
    // Sectigo Static CT logs.
    [/^(monument|statue)\d{4}h[12]\.sub\.ct\.sectigo\.com\//, "tesseract"],
    [/^billboard\.sub\.ct\.sectigo\.com\//, "tesseract"],
    [/^standee\.sub\.ctlabs\.sectigo\.com\//, "tesseract"],
    // Sectigo RFC 6962 logs.
    [/^(elephant|tiger)\d{4}h[12]\.ct\.sectigo\.com\//, "trillian"],
    [/^(dumbo|tigger\d{4})\.ctlabs\.sectigo\.com\//, "trillian"],
  ],
  // Maximum request body size in bytes, or null for the largest of the environment's
  // origins' defaults. Set it if the origin is configured with a different limit.
  maxBodyBytes: null,
  // Chains with more entries (which real ones never have) are forwarded to the origin
  // without being checked, so as not to spend the Snippet's limited CPU time on them.
  maxChainLength: 10,
  minCertBytes: 128,
  // How long each log's accepted roots (from its get-roots endpoint) are cached, both in
  // Cloudflare's cache and in the snippet's memory.
  rootsCacheSeconds: 60,
  // Prefix of the problem details "type" URI; the rejection reason code is appended.
  problemTypeBase: "https://github.com/sectigo/CF_CTreq#",
};

// How each origin differs, as far as it affects which requests it rejects:
// - x509: its X.509 parser, either Go's crypto/x509 ("go") or
//   certificate-transparency-go's x509 ("ctgo");
// - allowsOptions: it answers CORS preflight (OPTIONS) requests itself;
// - rejectsPrecertSigningCerts: it doesn't support Precertificate Signing Certificates;
// - allowsAnyOrigin: its responses have "Access-Control-Allow-Origin: *";
// - maxBodyBytes: its (default) maximum request body size: fixed in Sunlight, and set
//   by --max_cert_chain_bytes in TesseraCT and --max_cert_chain_size in Trillian.
const ORIGINS = {
  sunlight: { x509: "ctgo", allowsOptions: true, rejectsPrecertSigningCerts: true, allowsAnyOrigin: true, maxBodyBytes: 128 * 1024 },
  tesseract: { x509: "go", allowsOptions: false, rejectsPrecertSigningCerts: false, allowsAnyOrigin: false, maxBodyBytes: 512 * 1024 },
  trillian: { x509: "ctgo", allowsOptions: false, rejectsPrecertSigningCerts: false, allowsAnyOrigin: false, maxBodyBytes: 512000 },
};
// The origins that must all reject a request for it to be rejected, for each
// environment.
const ENVIRONMENTS = {
  sunlight: [ORIGINS.sunlight],
  tesseract: [ORIGINS.tesseract],
  trillian: [ORIGINS.trillian],
  common: Object.values(ORIGINS),
};
// Resolved when the snippet is loaded, so that a wrong environment fails at
// deployment rather than on every request.
const DEFAULT_ORIGINS = originsFor(CONFIG.environment, "CONFIG.environment");
const LOG_ORIGINS = CONFIG.logEnvironments.map((pair, i) => {
  const setting = `CONFIG.logEnvironments[${i}]`;
  if (!Array.isArray(pair) || pair.length !== 2 || !(pair[0] instanceof RegExp)) {
    throw new Error(`${setting} must be a [regular expression, environment] pair`);
  }
  return [pair[0], originsFor(pair[1], `${setting}'s environment`)];
});

function originsFor(environment, setting) {
  if (!Object.hasOwn(ENVIRONMENTS, environment)) {
    const names = Object.keys(ENVIRONMENTS).map((e) => JSON.stringify(e));
    throw new Error(`${setting} must be ${names.slice(0, -1).join(", ")}, or ${names.at(-1)}, not ${JSON.stringify(environment)}`);
  }
  return ENVIRONMENTS[environment];
}

// Returns the origins of the environment for a request's URL.
function originsForLog(url) {
  const log = url.hostname + url.pathname;
  for (const [pattern, origins] of LOG_ORIGINS) {
    // search() ignores lastIndex, so a pattern with the g or y flag matches every time.
    if (log.search(pattern) !== -1) {
      return origins;
    }
  }
  return DEFAULT_ORIGINS;
}

// OIDs as keys from oidKey(), i.e. their minimal encodings (without tag and length).
const OID_CT_POISON = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x03"; // 1.3.6.1.4.1.11129.2.4.3
const OID_CT_PRECERT_SIGNING = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x04"; // 1.3.6.1.4.1.11129.2.4.4
const OID_EXT_KEY_USAGE = "\x55\x1d\x25"; // 2.5.29.37
const NULL_VALUE = "\x05\x00";

// Standard, padded base64 (RFC 4648 section 4); atob() alone is more lenient. Go's
// decoder also skips CR and LF anywhere, so those are removed before testing this.
// With a length that is a multiple of 4, this is equivalent to
// /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/, but faster.
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const LINE_BREAKS = /[\r\n]/g;
// Go's encoding/json matches keys to struct fields case-insensitively. The /i flag
// without /u folds ASCII letters only, which is all that Go folds onto "chain".
const CHAIN_KEY = /^chain$/i;
const JSON_WHITESPACE = " \t\n\r";

// Returns the last top-level key in the text of a JSON object (already known to be
// valid JSON) that Go's encoding/json would decode into the "chain" field, or
// undefined. Go uses the last of several such keys, whatever their case. JSON.parse()
// keeps the last value of each key, but doesn't reveal the order of keys that differ
// only in case, so the order is found by scanning the text.
function lastChainKey(text) {
  let last;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      // Skip to the closing quote: the next one not escaped by an odd number of
      // backslashes.
      const start = i;
      let escaped;
      do {
        i = text.indexOf('"', i + 1);
        let backslash = i;
        while (text.charCodeAt(backslash - 1) === 0x5c) {
          backslash--;
        }
        escaped = (i - backslash) % 2 === 1;
      } while (escaped);
      let next = i + 1;
      while (JSON_WHITESPACE.includes(text[next])) {
        next++;
      }
      // A string at depth 1 followed by a colon is a top-level key. Only one with an
      // escape needs decoding.
      if (depth === 1 && text[next] === ":") {
        const raw = text.slice(start + 1, i);
        const key = raw.includes("\\") ? JSON.parse(text.slice(start, i + 1)) : raw;
        if (CHAIN_KEY.test(key)) {
          last = key;
        }
      }
    } else if (c === 0x7b || c === 0x5b) {
      depth++; // { or [
    } else if (c === 0x7d || c === 0x5d) {
      depth--; // } or ]
    }
  }
  return last;
}


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

// Decodes a TLV header at index i of a binary string as certificate-transparency-go's
// encoding/asn1 does (it accepts high tag numbers, which DER allows), returning
// { tag, number, length, offset } (tag being the first byte, and number the tag
// number), or null if the header is malformed. Unlike derDecode(), it doesn't check
// that the value fits before end, as that package doesn't for an explicit tag.
function ctgoHeader(data, i, end) {
  if (i >= end) {
    return null;
  }
  const tag = data.charCodeAt(i++);
  let number = tag & 0x1f;
  if (number === 0x1f) {
    number = 0;
    for (let n = 0; ; n++) {
      if (i >= end || n === 5) {
        return null;
      }
      const byte = data.charCodeAt(i++);
      number = number * 128 + (byte & 0x7f);
      if (byte < 0x80) {
        break;
      }
    }
    if (number < 0x1f || number > 0x7fffffff) {
      return null; // Should have used the low tag number form, or too large.
    }
  }
  if (i >= end) {
    return null;
  }
  let length = data.charCodeAt(i++);
  if (length >= 0x80) {
    const n = length & 0x7f;
    if (n === 0) {
      return null; // Indefinite length.
    }
    length = 0;
    for (let j = 0; j < n; j++) {
      if (i >= end || length >= 1 << 23) {
        return null; // Truncated, or too large.
      }
      length = length * 256 + data.charCodeAt(i++);
      if (length === 0) {
        return null; // Leading zero byte.
      }
    }
    if (length < 0x80) {
      return null; // Should have used the short form.
    }
  }
  return { tag, number, length, offset: i };
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

// Returns a key for the OBJECT IDENTIFIER whose contents are at [start, end) of a
// binary string, or null if the origin's X.509 parser would reject it. Both parsers
// reject an arc that is truncated, longer than 5 bytes, or 2^31 or more, but only Go's
// crypto/x509 rejects an empty OID or an arc that isn't minimally encoded (with a
// leading 0x80 byte): certificate-transparency-go's x509 reads such an arc as the
// same number, so e.g. a poison extension's OID needn't be encoded canonically. The
// key is the OID's minimal encoding (without any leading 0x80 bytes), so that two
// OIDs have the same key exactly when they have the same arcs.
function oidKey(der, start, end, origin) {
  if (start === end) {
    return origin.x509 === "go" ? null : "";
  }
  let padded = false;
  let value = 0;
  let length = 0;
  for (let i = start; i < end; i++) {
    const byte = der.charCodeAt(i);
    if (length === 0 && byte === 0x80) {
      if (origin.x509 === "go") {
        return null;
      }
      padded = true;
    }
    if (++length > 5) {
      return null;
    }
    value = value * 128 + (byte & 0x7f);
    if (byte < 0x80) {
      if (value > 0x7fffffff) {
        return null;
      }
      value = 0;
      length = 0;
    }
  }
  if (length !== 0) {
    return null; // Truncated.
  }
  if (!padded) {
    return der.slice(start, end);
  }
  let key = "";
  let arcStart = true;
  for (let i = start; i < end; i++) {
    const byte = der.charCodeAt(i);
    if (!(arcStart && byte === 0x80)) {
      key += der[i];
      arcStart = byte < 0x80;
    }
  }
  return key;
}

// Parses the SEQUENCE of extensions inside a certificate's [3] wrapper, returning
// { oid, critical, value } entries (oid is a key from oidKey(); value is the DER location
// of the extnValue contents) for the extensions that this snippet checks (CT poison and
// extended key usage), in their order in the certificate, or null if any extension is
// malformed, as the origin's X.509 parser would. Only Go's crypto/x509 rejects two
// extensions of the same type.
function certExtensions(cert, list, origin) {
  const extensions = [];
  const seen = origin.x509 === "go" ? new Set() : null;
  for (let at = list.offset; at < list.end; ) {
    const entry = derDecode(cert, at, list.end);
    if (entry === null) {
      return null;
    }
    at = entry.end;
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
    const id = oidKey(cert, oid.offset, oid.end, origin);
    if (id === null || value === null || value.tag !== 0x04 || seen?.has(id)) {
      return null;
    }
    seen?.add(id);
    if (id === OID_CT_POISON || id === OID_EXT_KEY_USAGE) {
      extensions.push({ oid: id, critical, value });
    }
  }
  return extensions;
}

// Parses a certificate into { der, issuer, subject, extensions } (the names being DER
// encodings including headers), or returns null if the origin's X.509 parser would
// reject it. The TBSCertificate is read field by field, as far as the extensions, as
// the origin's parser reads it: the optional unique IDs and extensions are only found
// directly after the public key, and anything after them is ignored.
// - Go's crypto/x509 (TesseraCT) only accepts v1, v2 and v3, and only reads the unique
//   IDs from v2 and v3 certificates and the extensions from v3 certificates.
// - certificate-transparency-go's x509 (Sunlight, Trillian) accepts any version and
//   reads them regardless. Its encoding/asn1 ignores the length of an explicitly
//   tagged field ([0] version, [3] extensions), reading the element after its header
//   instead, and treats [3] as absent if that element isn't a SEQUENCE.
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
  // Moves past the header of an explicitly tagged field, as certificate-transparency-go
  // does, or returns false if it would reject it (for being empty, or having nothing
  // after its header).
  const skipExplicitHeader = (header) => {
    if (header === null || header.length === 0 || header.offset === tbs.end) {
      return false;
    }
    i = header.offset;
    return true;
  };

  // version [0] EXPLICIT INTEGER DEFAULT v1 (0), which may also be encoded explicitly.
  let version = 0;
  if (peek(0xa0)) {
    if (origin.x509 === "go") {
      const wrapper = read(0xa0);
      const integer = wrapper && derDecode(der, wrapper.offset, wrapper.end);
      if (integer === null || integer.tag !== 0x02 || integer.length !== 1 || integer.end !== wrapper.end) {
        return null;
      }
      version = der.charCodeAt(integer.offset);
      if (version > 2) {
        return null; // Unknown (v4 or later) or negative.
      }
    } else if (!skipExplicitHeader(ctgoHeader(der, i, tbs.end)) || read(0x02) === null) {
      return null; // Its value isn't checked, as any version is accepted.
    }
  }
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
  const fields = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30].map(read);
  if (fields.includes(null)) {
    return null;
  }
  const [, signature, issuer, , subject] = fields;
  // Both X.509 parsers require the signature algorithm after the TBSCertificate to be
  // byte-identical to the one inside it.
  const outerSignature = derDecode(der, tbs.end, root.end);
  if (outerSignature?.tag !== 0x30 || der.slice(outerSignature.start, outerSignature.end) !== der.slice(signature.start, signature.end)) {
    return null;
  }
  let extensions = [];
  if (origin.x509 === "go") {
    if (version >= 1) {
      // issuerUniqueID [1] and subjectUniqueID [2], both IMPLICIT and optional.
      if ((peek(0x81) && read(0x81) === null) || (peek(0x82) && read(0x82) === null)) {
        return null;
      }
      if (version === 2 && peek(0xa3)) {
        // As in Go, anything after the SEQUENCE inside [3] is ignored.
        const wrapper = read(0xa3);
        const list = wrapper && derDecode(der, wrapper.offset, wrapper.end);
        extensions = list !== null && list.tag === 0x30 ? certExtensions(der, list, origin) : null;
      }
    }
  } else {
    // certificate-transparency-go parses the header of the next element (if any) for
    // each optional field in turn, rejecting the certificate if it is malformed.
    for (const tag of [0x81, 0x82]) {
      const header = i < tbs.end ? ctgoHeader(der, i, tbs.end) : undefined;
      if (header === null) {
        return null;
      }
      if (header?.tag === tag && read(tag) === null) {
        return null;
      }
    }
    if (i < tbs.end) {
      const header = ctgoHeader(der, i, tbs.end);
      if (header === null || header.offset === tbs.end) {
        return null; // An explicitly tagged field would have nothing after its header.
      }
      if ((header.tag & 0xc0) === 0x80 && header.number === 3 && (header.length === 0 || header.tag & 0x20)) {
        if (!skipExplicitHeader(header)) {
          return null;
        }
        const inner = ctgoHeader(der, i, tbs.end);
        if (inner === null) {
          return null;
        }
        if (inner.tag === 0x30) {
          const list = read(0x30);
          extensions = list && certExtensions(der, list, origin);
        }
      }
    }
  }
  if (extensions === null) {
    return null;
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
    const ids = oids?.map((o) => (o.tag === 0x06 ? oidKey(der, o.offset, o.end, origin) : null));
    return ids !== undefined && !ids.includes(null) && ids.includes(OID_CT_PRECERT_SIGNING);
  });
}

// A rejection, as the argument of errorResponse(). The message is the problem's title,
// which describes the reason; any details of this occurrence go in the detail.
const rejection = (reason, message, status = 400, headers = {}, detail = undefined) => ({ reason, message, status, headers, detail });
// A rejection of the chain entry with the given index, which the detail identifies.
const entryRejection = (reason, message, index, detail) => rejection(reason, message, 400, {}, `chain[${index}] ${detail}`);

// Parses a chain of DER certificates (each already known to be a DER SEQUENCE) as the
// origin's X.509 parser would, returning the parsed certificates, or the index of the
// first one that it would reject.
function parseChain(ders, origin) {
  const certs = [];
  for (const [index, der] of ders.entries()) {
    const parsed = parseCert(der, origin);
    if (parsed === null) {
      return index;
    }
    certs.push(parsed);
  }
  return certs;
}

// Returns the origin's rejection, if any, before checking the accepted roots.
function chainRejection(origin, certs, isPreChainAPI) {
  if (!Array.isArray(certs)) {
    return entryRejection("cert-unparseable", "chain entry cannot be parsed as an X.509 certificate", certs, "cannot be parsed as an X.509 certificate");
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
  for (let i = 0; i < certs.length; i++) {
    if (i + 1 < certs.length && certs[i].issuer !== certs[i + 1].subject) {
      return rejection("issuer-mismatch", "issuer of a certificate does not match the subject of the next certificate in the chain", 400, {}, `the issuer of chain[${i}] does not match the subject of chain[${i + 1}]`);
    }
  }
  return null;
}

// An issuer or the last subject must match an accepted root; stop at the first match.
function rootRejection(certs, roots) {
  if (roots === null) {
    return null;
  }
  for (const cert of certs) {
    if (isRoot(roots, cert.issuer)) {
      return null;
    }
  }
  return isRoot(roots, certs.at(-1).subject) ? null : rejection("root-not-accepted", "chain does not lead to a root that this log accepts");
}

// Returns the 32-bit FNV-1a hash of [start, end) of a binary string.
function nameHash(s, start = 0, end = s.length) {
  let h = 0x811c9dc5;
  for (let i = start; i < end; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
  }
  return h >>> 0;
}

// Returns whether a name's hash is among the roots' (a sorted Uint32Array), by binary
// search. A hash that matches a different name only causes a chain to be forwarded,
// for the origin to reject, so collisions (even contrived ones) are harmless.
function isRoot(roots, name) {
  const h = nameHash(name);
  let lo = 0;
  for (let hi = roots.length; lo < hi; ) {
    const mid = (lo + hi) >>> 1;
    if (roots[mid] < h) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return roots[lo] === h;
}

// Each log's accepted roots, by get-roots URL: { roots, expires }, roots being the
// sorted hashes of their subject names (4 bytes per root), or null if they couldn't be
// read.
const ROOTS_CACHE = new Map();
const MAX_CACHED_LOGS = 100;
// Roots' subjects are mostly within their first 513 bytes (684 base64 characters).
const ROOT_PREFIX_CHARS = 684;
// The largest get-roots response that is read (the largest real ones are about 1 MB),
// so that reading one stays well within the time limit.
const MAX_ROOTS_BYTES = 2 * 1024 * 1024;
const ASCII = new TextDecoder();

// Returns the hashes of the accepted root names of the log that a request (to add-chain
// or add-pre-chain) is for, or null if they are unknown, from the in-memory cache, or else
// the get-roots endpoint, whose response Cloudflare caches too. Only data is shared
// between requests, never a promise, as I/O can't be.
async function rootHashes(url) {
  const rootsUrl = url.origin + url.pathname.slice(0, url.pathname.lastIndexOf("/") + 1) + "get-roots";
  const cached = ROOTS_CACHE.get(rootsUrl);
  if (cached !== undefined && cached.expires > Date.now()) {
    return cached.roots;
  }
  let roots;
  try {
    const response = await fetch(rootsUrl, { cf: { cacheEverything: true, cacheTtlByStatus: { "200-299": CONFIG.rootsCacheSeconds } } });
    roots = await readRootHashes(response);
  } catch {
    return null; // E.g. a network error; not cached, so the next request tries again.
  }
  // Least recently fetched first, so that the oldest is evicted.
  ROOTS_CACHE.delete(rootsUrl);
  if (ROOTS_CACHE.size >= MAX_CACHED_LOGS) {
    ROOTS_CACHE.delete(ROOTS_CACHE.keys().next().value);
  }
  ROOTS_CACHE.set(rootsUrl, { roots, expires: Date.now() + CONFIG.rootsCacheSeconds * 1000 });
  return roots;
}

// Reads a get-roots response, {"certificates":["<base64 DER>",...]}, returning the
// sorted hashes of the roots' subject names, or null if it isn't one. It's streamed,
// and only enough of each root is decoded to find its subject, so that a response of a
// megabyte (hundreds of roots) needs little memory and CPU time. Go's encoding/json escapes no base64
// characters, so each string ends at the next quote. A response larger than
// MAX_ROOTS_BYTES isn't read.
async function readRootHashes(response) {
  if (!response.ok || response.body === null) {
    await response.body?.cancel();
    return null;
  }
  const reader = response.body.getReader();
  const hashes = [];
  let key;
  let pending = new Uint8Array(0);
  let total = 0;
  for (let r = await reader.read(); !r.done; r = await reader.read()) {
    total += r.value.length;
    if (total > MAX_ROOTS_BYTES) {
      await reader.cancel();
      return null;
    }
    let buf = r.value;
    if (pending.length) {
      buf = new Uint8Array(pending.length + r.value.length);
      buf.set(pending);
      buf.set(r.value, pending.length);
    }
    let i = 0;
    for (let open, close; (open = buf.indexOf(0x22, i)) !== -1; i = close + 1) {
      close = buf.indexOf(0x22, open + 1);
      if (close === -1) {
        break;
      }
      const string = buf.subarray(open + 1, close);
      // The first string must be the key, and the rest roots.
      const hash = key === undefined ? ((key = ASCII.decode(string)) === "certificates" ? -1 : null) : rootHash(string);
      if (hash === null) {
        await reader.cancel();
        return null;
      }
      if (hash >= 0) {
        hashes.push(hash);
      }
    }
    pending = buf.subarray(buf.indexOf(0x22, i) === -1 ? buf.length : i);
  }
  return key === undefined ? null : new Uint32Array(hashes).sort();
}

// Returns the hash of a root's subject name from the bytes of its base64 DER, or null
// if it can't be found. Usually, only a prefix needs decoding.
function rootHash(bytes) {
  try {
    let der = atob(ASCII.decode(bytes.subarray(0, ROOT_PREFIX_CHARS)));
    let subject = subjectOf(der);
    if (subject === null && bytes.length > ROOT_PREFIX_CHARS) {
      der = atob(ASCII.decode(bytes));
      subject = subjectOf(der);
    }
    return subject === null ? null : nameHash(der, subject.start, subject.end);
  } catch {
    return null; // Not base64.
  }
}

// Returns the location of the subject name in a DER certificate, or a prefix of one,
// or null if it isn't found there. Roots are trusted to be well-formed, so the
// Certificate and TBSCertificate headers, whose values extend past a prefix, are
// simply skipped.
function subjectOf(der) {
  let i = 0;
  for (let n = 0; n < 2; n++) {
    const length = der.charCodeAt(i + 1);
    i += 2 + (length > 0x80 ? length & 0x7f : 0);
  }
  if (der.charCodeAt(i) === 0xa0) {
    i = derDecode(der, i)?.end ?? der.length; // version
  }
  let field;
  // serialNumber, signature, issuer, validity, subject.
  for (const tag of [0x02, 0x30, 0x30, 0x30, 0x30]) {
    field = derDecode(der, i);
    if (field?.tag !== tag) {
      return null;
    }
    i = field.end;
  }
  return field;
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
// does, so that browsers can read them), rejections do too, except 405 responses,
// which Sunlight's router sends without it.
function errorResponse({ reason, message, status, headers, detail }, origins) {
  const problem = { type: CONFIG.problemTypeBase + reason, title: message, status, ...(detail !== undefined && { detail }) };
  const cors = status !== 405 && origins.some((o) => o.allowsAnyOrigin) ? { "Access-Control-Allow-Origin": "*" } : {};
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

// Returns the rejection, if any, for a request body, the chain's DER certificates (as
// binary strings) if the body should be checked further, or null if it should be
// forwarded unchecked.
function bodyRejectionOrChain(body) {
  const text = new TextDecoder("utf-8", { ignoreBOM: true }).decode(body);
  let json;
  try {
    // Any BOM is kept so that JSON.parse rejects it, as Go's encoding/json does.
    json = JSON.parse(text);
  } catch {
    return rejection("invalid-json", "unable to parse request body");
  }
  // As in Go, if there's more than one chain key (differing only in case), the last is
  // used. (Go also rejects the request if an earlier one isn't a valid chain, but the
  // snippet doesn't check those.) The text only needs scanning for the last one if
  // there are keys with different cases, as JSON.parse keeps the last value of each.
  let chainKey;
  if (json !== null && typeof json === "object" && !Array.isArray(json)) {
    const chainKeys = Object.keys(json).filter((k) => k.length === 5 && CHAIN_KEY.test(k));
    chainKey = chainKeys.length > 1 ? lastChainKey(text) : chainKeys[0];
  }
  const chain = chainKey === undefined ? undefined : json[chainKey];
  if (!Array.isArray(chain) || chain.length === 0) {
    return rejection("chain-missing", "chain is missing or empty");
  }
  if (chain.length > CONFIG.maxChainLength) {
    return null;
  }
  const ders = [];
  for (const [index, entry] of chain.entries()) {
    let base64 = typeof entry === "string" ? entry : null;
    if (base64 !== null && (base64.includes("\n") || base64.includes("\r"))) {
      base64 = base64.replace(LINE_BREAKS, "");
    }
    if (base64 === null || base64.length % 4 !== 0 || !BASE64.test(base64)) {
      return entryRejection("entry-not-base64", "chain entries must be base64 strings", index, "is not a string of standard, padded base64");
    }
    // atob() returns a "binary string" (one char per byte).
    const der = atob(base64);
    if (der.length < CONFIG.minCertBytes) {
      return entryRejection("entry-too-short", "chain entry is too short to be a certificate", index, `is ${der.length} bytes long, fewer than ${CONFIG.minCertBytes}`);
    }
    const root = derDecode(der, 0);
    if (root === null || root.tag !== 0x30 || root.end !== der.length) {
      return entryRejection("entry-not-der", "chain entry is not a DER SEQUENCE of the declared length", index, "is not a DER SEQUENCE of the declared length");
    }
    ders.push(der);
  }
  return ders;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origins = originsForLog(url);
    const isPreChainAPI = isPreChainPath(url.pathname);
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
    // A body is only too large if it's too large for every origin in the environment.
    const maxBodyBytes = CONFIG.maxBodyBytes ?? Math.max(...origins.map((o) => o.maxBodyBytes));
    const contentLength = request.headers.get("Content-Length");
    if (contentLength !== null && Number(contentLength) > maxBodyBytes) {
      return errorResponse(rejection("body-too-large", "request body too large", 413), origins);
    }
    // Started now, so that any fetch of the roots overlaps reading and parsing the body.
    const rootsPromise = rootHashes(url);
    const body = await readBody(request, maxBodyBytes);
    if (body === null) {
      return errorResponse(rejection("body-too-large", "request body too large", 413), origins);
    }

    const ders = bodyRejectionOrChain(body);
    if (ders !== null && !Array.isArray(ders)) {
      return errorResponse(ders, origins);
    }
    // Only reject if every origin in the environment would reject, reporting
    // TesseraCT's reason if it is one of them (else the first origin's). Origins with
    // the same X.509 parser share the parsed chain.
    if (ders !== null) {
      const parsed = new Map();
      for (const origin of origins) {
        if (!parsed.has(origin.x509)) {
          parsed.set(origin.x509, parseChain(ders, origin));
        }
      }
      const rejections = origins.map((origin) => chainRejection(origin, parsed.get(origin.x509), isPreChainAPI));
      if (rejections.some((r) => r === null)) {
        const roots = await rootsPromise;
        for (const [i, origin] of origins.entries()) {
          if (rejections[i] === null) {
            rejections[i] = rootRejection(parsed.get(origin.x509), roots);
          }
        }
      }
      if (rejections.every((r) => r !== null)) {
        return errorResponse(rejections[Math.max(0, origins.indexOf(ORIGINS.tesseract))], origins);
      }
    }

    // The original body stream has been consumed, so forward a copy of its exact bytes.
    return fetch(new Request(request, { body }));
  },
};

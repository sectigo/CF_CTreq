// CF_CTreq - Preprocessor for Certificate Transparency (CT) log API requests
// (RFC6962 and Static CT), implemented in JavaScript as a Cloudflare Snippet.
// Written by Rob Stradling.
// Copyright (C) 2026 Sectigo Limited.
//
// Requests to the add-chain and add-pre-chain endpoints must be POST (else 405) with
// a body (and any Content-Length) of at most CONFIG.maxBodyBytes (else 413). The body
// is parsed as the origin (TesseraCT, using Go's encoding/json) would parse it: the
// "chain" key is matched case-insensitively, and line breaks in base64 are ignored.
// The chain must be a non-empty array of at most CONFIG.maxChainLength base64
// strings, each decoding to at least CONFIG.minCertBytes and to a DER SEQUENCE whose
// declared length matches its actual length (else 400).
//
// Every certificate must then parse as X.509 down to its extensions (RFC 5280),
// else 400, and (as for the origin, extensions are only read from v3 certificates):
// - If the first certificate has the CT poison extension (RFC 6962 section 3.1) it
//   must be critical with a NULL value, and only add-pre-chain is permitted.
//   If it does not, only add-chain is permitted.
// - Each certificate's issuer name must be byte-identical to the subject name of
//   the next certificate in the chain. Signatures are not verified.
// Requests that pass these checks are forwarded to the origin unchanged.

const CONFIG = {
  maxBodyBytes: 128 * 1024,
  maxChainLength: 10,
  minCertBytes: 128,
  // Prefix of the problem details "type" URI; the rejection reason code is appended.
  problemTypeBase: "https://github.com/sectigo/CF_CTreq#",
};

// OID contents (without tag and length) as binary strings.
const OID_CT_POISON = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x03"; // 1.3.6.1.4.1.11129.2.4.3
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

// Parses the extensions inside the [3] wrapper of a v3 certificate into
// { oid, critical, value } entries (value is the DER location of the extnValue
// contents), or returns null if they are malformed, as Go's crypto/x509 would.
function certExtensions(cert, wrapper) {
  // As in Go, anything after the SEQUENCE inside [3] is ignored.
  const list = derDecode(cert, wrapper.offset, wrapper.end);
  const entries = list !== null && list.tag === 0x30 ? derChildren(cert, list) : null;
  if (entries === null) {
    return null;
  }
  const extensions = [];
  for (const entry of entries) {
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    // As in Go, anything after extnValue is ignored.
    const oid = entry.tag === 0x30 ? derDecode(cert, entry.offset, entry.end) : null;
    if (oid === null || oid.tag !== 0x06) {
      return null;
    }
    let critical = false;
    let i = oid.end;
    if (i < entry.end && cert.charCodeAt(i) === 0x01) {
      // Go's crypto/x509 only accepts 0x00 (FALSE) and 0xFF (TRUE).
      const flag = derDecode(cert, i, entry.end);
      const byte = flag?.length === 1 ? cert.charCodeAt(flag.offset) : -1;
      if (byte !== 0x00 && byte !== 0xff) {
        return null;
      }
      critical = byte === 0xff;
      i = flag.end;
    }
    const value = derDecode(cert, i, entry.end);
    const id = cert.slice(oid.offset, oid.end);
    // Go rejects a certificate with more than one extension of the same type.
    if (value === null || value.tag !== 0x04 || extensions.some((e) => e.oid === id)) {
      return null;
    }
    extensions.push({ oid: id, critical, value });
  }
  return extensions;
}

// Parses a certificate into { der, issuer, subject, extensions } (the names being DER
// encodings including headers), or returns null if it is malformed. The TBSCertificate
// is read field by field as Go's crypto/x509 reads it, as far as the extensions: the
// optional unique IDs are only read from v2 and v3 certificates, extensions only from
// v3 certificates and only where Go looks for them, and anything after that is ignored.
function parseCert(der) {
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
    const integer = wrapper && derDecode(der, wrapper.offset, wrapper.end);
    if (integer === null || integer.tag !== 0x02 || integer.length !== 1 || integer.end !== wrapper.end) {
      return null;
    }
    version = der.charCodeAt(integer.offset);
    if (version > 2) {
      return null; // Unknown (v4 or later) or negative.
    }
  }
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
  const fields = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30].map(read);
  if (fields.includes(null)) {
    return null;
  }
  const [, , issuer, , subject] = fields;
  let extensions = [];
  if (version >= 1) {
    // issuerUniqueID [1] and subjectUniqueID [2], both IMPLICIT and optional.
    if ((peek(0x81) && read(0x81) === null) || (peek(0x82) && read(0x82) === null)) {
      return null;
    }
    if (version === 2 && peek(0xa3)) {
      const wrapper = read(0xa3);
      extensions = wrapper && certExtensions(der, wrapper);
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
function errorResponse(reason, message, status = 400, headers = {}) {
  const problem = { type: CONFIG.problemTypeBase + reason, title: message, status };
  return new Response(JSON.stringify(problem) + "\n", {
    status,
    headers: { "Content-Type": "application/problem+json", "X-CTreq-Reject": reason, ...headers },
  });
}

export default {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    let isPreChainAPI;
    if (path.endsWith("/ct/v1/add-chain")) {
      isPreChainAPI = false;
    } else if (path.endsWith("/ct/v1/add-pre-chain")) {
      isPreChainAPI = true;
    } else {
      return fetch(request);
    }

    if (request.method !== "POST") {
      return errorResponse("method-not-allowed", "method not allowed; use POST", 405, { Allow: "POST" });
    }

    const contentLength = request.headers.get("Content-Length");
    if (contentLength !== null && Number(contentLength) > CONFIG.maxBodyBytes) {
      return errorResponse("body-too-large", "request body too large", 413);
    }

    const body = await readBody(request, CONFIG.maxBodyBytes);
    if (body === null) {
      return errorResponse("body-too-large", "request body too large", 413);
    }

    let json;
    try {
      // Keep any BOM so that JSON.parse rejects it, as Go's encoding/json does.
      json = JSON.parse(new TextDecoder("utf-8", { ignoreBOM: true }).decode(body));
    } catch {
      return errorResponse("invalid-json", "unable to parse request body");
    }
    const chainKeys = json !== null && typeof json === "object" ? Object.keys(json).filter((k) => CHAIN_KEY.test(k)) : [];
    // Go would use whichever such key comes last in the body, which JSON.parse can't
    // reveal when their cases differ, so a request with more than one is rejected.
    if (chainKeys.length > 1) {
      return errorResponse("chain-ambiguous", "more than one chain key, differing only in case");
    }
    const chain = chainKeys.length === 1 ? json[chainKeys[0]] : undefined;
    if (!Array.isArray(chain) || chain.length === 0) {
      return errorResponse("chain-missing", "chain is missing or empty");
    }
    if (chain.length > CONFIG.maxChainLength) {
      return errorResponse("chain-too-long", "chain has too many entries");
    }
    const certs = [];
    for (const entry of chain) {
      const base64 = typeof entry === "string" ? entry.replace(LINE_BREAKS, "") : null;
      if (base64 === null || !BASE64.test(base64)) {
        return errorResponse("entry-not-base64", "chain entries must be base64 strings");
      }
      // atob() returns a "binary string" (one char per byte).
      const cert = atob(base64);
      if (cert.length < CONFIG.minCertBytes) {
        return errorResponse("entry-too-short", "chain entry is too short to be a certificate");
      }
      const root = derDecode(cert, 0);
      if (root === null || root.tag !== 0x30 || root.end !== cert.length) {
        return errorResponse("entry-not-der", "chain entry is not a DER SEQUENCE of the declared length");
      }
      const parsed = parseCert(cert);
      if (parsed === null) {
        return errorResponse("cert-unparseable", "chain entry cannot be parsed as an X.509 certificate");
      }
      certs.push(parsed);
    }

    const { der: firstDer, extensions } = certs[0];
    const poison = extensions.find((e) => e.oid === OID_CT_POISON);
    if (poison !== undefined) {
      if (!poison.critical || firstDer.slice(poison.value.offset, poison.value.end) !== NULL_VALUE) {
        return errorResponse("poison-invalid", "CT poison extension must be critical and contain NULL");
      }
    }
    const hasPoison = poison !== undefined;
    if (hasPoison && !isPreChainAPI) {
      return errorResponse("precert-on-add-chain", "precertificate submitted to add-chain; use add-pre-chain");
    }
    if (!hasPoison && isPreChainAPI) {
      return errorResponse("cert-on-add-pre-chain", "certificate submitted to add-pre-chain; use add-chain");
    }
    for (let i = 0; i + 1 < certs.length; i++) {
      if (certs[i].issuer !== certs[i + 1].subject) {
        return errorResponse("issuer-mismatch", "issuer of a certificate does not match the subject of the next certificate in the chain");
      }
    }

    // The original body stream has been consumed, so forward a copy of its exact bytes.
    return fetch(new Request(request, { body }));
  },
};

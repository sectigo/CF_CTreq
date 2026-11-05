// CF_CTreq - Preprocessor for Certificate Transparency (CT) log API requests
// (RFC6962 and Static CT), implemented in JavaScript as a Cloudflare Snippet.
// Written by Rob Stradling.
// Copyright (C) 2026 Sectigo Limited.
//
// Cloudflare Snippet that preprocesses Certificate Transparency (RFC 6962)
// add-chain and add-pre-chain POST requests.
//
// Requests to these endpoints must be POST (else 405) with a Content-Type of
// application/json (else 415) and a Content-Length of at most CONFIG.maxBodyBytes
// (else 413). The chain must be a non-empty array of at most CONFIG.maxChainLength
// base64 strings, each decoding to at least CONFIG.minCertBytes and to a DER
// SEQUENCE whose declared length matches its actual length (else 400).
//
// The first certificate is then parsed down to its extensions (RFC 5280):
// - If the CT poison extension (RFC 6962 section 3.1) is present it must be
//   critical with a NULL value, and only add-pre-chain is permitted.
//   If it is absent, only add-chain is permitted.
// - A poisoned certificate must not also contain an embedded SCT list.
// - On add-chain, the second certificate must not be a Precertificate Signing
//   Certificate (RFC 6962 section 3.1), which can only sign precertificates.
// - If there is a second certificate, the first certificate's issuer name must be
//   byte-identical to its subject name. Signatures are not verified.
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
const OID_CT_SCT_LIST = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02"; // 1.3.6.1.4.1.11129.2.4.2
const OID_CT_PRECERT_SIGNING = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x04"; // 1.3.6.1.4.1.11129.2.4.4
const OID_EXT_KEY_USAGE = "\x55\x1d\x25"; // 2.5.29.37
const NULL_VALUE = "\x05\x00";

// Standard, padded base64 (RFC 4648 section 4); atob() alone is more lenient.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Decodes the DER TLV header at index i of a binary string. Returns null if the
// header is malformed, or if the value would extend past end.
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
    if (n === 0 || n > 4 || offset + n > end) {
      return null;
    }
    length = 0;
    for (let j = 0; j < n; j++) {
      length = length * 256 + data.charCodeAt(offset++);
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

// Decodes the fields of an X.509 TBSCertificate, or returns null if it is malformed.
function tbsFields(cert) {
  const root = derDecode(cert, 0);
  const tbs = root && derDecode(cert, root.offset, root.end);
  return tbs && tbs.tag === 0x30 ? derChildren(cert, tbs) : null;
}

// Returns the DER encodings (including headers) of the issuer and subject names,
// or null if the TBSCertificate is malformed.
function certNames(cert) {
  const fields = tbsFields(cert);
  if (fields === null) {
    return null;
  }
  const i = fields[0]?.tag === 0xa0 ? 1 : 0; // Skip the optional [0] version.
  const issuer = fields[i + 2]; // After serialNumber and signature.
  const subject = fields[i + 4]; // After validity.
  if (issuer?.tag !== 0x30 || subject?.tag !== 0x30) {
    return null;
  }
  return {
    issuer: cert.slice(issuer.start, issuer.end),
    subject: cert.slice(subject.start, subject.end),
  };
}

// Parses the extensions of an X.509 certificate into { oid, critical, value } entries
// (value is the DER location of the extnValue contents). Returns [] if the certificate
// has no extensions, or null if the certificate or its extensions are malformed.
function certExtensions(cert) {
  const fields = tbsFields(cert);
  if (fields === null) {
    return null;
  }
  const wrapper = fields.find((f) => f.tag === 0xa3); // [3] EXPLICIT Extensions
  if (wrapper === undefined) {
    return [];
  }
  const list = derDecode(cert, wrapper.offset, wrapper.end);
  const entries = list !== null && list.tag === 0x30 && list.end === wrapper.end ? derChildren(cert, list) : null;
  if (entries === null) {
    return null;
  }
  const extensions = [];
  for (const entry of entries) {
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    const parts = entry.tag === 0x30 ? derChildren(cert, entry) : null;
    if (parts === null || parts.length < 2 || parts.length > 3 || parts[0].tag !== 0x06 || parts.at(-1).tag !== 0x04) {
      return null;
    }
    if (parts.length === 3 && (parts[1].tag !== 0x01 || parts[1].length !== 1)) {
      return null;
    }
    extensions.push({
      oid: cert.slice(parts[0].offset, parts[0].end),
      critical: parts.length === 3 && cert.charCodeAt(parts[1].offset) !== 0,
      value: parts.at(-1),
    });
  }
  return extensions;
}

// A malformed certificate is treated as not being one; the origin will reject it.
function isPrecertSigningCert(cert) {
  const eku = certExtensions(cert)?.find((e) => e.oid === OID_EXT_KEY_USAGE);
  if (eku === undefined) {
    return false;
  }
  const list = derDecode(cert, eku.value.offset, eku.value.end);
  const oids = list !== null && list.tag === 0x30 ? derChildren(cert, list) : null;
  return oids !== null && oids.some((o) => o.tag === 0x06 && cert.slice(o.offset, o.end) === OID_CT_PRECERT_SIGNING);
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

    const mediaType = (request.headers.get("Content-Type") ?? "").split(";")[0].trim().toLowerCase();
    if (mediaType !== "application/json") {
      return errorResponse("unsupported-media-type", "unsupported media type; use application/json", 415);
    }

    const contentLength = request.headers.get("Content-Length");
    if (contentLength !== null && Number(contentLength) > CONFIG.maxBodyBytes) {
      return errorResponse("body-too-large", "request body too large", 413);
    }

    const body = await request.text();

    let chain;
    try {
      chain = JSON.parse(body).chain;
    } catch {
      return errorResponse("invalid-json", "unable to parse request body");
    }
    if (!Array.isArray(chain) || chain.length === 0) {
      return errorResponse("chain-missing", "chain is missing or empty");
    }
    if (chain.length > CONFIG.maxChainLength) {
      return errorResponse("chain-too-long", "chain has too many entries");
    }
    const certs = [];
    for (const entry of chain) {
      if (typeof entry !== "string" || !BASE64.test(entry)) {
        return errorResponse("entry-not-base64", "chain entries must be base64 strings");
      }
      // atob() returns a "binary string" (one char per byte).
      const cert = atob(entry);
      if (cert.length < CONFIG.minCertBytes) {
        return errorResponse("entry-too-short", "chain entry is too short to be a certificate");
      }
      const root = derDecode(cert, 0);
      if (root === null || root.tag !== 0x30 || root.end !== cert.length) {
        return errorResponse("entry-not-der", "chain entry is not a DER SEQUENCE of the declared length");
      }
      certs.push(cert);
    }

    const extensions = certExtensions(certs[0]);
    if (extensions === null) {
      return errorResponse("cert-unparseable", "unable to parse the extensions of the first certificate");
    }
    const poison = extensions.find((e) => e.oid === OID_CT_POISON);
    if (poison !== undefined) {
      if (!poison.critical || certs[0].slice(poison.value.offset, poison.value.end) !== NULL_VALUE) {
        return errorResponse("poison-invalid", "CT poison extension must be critical and contain NULL");
      }
      if (extensions.some((e) => e.oid === OID_CT_SCT_LIST)) {
        return errorResponse("poison-with-sct-list", "precertificate must not contain an embedded SCT list");
      }
    }
    const hasPoison = poison !== undefined;
    if (hasPoison && !isPreChainAPI) {
      return errorResponse("precert-on-add-chain", "precertificate submitted to add-chain; use add-pre-chain");
    }
    if (!hasPoison && isPreChainAPI) {
      return errorResponse("cert-on-add-pre-chain", "certificate submitted to add-pre-chain; use add-chain");
    }
    if (!isPreChainAPI && certs.length > 1 && isPrecertSigningCert(certs[1])) {
      return errorResponse("psc-on-add-chain", "precertificate signing certificate submitted as the issuer to add-chain");
    }
    if (certs.length > 1) {
      const leaf = certNames(certs[0]);
      if (leaf === null) {
        return errorResponse("issuer-unparseable", "unable to parse the issuer name of the first certificate");
      }
      // An unparseable second certificate is left for the origin to reject.
      const issuer = certNames(certs[1]);
      if (issuer !== null && leaf.issuer !== issuer.subject) {
        return errorResponse("issuer-mismatch", "issuer of the first certificate does not match the subject of the second");
      }
    }

    // The original body stream has been consumed, so forward a copy.
    return fetch(new Request(request, { body }));
  },
};

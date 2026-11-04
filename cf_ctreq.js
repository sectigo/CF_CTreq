// Cloudflare Snippet that preprocesses Certificate Transparency (RFC 6962)
// add-chain and add-pre-chain POST requests.
//
// The first certificate in the submitted chain is scanned for the byte
// sequence of a DER encoded CT Poison extension (RFC 6962 section 3.1):
//
//   30 13                                  SEQUENCE (Extension)
//     06 0a 2b 06 01 04 01 d6 79 02 04 03  OID 1.3.6.1.4.1.11129.2.4.3
//     01 01 ff                             BOOLEAN TRUE (critical)
//     04 02 05 00                          OCTET STRING { NULL }
//
// Requests to these endpoints must be POST (else 405) with a Content-Type of
// application/json (else 415) and a Content-Length of at most MAX_BODY_BYTES
// (else 413). The chain must be a non-empty array of at most MAX_CHAIN_LENGTH
// base64 strings, each decoding to at least MIN_CERT_BYTES and to a DER
// SEQUENCE whose declared length matches its actual length (else 400).
// If a critical CT Poison extension is present, only add-pre-chain is
// permitted. If it is absent, only add-chain is permitted.
// Requests that pass these checks are forwarded to the origin unchanged.

const CT_POISON_EXTENSION = String.fromCharCode(
  0x30, 0x13,
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x03,
  0x01, 0x01, 0xff,
  0x04, 0x02, 0x05, 0x00,
);

const MAX_BODY_BYTES = 128 * 1024;
const MAX_CHAIN_LENGTH = 10;
const MIN_CERT_BYTES = 128;
// Standard, padded base64 (RFC 4648 section 4); atob() alone is more lenient.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Total size implied by a DER SEQUENCE header, or -1 if the header is not valid.
// Callers must ensure bytes is at least 6 characters long.
function derSequenceSize(bytes) {
  if (bytes.charCodeAt(0) !== 0x30) {
    return -1;
  }
  const first = bytes.charCodeAt(1);
  if (first < 0x80) {
    return 2 + first;
  }
  // 0x80 is indefinite length, which DER forbids; more than 4 length bytes is implausible.
  const n = first & 0x7f;
  if (n === 0 || n > 4) {
    return -1;
  }
  let length = 0;
  for (let i = 0; i < n; i++) {
    length = length * 256 + bytes.charCodeAt(2 + i);
  }
  return 2 + n + length;
}

function errorResponse(message, status = 400, headers = {}) {
  return new Response(message + "\n", {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...headers },
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
      return errorResponse("method not allowed; use POST", 405, { Allow: "POST" });
    }

    const mediaType = (request.headers.get("Content-Type") ?? "").split(";")[0].trim().toLowerCase();
    if (mediaType !== "application/json") {
      return errorResponse("unsupported media type; use application/json", 415);
    }

    const contentLength = request.headers.get("Content-Length");
    if (contentLength !== null && Number(contentLength) > MAX_BODY_BYTES) {
      return errorResponse("request body too large", 413);
    }

    const body = await request.text();

    let chain;
    try {
      chain = JSON.parse(body).chain;
    } catch {
      return errorResponse("unable to parse request body");
    }
    if (!Array.isArray(chain) || chain.length === 0) {
      return errorResponse("chain is missing or empty");
    }
    if (chain.length > MAX_CHAIN_LENGTH) {
      return errorResponse("chain has too many entries");
    }
    let firstCert;
    for (const entry of chain) {
      if (typeof entry !== "string" || !BASE64.test(entry)) {
        return errorResponse("chain entries must be base64 strings");
      }
      // atob() returns a "binary string" (one char per byte).
      const cert = atob(entry);
      if (cert.length < MIN_CERT_BYTES) {
        return errorResponse("chain entry is too short to be a certificate");
      }
      if (derSequenceSize(cert) !== cert.length) {
        return errorResponse("chain entry is not a DER SEQUENCE of the declared length");
      }
      firstCert ??= cert;
    }

    const hasPoison = firstCert.includes(CT_POISON_EXTENSION);
    if (hasPoison && !isPreChainAPI) {
      return errorResponse("precertificate submitted to add-chain; use add-pre-chain");
    }
    if (!hasPoison && isPreChainAPI) {
      return errorResponse("certificate submitted to add-pre-chain; use add-chain");
    }

    // The original body stream has been consumed, so forward a copy.
    return fetch(new Request(request, { body }));
  },
};

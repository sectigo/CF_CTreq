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
// If the poison extension is present, only add-pre-chain is permitted.
// If it is absent, only add-chain is permitted.
// Requests that pass these checks are forwarded to the origin unchanged.

const CT_POISON_EXTENSION = String.fromCharCode(
  0x30, 0x13,
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x03,
  0x01, 0x01, 0xff,
  0x04, 0x02, 0x05, 0x00,
);

function errorResponse(message) {
  return new Response(message + "\n", {
    status: 400,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return fetch(request);
    }

    const path = new URL(request.url).pathname;
    let isPreChainAPI;
    if (path.endsWith("/ct/v1/add-chain")) {
      isPreChainAPI = false;
    } else if (path.endsWith("/ct/v1/add-pre-chain")) {
      isPreChainAPI = true;
    } else {
      return fetch(request);
    }

    const body = await request.text();

    let firstCert;
    try {
      const chain = JSON.parse(body).chain;
      if (!Array.isArray(chain) || chain.length === 0 || typeof chain[0] !== "string") {
        return errorResponse("chain is missing or empty");
      }
      // atob() returns a "binary string" (one char per byte).
      firstCert = atob(chain[0]);
    } catch {
      return errorResponse("unable to parse request body");
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

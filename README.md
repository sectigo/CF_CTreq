# CF_CTreq

## What is it?

CF_CTreq is a preprocessor for Certificate Transparency (CT) log API requests (RFC6962 and Static CT), implemented in JavaScript as a [Cloudflare Snippet](https://developers.cloudflare.com/rules/snippets/).

## Why is it needed?

A large volume of malformed log API requests might overwhelm the origin's error logging.  It's better to deal with malformed requests at the CDN edge wherever possible.

## How does it work?

Requests to the `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` endpoints are checked in the following order, and rejected if any check fails:

- `405 Method Not Allowed` (with an `Allow: POST` header) if the method is not `POST`.
- `415 Unsupported Media Type` if the `Content-Type` is not `application/json`.
- `413 Content Too Large` if the `Content-Length` exceeds 128 KiB (checked before the body is read).
- `400 Bad Request` if the body is not valid JSON.
- `400 Bad Request` if `chain` is missing/empty.
- `400 Bad Request` if `chain` has more than 10 entries, or any entry is not a standard padded base64 string, or decodes to fewer than 128 bytes.
- `400 Bad Request` if the first certificate in `chain` contains the byte sequence of a DER encoded, critical CT Poison extension (OID `1.3.6.1.4.1.11129.2.4.3`) and the request was sent to `add-chain`.
- `400 Bad Request` if the first certificate does not contain the poison extension and the request was sent to `add-pre-chain`.

All other requests (and valid submissions) are forwarded to the origin unchanged.

Further checks may be added in the future.

## Deployment

Create a Snippet in the Cloudflare dashboard with the contents of [`cf_ctreq.js`](cf_ctreq.js), and attach a rule that matches the log's `add-chain` and `add-pre-chain` endpoints, e.g.:

```
ends_with(http.request.uri.path, "/ct/v1/add-chain") or ends_with(http.request.uri.path, "/ct/v1/add-pre-chain")
```

## Testing

Requires Node.js 18 or later (no dependencies):

```
npm test
```

# CF_CTreq

## What is it?

CF_CTreq is a preprocessor for Certificate Transparency (CT) log API requests (RFC6962 and Static CT), implemented in JavaScript as a [Cloudflare Snippet](https://developers.cloudflare.com/rules/snippets/).

## Why is it needed?

A large volume of malformed log API requests might overwhelm the origin's error logging.  It's better to deal with malformed requests at the CDN edge wherever possible.

## How does it work?

Requests to the `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` endpoints are rejected with `405 Method Not Allowed` (with an `Allow: POST` header) unless they are `POST`, and with `415 Unsupported Media Type` unless the `Content-Type` is `application/json`.

For valid `POST` requests, the first certificate in the submitted `chain` is scanned for the byte sequence of a DER encoded, critical CT Poison extension (OID `1.3.6.1.4.1.11129.2.4.3`):

- If the poison extension is present, the request is rejected with `400 Bad Request` unless it was sent to `add-pre-chain`.
- If it is absent, the request is rejected with `400 Bad Request` unless it was sent to `add-chain`.
- Requests whose body is not valid JSON, or whose `chain` is missing/empty or whose first entry is not valid base64, are rejected with `400 Bad Request`.

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

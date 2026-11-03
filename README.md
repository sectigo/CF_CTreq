# ct-snippet

A [Cloudflare Snippet](https://developers.cloudflare.com/rules/snippets/) that
preprocesses Certificate Transparency ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962))
log submission requests before they reach the origin.

For `POST` requests to `.../ct/v1/add-chain` and `.../ct/v1/add-pre-chain`, the
first certificate in the submitted `chain` is scanned for the byte sequence of
a DER encoded, critical CT Poison extension (OID `1.3.6.1.4.1.11129.2.4.3`):

- If the poison extension is present, the request is rejected with `400 Bad Request`
  unless it was sent to `add-pre-chain`.
- If it is absent, the request is rejected with `400 Bad Request` unless it was
  sent to `add-chain`.
- Requests whose body is not valid JSON, or whose `chain` is missing/empty or
  whose first entry is not valid base64, are rejected with `400 Bad Request`.

All other requests (and valid submissions) are forwarded to the origin unchanged.

## Deployment

Create a Snippet in the Cloudflare dashboard with the contents of
[`snippet.js`](snippet.js), and attach a rule that matches the log's
`add-chain` and `add-pre-chain` endpoints, e.g.:

```
http.request.method eq "POST" and (ends_with(http.request.uri.path, "/ct/v1/add-chain") or ends_with(http.request.uri.path, "/ct/v1/add-pre-chain"))
```

## Testing

Requires Node.js 18 or later (no dependencies):

```
npm test
```

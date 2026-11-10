# CF_CTreq

## Contents

- [What is it?](#what-is-it)
- [Why is it needed?](#why-is-it-needed)
- [How does it work?](#how-does-it-work)
  - [Origin environment](#origin-environment)
  - [Rejection responses](#rejection-responses)
  - [Rejection reasons](#rejection-reasons)
    - [`method-not-allowed`](#method-not-allowed), [`body-too-large`](#body-too-large), [`invalid-json`](#invalid-json), [`chain-missing`](#chain-missing), [`chain-too-long`](#chain-too-long), [`entry-not-base64`](#entry-not-base64), [`entry-too-short`](#entry-too-short), [`entry-not-der`](#entry-not-der), [`cert-unparseable`](#cert-unparseable), [`poison-invalid`](#poison-invalid), [`precert-on-add-chain`](#precert-on-add-chain), [`cert-on-add-pre-chain`](#cert-on-add-pre-chain), [`psc-not-supported`](#psc-not-supported), [`issuer-mismatch`](#issuer-mismatch)
  - [Checks that are not done](#checks-that-are-not-done)
- [Deployment](#deployment)
  - [Limits](#limits)
- [Monitoring rejections](#monitoring-rejections)
  - [Cloudflare dashboard](#cloudflare-dashboard)
  - [Logging the header](#logging-the-header)
  - [Elastic](#elastic)
  - [Grafana](#grafana)
- [Testing](#testing)
  - [Testing a deployed log](#testing-a-deployed-log)

## What is it?

CF_CTreq is a preprocessor for Certificate Transparency (CT) log API requests (RFC6962 and Static CT), implemented in JavaScript as a [Cloudflare Snippet](https://developers.cloudflare.com/rules/snippets/).

## Why is it needed?

A CT log's `add-chain` and `add-pre-chain` endpoints have to be open to anyone on the Internet: any CA, monitor or researcher must be able to submit a certificate, without authentication.  That openness means a log also receives a steady stream of requests that it can never accept: truncated or mangled JSON, chains that aren't valid base64 or DER, precertificates sent to the wrong endpoint, chains in the wrong order, and so on, from buggy clients, misconfigured CAs, scanners and deliberate abuse.  A single faulty client in a retry loop can send them by the million.

Every one of those requests costs the origin something, even though it will be rejected:

- **Capacity**: the origin reads the body, decodes the JSON and parses the certificates before it can reject the request, using the same CPU, memory, bandwidth and connections that valid submissions need.
- **Error logging**: rejected submissions are logged, sometimes with the whole request.  A large volume of malformed requests can bury real problems, inflate storage and alerting costs, or overwhelm the logging pipeline altogether.
- **Collateral damage**: if the origin has to shed load or apply rate limits, legitimate CAs can be slowed down or turned away along with the junk.

CF_CTreq stops these requests at the CDN edge instead, before they reach the origin:

- **It never turns away a valid submission.**  Each check mirrors the origin's own parsing and rejection criteria, so it only rejects requests that the origin would reject anyway (see [How does it work?](#how-does-it-work)), and it forwards everything else byte for byte.
- **It is cheap and fast.**  It runs as a Cloudflare Snippet, typically in about 0.05 ms per request, and well within a Snippet's 5 ms limit even for the largest requests (see [Limits](#limits)).
- **It helps submitters fix their mistakes.**  Each rejection says precisely what is wrong, as a JSON problem details object, with a reason code that links to its explanation below.
- **It makes the problem visible.**  The reason code is also in an `X-CTreq-Reject` header, so rejections can be counted and charted by cause (see [Monitoring rejections](#monitoring-rejections)), showing which clients are misbehaving and how.

## How does it work?

Requests to the `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` endpoints are checked in the order of the [rejection reasons](#rejection-reasons) below, and are rejected at the first check that fails.  As the origin's router (Go's `http.ServeMux`, in TesseraCT, Sunlight and Trillian) does, each segment of the path is percent-decoded before matching, so e.g. `/ct/v1/add%2Dchain` is also checked.  All other requests (and valid submissions) are forwarded to the origin unchanged.  The limits mentioned below, and the [origin environment](#origin-environment), are set in the `CONFIG` object at the top of [`cf_ctreq.js`](cf_ctreq.js).

The body is interpreted as the origin would interpret it, so that the snippet neither rejects a request that the origin would accept nor checks a different chain from the one the origin would use.  For example, the `Content-Type` is not checked, the `chain` key is matched regardless of the case of its letters, and line breaks in base64 are ignored.

### Origin environment

The origins differ slightly in what they reject, so `CONFIG.environment` selects whose rejection criteria apply:

| `environment` | Rejects |
|---|---|
| `common` (default) | Only what TesseraCT, Sunlight and Trillian would all reject, so it is safe in front of any of them. |
| `tesseract` | What [TesseraCT](https://github.com/transparency-dev/tesseract) would reject (it uses Go's `encoding/json` and `crypto/x509`). |
| `sunlight` | What [Sunlight](https://github.com/FiloSottile/sunlight) would reject (it uses Go's `encoding/json`, and `certificate-transparency-go`'s `x509` package). |
| `trillian` | What the [Trillian](https://github.com/google/certificate-transparency-go/tree/master/trillian) CT front end (CTFE) would reject (it uses Go's `encoding/json`, and `certificate-transparency-go`'s `x509` package). |

All the origins parse the request body in the same way, but they differ as follows, so these checks depend on the environment:

| Request | TesseraCT | Sunlight | Trillian | `common` |
|---|---|---|---|---|
| `OPTIONS` (CORS preflight) | `method-not-allowed` | answered by Sunlight | `method-not-allowed` | forwarded |
| Certificate whose version is not v1, v2 or v3, or is not minimally encoded | `cert-unparseable` | accepted | accepted | forwarded |
| Certificate with two extensions of the same type | `cert-unparseable` | accepted | accepted | forwarded |
| Extension whose OID is empty or not minimally encoded (an arc with a leading `0x80` byte) | `cert-unparseable` | accepted, and decoded as if minimally encoded | accepted, and decoded as if minimally encoded | forwarded, unless all would reject the request regardless |
| `[0]` (version) or `[3]` (extensions) whose declared length doesn't match the element inside it, or `[3]` containing something other than a `SEQUENCE` | `cert-unparseable` | length ignored, and such a `[3]` treated as absent | length ignored, and such a `[3]` treated as absent | forwarded, unless all would reject the request regardless |
| Malformed header, or an empty element at the end of the TBSCertificate, after the public key | ignored | `cert-unparseable` | `cert-unparseable` | forwarded |
| Extensions in a v1 or v2 certificate | ignored | read, as in a v3 certificate | read, as in a v3 certificate | forwarded, unless all would reject the request regardless |
| Precertificate issued by a Precertificate Signing Certificate | accepted | `psc-not-supported` | accepted | forwarded |

In the `common` environment, the snippet checks the request against each origin's criteria, and only rejects it if all of them would, with the TesseraCT reason.

### Rejection responses

Every rejection response has an `X-CTreq-Reject` header containing a short reason code, so that rejections can be analysed in Cloudflare logs.  The body is a JSON [problem details](https://www.rfc-editor.org/rfc/rfc9457) object (`Content-Type: application/problem+json`) whose `type` is `https://github.com/sectigo/CF_CTreq#` followed by the reason code (so the URL leads to that reason's description below), whose `title` is a short description, and whose `status` repeats the HTTP status code, e.g.:

```json
{"type":"https://github.com/sectigo/CF_CTreq#poison-invalid","title":"CT poison extension must be critical and contain NULL","status":400}
```

When a particular chain entry is at fault (for `entry-not-base64`, `entry-too-short`, `entry-not-der`, `cert-unparseable` and `issuer-mismatch`), the object also has a `detail` that identifies it by its index in `chain`, e.g.:

```json
{"type":"https://github.com/sectigo/CF_CTreq#cert-unparseable","title":"chain entry cannot be parsed as an X.509 certificate","status":400,"detail":"chain[1] cannot be parsed as an X.509 certificate"}
```

In the `sunlight` and `common` environments, rejection responses (other than `405` ones, which Sunlight's router sends without it) also have an `Access-Control-Allow-Origin: *` header, as Sunlight's responses do, so that browser-based clients can read them.

### Rejection reasons

#### method-not-allowed

`405 Method Not Allowed`, with an `Allow` header, if the method is not `POST` (or, in the `sunlight` and `common` environments, `OPTIONS`).

#### body-too-large

`413 Content Too Large` if the `Content-Length` exceeds 128 KiB, which is checked before the body is read, or if the body itself turns out to exceed 128 KiB (e.g. when it is sent without a `Content-Length`), in which case reading stops at the limit.

#### invalid-json

`400 Bad Request` if the body is not valid JSON (including when it starts with a byte order mark).

#### chain-missing

`400 Bad Request` if `chain` is missing, is not an array, or is empty.  As for the origin, `chain` is matched regardless of the case of its letters, and if there is more than one such key (e.g. both `chain` and `Chain`), the last one is used.  (The origin would also reject the request if an earlier one isn't a valid chain, but the snippet doesn't check those.)

#### chain-too-long

`400 Bad Request` if `chain` has more than 10 entries.

#### entry-not-base64

`400 Bad Request` if any `chain` entry is not a string containing standard, padded base64.  Line breaks (`\r` and `\n`) anywhere in the string are ignored.

#### entry-too-short

`400 Bad Request` if any `chain` entry decodes to fewer than 128 bytes.

#### entry-not-der

`400 Bad Request` if any `chain` entry does not start with a DER `SEQUENCE` tag (`0x30`), its DER length is not minimally encoded, or its declared DER length does not match its decoded length.

#### cert-unparseable

`400 Bad Request` if any certificate in `chain` (not only the first) cannot be parsed as X.509 as far as its issuer and subject names and its extensions.  The TBSCertificate is read field by field as the origin's X.509 parser reads it: as in DER, every length must be minimally encoded, and an extension's `critical` flag, if present, must be `0x00` or `0xFF`.  The optional unique IDs and the extensions are only read directly after the public key; any extensions elsewhere are ignored, by this and the following checks, as is anything after the extensions or after an extension's value.  As described [above](#origin-environment), TesseraCT also requires the version to be v1, v2 or v3 and no two extensions to have the same OID, and only reads extensions from v3 certificates.  Each extension's OID is decoded as the origin's X.509 parser decodes it, and its arcs must not be truncated, longer than 5 bytes, or 2<sup>31</sup> or more; extensions (such as CT Poison) are then identified by their decoded OID, so that e.g. a non-minimally encoded poison OID counts as one for Sunlight and Trillian, which accept it.  Sunlight and Trillian's `encoding/asn1` also ignores the declared length of the explicitly tagged `[0]` (version) and `[3]` (extensions) fields, reading the element after their header instead, treats `[3]` as absent if that element isn't a `SEQUENCE`, and rejects a malformed header after the public key (or an element there with nothing after its header), as described [above](#origin-environment).

#### poison-invalid

`400 Bad Request` if the first certificate has a CT Poison extension (OID `1.3.6.1.4.1.11129.2.4.3`) that is not critical or whose value is not `NULL`.

#### precert-on-add-chain

`400 Bad Request` if the first certificate has a CT Poison extension and the request was sent to `add-chain`.

#### cert-on-add-pre-chain

`400 Bad Request` if the first certificate has no CT Poison extension and the request was sent to `add-pre-chain`.

#### psc-not-supported

`400 Bad Request`, in the `sunlight` environment only, if the first certificate has a CT Poison extension and the second certificate is a Precertificate Signing Certificate (extended key usage `1.3.6.1.4.1.11129.2.4.4`).  Sunlight doesn't support them, as [c2sp.org/static-ct-api@v1.1.0](https://c2sp.org/static-ct-api@v1.1.0) allows.

#### issuer-mismatch

`400 Bad Request` if a certificate in `chain` has an issuer name that is not byte-identical to the subject name of the next certificate in `chain`.  Signatures are not verified.

### Checks that are not done

As far as possible, the snippet aims to only reject requests that the origin would also reject, so that it never stops a submission from being logged.  Further checks may be added in the future, but the following checks are deliberately not done:

- **`Content-Type`**: RFC 6962 doesn't require a particular `Content-Type`, and none of the origins checks it, so a client that omits it or sends e.g. `text/plain` must still succeed.
- **Signatures, and chaining to an accepted root**: verifying signatures needs the public key algorithms and the log's root list, and is the most expensive part of chain validation, so it is left to the origin.  `issuer-mismatch` only compares names.
- **The log's acceptance policy**: TesseraCT can be configured to reject certificates by expiry date (`not_after_start`, `not_after_limit`, `reject_expired`, `reject_unexpired`), extended key usage, extension, intermediate, or SHA-1 signature; Trillian similarly by expiry date, extended key usage, extension, intermediate, or (to accept only CA certificates) the CA flag; and Sunlight by expiry date, or by blocked public key, and it requires the first certificate to have the `serverAuth` extended key usage (or, for a log of mark certificates, the Verified Mark Certificate one).  Repeating these checks would duplicate each log's configuration in the snippet, where it could drift out of sync.
- **Precertificate Signing Certificate as the issuer on `add-chain`**: RFC 6962 says that a Precertificate Signing Certificate (extended key usage `1.3.6.1.4.1.11129.2.4.4`) can only sign precertificates, so a certificate that one has issued is misissued.  But none of the origins checks extended key usage along the chain (TesseraCT's [`lax509`](https://github.com/transparency-dev/tesseract/blob/main/internal/lax509/README.md) deliberately skips it, so that misissued certificates can be logged and thereby discovered).  On `add-pre-chain`, only Sunlight rejects one ([`psc-not-supported`](#psc-not-supported)).
- **Embedded SCT list in a precertificate**: a precertificate with an embedded SCT list (OID `1.3.6.1.4.1.11129.2.4.2`) makes little sense, but none of the origins rejects one.
- **Certificate fields other than the names and extensions**: the contents of the serial number, signature algorithm, validity, public key and signature are not checked, and nor is anything after the extensions or after an extension's value (which all the origins also ignore).  Checking them would add code for little benefit, because the origin rejects a certificate that it can't parse.

The snippet's `CONFIG` limits are stricter than the origins' defaults: TesseraCT accepts a body of up to 512 KiB (Trillian, 512,000 bytes; Sunlight, 128 KiB) and all of them accept any number of chain entries, whereas the snippet's limits are 128 KiB (`body-too-large`) and 10 entries (`chain-too-long`), which are enough for real certificate chains.  None of the origins has a minimum certificate size, but the snippet's 128-byte minimum (`entry-too-short`) can't reject a chain that the origin would accept: every certificate in such a chain either has a valid signature from the next certificate in a path to a trusted root, or is byte-identical to one of the log's roots, so its names, public key and signature alone make it much larger than that.

## Deployment

Create a Snippet in the Cloudflare dashboard with the contents of [`cf_ctreq.js`](cf_ctreq.js), first setting `CONFIG.environment` to `tesseract`, `sunlight` or `trillian` if the log runs that software (or leaving it as `common`; see [Origin environment](#origin-environment)), and attach a rule that matches the log's `add-chain` and `add-pre-chain` endpoints, e.g.:

```
ends_with(http.request.uri.path, "/ct/v1/add-chain") or ends_with(http.request.uri.path, "/ct/v1/add-pre-chain")
```

The snippet forwards every request that isn't for an `add-chain` or `add-pre-chain` path unchanged, so a broader rule (up to "All incoming requests") won't cause any additional requests to be rejected.  (Matching only those two paths is recommended though: it avoids running the snippet on other traffic, so that traffic never passes through the snippet's `fetch()`).

Keep **Normalize incoming URLs** turned on (under **Rules** > **Settings** > **URL Normalization**; it is on by default).  The origin also routes percent-encoded forms of these paths, such as `/ct/v1/add%2Dchain`, to the same endpoints, and [URL normalization](https://developers.cloudflare.com/rules/normalization/how-it-works/) decodes them before the rule above is evaluated.  If it were turned off, the rule wouldn't match them, so they would reach the origin without being checked.

### Limits

Cloudflare [limits](https://developers.cloudflare.com/rules/snippets/#limits) a Snippet to 5 ms of execution time, 2 MB of memory and 32 KB of code; [`cf_ctreq.js`](cf_ctreq.js) is about 27 KB.  Measured with Node.js on a typical machine, a typical request takes about 0.05 ms, and the slowest requests allowed by the 128 KiB body limit (such as one certificate with about 10,000 extensions, or a body with thousands of JSON keys) take about 2 ms in the `common` environment, which parses each certificate with both X.509 parsers.

## Monitoring rejections

Every rejection carries an [`X-CTreq-Reject`](#rejection-responses) response header, so counting rejections by reason is a matter of getting that header into your logs.  This section is based on the Cloudflare, Elastic and Grafana documentation and has not been tested end to end.

### Cloudflare dashboard

[Custom dashboards](https://developers.cloudflare.com/analytics/custom-dashboards/) can chart HTTP traffic for the log's hostname, with the status code and path as dimensions or filters.  Rejections appear there as `405`, `413` and `400` responses on the two endpoints.  That gives volumes and trends, but not the reason: most reasons share `400`, which the origin also uses for its own errors.

The reason is only available in logs.  For a per-reason breakdown, log the header (below) and either chart it in your log tool, or, if you have [Log Explorer](https://developers.cloudflare.com/log-explorer/) (which is being merged into Observability Logs), check whether its `http_requests` dataset contains the `ResponseHeaders` field.

### Logging the header

The header is added to a response generated by the Snippet, so it only reaches logs if it is configured as a Logpush [custom field](https://developers.cloudflare.com/logs/logpush/logpush-job/custom-fields/) (per zone):

1. In the dashboard, go to **Observability** > **Export** > **Logpush**, select the **Configuration** tab, and under **Custom log fields** choose **Edit Custom Fields** > **Set new Custom Field**.  Set the type to *Response Header* and the name to `x-ctreq-reject` (header names must be lower case).  Alternatively, use the Rulesets API: a rule with action `log_custom_field` and `"response_fields": [{"name": "x-ctreq-reject"}]` in the zone's `http_log_custom_fields` phase.
2. Create a Logpush job for the `http_requests` dataset whose `field_names` include `ResponseHeaders`, for example:

```
curl "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/logpush/jobs" \
	--request POST \
	--header "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
	--json '{
		"name": "ctreq-rejections",
		"destination_conf": "<DESTINATION>",
		"dataset": "http_requests",
		"output_options": {
			"field_names": [
				"RayID", "EdgeStartTimestamp", "ClientRequestHost", "ClientRequestMethod",
				"ClientRequestPath", "EdgeResponseStatus", "OriginResponseStatus",
				"MatchedRules", "ResponseHeaders"
			],
			"timestamp_format": "rfc3339"
		},
		"enabled": true
	}'
```

Each logged request then has `"ResponseHeaders": {"x-ctreq-reject": "<reason>"}`.  `OriginResponseStatus` is `0` when Cloudflare answered without contacting the origin, as the Snippet does when it rejects a request, and `MatchedRules` lists the Cloudflare Rules products (including snippets) that matched.  Logpush [filters](https://developers.cloudflare.com/logs/logpush/logpush-job/filters/) and sampling can reduce the volume.  Response headers are logged as transformed values by default; the raw variant, which is only configurable through the API, refers to headers received from the origin.

### Elastic

Cloudflare supports Elastic as a Logpush destination (see [Enable Elastic](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/elastic/)), via the Elastic Cloudflare Logpush integration:

1. Create the Logpush job above, delivering to an object store that the Elastic Agent reads (S3 with SQS is the mode Elastic recommends; R2, GCS and Azure Blob Storage also work), or to an HTTPS endpoint hosted by the Elastic Agent (default port `9560`; set the same secret header on the job's `destination_conf` as `header_<name>=<value>` and in the integration).
2. In Kibana, add the **Cloudflare Logpush** integration and enable the `http_request` data stream with the matching collection method.  It comes with a prebuilt HTTP Request dashboard.
3. The header is stored in the `flattened` field `cloudflare_logpush.http_request.response.headers`, next to `cloudflare_logpush.http_request.edge.response.status` and `cloudflare_logpush.http_request.client.request.path`.  In Discover, `cloudflare_logpush.http_request.response.headers.x-ctreq-reject : *` selects the rejections.  For charts, break down by that sub-field path; if your visualisation tool will not aggregate on a `flattened` sub-field, copy the value into a keyword field with a runtime field or an `@custom` ingest pipeline.

### Grafana

Cloudflare does not list Grafana or Loki as a Logpush destination, so there are two routes:

- **Through Elastic**: add an Elasticsearch data source in Grafana for the `logs-cloudflare_logpush.http_request-*` data stream, and group a time series by the `cloudflare_logpush.http_request.response.headers.x-ctreq-reject` terms (the same `flattened` sub-field caveat applies).
- **Into Loki**: either send Logpush to an HTTPS endpoint that you operate (it must accept `POST`, present a trusted certificate and check the secret `header_*` value) and forward to Loki, which needs a component that converts Cloudflare's batches into Loki's push format; or use Grafana Alloy's [`loki.source.cloudflare`](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.cloudflare/), which pulls logs from Cloudflare's Logpull API with `fields_type = "all"` (or `additional_fields = ["ResponseHeaders"]`).  Cloudflare describes Logpull as a legacy feature that is only available on the Enterprise plan, and does not say that custom fields apply to it, so check that `ResponseHeaders` contains the header before relying on this route.  Extract the value in LogQL with `| json`.

## Testing

Requires Node.js 18 or later (no dependencies):

```
npm test
```

The tests also run on [GitHub Actions](.github/workflows/test.yml) for every push and pull request, in each [origin environment](#origin-environment), on Node.js 18, the current LTS version and the latest version.  Besides checking behaviour, they check that [`cf_ctreq.js`](cf_ctreq.js) stays within a Snippet's [size and time limits](#limits).

To also print every certificate chain the tests submit (decoded with `openssl x509`, which must be installed) and how the snippet responds to it, use npm's verbose flag:

```
npm test --verbose
```

The tests use the snippet's own `CONFIG.environment`, unless `CTREQ_ENVIRONMENT` selects another [origin environment](#origin-environment) (applied to a copy of the snippet loaded by the tests; `cf_ctreq.js` itself isn't changed):

```
CTREQ_ENVIRONMENT=sunlight npm test
```

Whichever environment is selected, one test also checks the differences between all of them.

### Testing a deployed log

To check a deployed snippet end to end, set `CTREQ_LOG_URL` to the log's base URL (including any path prefix such as a shard name), and `CTREQ_ENVIRONMENT` to the deployed snippet's environment if it differs from that of the local `cf_ctreq.js`:

```
CTREQ_LOG_URL=https://ct.example.com/2026h1 CTREQ_ENVIRONMENT=tesseract npm test
```

Each request that the local snippet rejects is then also sent to that URL, which must answer with the same status and `X-CTreq-Reject` reason.  Requests that the snippet would forward to the origin are never sent, so nothing is submitted to the log; those cases are only checked locally, and each test reports which requests were sent.  Only the paths under the base URL ending in `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` are used.

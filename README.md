# CF_CTreq

## What is it?

CF_CTreq is a preprocessor for Certificate Transparency (CT) log API requests (RFC6962 and Static CT), implemented in JavaScript as a [Cloudflare Snippet](https://developers.cloudflare.com/rules/snippets/).

## Why is it needed?

A large volume of malformed log API requests might overwhelm the origin's error logging.  It's better to deal with malformed requests at the CDN edge wherever possible.

## How does it work?

Requests to the `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` endpoints are checked in the order of the [rejection reasons](#rejection-reasons) below, and are rejected at the first check that fails.  All other requests (and valid submissions) are forwarded to the origin unchanged.  The limits mentioned below are set in the `CONFIG` object at the top of [`cf_ctreq.js`](cf_ctreq.js).

### Rejection responses

Every rejection response has an `X-CTreq-Reject` header containing a short reason code, so that rejections can be analysed in Cloudflare logs.  The body is a JSON [problem details](https://www.rfc-editor.org/rfc/rfc9457) object (`Content-Type: application/problem+json`) whose `type` is `https://github.com/sectigo/CF_CTreq#` followed by the reason code (so the URL leads to that reason's description below), whose `title` is a short description, and whose `status` repeats the HTTP status code, e.g.:

```json
{"type":"https://github.com/sectigo/CF_CTreq#poison-invalid","title":"CT poison extension must be critical and contain NULL","status":400}
```

### Rejection reasons

#### method-not-allowed

`405 Method Not Allowed`, with an `Allow: POST` header, if the method is not `POST`.

#### unsupported-media-type

`415 Unsupported Media Type` if the `Content-Type` is not `application/json`.

#### body-too-large

`413 Content Too Large` if the `Content-Length` exceeds 128 KiB.  This is checked before the body is read.

#### invalid-json

`400 Bad Request` if the body is not valid JSON.

#### chain-missing

`400 Bad Request` if `chain` is missing, is not an array, or is empty.

#### chain-too-long

`400 Bad Request` if `chain` has more than 10 entries.

#### entry-not-base64

`400 Bad Request` if any `chain` entry is not a string containing standard, padded base64.

#### entry-too-short

`400 Bad Request` if any `chain` entry decodes to fewer than 128 bytes.

#### entry-not-der

`400 Bad Request` if any `chain` entry does not start with a DER `SEQUENCE` tag (`0x30`), or its declared DER length does not match its decoded length.

#### cert-unparseable

`400 Bad Request` if any certificate in `chain` (not only the first) cannot be parsed as X.509 as far as its issuer and subject names and its extensions.

#### poison-invalid

`400 Bad Request` if the first certificate has a CT Poison extension (OID `1.3.6.1.4.1.11129.2.4.3`) that is not critical or whose value is not `NULL`.

#### poison-with-sct-list

`400 Bad Request` if the first certificate has a CT Poison extension and also an embedded SCT list (OID `1.3.6.1.4.1.11129.2.4.2`).

#### precert-on-add-chain

`400 Bad Request` if the first certificate has a CT Poison extension and the request was sent to `add-chain`.

#### cert-on-add-pre-chain

`400 Bad Request` if the first certificate has no CT Poison extension and the request was sent to `add-pre-chain`.

#### psc-on-add-chain

`400 Bad Request` if the request was sent to `add-chain` and the second certificate is a Precertificate Signing Certificate (extended key usage `1.3.6.1.4.1.11129.2.4.4`).

#### issuer-mismatch

`400 Bad Request` if a certificate in `chain` has an issuer name that is not byte-identical to the subject name of the next certificate in `chain`.  Signatures are not verified.

Further checks may be added in the future.

## Deployment

Create a Snippet in the Cloudflare dashboard with the contents of [`cf_ctreq.js`](cf_ctreq.js), and attach a rule that matches the log's `add-chain` and `add-pre-chain` endpoints, e.g.:

```
ends_with(http.request.uri.path, "/ct/v1/add-chain") or ends_with(http.request.uri.path, "/ct/v1/add-pre-chain")
```

The snippet forwards every request that isn't for an `add-chain` or `add-pre-chain` path unchanged, so a broader rule (up to "All incoming requests") won't cause any additional requests to be rejected.  (Matching only those two paths is recommended though: it avoids running the snippet on other traffic, so that traffic never passes through the snippet's `fetch()`).

## Monitoring rejections

Every rejection carries an [`X-CTreq-Reject`](#rejection-responses) response header, so counting rejections by reason is a matter of getting that header into your logs.  This section is based on the Cloudflare, Elastic and Grafana documentation and has not been tested end to end.

### Cloudflare dashboard

[Custom dashboards](https://developers.cloudflare.com/analytics/custom-dashboards/) can chart HTTP traffic for the log's hostname, with the status code and path as dimensions or filters.  Rejections appear there as `405`, `413`, `415` and `400` responses on the two endpoints.  That gives volumes and trends, but not the reason: most reasons share `400`, which the origin also uses for its own errors.

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

To also print every certificate chain the tests submit (decoded with `openssl x509`, which must be installed) and how the snippet responds to it, use npm's verbose flag:

```
npm test --verbose
```

### Testing a deployed log

To check a deployed snippet end to end, set `CTREQ_LOG_URL` to the log's base URL (including any path prefix such as a shard name):

```
CTREQ_LOG_URL=https://ct.example.com/2026h1 npm test
```

Each request that the local snippet rejects is then also sent to that URL, which must answer with the same status and `X-CTreq-Reject` reason.  Requests that the snippet would forward to the origin are never sent, so nothing is submitted to the log; those cases are only checked locally, and each test reports which requests were sent.  Only the paths under the base URL ending in `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` are used.

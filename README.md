# CF_CTreq [![Tests](https://github.com/sectigo/CF_CTreq/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/sectigo/CF_CTreq/actions/workflows/test.yml) [![Differential tests](https://github.com/sectigo/CF_CTreq/actions/workflows/differential.yml/badge.svg?branch=main)](https://github.com/sectigo/CF_CTreq/actions/workflows/differential.yml) [![Origin drift](https://github.com/sectigo/CF_CTreq/actions/workflows/drift.yml/badge.svg?branch=main)](https://github.com/sectigo/CF_CTreq/actions/workflows/drift.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sectigo/CF_CTreq/badge)](https://scorecard.dev/viewer/?uri=github.com/sectigo/CF_CTreq) [![Release](https://img.shields.io/github/v/release/sectigo/CF_CTreq)](https://github.com/sectigo/CF_CTreq/releases/latest) [![License: GPL-3.0](https://img.shields.io/github/license/sectigo/CF_CTreq)](LICENSE) [![Cloudflare Snippet](https://img.shields.io/badge/Cloudflare-Snippet-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/rules/snippets/)

## Contents

- [What is it?](#what-is-it)
- [Why is it needed?](#why-is-it-needed)
- [How does it work?](#how-does-it-work)
  - [Origin environment](#origin-environment)
  - [Rejection responses](#rejection-responses)
  - [Rejection reasons](#rejection-reasons)
    - [`method-not-allowed`](#method-not-allowed), [`body-too-large`](#body-too-large), [`invalid-json`](#invalid-json), [`chain-missing`](#chain-missing), [`entry-not-base64`](#entry-not-base64), [`entry-too-short`](#entry-too-short), [`entry-not-der`](#entry-not-der), [`cert-unparseable`](#cert-unparseable), [`poison-invalid`](#poison-invalid), [`precert-on-add-chain`](#precert-on-add-chain), [`cert-on-add-pre-chain`](#cert-on-add-pre-chain), [`psc-not-supported`](#psc-not-supported), [`issuer-mismatch`](#issuer-mismatch), [`root-not-accepted`](#root-not-accepted)
  - [Checks that are not done](#checks-that-are-not-done)
- [Deployment](#deployment)
  - [Accepted roots](#accepted-roots)
  - [Limits](#limits)
- [Monitoring rejections](#monitoring-rejections)
  - [Cloudflare dashboard](#cloudflare-dashboard)
  - [Logging the header](#logging-the-header)
  - [Elastic](#elastic)
  - [Grafana](#grafana)
- [Testing](#testing)
  - [Differential tests](#differential-tests)
  - [Running the snippet locally](#running-the-snippet-locally)
  - [Testing a deployed log](#testing-a-deployed-log)
    - [Rejections](#rejections), [Forwarding](#forwarding), [Resubmission](#resubmission)

## What is it?

CF_CTreq is an edge validator for Certificate Transparency (CT) log submissions (RFC 6962 and Static CT), implemented in JavaScript as a [Cloudflare Snippet](https://developers.cloudflare.com/rules/snippets/).  It rejects `add-chain` and `add-pre-chain` requests at the edge when the log would reject them anyway, and forwards everything else unchanged.

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

If one Snippet serves several logs that run different software, `CONFIG.logEnvironments` selects the environment for each log: it is a list of `[regular expression, environment, roots URL]` entries, and a request uses the environment of the first entry whose regular expression matches its hostname followed by its path (e.g. `tiger2027h1.ct.sectigo.com/ct/v1/add-chain`), or else `CONFIG.environment`.  So a log can be identified by its hostname or by a path prefix.  The optional roots URL serves a list of the hashes of the log's accepted roots' subject names (see [Accepted roots](#accepted-roots)), which are only checked for logs that have one, e.g.:

```js
logEnvironments: [
  [/^(tiger|elephant)\d{4}h[12]\.ct\.example\.com\//, "trillian", "https://roots.example.net/accepted-roots.txt"],
  [/^ct\.example\.com\/2027h1\//, "sunlight"],
],
```

It lists Sectigo's [logs](https://github.com/sectigo/CTLogs) by default (TesseraCT for Monument, Statue, Billboard and Standee, and Trillian for Elephant, Tiger, Dumbo and Tigger), without roots URLs, which doesn't affect other logs.  A misspelt environment, here or in `CONFIG.environment`, or a roots URL that isn't a URL or that the log's own regular expression matches, makes the Snippet fail as soon as it is deployed.

All the origins parse the request body in the same way, but they differ as follows, so these checks depend on the environment:

| Request | TesseraCT | Sunlight | Trillian | `common` |
|---|---|---|---|---|
| `OPTIONS` (CORS preflight) | `method-not-allowed` | answered by Sunlight | `method-not-allowed` | forwarded |
| Body of more than 128 KiB, up to 512,000 bytes | accepted | `body-too-large` | accepted | forwarded |
| Body of more than 512,000 bytes, up to 512 KiB | accepted | `body-too-large` | `body-too-large` | forwarded |
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

`413 Content Too Large`, as the origin responds, if the `Content-Length` exceeds the limit, which is checked before the body is read or roots are fetched, or if the body itself turns out to exceed it (e.g. when it is sent without a `Content-Length`), in which case reading stops at the limit.  The limit is the origin's default: 128 KiB for Sunlight (which can't be changed), 512 KiB for TesseraCT (`--max_cert_chain_bytes`) and 512,000 bytes for Trillian (`--max_cert_chain_size`, though its handlers also limit every `POST` body to 512 KiB, so a larger setting has no effect), and 512 KiB in the `common` environment.  If the origin is configured with a different limit, set `CONFIG.maxBodyBytes` to it.

#### invalid-json

`400 Bad Request` if the body is not valid JSON (including when it starts with a byte order mark).

#### chain-missing

`400 Bad Request` if `chain` is missing, is not an array, or is empty.  As for the origin, `chain` is matched regardless of the case of its letters, and if there is more than one such key (e.g. both `chain` and `Chain`), the last one is used.  (The origin would also reject the request if an earlier one isn't a valid chain, but the snippet doesn't check those.)

A `chain` of more than 10 entries (`CONFIG.maxChainLength`) is forwarded to the origin without any further checks.  Real chains have at most about 5 (the longest among 86,000 recent entries in all the logs in Google's log list), but the origins accept longer ones (TesseraCT any number, and Trillian up to 100, as does Sunlight once built with a version of `certificate-transparency-go` from November 2026 or later), and checking them would only spend the Snippet's limited CPU time on requests that hardly ever occur.

#### entry-not-base64

`400 Bad Request` if any `chain` entry is not a string containing standard, padded base64.  Line breaks (`\r` and `\n`) anywhere in the string are ignored.

#### entry-too-short

`400 Bad Request` if any `chain` entry decodes to fewer than 128 bytes.

#### entry-not-der

`400 Bad Request` if any `chain` entry does not start with a DER `SEQUENCE` tag (`0x30`), its DER length is not minimally encoded, or its declared DER length does not match its decoded length.

#### cert-unparseable

`400 Bad Request` if any certificate in `chain` (not only the first) cannot be parsed as X.509 as far as its issuer and subject names and its extensions.  The TBSCertificate is read field by field as the origin's X.509 parser reads it: as in DER, every length must be minimally encoded, an extension's `critical` flag, if present, must be `0x00` or `0xFF`, and the signature algorithm after the TBSCertificate must be byte-identical to the one inside it.  The optional unique IDs and the extensions are only read directly after the public key; any extensions elsewhere are ignored, by this and the following checks, as is anything after the extensions or after an extension's value.  As described [above](#origin-environment), TesseraCT also requires the version to be v1, v2 or v3 and no two extensions to have the same OID, and only reads extensions from v3 certificates.  Each extension's OID is decoded as the origin's X.509 parser decodes it, and its arcs must not be truncated, longer than 5 bytes, or 2<sup>31</sup> or more; extensions (such as CT Poison) are then identified by their decoded OID, so that e.g. a non-minimally encoded poison OID counts as one for Sunlight and Trillian, which accept it.  Sunlight and Trillian's `encoding/asn1` also ignores the declared length of the explicitly tagged `[0]` (version) and `[3]` (extensions) fields, reading the element after their header instead, treats `[3]` as absent if that element isn't a `SEQUENCE`, and rejects a malformed header after the public key (or an element there with nothing after its header), as described [above](#origin-environment).

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

#### root-not-accepted

`400 Bad Request` if `chain` doesn't lead to one of the log's accepted roots: no certificate in `chain` has an issuer name that is byte-identical to the subject name of an accepted root, and nor is `chain` just one certificate with such a subject name.  The origins find a chain's root by name in the same way (TesseraCT, Sunlight and Trillian all require the root's subject name to match the issuer name of the certificate that it signs), and only accept the chain if it is the submitted chain, perhaps followed by the root.  Only names are compared, so a chain may still be rejected by the origin, e.g. if a signature is invalid.  The lookup stops at the first certificate whose issuer is an accepted root, so the certificates after it aren't checked against the roots (but must still meet [`issuer-mismatch`](#issuer-mismatch)).

This check is only made for logs that `CONFIG.logEnvironments` gives a roots URL: the URL, on another hostname, of a list of the hashes of the log's accepted roots' subject names (see [Accepted roots](#accepted-roots) for how to generate and configure one).  It isn't made for logs whose entry has no roots URL (or `""` or `null`), or that use `CONFIG.environment`.  The snippet can't read the log's own `get-roots` endpoint, as Cloudflare fails a request with [error 1201](https://developers.cloudflare.com/rules/snippets/errors/) ("Snippet tried to continue to origin multiple times") if a Snippet makes more than one request to the origin: forwarding the submission after fetching `get-roots` from the log's hostname would always fail.  So a roots URL that the log's own regular expression matches makes the Snippet fail as soon as it is deployed, and one on the requested hostname is ignored.

The fetch starts while the request body is read, but the snippet doesn't wait for it if every origin already rejects the chain for another reason. The hashes are kept in a sorted `Uint32Array` (4 bytes per root), which is searched by binary search (about 10 comparisons for 700 roots).  A name whose hash matches a root's, but which isn't the root's name, only makes the snippet forward the chain, for the origin to reject as it would without the snippet, so hash collisions (even contrived ones) can never cause a false rejection.  The hashes are cached for `CONFIG.rootsCacheSeconds` (60 by default), both in Cloudflare's cache (via the `fetch()` options `cacheEverything` and `cacheTtlByStatus`, so that error responses aren't cached) and in the snippet's memory (for up to 100 logs).  If the list can't be read (e.g. the response is an error, doesn't start with the expected line, has a line that doesn't start with a hash, has no hashes at all, or is larger than 256 KiB), this check is skipped, so the snippet never rejects a chain for want of it (nor rejects every chain because of an empty list); such a response is cached too, but a failed fetch isn't.

### Checks that are not done

As far as possible, the snippet aims to only reject requests that the origin would also reject, so that it never stops a submission from being logged.  Further checks may be added in the future, but the following checks are deliberately not done:

- **`Content-Type`**: RFC 6962 doesn't require a particular `Content-Type`, and none of the origins checks it, so a client that omits it or sends e.g. `text/plain` must still succeed.
- **Signatures**: verifying signatures needs the public key algorithms, and is the most expensive part of chain validation, so it is left to the origin.  `issuer-mismatch` and `root-not-accepted` only compare names.
- **The log's acceptance policy**: TesseraCT can be configured to reject certificates by expiry date (`not_after_start`, `not_after_limit`, `reject_expired`, `reject_unexpired`), extended key usage, extension, intermediate, or SHA-1 signature; Trillian similarly by expiry date, extended key usage, extension, intermediate, or (to accept only CA certificates) the CA flag; and Sunlight by expiry date, or by blocked public key, and it requires the first certificate to have the `serverAuth` extended key usage (or, for a log of mark certificates, the Verified Mark Certificate one).  Repeating these checks would duplicate each log's configuration in the snippet, where it could drift out of sync.
- **Precertificate Signing Certificate as the issuer on `add-chain`**: RFC 6962 says that a Precertificate Signing Certificate (extended key usage `1.3.6.1.4.1.11129.2.4.4`) can only sign precertificates, so a certificate that one has issued is misissued.  But none of the origins checks extended key usage along the chain (TesseraCT's [`lax509`](https://github.com/transparency-dev/tesseract/blob/main/internal/lax509/README.md) deliberately skips it, so that misissued certificates can be logged and thereby discovered).  On `add-pre-chain`, only Sunlight rejects one ([`psc-not-supported`](#psc-not-supported)).
- **Embedded SCT list in a precertificate**: a precertificate with an embedded SCT list (OID `1.3.6.1.4.1.11129.2.4.2`) makes little sense, but none of the origins rejects one.
- **Certificate fields other than the names and extensions**: the contents of the serial number, signature algorithm (beyond matching the one after the TBSCertificate), validity, public key and signature are not checked, and nor is anything after the extensions or after an extension's value (which all the origins also ignore).  Checking them would add code for little benefit, because the origin rejects a certificate that it can't parse.

The snippet's body size limit is the origin's (see [`body-too-large`](#body-too-large)).  None of the origins has a minimum certificate size, but the snippet's 128-byte minimum (`entry-too-short`) can't reject a chain that the origin would accept: every certificate in such a chain either has a valid signature from the next certificate in a path to a trusted root, or is byte-identical to one of the log's roots, so its names, public key and signature alone make it much larger than that.

## Deployment

Set `CONFIG.environment` in [`cf_ctreq.js`](cf_ctreq.js) to `tesseract`, `sunlight` or `trillian` if the log runs that software (or leave it as `common`), or `CONFIG.logEnvironments` if the Snippet serves logs that run different software or their accepted roots are to be checked (see [Origin environment](#origin-environment) and [Accepted roots](#accepted-roots)), and `CONFIG.maxBodyBytes` if the origin's body size limit isn't its default (see [`body-too-large`](#body-too-large)). Then generate the deployment file:

```
npm ci
npm run build
```

This uses [Terser](https://terser.org/) to remove comments, compress code and shorten variable names, writing [`cf_ctreq.min.js`](cf_ctreq.min.js) without changing the readable source. Do not edit the generated file directly. The [minification workflow](.github/workflows/minify.yml) regenerates, tests and commits it to the same branch whenever the source or minifier configuration changes on a push (or when run manually). The workflow needs permission to push to that branch; branch protection rules must allow its bot commits.

Create a Snippet in the Cloudflare dashboard with the contents of [`cf_ctreq.min.js`](cf_ctreq.min.js), and attach a rule that matches the log's `add-chain` and `add-pre-chain` endpoints, e.g.:

```
ends_with(http.request.uri.path, "/ct/v1/add-chain") or ends_with(http.request.uri.path, "/ct/v1/add-pre-chain")
```

The snippet forwards every request that isn't for an `add-chain` or `add-pre-chain` path unchanged, so a broader rule (up to "All incoming requests") won't cause any additional requests to be rejected.  (Matching only those two paths is recommended though: it avoids running the snippet on other traffic, so that traffic never passes through the snippet's `fetch()`).

Keep **Normalize incoming URLs** turned on (under **Rules** > **Settings** > **URL Normalization**; it is on by default).  The origin also routes percent-encoded forms of these paths, such as `/ct/v1/add%2Dchain`, to the same endpoints, and [URL normalization](https://developers.cloudflare.com/rules/normalization/how-it-works/) decodes them before the rule above is evaluated.  If it were turned off, the rule wouldn't match them, so they would reach the origin without being checked.

The snippet makes up to two subrequests per request: one to forward it, and, for a log with a roots URL, at most once per `CONFIG.rootsCacheSeconds` for each copy of the snippet, one to the roots URL.  That is within every plan's [subrequest limit](https://developers.cloudflare.com/rules/snippets/#availability) (2 on Pro), provided that the roots URL isn't redirected.  Only one of them may go to the origin, or else Cloudflare fails the request with error 1201, so the roots URL must be on another hostname (see [Accepted roots](#accepted-roots)); whether one on another hostname in the same Cloudflare zone counts as the origin too isn't documented, so check a new roots URL with the [resubmission](#resubmission) check before relying on it.

### Accepted roots

To check that chains lead to one of a log's accepted roots (see [`root-not-accepted`](#root-not-accepted)), the snippet needs a list of the hashes of the roots' subject names, precalculated so that reading it takes little CPU time even for hundreds of roots.  [`tools/roots-hashes.mjs`](tools/roots-hashes.mjs) generates it from the log's `get-roots` endpoint, or from a file containing a `get-roots` response or a bundle of PEM certificates:

```
npm run roots-hashes -- https://tiger2027h1.ct.sectigo.com/ct/v1/get-roots > tiger2027h1-accepted-roots.txt
```

The list starts with the line `CF_CTreq Accepted Roots v1`, followed by one line per root: the 32-bit [FNV-1a](https://datatracker.ietf.org/doc/html/draft-eastlake-fnv) hash of its DER-encoded subject name (including the tag and length), as 8 hex digits, then (optionally) whitespace and its subject name, for people to read; blank lines, and lines starting with `#`, are ignored.  For example:

```
CF_CTreq Accepted Roots v1
# 232 roots, from https://tiger2027h1.ct.sectigo.com/ct/v1/get-roots
016305c1  OU=GlobalSign Root CA - R6, O=GlobalSign, CN=GlobalSign
01803395  C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com EV Root Certification Authority RSA R2
...
```

Publish the list on a web server on another hostname than the log's (preferably outside the log's Cloudflare zone: see the subrequests paragraph [above](#deployment)), and add its URL to the log's entry in `CONFIG.logEnvironments` as the third element (see [Origin environment](#origin-environment)), e.g.:

```js
[/^tiger2027h1\.ct\.example\.com\//, "trillian", "https://roots.example.net/tiger2027h1-accepted-roots.txt"],
```

Several logs that accept the same roots can share a roots URL, and its list is then fetched and cached once.  After deploying, check the log with the [resubmission](#resubmission) check: it fails if Cloudflare fails the snippet (e.g. with error 1201), or if the snippet rejects any of the log's own recent entries, e.g. because the list is missing one of their roots.

Regenerate and republish the list whenever the log's accepted roots change: if a root is missing from it, chains that lead to that root are rejected, although the log would accept them.  The snippet uses a new list within `CONFIG.rootsCacheSeconds`.

### Limits

Cloudflare [limits](https://developers.cloudflare.com/rules/snippets/#limits) a Snippet to 5 ms of CPU time (time spent waiting for subrequests doesn't count), 2 MB of memory and 32 KB of code. Deploy [`cf_ctreq.min.js`](cf_ctreq.min.js), which is tested against that size limit, rather than the larger readable source. Measured with Node.js on a typical machine (where CPU time is only an approximation of Cloudflare's), a typical request takes about 0.05 ms, and a real certificate as large as the body size limit allows (e.g. one with 20,000 DNS names in 512 KiB) takes about 2 ms.  Only crafted certificates take longer: the slowest that the 128 KiB limit allows (one with about 10,000 extensions) takes about 1 ms in the `sunlight` environment, but the slowest that the 512 KiB limit allows (about 43,000 extensions) takes about 4 ms in the `trillian` environment, 10 ms in the `tesseract` environment (which also checks for duplicate extensions), and 12 ms in the `common` environment (which parses each certificate with both X.509 parsers).  A request that exceeds the CPU time limit fails with Cloudflare [error 1203](https://developers.cloudflare.com/rules/snippets/errors/), rather than being forwarded or rejected.  No CA would issue such a certificate, so a log could only receive one from a client that was testing it; set `CONFIG.maxBodyBytes` to `131072` to keep even those within the limit, at the cost of rejecting larger chains that the origin would accept.

Checking the chain against the cached accepted roots adds no measurable time.  Reading a list of roots, when it isn't cached in memory, adds about 0.1 ms or less, even for 700 roots (about 94 KB): a whole request that reads one takes about 1.5 ms in a fresh copy of the snippet (most of it the snippet's own start-up), and 0.3 ms otherwise.  Reading the roots themselves instead (about 1 MB of certificates for 700 roots) would take about 5 ms, the whole of the time limit.  Each log's cached hashes take about 4 KB of memory, including their cache entry.

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
				"RayID", "EdgeStartTimestamp", "ClientIP", "ClientASN", "ClientRequestHost", "ClientRequestMethod",
				"ClientRequestPath", "ClientRequestUserAgent", "EdgeResponseStatus", "OriginResponseStatus",
				"MatchedRules", "ResponseHeaders"
			],
			"timestamp_format": "rfc3339"
		},
		"enabled": true
	}'
```

Each logged request then has `"ResponseHeaders": {"x-ctreq-reject": "<reason>"}`, and `ClientIP`, `ClientASN` (its network's AS number) and `ClientRequestUserAgent` identify the client that sent it.  `ClientIP` is the address that connected to Cloudflare, so it is the client's own unless the client used a proxy.  IP addresses are personal data under the GDPR, so your retention and privacy policies may need to cover them; logging `ClientASN` without `ClientIP` identifies clients less precisely, but without their addresses.  `OriginResponseStatus` is `0` when Cloudflare answered without contacting the origin, as the Snippet does when it rejects a request, and `MatchedRules` lists the Cloudflare Rules products (including snippets) that matched.  Logpush [filters](https://developers.cloudflare.com/logs/logpush/logpush-job/filters/) and sampling can reduce the volume.  Response headers are logged as transformed values by default; the raw variant, which is only configurable through the API, refers to headers received from the origin.

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

Requires Node.js 22.19 or later (no dependencies):

```
npm test
```

The test output groups related checks into named suites, roughly following the request-validation flow. The tests also run on [GitHub Actions](.github/workflows/test.yml) for every push and pull request, in each [origin environment](#origin-environment), on Node.js 22, the current LTS version and the latest version. Besides checking behaviour, they check the minified file's size and the snippet's CPU time against a Snippet's [limits](#limits).  CPU time is measured with `process.threadCpuUsage()`, taking the fastest of several runs, so that garbage collection and other processes don't cause spurious failures. To run the same behaviour tests against the minified code, including checking that the generated file matches the current source and minifier settings:

```
npm ci
npm run build
npm run test:minified
```

To also print every certificate chain the tests submit (decoded with `openssl x509`, which must be installed) and how the snippet responds to it, use npm's verbose flag:

```
npm test --verbose
```

The tests use the snippet's own `CONFIG.environment`, unless `CTREQ_ENVIRONMENT` selects another [origin environment](#origin-environment) (applied to a copy of the snippet loaded by the tests; `cf_ctreq.js` itself isn't changed):

```
CTREQ_ENVIRONMENT=sunlight npm test
```

Whichever environment is selected, one test also checks the differences between all of them.

### Differential tests

The differential tests check that, in each environment, the snippet never rejects a request that one of that environment's origins would accept.  They generate a corpus of request bodies (10,000 by default) with many structural variants of certificates and chains, JSON and base64, and compare the snippet's response to each, on both endpoints, with the verdicts of [models of the origins](test/differential/origins/main.go) that use the origins' own parsers: Go's `encoding/json`, and Go's `crypto/x509` (TesseraCT) or `certificate-transparency-go`'s `x509` package (Sunlight and Trillian, at the versions in [`versions.json`](test/differential/versions.json)).  The models check names, precertificate status and body size as the origins do, but (like the snippet) don't verify signatures, and nor do they check that the chain leads to an accepted root, so the snippet is given no roots URLs (and so skips [`root-not-accepted`](#root-not-accepted)).  They require Go:

```
npm run test:differential
```

`CTREQ_DIFF_COUNT` and `CTREQ_DIFF_SEED` change the corpus, and `CTREQ_DIFF_SUNLIGHT` and `CTREQ_DIFF_TRILLIAN` the `certificate-transparency-go` versions. Set `CTREQ_DIFF_SNIPPET=cf_ctreq.min.js` to test the generated file instead. They also run on [GitHub Actions](.github/workflows/differential.yml) for every push and pull request, against both the readable source and the minified code.

Generated requests can only explore the variants that the generator knows about, so the tests can also replay real ones: recent entries (256 per log by default) from every usable or qualified log in [Google's log list](https://www.gstatic.com/ct/log_list/v3/log_list.json), both RFC 6962 logs (`get-entries`) and static-ct-api logs (data tiles and issuers), each rebuilt as the `add-chain` or `add-pre-chain` request that could have submitted it and compared in the same way.  This needs network access:

```
npm run test:replay
```

`CTREQ_REPLAY_ENTRIES` changes the number of entries per log, and `CTREQ_REPLAY_LOGS` limits the logs to those whose descriptions contain one of its comma-separated substrings (e.g. `argon,tuscolo`).  [`replay.mjs`](test/differential/replay.mjs) on its own writes the requests as JSON lines.

The origins change over time, so an [origin drift](.github/workflows/drift.yml) workflow also runs weekly (and for pull requests that change the differential tests).  It runs the differential tests and the replay against the latest versions of the origins' parsers (the latest Go, and the `certificate-transparency-go` versions on Sunlight's `main` and Trillian's `master` branches), and it checks whether any of the upstream source files that determine the origins' rejection criteria (listed in [`upstream.json`](test/differential/upstream.json)) have changed since they were last reviewed:

```
node test/differential/upstream.mjs
```

If any of these fails, the workflow opens an issue.  After reviewing upstream changes (and updating the snippet, the origin models or `versions.json` if necessary), record them with `node test/differential/upstream.mjs --update`.

### Running the snippet locally

Cloudflare's [Wrangler](https://developers.cloudflare.com/workers/wrangler/) can run the snippet on your own machine, in Cloudflare's Workers runtime, in front of a real log (it needs no Cloudflare account in this mode):

```
npm run build
npx wrangler dev cf_ctreq.min.js --compatibility-date=2026-11-01 --local-upstream tiger2027h1.ct.sectigo.com --upstream-protocol https
```

Requests to `http://localhost:8787` then go through the snippet, which forwards those that it doesn't reject to the log, e.g.:

```
curl -X POST --data 'not json' http://localhost:8787/ct/v1/add-chain
```

The snippet sees the log's hostname, so `CONFIG.logEnvironments` applies as it would when deployed.  But Wrangler runs it as a Worker, so the limits that only apply to Snippets (such as their CPU time limit, and error 1201 for more than one request to the origin) aren't enforced: check those against a deployed snippet (see below).  Requests that the snippet forwards are real submissions to the log.  Wrangler keeps its local state in `.wrangler/`, which Git ignores.

### Testing a deployed log

Three checks send requests to a deployed snippet, and so to the log behind it.  Each needs `CTREQ_LOG_URL` set to the log's base URL (including any path prefix such as a shard name), and is only run when requested:

| Check | Command | Checks that | Sends to the log | Logs |
|---|---|---|---|---|
| [Rejections](#rejections) | `npm test` with `CTREQ_LOG_URL` and `CTREQ_ENVIRONMENT` set | the deployed snippet rejects requests exactly as the local one does | only requests that the snippet rejects | any |
| [Forwarding](#forwarding) | `npm run test:forwarding` | the snippet can forward a request at all | one request that the log itself rejects | production only |
| [Resubmission](#resubmission) | `npm run test:resubmit` | the snippet forwards real submissions | up to 256 of the log's own entries, which it already has | any |

Cloudflare fails a request with error 1201 ("Snippet tried to continue to origin multiple times") if a snippet makes more than one request to the origin, which only the forwarding and resubmission checks can detect.  Before enabling a new version of the snippet in front of production logs, run the resubmission check against a test log with it enabled, then the forwarding and resubmission checks against a production log as soon as it is enabled there.

#### Rejections

Set `CTREQ_ENVIRONMENT` to the environment that the deployed snippet uses for the log (from `CONFIG.logEnvironments`, or else `CONFIG.environment`), e.g. `trillian` for Sectigo's Tiger:

```
CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com CTREQ_ENVIRONMENT=trillian npm test
```

Each request that the local snippet rejects is then also sent to the log, which must answer with the same status and `X-CTreq-Reject` reason.  Requests that the snippet would forward to the origin are never sent, so nothing is submitted to the log; those cases are only checked locally, and each test reports which requests were sent.  Only the paths under the base URL ending in `/ct/v1/add-chain` and `/ct/v1/add-pre-chain` are used.

#### Forwarding

[`test/forwarding.mjs`](test/forwarding.mjs) checks that the snippet deployed in front of a production log can forward a request:

```
CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com npm run test:forwarding
```

It sends the log one of Google's CT log monitoring certificates, with its intermediate and root, but with the certificate's signature corrupted: the snippet forwards it, and the log itself rejects it, so nothing is logged.  It passes only if the log answers with its own `400 Bad Request`.  Only production logs accept Google's monitoring root, so it first checks the log's `get-roots`, and fails without sending anything if the root isn't there.

#### Resubmission

[`test/resubmit.mjs`](test/resubmit.mjs) checks that the deployed snippet forwards real submissions.  It fetches the log's last (up to) 256 entries, and resubmits each one to the same log, as the `add-chain` or `add-pre-chain` request that could have submitted it:

```
CTREQ_LOG_URL=https://tiger2027h1.ct.sectigo.com npm run test:resubmit
```

It fails if Cloudflare fails the snippet (e.g. with error 1201) for any of them, if any of them gets another server error, or if the snippet rejects any of them, as the log has already accepted them all; it also reports the log's responses.  Such failures may only affect some of the requests (e.g. only those handled by a copy of the snippet that hasn't yet cached the log's roots), so resubmitting many entries is more likely to find them than sending one.  The log already has the entries, so it returns their existing SCTs rather than adding entries, although TesseraCT's deduplication is best-effort, so a static-ct-api log might occasionally record a duplicate (which CT allows).  A static-ct-api log is read from its monitoring URL in Google's log list; for one that isn't listed, set `CTREQ_LOG_MONITORING_URL` too:

```
CTREQ_LOG_URL=https://standee.sub.ctlabs.sectigo.com CTREQ_LOG_MONITORING_URL=https://standee.mon.ctlabs.sectigo.com npm run test:resubmit
```

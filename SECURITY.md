# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately, using GitHub's [private vulnerability reporting](https://github.com/sectigo/CF_CTreq/security/advisories/new), rather than in a public issue or pull request.

Relevant issues include, for example, a request that the snippet rejects although the log would accept it (which could stop a certificate from being logged), a request that makes the snippet exceed a [Cloudflare Snippet limit](README.md#limits) or fail with an error, or any way that the snippet could change a request that it forwards.

A request that the snippet forwards although the log would reject it is not a vulnerability, as the log still rejects it.  Nor is the snippet a security control: it only rejects requests that the log would reject anyway.

## Supported versions

Only the latest release, and the `main` branch, are supported.

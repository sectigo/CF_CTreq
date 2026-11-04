import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import snippet from "../cf_ctreq.js";

const POISON = [
  0x30, 0x13, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02,
  0x04, 0x03, 0x01, 0x01, 0xff, 0x04, 0x02, 0x05, 0x00,
];

// Fake DER-ish byte blobs; the snippet only scans for the poison byte sequence.
const CERT = Buffer.from([0x30, 0x82, 0x01, 0x00, ...Array(64).fill(0xab)]).toString("base64");
const PRECERT = Buffer.from([0x30, 0x82, 0x01, 0x00, ...Array(32).fill(0xab), ...POISON, ...Array(32).fill(0xcd)]).toString("base64");
// Poison extension without the critical flag is not the DER sequence we look for.
const NONCRITICAL = Buffer.from([0x30, 0x10, ...POISON.slice(2, 14), 0x04, 0x02, 0x05, 0x00]).toString("base64");
const ISSUER = Buffer.from([0x30, 0x82, 0x01, 0x00, ...POISON]).toString("base64");

let forwarded;
beforeEach(() => {
  forwarded = null;
  globalThis.fetch = async (req) => {
    forwarded = { method: req.method, url: req.url, body: req.method === "POST" ? await req.text() : null };
    return new Response("origin", { status: 200 });
  };
});

function post(path, body) {
  return new Request("https://log.example.com" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

test("certificate to add-chain is forwarded", async () => {
  const body = JSON.stringify({ chain: [CERT, ISSUER] });
  const res = await snippet.fetch(post("/2026h1/ct/v1/add-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

test("precertificate to add-pre-chain is forwarded", async () => {
  const body = JSON.stringify({ chain: [PRECERT, ISSUER] });
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", body));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, body);
});

test("precertificate to add-chain is rejected", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [PRECERT] }));
  assert.equal(res.status, 400);
  assert.equal(forwarded, null);
});

test("certificate to add-pre-chain is rejected", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [CERT, ISSUER] }));
  assert.equal(res.status, 400);
  assert.equal(forwarded, null);
});

test("only the first certificate is scanned", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-chain", { chain: [CERT, PRECERT] }));
  assert.equal(res.status, 200);
});

test("non-critical poison extension is not treated as poison", async () => {
  const res = await snippet.fetch(post("/ct/v1/add-pre-chain", { chain: [NONCRITICAL] }));
  assert.equal(res.status, 400);
});

test("malformed requests are rejected", async () => {
  for (const body of ["not json", "{}", '{"chain":[]}', '{"chain":[1]}', '{"chain":["!!!"]}']) {
    const res = await snippet.fetch(post("/ct/v1/add-chain", body));
    assert.equal(res.status, 400, body);
  }
  assert.equal(forwarded, null);
});

test("non-POST requests to the endpoints get 405", async () => {
  for (const method of ["GET", "PUT", "DELETE", "OPTIONS"]) {
    for (const path of ["/ct/v1/add-chain", "/ct/v1/add-pre-chain"]) {
      const res = await snippet.fetch(new Request("https://log.example.com" + path, { method }));
      assert.equal(res.status, 405, method + " " + path);
      assert.equal(res.headers.get("Allow"), "POST");
    }
  }
  assert.equal(forwarded, null);
});

test("non-JSON Content-Type gets 415", async () => {
  for (const contentType of ["text/plain", "application/x-www-form-urlencoded", null]) {
    const headers = contentType ? { "Content-Type": contentType } : {};
    const req = new Request("https://log.example.com/ct/v1/add-chain", {
      method: "POST",
      headers,
      body: new Uint8Array([0x7b, 0x7d]),
    });
    if (!contentType) req.headers.delete("Content-Type");
    const res = await snippet.fetch(req);
    assert.equal(res.status, 415, String(contentType));
  }
  assert.equal(forwarded, null);
});

test("Content-Type parameters and case are accepted", async () => {
  const req = new Request("https://log.example.com/ct/v1/add-chain", {
    method: "POST",
    headers: { "Content-Type": "Application/JSON; charset=utf-8" },
    body: JSON.stringify({ chain: [CERT, ISSUER] }),
  });
  const res = await snippet.fetch(req);
  assert.equal(res.status, 200);
});

test("oversized Content-Length gets 413 without reading the body", async () => {
  const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
  req.headers.set("Content-Length", String(128 * 1024 + 1));
  let read = false;
  req.text = async () => { read = true; return ""; };
  const res = await snippet.fetch(req);
  assert.equal(res.status, 413);
  assert.equal(read, false);
  assert.equal(forwarded, null);
});

test("Content-Length at the limit is accepted", async () => {
  const req = post("/ct/v1/add-chain", { chain: [CERT, ISSUER] });
  req.headers.set("Content-Length", String(128 * 1024));
  const res = await snippet.fetch(req);
  assert.equal(res.status, 200);
});

test("other requests pass through untouched", async () => {
  let res = await snippet.fetch(new Request("https://log.example.com/ct/v1/get-sth"));
  assert.equal(res.status, 200);
  assert.equal(forwarded.method, "GET");
  res = await snippet.fetch(post("/ct/v1/other", "xyz"));
  assert.equal(res.status, 200);
  assert.equal(forwarded.body, "xyz");
});

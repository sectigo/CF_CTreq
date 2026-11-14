// Returns the code (e.g. "1201") and description of an error that Cloudflare generated instead of
// passing on the log's response, or null. Cloudflare's error responses are plain text
// ("error code: 1201") for some clients, and an HTML page (titled with the description, and
// with "errorCode: 1201" in a script) for others, including Node's fetch().
export function cloudflareError(text) {
  const code = text.match(/error code: (\d{4})/)?.[1] ?? text.match(/errorCode:\s*(\d{4})/)?.[1];
  if (code === undefined) return null;
  const title = text.match(/<title>([^|<]*)/)?.[1]?.trim();
  return title ? `${code} (${title})` : code;
}

// A short description of a response body, for messages: the start of a plain-text or JSON
// body, or the title of an HTML page.
export function describeBody(text) {
  const title = text.match(/<title>([^<]*)<\/title>/)?.[1]?.trim();
  return title !== undefined ? `HTML page "${title}"` : text.replace(/\s+/g, " ").trim().slice(0, 200);
}

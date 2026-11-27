// Checks whether any of the upstream source files that determine the origins' rejection
// criteria (listed, with their Git blob hashes, in upstream.json) have changed since
// they were last reviewed. If any have, review the changes (to see whether the snippet
// or the origin models need updating), then record them with --update.
//
// Instead of a blob hash, a file may have { "lines": <regular expression>, "watched": [...] }:
// then only its lines that match the expression (e.g. a go.mod's requirement of the parser's
// module, rather than its many other dependencies) are watched.
//
// Usage: node test/differential/upstream.mjs [--update]
// A GITHUB_TOKEN (or GH_TOKEN) avoids GitHub's limit on unauthenticated API requests.
import { readFileSync, writeFileSync } from "node:fs";

const file = new URL("upstream.json", import.meta.url);
const upstream = JSON.parse(readFileSync(file, "utf8"));
const update = process.argv.includes("--update");
const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

async function github(path) {
  const res = await fetch(`https://api.github.com/${path}`, {
    headers: { Accept: "application/vnd.github+json", ...(token && { Authorization: `Bearer ${token}` }) },
  });
  if (!res.ok) {
    throw new Error(`GET ${path}: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

let changed = 0;
for (const repo of upstream.repositories) {
  const head = (await github(`repos/${repo.repository}/commits/${repo.branch}`)).sha;
  for (const [path, watched] of Object.entries(repo.files)) {
    const contents = await github(`repos/${repo.repository}/contents/${path}?ref=${head}`);
    let current = contents.sha;
    let details = "";
    if (typeof watched === "object") {
      const pattern = new RegExp(watched.lines);
      const lines = Buffer.from(contents.content, "base64").toString("utf8").split("\n").map((l) => l.trim()).filter((l) => pattern.test(l));
      current = { ...watched, watched: lines };
      details = `\n  was: ${JSON.stringify(watched.watched)}\n  now: ${JSON.stringify(lines)}`;
    }
    if (JSON.stringify(current) !== JSON.stringify(watched)) {
      changed++;
      console.log(`CHANGED: ${repo.repository}/${path}: https://github.com/${repo.repository}/compare/${repo.reviewed}...${head}${details}`);
      repo.files[path] = current;
    }
  }
  if (update) {
    repo.reviewed = head;
  }
}
if (update) {
  writeFileSync(file, JSON.stringify(upstream, null, 2) + "\n");
  console.log(`Recorded the current versions of all watched files in upstream.json.`);
} else if (changed) {
  console.log(`\n${changed} watched upstream file(s) changed since they were reviewed. Review the changes,`);
  console.log("update the snippet, the origin models or versions.json if necessary, then run this with --update.");
  process.exitCode = 1;
} else {
  console.log("No watched upstream files have changed since they were reviewed.");
}

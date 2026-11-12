// Differential tests: checks that the snippet, in each environment, never rejects a
// request that one of that environment's origins would accept, by comparing its
// responses to a generated corpus with the verdicts of origin models that use the
// origins' own parsers (see origins/main.go). Requires Go.
//
// With --replay, the corpus is instead recent real entries from the logs in Google's
// log list (see replay.mjs), each sent to the endpoint it was submitted to; this needs
// network access.
//
// Environment variables:
//   CTREQ_DIFF_COUNT   number of requests to generate (default 10000)
//   CTREQ_DIFF_SEED    seed for the generator (default 1)
//   CTREQ_DIFF_SUNLIGHT, CTREQ_DIFF_TRILLIAN
//                      certificate-transparency-go versions to use for the Sunlight and
//                      Trillian models (default: those in versions.json)
//   CTREQ_DIFF_SNIPPET path of the snippet to test (default: cf_ctreq.js)
//   CTREQ_REPLAY_ENTRIES, CTREQ_REPLAY_LOGS
//                      with --replay, the entries per log and the logs (see replay.mjs)
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generate } from "./generate.mjs";
import { replay } from "./replay.mjs";

const here = new URL(".", import.meta.url).pathname;
const SOURCE = readFileSync(process.env.CTREQ_DIFF_SNIPPET || new URL("../../cf_ctreq.js", import.meta.url), "utf8");
const CONFIG_ENVIRONMENT = /((?:^|[{,])\s*environment:\s*)"[a-z]*"/m;
assert.match(SOURCE, CONFIG_ENVIRONMENT, "the snippet must set CONFIG.environment to a string literal");
const versions = JSON.parse(readFileSync(join(here, "versions.json"), "utf8"))["certificate-transparency-go"];
const sunlightVersion = process.env.CTREQ_DIFF_SUNLIGHT || versions.sunlight;
const trillianVersion = process.env.CTREQ_DIFF_TRILLIAN || versions.trillian;
const count = Number(process.env.CTREQ_DIFF_COUNT || 10000);
const seed = Number(process.env.CTREQ_DIFF_SEED || 1);
const replaying = process.argv.includes("--replay");
const warn = (message) => console.log(process.env.GITHUB_ACTIONS ? `::warning::${message}` : `Warning: ${message}`);

// The origins whose models must all reject a request for the snippet to reject it, for
// each environment (as ENVIRONMENTS in cf_ctreq.js).
const ENVIRONMENTS = {
  sunlight: ["sunlight"],
  tesseract: ["tesseract"],
  trillian: ["trillian"],
  common: ["sunlight", "tesseract", "trillian"],
};
const ENDPOINTS = ["add-chain", "add-pre-chain"];

const loadSnippet = async (environment) => {
  const source = SOURCE.replace(CONFIG_ENVIRONMENT, `$1${JSON.stringify(environment)}`);
  return (await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"))).default;
};

// Runs the origin models in a copy of the Go module that requires the given version of
// certificate-transparency-go, returning verdicts[id][model][endpoint].
function runModels(version, models, corpusFile, verdicts) {
  const dir = mkdtempSync(join(tmpdir(), "ctreq-origins-"));
  try {
    cpSync(join(here, "origins"), dir, { recursive: true });
    const go = (...args) => {
      const result = spawnSync("go", args, { cwd: dir, encoding: "utf8", input: args[0] === "run" ? readFileSync(corpusFile) : undefined, maxBuffer: 1 << 28 });
      if (result.error || result.status !== 0) {
        throw new Error(`go ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`);
      }
      return result.stdout;
    };
    go("get", `github.com/google/certificate-transparency-go@${version}`);
    go("mod", "tidy");
    for (const line of go("run", ".", `-models=${models.join(",")}`).trim().split("\n")) {
      const [id, model, ...outcomes] = line.split("\t");
      ((verdicts[id] ??= {})[model] = {}), ENDPOINTS.forEach((endpoint, i) => (verdicts[id][model][endpoint] = outcomes[i]));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

let corpus;
if (replaying) {
  const { items, logs, failed } = await replay({ log: () => {} });
  for (const { name, error } of failed) warn(`couldn't read ${name}: ${error}`);
  corpus = items;
  console.log(`Replaying ${corpus.length} real entries from ${logs - failed.length} of ${logs} logs.`);
  if (!corpus.length) throw new Error("no entries to replay");
} else {
  corpus = generate({ seed, count });
  console.log(`Generated ${corpus.length} requests (seed ${seed}).`);
}
const work = mkdtempSync(join(tmpdir(), "ctreq-differential-"));
const corpusFile = join(work, "corpus.jsonl");
writeFileSync(corpusFile, corpus.map((item) => JSON.stringify(item)).join("\n") + "\n");
console.log(`Origin models: TesseraCT (Go ${spawnSync("go", ["env", "GOVERSION"], { encoding: "utf8" }).stdout.trim()} crypto/x509), Sunlight (certificate-transparency-go ${sunlightVersion}), Trillian (certificate-transparency-go ${trillianVersion}).`);

const verdicts = {};
if (sunlightVersion === trillianVersion) {
  runModels(sunlightVersion, ["tesseract", "sunlight", "trillian"], corpusFile, verdicts);
} else {
  runModels(sunlightVersion, ["tesseract", "sunlight"], corpusFile, verdicts);
  runModels(trillianVersion, ["trillian"], corpusFile, verdicts);
}

// The snippet's outcomes: its rejection reason, or "forwarded". Its get-roots requests get
// this too, which isn't a list of roots, so it doesn't check chains against roots (which
// the models don't model).
globalThis.fetch = async () => new Response("origin");
const falseRejections = [];
const summary = {};
const correctRejections = {};
for (const [environment, members] of Object.entries(ENVIRONMENTS)) {
  const snippet = await loadSnippet(environment);
  const counts = (summary[environment] = { requests: 0, accepted: 0, "false rejections": 0, missed: 0 });
  for (const { id, body, endpoint: submittedTo } of corpus) {
    for (const endpoint of submittedTo ? [submittedTo] : ENDPOINTS) {
      const res = await snippet.fetch(new Request(`https://log.example.com/ct/v1/${endpoint}`, { method: "POST", body }));
      const outcome = res.headers.get("X-CTreq-Reject") ?? "forwarded";
      const accepters = members.filter((model) => verdicts[id][model][endpoint] === "accept");
      counts.requests++;
      if (accepters.length) counts.accepted++;
      if (outcome !== "forwarded" && accepters.length) {
        counts["false rejections"]++;
        falseRejections.push({ environment, endpoint, outcome, accepters, id, body });
      } else if (outcome === "forwarded" && !accepters.length) {
        counts.missed++;
      } else if (outcome !== "forwarded" && replaying) {
        const reasons = (correctRejections[environment] ??= {});
        reasons[outcome] = (reasons[outcome] ?? 0) + 1;
      }
    }
  }
}

console.log(`\nPer environment (${replaying ? "requests" : "requests x endpoints"}; 'accepted' = some origin in the environment would accept;`);
console.log("'missed' = forwarded, though every origin in it would reject):");
console.table(summary);
if (replaying && Object.keys(correctRejections).length) {
  console.log("\nReal entries that the snippet rejected, as every origin in the environment would:");
  for (const [environment, reasons] of Object.entries(correctRejections)) {
    console.log(`  ${environment}: ${Object.entries(reasons).map(([reason, n]) => `${reason} ${n}`).join(", ")}`);
  }
}
if (falseRejections.length) {
  const file = join(tmpdir(), `ctreq-false-rejections-${replaying ? "replay" : seed}.jsonl`);
  writeFileSync(file, falseRejections.map((f) => JSON.stringify(f)).join("\n") + "\n");
  console.log(`\n${falseRejections.length} FALSE REJECTIONS (all written to ${file}); the first few:`);
  for (const f of falseRejections.slice(0, 5)) {
    console.log(`  ${f.environment} ${f.endpoint}: ${f.outcome}, but ${f.accepters.join(" and ")} would accept request ${f.id}: ${f.body.slice(0, 120)}...`);
  }
  process.exitCode = 1;
} else {
  console.log("\nNo false rejections.");
}
rmSync(work, { recursive: true, force: true });

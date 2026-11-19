// Runs SCIM Verify (ghcr.io/limosa-io/scimverify) against the e2e lab and
// gates on it, applying the same declaration discipline as
// conformance/expected-failures.json: leaf test failures listed in
// e2e/scim-verify-expected.txt are expected; anything else - or a declaration
// that no longer fails - fails the run.
//
//   BASE=http://flareid:8787 KEY=$(node -pe '...lab-key.json...') node e2e/scim-verify-run.mjs
//
// In CI the workflow calls this with BASE=http://localhost:8787 --network
// host; locally, attach to the lab network instead:
//   NETWORK=flareid-lab_default BASE=http://flareid:8787 node e2e/scim-verify-run.mjs

import { spawnSync } from "node:child_process";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const E2E = dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.BASE ?? "http://localhost:8787").replace(/\/$/, "");
const NETWORK = process.env.NETWORK ?? "host";
const KEY = process.env.KEY ?? JSON.parse(readFileSync(join(E2E, "state", "lab-key.json"), "utf8")).key;
// Pinned: the image floats on :latest and its expectations are what the
// declarations below are calibrated against.
const IMAGE = process.env.SCIMVERIFY_IMAGE ?? "ghcr.io/limosa-io/scimverify@sha256:6a4b758d72d58636274fa5415d5b7fa39f9b0412938254e18ff90354f6f8e2e4";

mkdirSync(join(E2E, "..", "scim-verify-out"), { recursive: true });
const run = spawnSync("docker", [
  "run", "--rm", "--entrypoint", "node", "--network", NETWORK,
  "-v", `${join(E2E, "..")}:/work`, "-w", "/work",
  IMAGE, "/usr/src/app/bin/scimverify.js",
  "--base-url", `${BASE}/scim/v2`,
  "--auth-header", `Bearer ${KEY}`,
  "--config", "e2e/scim-verify.config.yaml",
  "--har-file", "scim-verify-out/scim-verify.har",
], { encoding: "utf8" });

const out = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
process.stdout.write(out);
if (run.error) { console.error(`docker run failed: ${run.error.message}`); process.exit(1); }

// Leaf failures are the indented "not ok" lines under each suite; top-level
// "not ok" lines are suite rollups and duplicate them.
const failures = [...out.matchAll(/^ {4}not ok \d+ - (.+)$/gm)].map((m) => m[1].trim());
const expected = new Set(
  readFileSync(join(E2E, "scim-verify-expected.txt"), "utf8")
    .split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
);
const unexpected = failures.filter((f) => !expected.has(f));
const stale = [...expected].filter((f) => !failures.includes(f));

for (const f of failures) console.log(`  ${expected.has(f) ? "expected-fail" : "FAIL        "} ${f}`);
for (const s of stale) console.log(`  stale-decl   ${s}`);
if (unexpected.length || stale.length) {
  console.error(`\n${unexpected.length} unexpected failure(s), ${stale.length} stale declaration(s)`);
  process.exit(1);
}
console.log(`\nSCIM Verify: ${failures.length} failure(s), all declared`);

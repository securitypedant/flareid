#!/usr/bin/env node
// Scrub the pre-shared secrets the suite config carries out of the exported
// result logs before CI uploads them as a workflow artifact.
//
// Ephemeral tokens are left alone: they expire quickly, belong to throwaway
// conformance clients, and the logs lose their diagnostic value without them.
// What must not persist is the material that authenticates - client secrets,
// the seeded user's password, the CONFORMANCE_TOKEN alias credential.
//
//   node conformance/redact-exports.mjs <export-dir> <suite-config.json>

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [dir, configPath] = process.argv.slice(2);
if (!dir || !configPath) {
  console.error("usage: redact-exports.mjs <export-dir> <suite-config.json>");
  process.exit(2);
}
// A missing export dir means the suite produced nothing to scrub (e.g. the
// run died before its first export) — succeed so the upload gate stays safe:
// `if-no-files-found: ignore` then simply uploads nothing.
if (!existsSync(dir)) {
  console.log(`no export dir at ${dir} - nothing to scrub`);
  process.exit(0);
}

// Collect every value stored under a secret-looking key anywhere in the
// nested suite config.
function collectSecrets(value, out = new Set()) {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      // Field tuples carry the secret after the field's name marker:
      // ["text", "name", "password", "Cf-…"].
      if (typeof item === "string" && /secret|password|token/i.test(item)) {
        const next = value[i + 1];
        if (typeof next === "string" && next.length >= 6) {
          out.add(next);
          i++;
          continue;
        }
      }
      collectSecrets(item, out);
    }
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (/secret|password|token/i.test(key) && typeof item === "string" && item.length >= 6) out.add(item);
      else collectSecrets(item, out);
    }
  }
  return out;
}

function* files(root) {
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}

const secrets = [...collectSecrets(JSON.parse(readFileSync(configPath, "utf8")))];
// The suite runner's API token is not in the config but can appear in logs.
for (const extra of [process.env.CONFORMANCE_TOKEN]) if (extra && extra.length >= 6) secrets.push(extra);
// Longest first so a secret that prefixes another is replaced whole.
secrets.sort((a, b) => b.length - a.length);

let touched = 0;
for (const path of files(dir)) {
  const text = readFileSync(path, "utf8");
  let next = text;
  for (const s of secrets) next = next.split(s).join("<redacted>");
  if (next !== text) {
    writeFileSync(path, next, { mode: statSync(path).mode });
    touched++;
  }
}
console.log(`redacted ${secrets.length} secret value(s) across ${touched} exported file(s)`);

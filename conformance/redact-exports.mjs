#!/usr/bin/env node
// Scrub the pre-shared secrets the suite config carries out of the exported
// result logs before CI uploads them as a workflow artifact.
//
// Ephemeral tokens are left alone: they expire quickly, belong to throwaway
// conformance clients, and the logs lose their diagnostic value without them.
// What must not persist is the material that authenticates - client secrets,
// the seeded user's password, the CONFORMANCE_TOKEN alias credential.
//
//   node conformance/redact-exports.mjs <export-dir> <suite-config.json> [more configs...]
//
// Pass every config a plan ran with: the fc/bc logout configs carry different
// client secrets than the shared one, and all of them can appear in exports.

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [dir, ...configPaths] = process.argv.slice(2);
if (!dir || !configPaths.length) {
  console.error("usage: redact-exports.mjs <export-dir> <suite-config.json> [more configs...]");
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

const configs = configPaths.filter(existsSync).map((p) => JSON.parse(readFileSync(p, "utf8")));
const secrets = [...collectSecrets(configs)];
// The suite runner's API token is not in the config but can appear in logs.
for (const extra of [process.env.CONFORMANCE_TOKEN]) if (extra && extra.length >= 6) secrets.push(extra);

// The same secret reaches exports in encoded forms too: HTTP Basic headers
// hold base64(client_id:secret), form posts hold percent-encodings, raw
// captures can hold base64 of the value alone, and JSON logs escape it.
// Literal-only replacement would let every one of those through.
function collectClientIds(value, out = new Set()) {
  if (Array.isArray(value)) for (const item of value) collectClientIds(item, out);
  else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key === "client_id" && typeof item === "string" && item) out.add(item);
      else collectClientIds(item, out);
    }
  }
  return out;
}
const b64url = (s) => Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const encoded = new Set();
for (const secret of secrets) {
  encoded.add(Buffer.from(secret, "utf8").toString("base64"));
  encoded.add(b64url(secret));
  encoded.add(encodeURIComponent(secret));
  const json = JSON.stringify(secret).slice(1, -1);
  if (json !== secret) encoded.add(json);
  for (const id of collectClientIds(configs)) {
    const basic = Buffer.from(`${id}:${secret}`, "utf8").toString("base64");
    encoded.add(basic);
    encoded.add(b64url(`${id}:${secret}`));
  }
}
secrets.push(...[...encoded].filter((e) => e.length >= 6));
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

#!/usr/bin/env node
// Bundles the app catalog's icons into the Worker:
//   catalog/icons/*.svg  ->  src/lib/catalog-icons.generated.ts
//
// Run: npm run catalog:icons            (writes the module)
//      npm run catalog:icons -- --check (fails if the module is stale; CI runs this)
//
// The Worker has no filesystem, so the SVGs ship as strings in a generated
// module, served back at /catalog-icons/<file>. Every catalog entry's "logo"
// field must name a file that exists here - the check enforces it, so a
// dropped icon fails the build instead of 404ing on the launchpad.

import { readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const iconDir = join(root, "catalog/icons");
const catalogDir = join(root, "catalog");
const outFile = join(root, "src/lib/catalog-icons.generated.ts");
const check = process.argv.includes("--check");

const files = (await readdir(iconDir)).filter((f) => f.endsWith(".svg")).sort();

// Every entry's logo must resolve to a committed icon, and no icon may be
// orphaned - drift either way means something is broken.
const entries = (await readdir(catalogDir)).filter((f) => f.endsWith(".json") && f !== "schema.json" && f !== "_template.json");
const errors = [];
for (const name of entries) {
  const entry = JSON.parse(await readFile(join(catalogDir, name), "utf8"));
  if (typeof entry.logo !== "string" || !entry.logo.startsWith("icons/")) {
    errors.push(`catalog/${name} has no "logo": "icons/<file>.svg"`);
  } else if (!files.includes(entry.logo.slice("icons/".length))) {
    errors.push(`catalog/${name} points at ${entry.logo}, which is not in catalog/icons/`);
  }
}
const referenced = new Set();
for (const name of entries) {
  const entry = JSON.parse(await readFile(join(catalogDir, name), "utf8"));
  if (typeof entry.logo === "string") referenced.add(entry.logo.slice("icons/".length));
}
for (const f of files) if (!referenced.has(f)) errors.push(`catalog/icons/${f} is not referenced by any catalog entry`);
if (errors.length) fail(errors);

const parts = [];
for (const f of files) {
  const svg = (await readFile(join(iconDir, f), "utf8")).trim();
  parts.push(`  ${JSON.stringify(`icons/${f}`)}: ${JSON.stringify(svg)},`);
}
const generated = `// GENERATED FILE - do not edit. Produced by scripts/catalog-icons.mjs
// (npm run catalog:icons) from catalog/icons/*.svg.

/** App-catalog icons, keyed by their catalog-relative path ("icons/slack.svg"). */
export const CATALOG_ICONS: Record<string, string> = {
${parts.join("\n")}
};
`;

if (check) {
  const current = await readFile(outFile, "utf8").catch(() => "");
  if (current !== generated) fail(["src/lib/catalog-icons.generated.ts is stale - run npm run catalog:icons"]);
  console.log("catalog-icons.generated.ts is up to date.");
} else {
  await writeFile(outFile, generated);
  console.log(`Wrote ${outFile} (${files.length} icons).`);
}

function fail(list) {
  for (const e of list) console.error(`catalog-icons: ${e}`);
  process.exit(1);
}

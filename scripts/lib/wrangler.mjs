// Wrangler wrappers.
//
// A theme worth noticing in ensureD1 and ensureKv: `wrangler d1 create` on a
// name that already exists FAILS rather than being idempotent, so "create, and
// if that did not work go and find it" is the only way to get an id reliably.

import { readFileSync, writeFileSync } from "node:fs";
import { capture, run } from "./run.mjs";
import { detail, error } from "./log.mjs";

/**
 * Creates a D1 database if it is not already there; returns its uuid either way.
 *
 * Exits with BOTH commands' output on failure, because the useful information
 * is split across them: the create says why it refused, the list says what is
 * actually there.
 */
export async function ensureD1(dir, name) {
  const created = await capture("wrangler", ["d1", "create", name], { cwd: dir });
  const fromCreate = /"database_id":\s*"([a-f0-9-]+)"/.exec(created.stdout + created.stderr);
  if (fromCreate) return fromCreate[1];

  const listed = await capture("wrangler", ["d1", "list", "--json"], { cwd: dir });
  const match = parseJsonList(listed.stdout).find((d) => d.name === name);
  if (match?.uuid) return match.uuid;

  error(`Could not create or find D1 database '${name}'.`);
  error("Output from 'wrangler d1 create':");
  console.error(created.stdout + created.stderr);
  error("Output from 'wrangler d1 list':");
  console.error(listed.stdout + listed.stderr);
  process.exit(1);
}

/**
 * Creates a KV namespace if it is not already there (matched by title); returns
 * its id either way.
 *
 * The endsWith fallback is not decoration: wrangler prefixes the title it
 * creates with the Worker name, so the namespace you asked for comes back
 * called something else.
 */
export async function ensureKv(dir, name) {
  const created = await capture("wrangler", ["kv", "namespace", "create", name], { cwd: dir });
  const fromCreate = /"id":\s*"([a-f0-9]+)"/.exec(created.stdout + created.stderr);
  if (fromCreate) return fromCreate[1];

  const listed = await capture("wrangler", ["kv", "namespace", "list"], { cwd: dir });
  const match = parseJsonList(listed.stdout).find((n) => n.title === name || n.title?.endsWith(`-${name}`));
  if (match?.id) return match.id;

  error(`Could not create or find KV namespace '${name}'.`);
  error("Output from 'wrangler kv namespace create':");
  console.error(created.stdout + created.stderr);
  error("Output from 'wrangler kv namespace list':");
  console.error(listed.stdout + listed.stderr);
  process.exit(1);
}

export async function hasSecret(dir, name) {
  const listed = await capture("wrangler", ["secret", "list"], { cwd: dir });
  return (listed.stdout + listed.stderr).includes(`"name": "${name}"`);
}

/**
 * Sets a secret, always overwriting.
 *
 * The value goes in over stdin and never as an argument: an argument is visible
 * in the process list, and on Windows would also go through a shell's quoting
 * rules.
 */
export async function setSecret(dir, name, value) {
  const result = await run("wrangler", ["secret", "put", name], { cwd: dir, quiet: true, input: value });
  if (result.code !== 0) {
    error(`Could not set ${name}:`);
    console.error(result.stdout + result.stderr);
    process.exit(1);
  }
  detail(`set ${name}`);
}

/** Sets a secret only if it is missing, unless `force` says otherwise. */
export async function setSecretOnce(dir, name, value, { force = false, reason = "" } = {}) {
  if (force || !(await hasSecret(dir, name))) {
    await setSecret(dir, name, value);
    return true;
  }
  detail(`${name} already set, leaving it${reason ? ` (${reason})` : ""}`);
  return false;
}

export async function applyMigrations(dir, dbName) {
  const result = await run("wrangler", ["d1", "migrations", "apply", dbName, "--remote"], { cwd: dir });
  if (result.code !== 0) {
    error(`Migrations failed for ${dbName}.`);
    process.exit(result.code);
  }
}

/**
 * Deploys the Worker in `dir`, returning its workers.dev URL if one was
 * reported.
 *
 * The URL is scraped from the output because wrangler offers no other way to
 * get it, and FlareID needs it: with no custom domain, its issuer IS that
 * hostname, which is only knowable after a deploy.
 */
export async function deployWorker(dir, { quiet = false } = {}) {
  const result = quiet
    ? await capture("wrangler", ["deploy"], { cwd: dir })
    : await run("wrangler", ["deploy"], { cwd: dir });
  if (result.code !== 0) {
    error(`Deploy failed in ${dir}.`);
    if (quiet) console.error(result.stdout + result.stderr);
    process.exit(result.code);
  }
  const text = (result.stdout ?? "") + (result.stderr ?? "");
  const url = /https:\/\/[a-z0-9.-]+\.workers\.dev/.exec(text);
  return url ? url[0] : "";
}

/**
 * Patches one string field's value in a JSONC file.
 *
 * A regex rather than a JSON round-trip because wrangler.jsonc has comments,
 * and the comments are a good part of its value - JSON.parse/stringify would
 * silently delete them. Returns false if the field was not found.
 *
 * A value that already starts and ends with `"` is used verbatim, for
 * pre-escaped JSON string values such as SIGNING_PUBLIC_JWK.
 */
export function patchJsonField(file, fieldName, newValue, occurrence = 0) {
  const rawValue =
    typeof newValue === "string" && newValue.startsWith('"') && newValue.endsWith('"')
      ? newValue
      : JSON.stringify(newValue);

  const content = readFileSync(file, "utf8");
  const pattern = new RegExp(`("${fieldName}"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"`, "g");

  let count = 0;
  let replaced = false;
  const patched = content.replace(pattern, (match, prefix) => {
    if (count++ === occurrence) {
      replaced = true;
      return `${prefix}${rawValue}`;
    }
    return match;
  });

  if (!replaced) return false;
  writeFileSync(file, patched, "utf8");
  return true;
}

/**
 * Parses a wrangler `--json` list, which is not always only JSON: wrangler
 * prints banners and warnings onto the same stream, so the array has to be
 * found rather than assumed to start at the first character.
 */
function parseJsonList(text) {
  const start = text.indexOf("[");
  if (start === -1) return [];
  try {
    const parsed = JSON.parse(text.slice(start, text.lastIndexOf("]") + 1));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

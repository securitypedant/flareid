#!/usr/bin/env node
// Writes the provisioning API's OpenAPI document and a readable reference:
//   docs/openapi.json       - the spec, exactly as GET /api/v1/openapi.json serves it
//   docs/api-reference.md   - every operation: permission, parameters, body, responses
//
// Run: npm run docs:api
//
// The spec is generated from the route definitions (src/api/openapi.ts), so
// this bundles the API module for Node with esbuild and asks it for the
// document - no Worker, no network, nothing hand-maintained. Re-run it after
// changing a route; test/api-parity.test.ts fails if docs/openapi.json is stale.

import { build } from "esbuild";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dir = await mkdtemp(join(tmpdir(), "flareid-api-docs-"));
const out = join(dir, "spec.mjs");

try {
  await build({
    stdin: {
      contents: 'import "./src/routes/api.ts"; export { openApiDocument } from "./src/api/openapi.ts";',
      resolveDir: root,
      loader: "ts",
    },
    bundle: true,
    platform: "node",
    format: "esm",
    outfile: out,
    logLevel: "error",
    // Modules that are never executed while building the document.
    external: ["cloudflare:*"],
  });
  const { openApiDocument } = await import(pathToFileURL(out).href);
  const spec = openApiDocument();
  await writeFile(join(root, "docs/openapi.json"), `${JSON.stringify(spec, null, 2)}\n`);
  await writeFile(join(root, "docs/api-reference.md"), renderMarkdown(spec));
  const operations = Object.values(spec.paths).reduce((n, item) => n + Object.keys(item).length, 0);
  console.log(`Wrote docs/openapi.json and docs/api-reference.md (${operations} operations).`);
} finally {
  await rm(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------

function renderMarkdown(spec) {
  const lines = [];
  const push = (...l) => lines.push(...l);
  push(
    `# ${spec.info.title} reference`,
    "",
    "Generated from the route definitions by `npm run docs:api`; do not edit by hand.",
    `The same document is served by every deployment at \`GET /api/v1/openapi.json\` (no token needed), and is in [openapi.json](openapi.json).`,
    "See [api.md](api.md) for authentication, permissions and worked examples.",
    "",
    `API version ${spec.info.version}.`,
    ""
  );

  const byTag = new Map(spec.tags.map((t) => [t.name, []]));
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      const tag = op.tags?.[0] ?? "Other";
      if (!byTag.has(tag)) byTag.set(tag, []);
      byTag.get(tag).push({ path, method, op });
    }
  }

  push("## Contents", "");
  for (const t of spec.tags) if (byTag.get(t.name)?.length) push(`- [${t.name}](#${anchor(t.name)}) - ${t.description}`);
  push("");

  for (const t of spec.tags) {
    const ops = byTag.get(t.name) ?? [];
    if (!ops.length) continue;
    push(`## ${t.name}`, "", t.description, "");
    push("| Method | Path | Permission | Summary |", "|---|---|---|---|");
    for (const { path, method, op } of ops) push(`| \`${method.toUpperCase()}\` | \`${path}\` | \`${op["x-permission"]}\` | ${op.summary ?? ""} |`);
    push("");
    for (const { path, method, op } of ops) {
      push(`### \`${method.toUpperCase()} ${path}\``, "");
      if (op.summary) push(`${op.summary}.`, "");
      if (op.description) push(op.description, "");
      push(`Permission: \`${op["x-permission"]}\``, "");
      const params = (op.parameters ?? []).filter((p) => p.in === "path" || p.in === "query");
      if (params.length) {
        push("| Parameter | In | Required | Description |", "|---|---|---|---|");
        for (const p of params) push(`| \`${p.name}\` | ${p.in} | ${p.required ? "yes" : "no"} | ${oneLine(p.description ?? p.schema?.description ?? typeOf(spec, p.schema))} |`);
        push("");
      }
      const body = op.requestBody?.content?.["application/json"]?.schema;
      if (body) push("Request body:", "", ...fields(spec, body), "");
      const ok = Object.entries(op.responses).find(([code]) => code.startsWith("2"));
      if (ok) {
        const schema = ok[1].content?.["application/json"]?.schema;
        push(`Response \`${ok[0]}\`:`, "", ...(schema ? fields(spec, schema) : ["(no body)"]), "");
      }
      const errors = Object.keys(op.responses).filter((code) => !code.startsWith("2"));
      if (errors.length) push(`Errors: ${errors.map((e) => `\`${e}\``).join(", ")} (\`{ "error", "message" }\`).`, "");
    }
  }
  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}

function anchor(text) {
  return text.toLowerCase().replace(/[^a-z0-9 -]/g, "").replace(/ /g, "-");
}

function oneLine(s) {
  return String(s ?? "").replace(/\|/g, "\\|").replace(/\n+/g, " ");
}

function deref(spec, schema) {
  let s = schema;
  for (let i = 0; s?.$ref && i < 10; i++) s = spec.components.schemas[s.$ref.split("/").pop()];
  return s ?? {};
}

function typeOf(spec, schema) {
  if (!schema) return "";
  if (schema.$ref) return schema.$ref.split("/").pop();
  const s = schema;
  if (s.enum) return s.enum.map((v) => JSON.stringify(v)).join(" \\| ");
  if (s.const !== undefined) return JSON.stringify(s.const);
  if (s.anyOf || s.oneOf) return (s.anyOf ?? s.oneOf).map((x) => typeOf(spec, x)).join(" \\| ");
  const t = Array.isArray(s.type) ? s.type.join(" \\| ") : s.type;
  if (t === "array") return `${typeOf(spec, s.items)}[]`;
  if (t === "object" && s.additionalProperties && typeof s.additionalProperties === "object" && !s.properties) return `map of ${typeOf(spec, s.additionalProperties) || "any"}`;
  return t ?? "any";
}

/** A field table for an object schema (one level; nested objects named by type). */
function fields(spec, schema) {
  const name = schema.$ref ? schema.$ref.split("/").pop() : null;
  const s = deref(spec, schema);
  if (!s.properties) return [`\`${typeOf(spec, schema)}\``];
  const required = new Set(s.required ?? []);
  const rows = Object.entries(s.properties).map(([k, v]) => {
    const d = deref(spec, v);
    const nested = d.properties && !v.$ref ? ` { ${Object.keys(d.properties).join(", ")} }` : "";
    return `| \`${k}\` | ${typeOf(spec, v)}${nested} | ${required.has(k) ? "yes" : "no"} | ${oneLine(v.description ?? d.description ?? "")} |`;
  });
  return [...(name ? [`\`${name}\`:`, ""] : []), "| Field | Type | Required | Description |", "|---|---|---|---|", ...rows];
}

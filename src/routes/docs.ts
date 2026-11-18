import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { openApiDocument, TAGS } from "../api/openapi.js";
// Registers every /api/v1 route, so the document is complete whatever imports this first.
import "./api.js";
import { DOCS_NAV, DOCS_PAGES, type DocHeading } from "../docs/content.generated.js";
import { escapeHtml, page, THEME_TOGGLE_BUTTON } from "../lib/html.js";
import { VERSION } from "../version.js";

/**
 * The public documentation site at /docs: the guides rendered from
 * docs/site/*.md at build time (scripts/docs-site.mjs), and an API reference
 * rendered here from the live OpenAPI document - the same one
 * GET /api/v1/openapi.json serves - so it always describes the routes this
 * deployment actually has. Nothing here reads D1 or KV: every page is static
 * for a given deployment.
 */
export const docs = new Hono<{ Bindings: Env }>();

const TITLE = "FlareID Docs";
const GITHUB = "https://github.com/securitypedant/flareid";

docs.get("/docs/", (c) => c.redirect("/docs", 301));
docs.get("/docs", (c) => guide(c, "index"));
docs.get("/docs/api/reference", (c) => respond(c, "API reference", referenceIndex(), "api-reference"));
docs.get("/docs/api/reference/:tag", (c) => {
  const tag = TAGS.find((t) => slugify(t.name) === c.req.param("tag"));
  return tag ? respond(c, `${tag.name} API`, referenceTag(tag.name, tag.description), "api-reference", slugify(tag.name)) : c.notFound();
});
docs.get("/docs/:slug", (c) => {
  const slug = c.req.param("slug");
  return slug !== "index" && DOCS_PAGES[slug] ? guide(c, slug) : c.notFound();
});

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

const ALL_PAGES = DOCS_NAV.flatMap((s) => s.pages);

function guide(c: Context<{ Bindings: Env }>, slug: string) {
  const p = DOCS_PAGES[slug]!;
  const i = ALL_PAGES.findIndex((x) => x.slug === slug);
  const prev = ALL_PAGES[i - 1];
  const next = slug === "api" ? { slug: "api/reference", title: "API reference" } : ALL_PAGES[i + 1];
  const pager = `<nav class="docs-pager" aria-label="Previous and next page">
    ${prev ? `<a href="${urlFor(prev.slug)}"><span>Previous</span>${escapeHtml(prev.title)}</a>` : "<span></span>"}
    ${next ? `<a class="next" href="${urlFor(next.slug)}"><span>Next</span>${escapeHtml(next.title)}</a>` : ""}
  </nav>`;
  return respond(c, p.title, `<h1>${escapeHtml(p.title)}</h1>${p.html}${pager}`, slug, "", p.headings, p.description);
}

function respond(c: Context<{ Bindings: Env }>, title: string, body: string, active: string, activeTag = "", headings: DocHeading[] = [], description = "") {
  const toc = headings.length >= 3 ? `<aside class="docs-toc" aria-label="On this page"><p>On this page</p>${headings.map((h) => `<a href="#${h.id}">${escapeHtml(h.text)}</a>`).join("")}</aside>` : "";
  const html = page(
    title,
    `<div class="docs-shell${toc ? " has-toc" : ""}">
      <nav class="docs-side" aria-label="Documentation">${sidebar(active, activeTag)}</nav>
      <main class="docs-main"><article class="card docs-body">${body.replace(/<table/g, '<div class="table-wrap"><table').replace(/<\/table>/g, "</table></div>")}</article></main>
      ${toc}
    </div>`,
    TITLE,
    true,
    topbar(),
    DOCS_STYLES,
    "",
    description ? `<meta name="description" content="${escapeHtml(description)}" />` : ""
  );
  // The same for everyone until the next deploy; the CSP and other headers
  // are still added by securityHeaders on the way out.
  return c.html(html, 200, { "Cache-Control": "public, max-age=300" });
}

function topbar(): string {
  return `<header class="topbar">
    <div class="brand-row">
      <a href="/docs" class="brand">
        <img src="/FlareID_Icon.png" alt="" class="brand-logo" />
        <span class="brand-name">FlareID</span>
        <span class="brand-tagline">Documentation <span class="brand-version">(v${VERSION})</span></span>
      </a>
    </div>
    <nav>
      ${THEME_TOGGLE_BUTTON}
      <a href="/admin">Admin console</a>
      <a href="${GITHUB}" target="_blank" rel="noopener noreferrer">GitHub</a>
    </nav>
  </header>`;
}

function sidebar(active: string, activeTag: string): string {
  return DOCS_NAV.map((s) => {
    const links = s.pages.map((p) => `<a href="${urlFor(p.slug)}"${p.slug === active ? ' class="active" aria-current="page"' : ""}>${escapeHtml(p.title)}</a>`);
    if (s.section === "API") {
      links.push(`<a href="/docs/api/reference"${active === "api-reference" && !activeTag ? ' class="active" aria-current="page"' : ""}>API reference</a>`);
      if (active === "api-reference") {
        for (const t of TAGS) {
          const slug = slugify(t.name);
          links.push(`<a class="sub${slug === activeTag ? " active" : ""}" href="/docs/api/reference/${slug}"${slug === activeTag ? ' aria-current="page"' : ""}>${escapeHtml(t.name)}</a>`);
        }
      }
    }
    return `<p class="docs-nav-section">${escapeHtml(s.section)}</p>${links.join("")}`;
  }).join("");
}

const urlFor = (slug: string) => (slug === "index" ? "/docs" : `/docs/${slug}`);
const slugify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

// ---------------------------------------------------------------------------
// API reference, from the OpenAPI document
// ---------------------------------------------------------------------------

interface Schema {
  $ref?: string;
  type?: string | string[];
  enum?: unknown[];
  const?: unknown;
  anyOf?: Schema[];
  oneOf?: Schema[];
  allOf?: Schema[];
  items?: Schema;
  properties?: Record<string, Schema>;
  additionalProperties?: boolean | Schema;
  required?: string[];
  description?: string;
}

interface Operation {
  tags?: string[];
  summary?: string;
  description?: string;
  "x-permission"?: string;
  parameters?: { name: string; in: string; required?: boolean; description?: string; schema?: Schema }[];
  requestBody?: { content?: Record<string, { schema?: Schema }> };
  responses: Record<string, { description?: string; content?: Record<string, { schema?: Schema }> }>;
}

interface Spec {
  paths: Record<string, Record<string, Operation>>;
  components?: { schemas?: Record<string, Schema> };
}

// Built once per isolate: the document describes routes, which only change with a deploy.
let cached: { spec: Spec; byTag: Map<string, { method: string; path: string; op: Operation }[]> } | null = null;
function reference() {
  if (cached) return cached;
  const spec = openApiDocument() as unknown as Spec;
  const byTag = new Map<string, { method: string; path: string; op: Operation }[]>();
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      const tag = op.tags?.[0] ?? "Other";
      byTag.set(tag, [...(byTag.get(tag) ?? []), { method, path, op }]);
    }
  }
  cached = { spec, byTag };
  return cached;
}

function referenceIndex(): string {
  const { byTag } = reference();
  const rows = TAGS.filter((t) => byTag.get(t.name)?.length)
    .map((t) => `<tr><td><a href="/docs/api/reference/${slugify(t.name)}">${escapeHtml(t.name)}</a></td><td>${escapeHtml(t.description)}</td><td>${byTag.get(t.name)!.length}</td></tr>`)
    .join("");
  return `<h1>API reference</h1>
    <p>Every operation of the provisioning API at <code>/api/v1</code>, generated from the code this deployment is running (version ${escapeHtml(VERSION)}). For keys, permissions and errors, read the <a href="/docs/api">Provisioning API</a> guide first.</p>
    <p>The same description is available as an OpenAPI 3.1 document at <a href="/api/v1/openapi.json"><code>/api/v1/openapi.json</code></a>, for client generators and API explorers.</p>
    <table><thead><tr><th>Area</th><th>Description</th><th>Operations</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function referenceTag(name: string, description: string): string {
  const { spec, byTag } = reference();
  const ops = byTag.get(name) ?? [];
  const summary = ops
    .map(({ method, path, op }) => `<tr><td>${methodBadge(method)}</td><td><a href="#${opId(method, path)}"><code>${escapeHtml(path)}</code></a></td><td>${escapeHtml(op.summary ?? "")}</td></tr>`)
    .join("");
  return `<h1>${escapeHtml(name)}</h1>
    <p>${inline(description)}</p>
    <table class="api-summary"><thead><tr><th>Method</th><th>Path</th><th>Summary</th></tr></thead><tbody>${summary}</tbody></table>
    ${ops.map(({ method, path, op }) => operation(spec, method, path, op)).join("")}`;
}

function operation(spec: Spec, method: string, path: string, op: Operation): string {
  const id = opId(method, path);
  const params = (op.parameters ?? []).filter((p) => p.in === "path" || p.in === "query");
  const body = op.requestBody?.content?.["application/json"]?.schema;
  const ok = Object.entries(op.responses).find(([code]) => code.startsWith("2"));
  const okSchema = ok?.[1].content?.["application/json"]?.schema;
  const errors = Object.keys(op.responses).filter((code) => !code.startsWith("2"));
  const permission = op["x-permission"] ?? "";
  return `<section class="api-op" id="${id}">
    <h2><a class="docs-anchor" href="#${id}" aria-hidden="true" tabindex="-1">#</a>${methodBadge(method)} <code>${escapeHtml(path)}</code></h2>
    ${op.summary ? `<p class="api-op-summary">${escapeHtml(op.summary)}.</p>` : ""}
    ${op.description ? `<p>${inline(op.description)}</p>` : ""}
    <p class="api-meta">Permission: <code>${escapeHtml(permission)}</code>${permission === "bootstrap-token" ? " (the BOOTSTRAP_TOKEN secret, not an API key)" : ""}</p>
    ${
      params.length
        ? `<h3>Parameters</h3><table><thead><tr><th>Name</th><th>In</th><th>Required</th><th>Description</th></tr></thead><tbody>${params
            .map((p) => `<tr><td><code>${escapeHtml(p.name)}</code></td><td>${escapeHtml(p.in)}</td><td>${p.required ? "Yes" : "No"}</td><td>${inline(p.description ?? p.schema?.description ?? typeOf(p.schema))}</td></tr>`)
            .join("")}</tbody></table>`
        : ""
    }
    ${body ? `<h3>Request body</h3>${fieldsTable(spec, body)}` : ""}
    ${ok ? `<h3>Response <code>${escapeHtml(ok[0])}</code></h3>${okSchema ? fieldsTable(spec, okSchema) : '<p class="muted">No body.</p>'}` : ""}
    ${errors.length ? `<p class="api-meta">Errors: ${errors.map((e) => `<code>${escapeHtml(e)}</code>`).join(" ")}, with a body of <code>{ "error", "message" }</code>.</p>` : ""}
  </section>`;
}

function fieldsTable(spec: Spec, schema: Schema): string {
  const rows = fieldRows(spec, schema, "", 0);
  if (!rows.length) return `<p>A JSON value of type <code>${escapeHtml(typeOf(schema))}</code>.</p>`;
  return `<table class="api-fields"><thead><tr><th>Field</th><th>Type</th><th>Required</th><th>Description</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

/** One row per property, nested objects (and arrays of objects) expanded beneath their parent, three levels deep. */
function fieldRows(spec: Spec, schema: Schema, prefix: string, depth: number): string[] {
  const s = objectSchema(spec, schema);
  if (!s?.properties || depth > 2) return [];
  const required = new Set(s.required ?? []);
  return Object.entries(s.properties).flatMap(([name, prop]) => {
    const d = deref(spec, prop);
    const path = `${prefix}${name}`;
    const row = `<tr><td><code>${escapeHtml(path)}</code></td><td>${escapeHtml(typeOf(prop))}</td><td>${required.has(name) ? "Yes" : "No"}</td><td>${inline(prop.description ?? d.description ?? "")}</td></tr>`;
    const child = d.items ? fieldRows(spec, d.items, `${path}[].`, depth + 1) : fieldRows(spec, prop, `${path}.`, depth + 1);
    return [row, ...child];
  });
}

/** The object behind a schema, through $ref, nullable unions and allOf. */
function objectSchema(spec: Spec, schema: Schema): Schema | null {
  const s = deref(spec, schema);
  if (s.properties) return s;
  const variants = (s.anyOf ?? s.oneOf ?? s.allOf ?? []).map((v) => deref(spec, v)).filter((v) => v.properties);
  if (variants.length === 1) return variants[0]!;
  if (s.allOf && variants.length) return { properties: Object.assign({}, ...variants.map((v) => v.properties)), required: variants.flatMap((v) => v.required ?? []) };
  return null;
}

function deref(spec: Spec, schema: Schema | undefined): Schema {
  let s = schema;
  for (let i = 0; s?.$ref && i < 10; i++) s = spec.components?.schemas?.[s.$ref.split("/").pop()!];
  return s ?? {};
}

function typeOf(schema: Schema | undefined): string {
  if (!schema) return "";
  if (schema.$ref) return "object";
  if (schema.enum) return schema.enum.map((v) => JSON.stringify(v)).join(" | ");
  if (schema.const !== undefined) return JSON.stringify(schema.const);
  if (schema.anyOf || schema.oneOf) return [...new Set((schema.anyOf ?? schema.oneOf)!.map(typeOf))].join(" | ");
  const t = Array.isArray(schema.type) ? schema.type.join(" | ") : schema.type;
  if (t === "array") return `${typeOf(schema.items) || "any"}[]`;
  if (t === "object" && schema.additionalProperties && typeof schema.additionalProperties === "object" && !schema.properties) return `map of ${typeOf(schema.additionalProperties) || "any"}`;
  return t ?? "any";
}

function methodBadge(method: string): string {
  return `<span class="api-method api-method-${method}">${method.toUpperCase()}</span>`;
}

const opId = (method: string, path: string) => slugify(`${method} ${path}`);

/** The spec's descriptions use Markdown's `code` and **bold**; everything else stays text. */
function inline(text: string): string {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

// ---------------------------------------------------------------------------

const DOCS_STYLES = `
  .page-wrap:has(> .docs-shell) { max-width: 1440px; padding-left: 24px; padding-right: 24px; }
  .docs-shell { display: grid; grid-template-columns: 220px minmax(0, 1fr); gap: 32px; align-items: start; }
  .docs-shell.has-toc { grid-template-columns: 220px minmax(0, 1fr) 200px; }
  .docs-side, .docs-toc { position: sticky; top: 80px; max-height: calc(100vh - 100px); overflow-y: auto; display: flex; flex-direction: column; gap: 1px; }
  .docs-side { margin-left: -12px; }
  .docs-nav-section { margin: 16px 0 4px 12px; font-size: 0.6875rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--fi-faint); }
  .docs-nav-section:first-child { margin-top: 0; }
  .docs-side a { padding: 5px 12px; font-size: 0.84rem; font-weight: 500; color: var(--fi-body); border-radius: 6px; border-left: 2px solid transparent; }
  .docs-side a:hover { background: var(--fi-line-soft); color: var(--fi-ink); text-decoration: none; }
  .docs-side a.active { background: var(--fi-accent-soft); color: var(--fi-accent); border-left-color: var(--fi-accent); }
  .docs-side a.sub { padding: 3px 12px 3px 24px; font-size: 0.8rem; color: var(--fi-muted); }
  .docs-side a.sub.active { background: transparent; color: var(--fi-accent); }
  .docs-toc p { margin: 0 0 6px; font-size: 0.6875rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--fi-faint); }
  .docs-toc a { font-size: 0.8rem; color: var(--fi-muted); padding: 3px 0; }
  .docs-toc a:hover { color: var(--fi-accent); text-decoration: none; }
  .docs-main { min-width: 0; }
  .docs-body { padding: 30px 36px 26px; max-width: 880px; font-size: 0.9375rem; line-height: 1.65; }
  .docs-body h1 { font-size: 1.75rem; margin-bottom: 14px; }
  .docs-body h2 { font-size: 1.2rem; margin: 34px 0 10px; padding-top: 4px; scroll-margin-top: 72px; }
  .docs-body h3 { font-size: 1rem; margin: 24px 0 8px; scroll-margin-top: 72px; }
  .docs-body p, .docs-body ul, .docs-body ol { margin: 0 0 14px; }
  .docs-body ul, .docs-body ol { padding-left: 22px; }
  .docs-body li { margin: 3px 0; }
  .docs-body li > ul, .docs-body li > ol { margin: 4px 0 0; }
  .docs-body pre { background: var(--fi-surface-2); border: 1px solid var(--fi-line); border-radius: 8px; padding: 12px 14px; overflow-x: auto; margin: 0 0 16px; line-height: 1.5; }
  .docs-body pre code { background: none; border: none; padding: 0; font-size: 0.8125rem; }
  .docs-body .table-wrap { margin: 4px 0 18px; overflow-x: auto; }
  .docs-body table { margin: 0; }
  .docs-body th, .docs-body td { vertical-align: top; font-size: 0.875rem; }
  .docs-body td code { white-space: nowrap; }
  .docs-body blockquote { margin: 0 0 16px; padding: 10px 14px; border-left: 3px solid var(--fi-accent); background: var(--fi-accent-soft); border-radius: 0 8px 8px 0; color: var(--fi-ink); }
  .docs-body blockquote p { margin: 0; }
  .docs-anchor { float: left; margin-left: -18px; width: 18px; color: var(--fi-faint); opacity: 0; font-weight: 400; text-decoration: none; }
  .docs-body h2:hover .docs-anchor, .docs-body h3:hover .docs-anchor { opacity: 1; }
  .docs-pager { display: flex; justify-content: space-between; gap: 12px; margin-top: 34px; padding-top: 18px; border-top: 1px solid var(--fi-line); }
  .docs-pager a { display: flex; flex-direction: column; padding: 10px 14px; border: 1px solid var(--fi-line); border-radius: 8px; font-weight: 600; min-width: 0; }
  .docs-pager a:hover { border-color: var(--fi-accent); text-decoration: none; }
  .docs-pager a.next { text-align: right; margin-left: auto; }
  .docs-pager span { font-size: 0.75rem; font-weight: 500; color: var(--fi-muted); }
  .api-op { border-top: 1px solid var(--fi-line); margin-top: 30px; }
  .api-op h2 { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 1.05rem; }
  .api-op h2 code { font-size: 0.95rem; }
  .api-op-summary { font-weight: 600; color: var(--fi-ink); }
  .api-meta { color: var(--fi-muted); font-size: 0.875rem; }
  .api-method { display: inline-block; min-width: 54px; text-align: center; padding: 2px 6px; border-radius: 5px; font-size: 0.6875rem; font-weight: 700; letter-spacing: 0.03em; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #fff; }
  .api-method-get { background: #15803d; }
  .api-method-post { background: #1d4ed8; }
  .api-method-put, .api-method-patch { background: #b45309; }
  .api-method-delete { background: #b91c1c; }
  .api-fields td:first-child code { white-space: nowrap; }
  @media (max-width: 1180px) { .docs-shell.has-toc { grid-template-columns: 220px minmax(0, 1fr); } .docs-toc { display: none; } }
  @media (max-width: 860px) {
    .docs-shell, .docs-shell.has-toc { grid-template-columns: 1fr; }
    .docs-side { position: static; max-height: none; margin-left: 0; flex-direction: row; flex-wrap: wrap; gap: 4px; }
    .docs-nav-section { display: none; }
    .docs-side a.sub { display: none; }
    .docs-body { padding: 22px 18px; }
    .topbar .brand-tagline { display: none; }
  }
`;

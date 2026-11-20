// The public documentation site at /docs, and the console's links into it.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { DOCS_NAV, DOCS_PAGES } from "../src/docs/content.generated.js";
import { ADMIN_HELP } from "../src/docs/help.js";
import { TAGS, registeredOperations } from "../src/api/openapi.js";

const get = (path: string, headers: Record<string, string> = {}) => SELF.fetch(`${BASE}${path}`, { headers, redirect: "manual" });

/** Every /docs[/slug][#anchor] link resolves to a page and, with an anchor, to a heading on it. */
function assertDocLink(href: string) {
  const [path, anchor] = href.split("#");
  const slug = path!.replace(/^\/docs\/?/, "") || "index";
  const target = DOCS_PAGES[slug];
  expect(target, `${href}: no such page`).toBeDefined();
  if (anchor) expect(target!.ids, `${href}: no such heading`).toContain(anchor);
}

describe("documentation site", () => {
  it("serves every guide publicly, with no session and on a fresh instance", async () => {
    for (const { pages } of DOCS_NAV) {
      for (const p of pages) {
        const res = await get(p.slug === "index" ? "/docs" : `/docs/${p.slug}`);
        expect(res.status, p.slug).toBe(200);
        const html = await res.text();
        expect(html).toContain(`<h1>${p.title}</h1>`);
        // The page's own entry is marked current in the sidebar.
        expect(html).toContain(`aria-current="page">${p.title}</a>`);
      }
    }
  });

  it("is cacheable and carries the usual security headers", async () => {
    const res = await get("/docs/saml");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
  });

  it("answers unknown pages with a 404 and /docs/ with a redirect", async () => {
    expect((await get("/docs/no-such-page", { Accept: "text/html" })).status).toBe(404);
    expect((await get("/docs/index")).status).toBe(404);
    expect((await get("/docs/api/reference/no-such-tag")).status).toBe(404);
    // Object.prototype keys are not pages either - a truthy lookup would 500.
    for (const slug of ["constructor", "hasOwnProperty", "toString", "__proto__"]) {
      expect((await get(`/docs/${slug}`)).status, slug).toBe(404);
    }
    const slash = await get("/docs/");
    expect(slash.status).toBe(301);
    expect(slash.headers.get("Location")).toBe("/docs");
  });

  it("renders the API reference from the live OpenAPI document: every tag and every operation", async () => {
    const index = await (await get("/docs/api/reference")).text();
    const ids: string[] = [];
    for (const tag of TAGS) {
      const slug = tag.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      expect(index).toContain(`href="/docs/api/reference/${slug}"`);
      const res = await get(`/docs/api/reference/${slug}`);
      expect(res.status, tag.name).toBe(200);
      const html = await res.text();
      ids.push(...[...html.matchAll(/<section class="api-op" id="([^"]+)"/g)].map((m) => m[1]!));
    }
    // One section per registered operation, none missing and none twice.
    expect(ids.length).toBe(registeredOperations.size);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("documents an operation's permission, parameters, body and response", async () => {
    const html = await (await get("/docs/api/reference/users")).text();
    expect(html).toContain('id="post-api-v1-users"');
    expect(html).toContain("Permission: <code>users:write</code>");
    expect(html).toContain("<code>given_name</code>");
    // Nested request fields are expanded under their parent.
    expect(html).toContain("<code>emails[].value</code>");
    expect(html).toContain("<code>username</code></td><td>string</td><td>Yes</td>");
  });

  it("escapes raw HTML in the sources rather than passing it through", () => {
    for (const p of Object.values(DOCS_PAGES)) expect(p.html, p.slug).not.toMatch(/<(script|iframe|style|img)\b/i);
  });
});

describe("console links into the docs", () => {
  beforeEach(resetDatabase);

  async function adminCookie() {
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  }

  it("every help link points at a page and heading that exist", () => {
    for (const href of Object.values(ADMIN_HELP)) assertDocLink(href);
  });

  it("puts a (?) beside the SAML apps title linking to the SAML guide, and Docs in the menu", async () => {
    await bootstrapInstance({ domain: "docs.test" });
    const cookie = await adminCookie();
    const saml = await (await get("/admin/integrations/saml", { Cookie: cookie })).text();
    expect(saml).toMatch(/<h1>SAML<\/h1><a class="help-link" href="\/docs\/saml" target="_blank" rel="noopener" title="Help: SAML apps"/);
    expect(saml).toContain('<a href="/docs" class="nav-docs" target="_blank"');
    // The menu ends with Log, then Docs.
    expect(saml.indexOf(">Log</a>")).toBeLessThan(saml.indexOf('class="nav-docs"'));

    const pages: [string, string][] = [
      ["/admin", "/docs/monitoring"],
      ["/admin/users", "/docs/users"],
      ["/admin/users/import", "/docs/importing"],
      ["/admin/groups", "/docs/groups"],
      ["/admin/apps", "/docs/applications"],
      ["/admin/integrations/scim", "/docs/scim"],
      ["/admin/security/policies", "/docs/policies"],
      ["/admin/security/factors", "/docs/policies#second-factors"],
      ["/admin/branding/email-templates", "/docs/email#templates"],
      ["/admin/audit", "/docs/monitoring#audit-log"],
    ];
    for (const [path, href] of pages) {
      const html = await (await get(path, { Cookie: cookie })).text();
      expect(html, path).toContain(`<a class="help-link" href="${href}"`);
    }
  });
});

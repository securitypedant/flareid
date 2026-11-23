// The unified Applications console: one list for OIDC clients and SAML apps,
// catalog apply, per-app SCIM provisioning links and the per-area gating.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { canAccess } from "../src/lib/admin-roles.js";
import { expand } from "../src/lib/permissions.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, cookie: string, body: Record<string, string>) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(body).toString(), redirect: "manual" });

async function adminCookie(): Promise<string> {
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
  return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
}

async function seedApps(apiKey: string): Promise<{ clientDbId: number; spDbId: number }> {
  const cl = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Team Grafana", redirect_uris: ["https://grafana.example.com/cb"] } });
  const sp = await apiCall("/api/v1/saml/service-providers", { token: apiKey, body: { entity_id: "https://slack.example.com", name: "Team Slack", acs_urls: ["https://slack.example.com/acs"] } });
  if (cl.status !== 200 || sp.status !== 200) throw new Error(`seed failed: ${JSON.stringify(cl.body)} ${JSON.stringify(sp.body)}`);
  return {
    clientDbId: (await env.DB.prepare("SELECT id FROM oauth_clients WHERE name = 'Team Grafana'").first<{ id: number }>())!.id,
    spDbId: (await env.DB.prepare("SELECT id FROM saml_service_providers WHERE name = 'Team Slack'").first<{ id: number }>())!.id,
  };
}

describe("unified applications list", () => {
  it("shows OIDC clients and SAML apps together, gated per area", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const { clientDbId, spDbId } = await seedApps(apiKey);
    // A SAML-only reader: sees the SP row but not the client row.
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, passwords: "none", groups: [{ name: "SAML Readers" }], users: [{ username: "sami", status: "active", groups: ["SAML Readers"] }] },
    });
    await apiCall("/api/v1/security/roles", { token: apiKey, body: { name: "SAML readers", permissions: ["saml:read"], groups: ["SAML Readers"] } });
    const samiId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'sami'").first<{ id: number }>())!.id;
    const sami = (await createSession(env, samiId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;

    const adminHtml = await (await get("/admin/apps", await adminCookie())).text();
    expect(adminHtml).toContain(`href="/admin/clients/${clientDbId}"`);
    expect(adminHtml).toContain(`href="/admin/saml/${spDbId}"`);
    expect(adminHtml).toContain(">OIDC<");
    expect(adminHtml).toContain(">SAML<");
    expect(adminHtml).toContain("Everyone");
    // The Applications section is in the sidebar with its pages.
    expect(adminHtml).toContain('href="/admin/apps" class="sub active"');
    expect(adminHtml).toContain('href="/admin/apps/catalog" class="sub');

    const samiHtml = await (await get("/admin/apps", sami)).text();
    expect(samiHtml).toContain("Team Slack");
    expect(samiHtml).not.toContain("Team Grafana");
    // saml:read opens the catalog; a users-only admin cannot read it.
    expect((await get("/admin/apps/catalog", sami)).status).toBe(200);
  });

  it("redirects the old OIDC list and keeps the SAML settings page", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedApps(apiKey);
    const cookie = await adminCookie();
    const res = await get("/admin/integrations/oidc", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/admin/apps");
    const saml = await get("/admin/integrations/saml", cookie);
    expect(saml.status).toBe(200);
    const html = await saml.text();
    expect(html).toContain("<h1>SAML</h1>");
    expect(html).toContain("Disabled algorithms");
    expect(html).toContain("/saml/metadata");
  });
});

describe("app catalog", () => {
  it("lists entries and renders a SAML entry's instructions with placeholder inputs", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    const catalog = await (await get("/admin/apps/catalog", cookie)).text();
    expect(catalog).toContain("/admin/apps/catalog/gitlab");
    expect(catalog).toContain("/admin/apps/catalog/grafana");

    const page = await (await get("/admin/apps/catalog/gitlab", cookie)).text();
    expect(page).toContain("In the app");
    expect(page).toContain("In FlareID");
    expect(page).toContain('name="ph_host"');
    expect(page).toContain('action="/admin/apps/catalog/gitlab/apply"');
    expect((await get("/admin/apps/catalog/nope", cookie)).status).toBe(404);
  });

  it("applies a SAML template into a prefilled service provider", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    const res = await post("/admin/apps/catalog/gitlab/apply", cookie, { ph_host: "gitlab.example.com" });
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toMatch(/^\/admin\/saml\/\d+/);
    const sp = await env.DB.prepare("SELECT * FROM saml_service_providers WHERE name = 'GitLab'").first<{ entity_id: string; acs_urls: string; logo_uri: string | null }>();
    expect(sp).not.toBeNull();
    expect(sp!.entity_id).toContain("gitlab.example.com");
    expect(JSON.parse(sp!.acs_urls).join(" ")).toContain("gitlab.example.com");
    expect(sp!.entity_id).not.toContain("{host}");
    // The entry's icon lands on the record so the launchpad shows it.
    expect(sp!.logo_uri).toContain("/catalog-icons/gitlab.svg");
  });

  it("applies an OIDC template into a prefilled client and shows the secret once", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    const res = await post("/admin/apps/catalog/grafana/apply", cookie, { ph_host: "grafana.example.com" });
    expect(res.status).toBe(200); // the once-only "Client created" page
    const html = await res.text();
    expect(html).toContain("Client secret");
    const cl = await env.DB.prepare("SELECT * FROM oauth_clients WHERE name = 'Grafana'").first<{ redirect_uris: string; grant_types: string | null; logo_uri: string | null }>();
    expect(cl).not.toBeNull();
    expect(JSON.parse(cl!.redirect_uris)).toEqual(["https://grafana.example.com/login/generic_oauth"]);
    expect(cl!.grant_types).toBe('["authorization_code"]');
    expect(cl!.logo_uri).toContain("/catalog-icons/grafana.svg");
  });
});

describe("applications permission mapping", () => {
  it("maps /admin/apps* to the right areas", () => {
    const r = (perms: string[]) => ({ perms: expand(perms), roles: [], isSuper: false, isAdmin: true });
    const usersOnly = r(["users:write"]);
    const samlRead = r(["saml:read"]);
    const oidcWrite = r(["oidc:write"]);
    // The unified list itself is open to any admin; its rows are gated in the view.
    expect(canAccess(usersOnly, "GET", "/admin/apps")).toBe(true);
    expect(canAccess(usersOnly, "POST", "/admin/apps")).toBe(false);
    // Catalog browsing takes either protocol's read.
    expect(canAccess(usersOnly, "GET", "/admin/apps/catalog")).toBe(false);
    expect(canAccess(usersOnly, "GET", "/admin/apps/catalog/gitlab")).toBe(false);
    expect(canAccess(samlRead, "GET", "/admin/apps/catalog")).toBe(true);
    expect(canAccess(oidcWrite, "GET", "/admin/apps/catalog/grafana")).toBe(true);
    // Applying a template writes into that entry's protocol area.
    expect(canAccess(samlRead, "POST", "/admin/apps/catalog/gitlab/apply")).toBe(false);
    expect(canAccess(r(["saml:write"]), "POST", "/admin/apps/catalog/gitlab/apply")).toBe(true);
    expect(canAccess(oidcWrite, "POST", "/admin/apps/catalog/gitlab/apply")).toBe(false);
    expect(canAccess(oidcWrite, "POST", "/admin/apps/catalog/grafana/apply")).toBe(true);
    expect(canAccess(r(["saml:write"]), "POST", "/admin/apps/catalog/nope/apply")).toBe(false);
    // Other writes under /admin/apps have no route: fail closed.
    expect(canAccess(r(["oidc:write", "saml:write"]), "POST", "/admin/apps/catalog/grafana")).toBe(false);
  });
});

describe("per-app SCIM provisioning", () => {
  it("links a target to an app and shows it on the app's page", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const { spDbId } = await seedApps(apiKey);
    const cookie = await adminCookie();

    // The create form pre-links the app.
    const form = await (await get(`/admin/integrations/scim/new?app_type=saml&app_id=${spDbId}`, cookie)).text();
    expect(form).toContain('name="app_type" value="saml"');
    expect(form).toContain(`name="app_id" value="${spDbId}"`);
    expect(form).toContain("Team Slack");

    const res = await post("/admin/scim/targets", cookie, {
      name: "Slack provisioning",
      endpoint: "https://scim.test",
      secret: "a-scim-bearer-token",
      enabled: "1",
      mode: "all",
      app_type: "saml",
      app_id: String(spDbId),
    });
    expect(res.status).toBe(302);
    const target = await env.DB.prepare("SELECT * FROM scim_targets WHERE name = 'Slack provisioning'").first<{ app_type: string | null; app_id: number | null }>();
    expect(target!.app_type).toBe("saml");
    expect(target!.app_id).toBe(spDbId);

    // The SP's page lists the linked target in its Provisioning card.
    const spPage = await (await get(`/admin/saml/${spDbId}?tab=provisioning`, cookie)).text();
    expect(spPage).toContain("Provisioning");
    expect(spPage).toContain("Slack provisioning");
    expect(spPage).toContain(`app_type=saml&app_id=${spDbId}`);

    // An unknown app linkage is refused, not stored.
    const bad = await post("/admin/scim/targets", cookie, { name: "Nowhere", endpoint: "https://scim.test", secret: "x", app_type: "saml", app_id: "9999" });
    expect(bad.status).toBe(302);
    expect(bad.headers.get("Location")).toContain("error=");
    expect(await env.DB.prepare("SELECT 1 FROM scim_targets WHERE name = 'Nowhere'").first()).toBeNull();

    // Standalone targets (no linkage) still work.
    const solo = await post("/admin/scim/targets", cookie, { name: "Whole directory", endpoint: "https://scim.test", secret: "x", enabled: "1", mode: "all" });
    expect(solo.status).toBe(302);
    expect((await env.DB.prepare("SELECT app_type FROM scim_targets WHERE name = 'Whole directory'").first<{ app_type: string | null }>())!.app_type).toBeNull();
  });
});

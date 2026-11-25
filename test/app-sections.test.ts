import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(() => resetDatabase());
const FORM = { "Content-Type": "application/x-www-form-urlencoded" };

async function seed() {
  const { apiKey } = await bootstrapInstance();
  for (const u of ["ada", "bob"]) await apiCall("/api/v1/users", { token: apiKey, body: { given_name: u, username: u, domain: "example.com", password: "user-password-123", status: "active" } });
  const ids = await Promise.all(["ada", "bob"].map(async (u) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id));
  for (const name of ["Payroll", "Wiki"]) {
    await env.DB.prepare("INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, access_mode) VALUES (?, 'x', ?, '[\"https://app.example/cb\"]', '', 'everyone')").bind(`c-${name}`, name).run();
  }
  const apps = (await env.DB.prepare("SELECT id, name FROM oauth_clients ORDER BY name").all<{ id: number; name: string }>()).results;
  const cookie = async (id: number) => (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { ada: ids[0]!, bob: ids[1]!, apps, adaCookie: await cookie(ids[0]!), bobCookie: await cookie(ids[1]!) };
}
const post = (path: string, body: Record<string, string>, cookie: string) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie, Origin: BASE }, body: new URLSearchParams(body).toString(), redirect: "manual" });
const page = async (cookie: string, q = "") => (await SELF.fetch(`${BASE}/account/applications${q}`, { headers: { Cookie: cookie } })).text();

describe("launchpad sections", () => {
  it("groups apps into the person's own sections, and deleting a section unsorts them", async () => {
    const { apps, adaCookie, bobCookie } = await seed();
    const payroll = apps.find((a) => a.name === "Payroll")!;
    await post("/account/applications/sections", { name: "  Finance  " }, adaCookie);
    const section = (await env.DB.prepare("SELECT id, name FROM user_app_sections").first<{ id: number; name: string }>())!;
    expect(section.name).toBe("Finance");
    await post("/account/applications/place", { app: `oidc:${payroll.id}`, section_id: String(section.id) }, adaCookie);

    const html = await page(adaCookie);
    expect(html).toContain('<h2 class="app-section-title">Finance</h2>');
    expect(html).toContain('<h2 class="app-section-title">Other apps</h2>');
    expect(html.indexOf("Payroll")).toBeLessThan(html.indexOf("Other apps"));
    // Someone else's launchpad is untouched, and they can't place into Ada's section.
    expect(await page(bobCookie)).not.toContain("Finance");
    await post("/account/applications/place", { app: `oidc:${payroll.id}`, section_id: String(section.id) }, bobCookie);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM user_app_placements").first<{ n: number }>())!.n).toBe(1);

    await post(`/account/applications/sections/${section.id}/delete`, {}, adaCookie);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM user_app_placements").first<{ n: number }>())!.n).toBe(0);
    expect(await page(adaCookie)).not.toContain('class="app-section-title"');
  });

  it("organise mode offers a section picker per app and reorders sections", async () => {
    const { adaCookie } = await seed();
    await post("/account/applications/sections", { name: "A" }, adaCookie);
    await post("/account/applications/sections", { name: "B" }, adaCookie);
    const [a, b] = (await env.DB.prepare("SELECT id FROM user_app_sections ORDER BY position").all<{ id: number }>()).results;
    await post(`/account/applications/sections/${b!.id}/move`, { dir: "up" }, adaCookie);
    const order = (await env.DB.prepare("SELECT id FROM user_app_sections ORDER BY position").all<{ id: number }>()).results.map((r) => r.id);
    expect(order).toEqual([b!.id, a!.id]);
    const html = await page(adaCookie, "?organise=1");
    expect(html.match(/name="section_id" data-autosubmit/g)).toHaveLength(2);
    expect(html).toContain("Add section");
  });
});

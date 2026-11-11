// Admin console feedback (v3.1.0): group member search/paging, fixed group type,
// groups CSV import page, overview stats, theme toggle and version.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { VERSION } from "../src/version.js";
import pkg from "../package.json";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function adminCookie() {
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
  return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
}
const get = async (path: string, cookie: string) => (await SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" }));

describe("admin console feedback", () => {
  it("shows the deployed version and a theme toggle; the version matches package.json", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    expect(VERSION).toBe(pkg.version);
    const html = await (await get("/admin", await adminCookie())).text();
    expect(html).toContain(`(v${VERSION})`);
    expect(html).toContain("data-theme-toggle");
    expect(html).toContain("IdP performance");
    expect(await (await get("/admin/performance", await adminCookie())).text()).toContain("Turn on the performance dashboard");
    expect(html).toContain("Last 24 hours");
  });

  it("pages a group's members 30 at a time and finds a person by name or UPN", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const users = Array.from({ length: 35 }, (_, i) => ({ username: `p${String(i).padStart(2, "0")}`, given_name: "Person", family_name: `N${i}`, status: "active", groups: ["Crew"] }));
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", groups: [{ name: "Crew" }], users } });
    const gid = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Crew'").first<{ id: number }>())!.id;
    const cookie = await adminCookie();
    const page1 = await (await get(`/admin/groups/${gid}`, cookie)).text();
    expect(page1).toContain("Members <span class=\"muted\" style=\"font-weight:500;\">(35)");
    expect(page1).toContain("Page 1 of 2");
    expect((page1.match(/\/admin\/users\/\d+">Person/g) ?? []).length).toBe(30);
    const page2 = await (await get(`/admin/groups/${gid}?mpage=2`, cookie)).text();
    expect((page2.match(/\/admin\/users\/\d+">Person/g) ?? []).length).toBe(5);
    const found = await (await get(`/admin/groups/${gid}?msearch=p07`, cookie)).text();
    expect(found).toContain("p07@horizon.test");
    // One row in the members table (the static-member picker further down lists everyone).
    expect((found.match(/\/admin\/users\/\d+">Person/g) ?? []).length).toBe(1);
    const none = await (await get(`/admin/groups/${gid}?msearch=nobody-here`, cookie)).text();
    expect(none).toContain("Nobody in this group matches");
  });

  it("fixes the group type: dynamic converts to static keeping its members, static never becomes dynamic", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const rule = JSON.stringify({ all: [{ field: "department", op: "eq", value: "Sales" }] });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, passwords: "none", groups: [{ name: "Sales", rule }, { name: "Fixed" }], users: [{ username: "sam", department: "Sales", status: "active" }, { username: "tia", department: "Ops", status: "active" }] },
    });
    const sales = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Sales'").first<{ id: number }>())!.id;
    const fixed = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Fixed'").first<{ id: number }>())!.id;
    const cookie = await adminCookie();

    const refused = await SELF.fetch(`${BASE}/admin/groups/${fixed}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams({ name: "Fixed", membership: "dynamic", rule_field: "department", rule_op: "eq", rule_value: "Ops", rule_schema: "" }).toString(), redirect: "manual" });
    expect(refused.status).toBe(400);

    const frozen = await SELF.fetch(`${BASE}/admin/groups/${sales}/freeze`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "", redirect: "manual" });
    expect(frozen.status).toBe(302);
    const row = await env.DB.prepare("SELECT rule FROM groups WHERE id = ?").bind(sales).first<{ rule: string }>();
    expect(row!.rule).toBe("");
    const members = await env.DB.prepare("SELECT u.username FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ?").bind(sales).all<{ username: string }>();
    expect(members.results.map((m) => m.username)).toEqual(["sam"]);
    expect((await SELF.fetch(`${BASE}/admin/groups/${sales}/freeze`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "", redirect: "manual" })).status).toBe(400);
  });

  it("offers a groups-only CSV import page, linked from the groups list", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    expect(await (await get("/admin/groups", cookie)).text()).toContain('href="/admin/groups/import"');
    const html = await (await get("/admin/groups/import", cookie)).text();
    expect(html).toContain('id="groups_csv"');
    expect(html).not.toContain('id="users_csv"');
    const users = await (await get("/admin/users/import", cookie)).text();
    expect(users).toContain('id="users_csv"');
    expect(users).toContain('id="groups_csv"');
  });
});

describe("admin console feedback 2", () => {
  it("adds static members without replacing them, removes one from the members panel", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", groups: [{ name: "Crew" }], users: [{ username: "ann", status: "active", groups: ["Crew"] }, { username: "bob", status: "active" }] } });
    const gid = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Crew'").first<{ id: number }>())!.id;
    const bob = (await env.DB.prepare("SELECT id FROM users WHERE username = 'bob'").first<{ id: number }>())!.id;
    const ann = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ann'").first<{ id: number }>())!.id;
    const cookie = await adminCookie();
    const page = await (await get(`/admin/groups/${gid}`, cookie)).text();
    expect(page.indexOf('name="add_user_ids"')).toBeGreaterThan(0);
    expect(page.indexOf('name="add_user_ids"')).toBeLessThan(page.indexOf("Members <span"));
    const save = await SELF.fetch(`${BASE}/admin/groups/${gid}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams({ name: "Crew", membership: "static", add_user_ids: String(bob) }).toString(), redirect: "manual" });
    expect(save.status).toBe(302);
    const members = async () => (await env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id").bind(gid).all<{ user_id: number }>()).results.map((r) => r.user_id);
    expect(await members()).toEqual([ann, bob].sort((a, b) => a - b));
    expect((await SELF.fetch(`${BASE}/admin/groups/${gid}/members/${ann}/remove`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "", redirect: "manual" })).status).toBe(302);
    expect(await members()).toEqual([bob]);
  });

  it("keeps sign-in pages light, links GitHub, and signs out without Clear-Site-Data", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const login = await (await SELF.fetch(`${BASE}/login`)).text();
    expect(login).toContain('<html data-theme="light">');
    expect(login).not.toContain("fi-theme");
    const admin = await (await get("/admin", await adminCookie())).text();
    expect(admin).toContain('href="https://github.com/securitypedant/flareid"');
    const out = await SELF.fetch(`${BASE}/logout`, { method: "POST", headers: FORM, redirect: "manual" });
    expect(out.headers.get("Clear-Site-Data")).toBeNull();
  });
});

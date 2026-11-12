// Granular admin roles: Directory Admins, Application Admins and Auditors,
// each limited to their console areas, and no path to a role from below Super Admin.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { canAccess } from "../src/lib/admin-roles.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      passwords: "none",
      groups: [{ name: "Crew" }],
      users: [
        { username: "dora", status: "active", groups: ["Directory Admins"] },
        { username: "apu", status: "active", groups: ["Application Admins"] },
        { username: "audi", status: "active", groups: ["Auditors"] },
        { username: "pat", status: "active", groups: ["Crew"] },
      ],
    },
  });
  const sessionFor = async (u: string) => {
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
    return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  };
  const idOf = async (table: string, col: string, v: string) => (await env.DB.prepare(`SELECT id FROM ${table} WHERE ${col} = ?`).bind(v).first<{ id: number }>())!.id;
  return { dora: await sessionFor("dora"), apu: await sessionFor("apu"), audi: await sessionFor("audi"), pat: await sessionFor("pat"), idOf };
}
const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, cookie: string, body: Record<string, string> = {}) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(body).toString(), redirect: "manual" });

describe("admin roles", () => {
  it("maps each role to its console areas", () => {
    const r = (x: string[]) => new Set(x as never[]);
    expect(canAccess(r(["directory"]), "POST", "/admin/users/5")).toBe(true);
    expect(canAccess(r(["directory"]), "GET", "/admin/integrations/oidc")).toBe(false);
    expect(canAccess(r(["applications"]), "POST", "/admin/clients")).toBe(true);
    expect(canAccess(r(["applications"]), "GET", "/admin/integrations/api-keys")).toBe(false);
    expect(canAccess(r(["auditor"]), "GET", "/admin/users")).toBe(true);
    expect(canAccess(r(["auditor"]), "POST", "/admin/users/5")).toBe(false);
    expect(canAccess(r(["auditor"]), "GET", "/admin/security")).toBe(false);
    expect(canAccess(r([]), "GET", "/admin")).toBe(false);
  });

  it("lets each role in only where it belongs, and filters the sidebar", async () => {
    const { dora, apu, audi, pat } = await setup();
    expect((await get("/admin", pat)).status).toBe(403);
    expect((await get("/admin/users", dora)).status).toBe(200);
    expect((await get("/admin/integrations/oidc", dora)).status).toBe(403);
    expect((await get("/admin/security", dora)).status).toBe(403);
    expect((await get("/admin/integrations/oidc", apu)).status).toBe(200);
    expect((await get("/admin/users", apu)).status).toBe(403);
    expect((await get("/admin/users", audi)).status).toBe(200);
    expect((await get("/admin/integrations/scim", audi)).status).toBe(200);
    expect((await post("/admin/groups", audi, { name: "Nope" })).status).toBe(403);
    const side = await (await get("/admin", dora)).text();
    expect(side).toContain('href="/admin/users"');
    expect(side).not.toContain('href="/admin/security"');
    expect(side).not.toContain('href="/admin/integrations"');
  });

  it("keeps admin roles and their holders out of reach below Super Admin", async () => {
    const { dora, idOf } = await setup();
    const superAdmins = await idOf("groups", "name", "Super Admins");
    const dirAdmins = await idOf("groups", "name", "Directory Admins");
    const admin = await idOf("users", "username", "admin");
    const pat = await idOf("users", "username", "pat");
    expect((await post(`/admin/groups/${superAdmins}`, dora, { name: "Super Admins", membership: "static", add_user_ids: String(pat) })).status).toBe(403);
    expect((await post(`/admin/groups/${dirAdmins}`, dora, { name: "Directory Admins", membership: "static", add_user_ids: String(pat) })).status).toBe(403);
    expect((await post(`/admin/users/${admin}/reset-password`, dora)).status).toBe(403);
    expect((await post(`/admin/users/${pat}`, dora, { group_ids: String(superAdmins) })).status).toBe(403);
    const imp = await SELF.fetch(`${BASE}/admin/users/import`, { method: "POST", headers: { "Content-Type": "application/json", Origin: BASE, Cookie: dora }, body: JSON.stringify({ version: 1, users: [{ username: "pat", groups: ["Super Admins"] }] }) });
    expect(imp.status).toBe(400);
    expect(await env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(superAdmins, pat).first()).toBeNull();
  });
});

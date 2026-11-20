// Granular admin roles: Directory Admins, Application Admins and Auditors,
// each limited to their console areas, and no path to a role from below Super Admin.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { canAccess } from "../src/lib/admin-roles.js";
import { expand } from "../src/lib/permissions.js";

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
  return { apiKey, dora: await sessionFor("dora"), apu: await sessionFor("apu"), audi: await sessionFor("audi"), pat: await sessionFor("pat"), idOf };
}
const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, cookie: string, body: Record<string, string> = {}) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(body).toString(), redirect: "manual" });

describe("admin roles", () => {
  it("maps each role's permissions to its console areas", () => {
    const r = (perms: string[]) => ({ perms: expand(perms), roles: [], isSuper: perms.includes("*"), isAdmin: true });
    const dir = r(["users:write", "groups:write", "domains:write", "schemas:write", "import:write", "audit:read", "performance:read"]);
    const aud = r(["users:read", "groups:read", "oidc:read", "audit:read"]);
    expect(canAccess(dir, "POST", "/admin/users/5")).toBe(true);
    // domains:write may manage domains, but "apply to all" moves Super Admins'
    // UPNs - that is Super Admin authority, like its API equivalent's "*" scope.
    expect(canAccess(dir, "POST", "/admin/domains/1/apply-to-all")).toBe(false);
    expect(canAccess(dir, "GET", "/admin/integrations/oidc")).toBe(false);
    expect(canAccess(r(["oidc:write", "saml:write"]), "POST", "/admin/clients")).toBe(true);
    expect(canAccess(r(["oidc:write"]), "GET", "/admin/integrations/api-keys")).toBe(false);
    expect(canAccess(aud, "GET", "/admin/users")).toBe(true);
    expect(canAccess(aud, "POST", "/admin/users/5")).toBe(false);
    expect(canAccess(aud, "GET", "/admin/security")).toBe(false);
    expect(canAccess({ ...r(["signin", "account:read"]), isAdmin: false }, "GET", "/admin")).toBe(false);
    expect(canAccess(r(["*"]), "POST", "/admin/setup")).toBe(true);
    expect(canAccess(dir, "POST", "/admin/setup")).toBe(false);
    // The user-page watch buttons write the risk watchlist (and emit a RISC
    // signal): cfone:write, like the API routes and the CF One page - the
    // /admin/users mount must not weaken them to users:write.
    expect(canAccess(dir, "POST", "/admin/users/5/watch")).toBe(false);
    expect(canAccess(dir, "POST", "/admin/users/5/unwatch")).toBe(false);
    expect(canAccess(r(["cfone:write"]), "POST", "/admin/users/5/watch")).toBe(true);
    expect(canAccess(dir, "POST", `/admin/users/0x${(5).toString(16)}/watch`)).toBe(false);
    // Trusting a SET transmitter hands its claims authority over every
    // account - Super Admin only, like registering an upstream IdP.
    expect(canAccess(r(["signals:write"]), "POST", "/admin/integrations/signals/transmitters")).toBe(false);
    expect(canAccess(r(["signals:write"]), "POST", "/admin/integrations/signals/transmitters/3/delete")).toBe(false);
    expect(canAccess(r(["signals:read"]), "GET", "/admin/integrations/signals/transmitters")).toBe(true);
    // Streams stay delegated: only the trust anchor moved.
    expect(canAccess(r(["signals:write"]), "POST", "/admin/integrations/signals/streams")).toBe(true);
    // Pointing a SCIM target exports the whole directory - Super Admin, while
    // the inbound-server settings stay with scim:write.
    expect(canAccess(r(["scim:write"]), "POST", "/admin/scim/targets")).toBe(false);
    expect(canAccess(r(["scim:write"]), "POST", "/admin/scim/targets/1")).toBe(false);
    expect(canAccess(r(["scim:write"]), "POST", "/admin/scim/targets/1/scope")).toBe(false);
    expect(canAccess(r(["scim:write"]), "POST", "/admin/scim/sync")).toBe(false);
    expect(canAccess(r(["scim:read"]), "GET", "/admin/scim/targets/1")).toBe(true);
    expect(canAccess(r(["scim:write"]), "POST", "/admin/scim/mappings")).toBe(true);
    // LDAP console pages have their own area: a scoped admin without the
    // grant cannot read them, one with it can, and writes need ldap:write.
    expect(canAccess(aud, "GET", "/admin/ldap")).toBe(false);
    expect(canAccess(aud, "GET", "/admin/integrations/ldap")).toBe(false);
    expect(canAccess(r(["ldap:read"]), "GET", "/admin/ldap/some-app")).toBe(true);
    expect(canAccess(r(["ldap:read"]), "POST", "/admin/ldap/some-app/revoke")).toBe(false);
    expect(canAccess(r(["ldap:write"]), "POST", "/admin/ldap/some-app/revoke")).toBe(true);
    // The console root and integrations index stay open to every admin; any
    // other unmapped /admin path fails closed to Super Admin.
    expect(canAccess(aud, "GET", "/admin")).toBe(true);
    expect(canAccess(aud, "GET", "/admin/integrations")).toBe(true);
    expect(canAccess(aud, "GET", "/admin/no-such-page")).toBe(false);
    expect(canAccess(aud, "GET", "/admin/reauth")).toBe(true);
  });

  it("lets each role in only where it belongs, and filters the sidebar", async () => {
    const { dora, apu, audi, pat } = await setup();
    expect((await get("/admin", pat)).status).toBe(403);
    expect((await get("/admin/users", dora)).status).toBe(200);
    expect((await get("/admin/integrations/oidc", dora)).status).toBe(403);
    expect((await get("/admin/security", dora)).status).toBe(403);
    expect((await get("/admin/integrations/oidc", apu)).status).toBe(302); // redirects to /admin/apps
    expect((await get("/admin/users", apu)).status).toBe(403);
    expect((await get("/admin/users", audi)).status).toBe(200);
    expect((await get("/admin/integrations/scim", audi)).status).toBe(200);
    expect((await post("/admin/groups", audi, { name: "Nope" })).status).toBe(403);
    const side = await (await get("/admin", dora)).text();
    expect(side).toContain('href="/admin/users"');
    expect(side).not.toContain('href="/admin/security"');
    expect(side).not.toContain('href="/admin/integrations"');
  });

  it("hides the audit-derived overview from roles without a monitoring permission", async () => {
    const { apiKey, audi, idOf } = await setup();
    // Every built-in admin role carries audit:read + performance:read, so the
    // gate only bites for a custom role: OIDC management, no monitoring.
    const crew = await idOf("groups", "name", "Crew");
    await apiCall("/api/v1/security/roles", { token: apiKey, body: { name: "OIDC Managers", permissions: ["oidc:write"], groups: ["Crew"] } });
    const patId = await idOf("users", "username", "pat");
    const patCookie = (await createSession(env, patId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;

    const patPage = await (await get("/admin", patCookie)).text();
    expect(patPage).not.toContain("Most active accounts");
    expect(patPage).not.toContain("Sign-in outcomes");
    expect(patPage).not.toContain("Last 24 hours");
    expect(patPage).toContain("OIDC Clients");

    // An Auditor reads the log, so the same numbers are theirs.
    const audiPage = await (await get("/admin", audi)).text();
    expect(audiPage).toContain("Most active accounts");
    expect(audiPage).toContain("Last 24 hours");
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

    // apply-to-all is Super Admin authority: a domains:write role cannot use it.
    const domain = await idOf("domains", "domain", "horizon.test");
    expect((await post(`/admin/domains/${domain}/apply-to-all`, dora)).status).toBe(403);
  });

  it("keeps the user-page watch buttons behind cfone:write, like the API and the CF One page", async () => {
    const { dora, idOf } = await setup();
    const patId = await idOf("users", "username", "pat");
    // A Directory Admin (users:write, no cfone) cannot flag or unflag.
    expect((await post(`/admin/users/${patId}/watch`, dora, { reason: "Flagged" })).status).toBe(403);
    expect((await post(`/admin/users/${patId}/unwatch`, dora)).status).toBe(403);
    expect(await env.DB.prepare("SELECT 1 FROM user_watch WHERE user_id = ?").bind(patId).first()).toBeNull();

    // The Super Admin's own button still works.
    const adminId = await idOf("users", "username", "admin");
    const superCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    expect((await post(`/admin/users/${patId}/watch`, superCookie, { reason: "Flagged" })).status).toBe(302);
    expect(await env.DB.prepare("SELECT 1 FROM user_watch WHERE user_id = ?").bind(patId).first()).not.toBeNull();
  });
});

describe("step-up re-authentication", () => {
  it("sends a stale session to re-authenticate before a sensitive action, then lets it through", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    // A multi-factor session (administrators always need one), just an old one.
    const { setCookie, sessionId } = await createSession(env, id, ["pwd", "mfa"], new Request(BASE));
    const cookie = setCookie.split(";")[0]!;
    await env.DB.prepare("UPDATE sessions SET created_at = ? WHERE id = ?").bind(new Date(Date.now() - 30 * 60 * 1000).toISOString(), sessionId).run();

    const mint = () => SELF.fetch(`${BASE}/admin/api-keys`, { method: "POST", headers: { ...FORM, Cookie: cookie, Referer: `${BASE}/admin/integrations/api-keys` }, body: new URLSearchParams({ name: "k", perm_users: "read" }).toString(), redirect: "manual" });
    const blocked = await mint();
    expect(blocked.status).toBe(303);
    const loc = blocked.headers.get("Location")!;
    expect(loc).toMatch(/^\/admin\/reauth\?next=/);
    // The interrupted POST is stashed: success goes to a resume URL, cancel to the form's page.
    const dest = new URL(`${BASE}${loc}`);
    const next = dest.searchParams.get("next")!;
    expect(next).toMatch(/^\/admin\/reauth\/resume\?id=/);
    expect(dest.searchParams.get("back")).toBe("/admin/integrations/api-keys");
    expect(await env.DB.prepare("SELECT 1 FROM api_keys WHERE name = 'k'").first()).toBeNull();
    // Non-sensitive actions are not interrupted.
    expect((await get("/admin/users", cookie)).status).toBe(200);

    const wrong = await post("/admin/reauth", cookie, { password: "nope", next });
    expect(wrong.headers.get("Location")).toContain("error=");
    const ok = await post("/admin/reauth", cookie, { password: "test-admin-password-1", next });
    expect(ok.headers.get("Location")).toBe(next);
    // The resume page replays the stashed POST as an auto-submitting form - once.
    const resume = await (await get(next, cookie)).text();
    expect(resume).toContain('action="/admin/api-keys"');
    expect(resume).toContain('name="name" value="k"');
    expect(resume).toContain('name="perm_users" value="read"');
    expect((await get(next, cookie)).status).not.toBe(200);
    // What the form replays is just a normal POST: the session is fresh now.
    expect((await mint()).status).not.toBe(303);
    expect(await env.DB.prepare("SELECT 1 FROM api_keys WHERE name = 'k'").first()).not.toBeNull();
  });

  it("gates every console POST on a stale session - including user create, groups, and non-digit id spellings", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/users", { token: apiKey, body: { username: "pat", given_name: "Pat", status: "active" } });
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const patId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'pat'").first<{ id: number }>())!.id;
    const { setCookie, sessionId } = await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE));
    const cookie = setCookie.split(";")[0]!;
    await env.DB.prepare("UPDATE sessions SET created_at = ? WHERE id = ?").bind(new Date(Date.now() - 30 * 60 * 1000).toISOString(), sessionId).run();

    const stalePost = (path: string) =>
      SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie, Referer: `${BASE}/admin` }, body: "x=1", redirect: "manual" });

    for (const path of [
      "/admin/users", // mints an account (was the mint-a-Super-Admin door)
      "/admin/users/import",
      `/admin/users/${patId}/status`,
      `/admin/users/${patId}/send-reset`,
      `/admin/users/${patId}/reset-password`,
      `/admin/users/+${patId}/reset-password`, // Number() coerces, \d+ did not match
      `/admin/users/0x${patId.toString(16)}/reset-password`,
      `/admin/users/${patId}%20/delete`,
      "/admin/groups",
      "/admin/clients",
      "/admin/domains",
      "/admin/schemas",
    ]) {
      const res = await stalePost(path);
      expect(res.status, path).toBe(303);
      expect(res.headers.get("Location"), path).toMatch(/^\/admin\/reauth\?next=/);
    }
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username != 'pat' AND username != 'admin'").first()).toBeNull();

    // The re-authentication flow itself stays open - gating it would deadlock.
    const re = await post("/admin/reauth", cookie, { password: "nope", next: "/admin" });
    expect(re.headers.get("Location")).toContain("error=");
  });

  it("lets a fresh session POST to the once-ungated routes", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    // POST /admin/groups with a fresh session reaches the handler, not reauth.
    const res = await post("/admin/groups", cookie, { name: "Fresh Crew", membership: "static" });
    expect(res.status).toBe(302);
    expect(await env.DB.prepare("SELECT 1 FROM groups WHERE name = 'Fresh Crew'").first()).not.toBeNull();
    void apiKey;
  });
});

describe("self-deactivation", () => {
  it("an admin cannot deactivate their own account by the switch or by an import", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const page = await (await get(`/admin/users/${id}`, cookie)).text();
    expect(page).toContain("You cannot deactivate your own account");
    expect((await post(`/admin/users/${id}/status`, cookie, { status: "disabled" })).status).toBe(400);
    const imp = await SELF.fetch(`${BASE}/admin/users/import`, { method: "POST", headers: { "Content-Type": "application/json", Origin: BASE, Cookie: cookie }, body: JSON.stringify({ version: 1, users: [{ username: "admin", status: "disabled" }] }) });
    expect(imp.status).toBe(400);
    expect((await env.DB.prepare("SELECT status FROM users WHERE id = ?").bind(id).first<{ status: string }>())!.status).toBe("active");
  });
});

describe("self-service permissions", () => {
  it("everyone holds the default User role; removing signin from it blocks sign-in", async () => {
    const { pat } = await setup();
    expect((await get("/account", pat)).status).toBe(200);
    await env.DB.prepare("UPDATE admin_roles SET permissions = '[\"account:read\"]' WHERE is_default = 1").run();
    const res = await get("/account", pat);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/login?denied=1");
    expect(await (await SELF.fetch(`${BASE}/login?denied=1`)).text()).toContain("not allowed to sign in");
  });
});

describe("roles page", () => {
  it("lists roles and administrators, creates a custom role, and refuses granting more than you hold", async () => {
    const { dora, idOf } = await setup();
    await bootstrapInstance({ domain: "horizon.test" }).catch(() => undefined);
    const adminId = await idOf("users", "username", "admin");
    const superCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const page = await (await get("/admin/security/roles", superCookie)).text();
    for (const n of ["User", "Super Admin", "Directory Admin", "Application Admin", "Auditor", "Administrators"]) expect(page).toContain(n);
    expect(page).toContain("dora@horizon.test");
    const crew = await idOf("groups", "name", "Crew");
    const created = await post("/admin/security/roles", superCookie, { name: "Helpdesk", description: "Resets", perm_users: "write", group_ids: String(crew) });
    expect(created.status).toBe(302);
    const pat = await idOf("users", "username", "pat");
    const { accessFor } = await import("../src/lib/admin-roles.js");
    expect((await accessFor(env, pat)).perms.has("users:write")).toBe(true);
    // A Directory Admin cannot reach roles at all; and a role editor cannot grant beyond themselves.
    expect((await get("/admin/security/roles", dora)).status).toBe(403);
  });
});

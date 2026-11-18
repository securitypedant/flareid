import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { accessFor } from "../src/lib/admin-roles.js";

beforeEach(resetDatabase);

async function scim(token: string, path: string, method = "GET", body?: unknown) {
  const res = await SELF.fetch(`${BASE}/scim/v2${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/scim+json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/** A delegated provisioning key: reads and writes the directory, must not administer. */
async function directoryWriter(apiKey: string): Promise<string> {
  const res = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "hr", scopes: ["directory:read", "directory:write"] } });
  return res.body.token as string;
}

/** A dynamic group whose rule matches `value` of `field`, linked to the named role. */
async function linkDynamicRoleGroup(name: string, role: string, field: string, value: string): Promise<number> {
  const gid = (await env.DB.prepare("INSERT INTO groups (name, description, rule) VALUES (?, '', ?) RETURNING id")
    .bind(name, JSON.stringify({ all: [{ field, op: "eq", value }] }))
    .first<{ id: number }>())!.id;
  await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT r.id, ? FROM admin_roles r WHERE r.name = ?").bind(gid, role).run();
  return gid;
}

async function userId(upn: string): Promise<number> {
  return (await env.DB.prepare("SELECT id FROM users WHERE upn = ?").bind(upn).first<{ id: number }>())!.id;
}

describe("SCIM admin-role boundary", () => {
  it("refuses a non-admin key to write attributes that grant a dynamic admin role", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const dw = await directoryWriter(apiKey);

    const created = await scim(dw, "/Users", "POST", { userName: "mallory@horizon.test", active: true });
    expect(created.status).toBe(201);

    const patched = await scim(dw, `/Users/${created.body.id}`, "PATCH", {
      schemas: [PATCH],
      Operations: [{ op: "replace", path: `${ENT}:department`, value: "OnCall" }],
    });
    expect(patched.status).toBe(403);
    expect((await accessFor(env, await userId("mallory@horizon.test"))).isAdmin).toBe(false);

    // The PUT twin refuses the same grant.
    const put = await scim(dw, `/Users/${created.body.id}`, "PUT", {
      userName: "mallory@horizon.test",
      [ENT]: { department: "OnCall" },
    });
    expect(put.status).toBe(403);
  });

  it("refuses a non-admin key to provision a user born into a dynamic admin role", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const dw = await directoryWriter(apiKey);

    const created = await scim(dw, "/Users", "POST", {
      userName: "oncall.hire@horizon.test",
      active: true,
      [ENT]: { department: "OnCall" },
    });
    expect(created.status).toBe(403);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE upn = 'oncall.hire@horizon.test'").first()).toBeNull();
  });

  it("lets an admin-scoped key do the same writes", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");

    const created = await scim(apiKey, "/Users", "POST", { userName: "oncall.hire@horizon.test", active: true, [ENT]: { department: "OnCall" } });
    expect(created.status).toBe(201);
    expect((await accessFor(env, await userId("oncall.hire@horizon.test"))).isAdmin).toBe(true);
  });

  it("refuses a mapped custom attribute that lands the user in a role group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    // Rules match custom_attributes by bare name - a mapping writing one is
    // the same grant as writing department.
    await linkDynamicRoleGroup("Vip Admins", "Directory Admin", "level", "gold");
    await apiCall("/api/v1/scim/mappings", { token: apiKey, method: "PUT", body: { mappings: [{ target: "custom.level", expression: "title" }] } });
    const dw = await directoryWriter(apiKey);

    const created = await scim(dw, "/Users", "POST", { userName: "mallory@horizon.test", title: "staff" });
    expect(created.status).toBe(201);

    const patched = await scim(dw, `/Users/${created.body.id}`, "PATCH", {
      schemas: [PATCH],
      Operations: [{ op: "replace", path: "title", value: "gold" }],
    });
    expect(patched.status).toBe(403);
    const row = (await env.DB.prepare("SELECT custom_attributes FROM users WHERE id = ?").bind(await userId("mallory@horizon.test")).first<{ custom_attributes: string }>())!;
    expect(JSON.parse(row.custom_attributes).level ?? "").not.toBe("gold");
    expect((await accessFor(env, await userId("mallory@horizon.test"))).isAdmin).toBe(false);

    const put = await scim(dw, `/Users/${created.body.id}`, "PUT", { userName: "mallory@horizon.test", title: "gold" });
    expect(put.status).toBe(403);
  });

  it("refuses a non-admin key to touch an account holding any admin role", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await directoryWriter(apiKey);

    // A Directory Admin, as an admin would have assigned it.
    const victim = await scim(apiKey, "/Users", "POST", { userName: "diradmin@horizon.test", active: true });
    const uid = await userId("diradmin@horizon.test");
    const da = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Directory Admins'").first<{ id: number }>())!.id;
    await env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(da, uid).run();
    expect((await accessFor(env, uid)).isAdmin).toBe(true);

    const patched = await scim(dw, `/Users/${victim.body.id}`, "PATCH", {
      schemas: [PATCH],
      Operations: [{ op: "replace", path: "active", value: false }],
    });
    expect(patched.status).toBe(403);
    expect((await env.DB.prepare("SELECT status FROM users WHERE id = ?").bind(uid).first<{ status: string }>())!.status).toBe("active");

    expect((await scim(dw, `/Users/${victim.body.id}`, "DELETE")).status).toBe(403);
    const put = await scim(dw, `/Users/${victim.body.id}`, "PUT", { userName: "diradmin@horizon.test", displayName: "Renamed" });
    expect(put.status).toBe(403);
  });

  it("refuses a non-admin key to change an admin-role group, its members, its name, or to delete it", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await directoryWriter(apiKey);
    const da = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Directory Admins'").first<{ id: number }>())!.id;

    const member = await scim(dw, "/Users", "POST", { userName: "mallory@horizon.test", active: true });
    expect(member.status).toBe(201);

    for (const attempt of [
      scim(dw, `/Groups/${da}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "add", path: "members", value: [{ value: member.body.id }] }] }),
      scim(dw, `/Groups/${da}`, "PUT", { displayName: "Directory Admins", members: [] }),
      scim(dw, `/Groups/${da}`, "DELETE"),
    ]) {
      expect((await attempt).status).toBe(403);
    }
    expect((await accessFor(env, await userId("mallory@horizon.test"))).isAdmin).toBe(false);
    expect(await env.DB.prepare("SELECT 1 FROM groups WHERE id = ?").bind(da).first()).not.toBeNull();
  });

  it("refuses a non-admin key to name a group after an admin-role group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await directoryWriter(apiKey);

    expect((await scim(dw, "/Groups", "POST", { displayName: "Directory Admins" })).status).toBe(403);
    expect((await scim(dw, "/Groups", "POST", { displayName: "Super Admins" })).status).toBe(403);

    const own = await scim(dw, "/Groups", "POST", { displayName: "Contractors" });
    expect(own.status).toBe(201);
    const renamed = await scim(dw, `/Groups/${own.body.id}`, "PATCH", {
      schemas: [PATCH],
      Operations: [{ op: "replace", path: "displayName", value: "Application Admins" }],
    });
    expect(renamed.status).toBe(403);
  });

  it("still lets a non-admin key do ordinary directory work", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await directoryWriter(apiKey);

    const created = await scim(dw, "/Users", "POST", { userName: "rita@horizon.test", active: true, [ENT]: { department: "Sales" } });
    expect(created.status).toBe(201);

    const patched = await scim(dw, `/Users/${created.body.id}`, "PATCH", {
      schemas: [PATCH],
      Operations: [{ op: "replace", path: `${ENT}:department`, value: "Support" }],
    });
    expect(patched.status).toBe(200);
    expect(patched.body[ENT].department).toBe("Support");

    const group = await scim(dw, "/Groups", "POST", { displayName: "Support", members: [{ value: created.body.id }] });
    expect(group.status).toBe(201);
    expect((await scim(dw, `/Groups/${group.body.id}`, "DELETE")).status).toBe(204);
  });

  it("rejects a non-address emails.value the API writer refuses", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await directoryWriter(apiKey);
    const created = await scim(dw, "/Users", "POST", { userName: "em@horizon.test", active: true });
    const patched = await scim(dw, `/Users/${created.body.id}`, "PATCH", {
      schemas: [PATCH],
      Operations: [{ op: "replace", path: "emails", value: [{ value: "not-an-email", primary: true }] }],
    });
    expect(patched.status).toBe(400);
  });
});

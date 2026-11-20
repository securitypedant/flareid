// Applying a schema conforms every user: same-named attributes carry over and
// every governed column the target schema drops is cleared. That is a mass
// attribute write, so below admin authority it must obey the same per-user
// rules as a single write - an account holding an admin role is untouchable
// (clearing the field its role group's rule matches on is a de-grant), and no
// conformed row may newly satisfy a role group's rule (a "ne" rule turns a
// cleared field into a fabricated grant).
import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { accessFor } from "../src/lib/admin-roles.js";

beforeEach(resetDatabase);

const USER_PASSWORD = "correct-horse-battery-1";

/** A delegated key holding only the schemas area. */
async function schemasWriter(apiKey: string): Promise<string> {
  const res = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "schemas", scopes: ["schemas:write"] } });
  return res.body.token as string;
}

/** A dynamic group whose single-condition rule is linked to the named role. */
async function linkDynamicRoleGroup(name: string, role: string, cond: { field: string; op: "eq" | "ne"; value: string }): Promise<number> {
  const gid = (await env.DB.prepare("INSERT INTO groups (name, description, rule) VALUES (?, '', ?) RETURNING id")
    .bind(name, JSON.stringify({ all: [cond] }))
    .first<{ id: number }>())!.id;
  await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT r.id, ? FROM admin_roles r WHERE r.name = ?").bind(gid, role).run();
  return gid;
}

/** A user schema defining nothing: conforming clears every governed attribute. */
async function sparseSchema(token: string): Promise<number> {
  const res = await apiCall("/api/v1/schemas", { token, body: { object_type: "user", name: "Sparse", attributes: [] } });
  expect(res.status).toBe(201);
  return res.body.id as number;
}

async function userField(username: string, column: string): Promise<string | null> {
  const row = await env.DB.prepare(`SELECT ${column} AS v FROM users WHERE username = ?`).bind(username).first<{ v: string | null }>();
  return row?.v ?? null;
}

async function userId(username: string): Promise<number> {
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

describe("schema apply vs admin roles", () => {
  it("refuses a delegated schemas:write key to conform an account holding an admin role dynamically", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", { field: "department", op: "eq", value: "OnCall" });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, domain: "horizon.test", users: [{ username: "oncall.user", department: "OnCall", status: "active", password: USER_PASSWORD }] },
    });
    const uid = await userId("oncall.user");
    expect((await accessFor(env, uid)).isAdmin).toBe(true);

    const sw = await schemasWriter(apiKey);
    const id = await sparseSchema(sw);
    const res = await apiCall(`/api/v1/schemas/${id}/apply`, { token: sw, body: {} });
    expect(res.status).toBe(403);
    // A refused apply writes nothing: the rule field survives, so does the role.
    expect(await userField("oncall.user", "department")).toBe("OnCall");
    expect((await accessFor(env, uid)).isAdmin).toBe(true);
  });

  it("refuses an apply that would fabricate an admin grant through a 'ne' rule", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    // department != "OnCall" - clearing department is what makes this match.
    await linkDynamicRoleGroup("Not On-Call", "Directory Admin", { field: "department", op: "ne", value: "OnCall" });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, domain: "horizon.test", users: [{ username: "staff.user", department: "OnCall", status: "active", password: USER_PASSWORD }] },
    });
    const uid = await userId("staff.user");
    expect((await accessFor(env, uid)).isAdmin).toBe(false);

    const sw = await schemasWriter(apiKey);
    const id = await sparseSchema(sw);
    const res = await apiCall(`/api/v1/schemas/${id}/apply`, { token: sw, body: {} });
    expect(res.status).toBe(403);
    expect(await userField("staff.user", "department")).toBe("OnCall");
    expect((await accessFor(env, uid)).isAdmin).toBe(false);
  });

  it("refuses a delegated key to mass-rewrite an account holding an admin role", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    // The setup administrator is a Super Admin; assertMayTouchUser would
    // refuse the same write one user at a time.
    const sw = await schemasWriter(apiKey);
    const id = await sparseSchema(sw);
    const res = await apiCall(`/api/v1/schemas/${id}/apply`, { token: sw, body: {} });
    expect(res.status).toBe(403);
    expect((await accessFor(env, await userId("admin"))).isAdmin).toBe(true);
  });

  it("lets an admin-scoped key apply the same schema", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, domain: "horizon.test", users: [{ username: "staff.user", department: "Sales", status: "active", password: USER_PASSWORD }] },
    });
    const id = await sparseSchema(apiKey);
    const res = await apiCall(`/api/v1/schemas/${id}/apply`, { token: apiKey, body: {} });
    expect(res.status).toBe(200);
    expect(res.body.applied).toBeGreaterThan(0);
    expect(await userField("staff.user", "department")).toBe("");
  });

  it("applies the same guard on the delete fallback, on both routes", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const sw = await schemasWriter(apiKey);
    const id = await sparseSchema(sw);
    // Deleting a schema conforms its objects to the default - the same mass
    // write, so the same refusal below admin authority when one of them holds
    // an admin role. An empty schema still deletes cleanly.
    await env.DB.prepare("UPDATE users SET schema_id = ? WHERE username = 'admin'").bind(id).run();
    const res = await apiCall(`/api/v1/schemas/${id}`, { token: sw, method: "DELETE" });
    expect(res.status).toBe(403);
    const schemas = await apiCall("/api/v1/schemas", { token: sw });
    expect((schemas.body.schemas as { id: number }[]).some((s) => s.id === id)).toBe(true);
    // An admin-scoped key can still delete it.
    expect((await apiCall(`/api/v1/schemas/${id}`, { token: apiKey, method: "DELETE" })).status).toBe(200);
  });
});

import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { accessFor } from "../src/lib/admin-roles.js";

beforeEach(resetDatabase);

const USER_PASSWORD = "correct-horse-battery-1";

/** A delegated key: may bulk-write the directory, must not administer it. */
async function importWriter(apiKey: string): Promise<string> {
  const res = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "etl", scopes: ["import:write"] } });
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

async function importBundle(token: string, bundle: unknown) {
  return apiCall("/api/v1/directory/import", { token, body: bundle });
}

describe("directory import vs admin roles", () => {
  it("refuses a non-admin bundle to write a rule or description on a role-linked group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await importWriter(apiKey);

    const res = await importBundle(dw, {
      version: 1,
      domain: "horizon.test",
      groups: [
        { name: "Directory Admins", rule: JSON.stringify({ all: [{ field: "department", op: "eq", value: "any" }] }), description: "captured" },
        { name: "Ordinary", rule: JSON.stringify({ all: [{ field: "department", op: "eq", value: "Sales" }] }) },
      ],
      users: [],
    });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body.errors)).toMatch(/Directory Admins/);

    const da = (await env.DB.prepare("SELECT rule, description FROM groups WHERE name = 'Directory Admins'").first<{ rule: string; description: string | null }>())!;
    expect(da.rule).toBe("");
    expect(da.description).not.toBe("captured");

    // A plain dynamic group in the same bundle is still fine.
    const ordinary = (await env.DB.prepare("SELECT rule FROM groups WHERE name = 'Ordinary'").first<{ rule: string }>())!;
    expect(JSON.parse(ordinary.rule).all[0].value).toBe("Sales");
  });

  it("refuses a non-admin bundle to touch a user who holds an admin role dynamically", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const dw = await importWriter(apiKey);

    // A dynamic Directory Admin - no group_members row anywhere.
    await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      users: [{ username: "oncall.admin", department: "OnCall", status: "active", password: USER_PASSWORD }],
    });
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'oncall.admin'").first<{ id: number }>())!.id;
    expect((await accessFor(env, uid)).isAdmin).toBe(true);

    // A non-admin bundle overwriting that account (new password, new status):
    // the whole bundle is refused, like a bundle touching a static admin.
    const res = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      users: [{ username: "oncall.admin", status: "disabled", password: "attackers-choice-1", department: "Other" }],
    });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/admin role/);
    const row = (await env.DB.prepare("SELECT status, department FROM users WHERE id = ?").bind(uid).first<{ status: string; department: string }>())!;
    expect(row.status).toBe("active");
    expect(row.department).toBe("OnCall");
  });

  it("refuses a non-admin bundle to create or update a user into a dynamic admin-role group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const dw = await importWriter(apiKey);

    // Create: born matching the rule.
    const born = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      users: [{ username: "new.admin", department: "OnCall", status: "active", password: USER_PASSWORD }],
    });
    expect(born.status).toBe(200);
    expect(JSON.stringify(born.body.errors)).toMatch(/admin role group/);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'new.admin'").first()).toBeNull();

    // Update: moved in afterwards.
    await importBundle(apiKey, { version: 1, domain: "horizon.test", users: [{ username: "rita", department: "Sales", status: "active", password: USER_PASSWORD }] });
    const moved = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      users: [{ username: "rita", department: "OnCall", status: "active" }],
    });
    expect(moved.status).toBe(200);
    expect(JSON.stringify(moved.body.errors)).toMatch(/admin role group/);
    expect((await env.DB.prepare("SELECT department FROM users WHERE username = 'rita'").first<{ department: string }>())!.department).toBe("Sales");
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'rita'").first<{ id: number }>())!.id;
    expect((await accessFor(env, uid)).isAdmin).toBe(false);
  });

  it("replace mode keeps administrators whose role is dynamic", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const dw = await importWriter(apiKey);

    await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      users: [
        { username: "oncall.admin", department: "OnCall", status: "active", password: USER_PASSWORD },
        { username: "gone.user", status: "active", password: USER_PASSWORD },
      ],
    });
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'oncall.admin'").first<{ id: number }>())!.id;
    expect((await accessFor(env, uid)).isAdmin).toBe(true);

    const res = await importBundle(dw, {
      version: 1, domain: "horizon.test", mode: "replace",
      users: [{ username: "fresh.user", status: "active", password: USER_PASSWORD }],
    });
    expect(res.status).toBe(200);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'gone.user'").first()).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'fresh.user'").first()).not.toBeNull();
    // The dynamic admin survived the wipe.
    expect((await accessFor(env, uid)).isAdmin).toBe(true);
  });

  it("lets an admin-scoped bundle write role-group rules", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const res = await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      groups: [{ name: "Directory Admins", rule: JSON.stringify({ all: [{ field: "employee_number", op: "eq", value: "777" }] }) }],
      users: [],
    });
    expect(res.status).toBe(200);
    expect(res.body.errors).toHaveLength(0);
    const da = (await env.DB.prepare("SELECT rule FROM groups WHERE name = 'Directory Admins'").first<{ rule: string }>())!;
    expect(JSON.parse(da.rule).all[0].value).toBe("777");
  });
});

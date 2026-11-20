import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { accessFor } from "../src/lib/admin-roles.js";
import { ensureDomain } from "../src/lib/domains.js";
import { createSession } from "../src/lib/sessions.js";

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

  it("re-checks the grant boundary on the manager second pass", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await importWriter(apiKey);

    await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      users: [{ username: "boss", status: "active", password: USER_PASSWORD }],
    });
    const bossExtId = (await env.DB.prepare("SELECT external_id FROM users WHERE username = 'boss'").first<{ external_id: string }>())!.external_id;
    await linkDynamicRoleGroup("Reports To Boss", "Directory Admin", "manager", bossExtId);

    // Create path: the first pass sees manager_external_id null; the second
    // pass must refuse the write that lands the account in the role group.
    const res = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      users: [{ username: "mallory", status: "active", password: USER_PASSWORD, manager: "boss" }],
    });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body.errors)).toMatch(/admin role group/);
    const mallory = (await env.DB.prepare("SELECT manager_external_id FROM users WHERE username = 'mallory'").first<{ manager_external_id: string | null }>())!;
    expect(mallory.manager_external_id).toBeNull();

    // A user whose main write is refused must not get the manager column
    // written either - the second pass only touches rows the import wrote.
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    await importBundle(apiKey, { version: 1, domain: "horizon.test", users: [{ username: "rita", department: "Sales", status: "active", password: USER_PASSWORD }] });
    const moved = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      users: [{ username: "rita", department: "OnCall", status: "active", manager: "boss" }],
    });
    expect(JSON.stringify(moved.body.errors)).toMatch(/admin role group/);
    const rita = (await env.DB.prepare("SELECT department, manager_external_id FROM users WHERE username = 'rita'").first<{ department: string; manager_external_id: string | null }>())!;
    expect(rita.department).toBe("Sales");
    expect(rita.manager_external_id).toBeNull();

    // The admin-scoped bundle may still set a manager that grants the role.
    const ok = await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      users: [{ username: "trusted", status: "active", password: USER_PASSWORD, manager: "boss" }],
    });
    expect(ok.body.errors).toHaveLength(0);
    expect(ok.body.managers_resolved).toBe(1);
  });

  it("refuses a composed upn that collides with another account's alias or email", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await importWriter(apiKey);
    await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      users: [{ username: "holder", status: "active", password: USER_PASSWORD }],
    });
    const holderId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'holder'").first<{ id: number }>())!.id;
    // holder owns "victim-alias@horizon.test" as an alias, and a second
    // account holds "their-mail@horizon.test" as its primary address.
    await env.DB.prepare("INSERT INTO user_emails (user_id, email, type, is_primary, created_at) VALUES (?, 'victim-alias@horizon.test', 'work', 0, ?)").bind(holderId, new Date().toISOString()).run();
    await env.DB.prepare("INSERT INTO users (upn, username, display_name, password_hash, password_salt, password_iterations, external_id, email, status, created_at, updated_at) VALUES ('someone@horizon.test', 'someone', 'S', '!', '', 0, ?, 'their-mail@horizon.test', 'active', ?, ?)")
      .bind(crypto.randomUUID(), new Date().toISOString(), new Date().toISOString())
      .run();

    const res = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      users: [
        { username: "victim-alias", status: "active", password: USER_PASSWORD },
        { username: "their-mail", status: "active", password: USER_PASSWORD },
        { username: "clean-name", status: "active", password: USER_PASSWORD },
      ],
    });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body.errors)).toMatch(/victim-alias@horizon\.test/);
    expect(JSON.stringify(res.body.errors)).toMatch(/their-mail@horizon\.test/);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'victim-alias'").first()).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'their-mail'").first()).toBeNull();
    // An uninvolved row still imports.
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'clean-name'").first()).not.toBeNull();
    // The alias owner's own upn re-import is untouched by the check.
    const again = await importBundle(dw, { version: 1, domain: "horizon.test", users: [{ username: "holder", status: "active" }] });
    expect(again.body.errors).toHaveLength(0);
  });

  it("refuses rule, description and member writes onto a system group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await importWriter(apiKey);
    // The lazily-created watchlist system group, as flagUser leaves it.
    await env.DB.prepare("INSERT INTO groups (name, description, system) VALUES ('Risk watchlist', 'watchlist desc', 'watchlist')").run();
    await importBundle(apiKey, {
      version: 1, domain: "horizon.test",
      users: [{ username: "ada", status: "active", password: USER_PASSWORD }],
    });
    const adaId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id;

    const res = await importBundle(dw, {
      version: 1, domain: "horizon.test",
      groups: [{ name: "Risk watchlist", description: "captured", rule: JSON.stringify({ all: [{ field: "department", op: "eq", value: "any" }] }) }],
      users: [{ username: "ada", status: "active", groups: ["Risk watchlist"] }],
    });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body.errors)).toMatch(/system group/);
    // Neither the definition nor the membership mirror changed.
    const group = (await env.DB.prepare("SELECT id, rule, description FROM groups WHERE name = 'Risk watchlist'").first<{ id: number; rule: string; description: string }>())!;
    expect(group.rule).toBe("");
    expect(group.description).toBe("watchlist desc");
    expect(await env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(group.id, adaId).first()).toBeNull();
  });

  it("reserves the Risk watchlist name for the system group, whoever the caller is", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await importWriter(apiKey);
    for (const token of [dw, apiKey]) {
      const res = await importBundle(token, { version: 1, groups: [{ name: "Risk watchlist" }], users: [] });
      expect(res.status).toBe(200);
      expect(JSON.stringify(res.body.errors)).toMatch(/reserved/);
    }
    expect(await env.DB.prepare("SELECT 1 FROM groups WHERE name = 'Risk watchlist'").first()).toBeNull();
  });
});

describe("bundle domains are DNS names", () => {
  // The import "ensures" the bundle's domain into the domains table, whose
  // consumers assume DNS names (UPNs embed it, brands suffix-match on it,
  // deleteDomain's LIKE uses it literally): "com" is a capture bug, not a
  // domain. Every writer gates on isValidDomain - the import routes too.
  it("refuses a bundle whose domain is not a DNS name, whoever the caller", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await importWriter(apiKey);

    for (const bad of ["com", "a,b", "a b", "a%"]) {
      const res = await importBundle(dw, { version: 1, domain: bad, users: [{ username: "probe", password: USER_PASSWORD }] });
      expect(res.status, bad).toBe(400);
    }
    // The admin-scoped key gets the same refusal: the invariant is about the
    // value, not the caller's area.
    expect((await importBundle(apiKey, { version: 1, domain: "com", users: [] })).status).toBe(400);
    const { results } = await env.DB.prepare("SELECT domain FROM domains WHERE domain IN ('com', 'a,b', 'a b', 'a%')").all();
    expect(results).toEqual([]);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'probe'").first()).toBeNull();

    // A well-formed fresh domain still imports: the gate is validity, not
    // prior registration.
    const ok = await importBundle(dw, { version: 1, domain: "branch.horizon.test", users: [{ username: "probe", password: USER_PASSWORD }] });
    expect(ok.status).toBe(200);
    expect(await env.DB.prepare("SELECT 1 FROM domains WHERE domain = 'branch.horizon.test'").first()).not.toBeNull();
  });

  it("the console import applies the same check", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const res = await SELF.fetch(`${BASE}/admin/users/import`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: BASE, Cookie: cookie },
      body: JSON.stringify({ version: 1, domain: "com", users: [{ username: "probe", password: USER_PASSWORD }] }),
    });
    expect(res.status).toBe(400);
    expect(await env.DB.prepare("SELECT 1 FROM domains WHERE domain = 'com'").first()).toBeNull();
  });

  it("ensureDomain validates like addDomain but tolerates existing rows", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    await expect(ensureDomain(env, "com")).rejects.toThrow(/not a valid DNS domain name/);
    await expect(ensureDomain(env, "a,b")).rejects.toThrow(/not a valid DNS domain name/);
    await ensureDomain(env, "branch.horizon.test");
    await ensureDomain(env, "branch.horizon.test"); // a second ensure is a no-op, not an error
    expect(await env.DB.prepare("SELECT 1 FROM domains WHERE domain = 'branch.horizon.test'").first()).not.toBeNull();
  });
});

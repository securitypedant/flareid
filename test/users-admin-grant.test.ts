import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { accessFor } from "../src/lib/admin-roles.js";

beforeEach(resetDatabase);

const USER_PASSWORD = "correct-horse-battery-1";

/** A delegated key: may write users, must not grant admin roles. */
async function usersWriter(apiKey: string): Promise<string> {
  const res = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "hr-sync", scopes: ["users:write"] } });
  return res.body.token as string;
}

/** A dynamic group whose rule matches `value` of `field`, linked to the named role. */
async function linkDynamicRoleGroup(name: string, role: string, field: string, value: string): Promise<void> {
  const gid = (await env.DB.prepare("INSERT INTO groups (name, description, rule) VALUES (?, '', ?) RETURNING id")
    .bind(name, JSON.stringify({ all: [{ field, op: "eq", value }] }))
    .first<{ id: number }>())!.id;
  await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT r.id, ? FROM admin_roles r WHERE r.name = ?").bind(gid, role).run();
}

describe("users:write vs dynamic admin roles", () => {
  it("refuses to create a user whose attributes match a dynamic admin-role rule", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const uw = await usersWriter(apiKey);

    const res = await apiCall("/api/v1/users", {
      token: uw,
      body: { username: "sneaky", given_name: "Sneaky", status: "active", password: USER_PASSWORD, schema: "FlareID HR", attributes: { department: "OnCall" } },
    });
    expect(res.status).toBe(403);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'sneaky'").first()).toBeNull();
  });

  it("refuses a PATCH that moves a user into a dynamic admin-role rule", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const uw = await usersWriter(apiKey);

    await apiCall("/api/v1/users", { token: apiKey, body: { username: "rita", given_name: "Rita", status: "active", password: USER_PASSWORD, schema: "FlareID HR" } });
    const res = await apiCall(`/api/v1/users/rita`, { token: uw, method: "PATCH", body: { attributes: { department: "OnCall" } } });
    expect(res.status).toBe(403);
    const uid = (await env.DB.prepare("SELECT id, department FROM users WHERE username = 'rita'").first<{ id: number; department: string }>())!;
    expect(uid.department).not.toBe("OnCall");
    expect((await accessFor(env, uid.id)).isAdmin).toBe(false);
  });

  it("refuses a status change that would grant a dynamic admin role", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("Active Admins", "Directory Admin", "status", "active");
    const uw = await usersWriter(apiKey);

    // Disabled user whose other fields are irrelevant - the rule matches status alone.
    await apiCall("/api/v1/users", { token: apiKey, body: { username: "dormant", given_name: "Dor", status: "disabled", password: USER_PASSWORD } });
    const res = await apiCall(`/api/v1/users/dormant`, { token: uw, method: "PATCH", body: { status: "active" } });
    expect(res.status).toBe(403);
    expect((await env.DB.prepare("SELECT status FROM users WHERE username = 'dormant'").first<{ status: string }>())!.status).toBe("disabled");
  });

  it("refuses to invite a disabled user who would match a status-rule admin role once active", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("Active Admins", "Directory Admin", "status", "active");
    const uw = await usersWriter(apiKey);

    await apiCall("/api/v1/users", { token: apiKey, body: { username: "dormant", given_name: "Dor", status: "disabled", password: USER_PASSWORD } });

    // The route needs the EMAIL binding, which the test env lacks; the guard
    // lives in the service, so call it as a non-privileged actor would.
    const { sendUserLink } = await import("../src/services/users.js");
    const { getUserById } = await import("../src/services/users.js");
    const user = await getUserById(env, (await env.DB.prepare("SELECT id FROM users WHERE username = 'dormant'").first<{ id: number }>())!.id);
    const ctx = { env, actor: { id: null, upn: "api-key hr-sync" }, privileged: false, selfId: null, req: new Request("https://test/") };
    await expect(sendUserLink(ctx, user!, "invite")).rejects.toThrow(/admin role group/);
    // No token was issued: the account can still be activated only by an admin.
    expect(await env.DB.prepare("SELECT 1 FROM account_tokens").first()).toBeNull();
  });

  it("still lets users:write do ordinary attribute writes", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");
    const uw = await usersWriter(apiKey);

    await apiCall("/api/v1/users", { token: apiKey, body: { username: "rita", given_name: "Rita", status: "active", password: USER_PASSWORD, schema: "FlareID HR" } });
    const res = await apiCall(`/api/v1/users/rita`, { token: uw, method: "PATCH", body: { attributes: { department: "Sales" } } });
    expect(res.status).toBe(200);
    expect((await env.DB.prepare("SELECT department FROM users WHERE username = 'rita'").first<{ department: string }>())!.department).toBe("Sales");
  });

  it("lets an admin key grant the role", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await linkDynamicRoleGroup("On-Call", "Directory Admin", "department", "OnCall");

    await apiCall("/api/v1/users", { token: apiKey, body: { username: "rita", given_name: "Rita", status: "active", password: USER_PASSWORD, schema: "FlareID HR" } });
    const res = await apiCall(`/api/v1/users/rita`, { token: apiKey, method: "PATCH", body: { attributes: { department: "OnCall" } } });
    expect(res.status).toBe(200);
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'rita'").first<{ id: number }>())!.id;
    expect((await accessFor(env, uid)).isAdmin).toBe(true);
  });
});

import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { myAccessHistory } from "../src/lib/access.js";

beforeEach(() => resetDatabase());

async function seed() {
  const { apiKey } = await bootstrapInstance();
  const u = await apiCall("/api/v1/users", { token: apiKey, body: { given_name: "Ada", username: "ada", domain: "example.com", password: "user-password-123", status: "active" } });
  expect(u.status).toBe(201);
  const user = (await env.DB.prepare("SELECT id FROM users WHERE upn = 'ada@example.com'").first<{ id: number }>())!;
  const g = await apiCall("/api/v1/groups", { token: apiKey, body: { name: "Engineering" } });
  expect(g.status).toBe(201);
  const group = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Engineering'").first<{ id: number }>())!;
  return { apiKey, userId: user.id, groupId: group.id };
}

describe("access history", () => {
  it("records group adds and removes through the API", async () => {
    const { apiKey, userId, groupId } = await seed();
    const add = await apiCall(`/api/v1/groups/${groupId}/members`, { token: apiKey, body: { usernames: ["ada"] } });
    expect(add.body).toMatchObject({ ok: true, added: 1 });
    expect((await apiCall(`/api/v1/groups/${groupId}/members/ada`, { token: apiKey, method: "DELETE" })).status).toBeLessThan(300);
    const events = await myAccessHistory(env, userId);
    expect(events.map((e) => [e.target_name, e.action])).toEqual([
      ["Engineering", "removed"],
      ["Engineering", "added"],
    ]);
  });

  it("a replace-all rewrite logs nothing for members who stayed", async () => {
    const { userId, groupId } = await seed();
    await env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(groupId, userId).run();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(groupId),
      env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(groupId, userId),
    ]);
    expect((await myAccessHistory(env, userId)).map((e) => e.action)).toEqual(["added"]);
  });

  it("records direct app assignment changes, including app deletion", async () => {
    const { userId } = await seed();
    await env.DB.prepare(
      "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, assigned_users) VALUES ('c1', 'x', 'Wiki', '[]', '', '[]')"
    ).run();
    await env.DB.prepare("UPDATE oauth_clients SET assigned_users = ? WHERE client_id = 'c1'").bind(JSON.stringify([userId])).run();
    await env.DB.prepare("UPDATE oauth_clients SET name = 'Wiki 2' WHERE client_id = 'c1'").run();
    await env.DB.prepare("DELETE FROM oauth_clients WHERE client_id = 'c1'").run();
    expect((await myAccessHistory(env, userId)).map((e) => [e.target_type, e.target_name, e.action])).toEqual([
      ["oidc_app", "Wiki 2", "removed"],
      ["oidc_app", "Wiki", "added"],
    ]);
  });

  it("deleting the user leaves no history behind and does not fail", async () => {
    const { userId, groupId } = await seed();
    await env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(groupId, userId).run();
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM access_history WHERE user_id = ?").bind(userId).first<{ n: number }>())!.n).toBe(0);
  });
});

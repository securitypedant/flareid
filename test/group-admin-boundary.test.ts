import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { addGroupMembers, createGroup, removeGroupMember, updateGroup } from "../src/services/groups.js";
import type { ServiceCtx } from "../src/services/context.js";

beforeEach(resetDatabase);

/** A delegated key: may write groups, must not touch administrators. */
async function groupsWriter(apiKey: string): Promise<string> {
  const res = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "etl", scopes: ["groups:write"] } });
  return res.body.token as string;
}

async function makeGroup(apiKey: string, name: string): Promise<number> {
  const res = await apiCall("/api/v1/groups", { token: apiKey, body: { name } });
  if (res.status !== 201) throw new Error(`group create failed: ${JSON.stringify(res.body)}`);
  return res.body.id as number;
}

const memberOf = (groupId: number, userId: number) => env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(groupId, userId).first();
const adminId = () => env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>().then((r) => r!.id);
const memberlessInput = { name: "Synced", description: "", rule: "", schemaId: null, custom: {}, requestable: false, cfListSync: false };

/** The boundary a directory-scoped caller (key, console role, group manager) runs as. */
const delegated: ServiceCtx = { env, actor: { id: null, upn: "delegated@test" }, privileged: false, selfId: null };
const privileged: ServiceCtx = { env, actor: { id: null, upn: "admin@test" }, privileged: true, selfId: null };

describe("group membership writes vs admin accounts", () => {
  it("refuses a non-privileged caller to add or remove an administrator's memberships", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const gw = await groupsWriter(apiKey);
    const groupId = await makeGroup(apiKey, "Synced");
    const uid = await adminId();

    // API surface: add an administrator to an ordinary group.
    const add = await apiCall(`/api/v1/groups/${groupId}/members`, { token: gw, body: { usernames: ["admin"] } });
    expect(add.status).toBe(403);
    expect(await memberOf(groupId, uid)).toBeNull();

    // Service surface, same checks: create-with-members, update replace, remove.
    await expect(createGroup(delegated, { ...memberlessInput, name: "Fresh" }, [uid])).rejects.toThrow(/admin role/);
    await env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(groupId, uid).run();
    await expect(removeGroupMember(delegated, groupId, uid)).rejects.toThrow(/admin role/);
    await expect(updateGroup(delegated, groupId, memberlessInput, [])).rejects.toThrow(/admin role/);
    expect(await memberOf(groupId, uid)).toBeTruthy();

    // API surface: remove the administrator.
    const del = await apiCall(`/api/v1/groups/${groupId}/members/admin`, { token: gw, method: "DELETE" });
    expect(del.status).toBe(403);
    expect(await memberOf(groupId, uid)).toBeTruthy();
  });

  it("still lets an admin-scoped caller manage an administrator's memberships", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const groupId = await makeGroup(apiKey, "Synced");
    const uid = await adminId();

    const add = await apiCall(`/api/v1/groups/${groupId}/members`, { token: apiKey, body: { usernames: ["admin"] } });
    expect(add.status).toBe(200);
    expect(await memberOf(groupId, uid)).toBeTruthy();
    const del = await apiCall(`/api/v1/groups/${groupId}/members/admin`, { token: apiKey, method: "DELETE" });
    expect(del.status).toBe(200);
    expect(await memberOf(groupId, uid)).toBeNull();

    await addGroupMembers(privileged, groupId, [uid]);
    await removeGroupMember(privileged, groupId, uid);
    await updateGroup(privileged, groupId, memberlessInput, [uid]);
    expect(await memberOf(groupId, uid)).toBeTruthy();
  });

  it("leaves ordinary members to delegated writers", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const gw = await groupsWriter(apiKey);
    const groupId = await makeGroup(apiKey, "Synced");
    await apiCall("/api/v1/users", { token: apiKey, body: { username: "ada", given_name: "Ada", password: "user-password-123", status: "active" } });

    const add = await apiCall(`/api/v1/groups/${groupId}/members`, { token: gw, body: { usernames: ["ada"] } });
    expect(add.status).toBe(200);
    expect(add.body.added).toBe(1);

    // A replace that only rewrites the same set touches nobody - allowed.
    const adaId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id;
    await updateGroup(delegated, groupId, memberlessInput, [adaId]);
    expect(await memberOf(groupId, adaId)).toBeTruthy();
  });
});

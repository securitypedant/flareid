import type { Env } from "../env.js";
import { getScimConfig, getScimScope, type ScimScope } from "./settings.js";
import type { GroupRow, UserRow } from "./types.js";

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

export interface ScimResult {
  ok: boolean;
  status?: number;
  error?: string;
}

async function isUserInScimScope(env: Env, scope: ScimScope, userId: number): Promise<boolean> {
  if (scope.mode === "all") return true;
  if (scope.groupIds.length === 0) return false;
  const placeholders = scope.groupIds.map(() => "?").join(",");
  const row = await env.DB.prepare(`SELECT 1 FROM group_members WHERE user_id = ? AND group_id IN (${placeholders})`)
    .bind(userId, ...scope.groupIds)
    .first();
  return !!row;
}

function isGroupInScimScope(scope: ScimScope, groupId: number): boolean {
  return scope.mode === "all" || scope.groupIds.includes(groupId);
}

async function scimFetch(env: Env, path: string, init: RequestInit): Promise<Response> {
  const { endpoint, secret } = await getScimConfig(env);
  if (!endpoint || !secret) throw new Error("SCIM is not configured (Admin -> SCIM)");

  return fetch(`${endpoint}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/scim+json",
      Accept: "application/scim+json",
      ...init.headers,
    },
  });
}

/**
 * Builds the SCIM User resource for a person, including their job title (core
 * User schema) and department/manager (Enterprise User extension - standard
 * SCIM attributes for exactly this). The manager is only included once they
 * themselves have been pushed and have a scim_id - it self-heals on the next
 * sync if pushed out of order.
 */
async function userToScim(env: Env, user: UserRow) {
  let manager: { value: string; displayName?: string } | undefined;
  if (user.manager_external_id) {
    const managerRow = await env.DB.prepare("SELECT scim_id, display_name FROM users WHERE external_id = ?")
      .bind(user.manager_external_id)
      .first<{ scim_id: string | null; display_name: string }>();
    if (managerRow?.scim_id) manager = { value: managerRow.scim_id, displayName: managerRow.display_name };
  }

  return {
    schemas: [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
    externalId: user.external_id,
    userName: user.upn,
    name: { givenName: user.given_name, familyName: user.family_name },
    displayName: user.display_name,
    title: user.job_title || undefined,
    emails: [{ value: user.upn, primary: true, type: "work" }],
    active: user.status === "active",
    [ENTERPRISE_USER_SCHEMA]: {
      employeeNumber: user.employee_number || undefined,
      department: user.department || undefined,
      manager,
    },
  };
}

/**
 * Creates the user in the SCIM server if it doesn't have a scim_id yet,
 * otherwise replaces (PUT) it. Respects the configured SCIM sync scope: a
 * user outside scope is deactivated (if previously synced) or skipped
 * entirely (if never synced).
 */
export async function pushUser(env: Env, user: UserRow): Promise<ScimResult> {
  try {
    const scope = await getScimScope(env);
    if (!(await isUserInScimScope(env, scope, user.id))) {
      return user.scim_id ? deactivateUserScim(env, user) : { ok: true };
    }

    const body = JSON.stringify(await userToScim(env, user));

    if (!user.scim_id) {
      return createScimUser(env, user, body);
    }

    const res = await scimFetch(env, `/Users/${user.scim_id}`, { method: "PUT", body });
    if (res.ok) return { ok: true, status: res.status };

    // The remote resource we had on file is gone (e.g. the SCIM population was
    // reset) - self-heal by recreating it instead of failing forever.
    if (res.status === 404) {
      await env.DB.prepare("UPDATE users SET scim_id = NULL WHERE id = ?").bind(user.id).run();
      return createScimUser(env, { ...user, scim_id: null }, body);
    }

    return { ok: false, status: res.status, error: await res.text() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function createScimUser(env: Env, user: UserRow, body: string): Promise<ScimResult> {
  const res = await scimFetch(env, "/Users", { method: "POST", body });
  if (!res.ok) return { ok: false, status: res.status, error: await res.text() };
  const created = await res.json<{ id: string }>();
  await env.DB.prepare("UPDATE users SET scim_id = ? WHERE id = ?").bind(created.id, user.id).run();
  return { ok: true, status: res.status };
}

/** Marks a user inactive in the SCIM server (Access treats this as deprovisioning) rather than hard-deleting. */
export async function deactivateUserScim(env: Env, user: UserRow): Promise<ScimResult> {
  if (!user.scim_id) return { ok: true };
  try {
    const res = await scimFetch(env, `/Users/${user.scim_id}`, {
      method: "PATCH",
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "active", value: false }],
      }),
    });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await res.text() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

export async function deleteUserScim(env: Env, user: UserRow): Promise<ScimResult> {
  if (!user.scim_id) return { ok: true };
  try {
    const res = await scimFetch(env, `/Users/${user.scim_id}`, { method: "DELETE" });
    return res.ok || res.status === 404 ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await res.text() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

function groupToScim(group: GroupRow, members: { scimId: string; upn: string }[]) {
  return {
    schemas: [GROUP_SCHEMA],
    externalId: String(group.id),
    displayName: group.name,
    members: members.map((m) => ({ value: m.scimId, display: m.upn })),
  };
}

/**
 * Creates/replaces a group in the SCIM server. Members without a scim_id yet
 * (not pushed as users) are skipped - push users first. A group outside the
 * configured scope is removed from the SCIM server (if previously synced) or
 * skipped entirely (if never synced).
 */
export async function pushGroup(
  env: Env,
  group: GroupRow,
  members: { scimId: string; upn: string }[]
): Promise<ScimResult> {
  try {
    const scope = await getScimScope(env);
    if (!isGroupInScimScope(scope, group.id)) {
      if (!group.scim_id) return { ok: true };
      const result = await deleteGroupScim(env, group);
      if (result.ok) await env.DB.prepare("UPDATE groups SET scim_id = NULL WHERE id = ?").bind(group.id).run();
      return result;
    }

    if (!group.scim_id) {
      return createScimGroup(env, group, members);
    }

    const res = await scimFetch(env, `/Groups/${group.scim_id}`, {
      method: "PUT",
      body: JSON.stringify(groupToScim(group, members)),
    });
    if (res.ok) return { ok: true, status: res.status };

    // Self-heal, same as pushUser: recreate if the remote resource is gone.
    if (res.status === 404) {
      await env.DB.prepare("UPDATE groups SET scim_id = NULL WHERE id = ?").bind(group.id).run();
      return createScimGroup(env, { ...group, scim_id: null }, members);
    }

    return { ok: false, status: res.status, error: await res.text() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function createScimGroup(env: Env, group: GroupRow, members: { scimId: string; upn: string }[]): Promise<ScimResult> {
  const res = await scimFetch(env, "/Groups", { method: "POST", body: JSON.stringify(groupToScim(group, members)) });
  if (!res.ok) return { ok: false, status: res.status, error: await res.text() };
  const created = await res.json<{ id: string }>();
  await env.DB.prepare("UPDATE groups SET scim_id = ? WHERE id = ?").bind(created.id, group.id).run();
  return { ok: true, status: res.status };
}

export async function deleteGroupScim(env: Env, group: GroupRow): Promise<ScimResult> {
  if (!group.scim_id) return { ok: true };
  try {
    const res = await scimFetch(env, `/Groups/${group.scim_id}`, { method: "DELETE" });
    return res.ok || res.status === 404 ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await res.text() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

export async function testScimConnection(env: Env): Promise<ScimResult> {
  try {
    const res = await scimFetch(env, "/Users?count=1", { method: "GET" });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await res.text() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/** Pushes every user, then every group (with resolved member scim_ids). Best-effort; returns a summary. */
export async function syncAll(env: Env): Promise<{ users: number; userErrors: number; groups: number; groupErrors: number }> {
  const { results: users } = await env.DB.prepare("SELECT * FROM users").all<UserRow>();
  let userErrors = 0;
  for (const user of users) {
    const result = await pushUser(env, user);
    if (!result.ok) userErrors++;
  }

  const { results: groups } = await env.DB.prepare("SELECT * FROM groups").all<GroupRow>();
  let groupErrors = 0;
  for (const group of groups) {
    const { results: memberRows } = await env.DB.prepare(
      "SELECT u.scim_id as scimId, u.upn FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ? AND u.scim_id IS NOT NULL"
    )
      .bind(group.id)
      .all<{ scimId: string; upn: string }>();

    const result = await pushGroup(env, group, memberRows);
    if (!result.ok) groupErrors++;
  }

  return { users: users.length, userErrors, groups: groups.length, groupErrors };
}

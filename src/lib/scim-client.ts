import type { Env } from "../env.js";
import { resolveGroupMemberUserIds, parseRule, userMatchesRule } from "./groups.js";
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
  const row = await env.DB.prepare(`SELECT 1 FROM group_members WHERE user_id = ? AND group_id IN (SELECT value FROM json_each(?))`)
    .bind(userId, JSON.stringify(scope.groupIds))
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
      // Only for a user that still exists here: a push working from a row
      // captured before a delete would otherwise resurrect the account.
      const cleared = await env.DB.prepare("UPDATE users SET scim_id = NULL WHERE id = ?").bind(user.id).run();
      if (cleared.meta.changes === 0) return { ok: true, status: 404 };
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
  const linked = await env.DB.prepare("UPDATE users SET scim_id = ? WHERE id = ?").bind(created.id, user.id).run();
  // Deleted locally while the POST was in flight: the new remote user has no
  // local link, so it goes straight onto the deprovision queue.
  if (linked.meta.changes === 0) await queueScimDeprovision(env, "user", created.id, user.upn).run();
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
      const cleared = await env.DB.prepare("UPDATE groups SET scim_id = NULL WHERE id = ?").bind(group.id).run();
      if (cleared.meta.changes === 0) return { ok: true, status: 404 };
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
  const linked = await env.DB.prepare("UPDATE groups SET scim_id = ? WHERE id = ?").bind(created.id, group.id).run();
  if (linked.meta.changes === 0) await queueScimDeprovision(env, "group", created.id, group.name).run();
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
/** Users pushed per invocation: a full sync of a large directory continues across invocations (the hourly cron). */
const SYNC_BATCH = 200;
const SYNC_CURSOR_KEY = "scim_sync_cursor";

/**
 * A full sync, in bounded batches. Each call pushes the next SYNC_BATCH users
 * after the stored cursor; when no users are left it pushes every group and
 * clears the cursor. `complete` says whether this call finished the sync; if
 * not, the next call (manual, or the cron via continueScimSync) picks it up;
 * once a sync completes the cursor is cleared, so the next call starts afresh.
 */
export async function syncAll(env: Env, opts: { restart?: boolean } = {}): Promise<{ users: number; userErrors: number; groups: number; groupErrors: number; complete: boolean; remainingUsers: number }> {
  await drainScimDeprovisionQueue(env);
  const stored = opts.restart ? 0 : Number((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(SYNC_CURSOR_KEY).first<{ value: string }>())?.value) || 0;
  const { results: users } = await env.DB.prepare("SELECT * FROM users WHERE id > ? ORDER BY id LIMIT ?").bind(stored, SYNC_BATCH).all<UserRow>();
  let userErrors = 0;
  for (const user of users) {
    const result = await pushUser(env, user);
    if (!result.ok) userErrors++;
  }
  const setCursor = (v: string) =>
    env.DB.prepare("INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
      .bind(SYNC_CURSOR_KEY, v, new Date().toISOString())
      .run();
  if (users.length === SYNC_BATCH) {
    const last = users[users.length - 1]!.id;
    await setCursor(String(last));
    const remaining = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE id > ?").bind(last).first<{ n: number }>())?.n ?? 0;
    // Exactly a batch left nothing behind: carry straight on to the groups.
    if (remaining > 0) return { users: users.length, userErrors, groups: 0, groupErrors: 0, complete: false, remainingUsers: remaining };
  }
  const { groups, groupErrors } = await syncGroups(env);
  await setCursor("");
  return { users: users.length, userErrors, groups, groupErrors, complete: true, remainingUsers: 0 };
}

/** Cron: carries on a full sync that a previous invocation left unfinished. */
export async function continueScimSync(env: Env): Promise<void> {
  const cursor = (await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(SYNC_CURSOR_KEY).first<{ value: string }>())?.value;
  if (cursor && (await isScimConfigured(env))) await syncAll(env, { restart: false });
}

/** Pushes every group with its resolved members (dynamic ones included). */
/** Pushes one group with its current resolved members (for writers that change a single group). */
export async function pushGroupCurrent(env: Env, group: GroupRow): Promise<ScimResult> {
  const memberIds = await resolveGroupMemberUserIds(env, group);
  const { results } = memberIds.length
    ? await env.DB.prepare("SELECT scim_id as scimId, upn FROM users WHERE id IN (SELECT value FROM json_each(?)) AND scim_id IS NOT NULL")
        .bind(JSON.stringify(memberIds))
        .all<{ scimId: string; upn: string }>()
    : { results: [] as { scimId: string; upn: string }[] };
  return pushGroup(env, group, results);
}

/**
 * A queue entry for a remote object whose local row is being deleted - run it
 * in the same batch as the deletion, then drain. The remote id survives a
 * failed or budget-cut DELETE instead of vanishing with the row.
 */
export function queueScimDeprovision(env: Env, kind: "user" | "group", scimId: string, label: string): D1PreparedStatement {
  return env.DB.prepare("INSERT OR IGNORE INTO scim_deprovision_queue (kind, scim_id, label, queued_at) VALUES (?, ?, ?, ?)").bind(kind, scimId, label, new Date().toISOString());
}

/**
 * Re-pushes the dynamic groups whose rule result differs between a user's old
 * and new row (all of them a user could match when there is no old row). One
 * failure does not skip the rest; failures are reported together.
 */
export async function pushChangedDynamicGroups(env: Env, before: UserRow | null, after: UserRow | null): Promise<ScimResult> {
  const { results } = await env.DB.prepare("SELECT * FROM groups WHERE rule != ''").all<GroupRow>();
  const errors: string[] = [];
  for (const group of results) {
    const rule = parseRule(group.rule);
    if (!rule) continue;
    const was = before ? userMatchesRule(before, rule) : false;
    const now = after ? userMatchesRule(after, rule) : false;
    if (was === now) continue;
    const r = await pushGroupCurrent(env, group);
    if (!r.ok) errors.push(`${group.name}: ${r.error ?? r.status}`);
  }
  return errors.length ? { ok: false, error: errors.join("; ").slice(0, 500) } : { ok: true };
}

/**
 * Re-pushes users who were just removed from a group, so pushUser can
 * re-evaluate their SCIM scope (and deactivate them downstream if they left it).
 */
export async function pushUsersById(env: Env, ids: number[]): Promise<ScimResult> {
  const errors: string[] = [];
  for (const id of ids) {
    const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
    if (!user) continue;
    const r = await pushUser(env, user);
    if (!r.ok) errors.push(`${user.upn}: ${r.error ?? r.status}`);
  }
  return errors.length ? { ok: false, error: errors.join("; ").slice(0, 500) } : { ok: true };
}

/** Remote objects still to delete per invocation: keeps each request inside the Workers subrequest budget. */
const DEPROVISION_BATCH = 25;

/**
 * Sends queued downstream DELETEs (scim_deprovision_queue), at most
 * DEPROVISION_BATCH per call. A success - or a 404, already gone - removes the
 * entry; a failure stays queued for the next drain.
 */
export async function drainScimDeprovisionQueue(env: Env): Promise<{ removed: number; removedUsers: number; removedGroups: number; failed: number; remaining: number }> {
  let removedUsers = 0;
  let removedGroups = 0;
  let failed = 0;
  if (await isScimConfigured(env)) {
    const { results } = await env.DB.prepare("SELECT kind, scim_id, label FROM scim_deprovision_queue ORDER BY attempts, queued_at LIMIT ?")
      .bind(DEPROVISION_BATCH)
      .all<{ kind: "user" | "group"; scim_id: string; label: string }>();
    for (const item of results) {
      const r = item.kind === "user"
        ? await deleteUserScim(env, { scim_id: item.scim_id } as UserRow)
        : await deleteGroupScim(env, { scim_id: item.scim_id } as GroupRow);
      if (r.ok) {
        if (item.kind === "user") removedUsers++;
        else removedGroups++;
        await env.DB.prepare("DELETE FROM scim_deprovision_queue WHERE kind = ? AND scim_id = ?").bind(item.kind, item.scim_id).run();
      } else {
        failed++;
        await env.DB.prepare("UPDATE scim_deprovision_queue SET attempts = attempts + 1, last_error = ? WHERE kind = ? AND scim_id = ?")
          .bind(String(r.error ?? r.status ?? "failed").slice(0, 500), item.kind, item.scim_id)
          .run();
      }
    }
  }
  const remaining = (await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_deprovision_queue").first<{ n: number }>())?.n ?? 0;
  return { removed: removedUsers + removedGroups, removedUsers, removedGroups, failed, remaining };
}

export async function syncGroups(env: Env): Promise<{ groups: number; groupErrors: number }> {
  const { results: groups } = await env.DB.prepare("SELECT * FROM groups").all<GroupRow>();
  let groupErrors = 0;
  for (const group of groups) {
    const memberIds = await resolveGroupMemberUserIds(env, group);
    const { results: memberRows } = memberIds.length
      ? await env.DB.prepare(
          `SELECT scim_id as scimId, upn FROM users WHERE id IN (SELECT value FROM json_each(?)) AND scim_id IS NOT NULL`
        )
          .bind(JSON.stringify(memberIds))
          .all<{ scimId: string; upn: string }>()
      : { results: [] as { scimId: string; upn: string }[] };

    const result = await pushGroup(env, group, memberRows);
    if (!result.ok) groupErrors++;
  }

  return { groups: groups.length, groupErrors };
}

export async function isScimConfigured(env: Env): Promise<boolean> {
  const { endpoint, secret } = await getScimConfig(env);
  return !!endpoint && !!secret;
}

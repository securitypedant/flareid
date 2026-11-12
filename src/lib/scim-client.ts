import { resolveManyGroupMemberUserIds } from "./groups.js";
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

/** A group member as pushed: the local user and the remote user id they were sent as. */
export interface ScimMember {
  userId: number;
  scimId: string;
  upn: string;
}

const PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
/** Member references per PATCH request: keeps each body small for a big change. */
const PATCH_MEMBERS_PER_REQUEST = 1000;

function groupToScim(group: GroupRow, members: ScimMember[]) {
  return {
    schemas: [GROUP_SCHEMA],
    externalId: String(group.id),
    displayName: group.name,
    members: members.map((m) => ({ value: m.scimId, display: m.upn })),
  };
}

/** Bodies for a membership change, at most PATCH_MEMBERS_PER_REQUEST member references each. */
export function groupPatchBodies(add: string[], remove: string[], rename: string | null): string[] {
  const bodies: string[] = [];
  let a = 0;
  let r = 0;
  do {
    const ops: Record<string, unknown>[] = [];
    if (rename !== null && bodies.length === 0) ops.push({ op: "replace", path: "displayName", value: rename });
    const adds = add.slice(a, a + PATCH_MEMBERS_PER_REQUEST);
    a += adds.length;
    if (adds.length) ops.push({ op: "add", path: "members", value: adds.map((value) => ({ value })) });
    const removes = remove.slice(r, r + PATCH_MEMBERS_PER_REQUEST - adds.length);
    r += removes.length;
    // The value-filter form (RFC 7644 3.5.2.2), which every SCIM server
    // accepts for removing one member.
    for (const id of removes) ops.push({ op: "remove", path: `members[value eq "${id.replace(/["\\]/g, "\\$&")}"]` });
    bodies.push(JSON.stringify({ schemas: [PATCH_OP_SCHEMA], Operations: ops }));
  } while (a < add.length || r < remove.length);
  return bodies;
}

/** The last push the SCIM server accepted for a group, if it is for the remote group on file. */
async function lastPushed(env: Env, group: GroupRow): Promise<{ displayName: string; members: Map<number, string> } | null> {
  if (!group.scim_id) return null;
  const state = await env.DB.prepare("SELECT display_name FROM scim_group_state WHERE group_id = ? AND scim_id = ?").bind(group.id, group.scim_id).first<{ display_name: string }>();
  if (!state) return null;
  const { results } = await env.DB.prepare("SELECT user_id, scim_id FROM scim_group_members WHERE group_id = ?").bind(group.id).all<{ user_id: number; scim_id: string }>();
  return { displayName: state.display_name, members: new Map(results.map((m) => [m.user_id, m.scim_id])) };
}

const upsertState = (env: Env, groupId: number, scimId: string, name: string) =>
  env.DB.prepare(
    `INSERT INTO scim_group_state (group_id, scim_id, display_name, pushed_at) SELECT id, ?, ?, ? FROM groups WHERE id = ?
     ON CONFLICT(group_id) DO UPDATE SET scim_id = excluded.scim_id, display_name = excluded.display_name, pushed_at = excluded.pushed_at`
  ).bind(scimId, name, new Date().toISOString(), groupId);

/**
 * Member rows for the stored state. Joined to users and groups, so a row
 * deleted while the push was in flight is simply not recorded.
 */
const insertMembers = (env: Env, groupId: number, members: { userId: number; scimId: string }[]) =>
  env.DB.prepare(
    `INSERT OR REPLACE INTO scim_group_members (group_id, user_id, scim_id)
     SELECT g.id, u.id, json_extract(j.value, '$[1]') FROM json_each(?) j JOIN users u ON u.id = json_extract(j.value, '$[0]') JOIN groups g ON g.id = ?`
  ).bind(JSON.stringify(members.map((m) => [m.userId, m.scimId])), groupId);

/** Records a full push (PUT or POST): the remote group now has exactly these members. */
async function recordFullPush(env: Env, group: GroupRow, scimId: string, members: ScimMember[]): Promise<void> {
  await env.DB.batch([env.DB.prepare("DELETE FROM scim_group_members WHERE group_id = ?").bind(group.id), insertMembers(env, group.id, members), upsertState(env, group.id, scimId, group.name)]);
}

/** Forgets what was pushed: the next push sends the group in full. */
export function clearGroupPushState(env: Env, groupId: number): D1PreparedStatement[] {
  return [env.DB.prepare("DELETE FROM scim_group_members WHERE group_id = ?").bind(groupId), env.DB.prepare("DELETE FROM scim_group_state WHERE group_id = ?").bind(groupId)];
}

/**
 * Creates or updates a group in the SCIM server. Members without a scim_id yet
 * (not pushed as users) are skipped - push users first. A group outside the
 * configured scope is removed from the SCIM server (if previously synced) or
 * skipped entirely (if never synced).
 *
 * An update is proportional to the change: when the last accepted push is on
 * file (scim_group_state), only the members added and removed since are sent,
 * as RFC 7644 PATCH operations (Cloudflare Access's SCIM endpoint takes the
 * add/remove-members form Okta and Entra ID send); nothing at all when nothing
 * changed. A full PUT is sent instead when there is no stored state, when more
 * than half the group changed, when `full` is set (a full sync), or when the
 * server refuses the PATCH. A 404 recreates the group either way.
 */
export async function pushGroup(env: Env, group: GroupRow, members: ScimMember[], opts: { full?: boolean } = {}): Promise<ScimResult> {
  try {
    const scope = await getScimScope(env);
    if (!isGroupInScimScope(scope, group.id)) {
      if (!group.scim_id) return { ok: true };
      const result = await deleteGroupScim(env, group);
      if (result.ok) await env.DB.batch([env.DB.prepare("UPDATE groups SET scim_id = NULL WHERE id = ?").bind(group.id), ...clearGroupPushState(env, group.id)]);
      return result;
    }

    if (!group.scim_id) {
      return createScimGroup(env, group, members);
    }

    const last = opts.full ? null : await lastPushed(env, group);
    if (last) {
      const wanted = new Map(members.map((m) => [m.userId, m]));
      const add = members.filter((m) => last.members.get(m.userId) !== m.scimId);
      const gone = [...last.members].filter(([userId]) => !wanted.has(userId)).map(([userId, scimId]) => ({ userId, scimId }));
      const rename = last.displayName !== group.name ? group.name : null;
      if (add.length + gone.length === 0 && rename === null) return { ok: true };
      if (add.length + gone.length <= Math.max(wanted.size, last.members.size) / 2) {
        const patched = await patchGroup(env, group, add, gone, rename);
        if (patched !== "fallback") return patched;
      }
    }

    return await putGroup(env, group, members);
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/** Sends a membership delta; "fallback" when the server refused it and a full PUT should follow. */
async function patchGroup(env: Env, group: GroupRow, add: ScimMember[], gone: { userId: number; scimId: string }[], rename: string | null): Promise<ScimResult | "fallback"> {
  // A member whose user was recreated downstream since (a new remote id)
  // left the group along with the old remote user: nothing to remove.
  const { results: current } = gone.length
    ? await env.DB.prepare("SELECT id, scim_id FROM users WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(gone.map((g) => g.userId))).all<{ id: number; scim_id: string | null }>()
    : { results: [] as { id: number; scim_id: string | null }[] };
  const stillRemote = new Map(current.map((u) => [u.id, u.scim_id]));
  const remove = gone.filter((g) => stillRemote.get(g.userId) === g.scimId).map((g) => g.scimId);

  for (const body of groupPatchBodies(add.map((m) => m.scimId), remove, rename)) {
    const res = await scimFetch(env, `/Groups/${group.scim_id}`, { method: "PATCH", body });
    if (res.ok) continue;
    if (res.status === 404) return recreateGroup(env, group, null);
    // Refused (or failed part-way): the state is unknown, so send it whole.
    return "fallback";
  }
  await env.DB.batch([
    env.DB.prepare("DELETE FROM scim_group_members WHERE group_id = ? AND user_id IN (SELECT value FROM json_each(?))").bind(group.id, JSON.stringify(gone.map((g) => g.userId))),
    insertMembers(env, group.id, add),
    upsertState(env, group.id, group.scim_id!, group.name),
  ]);
  return { ok: true, status: 200 };
}

async function putGroup(env: Env, group: GroupRow, members: ScimMember[]): Promise<ScimResult> {
  const res = await scimFetch(env, `/Groups/${group.scim_id}`, { method: "PUT", body: JSON.stringify(groupToScim(group, members)) });
  if (res.ok) {
    await recordFullPush(env, group, group.scim_id!, members);
    return { ok: true, status: res.status };
  }
  // Self-heal, same as pushUser: recreate if the remote resource is gone.
  if (res.status === 404) return recreateGroup(env, group, members);
  await env.DB.batch(clearGroupPushState(env, group.id));
  return { ok: false, status: res.status, error: await res.text() };
}

/** The remote group is gone: unlink it and create it again (with `members`, or the group's current members). */
async function recreateGroup(env: Env, group: GroupRow, members: ScimMember[] | null): Promise<ScimResult> {
  const cleared = await env.DB.prepare("UPDATE groups SET scim_id = NULL WHERE id = ?").bind(group.id).run();
  await env.DB.batch(clearGroupPushState(env, group.id));
  if (cleared.meta.changes === 0) return { ok: true, status: 404 };
  return createScimGroup(env, { ...group, scim_id: null }, members ?? (await currentScimMembers(env, group)));
}

async function createScimGroup(env: Env, group: GroupRow, members: ScimMember[]): Promise<ScimResult> {
  const res = await scimFetch(env, "/Groups", { method: "POST", body: JSON.stringify(groupToScim(group, members)) });
  if (!res.ok) return { ok: false, status: res.status, error: await res.text() };
  const created = await res.json<{ id: string }>();
  const linked = await env.DB.prepare("UPDATE groups SET scim_id = ? WHERE id = ?").bind(created.id, group.id).run();
  if (linked.meta.changes === 0) await queueScimDeprovision(env, "group", created.id, group.name).run();
  else await recordFullPush(env, group, created.id, members);
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
export interface SyncStep {
  /** What this call did: a batch of users, or the groups. */
  phase: "users" | "groups";
  users: number;
  userErrors: number;
  groups: number;
  groupErrors: number;
  complete: boolean;
  remainingUsers: number;
  /** Up to five failures from this step, for the sync log. */
  errors: { target: string; status?: number; error: string }[];
}

export async function syncAll(env: Env, opts: { restart?: boolean } = {}): Promise<SyncStep> {
  await drainScimDeprovisionQueue(env);
  const setCursor = (v: string) =>
    env.DB.prepare("INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
      .bind(SYNC_CURSOR_KEY, v, new Date().toISOString())
      .run();
  const stored = opts.restart ? "" : ((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(SYNC_CURSOR_KEY).first<{ value: string }>())?.value ?? "");
  const errors: SyncStep["errors"] = [];
  const note = (target: string, r: ScimResult) => {
    if (!r.ok && errors.length < 5) errors.push({ target, status: r.status, error: String(r.error ?? "").slice(0, 300) });
  };

  // Last step: the groups, once every user has been pushed (members need their SCIM ids).
  if (stored === "groups") {
    const { groups, groupErrors, failures } = await syncGroups(env);
    for (const f of failures) note(f.name, f.result);
    await setCursor("");
    return { phase: "groups", users: 0, userErrors: 0, groups, groupErrors, complete: true, remainingUsers: 0, errors };
  }

  const { results: users } = await env.DB.prepare("SELECT * FROM users WHERE id > ? ORDER BY id LIMIT ?").bind(Number(stored) || 0, SYNC_BATCH).all<UserRow>();
  let userErrors = 0;
  for (const user of users) {
    const result = await pushUser(env, user);
    if (!result.ok) userErrors++;
    note(user.upn, result);
  }
  const last = users.length ? users[users.length - 1]!.id : Number(stored) || 0;
  const remaining = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE id > ?").bind(last).first<{ n: number }>())?.n ?? 0;
  await setCursor(remaining > 0 ? String(last) : "groups");
  return { phase: "users", users: users.length, userErrors, groups: 0, groupErrors: 0, complete: false, remainingUsers: remaining, errors };
}

/** Cron: carries on a full sync that a previous invocation left unfinished. */
export async function continueScimSync(env: Env): Promise<void> {
  const cursor = (await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(SYNC_CURSOR_KEY).first<{ value: string }>())?.value;
  if (cursor && (await isScimConfigured(env))) await syncAll(env, { restart: false });
}

/** Pushes every group with its resolved members (dynamic ones included). */
/** Pushes one group with its current resolved members (for writers that change a single group). */
export async function pushGroupCurrent(env: Env, group: GroupRow): Promise<ScimResult> {
  return pushGroup(env, group, await currentScimMembers(env, group));
}

/** A group's current members that have been pushed as users (have a scim_id). */
async function currentScimMembers(env: Env, group: GroupRow): Promise<ScimMember[]> {
  const memberIds = await resolveGroupMemberUserIds(env, group);
  if (!memberIds.length) return [];
  const { results } = await env.DB.prepare("SELECT id AS userId, scim_id AS scimId, upn FROM users WHERE id IN (SELECT value FROM json_each(?)) AND scim_id IS NOT NULL")
    .bind(JSON.stringify(memberIds))
    .all<ScimMember>();
  return results;
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

export async function syncGroups(env: Env, onlyIds?: number[]): Promise<{ groups: number; groupErrors: number; failures: { name: string; result: ScimResult }[] }> {
  // onlyIds: just these groups (an import that touched a few people), not the whole directory.
  const { results: groups } = onlyIds
    ? await env.DB.prepare("SELECT * FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(onlyIds)).all<GroupRow>()
    : await env.DB.prepare("SELECT * FROM groups").all<GroupRow>();
  let groupErrors = 0;
  const failures: { name: string; result: ScimResult }[] = [];
  const members = await resolveManyGroupMemberUserIds(env, groups);
  // SCIM ids for every user once, rather than a query per group.
  const { results: synced } = await env.DB.prepare("SELECT id, scim_id, upn FROM users WHERE scim_id IS NOT NULL").all<{ id: number; scim_id: string; upn: string }>();
  const byId = new Map(synced.map((u) => [u.id, { userId: u.id, scimId: u.scim_id, upn: u.upn }]));
  for (const group of groups) {
    const memberIds = members.get(group.id) ?? [];
    const memberRows = memberIds.map((id) => byId.get(id)).filter((m): m is ScimMember => Boolean(m));

    // A full sync (every group) re-sends each group whole, which also
    // refreshes the stored state; a targeted one sends only the changes.
    const result = await pushGroup(env, group, memberRows, { full: !onlyIds });
    if (!result.ok) {
      groupErrors++;
      if (failures.length < 5) failures.push({ name: group.name, result });
    }
  }

  return { groups: groups.length, groupErrors, failures };
}

export async function isScimConfigured(env: Env): Promise<boolean> {
  const { endpoint, secret } = await getScimConfig(env);
  return !!endpoint && !!secret;
}

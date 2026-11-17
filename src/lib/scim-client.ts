import { resolveManyGroupMemberUserIds } from "./groups.js";
import type { Env } from "../env.js";
import { resolveGroupMemberUserIds, parseRule, userMatchesRule } from "./groups.js";
import { getScimConfig, getScimScope, getScimTuning, validateScimEndpoint, type ScimScope } from "./settings.js";
import { timed, recordEvent } from "./metrics.js";
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

/** A downstream error body is diagnostic only: bounded before it is logged or returned. */
async function scimError(res: Response): Promise<string> {
  return (await res.text()).slice(0, 300);
}

/**
 * Every outbound call goes through here, so this is where the pace is kept:
 * receivers backed by a single object (Cloudflare Access's endpoint is) fall
 * over when requests arrive back to back. The gap and the chunk sizes live in
 * settings so they can be tuned per target system (getScimTuning).
 *
 * The tuning read and the "next allowed" mark are cached per isolate: a sync
 * of any size would otherwise add a settings read to every request, and the
 * mark only has to discipline bursts anyway.
 */
let paceCache: { at: number; paceMs: number } | null = null;
let nextRequestAt = 0;

async function pace(env: Env): Promise<void> {
  if (!paceCache || Date.now() - paceCache.at > 10_000) {
    paceCache = { at: Date.now(), paceMs: (await getScimTuning(env)).paceMs };
  }
  if (!paceCache.paceMs) return;
  const wait = nextRequestAt - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  nextRequestAt = Date.now() + paceCache.paceMs;
}

async function scimFetch(env: Env, path: string, init: RequestInit): Promise<Response> {
  const { endpoint, secret } = await getScimConfig(env);
  if (!endpoint || !secret) throw new Error("SCIM is not configured (Admin -> SCIM)");
  const problem = validateScimEndpoint(endpoint);
  if (problem) throw new Error(problem);

  await pace(env);

  // Redirects are followed by hand: the Bearer credential is attached again
  // only while the target stays on the configured origin - fetch's default
  // 'follow' would forward it cross-origin.
  const done = (res: Response): Response => {
    // The remote's status is an event, not a span: outbound answers never
    // become FlareID responses, so the 5xx charts would never see them.
    recordEvent(env, "scim.outbound", String(res.status));
    return res;
  };
  let url = `${endpoint}${path}`;
  try {
    for (let hops = 0; ; hops++) {
      const res = await timed(env, "scim.outbound", fetch(url, {
        ...init,
        redirect: "manual",
        // A stalled remote must not head-of-line block the whole sync.
        signal: AbortSignal.timeout(10_000),
        headers: {
          Authorization: `Bearer ${secret}`,
          "Content-Type": "application/scim+json",
          Accept: "application/scim+json",
          ...init.headers,
        },
      }));
      if (res.status < 300 || res.status >= 400 || hops >= 3) return done(res);
      const location = res.headers.get("location");
      if (!location) return done(res);
      const next = new URL(location, url);
      if (next.origin !== new URL(url).origin) return done(res);
      url = next.toString();
    }
  } catch (e) {
    recordEvent(env, "scim.outbound", "network error");
    throw e;
  }
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

    return { ok: false, status: res.status, error: await scimError(res) };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/**
 * Asks the remote which id it already gave this object - the recovery for a
 * create that conflicts (409) or whose link was lost. A SCIM server that
 * enforces externalId/userName uniqueness answers 409 rather than minting a
 * second copy; servers that do not enforce it get the single-flight lock and
 * the guarded link write below instead.
 */
async function resolveRemoteId(env: Env, collection: "/Users" | "/Groups", externalId: string, userName?: string): Promise<string | null> {
  for (const filter of [`externalId eq "${externalId.replace(/["\\]/g, "\\$&")}"`, ...(userName ? [`userName eq "${userName.replace(/["\\]/g, "\\$&")}"`] : [])]) {
    const res = await scimFetch(env, `${collection}?filter=${encodeURIComponent(filter)}`, {});
    if (!res.ok) continue;
    const id = (await res.json<{ Resources?: { id?: string }[] }>()).Resources?.[0]?.id;
    if (id) return id;
  }
  return null;
}

async function createScimUser(env: Env, user: UserRow, body: string): Promise<ScimResult> {
  const res = await scimFetch(env, "/Users", { method: "POST", body });
  if (!res.ok) {
    if (res.status === 409) {
      const id = await resolveRemoteId(env, "/Users", user.external_id, user.upn);
      if (id && (await linkUserScimId(env, user.id, id, user.upn))) return { ok: true, status: res.status };
    }
    return { ok: false, status: res.status, error: await scimError(res) };
  }
  const created = await res.json<{ id: string }>();
  await linkUserScimId(env, user.id, created.id, user.upn);
  return { ok: true, status: res.status };
}

/**
 * Links a remote id to the user. The `scim_id IS NULL` guard keeps a second
 * writer (another push overlapping the same create) from overwriting the
 * first link; when the write loses - the row was deleted or already linked -
 * the just-created remote object goes onto the deprovision queue instead of
 * becoming an untracked orphan the IdP can never deactivate.
 */
async function linkUserScimId(env: Env, userId: number, scimId: string, upn: string): Promise<boolean> {
  const linked = await env.DB.prepare("UPDATE users SET scim_id = ? WHERE id = ? AND scim_id IS NULL").bind(scimId, userId).run();
  if (linked.meta.changes > 0) return true;
  const label = (await env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(userId).first<{ upn: string }>())?.upn ?? upn;
  await queueScimDeprovision(env, "user", scimId, label).run();
  return false;
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
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

export async function deleteUserScim(env: Env, user: UserRow): Promise<ScimResult> {
  if (!user.scim_id) return { ok: true };
  try {
    const res = await scimFetch(env, `/Users/${user.scim_id}`, { method: "DELETE" });
    return res.ok || res.status === 404 ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
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
/** Default member references per PATCH body; the live value is the scim_members_per_request setting. */
const DEFAULT_MEMBERS_PER_REQUEST = 50;

function groupToScim(group: GroupRow, members: ScimMember[]) {
  return {
    schemas: [GROUP_SCHEMA],
    externalId: String(group.id),
    displayName: group.name,
    members: members.map((m) => ({ value: m.scimId, display: m.upn })),
  };
}

/** Bodies for a membership change, at most `perRequest` member references each. */
export function groupPatchBodies(add: string[], remove: string[], rename: string | null, perRequest = DEFAULT_MEMBERS_PER_REQUEST): string[] {
  const bodies: string[] = [];
  let a = 0;
  let r = 0;
  do {
    const ops: Record<string, unknown>[] = [];
    if (rename !== null && bodies.length === 0) ops.push({ op: "replace", path: "displayName", value: rename });
    const adds = add.slice(a, a + perRequest);
    a += adds.length;
    if (adds.length) ops.push({ op: "add", path: "members", value: adds.map((value) => ({ value })) });
    const removes = remove.slice(r, r + perRequest - adds.length);
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
      // Gone is per pushed (userId, scimId) pair, not per user: a member
      // whose remote id rotated keeps its seat but owes the remote group a
      // remove for the stale reference it was pushed as.
      const gone = [...last.members].filter(([userId, scimId]) => wanted.get(userId)?.scimId !== scimId).map(([userId, scimId]) => ({ userId, scimId }));
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
  // Every pushed reference that is no longer wanted is removed - including a
  // rotated member's previous remote id, which the server may still hold as a
  // dangling member. If it was already gone the remove is a no-op, and a
  // server that refuses it outright falls back to the full PUT below.
  const remove = gone.map((g) => g.scimId);
  const perRequest = (await getScimTuning(env)).membersPerRequest;

  for (const body of groupPatchBodies(add.map((m) => m.scimId), remove, rename, perRequest)) {
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

/**
 * A full push, split so no single body can dwarf the receiver's limits: the
 * PUT carries identity only (externalId + displayName), the members arrive in
 * membersPerRequest-sized PATCH adds. A mid-way failure clears the pushed
 * state so the next run redoes the whole thing - member-add on an existing
 * reference is a no-op per RFC 7644, so re-adding is safe.
 */
async function putGroup(env: Env, group: GroupRow, members: ScimMember[]): Promise<ScimResult> {
  const res = await scimFetch(env, `/Groups/${group.scim_id}`, { method: "PUT", body: JSON.stringify(groupToScim(group, [])) });
  if (!res.ok) {
    // Self-heal, same as pushUser: recreate if the remote resource is gone.
    if (res.status === 404) return recreateGroup(env, group, members);
    await env.DB.batch(clearGroupPushState(env, group.id));
    return { ok: false, status: res.status, error: await scimError(res) };
  }
  const loaded = await addMembers(env, group, members);
  if (loaded) {
    await env.DB.batch(clearGroupPushState(env, group.id));
    return { ok: false, status: loaded.status, error: loaded.error };
  }
  await recordFullPush(env, group, group.scim_id!, members);
  return { ok: true, status: res.status };
}

/** PATCHes members into a remote group, in tuning-sized chunks; null on success. */
async function addMembers(env: Env, group: GroupRow, members: ScimMember[]): Promise<{ status?: number; error: string } | null> {
  const perRequest = (await getScimTuning(env)).membersPerRequest;
  for (const body of groupPatchBodies(members.map((m) => m.scimId), [], null, perRequest)) {
    const res = await scimFetch(env, `/Groups/${group.scim_id}`, { method: "PATCH", body });
    if (!res.ok) return { status: res.status, error: await scimError(res) };
  }
  return null;
}

/** The remote group is gone: unlink it and create it again (with `members`, or the group's current members). */
async function recreateGroup(env: Env, group: GroupRow, members: ScimMember[] | null): Promise<ScimResult> {
  const cleared = await env.DB.prepare("UPDATE groups SET scim_id = NULL WHERE id = ?").bind(group.id).run();
  await env.DB.batch(clearGroupPushState(env, group.id));
  if (cleared.meta.changes === 0) return { ok: true, status: 404 };
  return createScimGroup(env, { ...group, scim_id: null }, members ?? (await currentScimMembers(env, group)));
}

async function createScimGroup(env: Env, group: GroupRow, members: ScimMember[]): Promise<ScimResult> {
  // The member list is never embedded in the create either - same reason as
  // putGroup: a big group's body is what the DO-bound receivers refuse.
  const res = await scimFetch(env, "/Groups", { method: "POST", body: JSON.stringify(groupToScim(group, [])) });
  if (!res.ok) {
    if (res.status === 409) {
      const id = await resolveRemoteId(env, "/Groups", String(group.id));
      if (id && (await linkGroupScimId(env, group, id, members))) return { ok: true, status: res.status };
    }
    return { ok: false, status: res.status, error: await scimError(res) };
  }
  const created = await res.json<{ id: string }>();
  // Link with an empty member list first: the members still have to land, and
  // if they don't the recorded state must not claim they did.
  if (!(await linkGroupScimId(env, group, created.id, []))) return { ok: true, status: res.status };
  const linkedGroup = { ...group, scim_id: created.id };
  const loaded = await addMembers(env, linkedGroup, members);
  if (loaded) {
    await env.DB.batch(clearGroupPushState(env, group.id));
    return { ok: false, status: loaded.status, error: loaded.error };
  }
  await recordFullPush(env, linkedGroup, created.id, members);
  return { ok: true, status: res.status };
}

/** The group counterpart of linkUserScimId: guarded write, losing remote id queued for deprovision. */
async function linkGroupScimId(env: Env, group: GroupRow, scimId: string, members: ScimMember[]): Promise<boolean> {
  const linked = await env.DB.prepare("UPDATE groups SET scim_id = ? WHERE id = ? AND scim_id IS NULL").bind(scimId, group.id).run();
  if (linked.meta.changes === 0) {
    await queueScimDeprovision(env, "group", scimId, group.name).run();
    return false;
  }
  await recordFullPush(env, group, scimId, members);
  return true;
}

export async function deleteGroupScim(env: Env, group: GroupRow): Promise<ScimResult> {
  if (!group.scim_id) return { ok: true };
  try {
    const res = await scimFetch(env, `/Groups/${group.scim_id}`, { method: "DELETE" });
    return res.ok || res.status === 404 ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

export async function testScimConnection(env: Env): Promise<ScimResult> {
  try {
    const res = await scimFetch(env, "/Users?count=1", { method: "GET" });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/** Pushes every user, then every group (with resolved member scim_ids). Best-effort; returns a summary. */
/** Users pushed per invocation is the scim_sync_batch setting: a full sync of a large directory continues across invocations (the hourly cron). */
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
  /** True when this call did no work because another sync holds the lock. */
  busy?: boolean;
}

const SYNC_LOCK_KEY = "scim_sync_lock";
/** A batch is bounded by the SCIM server's own timeouts; a lock older than this belonged to a dead runner. */
const SYNC_LOCK_STALE_MS = 15 * 60 * 1000;

/**
 * Claims the full-sync lock. idp_settings.value is "ISO timestamp : uuid", so
 * lexical comparison doubles as a staleness check: an abandoned lock expires
 * instead of wedging every later sync.
 */
async function claimSyncLock(env: Env): Promise<string | null> {
  const token = `${new Date().toISOString()}:${crypto.randomUUID()}`;
  const stale = new Date(Date.now() - SYNC_LOCK_STALE_MS).toISOString();
  const claimed = await env.DB.prepare(
    `INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
     WHERE idp_settings.value < ?`
  )
    .bind(SYNC_LOCK_KEY, token, new Date().toISOString(), stale)
    .run();
  return claimed.meta.changes ? token : null;
}

export async function syncAll(env: Env, opts: { restart?: boolean } = {}): Promise<SyncStep> {
  const lock = await claimSyncLock(env);
  if (!lock) {
    // The console poller, an API caller, or the hourly cron can all invoke a
    // sync at once; two runners processing the same batch create duplicate
    // remote objects, so the loser coalesces instead.
    const remainingUsers = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE scim_id IS NULL").first<{ n: number }>())?.n ?? 0;
    return { phase: "users", users: 0, userErrors: 0, groups: 0, groupErrors: 0, complete: false, remainingUsers, busy: true, errors: [] };
  }
  try {
    return await syncAllLocked(env, opts);
  } finally {
    await env.DB.prepare("DELETE FROM idp_settings WHERE key = ? AND value = ?").bind(SYNC_LOCK_KEY, lock).run();
  }
}

async function syncAllLocked(env: Env, opts: { restart?: boolean }): Promise<SyncStep> {
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

  const { syncBatchSize } = await getScimTuning(env);
  const { results: users } = await env.DB.prepare("SELECT * FROM users WHERE id > ? ORDER BY id LIMIT ?").bind(Number(stored) || 0, syncBatchSize).all<UserRow>();
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

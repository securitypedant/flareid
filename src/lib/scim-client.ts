import { resolveManyGroupMemberUserIds } from "./groups.js";
import type { Env } from "../env.js";
import { resolveGroupMemberUserIds, parseRule, userMatchesRule } from "./groups.js";
import { enabledScimTargets, getScimTarget, targetGroupScimId, targetUserScimId, type ScimScope, type ScimTarget } from "./scim-targets.js";
import { validateScimEndpoint } from "./settings.js";
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

export { isScimConfigured } from "./scim-targets.js";
export type { ScimTarget } from "./scim-targets.js";

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
 * over when requests arrive back to back. Each target keeps its own gap - a
 * slow endpoint must not stall pushes to a fast one.
 *
 * The "next allowed" marks are cached per isolate and per target: a sync of
 * any size would otherwise add a settings read to every request, and the
 * marks only have to discipline bursts anyway.
 */
const nextRequestAt = new Map<number, number>();

async function pace(target: ScimTarget): Promise<void> {
  if (!target.paceMs) return;
  const next = nextRequestAt.get(target.id) ?? 0;
  const wait = next - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  nextRequestAt.set(target.id, Date.now() + target.paceMs);
}

async function scimFetch(env: Env, target: ScimTarget, path: string, init: RequestInit): Promise<Response> {
  const { endpoint, secret } = target;
  if (!endpoint || !secret) throw new Error(`SCIM target "${target.name}" has no endpoint or secret`);
  const problem = validateScimEndpoint(endpoint);
  if (problem) throw new Error(problem);

  await pace(target);

  // Redirects are followed by hand: the Bearer credential is attached again
  // only while the target stays on the configured origin - fetch's default
  // 'follow' would forward it cross-origin.
  const done = (res: Response): Response => {
    // The remote's status is an event, not a span: outbound answers never
    // become FlareID responses, so the 5xx charts would never see them.
    recordEvent(env, "scim.outbound", `${target.name} ${res.status}`);
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
    recordEvent(env, "scim.outbound", `${target.name} network error`);
    throw e;
  }
}

/**
 * Runs `work` once per enabled target, sequentially (each target's pace is
 * its own). The merged result is ok only when every target accepted; failures
 * carry the target name so a one-target setup reads exactly as before.
 */
async function fanOut(env: Env, work: (target: ScimTarget) => Promise<ScimResult>): Promise<ScimResult> {
  const targets = (await enabledScimTargets(env)).filter((t) => t.endpoint && t.secret);
  const errors: string[] = [];
  for (const target of targets) {
    const r = await work(target);
    if (!r.ok) errors.push(`${target.name}: ${r.error ?? (r.status ? `HTTP ${r.status}` : "failed")}`);
  }
  return errors.length ? { ok: false, error: errors.join("; ").slice(0, 500) } : { ok: true };
}

/**
 * Builds the SCIM User resource for a person, including their job title (core
 * User schema) and department/manager (Enterprise User extension - standard
 * SCIM attributes for exactly this). The manager is only included once they
 * themselves have been pushed to this target - it self-heals on the next sync
 * if pushed out of order.
 */
async function userToScim(env: Env, target: ScimTarget, user: UserRow) {
  let manager: { value: string; displayName?: string } | undefined;
  if (user.manager_external_id) {
    const managerRow = await env.DB.prepare(
      "SELECT l.scim_id, u.display_name FROM users u JOIN scim_user_links l ON l.user_id = u.id AND l.target_id = ? WHERE u.external_id = ?"
    )
      .bind(target.id, user.manager_external_id)
      .first<{ scim_id: string | null; display_name: string }>();
    if (managerRow?.scim_id) manager = { value: managerRow.scim_id, displayName: managerRow.display_name };
  }

  const { results: emails } = await env.DB.prepare("SELECT email, type, is_primary FROM user_emails WHERE user_id = ? ORDER BY is_primary DESC, id").bind(user.id).all<{ email: string; type: string; is_primary: number }>();
  return {
    schemas: [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
    externalId: user.external_id,
    userName: user.upn,
    name: { givenName: user.given_name, familyName: user.family_name },
    displayName: user.display_name,
    title: user.job_title || undefined,
    emails: emails.length
      ? emails.map((e) => ({ value: e.email, type: e.type || "work", ...(e.is_primary ? { primary: true } : {}) }))
      : [{ value: user.upn, primary: true, type: "work" }],
    active: user.status === "active",
    [ENTERPRISE_USER_SCHEMA]: {
      employeeNumber: user.employee_number || undefined,
      department: user.department || undefined,
      manager,
    },
  };
}

/**
 * Creates the user in this target if it has no link yet, otherwise replaces
 * (PUT) it. Respects the target's sync scope: a user outside scope is
 * deactivated (if previously synced) or skipped entirely (if never synced).
 */
export async function pushUser(env: Env, user: UserRow): Promise<ScimResult> {
  return fanOut(env, (target) => pushUserToTarget(env, target, user));
}

/** The per-target half of pushUser, for writers scoped to one target (scope changes, per-target syncs). */
export async function pushUserToTarget(env: Env, target: ScimTarget, user: UserRow): Promise<ScimResult> {
  try {
    const scimId = await targetUserScimId(env, target.id, user.id);
    if (!(await isUserInScimScope(env, target.scope, user.id))) {
      return scimId ? deactivateRemoteUser(env, target, scimId) : { ok: true };
    }

    const body = JSON.stringify(await userToScim(env, target, user));

    if (!scimId) {
      // A row captured before a delete (a stale in-flight push) must not
      // resurrect the account - links cascade away with the user, so no link
      // plus no row means it is already gone.
      const alive = await env.DB.prepare("SELECT 1 FROM users WHERE id = ?").bind(user.id).first();
      if (!alive) return { ok: true };
      return createScimUser(env, target, user, body);
    }

    const res = await scimFetch(env, target, `/Users/${scimId}`, { method: "PUT", body });
    if (res.ok) return { ok: true, status: res.status };

    // The remote resource we had on file is gone (e.g. the SCIM population was
    // reset) - self-heal by recreating it instead of failing forever.
    if (res.status === 404) {
      // Only for a user that still exists here: a push working from a row
      // captured before a delete would otherwise resurrect the account.
      const cleared = await env.DB.prepare("DELETE FROM scim_user_links WHERE target_id = ? AND user_id = ? AND scim_id = ?").bind(target.id, user.id, scimId).run();
      if (cleared.meta.changes === 0) return { ok: true, status: 404 };
      return createScimUser(env, target, user, body);
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
async function resolveRemoteId(env: Env, target: ScimTarget, collection: "/Users" | "/Groups", externalId: string, userName?: string): Promise<string | null> {
  for (const filter of [`externalId eq "${externalId.replace(/["\\]/g, "\\$&")}"`, ...(userName ? [`userName eq "${userName.replace(/["\\]/g, "\\$&")}"`] : [])]) {
    const res = await scimFetch(env, target, `${collection}?filter=${encodeURIComponent(filter)}`, {});
    if (!res.ok) continue;
    const id = (await res.json<{ Resources?: { id?: string }[] }>()).Resources?.[0]?.id;
    if (id) return id;
  }
  return null;
}

async function createScimUser(env: Env, target: ScimTarget, user: UserRow, body: string): Promise<ScimResult> {
  const res = await scimFetch(env, target, "/Users", { method: "POST", body });
  if (!res.ok) {
    if (res.status === 409) {
      const id = await resolveRemoteId(env, target, "/Users", user.external_id, user.upn);
      if (id && (await linkUserScimId(env, target, user.id, id, user.upn))) return { ok: true, status: res.status };
    }
    return { ok: false, status: res.status, error: await scimError(res) };
  }
  const created = await res.json<{ id: string }>();
  await linkUserScimId(env, target, user.id, created.id, user.upn);
  return { ok: true, status: res.status };
}

/**
 * Links a remote id to the user. The INSERT OR IGNORE keeps a second writer
 * (another push overlapping the same create) from overwriting the first link;
 * when the write loses - the row was deleted or already linked - the
 * just-created remote object goes onto the deprovision queue instead of
 * becoming an untracked orphan the IdP can never deactivate.
 */
async function linkUserScimId(env: Env, target: ScimTarget, userId: number, scimId: string, upn: string): Promise<boolean> {
  const linked = await env.DB.prepare("INSERT OR IGNORE INTO scim_user_links (target_id, user_id, scim_id) VALUES (?, ?, ?)").bind(target.id, userId, scimId).run();
  if (linked.meta.changes > 0) return true;
  const label = (await env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(userId).first<{ upn: string }>())?.upn ?? upn;
  await queueScimDeprovision(env, target.id, "user", scimId, label).run();
  return false;
}

/** Marks a user inactive in the remote server (Access treats this as deprovisioning) rather than hard-deleting. */
async function deactivateRemoteUser(env: Env, target: ScimTarget, scimId: string): Promise<ScimResult> {
  const res = await scimFetch(env, target, `/Users/${scimId}`, {
    method: "PATCH",
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "active", value: false }],
    }),
  });
  return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
}

export async function deactivateUserScim(env: Env, user: UserRow): Promise<ScimResult> {
  return fanOut(env, async (target) => {
    const scimId = await targetUserScimId(env, target.id, user.id);
    if (!scimId) return { ok: true };
    try {
      return await deactivateRemoteUser(env, target, scimId);
    } catch (error) {
      return { ok: false, error: String(error) };
    }
  });
}

async function deleteRemoteUser(env: Env, target: ScimTarget, scimId: string): Promise<ScimResult> {
  const res = await scimFetch(env, target, `/Users/${scimId}`, { method: "DELETE" });
  return res.ok || res.status === 404 ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
}

export async function deleteUserScim(env: Env, user: UserRow): Promise<ScimResult> {
  return fanOut(env, async (target) => {
    const scimId = await targetUserScimId(env, target.id, user.id);
    if (!scimId) return { ok: true };
    try {
      return await deleteRemoteUser(env, target, scimId);
    } catch (error) {
      return { ok: false, error: String(error) };
    }
  });
}

/** A group member as pushed: the local user and the remote user id they were sent as. */
export interface ScimMember {
  userId: number;
  scimId: string;
  upn: string;
}

const PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
/** Default member references per PATCH body; the live value is each target's members_per_request. */
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

/** The last push this target accepted for a group, if it is for the remote group on file. */
async function lastPushed(env: Env, target: ScimTarget, group: GroupRow): Promise<{ displayName: string; members: Map<number, string> } | null> {
  const scimId = await targetGroupScimId(env, target.id, group.id);
  if (!scimId) return null;
  const state = await env.DB.prepare("SELECT display_name FROM scim_group_state WHERE target_id = ? AND group_id = ? AND scim_id = ?").bind(target.id, group.id, scimId).first<{ display_name: string }>();
  if (!state) return null;
  const { results } = await env.DB.prepare("SELECT user_id, scim_id FROM scim_group_members WHERE target_id = ? AND group_id = ?").bind(target.id, group.id).all<{ user_id: number; scim_id: string }>();
  return { displayName: state.display_name, members: new Map(results.map((m) => [m.user_id, m.scim_id])) };
}

const upsertState = (env: Env, targetId: number, groupId: number, scimId: string, name: string) =>
  env.DB.prepare(
    `INSERT INTO scim_group_state (target_id, group_id, scim_id, display_name, pushed_at) SELECT ?, id, ?, ?, ? FROM groups WHERE id = ?
     ON CONFLICT(target_id, group_id) DO UPDATE SET scim_id = excluded.scim_id, display_name = excluded.display_name, pushed_at = excluded.pushed_at`
  ).bind(targetId, scimId, name, new Date().toISOString(), groupId);

/**
 * Member rows for the stored state. Joined to users and groups, so a row
 * deleted while the push was in flight is simply not recorded.
 */
const insertMembers = (env: Env, targetId: number, groupId: number, members: { userId: number; scimId: string }[]) =>
  env.DB.prepare(
    `INSERT OR REPLACE INTO scim_group_members (target_id, group_id, user_id, scim_id)
     SELECT ?, g.id, u.id, json_extract(j.value, '$[1]') FROM json_each(?) j JOIN users u ON u.id = json_extract(j.value, '$[0]') JOIN groups g ON g.id = ?`
  ).bind(targetId, JSON.stringify(members.map((m) => [m.userId, m.scimId])), groupId);

/** Records a full push (PUT or POST): the remote group now has exactly these members. */
async function recordFullPush(env: Env, target: ScimTarget, group: GroupRow, scimId: string, members: ScimMember[]): Promise<void> {
  await env.DB.batch([env.DB.prepare("DELETE FROM scim_group_members WHERE target_id = ? AND group_id = ?").bind(target.id, group.id), insertMembers(env, target.id, group.id, members), upsertState(env, target.id, group.id, scimId, group.name)]);
}

/** Forgets what was pushed to this target: the next push sends the group in full. */
export function clearGroupPushState(env: Env, targetId: number, groupId: number): D1PreparedStatement[] {
  return [env.DB.prepare("DELETE FROM scim_group_members WHERE target_id = ? AND group_id = ?").bind(targetId, groupId), env.DB.prepare("DELETE FROM scim_group_state WHERE target_id = ? AND group_id = ?").bind(targetId, groupId)];
}

/**
 * Creates or updates a group in every enabled target. Members without a link
 * to that target yet (not pushed as users there) are skipped - push users
 * first. A group outside a target's scope is removed from that target (if
 * previously synced) or skipped entirely.
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
  return fanOut(env, (target) => pushGroupToTarget(env, target, group, members, opts));
}

async function pushGroupToTarget(env: Env, target: ScimTarget, group: GroupRow, members: ScimMember[], opts: { full?: boolean } = {}): Promise<ScimResult> {
  try {
    const scimId = await targetGroupScimId(env, target.id, group.id);
    if (!isGroupInScimScope(target.scope, group.id)) {
      if (!scimId) return { ok: true };
      const result = await deleteRemoteGroup(env, target, scimId);
      if (result.ok) await env.DB.batch([env.DB.prepare("DELETE FROM scim_group_links WHERE target_id = ? AND group_id = ?").bind(target.id, group.id), ...clearGroupPushState(env, target.id, group.id)]);
      return result;
    }

    if (!scimId) {
      // As for users: no link plus no row means this push is working from a
      // row captured before a delete - it must not resurrect the group.
      const alive = await env.DB.prepare("SELECT 1 FROM groups WHERE id = ?").bind(group.id).first();
      if (!alive) return { ok: true };
      return createScimGroup(env, target, group, members);
    }

    const last = opts.full ? null : await lastPushed(env, target, group);
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
        const patched = await patchGroup(env, target, group, scimId, add, gone, rename);
        if (patched !== "fallback") return patched;
      }
    }

    return await putGroup(env, target, group, scimId, members);
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/** Sends a membership delta; "fallback" when the server refused it and a full PUT should follow. */
async function patchGroup(env: Env, target: ScimTarget, group: GroupRow, scimId: string, add: ScimMember[], gone: { userId: number; scimId: string }[], rename: string | null): Promise<ScimResult | "fallback"> {
  // Every pushed reference that is no longer wanted is removed - including a
  // rotated member's previous remote id, which the server may still hold as a
  // dangling member. If it was already gone the remove is a no-op, and a
  // server that refuses it outright falls back to the full PUT below.
  const remove = gone.map((g) => g.scimId);

  for (const body of groupPatchBodies(add.map((m) => m.scimId), remove, rename, target.membersPerRequest)) {
    const res = await scimFetch(env, target, `/Groups/${scimId}`, { method: "PATCH", body });
    if (res.ok) continue;
    if (res.status === 404) return recreateGroup(env, target, group, scimId, null);
    // Refused (or failed part-way): the state is unknown, so send it whole.
    return "fallback";
  }
  await env.DB.batch([
    env.DB.prepare("DELETE FROM scim_group_members WHERE target_id = ? AND group_id = ? AND user_id IN (SELECT value FROM json_each(?))").bind(target.id, group.id, JSON.stringify(gone.map((g) => g.userId))),
    insertMembers(env, target.id, group.id, add),
    upsertState(env, target.id, group.id, scimId, group.name),
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
async function putGroup(env: Env, target: ScimTarget, group: GroupRow, scimId: string, members: ScimMember[]): Promise<ScimResult> {
  const res = await scimFetch(env, target, `/Groups/${scimId}`, { method: "PUT", body: JSON.stringify(groupToScim(group, [])) });
  if (!res.ok) {
    // Self-heal, same as pushUser: recreate if the remote resource is gone.
    if (res.status === 404) return recreateGroup(env, target, group, scimId, members);
    await env.DB.batch(clearGroupPushState(env, target.id, group.id));
    return { ok: false, status: res.status, error: await scimError(res) };
  }
  const loaded = await addMembers(env, target, scimId, members);
  if (loaded) {
    await env.DB.batch(clearGroupPushState(env, target.id, group.id));
    return { ok: false, status: loaded.status, error: loaded.error };
  }
  await recordFullPush(env, target, group, scimId, members);
  return { ok: true, status: res.status };
}

/** PATCHes members into a remote group, in tuning-sized chunks; null on success. */
async function addMembers(env: Env, target: ScimTarget, scimId: string, members: ScimMember[]): Promise<{ status?: number; error: string } | null> {
  for (const body of groupPatchBodies(members.map((m) => m.scimId), [], null, target.membersPerRequest)) {
    const res = await scimFetch(env, target, `/Groups/${scimId}`, { method: "PATCH", body });
    if (!res.ok) return { status: res.status, error: await scimError(res) };
  }
  return null;
}

/** The remote group is gone: unlink it and create it again (with `members`, or the group's current members). */
async function recreateGroup(env: Env, target: ScimTarget, group: GroupRow, scimId: string, members: ScimMember[] | null): Promise<ScimResult> {
  const cleared = await env.DB.prepare("DELETE FROM scim_group_links WHERE target_id = ? AND group_id = ? AND scim_id = ?").bind(target.id, group.id, scimId).run();
  await env.DB.batch(clearGroupPushState(env, target.id, group.id));
  if (cleared.meta.changes === 0) return { ok: true, status: 404 };
  return createScimGroup(env, target, group, members ?? (await currentScimMembers(env, target, group)));
}

async function createScimGroup(env: Env, target: ScimTarget, group: GroupRow, members: ScimMember[]): Promise<ScimResult> {
  // The member list is never embedded in the create either - same reason as
  // putGroup: a big group's body is what the DO-bound receivers refuse.
  const res = await scimFetch(env, target, "/Groups", { method: "POST", body: JSON.stringify(groupToScim(group, [])) });
  if (!res.ok) {
    if (res.status === 409) {
      const id = await resolveRemoteId(env, target, "/Groups", String(group.id));
      if (id && (await linkGroupScimId(env, target, group, id, members))) return { ok: true, status: res.status };
    }
    return { ok: false, status: res.status, error: await scimError(res) };
  }
  const created = await res.json<{ id: string }>();
  // Link with an empty member list first: the members still have to land, and
  // if they don't the recorded state must not claim they did.
  if (!(await linkGroupScimId(env, target, group, created.id, []))) return { ok: true, status: res.status };
  const loaded = await addMembers(env, target, created.id, members);
  if (loaded) {
    await env.DB.batch(clearGroupPushState(env, target.id, group.id));
    return { ok: false, status: loaded.status, error: loaded.error };
  }
  await recordFullPush(env, target, group, created.id, members);
  return { ok: true, status: res.status };
}

/** The group counterpart of linkUserScimId: guarded write, losing remote id queued for deprovision. */
async function linkGroupScimId(env: Env, target: ScimTarget, group: GroupRow, scimId: string, members: ScimMember[]): Promise<boolean> {
  const linked = await env.DB.prepare("INSERT OR IGNORE INTO scim_group_links (target_id, group_id, scim_id) VALUES (?, ?, ?)").bind(target.id, group.id, scimId).run();
  if (linked.meta.changes === 0) {
    await queueScimDeprovision(env, target.id, "group", scimId, group.name).run();
    return false;
  }
  await recordFullPush(env, target, group, scimId, members);
  return true;
}

async function deleteRemoteGroup(env: Env, target: ScimTarget, scimId: string): Promise<ScimResult> {
  const res = await scimFetch(env, target, `/Groups/${scimId}`, { method: "DELETE" });
  return res.ok || res.status === 404 ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
}

export async function deleteGroupScim(env: Env, group: GroupRow): Promise<ScimResult> {
  return fanOut(env, async (target) => {
    const scimId = await targetGroupScimId(env, target.id, group.id);
    if (!scimId) return { ok: true };
    try {
      return await deleteRemoteGroup(env, target, scimId);
    } catch (error) {
      return { ok: false, error: String(error) };
    }
  });
}

export async function testScimConnection(env: Env, targetId?: number): Promise<ScimResult> {
  try {
    const target = targetId !== undefined ? await getScimTarget(env, targetId) : (await enabledScimTargets(env))[0];
    if (!target) return { ok: false, error: "No SCIM target configured" };
    const res = await scimFetch(env, target, "/Users?count=1", { method: "GET" });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, error: await scimError(res) };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/** Users pushed per invocation is each target's sync_batch: a full sync of a large directory continues across invocations (the hourly cron). */
const SYNC_CURSOR_KEY = "scim_sync_cursor";

/**
 * A full sync of one target, in bounded batches. Each call pushes the next
 * sync_batch users after the stored cursor; when no users are left it pushes
 * every group and clears the cursor. `complete` says whether this call
 * finished the sync; if not, the next call (manual, or the cron via
 * continueScimSync) picks it up; once a sync completes the cursor is cleared,
 * so the next call starts afresh.
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

const cursorKey = (targetId: number) => `${SYNC_CURSOR_KEY}:${targetId}`;
const lockKey = (targetId: number) => `${SYNC_LOCK_KEY}:${targetId}`;

/**
 * Claims the full-sync lock. idp_settings.value is "ISO timestamp : uuid", so
 * lexical comparison doubles as a staleness check: an abandoned lock expires
 * instead of wedging every later sync.
 */
async function claimSyncLock(env: Env, targetId: number): Promise<string | null> {
  const token = `${new Date().toISOString()}:${crypto.randomUUID()}`;
  const stale = new Date(Date.now() - SYNC_LOCK_STALE_MS).toISOString();
  const claimed = await env.DB.prepare(
    `INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
     WHERE idp_settings.value < ?`
  )
    .bind(lockKey(targetId), token, new Date().toISOString(), stale)
    .run();
  return claimed.meta.changes ? token : null;
}

/**
 * One batch of a full sync against a target (the first enabled one unless
 * `targetId` says otherwise). The console poller, an API caller, or the
 * hourly cron can all invoke a sync at once; two runners processing the same
 * batch create duplicate remote objects, so the loser coalesces instead.
 */
export async function syncAll(env: Env, opts: { restart?: boolean; targetId?: number } = {}): Promise<SyncStep> {
  const target = opts.targetId !== undefined ? await getScimTarget(env, opts.targetId) : (await enabledScimTargets(env))[0];
  if (!target) return { phase: "users", users: 0, userErrors: 0, groups: 0, groupErrors: 0, complete: true, remainingUsers: 0, errors: [] };

  const lock = await claimSyncLock(env, target.id);
  if (!lock) {
    const remainingUsers = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE id NOT IN (SELECT user_id FROM scim_user_links WHERE target_id = ?)").bind(target.id).first<{ n: number }>())?.n ?? 0;
    return { phase: "users", users: 0, userErrors: 0, groups: 0, groupErrors: 0, complete: false, remainingUsers, busy: true, errors: [] };
  }
  try {
    return await syncAllLocked(env, target, opts);
  } finally {
    await env.DB.prepare("DELETE FROM idp_settings WHERE key = ? AND value = ?").bind(lockKey(target.id), lock).run();
  }
}

async function syncAllLocked(env: Env, target: ScimTarget, opts: { restart?: boolean }): Promise<SyncStep> {
  await drainScimDeprovisionQueue(env, target.id);
  const key = cursorKey(target.id);
  const setCursor = (v: string) =>
    env.DB.prepare("INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
      .bind(key, v, new Date().toISOString())
      .run();
  const stored = opts.restart ? "" : ((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(key).first<{ value: string }>())?.value ?? "");
  const errors: SyncStep["errors"] = [];
  const note = (t: string, r: ScimResult) => {
    if (!r.ok && errors.length < 5) errors.push({ target: t, status: r.status, error: String(r.error ?? "").slice(0, 300) });
  };

  // Last step: the groups, once every user has been pushed (members need their SCIM ids).
  if (stored === "groups") {
    const { groups, groupErrors, failures } = await syncGroups(env, target);
    for (const f of failures) note(f.name, f.result);
    await setCursor("");
    return { phase: "groups", users: 0, userErrors: 0, groups, groupErrors, complete: true, remainingUsers: 0, errors };
  }

  const { results: users } = await env.DB.prepare("SELECT * FROM users WHERE id > ? ORDER BY id LIMIT ?").bind(Number(stored) || 0, target.syncBatchSize).all<UserRow>();
  let userErrors = 0;
  for (const user of users) {
    const result = await pushUserToTarget(env, target, user);
    if (!result.ok) userErrors++;
    note(user.upn, result);
  }
  const last = users.length ? users[users.length - 1]!.id : Number(stored) || 0;
  const remaining = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE id > ?").bind(last).first<{ n: number }>())?.n ?? 0;
  await setCursor(remaining > 0 ? String(last) : "groups");
  return { phase: "users", users: users.length, userErrors, groups: 0, groupErrors: 0, complete: false, remainingUsers: remaining, errors };
}

/** Cron: carries on every full sync that a previous invocation left unfinished. */
export async function continueScimSync(env: Env): Promise<void> {
  const { results: cursors } = await env.DB.prepare("SELECT key FROM idp_settings WHERE key LIKE 'scim_sync_cursor:%' AND value != ''").all<{ key: string }>();
  for (const { key } of cursors) {
    const targetId = Number(key.split(":")[1]);
    if (Number.isInteger(targetId)) await syncAll(env, { targetId });
  }
}

/** Pushes one group with its current resolved members (for writers that change a single group). */
export async function pushGroupCurrent(env: Env, group: GroupRow): Promise<ScimResult> {
  return fanOut(env, async (target) => pushGroupToTarget(env, target, group, await currentScimMembers(env, target, group)));
}

/** A group's current members that have been pushed to this target as users (have a link). */
async function currentScimMembers(env: Env, target: ScimTarget, group: GroupRow): Promise<ScimMember[]> {
  const memberIds = await resolveGroupMemberUserIds(env, group);
  if (!memberIds.length) return [];
  const { results } = await env.DB.prepare(
    "SELECT u.id AS userId, l.scim_id AS scimId, u.upn FROM users u JOIN scim_user_links l ON l.user_id = u.id AND l.target_id = ? WHERE u.id IN (SELECT value FROM json_each(?))"
  )
    .bind(target.id, JSON.stringify(memberIds))
    .all<ScimMember>();
  return results;
}

/**
 * A queue entry for a remote object whose local row is being deleted - run it
 * in the same batch as the deletion, then drain. The remote id survives a
 * failed or budget-cut DELETE instead of vanishing with the row.
 */
export function queueScimDeprovision(env: Env, targetId: number, kind: "user" | "group", scimId: string, label: string): D1PreparedStatement {
  return env.DB.prepare("INSERT OR IGNORE INTO scim_deprovision_queue (target_id, kind, scim_id, label, queued_at) VALUES (?, ?, ?, ?, ?)").bind(targetId, kind, scimId, label, new Date().toISOString());
}

/**
 * One deprovision statement per target the local row was ever pushed to -
 * what callers need when a user or group is deleted (the links themselves are
 * dropped by the same transaction's cascades).
 */
export async function scimDeprovisionStatements(env: Env, kind: "user" | "group", localId: number, label: string): Promise<D1PreparedStatement[]> {
  const links = kind === "user"
    ? await env.DB.prepare("SELECT target_id, scim_id FROM scim_user_links WHERE user_id = ?").bind(localId).all<{ target_id: number; scim_id: string }>()
    : await env.DB.prepare("SELECT target_id, scim_id FROM scim_group_links WHERE group_id = ?").bind(localId).all<{ target_id: number; scim_id: string }>();
  return links.results.map((l) => queueScimDeprovision(env, l.target_id, kind, l.scim_id, label));
}

/**
 * Deprovision statements for a set of rows being deleted in bulk (imports,
 * directory reset): one link lookup for the whole set, one queued DELETE per
 * (target, remote id).
 */
export async function scimDeprovisionStatementsForMany(env: Env, kind: "user" | "group", items: { id: number; label: string }[]): Promise<D1PreparedStatement[]> {
  if (!items.length) return [];
  const col = kind === "user" ? "user_id" : "group_id";
  const { results } = await env.DB.prepare(`SELECT ${col} AS local_id, target_id, scim_id FROM ${kind === "user" ? "scim_user_links" : "scim_group_links"} WHERE ${col} IN (SELECT value FROM json_each(?))`)
    .bind(JSON.stringify(items.map((i) => i.id)))
    .all<{ local_id: number; target_id: number; scim_id: string }>();
  const label = new Map(items.map((i) => [i.id, i.label]));
  return results.map((l) => queueScimDeprovision(env, l.target_id, kind, l.scim_id, label.get(l.local_id) ?? ""));
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
 * Re-pushes users who were just removed from a group, so each target can
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
export async function drainScimDeprovisionQueue(env: Env, targetId?: number): Promise<{ removed: number; removedUsers: number; removedGroups: number; failed: number; remaining: number }> {
  let removedUsers = 0;
  let removedGroups = 0;
  let failed = 0;
  const { results } = await env.DB.prepare(
    `SELECT q.target_id, q.kind, q.scim_id, q.label, t.id AS tid, t.name, t.endpoint, t.secret, t.scope_mode, t.scope_group_ids, t.pace_ms, t.members_per_request, t.sync_batch, t.enabled
     FROM scim_deprovision_queue q JOIN scim_targets t ON t.id = q.target_id AND t.enabled = 1
     ${targetId !== undefined ? "WHERE q.target_id = ?" : ""}
     ORDER BY q.attempts, q.queued_at LIMIT ?`
  )
    .bind(...(targetId !== undefined ? [targetId, DEPROVISION_BATCH] : [DEPROVISION_BATCH]))
    .all<{ target_id: number; kind: "user" | "group"; scim_id: string; label: string; tid: number; name: string; endpoint: string; secret: string; scope_mode: string; scope_group_ids: string; pace_ms: number; members_per_request: number; sync_batch: number; enabled: number }>();
  const targets = new Map<number, ScimTarget>();
  for (const item of results) {
    let target = targets.get(item.target_id);
    if (!target) {
      target = (await getScimTarget(env, item.target_id))!;
      targets.set(item.target_id, target);
    }
    const r = item.kind === "user" ? await deleteRemoteUser(env, target, item.scim_id) : await deleteRemoteGroup(env, target, item.scim_id);
    if (r.ok) {
      if (item.kind === "user") removedUsers++;
      else removedGroups++;
      await env.DB.prepare("DELETE FROM scim_deprovision_queue WHERE target_id = ? AND kind = ? AND scim_id = ?").bind(item.target_id, item.kind, item.scim_id).run();
    } else {
      failed++;
      await env.DB.prepare("UPDATE scim_deprovision_queue SET attempts = attempts + 1, last_error = ? WHERE target_id = ? AND kind = ? AND scim_id = ?")
        .bind(String(r.error ?? r.status ?? "failed").slice(0, 500), item.target_id, item.kind, item.scim_id)
        .run();
    }
  }
  const remaining = (await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_deprovision_queue").first<{ n: number }>())?.n ?? 0;
  return { removed: removedUsers + removedGroups, removedUsers, removedGroups, failed, remaining };
}

export async function syncGroups(env: Env, target: ScimTarget, onlyIds?: number[]): Promise<{ groups: number; groupErrors: number; failures: { name: string; result: ScimResult }[] }> {
  // onlyIds: just these groups (an import that touched a few people), not the whole directory.
  const { results: groups } = onlyIds
    ? await env.DB.prepare("SELECT * FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(onlyIds)).all<GroupRow>()
    : await env.DB.prepare("SELECT * FROM groups").all<GroupRow>();
  let groupErrors = 0;
  const failures: { name: string; result: ScimResult }[] = [];
  const members = await resolveManyGroupMemberUserIds(env, groups);
  // SCIM ids for every user once, rather than a query per group.
  const { results: synced } = await env.DB.prepare("SELECT l.user_id AS id, l.scim_id, u.upn FROM scim_user_links l JOIN users u ON u.id = l.user_id WHERE l.target_id = ?").bind(target.id).all<{ id: number; scim_id: string; upn: string }>();
  const byId = new Map(synced.map((u) => [u.id, { userId: u.id, scimId: u.scim_id, upn: u.upn }]));
  for (const group of groups) {
    const memberIds = members.get(group.id) ?? [];
    const memberRows = memberIds.map((id) => byId.get(id)).filter((m): m is ScimMember => Boolean(m));

    // A full sync (every group) re-sends each group whole, which also
    // refreshes the stored state; a targeted one sends only the changes.
    const result = await pushGroupToTarget(env, target, group, memberRows, { full: !onlyIds });
    if (!result.ok) {
      groupErrors++;
      if (failures.length < 5) failures.push({ name: group.name, result });
    }
  }

  return { groups: groups.length, groupErrors, failures };
}

/** Fan-out variant for callers that sync groups on their own schedule (imports): all enabled targets, only these groups (every group when omitted). */
export async function syncGroupsAllTargets(env: Env, onlyIds?: number[]): Promise<{ groups: number; groupErrors: number }> {
  let groups = 0;
  let groupErrors = 0;
  for (const target of await enabledScimTargets(env)) {
    const r = await syncGroups(env, target, onlyIds);
    groups = Math.max(groups, r.groups);
    groupErrors += r.groupErrors;
  }
  return { groups, groupErrors };
}

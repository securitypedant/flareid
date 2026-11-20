import type { Env } from "../env.js";
import { MAX_RULE_BYTES, MAX_RULE_CONDITIONS, parseRule, userMatchesRule } from "../lib/groups.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { userEditableAttributeNames } from "../lib/schemas.js";
import { drainScimDeprovisionQueue, pushUsersById, scimDeprovisionStatements } from "../lib/scim-client.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { afterResponse, audit, ServiceError, type ServiceCtx } from "./context.js";
import { assertMayNameGroup, assertMayTouchGroup, assertMayTouchUser } from "./guards.js";
import { WATCHLIST_GROUP_NAME } from "../lib/cfone.js";
import { adminRoleGroupIds } from "../lib/admin-roles.js";
import { scimConfigured, syncGroupBestEffort } from "./scim-sync.js";

export async function getGroupById(env: Env, id: number): Promise<GroupRow | null> {
  return env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();
}

/**
 * Checks a rule (JSON, or "" for a static group) before it is stored: within
 * the evaluator's bounds, and not on a field users can set themselves - that
 * would let anyone choose their own groups.
 */
export async function assertRuleAllowed(env: Env, rule: string): Promise<void> {
  if (!rule) return;
  const parsed = parseRule(rule);
  if (!parsed) throw new ServiceError(400, `A rule needs between 1 and ${MAX_RULE_CONDITIONS} conditions, each a field, an op ("eq" or "ne") and a value, in at most ${MAX_RULE_BYTES} bytes.`);
  const editable = await userEditableAttributeNames(env);
  const clash = parsed.all.map((cond) => cond.field.replace(/^custom\./, "")).find((f) => editable.has(f));
  if (clash) throw new ServiceError(400, `"${clash}" is user-editable in a schema, so it cannot drive group membership. Turn off "User can edit" for it first.`);
}

export interface GroupInput {
  name: string;
  description: string;
  /** Rule JSON, or "" for a static group. */
  rule: string;
  schemaId: number | null;
  /** Values for the group schema's attributes; only those are kept. */
  custom: Record<string, string>;
  /** Whether people may ask for membership on My account (static groups only). */
  requestable: boolean;
  /** Keep the member emails in a Cloudflare One gateway list (needs the connection configured). */
  cfListSync: boolean;
}

function checkName(input: GroupInput, existingName: string | null): void {
  if (!input.name) throw new ServiceError(400, "A group name is required.");
  // Super Admins controls access to the console, so it is always assigned by hand.
  if ((existingName === SUPER_ADMINS_GROUP || input.name === SUPER_ADMINS_GROUP) && input.rule) {
    throw new ServiceError(400, `The ${SUPER_ADMINS_GROUP} group cannot be dynamic.`);
  }
  // The watchlist system group is created lazily under this exact name; an
  // ordinary group holding it first would break that creation and borrow its
  // meaning downstream. Reserved unconditionally - an admin-scoped writer
  // squatting it breaks flag operations all the same.
  if (input.name === WATCHLIST_GROUP_NAME && existingName !== WATCHLIST_GROUP_NAME) {
    throw new ServiceError(400, `"${input.name}" is reserved for the system's risk watchlist.`);
  }
}

export async function createGroup(ctx: ServiceCtx, input: GroupInput, memberIds: number[]): Promise<number> {
  checkName(input, null);
  await assertRuleAllowed(ctx.env, input.rule);
  await assertMayNameGroup(ctx, input.name);
  if (input.rule && memberIds.length) throw new ServiceError(400, "A dynamic group's members follow its rule; it takes no explicit members.");
  if (await ctx.env.DB.prepare("SELECT id FROM groups WHERE name = ?").bind(input.name).first()) {
    throw new ServiceError(409, `A group named "${input.name}" already exists.`);
  }
  // Founding members face the same check as every other membership write.
  for (const uid of memberIds) await assertMayTouchUser(ctx, uid);
  const result = await ctx.env.DB.prepare("INSERT INTO groups (name, description, rule, schema_id, custom_attributes, requestable, cf_list_sync) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(input.name, input.description || null, input.rule, input.schemaId, JSON.stringify(input.custom), input.requestable && !input.rule ? 1 : 0, input.cfListSync ? 1 : 0)
    .run();
  const id = Number(result.meta.last_row_id);
  if (memberIds.length > 0) {
    await ctx.env.DB.batch(memberIds.map((uid) => ctx.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)));
  }
  await audit(ctx, "group.created", input.name, input.rule ? { rule: input.rule } : undefined);
  await afterResponse(ctx, (later) => syncGroupBestEffort(later, id));
  return id;
}

/**
 * Updates a group. `memberIds` is the complete explicit member set of a
 * static group, or undefined to keep the current members. The type is fixed
 * at creation: dynamic -> static only via freezeGroup, which keeps the members.
 */
export async function updateGroup(ctx: ServiceCtx, id: number, input: GroupInput, memberIds?: number[]): Promise<void> {
  const current = await getGroupById(ctx.env, id);
  if (!current) throw new ServiceError(404, "Not found");
  await assertMayTouchGroup(ctx, id);
  if (current.system) throw new ServiceError(400, `"${current.name}" is a system group and cannot be edited.`);
  checkName(input, current.name);
  await assertRuleAllowed(ctx.env, input.rule);
  if (await ctx.env.DB.prepare("SELECT id FROM groups WHERE name = ? AND id != ?").bind(input.name, id).first()) {
    throw new ServiceError(409, `A group named "${input.name}" already exists.`);
  }
  if ((current.rule !== "") !== (input.rule !== "")) {
    throw new ServiceError(400, "A group's type cannot be changed here. A dynamic group can be converted to static from its page.");
  }
  // Console authority is membership of the group with exactly this name, so
  // the built-in group keeps it: renamed away, the name would be free for any
  // directory writer (SCIM, import) to claim for a group it controls.
  if ((current.name === SUPER_ADMINS_GROUP) !== (input.name === SUPER_ADMINS_GROUP)) {
    throw new ServiceError(400, `The ${SUPER_ADMINS_GROUP} group cannot be renamed, and no other group can take its name.`);
  }
  const { results: before } = await ctx.env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(id).all<{ user_id: number }>();
  const members = input.rule ? [] : (memberIds ?? before.map((b) => b.user_id));
  if (memberIds !== undefined) {
    // A replace touches whoever is added or removed - and membership writes
    // act on the member's account, so an administrator's memberships need
    // admin authority (the check SCIM's member operations make).
    const beforeIds = new Set(before.map((b) => b.user_id));
    const nextIds = new Set(members);
    const touched = [...members.filter((uid) => !beforeIds.has(uid)), ...before.map((b) => b.user_id).filter((uid) => !nextIds.has(uid))];
    for (const uid of touched) await assertMayTouchUser(ctx, uid);
  }

  await ctx.env.DB.batch([
    ctx.env.DB.prepare("UPDATE groups SET name = ?, description = ?, rule = ?, schema_id = ?, custom_attributes = ?, requestable = ?, cf_list_sync = ? WHERE id = ?").bind(
      input.name,
      input.description || null,
      input.rule,
      input.schemaId,
      JSON.stringify(input.custom),
      input.requestable && !input.rule ? 1 : 0,
      input.cfListSync && !current.system ? 1 : 0,
      id
    ),
    // A dynamic group holds no explicit rows; a static one holds exactly this set.
    ctx.env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(id),
    ...[...new Set(members)].map((uid) => ctx.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)),
  ]);

  await audit(ctx, "group.updated", input.name, input.rule ? { rule: input.rule } : undefined);
  await afterResponse(ctx, async (later) => {
    await syncGroupBestEffort(later, id);
    // Members this edit removed are re-pushed: leaving a SCIM-scoped group can take them out of scope.
    if (await scimConfigured(later.env)) {
      const kept = new Set(members);
      const r = await pushUsersById(later.env, before.map((b) => b.user_id).filter((uid) => !kept.has(uid)));
      if (!r.ok) await audit(later, "scim.user_sync_failed", input.name, { action: "membership_removed", error: r.error });
    }
  });
}

/** Dynamic -> static: the rule's current matches become assigned members. */
export async function freezeGroup(ctx: ServiceCtx, id: number): Promise<number> {
  const group = await getGroupById(ctx.env, id);
  const rule = group ? parseRule(group.rule) : null;
  if (!group || !rule) throw new ServiceError(400, "Only a dynamic group can be converted to static.");
  await assertMayTouchGroup(ctx, id);
  const { results } = await ctx.env.DB.prepare("SELECT * FROM users").all<UserRow>();
  const ids = results.filter((u) => userMatchesRule(u, rule)).map((u) => u.id);
  // Rule off and the matches written as assigned rows in one batch, so the
  // group never has a moment with neither.
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("UPDATE groups SET rule = '' WHERE id = ?").bind(id),
    ctx.env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(id),
    ctx.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) SELECT ?, value FROM json_each(?)").bind(id, JSON.stringify(ids)),
  ]);
  await audit(ctx, "group.converted_to_static", group.name, { members: ids.length, rule: group.rule });
  await afterResponse(ctx, (later) => syncGroupBestEffort(later, id));
  return ids.length;
}

export async function deleteGroup(ctx: ServiceCtx, id: number): Promise<GroupRow> {
  const group = await getGroupById(ctx.env, id);
  if (!group) throw new ServiceError(404, "Not found");
  if (group.name === SUPER_ADMINS_GROUP) throw new ServiceError(400, `The ${SUPER_ADMINS_GROUP} group cannot be deleted.`);
  if (group.system) throw new ServiceError(400, `"${group.name}" is a system group and cannot be deleted.`);
  await assertMayTouchGroup(ctx, id);
  const { results: members } = await ctx.env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(id).all<{ user_id: number }>();
  // Local first with the remote id queued in the same batch, as for users.
  await ctx.env.DB.batch([
    ...(await scimDeprovisionStatements(ctx.env, "group", group.id, group.name)),
    ctx.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(id),
  ]);
  await afterResponse(ctx, async (later) => {
    if (await scimConfigured(later.env)) {
      const drained = await drainScimDeprovisionQueue(later.env);
      const pushed = await pushUsersById(later.env, members.map((m) => m.user_id));
      if (drained.failed || !pushed.ok) await audit(later, "scim.group_sync_failed", group.name, { action: "delete", queued: drained.remaining, error: pushed.error });
    }
  });
  await audit(ctx, "group.deleted", group.name);
  return group;
}

/** Adds explicit members to a static group; people already in it are left as they are. */
export async function addGroupMembers(ctx: ServiceCtx, id: number, userIds: number[]): Promise<number> {
  const group = await getGroupById(ctx.env, id);
  if (!group) throw new ServiceError(404, "Not found");
  if (group.rule) throw new ServiceError(400, "Members of a dynamic group follow its rule.");
  if (group.system) throw new ServiceError(400, `Membership of "${group.name}" is maintained automatically; it cannot be edited.`);
  await assertMayTouchGroup(ctx, id);
  if (userIds.length === 0) return 0;
  // Adding someone changes their account's memberships: an administrator's
  // need admin authority - the check SCIM's member operations make.
  for (const uid of userIds) await assertMayTouchUser(ctx, uid);
  const results = await ctx.env.DB.batch(userIds.map((uid) => ctx.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)));
  const added = results.reduce((n, r) => n + Number(r.meta.changes ?? 0), 0);
  await audit(ctx, "group.members_added", group.name, { count: added });
  await afterResponse(ctx, async (later) => {
    await syncGroupBestEffort(later, id);
    if (await scimConfigured(later.env)) await pushUsersById(later.env, userIds);
  });
  return added;
}

export async function removeGroupMember(ctx: ServiceCtx, id: number, uid: number): Promise<void> {
  const group = await getGroupById(ctx.env, id);
  if (!group || group.rule) throw new ServiceError(400, "Members of a dynamic group follow its rule.");
  if (group.system) throw new ServiceError(400, `Membership of "${group.name}" is maintained automatically; it cannot be edited.`);
  if (group.name === SUPER_ADMINS_GROUP && uid === ctx.selfId) throw new ServiceError(400, "You cannot remove yourself from Super Admins.");
  await assertMayTouchGroup(ctx, id);
  await assertMayTouchUser(ctx, uid);
  const user = await ctx.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(uid).first<{ upn: string }>();
  await ctx.env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").bind(id, uid).run();
  await audit(ctx, "group.member_removed", group.name, { user: user?.upn });
  await afterResponse(ctx, async (later) => {
    await syncGroupBestEffort(later, id);
    if (await scimConfigured(later.env)) await pushUsersById(later.env, [uid]);
  });
}

/** Names people as managers of a group; they can then change members and answer requests from My account. */
export async function addGroupManagers(ctx: ServiceCtx, id: number, userIds: number[]): Promise<number> {
  const group = await getGroupById(ctx.env, id);
  if (!group) throw new ServiceError(404, "Not found");
  if (group.rule) throw new ServiceError(400, "A dynamic group's membership follows its rule - there is nothing to delegate.");
  if (group.system) throw new ServiceError(400, `"${group.name}" is a system group; it takes no managers.`);
  // A role group's members are an admin grant - delegated management must
  // never reach it, so naming managers there is refused even for Super Admin.
  if ((await adminRoleGroupIds(ctx.env)).has(id)) throw new ServiceError(400, "An admin role group can't have managers - its membership grants an admin role.");
  await assertMayTouchGroup(ctx, id);
  if (!userIds.length) return 0;
  const results = await ctx.env.DB.batch(
    userIds.map((uid) => ctx.env.DB.prepare("INSERT OR IGNORE INTO group_managers (group_id, user_id, created_at) VALUES (?, ?, ?)").bind(id, uid, new Date().toISOString()))
  );
  const added = results.reduce((n, r) => n + Number(r.meta.changes ?? 0), 0);
  await audit(ctx, "group.managers_added", group.name, { count: added });
  return added;
}

export async function removeGroupManager(ctx: ServiceCtx, id: number, uid: number): Promise<void> {
  const group = await getGroupById(ctx.env, id);
  if (!group) throw new ServiceError(404, "Not found");
  await assertMayTouchGroup(ctx, id);
  const user = await ctx.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(uid).first<{ upn: string }>();
  await ctx.env.DB.prepare("DELETE FROM group_managers WHERE group_id = ? AND user_id = ?").bind(id, uid).run();
  await audit(ctx, "group.manager_removed", group.name, { user: user?.upn });
}

/**
 * A group's current members - assigned ones for a static group, rule matches
 * for a dynamic one - optionally filtered by name, UPN or username, one page
 * at a time, so "is this person in the group?" has an answer at any size.
 */
export async function groupMembers(env: Env, group: GroupRow, search: string, limit: number, offset: number): Promise<{ total: number; rows: UserRow[] }> {
  const rule = parseRule(group.rule);
  const needle = search.trim().toLowerCase();
  if (rule) {
    const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY display_name").all<UserRow>();
    const all = results.filter((u) => userMatchesRule(u, rule));
    const hits = needle ? all.filter((u) => `${u.display_name} ${u.upn} ${u.username}`.toLowerCase().includes(needle)) : all;
    return { total: hits.length, rows: hits.slice(offset, offset + limit) };
  }
  const like = `%${needle}%`;
  const where = "FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ? AND (lower(u.display_name) LIKE ? OR lower(u.upn) LIKE ? OR u.username LIKE ?)";
  const total = (await env.DB.prepare(`SELECT COUNT(*) AS n ${where}`).bind(group.id, like, like, like).first<{ n: number }>())?.n ?? 0;
  const rows = (await env.DB.prepare(`SELECT u.* ${where} ORDER BY u.display_name LIMIT ? OFFSET ?`).bind(group.id, like, like, like, limit, offset).all<UserRow>()).results;
  return { total, rows };
}

// ---------------------------------------------------------------------------
// Bulk actions over the groups list: selection can span pages and searches,
// so each group is re-checked when the action runs - never trust the page's
// idea of what was selected.
// ---------------------------------------------------------------------------

export interface BulkGroupResult {
  /** Names of the groups the action applied to. */
  applied: string[];
  /** Names it could not touch: dynamic (no assigned membership to edit) or, for a non-privileged actor, admin role groups. */
  skipped: string[];
}

/** The groups an action may touch: static, and below Super Admin authority not admin-role ones. */
async function bulkEditableGroups(ctx: ServiceCtx, ids: number[]): Promise<{ editable: GroupRow[]; skipped: string[] }> {
  const unique = [...new Set(ids)].filter((id) => Number.isInteger(id) && id > 0);
  if (!unique.length) return { editable: [], skipped: [] };
  const { results } = await ctx.env.DB.prepare("SELECT * FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(unique)).all<GroupRow>();
  const skipped = results.filter((g) => g.rule || g.system).map((g) => g.name);
  let editable = results.filter((g) => !g.rule && !g.system);
  if (!ctx.privileged) {
    const protectedIds = await adminRoleGroupIds(ctx.env);
    skipped.push(...editable.filter((g) => protectedIds.has(g.id)).map((g) => g.name));
    editable = editable.filter((g) => !protectedIds.has(g.id));
  }
  return { editable, skipped };
}

/** Turns "People can request membership" on or off for every static, unprotected group in the set. */
export async function bulkSetRequestable(ctx: ServiceCtx, ids: number[], on: boolean): Promise<BulkGroupResult> {
  const { editable, skipped } = await bulkEditableGroups(ctx, ids);
  if (!editable.length) throw new ServiceError(400, skipped.length ? `None of the selected groups can be changed: ${skipped.join(", ")}.` : "No groups selected.");
  await ctx.env.DB.batch(editable.map((g) => ctx.env.DB.prepare("UPDATE groups SET requestable = ? WHERE id = ?").bind(on ? 1 : 0, g.id)));
  await audit(ctx, "group.bulk_requestable", undefined, { on, groups: editable.map((g) => g.name), skipped });
  return { applied: editable.map((g) => g.name), skipped };
}

/** Adds the same people to every static, unprotected group in the set - the same writes the members endpoints make. */
export async function bulkAddMembers(ctx: ServiceCtx, ids: number[], userIds: number[]): Promise<BulkGroupResult & { added: number }> {
  const { editable, skipped } = await bulkEditableGroups(ctx, ids);
  if (!editable.length) throw new ServiceError(400, skipped.length ? `None of the selected groups can take members: ${skipped.join(", ")}.` : "No groups selected.");
  let added = 0;
  for (const group of editable) {
    added += await addGroupMembers(ctx, group.id, userIds);
  }
  await audit(ctx, "group.bulk_members_added", undefined, { groups: editable.map((g) => g.name), people: userIds.length, added, skipped });
  return { applied: editable.map((g) => g.name), skipped, added };
}

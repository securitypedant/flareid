import type { Env } from "../env.js";
import { MAX_RULE_BYTES, MAX_RULE_CONDITIONS, parseRule, userMatchesRule } from "../lib/groups.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { userEditableAttributeNames } from "../lib/schemas.js";
import { drainScimDeprovisionQueue, pushUsersById, queueScimDeprovision } from "../lib/scim-client.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";
import { assertMayNameGroup, assertMayTouchGroup } from "./guards.js";
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
}

function checkName(input: GroupInput, existingName: string | null): void {
  if (!input.name) throw new ServiceError(400, "A group name is required.");
  // Super Admins controls access to the console, so it is always assigned by hand.
  if ((existingName === SUPER_ADMINS_GROUP || input.name === SUPER_ADMINS_GROUP) && input.rule) {
    throw new ServiceError(400, `The ${SUPER_ADMINS_GROUP} group cannot be dynamic.`);
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
  const result = await ctx.env.DB.prepare("INSERT INTO groups (name, description, rule, schema_id, custom_attributes) VALUES (?, ?, ?, ?, ?)")
    .bind(input.name, input.description || null, input.rule, input.schemaId, JSON.stringify(input.custom))
    .run();
  const id = Number(result.meta.last_row_id);
  if (memberIds.length > 0) {
    await ctx.env.DB.batch(memberIds.map((uid) => ctx.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)));
  }
  await audit(ctx, "group.created", input.name, input.rule ? { rule: input.rule } : undefined);
  await syncGroupBestEffort(ctx, id);
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

  await ctx.env.DB.batch([
    ctx.env.DB.prepare("UPDATE groups SET name = ?, description = ?, rule = ?, schema_id = ?, custom_attributes = ? WHERE id = ?").bind(
      input.name,
      input.description || null,
      input.rule,
      input.schemaId,
      JSON.stringify(input.custom),
      id
    ),
    // A dynamic group holds no explicit rows; a static one holds exactly this set.
    ctx.env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(id),
    ...[...new Set(members)].map((uid) => ctx.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)),
  ]);

  await audit(ctx, "group.updated", input.name, input.rule ? { rule: input.rule } : undefined);
  await syncGroupBestEffort(ctx, id);
  // Members this edit removed are re-pushed: leaving a SCIM-scoped group can take them out of scope.
  if (await scimConfigured(ctx.env)) {
    const kept = new Set(members);
    const r = await pushUsersById(ctx.env, before.map((b) => b.user_id).filter((uid) => !kept.has(uid)));
    if (!r.ok) await audit(ctx, "scim.user_sync_failed", input.name, { action: "membership_removed", error: r.error });
  }
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
  await syncGroupBestEffort(ctx, id);
  return ids.length;
}

export async function deleteGroup(ctx: ServiceCtx, id: number): Promise<GroupRow> {
  const group = await getGroupById(ctx.env, id);
  if (!group) throw new ServiceError(404, "Not found");
  if (group.name === SUPER_ADMINS_GROUP) throw new ServiceError(400, `The ${SUPER_ADMINS_GROUP} group cannot be deleted.`);
  await assertMayTouchGroup(ctx, id);
  const { results: members } = await ctx.env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(id).all<{ user_id: number }>();
  // Local first with the remote id queued in the same batch, as for users.
  await ctx.env.DB.batch([
    ...(group.scim_id ? [queueScimDeprovision(ctx.env, "group", group.scim_id, group.name)] : []),
    ctx.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(id),
  ]);
  if (await scimConfigured(ctx.env)) {
    const drained = await drainScimDeprovisionQueue(ctx.env);
    const pushed = await pushUsersById(ctx.env, members.map((m) => m.user_id));
    if (drained.failed || !pushed.ok) await audit(ctx, "scim.group_sync_failed", group.name, { action: "delete", queued: drained.remaining, error: pushed.error });
  }
  await audit(ctx, "group.deleted", group.name);
  return group;
}

/** Adds explicit members to a static group; people already in it are left as they are. */
export async function addGroupMembers(ctx: ServiceCtx, id: number, userIds: number[]): Promise<number> {
  const group = await getGroupById(ctx.env, id);
  if (!group) throw new ServiceError(404, "Not found");
  if (group.rule) throw new ServiceError(400, "Members of a dynamic group follow its rule.");
  await assertMayTouchGroup(ctx, id);
  if (userIds.length === 0) return 0;
  const results = await ctx.env.DB.batch(userIds.map((uid) => ctx.env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)));
  const added = results.reduce((n, r) => n + Number(r.meta.changes ?? 0), 0);
  await audit(ctx, "group.members_added", group.name, { count: added });
  await syncGroupBestEffort(ctx, id);
  if (await scimConfigured(ctx.env)) await pushUsersById(ctx.env, userIds);
  return added;
}

export async function removeGroupMember(ctx: ServiceCtx, id: number, uid: number): Promise<void> {
  const group = await getGroupById(ctx.env, id);
  if (!group || group.rule) throw new ServiceError(400, "Members of a dynamic group follow its rule.");
  if (group.name === SUPER_ADMINS_GROUP && uid === ctx.selfId) throw new ServiceError(400, "You cannot remove yourself from Super Admins.");
  await assertMayTouchGroup(ctx, id);
  const user = await ctx.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(uid).first<{ upn: string }>();
  await ctx.env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").bind(id, uid).run();
  await audit(ctx, "group.member_removed", group.name, { user: user?.upn });
  await syncGroupBestEffort(ctx, id);
  if (await scimConfigured(ctx.env)) await pushUsersById(ctx.env, [uid]);
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

import { accessFor, adminRoleGroupIds, adminRoleGroupNames, grantsAdminRoleGroup } from "../lib/admin-roles.js";
import { isGroupManager } from "../lib/group-managers.js";
import type { UserRow } from "../lib/types.js";
import { ServiceError, type ServiceCtx } from "./context.js";

/**
 * Below Super Admin (or an admin API key), nobody can change who holds an
 * admin role or act on an account that holds one: a Directory Admin could
 * otherwise make themselves (or anyone) Super Admin, or reset a Super
 * Admin's password. The console enforces the same rules in a middleware
 * before any form is read; these keep every service honest on its own.
 */

const NEEDS = "needs a Super Admin (an admin API key)";

export async function assertMayTouchUser(ctx: ServiceCtx, userId: number): Promise<void> {
  if (ctx.privileged) return;
  if ((await accessFor(ctx.env, userId)).isAdmin) throw new ServiceError(403, `Changing an account that holds an admin role ${NEEDS}.`);
}

export async function assertMayTouchGroup(ctx: ServiceCtx, groupId: number): Promise<void> {
  if (ctx.privileged) return;
  if ((await adminRoleGroupIds(ctx.env)).has(groupId)) throw new ServiceError(403, `Changing an admin role group ${NEEDS}.`);
}

export async function assertMayAssignGroups(ctx: ServiceCtx, groupIds: number[]): Promise<void> {
  if (ctx.privileged || groupIds.length === 0) return;
  const roleGroups = await adminRoleGroupIds(ctx.env);
  if (groupIds.some((id) => roleGroups.has(id))) throw new ServiceError(403, `Giving someone an admin role ${NEEDS}.`);
}

/**
 * An attribute write can be an admin grant too: the post-write row is checked
 * against the rule of every dynamic group linked to a role. `before` is null
 * on the create path - any match is a grant. assertMayTouchUser already stops
 * a non-privileged caller editing an existing holder; this stops them making
 * a new one.
 */
export async function assertNoAdminRoleGrant(ctx: ServiceCtx, before: UserRow | null, after: UserRow): Promise<void> {
  if (ctx.privileged) return;
  const granted = await grantsAdminRoleGroup(ctx.env, before, after);
  if (granted) throw new ServiceError(403, `That change puts the user in "${granted}", an admin role group - ${NEEDS}.`);
}

/**
 * Who may change a group's members and answer its access requests without
 * groups:write: its managers. Admin-role groups are excluded up front by the
 * ordinary guard - delegated management never delegates an admin grant.
 */
export async function assertMayManageGroup(ctx: ServiceCtx, groupId: number): Promise<void> {
  await assertMayTouchGroup(ctx, groupId);
  if (ctx.privileged) return;
  if (ctx.selfId && (await isGroupManager(ctx.env, ctx.selfId, groupId))) return;
  throw new ServiceError(403, "Only this group's managers can do that here.");
}

export async function assertMayNameGroup(ctx: ServiceCtx, name: string): Promise<void> {
  if (ctx.privileged) return;
  if ((await adminRoleGroupNames(ctx.env)).includes(name)) throw new ServiceError(403, `Creating an admin role group ${NEEDS}.`);
}

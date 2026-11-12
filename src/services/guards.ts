import { accessFor, adminRoleGroupIds, adminRoleGroupNames } from "../lib/admin-roles.js";
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

export async function assertMayNameGroup(ctx: ServiceCtx, name: string): Promise<void> {
  if (ctx.privileged) return;
  if ((await adminRoleGroupNames(ctx.env)).includes(name)) throw new ServiceError(403, `Creating an admin role group ${NEEDS}.`);
}

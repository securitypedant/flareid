import { SUPER_ROLE, type RoleRow } from "../lib/admin-roles.js";
import { grants, isPermission, type Permission } from "../lib/permissions.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";

/**
 * Authentication policies and admin roles: the two "who must do what" tables,
 * each with its groups.
 */

// ---------------------------------------------------------------------------
// Authentication policies
// ---------------------------------------------------------------------------

export interface PolicyInput {
  name: string;
  description: string;
  requirement: "password" | "mfa";
  priority: number;
  groupIds: number[];
  makeDefault: boolean;
}

/** Normalises raw input the same way for a form and a JSON body. */
export function normalizePolicy(raw: { name?: unknown; description?: unknown; requirement?: unknown; priority?: unknown; groupIds?: unknown[]; makeDefault?: unknown }): PolicyInput {
  const name = String(raw.name ?? "").trim().slice(0, 80);
  if (!name) throw new ServiceError(400, "A policy name is required.");
  return {
    name,
    description: String(raw.description ?? "").trim().slice(0, 200),
    requirement: String(raw.requirement) === "password" ? "password" : "mfa",
    priority: Math.min(1000, Math.max(1, Math.floor(Number(raw.priority)) || 100)),
    groupIds: (raw.groupIds ?? []).map(Number).filter(Boolean),
    makeDefault: Boolean(raw.makeDefault),
  };
}

async function savePolicyGroups(ctx: ServiceCtx, policyId: number, groupIds: number[]): Promise<void> {
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("DELETE FROM auth_policy_groups WHERE policy_id = ?").bind(policyId),
    ctx.env.DB.prepare("INSERT OR IGNORE INTO auth_policy_groups (policy_id, group_id) SELECT ?, g.id FROM groups g WHERE g.id IN (SELECT value FROM json_each(?))").bind(policyId, JSON.stringify(groupIds)),
  ]);
}

export async function createPolicy(ctx: ServiceCtx, f: PolicyInput): Promise<number> {
  if (await ctx.env.DB.prepare("SELECT 1 FROM auth_policies WHERE name = ?").bind(f.name).first()) throw new ServiceError(400, "A policy with that name already exists.");
  const row = await ctx.env.DB.prepare("INSERT INTO auth_policies (name, description, requirement, priority, is_default, created_at) VALUES (?, ?, ?, ?, 0, ?) RETURNING id")
    .bind(f.name, f.description, f.requirement, f.priority, new Date().toISOString())
    .first<{ id: number }>();
  await savePolicyGroups(ctx, row!.id, f.groupIds);
  await audit(ctx, "auth_policy.created", f.name, { requirement: f.requirement, groups: f.groupIds.length });
  return row!.id;
}

export async function updatePolicy(ctx: ServiceCtx, id: number, f: PolicyInput): Promise<void> {
  const current = await ctx.env.DB.prepare("SELECT * FROM auth_policies WHERE id = ?").bind(id).first<{ is_default: number; name: string }>();
  if (!current) throw new ServiceError(404, "Not found");
  if (await ctx.env.DB.prepare("SELECT 1 FROM auth_policies WHERE name = ? AND id != ?").bind(f.name, id).first()) throw new ServiceError(400, "A policy with that name already exists.");
  await ctx.env.DB.prepare("UPDATE auth_policies SET name = ?, description = ?, requirement = ?, priority = ? WHERE id = ?").bind(f.name, f.description, f.requirement, f.priority, id).run();
  await savePolicyGroups(ctx, id, f.groupIds);
  if (!current.is_default && f.makeDefault) {
    await ctx.env.DB.prepare("UPDATE auth_policies SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END").bind(id).run();
  }
  await audit(ctx, "auth_policy.updated", f.name, { requirement: f.requirement, default: Boolean(current.is_default || f.makeDefault) });
}

export async function deletePolicy(ctx: ServiceCtx, id: number): Promise<void> {
  const p = await ctx.env.DB.prepare("SELECT name, is_default FROM auth_policies WHERE id = ?").bind(id).first<{ name: string; is_default: number }>();
  if (!p) throw new ServiceError(404, "Not found");
  if (p.is_default) throw new ServiceError(400, "The default policy cannot be deleted; make another policy the default first.");
  await ctx.env.DB.batch([ctx.env.DB.prepare("DELETE FROM auth_policy_groups WHERE policy_id = ?").bind(id), ctx.env.DB.prepare("DELETE FROM auth_policies WHERE id = ?").bind(id)]);
  await audit(ctx, "auth_policy.deleted", p.name);
}

// ---------------------------------------------------------------------------
// Admin roles
// ---------------------------------------------------------------------------

export interface RoleInput {
  name: string;
  description: string;
  permissions: Permission[];
  groupIds: number[];
}

/**
 * Normalises a role and applies the no-escalation rule: nobody can grant a
 * permission they do not hold themselves, and "*" only a holder of "*".
 * `held` is the caller's expanded permission set.
 */
export function normalizeRole(raw: { name?: unknown; description?: unknown; permissions: string[]; groupIds?: unknown[] }, held: Set<Permission>): RoleInput {
  const name = String(raw.name ?? "").trim().slice(0, 80);
  if (!name) throw new ServiceError(400, "A role needs a name.");
  const unknown = raw.permissions.filter((p) => !isPermission(p));
  if (unknown.length) throw new ServiceError(400, `Unknown permission(s): ${unknown.join(", ")}.`);
  const permissions = [...new Set(raw.permissions)];
  const beyond = permissions.filter((p) => (p === "*" ? !held.has("*") : !grants(held, p)));
  if (beyond.length) throw new ServiceError(403, `You cannot grant permissions you do not hold: ${beyond.join(", ")}.`);
  return { name, description: String(raw.description ?? "").trim().slice(0, 200), permissions, groupIds: (raw.groupIds ?? []).map(Number).filter(Boolean) };
}

async function saveRoleGroups(ctx: ServiceCtx, roleId: number, groupIds: number[]): Promise<void> {
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("DELETE FROM admin_role_groups WHERE role_id = ?").bind(roleId),
    ctx.env.DB.prepare("INSERT OR IGNORE INTO admin_role_groups (role_id, group_id) SELECT ?, id FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(roleId, JSON.stringify(groupIds)),
  ]);
}

export async function createRole(ctx: ServiceCtx, f: RoleInput): Promise<number> {
  if (await ctx.env.DB.prepare("SELECT 1 FROM admin_roles WHERE name = ?").bind(f.name).first()) throw new ServiceError(400, "A role with that name already exists.");
  const row = await ctx.env.DB.prepare("INSERT INTO admin_roles (name, description, permissions, created_at) VALUES (?, ?, ?, ?) RETURNING id")
    .bind(f.name, f.description, JSON.stringify(f.permissions), new Date().toISOString())
    .first<{ id: number }>();
  await saveRoleGroups(ctx, row!.id, f.groupIds);
  await audit(ctx, "role.created", f.name, { permissions: f.permissions, groups: f.groupIds.length });
  return row!.id;
}

/** Super Admin is immutable; a built-in role keeps its name; a default role (everyone) has no groups. */
export async function updateRole(ctx: ServiceCtx, id: number, f: RoleInput): Promise<void> {
  const role = await ctx.env.DB.prepare("SELECT * FROM admin_roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!role) throw new ServiceError(404, "Not found");
  if (role.name === SUPER_ROLE) throw new ServiceError(400, "Super Admin cannot be changed.");
  const name = role.builtin ? role.name : f.name;
  if (await ctx.env.DB.prepare("SELECT 1 FROM admin_roles WHERE name = ? AND id != ?").bind(name, id).first()) throw new ServiceError(400, "A role with that name already exists.");
  await ctx.env.DB.prepare("UPDATE admin_roles SET name = ?, description = ?, permissions = ? WHERE id = ?").bind(name, f.description, JSON.stringify(f.permissions), id).run();
  if (!role.is_default) await saveRoleGroups(ctx, id, f.groupIds);
  await audit(ctx, "role.updated", name, { permissions: f.permissions, groups: f.groupIds.length });
}

export async function deleteRole(ctx: ServiceCtx, id: number): Promise<void> {
  const role = await ctx.env.DB.prepare("SELECT * FROM admin_roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!role) throw new ServiceError(404, "Not found");
  if (role.builtin) throw new ServiceError(400, "Built-in roles cannot be deleted; edit their permissions or groups instead.");
  await ctx.env.DB.batch([ctx.env.DB.prepare("DELETE FROM admin_role_groups WHERE role_id = ?").bind(id), ctx.env.DB.prepare("DELETE FROM admin_roles WHERE id = ?").bind(id)]);
  await audit(ctx, "role.deleted", role.name);
}

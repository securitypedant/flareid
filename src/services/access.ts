import { adminMfaRelaxedDetail, adminsWithoutMfaPolicy, anyAdminUnderMfaPolicy } from "../lib/admin-mfa.js";
import { ADMIN_FACTORS, FACTOR_KEYS, isFactorUsable } from "../lib/auth-policy.js";
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
  /** Sign-in needs a verified WARP device certificate (request.cf.tlsClientAuth). */
  deviceCert: boolean;
  /** Max tolerated Cloudflare ZT risk level ('' = no check). */
  maxRisk: string;
}

const RISK_CAPS = new Set(["", "low", "medium"]);

/** Normalises raw input the same way for a form and a JSON body. */
export function normalizePolicy(raw: { name?: unknown; description?: unknown; requirement?: unknown; priority?: unknown; groupIds?: unknown[]; makeDefault?: unknown; deviceCert?: unknown; maxRisk?: unknown }): PolicyInput {
  const name = String(raw.name ?? "").trim().slice(0, 80);
  if (!name) throw new ServiceError(400, "A policy name is required.");
  return {
    name,
    description: String(raw.description ?? "").trim().slice(0, 200),
    requirement: String(raw.requirement) === "password" ? "password" : "mfa",
    priority: Math.min(1000, Math.max(1, Math.floor(Number(raw.priority)) || 100)),
    groupIds: (raw.groupIds ?? []).map(Number).filter(Boolean),
    makeDefault: Boolean(raw.makeDefault),
    deviceCert: Boolean(raw.deviceCert),
    maxRisk: RISK_CAPS.has(String(raw.maxRisk ?? "")) ? String(raw.maxRisk) : "",
  };
}

async function savePolicyGroups(ctx: ServiceCtx, policyId: number, groupIds: number[]): Promise<void> {
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("DELETE FROM auth_policy_groups WHERE policy_id = ?").bind(policyId),
    ctx.env.DB.prepare("INSERT OR IGNORE INTO auth_policy_groups (policy_id, group_id) SELECT ?, g.id FROM groups g WHERE g.id IN (SELECT value FROM json_each(?))").bind(policyId, JSON.stringify(groupIds)),
  ]);
}


/**
 * The same invariant saveFactor enforces in the other direction: a policy may
 * not require a second factor while none is usable - and, while the write
 * would put an administrator under it, while none of the factors they may use
 * is usable. Caller evaluates coverage against the post-write state and reverts
 * on a throw.
 */
async function assertFactorsExistForMfa(ctx: ServiceCtx): Promise<void> {
  if (!(await Promise.all(FACTOR_KEYS.map((k) => isFactorUsable(ctx.env, k)))).some(Boolean)) {
    throw new ServiceError(400, "At least one second factor must be on before a policy can require one.");
  }
  if (!(await Promise.all(ADMIN_FACTORS.map((k) => isFactorUsable(ctx.env, k)))).some(Boolean) && (await anyAdminUnderMfaPolicy(ctx.env))) {
    throw new ServiceError(400, "This policy would make administrators use a second factor, but none they may use is on: keep the authenticator app, passkeys or email codes on.");
  }
}

/**
 * Policy changes can leave administrators on a password alone (an admin group
 * taken out of "Password and a second factor", a password policy made the
 * default...): allowed - the instance's choice - but audited as
 * `admin_mfa_relaxed`, and the Policies page warns while it holds.
 */
export async function createPolicy(ctx: ServiceCtx, f: PolicyInput): Promise<number> {
  const before = await adminsWithoutMfaPolicy(ctx.env);
  if (await ctx.env.DB.prepare("SELECT 1 FROM auth_policies WHERE name = ?").bind(f.name).first()) throw new ServiceError(400, "A policy with that name already exists.");
  const row = await ctx.env.DB.prepare("INSERT INTO auth_policies (name, description, requirement, priority, is_default, device_cert, max_risk, created_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?) RETURNING id")
    .bind(f.name, f.description, f.requirement, f.priority, f.deviceCert ? 1 : 0, f.maxRisk, new Date().toISOString())
    .first<{ id: number }>();
  await savePolicyGroups(ctx, row!.id, f.groupIds);
  try {
    if (f.requirement === "mfa") await assertFactorsExistForMfa(ctx);
  } catch (e) {
    await ctx.env.DB.batch([ctx.env.DB.prepare("DELETE FROM auth_policy_groups WHERE policy_id = ?").bind(row!.id), ctx.env.DB.prepare("DELETE FROM auth_policies WHERE id = ?").bind(row!.id)]);
    throw e;
  }
  await audit(ctx, "auth_policy.created", f.name, { requirement: f.requirement, groups: f.groupIds.length, ...(await adminMfaRelaxedDetail(ctx.env, before)) });
  return row!.id;
}

export async function updatePolicy(ctx: ServiceCtx, id: number, f: PolicyInput): Promise<void> {
  const current = await ctx.env.DB.prepare("SELECT * FROM auth_policies WHERE id = ?").bind(id).first<{ is_default: number; name: string; description: string; requirement: string; priority: number; device_cert: number; max_risk: string }>();
  if (!current) throw new ServiceError(404, "Not found");
  const before = await adminsWithoutMfaPolicy(ctx.env);
  if (await ctx.env.DB.prepare("SELECT 1 FROM auth_policies WHERE name = ? AND id != ?").bind(f.name, id).first()) throw new ServiceError(400, "A policy with that name already exists.");
  // Captured so a refused write leaves nothing behind.
  const beforeGroups = (await ctx.env.DB.prepare("SELECT group_id FROM auth_policy_groups WHERE policy_id = ?").bind(id).all<{ group_id: number }>()).results.map((g) => g.group_id);
  const beforeDefault = (await ctx.env.DB.prepare("SELECT id FROM auth_policies WHERE is_default = 1").first<{ id: number }>())?.id ?? 0;
  await ctx.env.DB.prepare("UPDATE auth_policies SET name = ?, description = ?, requirement = ?, priority = ?, device_cert = ?, max_risk = ? WHERE id = ?").bind(f.name, f.description, f.requirement, f.priority, f.deviceCert ? 1 : 0, f.maxRisk, id).run();
  await savePolicyGroups(ctx, id, f.groupIds);
  if (!current.is_default && f.makeDefault) {
    await ctx.env.DB.prepare("UPDATE auth_policies SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END").bind(id).run();
  }
  try {
    if (f.requirement === "mfa") await assertFactorsExistForMfa(ctx);
  } catch (e) {
    await ctx.env.DB.batch([
      ctx.env.DB.prepare("UPDATE auth_policies SET name = ?, description = ?, requirement = ?, priority = ?, is_default = ?, device_cert = ?, max_risk = ? WHERE id = ?").bind(current.name, current.description, current.requirement, current.priority, current.is_default, current.device_cert, current.max_risk, id),
      ctx.env.DB.prepare("DELETE FROM auth_policy_groups WHERE policy_id = ?").bind(id),
      ctx.env.DB.prepare("INSERT OR IGNORE INTO auth_policy_groups (policy_id, group_id) SELECT ?, g.id FROM groups g WHERE g.id IN (SELECT value FROM json_each(?))").bind(id, JSON.stringify(beforeGroups)),
      ctx.env.DB.prepare("UPDATE auth_policies SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END").bind(beforeDefault),
    ]);
    throw e;
  }
  await audit(ctx, "auth_policy.updated", f.name, { requirement: f.requirement, default: Boolean(current.is_default || f.makeDefault), ...(await adminMfaRelaxedDetail(ctx.env, before)) });
}

export async function deletePolicy(ctx: ServiceCtx, id: number): Promise<void> {
  const p = await ctx.env.DB.prepare("SELECT name, is_default FROM auth_policies WHERE id = ?").bind(id).first<{ name: string; is_default: number }>();
  if (!p) throw new ServiceError(404, "Not found");
  if (p.is_default) throw new ServiceError(400, "The default policy cannot be deleted; make another policy the default first.");
  const before = await adminsWithoutMfaPolicy(ctx.env);
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("DELETE FROM auth_policy_groups WHERE policy_id = ?").bind(id),
    // Apps bound to it fall back to each sign-in's own policy.
    ctx.env.DB.prepare("UPDATE oauth_clients SET policy_id = NULL WHERE policy_id = ?").bind(id),
    ctx.env.DB.prepare("UPDATE saml_service_providers SET policy_id = NULL WHERE policy_id = ?").bind(id),
    ctx.env.DB.prepare("DELETE FROM auth_policies WHERE id = ?").bind(id),
  ]);
  const relaxed = await adminMfaRelaxedDetail(ctx.env, before);
  await audit(ctx, "auth_policy.deleted", p.name, relaxed.admin_mfa_relaxed ? relaxed : undefined);
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
  const before = await adminsWithoutMfaPolicy(ctx.env);
  if (await ctx.env.DB.prepare("SELECT 1 FROM admin_roles WHERE name = ?").bind(f.name).first()) throw new ServiceError(400, "A role with that name already exists.");
  const row = await ctx.env.DB.prepare("INSERT INTO admin_roles (name, description, permissions, created_at) VALUES (?, ?, ?, ?) RETURNING id")
    .bind(f.name, f.description, JSON.stringify(f.permissions), new Date().toISOString())
    .first<{ id: number }>();
  await saveRoleGroups(ctx, row!.id, f.groupIds);
  await audit(ctx, "role.created", f.name, { permissions: f.permissions, groups: f.groupIds.length, ...(await adminMfaRelaxedDetail(ctx.env, before)) });
  return row!.id;
}

/** Super Admin is immutable; a built-in role keeps its name; a default role (everyone) has no groups. */
export async function updateRole(ctx: ServiceCtx, id: number, f: RoleInput): Promise<void> {
  const role = await ctx.env.DB.prepare("SELECT * FROM admin_roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!role) throw new ServiceError(404, "Not found");
  if (role.name === SUPER_ROLE) throw new ServiceError(400, "Super Admin cannot be changed.");
  const before = await adminsWithoutMfaPolicy(ctx.env);
  const name = role.builtin ? role.name : f.name;
  if (await ctx.env.DB.prepare("SELECT 1 FROM admin_roles WHERE name = ? AND id != ?").bind(name, id).first()) throw new ServiceError(400, "A role with that name already exists.");
  await ctx.env.DB.prepare("UPDATE admin_roles SET name = ?, description = ?, permissions = ? WHERE id = ?").bind(name, f.description, JSON.stringify(f.permissions), id).run();
  if (!role.is_default) await saveRoleGroups(ctx, id, f.groupIds);
  await audit(ctx, "role.updated", name, { permissions: f.permissions, groups: f.groupIds.length, ...(await adminMfaRelaxedDetail(ctx.env, before)) });
}

export async function deleteRole(ctx: ServiceCtx, id: number): Promise<void> {
  const role = await ctx.env.DB.prepare("SELECT * FROM admin_roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!role) throw new ServiceError(404, "Not found");
  if (role.builtin) throw new ServiceError(400, "Built-in roles cannot be deleted; edit their permissions or groups instead.");
  await ctx.env.DB.batch([ctx.env.DB.prepare("DELETE FROM admin_role_groups WHERE role_id = ?").bind(id), ctx.env.DB.prepare("DELETE FROM admin_roles WHERE id = ?").bind(id)]);
  await audit(ctx, "role.deleted", role.name);
}

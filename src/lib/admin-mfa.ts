import type { Env } from "../env.js";
import { rolePermissions } from "./admin-roles.js";
import { resolveManyGroupMemberUserIds } from "./groups.js";
import type { GroupRow } from "./types.js";

/**
 * Whether the authentication policies make administrators use a second
 * factor. Secure by default - a fresh install puts Super Admins in "Password
 * and a second factor" and makes it the default - but an instance may relax it
 * (setup's "Require a second factor for administrators" box, or Security >
 * Policies). Administrators follow their policy like everyone else; this is
 * what the console warns about and what keeps an administrator's last strong
 * factor switched on while a policy still needs one.
 */

/** A permission beyond self-service: the same test as accessFor's isAdmin. */
const isAdminPermission = (p: string) => p === "*" || (p.includes(":") && !p.startsWith("account:"));

export interface AdminPolicy {
  userId: number;
  /** The policy that applies to them (policyForUser), or null when there is none. */
  policyId: number | null;
  requiresMfa: boolean;
}

/**
 * Every administrator (anyone holding a role beyond self-service), with the
 * policy that applies to them - the same choice policyForUser makes, for all
 * of them in a few queries rather than per person.
 */
export async function adminPolicies(env: Env): Promise<AdminPolicy[]> {
  const [roles, roleGroups, policies, policyGroups] = await env.DB.batch([
    env.DB.prepare("SELECT id, is_default, permissions FROM admin_roles"),
    env.DB.prepare("SELECT role_id, group_id FROM admin_role_groups"),
    env.DB.prepare("SELECT id, requirement, is_default FROM auth_policies ORDER BY priority, id"),
    env.DB.prepare("SELECT policy_id, group_id FROM auth_policy_groups"),
  ]);
  const roleRows = roles!.results as { id: number; is_default: number; permissions: string }[];
  const adminRoleIds = new Set(roleRows.filter((r) => rolePermissions(r).some(isAdminPermission)).map((r) => r.id));
  const policyRows = policies!.results as { id: number; requirement: string; is_default: number }[];
  const policyLinks = policyGroups!.results as { policy_id: number; group_id: number }[];

  // A default role reaches everyone: if it grants admin permissions, everyone is an administrator.
  const everyone = roleRows.some((r) => r.is_default && adminRoleIds.has(r.id));
  const adminGroupIds = new Set((roleGroups!.results as { role_id: number; group_id: number }[]).filter((l) => adminRoleIds.has(l.role_id)).map((l) => l.group_id));
  const groupIds = [...new Set([...adminGroupIds, ...policyLinks.map((l) => l.group_id)])];
  const groups = groupIds.length ? (await env.DB.prepare("SELECT * FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(groupIds)).all<GroupRow>()).results : [];
  const members = await resolveManyGroupMemberUserIds(env, groups);

  const adminIds = everyone
    ? (await env.DB.prepare("SELECT id FROM users").all<{ id: number }>()).results.map((u) => u.id)
    : [...new Set([...adminGroupIds].flatMap((g) => members.get(g) ?? []))];
  const memberSets = new Map([...members].map(([g, ids]) => [g, new Set(ids)]));
  const fallback = policyRows.find((p) => p.is_default) ?? null;
  return adminIds.map((userId) => {
    // Lowest priority number first (then id), as policyForUser orders them.
    const policy = policyRows.find((p) => policyLinks.some((l) => l.policy_id === p.id && memberSets.get(l.group_id)?.has(userId))) ?? fallback;
    return { userId, policyId: policy?.id ?? null, requiresMfa: policy?.requirement === "mfa" };
  });
}

/** Administrators whose policy lets them sign in with a password alone. */
export async function adminsWithoutMfaPolicy(env: Env): Promise<number[]> {
  return (await adminPolicies(env)).filter((a) => !a.requiresMfa).map((a) => a.userId);
}

/** Whether a policy that requires a second factor applies to at least one administrator. */
export async function anyAdminUnderMfaPolicy(env: Env): Promise<boolean> {
  return (await adminPolicies(env)).some((a) => a.requiresMfa);
}

/**
 * Audit details for a policy change: which administrators it newly left on a
 * password alone. `before` is adminsWithoutMfaPolicy() taken before the change.
 */
export async function adminMfaRelaxedDetail(env: Env, before: number[]): Promise<{ admin_mfa_relaxed?: true; admins_without_mfa?: number }> {
  const after = await adminsWithoutMfaPolicy(env);
  const was = new Set(before);
  return after.some((id) => !was.has(id)) ? { admin_mfa_relaxed: true, admins_without_mfa: after.length } : {};
}

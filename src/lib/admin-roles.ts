import type { Env } from "../env.js";
import { getUserGroupNames } from "./db.js";
import { parseRule, userMatchesRule } from "./groups.js";
import { expand, grants, type Area, type Permission } from "./permissions.js";
import type { UserRow } from "./types.js";

/**
 * Roles (migration 0023): named permission sets granted to groups, or to
 * everyone for a default role ("User"). A person's access is the union of the
 * default roles and the roles of every group they are in, dynamic ones
 * included. See permissions.ts for the model, shared with API keys.
 */

export interface RoleRow {
  id: number;
  name: string;
  description: string;
  builtin: number;
  is_default: number;
  permissions: string;
  created_at: string;
}

export interface Access {
  /** Every permission held, expanded ("*" for Super Admin). */
  perms: Set<Permission>;
  /** Names of the roles that granted them. */
  roles: string[];
  isSuper: boolean;
  /** Holds any permission beyond the self-service ones: reaches the admin console. */
  isAdmin: boolean;
}

export const SUPER_ROLE = "Super Admin";

export function rolePermissions(role: Pick<RoleRow, "permissions">): Permission[] {
  try {
    const v = JSON.parse(role.permissions) as unknown;
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}

export async function accessFor(env: Env, userId: number): Promise<Access> {
  const names = await getUserGroupNames(env, userId);
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT r.* FROM admin_roles r
      LEFT JOIN admin_role_groups rg ON rg.role_id = r.id
      LEFT JOIN groups g ON g.id = rg.group_id
      WHERE r.is_default = 1 OR g.name IN (SELECT value FROM json_each(?))`
  )
    .bind(JSON.stringify(names))
    .all<RoleRow>();
  const perms = expand(results.flatMap(rolePermissions));
  const isSuper = perms.has("*");
  const isAdmin = isSuper || [...perms].some((p) => p.includes(":") && !p.startsWith("account:"));
  return { perms, roles: results.map((r) => r.name), isSuper, isAdmin };
}

/** Whether a user's roles let them sign in at all (the default "User" role grants it). */
export async function canSignIn(env: Env, userId: number): Promise<boolean> {
  return grants((await accessFor(env, userId)).perms, "signin");
}

/** Console areas by path prefix; the request method picks read (GET) or write (POST). */
const PATH_AREAS: [string, Area][] = [
  ["/admin/integrations/api-keys", "api_keys"],
  ["/admin/api-keys", "api_keys"],
  ["/admin/integrations/oidc", "oidc"],
  ["/admin/clients", "oidc"],
  ["/admin/integrations/saml", "saml"],
  ["/admin/saml", "saml"],
  ["/admin/integrations/scim", "scim"],
  ["/admin/scim", "scim"],
  ["/admin/integrations/ldap", "ldap"],
  ["/admin/ldap", "ldap"],
  ["/admin/integrations/federation", "federation"],
  ["/admin/integrations/email", "email"],
  ["/admin/email", "email"],
  ["/admin/integrations/cf-one", "cfone"],
  ["/admin/integrations/signals", "signals"],
  ["/admin/users/import", "import"],
  ["/admin/groups/import", "import"],
  ["/admin/users", "users"],
  ["/admin/access", "groups"],
  ["/admin/groups", "groups"],
  ["/admin/domains", "domains"],
  ["/admin/schemas", "schemas"],
  ["/admin/security/roles", "roles"],
  ["/admin/security/signing-keys", "signing_keys"],
  ["/admin/security", "security"],
  ["/admin/branding", "branding"],
  ["/admin/audit", "audit"],
  ["/admin/log", "audit"],
  ["/admin/performance", "performance"],
];

const under = (path: string, prefix: string) => path === prefix || path.startsWith(`${prefix}/`);

/** The permission a console request needs, or null for pages any admin may open. */
export function requiredPermission(method: string, path: string): Permission | null | "super" {
  if (under(path, "/admin/setup")) return "super";
  // Rewriting every UPN moves Super Admins too, and recovery mail follows the
  // UPN: the API gates its equivalent on the "admin" scope; this is the same bar.
  if (under(path, "/admin/domains") && path.endsWith("/apply-to-all")) return "super";
  // The user lookup feeds pickers in several areas; reading users is enough.
  if (path === "/admin/users/lookup") return "users:read";
  // Open to every admin role: the console root, the integrations index and the
  // step-up ceremony itself.
  if (path === "/admin" || path === "/admin/integrations" || under(path, "/admin/reauth")) return null;
  const write = method !== "GET" && method !== "HEAD";
  // Registering or changing an upstream IdP hands its claims authority over
  // every account here (adoption by address match, JIT provisioning) - the
  // same blast radius as minting an admin key, so writes are Super-Admin-only.
  // Reads stay delegated (federation:read via /admin/integrations/federation).
  if (under(path, "/admin/federation")) return write ? "super" : "federation:read";
  // Trusting a SET transmitter hands its verified claims authority over every
  // account (session revocation, risk flags) - the same trust-anchor decision
  // as an upstream IdP, so transmitter writes are Super-Admin-only too.
  if (under(path, "/admin/integrations/signals/transmitters")) return write ? "super" : "signals:read";
  // Choosing where the whole directory is provisioned - and pushing it there -
  // exports every account's attributes, the outbound mirror of the federation
  // rule: SCIM target and full-sync writes are Super-Admin-only. Reads stay
  // delegated; so do the inbound-server settings (mappings, correlation).
  if (under(path, "/admin/scim/targets") || path === "/admin/scim/sync" || path === "/admin/scim/test") return write ? "super" : "scim:read";
  // Flagging a user onto the risk watchlist is cfone:write on the API and on
  // the CF One page; the /admin/users mount point must not weaken it to
  // users:write.
  if (/^\/admin\/users\/[^/]+\/(?:un)?watch$/.test(path)) return write ? "cfone:write" : "cfone:read";
  const hit = PATH_AREAS.find(([prefix]) => under(path, prefix));
  // Anything unmapped fails closed to Super Admin - a new console page is
  // denied until it deliberately joins PATH_AREAS, never accidentally open.
  if (!hit) return "super";
  const area = hit[1];
  if (area === "import") return write ? "import:write" : "users:read";
  return `${area}:${write ? "write" : "read"}`;
}

export function canAccess(access: Access, method: string, path: string): boolean {
  if (!access.isAdmin) return false;
  if (access.isSuper) return true;
  const need = requiredPermission(method, path);
  if (need === "super") return false;
  if (need === null) return method === "GET" || method === "HEAD" || path === "/admin/reauth" || path.startsWith("/admin/reauth/");
  return grants(access.perms, need);
}

/** Sidebar sections a person can open. */
export function visibleSections(access: Access): Set<string> {
  const can = (a: Area) => grants(access.perms, `${a}:read`) || (a === "import" && grants(access.perms, "import:write"));
  const s = new Set<string>(["overview"]);
  if (can("users")) s.add("users");
  if (can("groups")) s.add("groups");
  if (can("domains")) s.add("domains");
  if (can("schemas")) s.add("schemas");
  if (can("oidc") || can("saml") || can("scim") || can("ldap") || can("email") || can("cfone") || can("signals") || can("api_keys")) s.add("integrations");
  if (can("branding")) s.add("branding");
  if (can("security") || can("roles") || can("signing_keys")) s.add("security");
  if (can("audit")) s.add("audit");
  return s;
}

/** Groups that grant any admin role (beyond self-service): changing them needs roles:write. */
export async function adminRoleGroupIds(env: Env): Promise<Set<number>> {
  const { results } = await env.DB.prepare("SELECT rg.group_id, r.permissions FROM admin_role_groups rg JOIN admin_roles r ON r.id = rg.role_id").all<{ group_id: number; permissions: string }>();
  return new Set(results.filter((r) => rolePermissions(r).some((p) => p !== "signin" && !p.startsWith("account:"))).map((r) => r.group_id));
}

/**
 * Whether a permission set can change anything beyond the holder's own
 * account: "*" or any "<area>:write". The self-service permissions ("signin",
 * "account:*") don't count. Used where a feature may grant a read-only admin
 * role but never a write-capable one (JIT group assignment on upstream IdPs).
 */
export function grantsWritePermission(perms: Iterable<string>): boolean {
  return [...expand(perms)].some((p) => (p === "*" || p.endsWith(":write")) && !p.startsWith("account:"));
}

/**
 * The admin roles each group grants and whether any of them can write, keyed
 * by group - for pickers that show the grant and must refuse write-capable
 * groups. Roles with only signin/self-service permissions don't count, the
 * same rule groupRolesMap applies.
 */
export async function groupRoleWriteMap(env: Env): Promise<Map<number, { roles: string[]; writable: boolean }>> {
  const { results } = await env.DB
    .prepare("SELECT rg.group_id, r.name, r.permissions FROM admin_role_groups rg JOIN admin_roles r ON r.id = rg.role_id ORDER BY r.name")
    .all<{ group_id: number; name: string; permissions: string }>();
  const map = new Map<number, { roles: string[]; writable: boolean }>();
  for (const r of results) {
    const perms = rolePermissions(r);
    if (!perms.some((p) => p !== "signin" && !p.startsWith("account:"))) continue;
    const e = map.get(r.group_id) ?? { roles: [], writable: false };
    e.roles.push(r.name);
    e.writable ||= grantsWritePermission(perms);
    map.set(r.group_id, e);
  }
  return map;
}

/** The admin roles each group grants, keyed by group - roles with only signin/self-service permissions don't count. */
export async function groupRolesMap(env: Env): Promise<Map<number, { name: string; description: string }[]>> {
  const { results } = await env.DB
    .prepare("SELECT rg.group_id, r.name, r.description, r.permissions FROM admin_role_groups rg JOIN admin_roles r ON r.id = rg.role_id ORDER BY r.name")
    .all<{ group_id: number; name: string; description: string; permissions: string }>();
  const map = new Map<number, { name: string; description: string }[]>();
  for (const r of results) {
    if (!rolePermissions(r).some((p) => p !== "signin" && !p.startsWith("account:"))) continue;
    const list = map.get(r.group_id) ?? [];
    list.push({ name: r.name, description: r.description });
    map.set(r.group_id, list);
  }
  return map;
}

/** Names of the groups that grant an admin role - FlareID's own groups, kept by wipes and replace-imports. */
export async function adminRoleGroupNames(env: Env): Promise<string[]> {
  const ids = [...(await adminRoleGroupIds(env))];
  if (!ids.length) return ["Super Admins"];
  const { results } = await env.DB.prepare("SELECT name FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(ids)).all<{ name: string }>();
  return [...new Set(["Super Admins", ...results.map((r) => r.name)])];
}

/**
 * The name of an admin-role group a user-attribute write would newly put the
 * user into, or null. A dynamic group's rule can turn an innocent-looking
 * attribute write (department = "OnCall") into an admin grant, so every writer
 * below admin authority checks the post-write row against the rules of every
 * dynamic group linked to a role. `before` is null on the create path: any
 * match is a grant a provisioning peer may not make.
 */
export async function grantsAdminRoleGroup(env: Env, before: UserRow | null, after: UserRow): Promise<string | null> {
  const roleGroups = await adminRoleGroupIds(env);
  if (!roleGroups.size) return null;
  const { results } = await env.DB.prepare("SELECT id, name, rule FROM groups WHERE rule != ''").all<{ id: number; name: string; rule: string }>();
  for (const g of results) {
    if (!roleGroups.has(g.id)) continue;
    const rule = parseRule(g.rule);
    if (!rule) continue;
    if (before === null ? userMatchesRule(after, rule) : !userMatchesRule(before, rule) && userMatchesRule(after, rule)) return g.name;
  }
  return null;
}

export async function listRoles(env: Env): Promise<(RoleRow & { groups: { id: number; name: string }[] })[]> {
  const { results } = await env.DB.prepare("SELECT * FROM admin_roles ORDER BY is_default DESC, builtin DESC, name").all<RoleRow>();
  const { results: links } = await env.DB.prepare("SELECT rg.role_id, g.id, g.name FROM admin_role_groups rg JOIN groups g ON g.id = rg.group_id ORDER BY g.name").all<{ role_id: number; id: number; name: string }>();
  return results.map((r) => ({ ...r, groups: links.filter((l) => l.role_id === r.id).map((l) => ({ id: l.id, name: l.name })) }));
}

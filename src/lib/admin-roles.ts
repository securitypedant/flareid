import type { Env } from "../env.js";
import { getUserGroupNames } from "./db.js";
import { expand, grants, type Area, type Permission } from "./permissions.js";

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
  ["/admin/integrations/email", "email"],
  ["/admin/email", "email"],
  ["/admin/users/import", "import"],
  ["/admin/groups/import", "import"],
  ["/admin/users", "users"],
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
  // The user lookup feeds pickers in several areas; reading users is enough.
  if (path === "/admin/users/lookup") return "users:read";
  const write = method !== "GET" && method !== "HEAD";
  const hit = PATH_AREAS.find(([prefix]) => under(path, prefix));
  if (!hit) return null;
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
  if (can("oidc") || can("saml") || can("scim") || can("email") || can("api_keys")) s.add("integrations");
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

/** Names of the groups that grant an admin role - FlareID's own groups, kept by wipes and replace-imports. */
export async function adminRoleGroupNames(env: Env): Promise<string[]> {
  const ids = [...(await adminRoleGroupIds(env))];
  if (!ids.length) return ["Super Admins"];
  const { results } = await env.DB.prepare("SELECT name FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(ids)).all<{ name: string }>();
  return [...new Set(["Super Admins", ...results.map((r) => r.name)])];
}

export async function listRoles(env: Env): Promise<(RoleRow & { groups: { id: number; name: string }[] })[]> {
  const { results } = await env.DB.prepare("SELECT * FROM admin_roles ORDER BY is_default DESC, builtin DESC, name").all<RoleRow>();
  const { results: links } = await env.DB.prepare("SELECT rg.role_id, g.id, g.name FROM admin_role_groups rg JOIN groups g ON g.id = rg.group_id ORDER BY g.name").all<{ role_id: number; id: number; name: string }>();
  return results.map((r) => ({ ...r, groups: links.filter((l) => l.role_id === r.id).map((l) => ({ id: l.id, name: l.name })) }));
}

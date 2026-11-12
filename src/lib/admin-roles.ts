import type { Env } from "../env.js";
import { getUserGroupNames } from "./db.js";

/**
 * Admin roles, each held through membership of a built-in group (migration
 * 0019). A role grants a set of console areas; Super Admins have all of them.
 */
export type AdminRole = "super" | "directory" | "applications" | "auditor";

export const ROLE_GROUPS: Record<string, AdminRole> = {
  "Super Admins": "super",
  "Directory Admins": "directory",
  "Application Admins": "applications",
  Auditors: "auditor",
};
export const ROLE_GROUP_NAMES = Object.keys(ROLE_GROUPS);

export async function adminRolesFor(env: Env, userId: number): Promise<Set<AdminRole>> {
  const names = await getUserGroupNames(env, userId);
  return new Set(names.map((n) => ROLE_GROUPS[n]).filter((r): r is AdminRole => Boolean(r)));
}

/** Console areas each role can use (path prefixes under /admin). */
const AREAS: Record<Exclude<AdminRole, "super" | "auditor">, string[]> = {
  directory: ["/admin/users", "/admin/groups", "/admin/domains", "/admin/schemas"],
  applications: ["/admin/integrations", "/admin/clients", "/admin/saml", "/admin/scim", "/admin/email"],
};
/** Reachable by every admin role. */
const SHARED = ["/admin/performance", "/admin/audit", "/admin/log"];
/** Super Admins only, even for reading. */
const SUPER_ONLY = ["/admin/security", "/admin/branding", "/admin/setup", "/admin/api-keys", "/admin/integrations/api-keys"];

const under = (path: string, prefix: string) => path === prefix || path.startsWith(`${prefix}/`);

/** Whether these roles may make this request. Auditors read; nobody but Super Admins writes outside their areas. */
export function canAccess(roles: Set<AdminRole>, method: string, path: string): boolean {
  if (roles.has("super")) return true;
  if (roles.size === 0) return false;
  if (SUPER_ONLY.some((p) => under(path, p))) return false;
  const read = method === "GET" || method === "HEAD";
  if (path === "/admin" || SHARED.some((p) => under(path, p))) return read;
  for (const role of ["directory", "applications"] as const) {
    if (roles.has(role) && AREAS[role].some((p) => under(path, p))) return true;
  }
  return read && roles.has("auditor");
}

/** Top-level console sections a set of roles can see, for the sidebar. */
export function visibleSections(roles: Set<AdminRole>): Set<string> {
  const all = ["overview", "users", "groups", "integrations", "domains", "branding", "security", "schemas", "audit"];
  if (roles.has("super")) return new Set(all);
  const s = new Set(["overview", "audit"]);
  if (roles.has("directory") || roles.has("auditor")) ["users", "groups", "domains", "schemas"].forEach((x) => s.add(x));
  if (roles.has("applications") || roles.has("auditor")) s.add("integrations");
  return s;
}

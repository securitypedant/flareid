/**
 * The one permissions model, shared by admin roles, API keys and ordinary
 * users. A permission is "<area>:read" or "<area>:write" (write implies read),
 * "signin" and "account:*" are the self-service ones every user normally
 * holds, and "*" is everything (Super Admin, admin-scoped API keys).
 */

export const AREAS = [
  { key: "users", label: "Users", group: "Directory" },
  { key: "groups", label: "Groups", group: "Directory" },
  { key: "domains", label: "Domains", group: "Directory" },
  { key: "schemas", label: "Schemas", group: "Directory" },
  { key: "import", label: "Import and reset", group: "Directory", writeOnly: true },
  { key: "oidc", label: "OIDC clients", group: "Applications" },
  { key: "saml", label: "SAML apps", group: "Applications" },
  { key: "scim", label: "SCIM provisioning", group: "Applications" },
  { key: "email", label: "Email", group: "Applications" },
  { key: "api_keys", label: "API keys", group: "Platform" },
  { key: "security", label: "Security settings and policies", group: "Platform" },
  { key: "branding", label: "Branding", group: "Platform" },
  { key: "signing_keys", label: "Signing keys", group: "Platform" },
  { key: "roles", label: "Roles", group: "Platform" },
  { key: "audit", label: "Log", group: "Monitoring", readOnly: true },
  { key: "performance", label: "Overview and performance", group: "Monitoring", readOnly: true },
] as const;
export type Area = (typeof AREAS)[number]["key"];

export const SELF_PERMISSIONS = [
  { key: "signin", label: "Sign in (to FlareID and to apps)" },
  { key: "account:read", label: "View their own account" },
  { key: "account:write", label: "Change their own password, factors and profile" },
] as const;

export type Permission = string;

const AREA_KEYS = new Set<string>(AREAS.map((a) => a.key));

export function isPermission(p: string): boolean {
  if (p === "*" || SELF_PERMISSIONS.some((s) => s.key === p)) return true;
  const [area, action] = p.split(":");
  return AREA_KEYS.has(area ?? "") && (action === "read" || action === "write");
}

/**
 * The API's original scopes, kept working: each is shorthand for permissions.
 * A key created with them keeps exactly the access it had.
 */
export const LEGACY_SCOPES: Record<string, Permission[]> = {
  "directory:read": ["users:read", "groups:read", "domains:read", "schemas:read", "oidc:read", "saml:read"],
  "directory:write": ["users:write", "groups:write", "domains:write", "import:write", "oidc:read", "saml:read", "schemas:read"],
  "clients:write": ["oidc:write", "saml:write"],
  "settings:write": ["security:write", "branding:write", "email:write", "scim:write", "schemas:write"],
  admin: ["*"],
};

/** Expands a held list (permissions and legacy scopes) into the set it grants. */
export function expand(held: Iterable<string>): Set<Permission> {
  const out = new Set<Permission>();
  for (const h of held) for (const p of LEGACY_SCOPES[h] ?? [h]) out.add(p);
  return out;
}

/** Whether a held set grants `required` ("x:read" is granted by "x:write"; "*" grants all). */
export function grants(held: Set<Permission>, required: Permission): boolean {
  if (held.has("*") || held.has(required)) return true;
  // A legacy scope required by an API route is met by the permissions it stands for.
  const legacy = LEGACY_SCOPES[required];
  if (legacy) return legacy.every((p) => grants(held, p));
  const [area, action] = required.split(":");
  return action === "read" && held.has(`${area}:write`);
}

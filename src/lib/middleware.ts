import { adminRolesFor, canAccess, type AdminRole } from "./admin-roles.js";
import { secondFactorGate } from "./auth-policy.js";
import type { Context, Next } from "hono";
import type { Env } from "../env.js";
import { getSession } from "./sessions.js";
import { getUserById, getUserGroupNames } from "./db.js";
import { isMfaRequired } from "./settings.js";
import type { UserRow } from "./types.js";

declare module "hono" {
  interface ContextVariableMap {
    user: UserRow;
    isSuperAdmin: boolean;
    /** Admin roles held through the built-in role groups (admin-roles.ts). */
    adminRoles: Set<AdminRole>;
    sessionId: string;
    /** Resolved once per request by the `resolveAppName` middleware - the admin-configurable display name, falling back to the APP_NAME env var. */
    appName: string;
  }
}

export const SUPER_ADMINS_GROUP = "Super Admins";

export async function isSuperAdmin(env: Env, userId: number): Promise<boolean> {
  const groups = await getUserGroupNames(env, userId);
  return groups.includes(SUPER_ADMINS_GROUP);
}

export async function requireSession(c: Context<{ Bindings: Env }>, next: Next) {
  const session = await getSession(c.req.raw, c.env);
  const user = session ? await getUserById(c.env, session.userId) : null;

  if (!user || user.status !== "active") {
    const next = encodeURIComponent(new URL(c.req.url).pathname);
    return c.redirect(`/login?next=${next}`, 302);
  }

  c.set("user", user);
  c.set("sessionId", session!.id);
  const roles = await adminRolesFor(c.env, user.id);
  c.set("adminRoles", roles);
  c.set("isSuperAdmin", roles.has("super"));

  // Safety net: even outside the forced-enrollment flow right after login
  // (see login.ts), nothing else should be usable without MFA once it's required.
  const path = new URL(c.req.url).pathname;
  const exempt = path.startsWith("/account/mfa") || path === "/logout";
  if (!exempt && !path.startsWith("/account/passkeys")) {
    const gate = await secondFactorGate(c.env, user, session!.amr);
    if (gate === "enrol") return c.redirect("/account/mfa/setup", 302);
    // The policy needs the second factor this session did not use: sign in again.
    if (gate === "login") return c.redirect(`/login?next=${encodeURIComponent(path)}`, 302);
  }

  await next();
}

/** Any admin role reaches the console; each request must be within the roles' areas (canAccess). */
export async function requireAdmin(c: Context<{ Bindings: Env }>, next: Next) {
  const roles = c.get("adminRoles");
  if (!roles || roles.size === 0) return c.text("Forbidden", 403);
  if (!canAccess(roles, c.req.method, c.req.path)) {
    return c.text(roles.has("auditor") && c.req.method !== "GET" ? "Forbidden: Auditors have read-only access." : "Forbidden: your admin role does not cover this part of the console.", 403);
  }
  await next();
}

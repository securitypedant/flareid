import { grants } from "./permissions.js";
import { accessFor, canAccess, type Access } from "./admin-roles.js";
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
    /** Permissions held through roles (admin-roles.ts, permissions.ts). */
    access: Access;
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
  const access = await accessFor(c.env, user.id);
  if (!grants(access.perms, "signin")) return c.redirect("/login?denied=1", 302);
  c.set("access", access);
  c.set("isSuperAdmin", access.isSuper);

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
  const access = c.get("access");
  if (!access?.isAdmin) return c.text("Forbidden", 403);
  if (!canAccess(access, c.req.method, c.req.path)) {
    return c.text(c.req.method === "GET" ? "Forbidden: your role does not include this part of the console." : "Forbidden: your role can view this but not change it.", 403);
  }
  await next();
}

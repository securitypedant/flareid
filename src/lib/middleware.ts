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
  c.set("isSuperAdmin", await isSuperAdmin(c.env, user.id));

  // Safety net: even outside the forced-enrollment flow right after login
  // (see login.ts), nothing else should be usable without MFA once it's required.
  const path = new URL(c.req.url).pathname;
  const exempt = path.startsWith("/account/mfa") || path === "/logout";
  if (!exempt && !user.mfa_enabled && (await isMfaRequired(c.env))) {
    return c.redirect("/account/mfa/setup", 302);
  }

  await next();
}

export async function requireAdmin(c: Context<{ Bindings: Env }>, next: Next) {
  if (!c.get("isSuperAdmin")) return c.text("Forbidden", 403);
  await next();
}

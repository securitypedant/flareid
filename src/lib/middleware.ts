import { errorPage, safeBackHref } from "./html.js";
import { grants } from "./permissions.js";
import { accessFor, canAccess, type Access } from "./admin-roles.js";
import { secondFactorGate } from "./auth-policy.js";
import type { Context, Next } from "hono";
import type { Env } from "../env.js";
import { clearSessionCookie, getSession, revokeSession } from "./sessions.js";
import { getUserById, getUserGroupNames } from "./db.js";
import { isMfaRequired } from "./settings.js";
import type { UserRow } from "./types.js";
import type { NotificationFeed } from "./html.js";

declare module "hono" {
  interface ContextVariableMap {
    user: UserRow;
    isSuperAdmin: boolean;
    /** Permissions held through roles (admin-roles.ts, permissions.ts). */
    access: Access;
    sessionId: string;
    /** Resolved once per request by the `resolveAppName` middleware - the admin-configurable display name, falling back to the APP_NAME env var. */
    appName: string;
    /** The brand's uploaded logo for the top bar (brands.ts): the default brand's, or on My account the person's; null for FlareID's icon. */
    logoUrl: string | null;
    /** Console timezone override (settings.ts): "" for each browser's own zone, else "UTC" or an IANA zone - carried on the top bar's data-tz for TS_SCRIPT. */
    consoleTz: string;
    /** The bell's feed for this page load (notifications.ts), set by the admin/account middleware. */
    notifications: NotificationFeed | null;
    /** Pending access-request count for the left-nav badge (admin pages). */
    accessPending: number;
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
  if (path !== "/logout") {
    const gate = await secondFactorGate(c.env, user, session!.amr);
    // "enrol": no factor exists yet, so the enrolment pages - and only those -
    // stay reachable; everything else parks at the setup page.
    if (gate === "enrol" && !path.startsWith("/account/mfa") && !path.startsWith("/account/passkeys")) {
      return c.redirect("/account/mfa/setup", 302);
    }
    // "login": a factor exists but this session did not present it. Nothing
    // the session can do substitutes for signing in again - enrolment would
    // upgrade its own amr and launder the missing proof - so it ends here.
    if (gate === "login") {
      await revokeSession(c.env, session!.id);
      const res = c.redirect(`/login?next=${encodeURIComponent(path)}`, 302);
      res.headers.append("Set-Cookie", clearSessionCookie());
      return res;
    }
  }

  await next();
}

/** Any admin role reaches the console; each request must be within the roles' areas (canAccess). */
export async function requireAdmin(c: Context<{ Bindings: Env }>, next: Next) {
  const access = c.get("access");
  const refuse = (message: string, back: string) => c.html(errorPage(c.get("appName"), 403, message, safeBackHref(c.req.raw, back), Boolean(access?.isAdmin), c.get("logoUrl")), 403);
  if (!access?.isAdmin) return refuse("The admin console is for administrators. Ask a Super Admin if you need access.", "/account");
  if (!canAccess(access, c.req.method, c.req.path)) {
    return refuse(c.req.method === "GET" ? "Your role doesn't include this part of the console." : "Your role can view this but not change it.", "/admin");
  }
  await next();
}

import type { Env } from "../env.js";
import { markConsumed } from "./one-shot.js";

/**
 * Step-up re-authentication. Sensitive admin actions need the user to have
 * proved their credentials within the last STEP_UP_WINDOW_MINUTES - at
 * sign-in, or again on /admin/reauth - not just to hold a session cookie,
 * which may have been left on an unlocked machine hours ago.
 */
export const STEP_UP_WINDOW_MINUTES = 10;

/**
 * Every POST under /admin is sensitive by default: console writes change
 * credentials, role membership, trust anchors or security policy, and naming
 * them one by one is how routes slip through (this list once covered 32 of 83
 * POST routes). The open list is only the re-authentication flow itself - it
 * is how a stale session becomes fresh, so gating it would deadlock.
 *
 * Classifying on the path prefix - never on the shape of an :id segment -
 * also keeps exotic spellings (`/admin/users/+2/reset-password`, `0x2`,
 * `2e0`, padded ids) inside the gate while the route's Number() coercion
 * still resolves them to a real id.
 */
const OPEN: RegExp[] = [/^\/admin\/reauth(\/|$)/];

export function isSensitive(method: string, path: string): boolean {
  return method === "POST" && /^\/admin(\/|$)/.test(path) && !OPEN.some((r) => r.test(path));
}

/**
 * Whether the session proved its credentials within the window: its sign-in,
 * or a later /admin/reauth.
 *
 * Security questions never stand in for that proof for a Super Admin: a
 * session whose second factor was security questions (amr "kba") only counts
 * once re-authenticated on /admin/reauth, which takes the password plus the
 * authenticator (when enrolled) or a passkey - never the questions. They are
 * the weakest factor, and Super Admin actions are the most sensitive.
 */
export async function isFreshlyAuthenticated(env: Env, sessionId: string, opts: { superAdmin?: boolean } = {}): Promise<boolean> {
  const row = await env.DB.prepare("SELECT created_at, stepped_up_at, amr FROM sessions WHERE id = ?")
    .bind(sessionId)
    .first<{ created_at: string; stepped_up_at: string | null; amr: string }>();
  if (!row) return false;
  const signInCounts = !(opts.superAdmin && sessionUsedSecurityQuestions(row.amr));
  const last = Math.max(signInCounts ? Date.parse(row.created_at) : 0, row.stepped_up_at ? Date.parse(row.stepped_up_at) : 0);
  return Date.now() - last < STEP_UP_WINDOW_MINUTES * 60 * 1000;
}

function sessionUsedSecurityQuestions(amr: string): boolean {
  try {
    return (JSON.parse(amr) as string[]).includes("kba");
  } catch {
    return false;
  }
}

export async function markSteppedUp(env: Env, sessionId: string): Promise<void> {
  await env.DB.prepare("UPDATE sessions SET stepped_up_at = ? WHERE id = ?").bind(new Date().toISOString(), sessionId).run();
}

/**
 * A sensitive POST interrupted for step-up, kept server-side so completing
 * the re-authentication replays it instead of dropping the admin back on an
 * emptied form. Bound to the session that submitted it, single-use, and gone
 * within the step-up window.
 */
export interface PendingAction {
  path: string;
  fields: [string, string][];
  /** The page the form was on, for the fallback when the stash has expired. */
  back: string;
}

const PENDING_PREFIX = "stepup-pending:";
const PENDING_MAX_BYTES = 64 * 1024;

/** Stashes a form POST for replay after step-up; null when it can't be replayed (a file upload, an oversized body, a KV failure). */
export async function stashPendingAction(env: Env, sessionId: string, req: Request, back: string): Promise<string | null> {
  try {
    const form = await req.formData();
    const fields: [string, string][] = [];
    let bytes = 0;
    for (const [name, value] of form.entries()) {
      if (typeof value !== "string") return null;
      bytes += name.length + value.length;
      if (bytes > PENDING_MAX_BYTES) return null;
      fields.push([name, value]);
    }
    const id = crypto.randomUUID();
    await env.SESSIONS_KV.put(PENDING_PREFIX + id, JSON.stringify({ sessionId, path: new URL(req.url).pathname, fields, back }), { expirationTtl: STEP_UP_WINDOW_MINUTES * 60 });
    return id;
  } catch {
    return null;
  }
}

/** Returns and consumes the stash - only for the session that submitted it. */
export async function takePendingAction(env: Env, sessionId: string, id: string): Promise<PendingAction | null> {
  let parsed: PendingAction & { sessionId?: string };
  try {
    parsed = JSON.parse((await env.SESSIONS_KV.get(PENDING_PREFIX + id)) ?? "") as PendingAction & { sessionId?: string };
  } catch {
    return null;
  }
  if (!parsed?.sessionId || parsed.sessionId !== sessionId || !parsed.path.startsWith("/admin")) return null;
  if (!(await markConsumed(env, PENDING_PREFIX + id))) return null;
  await env.SESSIONS_KV.delete(PENDING_PREFIX + id);
  return { path: parsed.path, fields: parsed.fields, back: parsed.back.startsWith("/admin") ? parsed.back : "/admin" };
}

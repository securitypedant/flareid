import type { Env } from "../env.js";

/**
 * Step-up re-authentication. Sensitive admin actions need the user to have
 * proved their credentials within the last STEP_UP_WINDOW_MINUTES - at
 * sign-in, or again on /admin/reauth - not just to hold a session cookie,
 * which may have been left on an unlocked machine hours ago.
 */
export const STEP_UP_WINDOW_MINUTES = 10;

const SENSITIVE: RegExp[] = [
  /^\/admin\/api-keys(\/|$)/, // minting and revoking API keys
  /^\/admin\/clients\/\d+\/(rotate-secret|delete)$/,
  /^\/admin\/saml\/\d+\/delete$/,
  /^\/admin\/users\/\d+\/(reset-password|reset-mfa|delete)$/,
  /^\/admin\/security\/signing-keys\/[^/]+\/rotate$/, // token signing key rotation (also under /admin/security below; explicit so it survives a narrower rule)
  /^\/admin\/security(\/|$)/, // policies, factors, password and session rules
  /^\/admin\/setup(\/|$)/,
  /^\/admin\/scim$/, // the SCIM endpoint and secret
];

export function isSensitive(method: string, path: string): boolean {
  return method === "POST" && SENSITIVE.some((r) => r.test(path));
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

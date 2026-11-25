import type { Env } from "../env.js";

/**
 * A person's own sign-in attempts, successful and failed, read from the audit
 * log (account -> Security). Web and federated sign-ins are logged against
 * the identifier typed, so failures typed as an alias are found by matching
 * every spelling the account answers to; LDAP binds are found by actor.
 */

const WEB_ACTIONS = ["login.success", "login.failed", "login.mfa_failed", "login.rate_limited", "login.mfa_rate_limited", "login.denied_risk", "login.denied_device_cert"];
const LDAP_ACTIONS = ["ldap.bind.success"];

export interface SignInEvent {
  at: string;
  ok: boolean;
  method: string;
  reason: string;
  ip: string | null;
  device: string;
}

const FAILURE_REASONS: Record<string, string> = {
  "login.failed": "Wrong password",
  "login.mfa_failed": "Second step failed",
  "login.rate_limited": "Too many attempts",
  "login.mfa_rate_limited": "Too many attempts",
  "login.denied_risk": "Blocked by risk policy",
  "login.denied_device_cert": "Device check failed",
};

const AMR_LABELS: Record<string, string> = {
  pwd: "Password",
  hwk: "Passkey",
  otp: "Email code",
  sms: "SMS code",
  kba: "Security questions",
  backup_code: "Backup code",
  mfa_remembered_device: "Remembered device",
};

function methodFor(action: string, details: Record<string, unknown>): string {
  if (action.startsWith("ldap.")) return "LDAP bind";
  const amr = Array.isArray(details.amr) ? (details.amr as string[]) : [];
  if (amr.includes("ext")) return typeof details.via === "string" ? `Via ${details.via}` : "External identity provider";
  const parts = amr.map((a) => AMR_LABELS[a]).filter((x): x is string => Boolean(x));
  // A bare "mfa" next to the password is the authenticator app (login.ts).
  if (amr.includes("mfa") && parts.length === 1 && parts[0] === "Password") parts.push("Authenticator app");
  if (parts.length) return parts.join(" + ");
  const method = typeof details.method === "string" ? details.method : "";
  return { passkey: "Passkey", email_otp: "Email code", security_questions: "Security questions" }[method] ?? (action === "login.failed" || action === "login.rate_limited" ? "Password" : "");
}

/** "Chrome on macOS" from a User-Agent; "" when there isn't one. */
export function describeUserAgent(ua: string | null): string {
  if (!ua) return "";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\/|Opera/.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl\//i.test(ua) ? "curl" : "";
  const os = /iPhone|iPad|iPod/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
  return browser && os ? `${browser} on ${os}` : browser || os || ua.slice(0, 40);
}

export async function signInHistory(env: Env, user: { id: number; upn: string; username: string }, limit = 25): Promise<SignInEvent[]> {
  const [{ results: emails }, { results: phones }] = await Promise.all([
    env.DB.prepare("SELECT email AS v FROM user_emails WHERE user_id = ? AND verified = 1").bind(user.id).all<{ v: string }>(),
    env.DB.prepare("SELECT phone AS v FROM user_phones WHERE user_id = ? AND verified = 1").bind(user.id).all<{ v: string }>(),
  ]);
  const spellings = [...new Set([user.upn, user.username, ...emails.map((e) => e.v), ...phones.map((p) => p.v)].filter(Boolean).map((s) => s.toLowerCase()))];
  const { results } = await env.DB.prepare(
    `SELECT at, action, details, ip, user_agent FROM (
       SELECT id, at, action, details, ip, user_agent FROM audit_log
        WHERE target IN (SELECT value FROM json_each(?)) AND action IN (SELECT value FROM json_each(?))
       UNION
       SELECT id, at, action, details, ip, user_agent FROM audit_log
        WHERE actor_user_id = ? AND action IN (SELECT value FROM json_each(?))
     ) ORDER BY id DESC LIMIT ?`
  )
    .bind(JSON.stringify(spellings), JSON.stringify(WEB_ACTIONS), user.id, JSON.stringify(LDAP_ACTIONS), limit)
    .all<{ at: string; action: string; details: string | null; ip: string | null; user_agent: string | null }>();
  return results.map((r) => {
    let details: Record<string, unknown> = {};
    try {
      details = JSON.parse(r.details || "{}") as Record<string, unknown>;
    } catch {
      /* not JSON */
    }
    const ok = r.action === "login.success" || r.action === "ldap.bind.success";
    return { at: r.at, ok, method: methodFor(r.action, details), reason: ok ? "" : (FAILURE_REASONS[r.action] ?? "Failed"), ip: r.ip ?? (typeof details.ip === "string" ? details.ip : null), device: describeUserAgent(r.user_agent) };
  });
}

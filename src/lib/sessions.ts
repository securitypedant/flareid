import { sha256Hex } from "./tokens.js";
import type { Env } from "../env.js";
import { randomToken } from "./tokens.js";
import { getClientIp } from "./rate-limit.js";
import { getSessionPolicy, normalizeSessionPolicy, SESSION_DEFAULTS } from "./settings.js";

const SESSION_COOKIE = "__Host-flareid_session";
/** The default SSO session lifetime; the effective one is the "session_max_hours" setting (Admin → Security). */
export const SESSION_TTL_SECONDS = 60 * 60 * SESSION_DEFAULTS.maxHours;

export interface SessionInfo {
  id: string;
  userId: number;
  amr: string[];
  /** When this session was created - the AuthnInstant an SSO reuse should report. */
  createdAt: string;
}

export interface SessionRow {
  id: string;
  user_id: number;
  amr: string;
  created_at: string;
  last_seen_at: string;
  ip: string | null;
  user_agent: string | null;
  revoked_at: string | null;
}

/** Whether the request carries a FlareID session cookie at all (valid or not) - i.e. whether it could act as someone. */
export function hasSessionCookie(request: Request): boolean {
  return readSessionIdFromCookie(request) !== null;
}

function readSessionIdFromCookie(request: Request): string | null {
  const cookieHeader = request.headers.get("Cookie") ?? "";
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const target = cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  return target ? target.substring(SESSION_COOKIE.length + 1) : null;
}

/** Creates a server-tracked session row (so it can later be listed/revoked) and returns the Set-Cookie header for it. */
/**
 * The OIDC `sid` claim for a session: a one-way derivation, never the session
 * id itself - that is the __Host-flareid_session cookie, a bearer credential,
 * and an id_token is handed to relying parties. Distinct from the SAML
 * SessionIndex derivation (saml/messages.ts) so the two cannot be correlated.
 */
export async function oidcSid(sessionId: string): Promise<string> {
  return `_${await sha256Hex(`flareid oidc sid v1\n${sessionId}`)}`;
}

export async function createSession(
  env: Env,
  userId: number,
  amr: string[],
  request: Request
): Promise<{ sessionId: string; setCookie: string }> {
  const sessionId = randomToken(32);
  const now = new Date().toISOString();

  const [policy] = await Promise.all([
    getSessionPolicy(env),
    env.DB.prepare("INSERT INTO sessions (id, user_id, amr, created_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(sessionId, userId, JSON.stringify(amr), now, now, getClientIp(request), request.headers.get("User-Agent"))
      .run(),
  ]);

  // The cookie outlives nothing the server would honour: getSession enforces
  // the same maximum (and the idle limit) on every request.
  const setCookie = `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${policy.maxHours * 3600}`;
  return { sessionId, setCookie };
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`;
}

export async function getSession(request: Request, env: Env): Promise<SessionInfo | null> {
  const sessionId = readSessionIdFromCookie(request);
  if (!sessionId) return null;

  // The session limits ride along in the same query, so enforcing them costs
  // no extra round trip on what is the hottest path in the app.
  const row = await env.DB.prepare(
    `SELECT s.*,
            (SELECT value FROM idp_settings WHERE key = 'session_max_hours') AS policy_max_hours,
            (SELECT value FROM idp_settings WHERE key = 'session_idle_minutes') AS policy_idle_minutes
       FROM sessions s WHERE s.id = ? AND s.revoked_at IS NULL`
  )
    .bind(sessionId)
    .first<SessionRow & { policy_max_hours: string | null; policy_idle_minutes: string | null }>();
  if (!row) return null;
  const policy = normalizeSessionPolicy(row.policy_max_hours, row.policy_idle_minutes);
  const now = Date.now();
  if (now - new Date(row.created_at).getTime() > policy.maxHours * 3600 * 1000) return null;
  if (policy.idleMinutes > 0 && now - new Date(row.last_seen_at).getTime() > policy.idleMinutes * 60 * 1000) return null;

  // Best-effort "last seen" bump - powers the active-sessions list.
  await env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(new Date().toISOString(), sessionId).run();

  return { id: row.id, userId: row.user_id, amr: JSON.parse(row.amr || '["pwd"]'), createdAt: row.created_at };
}

export async function getSessionUserId(request: Request, env: Env): Promise<number | null> {
  const session = await getSession(request, env);
  return session?.userId ?? null;
}

export async function getSessionAmr(request: Request, env: Env): Promise<string[]> {
  const session = await getSession(request, env);
  return session?.amr ?? ["pwd"];
}

/**
 * Ends every token grant a user holds. Deactivation is meant to cut access
 * immediately; revoking the grants directly means it does not depend on every
 * consumer (/token, /userinfo, /introspect, RPs' caches) re-checking status.
 */
/**
 * Ends every credential derived from the account other than sessions: OAuth
 * access and refresh tokens, unredeemed authorization codes, and outstanding
 * invitation/reset links. Called on deactivation and on every password
 * change - otherwise a refresh token, or an old invitation that re-activates
 * the account, outlives the compromise response.
 */
export async function revokeTokensForUser(env: Env, userId: number): Promise<void> {
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM access_tokens WHERE user_id = ?").bind(userId),
    env.DB.prepare("DELETE FROM auth_codes WHERE user_id = ?").bind(userId),
    env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, userId),
    env.DB.prepare("UPDATE account_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL").bind(now, userId),
  ]);
}

/**
 * Every statement needed to delete a user, for one D1 batch: each table with a
 * users(id) foreign key, then the row. Shared by the admin delete and the
 * directory import's replace mode, so the two cannot drift - a table added
 * later goes here once.
 */
export function deleteUserStatements(env: Env, ...ids: number[]): D1PreparedStatement[] {
  // One JSON parameter, not one per id: D1 allows at most 100 bound parameters per query.
  const idList = JSON.stringify(ids);
  return [
    env.DB.prepare(`DELETE FROM group_members WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM sessions WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM access_tokens WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM refresh_tokens WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM auth_codes WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM mfa_backup_codes WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM trusted_devices WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM account_tokens WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM oauth_consents WHERE user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    // Audit history is kept, detached from the account.
    env.DB.prepare(`UPDATE audit_log SET actor_user_id = NULL WHERE actor_user_id IN (SELECT value FROM json_each(?))`).bind(idList),
    env.DB.prepare(`DELETE FROM users WHERE id IN (SELECT value FROM json_each(?))`).bind(idList),
  ];
}

/** Revokes a session by its own id (e.g. on logout, or "sign out this device"). */
export async function revokeSession(env: Env, sessionId: string): Promise<void> {
  await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ?").bind(new Date().toISOString(), sessionId).run();
}

/** Revokes every active session for a user (optionally keeping one, e.g. the current one). Returns how many were revoked. */
export async function revokeAllSessionsForUser(env: Env, userId: number, exceptSessionId?: string): Promise<number> {
  const now = new Date().toISOString();
  const result = exceptSessionId
    ? await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id != ?")
        .bind(now, userId, exceptSessionId)
        .run()
    : await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(now, userId)
        .run();
  return result.meta.changes ?? 0;
}

export async function listActiveSessionsForUser(env: Env, userId: number): Promise<SessionRow[]> {
  const { results } = await env.DB.prepare(
    "SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC"
  )
    .bind(userId)
    .all<SessionRow>();
  return results;
}

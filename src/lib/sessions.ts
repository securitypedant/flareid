import type { Env } from "../env.js";
import { randomToken } from "./tokens.js";
import { getClientIp } from "./rate-limit.js";

const SESSION_COOKIE = "__Host-flareid_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12h SSO session

export interface SessionInfo {
  id: string;
  userId: number;
  amr: string[];
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

function readSessionIdFromCookie(request: Request): string | null {
  const cookieHeader = request.headers.get("Cookie") ?? "";
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const target = cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  return target ? target.substring(SESSION_COOKIE.length + 1) : null;
}

/** Creates a server-tracked session row (so it can later be listed/revoked) and returns the Set-Cookie header for it. */
export async function createSession(
  env: Env,
  userId: number,
  amr: string[],
  request: Request
): Promise<{ sessionId: string; setCookie: string }> {
  const sessionId = randomToken(32);
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, amr, created_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(sessionId, userId, JSON.stringify(amr), now, now, getClientIp(request), request.headers.get("User-Agent"))
    .run();

  const setCookie = `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`;
  return { sessionId, setCookie };
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`;
}

export async function getSession(request: Request, env: Env): Promise<SessionInfo | null> {
  const sessionId = readSessionIdFromCookie(request);
  if (!sessionId) return null;

  const row = await env.DB.prepare("SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL")
    .bind(sessionId)
    .first<SessionRow>();
  if (!row) return null;
  if (Date.now() - new Date(row.created_at).getTime() > SESSION_TTL_SECONDS * 1000) return null;

  // Best-effort "last seen" bump - powers the active-sessions list.
  await env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(new Date().toISOString(), sessionId).run();

  return { id: row.id, userId: row.user_id, amr: JSON.parse(row.amr || '["pwd"]') };
}

export async function getSessionUserId(request: Request, env: Env): Promise<number | null> {
  const session = await getSession(request, env);
  return session?.userId ?? null;
}

export async function getSessionAmr(request: Request, env: Env): Promise<string[]> {
  const session = await getSession(request, env);
  return session?.amr ?? ["pwd"];
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

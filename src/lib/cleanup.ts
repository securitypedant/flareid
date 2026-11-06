import type { Env } from "../env.js";
import { getAuditRetentionDays, getSessionPolicy } from "./settings.js";

/**
 * Scheduled garbage collection for expiring state.
 *
 * Runs from the Cron Trigger in wrangler.jsonc (hourly). Every table here
 * otherwise only shrinks incidentally - an auth code is deleted when it is
 * redeemed, but one that is never redeemed sits there forever - and unbounded
 * D1 growth is an operational failure, not a cosmetic one.
 *
 * KV-backed state (login flows, MFA challenges, SAML request IDs) is not here:
 * it is written with expirationTtl and expires on its own. Rate-limit counters
 * moved to D1 (atomic upserts), so they are pruned below - a week is far past
 * any sane window_minutes and stale rows self-reset anyway.
 *
 * Grace periods are deliberate:
 * - Rotated and revoked refresh tokens are kept for REFRESH_TOMBSTONE_DAYS so a
 *   replayed token is still recognised as reuse (and revokes its family)
 *   rather than looking merely unknown.
 * - Revoked sessions are kept for a day so "signed out" still shows up in the
 *   admin's view of what just happened.
 */

const REFRESH_TOMBSTONE_DAYS = 30;
const REVOKED_SESSION_GRACE_SECONDS = 24 * 60 * 60;

export interface CleanupResult {
  auth_codes: number;
  access_tokens: number;
  refresh_tokens: number;
  sessions: number;
  trusted_devices: number;
  audit_log: number;
}

const iso = (ms: number) => new Date(ms).toISOString();

export async function purgeExpiredState(env: Env, now = Date.now()): Promise<CleanupResult> {
  const [retentionDays, sessionPolicy] = await Promise.all([getAuditRetentionDays(env), getSessionPolicy(env)]);
  const day = 24 * 60 * 60 * 1000;

  const results = await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_codes WHERE expires_at < ?").bind(iso(now)),
    env.DB.prepare("DELETE FROM access_tokens WHERE expires_at < ?").bind(iso(now)),
    env.DB.prepare(
      `DELETE FROM refresh_tokens
        WHERE expires_at < ?
           OR (revoked_at IS NOT NULL AND revoked_at < ?)
           OR (rotated_at IS NOT NULL AND rotated_at < ?)`
    ).bind(iso(now), iso(now - REFRESH_TOMBSTONE_DAYS * day), iso(now - REFRESH_TOMBSTONE_DAYS * day)),
    env.DB.prepare("DELETE FROM sessions WHERE created_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)").bind(
      iso(now - sessionPolicy.maxHours * 3600 * 1000),
      iso(now - REVOKED_SESSION_GRACE_SECONDS * 1000)
    ),
    env.DB.prepare("DELETE FROM trusted_devices WHERE expires_at < ?").bind(iso(now)),
    env.DB.prepare("DELETE FROM audit_log WHERE at < ?").bind(iso(now - retentionDays * day)),
    // window_start is epoch milliseconds, not an ISO string: compared with
    // text, SQLite sorts every integer lower, which deleted every counter.
    env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 7 * day),
  ]);

  const [authCodes, accessTokens, refreshTokens, sessions, trustedDevices, auditLog] = results.map((r) => Number(r.meta.changes ?? 0));
  return {
    auth_codes: authCodes!,
    access_tokens: accessTokens!,
    refresh_tokens: refreshTokens!,
    sessions: sessions!,
    trusted_devices: trustedDevices!,
    audit_log: auditLog!,
  };
}

import type { Env } from "../env.js";
import { getSetting, setSetting } from "./settings.js";

export interface RateLimitPolicy {
  maxAttempts: number;
  windowMinutes: number;
}

const DEFAULT_POLICY: RateLimitPolicy = { maxAttempts: 5, windowMinutes: 15 };

/**
 * The per-IP bucket aggregates the failures of every principal behind one
 * egress address, so it needs a budget far larger than any single account's;
 * otherwise a handful of failures by one party denies sign-in to everyone
 * sharing the IP (office NAT, VPN, CGNAT). 20x still throttles real sprays.
 */
const IP_BUCKET_ATTEMPT_MULTIPLIER = 20;

export async function getRateLimitPolicy(env: Env): Promise<RateLimitPolicy> {
  const [maxAttempts, windowMinutes] = await Promise.all([
    getSetting(env, "rate_limit_max_attempts"),
    getSetting(env, "rate_limit_window_minutes"),
  ]);
  return {
    maxAttempts: Number(maxAttempts) || DEFAULT_POLICY.maxAttempts,
    windowMinutes: Number(windowMinutes) || DEFAULT_POLICY.windowMinutes,
  };
}

export async function setRateLimitPolicy(env: Env, policy: RateLimitPolicy): Promise<void> {
  await Promise.all([
    setSetting(env, "rate_limit_max_attempts", String(Math.max(1, policy.maxAttempts))),
    setSetting(env, "rate_limit_window_minutes", String(Math.max(1, policy.windowMinutes))),
  ]);
}

/**
 * Fixed-window attempt accounting in D1: a single INSERT .. ON CONFLICT ..
 * DO UPDATE .. RETURNING increments and reports the count atomically, so the
 * limit decision and the record can never race the way the KV get/put pair did.
 *
 * Callers record the attempt BEFORE checking credentials and refuse the
 * request when the returned count exceeds the budget. Counting an attempt
 * before verifying slightly over-counts mixed success/failure bursts, which
 * fails safe; a successful login clears the account bucket.
 */
async function recordAttempt(env: Env, key: string, windowMs: number): Promise<number> {
  const now = Date.now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN ? - window_start > ? THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN ? - window_start > ? THEN ? ELSE window_start END
     RETURNING count`
  )
    .bind(key, now, now, windowMs, now, windowMs, now)
    .first<{ count: number }>();
  return row?.count ?? 1;
}

/**
 * A general fixed-window counter for anything that is not a sign-in (password
 * recovery, invitations): records one attempt and reports whether the key is
 * now over `max` within the window.
 */
export async function recordRateAttempt(env: Env, key: string, max: number, windowMinutes: number): Promise<boolean> {
  return (await recordAttempt(env, key, windowMinutes * 60_000)) > max;
}

export function getClientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? request.headers.get("X-Forwarded-For") ?? "unknown";
}

/**
 * The address a per-client budget is keyed on. An IPv6 client normally holds a
 * whole /64, so keying the full address would hand it 2^64 fresh budgets;
 * IPv4 stays as is.
 */
export function rateLimitAddress(ip: string): string {
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = ip.includes("::") ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right] : left;
  return `${groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, "")).join(":")}::/64`;
}

/** A successful step gives its unit back to the shared per-IP bucket, so that bucket counts failures only. */
async function refundIpAttempt(env: Env, ip: string): Promise<void> {
  await env.DB.prepare("UPDATE rate_limits SET count = MAX(count - 1, 0) WHERE key = ?").bind(`login:ip:${rateLimitAddress(ip)}`).run();
}

/**
 * The identifier a bucket binds to: the resolved account's canonical UPN when
 * the submitted name matches a user, else the normalized submission - so
 * spelling variants (" admin", "admin@x", whitespace tricks) share one budget
 * instead of each claiming a fresh one.
 */
export function loginRateKey(identifier: string, user: { username: string } | null): string {
  // The username part, whether or not the account exists: "alice" and
  // "alice@domain" must share a bucket for unknown names exactly as they do
  // for real ones, or the lockout message tells which accounts exist.
  return (user?.username ?? identifier.trim().split("@")[0]!).trim().toLowerCase();
}

/**
 * Records one password-step attempt against the account bucket and the shared
 * per-IP bucket, and reports whether either is over budget. Call BEFORE
 * verifying the password; the increment IS the attempt. On success the caller
 * clears the account bucket with clearLoginAttempts.
 */
export async function recordLoginAttempt(env: Env, accountKey: string, ip: string): Promise<boolean> {
  const policy = await getRateLimitPolicy(env);
  const windowMs = policy.windowMinutes * 60_000;
  const [byAccount, byIp] = await Promise.all([
    recordAttempt(env, `login:upn:${accountKey}`, windowMs),
    recordAttempt(env, `login:ip:${rateLimitAddress(ip)}`, windowMs),
  ]);
  return byAccount > policy.maxAttempts || byIp > policy.maxAttempts * IP_BUCKET_ATTEMPT_MULTIPLIER;
}

/** Clears the account bucket after a successful password step. */
export async function clearLoginAttempts(env: Env, accountKey: string, ip?: string): Promise<void> {
  await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(`login:upn:${accountKey}`).run();
  if (ip) await refundIpAttempt(env, ip);
}

/**
 * The MFA step's bucket lives in a namespace no password-step input can reach:
 * it is keyed on the numeric user id, never on a submitted identifier string.
 */
export async function recordMfaAttempt(env: Env, userId: number, ip: string): Promise<boolean> {
  const policy = await getRateLimitPolicy(env);
  const windowMs = policy.windowMinutes * 60_000;
  const [byUser, byIp] = await Promise.all([
    recordAttempt(env, `login:mfa:${userId}`, windowMs),
    recordAttempt(env, `login:ip:${rateLimitAddress(ip)}`, windowMs),
  ]);
  return byUser > policy.maxAttempts || byIp > policy.maxAttempts * IP_BUCKET_ATTEMPT_MULTIPLIER;
}

/** Clears the account's MFA bucket after a successful second factor. */
export async function clearMfaAttempts(env: Env, userId: number, ip?: string): Promise<void> {
  await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(`login:mfa:${userId}`).run();
  if (ip) await refundIpAttempt(env, ip);
}

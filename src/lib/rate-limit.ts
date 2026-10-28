import type { Env } from "../env.js";
import { getSetting, setSetting } from "./settings.js";

export interface RateLimitPolicy {
  maxAttempts: number;
  windowMinutes: number;
}

const DEFAULT_POLICY: RateLimitPolicy = { maxAttempts: 5, windowMinutes: 15 };

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

interface AttemptRecord {
  count: number;
  windowStart: number;
}

/**
 * Fixed-window login attempt limiter, backed by KV. Tracks by an arbitrary key
 * (call once for the UPN being attempted and once for the client IP, so both a
 * targeted attack on one account and a broad spray from one IP get throttled).
 */
async function recordAttempt(env: Env, key: string, policy: RateLimitPolicy): Promise<boolean> {
  const kvKey = `ratelimit:${key}`;
  const now = Date.now();
  const windowMs = policy.windowMinutes * 60_000;

  const raw = await env.SESSIONS_KV.get(kvKey);
  let record: AttemptRecord = raw ? JSON.parse(raw) : { count: 0, windowStart: now };

  if (now - record.windowStart > windowMs) {
    record = { count: 0, windowStart: now };
  }

  record.count++;
  await env.SESSIONS_KV.put(kvKey, JSON.stringify(record), { expirationTtl: policy.windowMinutes * 60 });

  return record.count >= policy.maxAttempts;
}

async function isLimited(env: Env, key: string, policy: RateLimitPolicy): Promise<boolean> {
  const kvKey = `ratelimit:${key}`;
  const raw = await env.SESSIONS_KV.get(kvKey);
  if (!raw) return false;
  const record = JSON.parse(raw) as AttemptRecord;
  if (Date.now() - record.windowStart > policy.windowMinutes * 60_000) return false;
  return record.count >= policy.maxAttempts;
}

export function getClientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? request.headers.get("X-Forwarded-For") ?? "unknown";
}

/** Checks (without recording) whether login attempts for this UPN or IP are currently blocked. */
export async function isLoginRateLimited(env: Env, upn: string, ip: string): Promise<boolean> {
  const policy = await getRateLimitPolicy(env);
  const [byUpn, byIp] = await Promise.all([
    isLimited(env, `login:upn:${upn.toLowerCase()}`, policy),
    isLimited(env, `login:ip:${ip}`, policy),
  ]);
  return byUpn || byIp;
}

/** Records a failed login attempt for both the UPN and the source IP. */
export async function recordFailedLogin(env: Env, upn: string, ip: string): Promise<void> {
  const policy = await getRateLimitPolicy(env);
  await Promise.all([
    recordAttempt(env, `login:upn:${upn.toLowerCase()}`, policy),
    recordAttempt(env, `login:ip:${ip}`, policy),
  ]);
}

/** Clears the failed-attempt counters for a UPN after a successful login. */
export async function clearLoginAttempts(env: Env, upn: string): Promise<void> {
  await env.SESSIONS_KV.delete(`ratelimit:login:upn:${upn.toLowerCase()}`);
}

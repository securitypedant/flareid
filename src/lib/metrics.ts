import type { MiddlewareHandler } from "hono";
import type { Env } from "../env.js";

/**
 * IdP performance metrics via Workers Analytics Engine.
 *
 * Every request writes one data point - route family, method, status and the
 * time the Worker spent - to the optional METRICS dataset. Writing is
 * fire-and-forget and costs no D1 or KV write, so it is safe on anonymous
 * routes. Reading needs the Analytics Engine SQL API, which takes an account
 * API token: set CF_ACCOUNT_ID (var) and CF_ANALYTICS_TOKEN (secret, Account
 * Analytics: Read). Without them the overview says how to enable the panel.
 */

const DATASET = "flareid_requests";

/** Route family for a path - coarse on purpose, so ids and tokens never become dimensions. */
export function routeFamily(path: string): string {
  if (path === "/token" || path === "/introspect" || path === "/revoke") return "token";
  if (path === "/userinfo") return "userinfo";
  if (path === "/authorize" || path.startsWith("/consent/")) return "authorize";
  if (path === "/login" || path.startsWith("/login/")) return "login";
  if (path.startsWith("/saml/")) return "saml";
  if (path.startsWith("/scim/v2")) return "scim";
  if (path.startsWith("/api/")) return "api";
  if (path.startsWith("/admin")) return "admin";
  if (path.startsWith("/account")) return "account";
  if (path.startsWith("/.well-known/") || path === "/jwks.json") return "discovery";
  return "other";
}

export const recordRequestMetrics: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const started = Date.now();
  await next();
  const ds = c.env.METRICS;
  if (!ds) return;
  try {
    ds.writeDataPoint({
      indexes: [routeFamily(c.req.path)],
      blobs: [routeFamily(c.req.path), c.req.method, String(c.res.status)],
      doubles: [Date.now() - started, c.res.status],
    });
  } catch {
    // Metrics never break a request.
  }
};

export interface FamilyStats {
  family: string;
  requests: number;
  errors: number;
  p50: number;
  p95: number;
}

export type PerformanceResult =
  | { configured: false }
  | { configured: true; ok: true; families: FamilyStats[]; total: number; errors: number }
  | { configured: true; ok: false; error: string };

/** Requests, 5xx errors and latency percentiles per route family over the last `hours`. */
export async function readPerformance(env: Env, hours = 24): Promise<PerformanceResult> {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return { configured: false };
  const sql = `SELECT blob1 AS family, SUM(_sample_interval) AS requests,
      SUM(IF(double2 >= 500, _sample_interval, 0)) AS errors,
      quantileWeighted(0.5)(double1, _sample_interval) AS p50,
      quantileWeighted(0.95)(double1, _sample_interval) AS p95
    FROM ${DATASET} WHERE timestamp > NOW() - INTERVAL '${Math.max(1, Math.min(168, Math.floor(hours)))}' HOUR
    GROUP BY family ORDER BY requests DESC FORMAT JSON`;
  try {
    const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: "POST",
      headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` },
      body: sql,
    });
    if (!res.ok) return { configured: true, ok: false, error: `Analytics Engine answered ${res.status}` };
    const body = (await res.json()) as { data?: Record<string, string | number>[] };
    const families = (body.data ?? []).map((r) => ({
      family: String(r.family),
      requests: Number(r.requests) || 0,
      errors: Number(r.errors) || 0,
      p50: Math.round(Number(r.p50) || 0),
      p95: Math.round(Number(r.p95) || 0),
    }));
    return { configured: true, ok: true, families, total: families.reduce((s, f) => s + f.requests, 0), errors: families.reduce((s, f) => s + f.errors, 0) };
  } catch (e) {
    return { configured: true, ok: false, error: String(e).slice(0, 200) };
  }
}

export interface SeriesPoint {
  t: string;
  requests: number;
  errors: number;
  p50: number;
  p95: number;
}

export type SeriesResult = { configured: false } | { configured: true; ok: true; points: SeriesPoint[] } | { configured: true; ok: false; error: string };

/** Requests, 5xx and latency percentiles per time bucket, oldest first (empty buckets filled with zeros). */
export async function readPerformanceSeries(env: Env, hours: number, bucketMinutes: number, family?: string): Promise<SeriesResult> {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return { configured: false };
  const h = Math.max(1, Math.min(168, Math.floor(hours)));
  const b = Math.max(1, Math.min(1440, Math.floor(bucketMinutes)));
  const fam = family && /^[a-z]+$/.test(family) ? ` AND blob1 = '${family}'` : "";
  const sql = `SELECT toStartOfInterval(timestamp, INTERVAL '${b}' MINUTE) AS t, SUM(_sample_interval) AS requests,
      SUM(IF(double2 >= 500, _sample_interval, 0)) AS errors,
      quantileWeighted(0.5)(double1, _sample_interval) AS p50,
      quantileWeighted(0.95)(double1, _sample_interval) AS p95
    FROM ${DATASET} WHERE timestamp > NOW() - INTERVAL '${h}' HOUR${fam}
    GROUP BY t ORDER BY t FORMAT JSON`;
  try {
    const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: "POST",
      headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` },
      body: sql,
    });
    if (!res.ok) return { configured: true, ok: false, error: `Analytics Engine answered ${res.status}` };
    const body = (await res.json()) as { data?: Record<string, string | number>[] };
    const got = new Map((body.data ?? []).map((r) => [new Date(String(r.t).replace(" ", "T") + (String(r.t).endsWith("Z") ? "" : "Z")).getTime(), r]));
    const step = b * 60_000;
    const end = Math.floor(Date.now() / step) * step;
    const points: SeriesPoint[] = [];
    for (let at = end - Math.ceil((h * 60) / b - 1) * step; at <= end; at += step) {
      const r = got.get(at);
      points.push({ t: new Date(at).toISOString(), requests: Number(r?.requests) || 0, errors: Number(r?.errors) || 0, p50: Math.round(Number(r?.p50) || 0), p95: Math.round(Number(r?.p95) || 0) });
    }
    return { configured: true, ok: true, points };
  } catch (e) {
    return { configured: true, ok: false, error: String(e).slice(0, 200) };
  }
}

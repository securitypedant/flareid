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
const SPANS_DATASET = "flareid_spans";

/**
 * Sub-request telemetry (the `flareid_spans` dataset): which pieces inside a
 * request cost time, and discrete events worth counting. One datapoint per
 * record, all fire-and-forget like the request points above.
 *   blobs:   [kind ("span" | "event"), name, detail]
 *   doubles: [ms or count, 0]
 * `name` is from a fixed vocabulary - never user input - and `detail` carries
 * a coarse outcome (for events) or stays empty (for spans).
 */
export function recordSpan(env: Pick<Env, "METRICS_SPANS">, name: string, ms: number): void {
  try {
    env.METRICS_SPANS?.writeDataPoint({ indexes: [name], blobs: ["span", name, ""], doubles: [Math.max(0, Math.round(ms)), 0] });
  } catch {
    // Metrics never break a request.
  }
}

/** Time an async operation into a named span. */
export async function timed<T>(env: Pick<Env, "METRICS_SPANS">, name: string, p: Promise<T>): Promise<T> {
  const started = Date.now();
  try {
    return await p;
  } finally {
    recordSpan(env, name, Date.now() - started);
  }
}

/** Count an occurrence - sign-ins, bind failures, token mints. */
export function recordEvent(env: Pick<Env, "METRICS_SPANS">, name: string, detail = ""): void {
  try {
    env.METRICS_SPANS?.writeDataPoint({ indexes: [name], blobs: ["event", name, detail], doubles: [1, 0] });
  } catch {
    // Metrics never break a request.
  }
}

export interface SpanStats {
  name: string;
  calls: number;
  totalMs: number;
  avgMs: number;
  p95: number;
}

/** Time spent inside each instrumented span over the last `hours`. */
export async function readSpanStats(env: Env, hours = 24): Promise<SpanStats[] | null> {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return null;
  const sql = `SELECT blob2 AS name, SUM(_sample_interval) AS calls,
      SUM(double1 * _sample_interval) AS total_ms,
      quantileWeighted(0.95)(double1, _sample_interval) AS p95
    FROM ${SPANS_DATASET} WHERE timestamp > NOW() - INTERVAL '${Math.max(1, Math.min(168, Math.floor(hours)))}' HOUR AND blob1 = 'span'
    GROUP BY name ORDER BY total_ms DESC FORMAT JSON`;
  try {
    const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: "POST",
      headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` },
      body: sql,
      // Admin-reporting queries only - bound the wait so a stalled AE API
      // can't pin the request open.
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { data?: Record<string, string | number>[] };
    return (body.data ?? []).map((r) => ({
      name: String(r.name),
      calls: Number(r.calls) || 0,
      totalMs: Math.round(Number(r.total_ms) || 0),
      avgMs: Math.round((Number(r.total_ms) || 0) / Math.max(1, Number(r.calls) || 1)),
      p95: Math.round(Number(r.p95) || 0),
    }));
  } catch {
    return null;
  }
}

/** Event counts (sign-ins etc.) over the last `minutes` - the live strip. */
export async function readEventCounts(env: Env, minutes = 30): Promise<{ name: string; detail: string; count: number }[] | null> {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return null;
  const sql = `SELECT blob2 AS name, blob3 AS detail, SUM(_sample_interval) AS count
    FROM ${SPANS_DATASET} WHERE timestamp > NOW() - INTERVAL '${Math.max(1, Math.min(1440, Math.floor(minutes)))}' MINUTE AND blob1 = 'event'
    GROUP BY name, detail ORDER BY count DESC FORMAT JSON`;
  try {
    const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: "POST",
      headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` },
      body: sql,
      // Admin-reporting queries only - bound the wait so a stalled AE API
      // can't pin the request open.
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { data?: Record<string, string | number>[] };
    return (body.data ?? []).map((r) => ({ name: String(r.name), detail: String(r.detail), count: Number(r.count) || 0 }));
  } catch {
    return null;
  }
}

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
  const ms = Date.now() - started;
  // One structured line per request: Workers Logs (wrangler tail, Logpush)
  // captures console output, so this is the machine-readable access log.
  try {
    console.log(JSON.stringify({ msg: "http.request", family: routeFamily(c.req.path), method: c.req.method, status: c.res.status, ms }));
  } catch {
    /* logging never breaks a request */
  }
  const ds = c.env.METRICS;
  if (!ds) return;
  try {
    ds.writeDataPoint({
      indexes: [routeFamily(c.req.path)],
      blobs: [routeFamily(c.req.path), c.req.method, String(c.res.status)],
      doubles: [ms, c.res.status],
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
      // Admin-reporting queries only - bound the wait so a stalled AE API
      // can't pin the request open.
      signal: AbortSignal.timeout(15_000),
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
      // Admin-reporting queries only - bound the wait so a stalled AE API
      // can't pin the request open.
      signal: AbortSignal.timeout(15_000),
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

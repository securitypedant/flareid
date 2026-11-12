import type { Env } from "../env.js";
import { readPerformance, readPerformanceSeries } from "../lib/metrics.js";
import type { AuditLogRow } from "../lib/types.js";

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/** Who did it: a person, an API key (or the bootstrap token), or nobody signed in (failed sign-ins, the scheduler). */
export const LOG_ACTORS: Record<string, { label: string; where: string }> = {
  people: { label: "People", where: "actor_user_id IS NOT NULL" },
  // Failed key attempts have no actor (the key did not authenticate) but belong here.
  api: { label: "API keys", where: "(actor_upn LIKE 'api-key:%' OR actor_upn = 'bootstrap-token' OR action = 'api.auth_failed')" },
  system: {
    label: "Anonymous & system",
    where:
      "actor_user_id IS NULL AND action != 'api.auth_failed' AND (actor_upn IS NULL OR (actor_upn NOT LIKE 'api-key:%' AND actor_upn != 'bootstrap-token'))",
  },
};

/** Action families, by the prefix before the dot. SAML covers both saml.* and saml_sp.*. */
export const LOG_CATEGORIES: Record<string, { label: string; like: string }> = {
  login: { label: "Sign-ins", like: "login.%" },
  user: { label: "Users", like: "user.%" },
  group: { label: "Groups", like: "group.%" },
  directory: { label: "Directory imports", like: "directory.%" },
  api: { label: "API requests", like: "api.%" },
  api_key: { label: "API keys", like: "api_key.%" },
  oidc: { label: "OIDC", like: "oidc_client.%" },
  oauth: { label: "OAuth tokens", like: "oauth.%" },
  saml: { label: "SAML", like: "saml%" },
  scim: { label: "SCIM", like: "scim.%" },
  settings: { label: "Settings", like: "settings.%" },
  domain: { label: "Domains", like: "domain.%" },
  schema: { label: "Schemas", like: "schema.%" },
  idp: { label: "Setup & recovery", like: "idp.%" },
};

export interface LogFilters {
  search: string;
  /** A LOG_ACTORS key, or "". */
  actor: string;
  /** A LOG_CATEGORIES key, or "". */
  category: string;
  /** YYYY-MM-DD (UTC, inclusive), or "". */
  from: string;
  to: string;
}

/** Cleans raw filter values: unknown actors/categories and malformed dates are dropped rather than refused. */
export function logFilters(raw: { search?: string; actor?: string; category?: string; from?: string; to?: string }): LogFilters {
  const isDate = (v: string | undefined) => (v && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : "");
  return {
    search: raw.search ?? "",
    actor: LOG_ACTORS[raw.actor ?? ""] ? raw.actor! : "",
    category: LOG_CATEGORIES[raw.category ?? ""] ? raw.category! : "",
    from: isDate(raw.from),
    to: isDate(raw.to),
  };
}

export async function queryAuditLog(env: Env, f: LogFilters, limit: number, offset: number): Promise<{ total: number; entries: AuditLogRow[] }> {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (f.search) {
    const like = `%${f.search}%`;
    conditions.push("(actor_upn LIKE ? OR action LIKE ? OR target LIKE ? OR details LIKE ? OR ip LIKE ?)");
    params.push(like, like, like, like, like);
  }
  if (f.actor) conditions.push(LOG_ACTORS[f.actor]!.where);
  if (f.category) {
    conditions.push("action LIKE ?");
    params.push(LOG_CATEGORIES[f.category]!.like);
  }
  // Dates are whole UTC days, inclusive at both ends.
  if (f.from) {
    conditions.push("at >= ?");
    params.push(`${f.from}T00:00:00.000Z`);
  }
  if (f.to) {
    conditions.push("at < ?");
    params.push(new Date(Date.parse(`${f.to}T00:00:00.000Z`) + 86_400_000).toISOString());
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const [count, rows] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) as n FROM audit_log ${whereClause}`).bind(...params),
    env.DB.prepare(`SELECT * FROM audit_log ${whereClause} ORDER BY at DESC LIMIT ? OFFSET ?`).bind(...params, limit, offset),
  ]);
  return { total: Number((count!.results[0] as { n: number } | undefined)?.n ?? 0), entries: rows!.results as AuditLogRow[] };
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

export const DASHBOARD_DAYS = 30;

/** YYYY-MM-DD for a day offset from today, in UTC to match the audit log's timestamps. */
export function dayKey(offsetDays: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

/** Everything the console overview shows, as numbers. */
export async function overviewStats(env: Env) {
  const since = `${dayKey(-(DASHBOARD_DAYS - 1))}T00:00:00.000Z`;
  const day = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const n = (r: D1Result) => (r.results[0] as { n: number } | undefined)?.n ?? 0;
  const [counts, loginsByDay, outcomes, topActions, topUsers] = await Promise.all([
    env.DB.batch([
      env.DB.prepare("SELECT COUNT(*) AS n FROM users"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM groups"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM oauth_clients"),
      // Sessions carry no expiry column - validity is created_at plus the 12h TTL
      // in lib/sessions.ts, so the same rule is applied here rather than inventing
      // one that would over-count long-dead sessions.
      env.DB.prepare("SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL AND created_at > ?").bind(new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()),
      env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE mfa_enabled = 1"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM saml_service_providers"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM api_keys WHERE revoked_at IS NULL"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'active'"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND action = 'login.success'").bind(day),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND (action LIKE 'login.failed%' OR action LIKE 'login.mfa_failed%')").bind(day),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND action = 'login.rate_limited'").bind(day),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND action = 'api.request'").bind(day),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND action = 'api.auth_failed'").bind(day),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND action LIKE 'scim.%failed'").bind(day),
      env.DB.prepare("SELECT COUNT(*) AS n FROM scim_deprovision_queue"),
      env.DB.prepare("SELECT COUNT(*) AS n FROM refresh_tokens WHERE revoked_at IS NULL AND rotated_at IS NULL AND expires_at > ?").bind(new Date().toISOString()),
      env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE at >= ? AND action = 'user.step_up_failed'").bind(day),
    ]),
    // The audit log is the source of truth for activity: login.success and
    // login.failed have been recorded since the first version, so these charts
    // need no new instrumentation - just grouping.
    env.DB.prepare(
      `SELECT substr(at, 1, 10) AS day,
              SUM(CASE WHEN action = 'login.success' THEN 1 ELSE 0 END) AS ok,
              SUM(CASE WHEN action LIKE 'login.failed%' OR action LIKE 'login.mfa_failed%' THEN 1 ELSE 0 END) AS bad
         FROM audit_log
        WHERE at >= ? AND action LIKE 'login.%'
        GROUP BY day ORDER BY day`
    )
      .bind(since)
      .all<{ day: string; ok: number; bad: number }>(),
    env.DB.prepare(`SELECT action, COUNT(*) AS n FROM audit_log WHERE at >= ? AND action LIKE 'login.%' GROUP BY action ORDER BY n DESC`).bind(since).all<{ action: string; n: number }>(),
    env.DB.prepare(`SELECT action, COUNT(*) AS n FROM audit_log WHERE at >= ? AND action NOT LIKE 'login.%' GROUP BY action ORDER BY n DESC LIMIT 6`).bind(since).all<{ action: string; n: number }>(),
    env.DB.prepare(
      `SELECT actor_upn AS upn, COUNT(*) AS n FROM audit_log
        WHERE at >= ? AND action = 'login.success' AND actor_upn IS NOT NULL
        GROUP BY actor_upn ORDER BY n DESC LIMIT 6`
    )
      .bind(since)
      .all<{ upn: string; n: number }>(),
  ]);
  const [users, groups, oidcClients, activeSessions, mfaEnrolled, samlApps, apiKeys, activeUsers, ok24, bad24, limited24, api24, apiBad24, scimFail24, scimQueue, refreshLive, stepUpBad24] = counts.map(n);
  // Fill the gaps: a day with no logins has to be a zero, not a missing day,
  // or the shape of the chart lies about the period.
  const byDay = new Map(loginsByDay.results.map((r) => [r.day, r]));
  const signInsByDay = Array.from({ length: DASHBOARD_DAYS }, (_, i) => dayKey(-(DASHBOARD_DAYS - 1 - i))).map((d) => ({ day: d, success: byDay.get(d)?.ok ?? 0, failed: byDay.get(d)?.bad ?? 0 }));
  return {
    counts: { users: users!, groups: groups!, oidc_clients: oidcClients!, saml_apps: samlApps!, active_api_keys: apiKeys!, active_users: activeUsers!, active_sessions: activeSessions!, mfa_enrolled: mfaEnrolled!, live_refresh_grants: refreshLive!, scim_deletions_queued: scimQueue! },
    last_24h: { sign_ins: ok24!, failed_sign_ins: bad24!, rate_limited_sign_ins: limited24!, failed_step_ups: stepUpBad24!, api_calls: api24!, rejected_api_keys: apiBad24!, scim_sync_failures: scimFail24! },
    last_30d: {
      sign_ins: signInsByDay.reduce((s, d) => s + d.success, 0),
      failed_sign_ins: signInsByDay.reduce((s, d) => s + d.failed, 0),
      sign_ins_by_day: signInsByDay,
      outcomes: outcomes.results,
      top_actions: topActions.results,
      top_users: topUsers.results,
    },
  };
}

// ---------------------------------------------------------------------------
// Performance
// ---------------------------------------------------------------------------

export const PERF_RANGES = {
  "1h": { hours: 1, bucket: 5, label: "Last hour", fmt: (d: Date) => d.toISOString().slice(11, 16) },
  "24h": { hours: 24, bucket: 60, label: "Last 24 hours", fmt: (d: Date) => d.toISOString().slice(11, 13) + "h" },
  "7d": { hours: 168, bucket: 360, label: "Last 7 days", fmt: (d: Date) => d.toISOString().slice(5, 10) + " " + d.toISOString().slice(11, 13) + "h" },
} as const;
export type PerfRange = keyof typeof PERF_RANGES;

/** The series and per-endpoint totals for a range, from Workers Analytics Engine. */
export async function performanceReport(env: Env, rawRange: string | undefined, rawFamily: string | undefined) {
  const rangeKey: PerfRange = rawRange && rawRange in PERF_RANGES ? (rawRange as PerfRange) : "24h";
  const range = PERF_RANGES[rangeKey];
  const family = /^[a-z]+$/.test(rawFamily ?? "") ? rawFamily! : "";
  const [series, totals] = await Promise.all([readPerformanceSeries(env, range.hours, range.bucket, family || undefined), readPerformance(env, range.hours)]);
  return { rangeKey, range, family, series, totals };
}

import { z } from "@hono/zod-openapi";
import { LOG_ACTORS, LOG_CATEGORIES, logFilters, overviewStats, PERF_RANGES, performanceReport, queryAuditLog } from "../services/monitoring.js";
import { defineRoute } from "./openapi.js";
import { AuditEntrySchema } from "./schemas.js";

/** The console's overview, performance dashboard and log, as data. */

const Count = z.object({ action: z.string(), n: z.number() });

defineRoute(
  {
    method: "get",
    path: "/api/v1/stats",
    tag: "Monitoring",
    permission: "performance:read",
    summary: "Overview statistics",
    description:
      "The numbers on the console's overview: directory counts, second-factor enrolment, the last 24 hours and the last 30 days of sign-in activity (from the audit log). `counts.mfa_enrolled` is the number of users with any second factor (authenticator app, passkey, email codes or security questions); `second_factors` breaks it down.",
    response: z.object({
      counts: z.record(z.string(), z.number()),
      second_factors: z
        .object({
          any: z.number().openapi({ description: "Users with at least one second factor enrolled (= counts.mfa_enrolled)." }),
          totp: z.number().openapi({ description: "Authenticator app." }),
          passkey: z.number().openapi({ description: "At least one passkey." }),
          email_otp: z.number().openapi({ description: "Email codes." }),
          security_questions: z.number().openapi({ description: "Security questions (not accepted as an administrator's second factor)." }),
        })
        .openapi("SecondFactorCounts"),
      last_24h: z.record(z.string(), z.number()),
      last_30d: z.object({
        sign_ins: z.number(),
        failed_sign_ins: z.number(),
        sign_ins_by_day: z.array(z.object({ day: z.string(), success: z.number(), failed: z.number() })),
        outcomes: z.array(Count),
        top_actions: z.array(Count),
        top_users: z.array(z.object({ upn: z.string(), n: z.number() })),
      }),
    }),
  },
  async (c) => c.json(await overviewStats(c.env))
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/performance",
    tag: "Monitoring",
    permission: "performance:read",
    summary: "Request volume, errors and latency",
    description:
      "From Workers Analytics Engine. Without CF_ACCOUNT_ID and CF_ANALYTICS_TOKEN the answer is `configured: false` (still 200), so a dashboard can say what to set up; a failed query is `configured: true, ok: false` with the error.",
    query: z.object({ range: z.enum(Object.keys(PERF_RANGES) as [keyof typeof PERF_RANGES, ...(keyof typeof PERF_RANGES)[]]).optional(), endpoint: z.string().optional().openapi({ description: "One route family, e.g. token." }) }),
    response: z
      .object({
        configured: z.boolean(),
        ok: z.boolean().optional(),
        error: z.string().optional(),
        message: z.string().optional(),
        range: z.string(),
        bucket_minutes: z.number(),
        endpoint: z.string().nullable(),
        points: z.array(z.object({ t: z.string(), requests: z.number(), errors: z.number(), p50: z.number(), p95: z.number() }).passthrough()).optional(),
        families: z.array(z.object({ family: z.string(), requests: z.number(), errors: z.number(), p50: z.number(), p95: z.number() }).passthrough()).optional(),
      })
      .openapi("Performance"),
  },
  async (c) => {
    const { rangeKey, range, family, series, totals } = await performanceReport(c.env, c.req.query("range"), c.req.query("endpoint"));
    const base = { range: rangeKey, bucket_minutes: range.bucket, endpoint: family || null };
    if (!series.configured || !totals.configured) {
      return c.json({ configured: false, message: "Set the CF_ACCOUNT_ID var and the CF_ANALYTICS_TOKEN secret (Account Analytics: Read) to read performance data.", ...base });
    }
    if (!series.ok || !totals.ok) return c.json({ configured: true, ok: false, error: !series.ok ? series.error : (totals as { error: string }).error, ...base });
    return c.json({ configured: true, ok: true, ...base, points: series.points, families: totals.families });
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/audit",
    tag: "Monitoring",
    permission: "audit:read",
    summary: "Read the audit log",
    description: `Newest first, with the console's filters. actor: ${Object.keys(LOG_ACTORS).join(", ")}; category: ${Object.keys(LOG_CATEGORIES).join(", ")}; from/to are whole UTC days (YYYY-MM-DD, inclusive).`,
    query: z.object({
      search: z.string().optional().openapi({ description: "Matches actor, action, target, details or IP." }),
      actor: z.string().optional(),
      category: z.string().optional(),
      from: z.string().optional(),
      to: z.string().optional(),
      limit: z.string().optional().openapi({ description: "Default 100, at most 500." }),
      offset: z.string().optional(),
    }),
    response: z.object({ total: z.number(), limit: z.number(), offset: z.number(), entries: z.array(AuditEntrySchema) }),
  },
  async (c) => {
    const limit = Math.min(Number(c.req.query("limit") ?? 100) || 100, 500);
    const offset = Math.max(Number(c.req.query("offset") ?? 0) || 0, 0);
    const filters = logFilters({ search: c.req.query("search"), actor: c.req.query("actor"), category: c.req.query("category"), from: c.req.query("from"), to: c.req.query("to") });
    const { total, entries } = await queryAuditLog(c.env, filters, limit, offset);
    return c.json({
      total,
      limit,
      offset,
      entries: entries.map(({ actor_user_id: _id, details, ...e }) => {
        let parsed: unknown = details;
        try {
          parsed = details ? JSON.parse(details) : null;
        } catch {
          // Kept as the stored string.
        }
        return { ...e, details: parsed };
      }),
    });
  }
);

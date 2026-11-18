# Observability and alerting

## What already emits

| Signal | Where | Notes |
| --- | --- | --- |
| Request metrics (volume, errors, p50/p95) | `METRICS` Analytics Engine dataset, per request | Visible on the admin overview when `CF_ACCOUNT_ID` + `CF_ANALYTICS_TOKEN` are set. |
| Audit-derived metrics | same dataset, one data point per audited action | `lib/metrics.ts` - `recordEvent(env, action)`. |
| Audit log | `audit_log` table, hash-chained | `GET /api/v1/audit`, `/admin/audit`, `?verify=1` recomputes the chain. |
| `console.log` events | Workers Logs / Logpush | Structured JSON: `cleanup`, `cfone_sync`, `scim_deprovision`, `backup_snapshot`, failures. |
| Health | `GET /health` → `{status:"ok"}` | Unauthenticated liveness for uptime monitors; no DB touch. |

`wrangler.jsonc` already sets `"observability": { "enabled": true }`, so
logs and traces are on in the dashboard (Observability → Workers).

## Alerting via Workers notifications

Cloudflare doesn't let a Worker configure its own alerts - they're account
notifications in the dashboard (**Notifications → Add**). The ones worth
setting for this deployment:

- **Workers → Usage warning** on the `flareid-idp` Worker: fires on
  CPU-time/request spikes. A sudden 5xx or CPU burst usually means a bad
  dependency (SCIM target, Cloudflare One API) or an attack.
- **Workers → Errors**: notification when the Worker throws. Uncaught errors
  are also in Workers Logs; this just pushes them to email/webhook/PagerDuty.
- **Health check** (optional, external): point your uptime monitor at
  `GET /health` - it's unauthenticated, cheap, and returns 200 only when the
  Worker is dispatching.

## Queries worth keeping (Analytics Engine, SQL API)

```sql
-- 5xx rate, last hour
SELECT blob1 AS route, count(*) AS errors FROM flareid_requests
WHERE timestamp > NOW() - INTERVAL '1' HOUR AND double2 >= 500
GROUP BY route ORDER BY errors DESC;

-- Failed sign-ins by user, last hour (burst detector - also auto-flags at 10+)
SELECT blob2 AS action, count(*) FROM flareid_requests
WHERE timestamp > NOW() - INTERVAL '1' HOUR AND blob2 = 'login.failed'
GROUP BY action;
```

(The exact blob indexes are in `src/lib/metrics.ts`; the overview page queries
them already if `CF_ANALYTICS_TOKEN` is set.)

## Operational events worth watching in logs

- `cfone_sync_failed`, `scim_deprovision_failed`, `backup_snapshot_failed` -
  scheduled jobs that failed; each emits on every retry so a stuck one is
  loud.
- `saml_metadata_refresh_error` - an SP's metadata URL is unreachable.
- Audit `broken`/`fork` from `GET /api/v1/audit/verify` - run it in a daily
  job; anything but `ok` is worth a look (`fork` can occur under concurrent
  writes; `broken` cannot).

## Audit tamper-evidence

Every audit row carries `chain_hash` - SHA-256 over the previous row's hash
plus its own contents. Deleting or editing a written row breaks every hash
after it; `GET /api/v1/audit/verify` (or the Log page's *Verify integrity*)
recomputes the chain. Export includes `chain_hash` per line so an export can
be re-verified offline.

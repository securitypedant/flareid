import type { Env } from "../env.js";
import type { UserRow } from "./types.js";
import { getClientIp } from "./rate-limit.js";
import { recordEvent } from "./metrics.js";

/**
 * `actor.id` is nullable because not every actor is a user: an action taken
 * through the provisioning API is attributed to a key, not a person, and
 * actor_user_id references users(id) - so those rows carry a null id and the
 * key's name in actor_upn.
 */
export async function logAudit(
  env: Env,
  actor: UserRow | { id: number | null; upn: string } | null,
  action: string,
  target?: string,
  details?: Record<string, unknown>,
  request?: Request
): Promise<void> {
  await insertAudit(env, actor, action, target, details, request ? getClientIp(request) : null, request?.headers.get("User-Agent") ?? null);
}

/**
 * Same row without a Request - for protocols that arrive over TCP, where the
 * remote address and a synthetic user agent are all there is (LDAP.md).
 */
export async function logAuditRaw(
  env: Env,
  actor: UserRow | { id: number | null; upn: string } | null,
  action: string,
  target: string | undefined,
  details: Record<string, unknown> | undefined,
  peer: { ip: string | null; userAgent: string | null }
): Promise<void> {
  await insertAudit(env, actor, action, target, details, peer.ip, peer.userAgent);
}

async function insertAudit(env: Env, actor: UserRow | { id: number | null; upn: string } | null, action: string, target: string | undefined, details: Record<string, unknown> | undefined, ip: string | null, userAgent: string | null): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO audit_log (at, actor_user_id, actor_upn, action, target, details, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      new Date().toISOString(),
      actor?.id ?? null,
      actor?.upn ?? null,
      action,
      target == null ? null : target.slice(0, 256),
      // Attacker-influenced fields are bounded like target: an anonymous
      // caller must not amplify request volume into unbounded log writes.
      details ? JSON.stringify(details).slice(0, 4_096) : null,
      ip,
      userAgent?.slice(0, 512) ?? null
    )
    .run();
  recordEvent(env, action); // audited actions double as live metrics (lib/metrics.ts)
}

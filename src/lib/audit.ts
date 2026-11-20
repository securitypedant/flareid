import type { Env } from "../env.js";
import type { UserRow } from "./types.js";
import { getClientIp } from "./rate-limit.js";
import { recordEvent } from "./metrics.js";
import { sha256Hex } from "./tokens.js";

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

function auditDigest(at: string, actorUserId: number | null, actorUpn: string | null, action: string, target: string | null, details: string | null, ip: string | null, userAgent: string | null): Promise<string> {
  return sha256Hex([at, actorUserId ?? "", actorUpn ?? "", action, target ?? "", details ?? "", ip ?? "", userAgent ?? ""].join("|"));
}

async function insertAudit(env: Env, actor: UserRow | { id: number | null; upn: string } | null, action: string, target: string | undefined, details: Record<string, unknown> | undefined, ip: string | null, userAgent: string | null): Promise<void> {
  const at = new Date().toISOString();
  const targetVal = target == null ? null : target.slice(0, 256);
  // Attacker-influenced fields are bounded like target: an anonymous
  // caller must not amplify request volume into unbounded log writes.
  const detailsVal = details ? JSON.stringify(details).slice(0, 4_096) : null;
  const uaVal = userAgent?.slice(0, 512) ?? null;
  const digest = await auditDigest(at, actor?.id ?? null, actor?.upn ?? null, action, targetVal, detailsVal, ip, uaVal);
  // Hash-chained for tamper-evidence: each row's chain_hash covers the
  // previous row's hash plus this row's contents, so deleting or rewriting a
  // written row breaks the chain past it. Concurrent writers can share a
  // parent (a fork) - the verifier reports that rather than a break.
  const prev = await env.DB.prepare("SELECT chain_hash FROM audit_log WHERE chain_hash IS NOT NULL ORDER BY id DESC LIMIT 1").first<{ chain_hash: string }>();
  const chainHash = await sha256Hex(`${prev?.chain_hash ?? ""}|${digest}`);
  await env.DB.prepare(
    "INSERT INTO audit_log (at, actor_user_id, actor_upn, action, target, details, ip, user_agent, chain_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(at, actor?.id ?? null, actor?.upn ?? null, action, targetVal, detailsVal, ip, uaVal, chainHash)
    .run();
  recordEvent(env, action); // audited actions double as live metrics (lib/metrics.ts)
}

export interface AuditVerifyResult {
  checked: number;
  /** Rows predating the chain (chain_hash IS NULL) are counted but not verified. */
  unchained: number;
  status: "ok" | "empty" | "broken" | "fork";
  /** Row id of the first anomaly, when any. */
  at_id?: number;
  message?: string;
}

/**
 * Walks the audit log in id order and recomputes every chain_hash. Rows that
 * predate the feature (chain_hash NULL) are skipped and counted. Two rows
 * sharing a parent hash is a "fork" - suspicious but can occur naturally
 * under concurrent writes; a row whose contents or stored hash don't match
 * is "broken" - someone tampered.
 *
 * The oldest row the window can see is the anchor: trusted, not re-verified
 * (its parent is out of sight or deleted). That is what the hourly retention
 * purge in cleanup.ts leaves behind - it removes a whole *prefix* of the
 * chain, so a surviving boundary row whose stored hash covers a deleted
 * parent is the routine case, not tampering. Deleting a row among the
 * retained ones still reports "broken": the next row's expected parent is
 * gone. The trade-off, already true of any log longer than the window, is
 * that prefix deletion itself is out of scope for this check.
 */
export async function verifyAuditChain(env: Env, limit = 10_000): Promise<AuditVerifyResult> {
  // limit+1 newest rows: when the log is longer than the window, the extra
  // oldest row seeds the parent hash the first verified row chains from.
  const rows = await env.DB.prepare(
    "SELECT id, at, actor_user_id, actor_upn, action, target, details, ip, user_agent, chain_hash FROM audit_log WHERE chain_hash IS NOT NULL ORDER BY id DESC LIMIT ?"
  ).bind(limit + 1).all();
  const total = await env.DB.prepare("SELECT COUNT(*) AS c, SUM(CASE WHEN chain_hash IS NULL THEN 1 ELSE 0 END) AS u FROM audit_log").first<{ c: number; u: number | null }>();
  const unchained = total?.u ?? 0;
  if (!rows.results?.length) {
    return { checked: 0, unchained, status: (total?.c ?? 0) > 0 ? "ok" : "empty", message: "No chained rows to verify." };
  }
  // We fetched newest-first; verify oldest-first. The extra row a full window
  // carries, and - after a retention purge - the boundary row, are the same
  // thing: the anchor the first verified row chains from.
  const ordered = [...rows.results] as unknown as Array<Record<string, unknown>>;
  ordered.reverse();
  const anchor = ordered.shift()!;
  const seenHashes: string[] = ["", String(anchor.chain_hash)];
  let prevHash = String(anchor.chain_hash);
  for (const r of ordered) {
    const digest = await auditDigest(
      String(r.at),
      (r.actor_user_id as number | null) ?? null,
      (r.actor_upn as string | null) ?? null,
      String(r.action),
      (r.target as string | null) ?? null,
      (r.details as string | null) ?? null,
      (r.ip as string | null) ?? null,
      (r.user_agent as string | null) ?? null
    );
    const expected = await sha256Hex(`${prevHash}|${digest}`);
    const stored = String(r.chain_hash);
    if (stored !== expected) {
      // Mismatch: either the row was tampered with, or it is a fork - two
      // concurrent writes both chained off the same parent. A fork's stored
      // hash still verifies against some earlier chain hash.
      let fork = false;
      for (const h of seenHashes) {
        if (await sha256Hex(`${h}|${digest}`) === stored) { fork = true; break; }
      }
      return {
        checked: ordered.length,
        unchained,
        status: fork ? "fork" : "broken",
        at_id: Number(r.id),
        message: fork
          ? `Row ${r.id} shares a parent with an earlier row (concurrent writes).`
          : `Row ${r.id} fails verification - contents or predecessor hash were altered.`,
      };
    }
    seenHashes.push(stored);
    prevHash = stored;
  }
  return { checked: ordered.length, unchained, status: "ok" };
}

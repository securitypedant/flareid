import type { Env } from "../env.js";

/**
 * Atomic single-use claims.
 *
 * Workers KV deletes take up to ~60s to propagate, so `get` + `delete` cannot
 * make anything truly one-shot: a replay inside the window re-reads the value.
 * The claim marker lives in D1's rate_limits table instead - the INSERT ..
 * ON CONFLICT is atomic, and its cleanup sweep bounds the marker's life for
 * free (weeks - far past any credential's TTL).
 */

/** Marks a scope consumed. True for the first claimer, false for every replay. */
export async function markConsumed(env: Env, scope: string): Promise<boolean> {
  const seen = await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count`
  )
    .bind(`oneshot:${scope}`, Date.now())
    .first<{ count: number }>();
  return (seen?.count ?? 1) === 1;
}

/** True once markConsumed has claimed the scope - a read-only replay probe. */
export async function isConsumed(env: Env, scope: string): Promise<boolean> {
  return !!(await env.DB.prepare("SELECT 1 AS x FROM rate_limits WHERE key = ?").bind(`oneshot:${scope}`).first());
}

/** Reads and consumes a KV value: the first caller gets it, every replay gets null. */
export async function claimOnce(env: Env, kvKey: string): Promise<string | null> {
  const raw = await env.SESSIONS_KV.get(kvKey);
  if (raw === null) return null;
  if (!(await markConsumed(env, kvKey))) return null;
  await env.SESSIONS_KV.delete(kvKey);
  return raw;
}

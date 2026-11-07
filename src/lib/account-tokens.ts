import type { Env } from "../env.js";
import { randomToken, sha256Hex } from "./tokens.js";

export type AccountTokenPurpose = "reset" | "invite";

/** How long each kind of link works. A reset is a live credential, so it is short. */
export const ACCOUNT_TOKEN_TTL_SECONDS: Record<AccountTokenPurpose, number> = {
  reset: 60 * 60,
  invite: 7 * 24 * 60 * 60,
};

/**
 * Issues a single-use link token for a user, revoking any earlier unused one
 * for the same purpose - only the most recent email's link works. Returns the
 * raw token, which exists only in that email; the table holds its hash.
 */
export async function issueAccountToken(env: Env, userId: number, purpose: AccountTokenPurpose): Promise<string> {
  const token = randomToken(32);
  const now = new Date();
  await env.DB.batch([
    env.DB.prepare("UPDATE account_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL").bind(
      now.toISOString(),
      userId,
      purpose
    ),
    env.DB.prepare("INSERT INTO account_tokens (token_hash, user_id, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)").bind(
      await sha256Hex(token),
      userId,
      purpose,
      now.toISOString(),
      new Date(now.getTime() + ACCOUNT_TOKEN_TTL_SECONDS[purpose] * 1000).toISOString()
    ),
  ]);
  return token;
}

/** The user a still-valid token belongs to, without using it up - for rendering the form behind the link. */
export async function peekAccountToken(env: Env, token: string, purpose: AccountTokenPurpose): Promise<number | null> {
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const row = await env.DB.prepare(
    "SELECT user_id FROM account_tokens WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?"
  )
    .bind(await sha256Hex(token), purpose, new Date().toISOString())
    .first<{ user_id: number }>();
  return row?.user_id ?? null;
}

/** Uses a token up, atomically: of two racing requests, exactly one gets the user id. */
export async function consumeAccountToken(env: Env, token: string, purpose: AccountTokenPurpose): Promise<number | null> {
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const now = new Date().toISOString();
  const row = await env.DB.prepare(
    "UPDATE account_tokens SET used_at = ? WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id"
  )
    .bind(now, await sha256Hex(token), purpose, now)
    .first<{ user_id: number }>();
  return row?.user_id ?? null;
}

/** Invalidates every outstanding link for a user (password changed some other way, account disabled). */
export async function revokeAccountTokens(env: Env, userId: number): Promise<void> {
  await env.DB.prepare("UPDATE account_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL").bind(new Date().toISOString(), userId).run();
}

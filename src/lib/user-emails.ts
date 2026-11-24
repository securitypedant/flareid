import type { Env } from "../env.js";
import { isEmailAddress } from "./email.js";
import type { UserRow } from "./types.js";

/**
 * The user's full list of contact addresses (user_emails table). users.email
 * stays the denormalized primary - every existing read path (the LDAP mail
 * attribute, recovery links, email OTP, the SCIM primary entry) keeps working
 * without knowing this table exists.
 *
 * An address is unique across the whole directory: recovery-by-email has to
 * name exactly one account, and an HR system mailing the same address into
 * two people's records is a data bug worth surfacing rather than tolerating.
 */

export interface UserEmail {
  id: number;
  user_id: number;
  email: string;
  type: string;
  is_primary: number;
}

export interface UserEmailInput {
  value: string;
  type?: string;
  primary?: boolean;
}

export async function listUserEmails(env: Env, userId: number): Promise<UserEmail[]> {
  const { results } = await env.DB.prepare(
    "SELECT id, user_id, email, type, is_primary FROM user_emails WHERE user_id = ? ORDER BY is_primary DESC, id"
  ).bind(userId).all<UserEmail>();
  return results;
}

/** Every address for many users at once, keyed by user_id (admin list pages). */
export async function listUserEmailsFor(env: Env, userIds: number[]): Promise<Map<number, UserEmail[]>> {
  const map = new Map<number, UserEmail[]>();
  if (userIds.length === 0) return map;
  const { results } = await env.DB.prepare(
    `SELECT id, user_id, email, type, is_primary FROM user_emails WHERE user_id IN (${userIds.map(() => "?").join(",")}) ORDER BY user_id, is_primary DESC, id`
  ).bind(...userIds).all<UserEmail>();
  for (const row of results) {
    const list = map.get(row.user_id) ?? [];
    list.push(row);
    map.set(row.user_id, list);
  }
  return map;
}

/** The user an address belongs to (any slot - primary or alias). Null when none. */
export async function getUserByAnyEmail(env: Env, address: string): Promise<UserRow | null> {
  const email = address.trim().toLowerCase();
  return (
    (await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first<UserRow>()) ??
    (await env.DB.prepare("SELECT u.* FROM users u JOIN user_emails e ON e.user_id = u.id WHERE e.email = ?").bind(email).first<UserRow>()) ??
    null
  );
}

/** Callers turn this into their own 4xx - it is never an internal error. */
export class UserEmailError extends Error {}

/** Throws when an address is malformed or belongs to someone else (userId null = creating: no owner allowed). */
export async function assertEmailsUsable(env: Env, userId: number | null, emails: UserEmailInput[]): Promise<void> {
  for (const e of emails) {
    const addr = e.value.trim().toLowerCase();
    if (!isEmailAddress(addr)) throw new UserEmailError(`"${e.value}" is not a valid email address.`);
    const owner = await env.DB.prepare("SELECT user_id FROM user_emails WHERE email = ?").bind(addr).first<{ user_id: number }>();
    if (owner && owner.user_id !== userId) throw new UserEmailError(`"${addr}" already belongs to another account.`);
    // The two identifier namespaces must not overlap: an alias spelled like
    // someone else's sign-in name would make resolvers ambiguous. (username
    // holds no '@', so the clause would be dead weight.)
    const clash = await env.DB.prepare("SELECT id FROM users WHERE (upn = ? OR email = ?) AND id != ?").bind(addr, addr, userId ?? -1).first<{ id: number }>();
    if (clash) throw new UserEmailError(`"${addr}" already belongs to another account.`);
  }
}

/**
 * Replaces the user's address list and mirrors the primary into users.email.
 * First entry is primary unless one is marked; the primary is always present
 * as a row too, so the table is the complete list, not just aliases.
 * Returns whether the primary changed (callers revoke account tokens then -
 * links already sent must not outlive a correction).
 */
export async function setUserEmails(env: Env, userId: number, emails: UserEmailInput[]): Promise<boolean> {
  const clean: { email: string; type: string; is_primary: number }[] = [];
  const seen = new Set<string>();
  for (const e of emails) {
    const addr = String(e.value ?? "").trim().toLowerCase();
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    clean.push({ email: addr, type: (e.type ?? "work").trim() || "work", is_primary: 0 });
  }
  if (clean.length > 0) {
    const primaryIdx = emails.findIndex((e) => e.primary && seen.has(String(e.value ?? "").trim().toLowerCase()));
    clean[primaryIdx >= 0 ? primaryIdx : 0]!.is_primary = 1;
  }

  await assertEmailsUsable(env, userId, clean.map((e) => ({ value: e.email })));

  const previous = (await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(userId).first<{ email: string | null }>())?.email ?? null;
  const primary = clean.find((e) => e.is_primary === 1)?.email ?? null;
  const now = new Date().toISOString();
  const stmts = [
    env.DB.prepare("DELETE FROM user_emails WHERE user_id = ?").bind(userId),
    ...clean.map((e) =>
      env.DB.prepare("INSERT INTO user_emails (user_id, email, type, is_primary, created_at) VALUES (?, ?, ?, ?, ?)").bind(userId, e.email, e.type, e.is_primary, now)
    ),
    env.DB.prepare("UPDATE users SET email = ? WHERE id = ?").bind(primary, userId),
  ];
  await env.DB.batch(stmts);
  return previous !== primary;
}

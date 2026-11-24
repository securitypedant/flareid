/**
 * The user's listed phone numbers (user_phones table) - the phone twin of
 * user-emails.ts. Any listed number resolves the account at sign-in, and a
 * phone-identifier account's upn itself is a number that lives there too.
 *
 * Numbers are stored E.164 ('+' required, like the identifier grammar) and are
 * unique across the whole directory for the same reason addresses are:
 * sign-in by number has to name exactly one account.
 */

import type { Env } from "../env.js";
import type { UserRow } from "./types.js";

export interface UserPhone {
  id: number;
  user_id: number;
  phone: string;
  type: string;
  is_primary: number;
}

export interface UserPhoneInput {
  value: string;
  type?: string;
  primary?: boolean;
}

/** Normalizes input to E.164: strips spaces/dashes/parens, '+' required. Null when invalid. */
export function normalizePhone(raw: string): string | null {
  const digits = raw.trim().replace(/[^\d+]/g, "");
  return /^\+[1-9]\d{6,14}$/.test(digits) ? digits : null;
}

export async function listUserPhones(env: Env, userId: number): Promise<UserPhone[]> {
  const { results } = await env.DB.prepare(
    "SELECT id, user_id, phone, type, is_primary FROM user_phones WHERE user_id = ? ORDER BY is_primary DESC, id"
  ).bind(userId).all<UserPhone>();
  return results;
}

/** The user a number belongs to (any slot - primary or alias). Null when none. */
export async function getUserByAnyPhone(env: Env, number: string): Promise<UserRow | null> {
  const phone = normalizePhone(number);
  if (!phone) return null;
  return (
    (await env.DB.prepare("SELECT u.* FROM users u JOIN user_phones p ON p.user_id = u.id WHERE p.phone = ?").bind(phone).first<UserRow>()) ?? null
  );
}

/** Callers turn this into their own 4xx - it is never an internal error. */
export class UserPhoneError extends Error {}

/** Throws when a number is malformed or belongs to someone else (userId null = creating: no owner allowed). */
export async function assertPhonesUsable(env: Env, userId: number | null, phones: UserPhoneInput[]): Promise<void> {
  for (const p of phones) {
    const num = normalizePhone(p.value);
    if (!num) throw new UserPhoneError(`"${p.value}" is not a valid phone number (use international format, e.g. +15551234567).`);
    const owner = await env.DB.prepare("SELECT user_id FROM user_phones WHERE phone = ?").bind(num).first<{ user_id: number }>();
    if (owner && owner.user_id !== userId) throw new UserPhoneError(`"${num}" already belongs to another account.`);
    // The two identifier namespaces must not overlap: a listed number spelled
    // like another account's sign-in name would resolve both ways.
    const clash = await env.DB.prepare("SELECT id FROM users WHERE upn = ? AND id != ?").bind(num, userId ?? -1).first<{ id: number }>();
    if (clash) throw new UserPhoneError(`"${num}" is another account's sign-in name.`);
  }
}

/**
 * Replaces the user's number list. First entry is primary unless one is
 * marked. Returns whether the set changed.
 */
export async function setUserPhones(env: Env, userId: number, phones: UserPhoneInput[]): Promise<void> {
  const clean: { phone: string; type: string; is_primary: number }[] = [];
  const seen = new Set<string>();
  for (const p of phones) {
    const num = normalizePhone(String(p.value ?? ""));
    if (!num || seen.has(num)) continue;
    seen.add(num);
    clean.push({ phone: num, type: (p.type ?? "mobile").trim() || "mobile", is_primary: 0 });
  }
  if (clean.length > 0) {
    const primaryIdx = phones.findIndex((p) => p.primary && seen.has(normalizePhone(String(p.value ?? "")) ?? ""));
    clean[primaryIdx >= 0 ? primaryIdx : 0]!.is_primary = 1;
  }

  await assertPhonesUsable(env, userId, clean.map((p) => ({ value: p.phone })));

  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM user_phones WHERE user_id = ?").bind(userId),
    ...clean.map((p) =>
      env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, created_at) VALUES (?, ?, ?, ?, ?)").bind(userId, p.phone, p.type, p.is_primary, now)
    ),
  ]);
}

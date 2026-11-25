/**
 * Self-service alias verification (docs/identifiers.md): a user may add an
 * email address or phone number to their own account, but the row starts
 * unverified - it reserves the spelling against other accounts yet resolves
 * nothing - until a six-digit code sent to the address/number comes back.
 * Codes live only as SHA-256 hashes in KV (same pattern as email-otp.ts),
 * expire after ALIAS_VERIFY_MINUTES, and five wrong guesses invalidate the
 * pending code.
 *
 * Emails go through the configured sender; numbers need an SMS provider
 * (lib/sms.ts) - without one, phone adds fail with a clear error rather than
 * minting a sign-in door nobody proved.
 */

import type { Env } from "../env.js";
import type { UserRow } from "./types.js";
import { isEmailAddress, sendEmail } from "./email.js";
import { buildEmail } from "./email-templates.js";
import { brandFor } from "./brands.js";
import { sendSms } from "./sms.js";
import { normalizePhone } from "./user-phones.js";

export const ALIAS_VERIFY_MINUTES = 10;
const MAX_WRONG_ATTEMPTS = 5;
const SENDS_PER_WINDOW = 5;
const SEND_WINDOW_SECONDS = 15 * 60;

export type AliasKind = "email" | "phone";

export class AliasVerifyError extends Error {}

/** Detect the alias kind from raw input: '+/digit-prefixed -> phone, else email. */
export function aliasKindFor(raw: string): AliasKind | null {
  const s = raw.trim();
  if (!s) return null;
  if (normalizePhone(s)) return "phone";
  if (isEmailAddress(s.toLowerCase())) return "email";
  return null;
}

/** Normalizes to the stored spelling (lowercased address, E.164 number). Null when invalid for its kind. */
export function normalizeAlias(kind: AliasKind, raw: string): string | null {
  return kind === "phone" ? normalizePhone(raw) : isEmailAddress(raw.trim().toLowerCase()) ? raw.trim().toLowerCase() : null;
}

const kvKey = (userId: number, kind: AliasKind, value: string) => `aliasv:${userId}:${kind}:${encodeURIComponent(value)}`;
const sendKey = (userId: number) => `aliasv_n:${userId}`;

interface StoredCode {
  hash: string;
  attempts: number;
}

async function hashCode(userId: number, kind: AliasKind, value: string, code: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`flareid alias verify v1\n${userId}\n${kind}\n${value}\n${code}`));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomCode(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000;
  return String(n).padStart(6, "0");
}

export type SendOutcome = { ok: true; resent?: boolean } | { ok: false; error: string };

/** What an add/resend does: owns it unverified -> resend; owns it verified -> error; free -> claim row + send. */
export async function startAliasVerification(env: Env, user: UserRow, kind: AliasKind, rawValue: string): Promise<SendOutcome> {
  const value = normalizeAlias(kind, rawValue);
  if (!value) {
    return { ok: false, error: kind === "phone" ? `"${rawValue}" is not a valid phone number (use international format, e.g. +15551234567).` : `"${rawValue}" is not a valid email address.` };
  }

  // A pending code uses up one of the user's send slots even when it bounces.
  const rate = await env.SESSIONS_KV.get<{ count: number; resetAt: number }>(sendKey(user.id), "json");
  if (rate && rate.resetAt > Date.now() && rate.count >= SENDS_PER_WINDOW) {
    return { ok: false, error: `Too many codes requested - wait ${Math.ceil((rate.resetAt - Date.now()) / 60000)} minutes and try again.` };
  }

  const table = kind === "phone" ? "user_phones" : "user_emails";
  const col = kind === "phone" ? "phone" : "email";
  const mine = await env.DB.prepare(`SELECT id, verified, is_primary FROM ${table} WHERE user_id = ? AND ${col} = ?`).bind(user.id, value).first<{ id: number; verified: number; is_primary: number }>();
  if (mine?.verified) return { ok: false, error: "That is already on your account." };
  const other = await env.DB.prepare(`SELECT user_id FROM ${table} WHERE ${col} = ? AND user_id != ?`).bind(value, user.id).first<{ user_id: number }>();
  if (other) return { ok: false, error: "That already belongs to another account." };
  // An alias spelled like any account's sign-in name collides with it.
  const nameClash = await env.DB.prepare(`SELECT id FROM users WHERE (upn = ? OR email = ?) AND id != ?`).bind(value, value, user.id).first<{ id: number }>();
  if (nameClash) return { ok: false, error: "That is another account's sign-in name." };

  const code = randomCode();
  const outcome =
    kind === "phone"
      ? await sendSms(env, value, `${code} is your verification code.`)
      : await sendEmail(env, await buildEmail(env, "alias_verify", await brandFor(env, { upn: user.upn }), { name: user.display_name || user.username, code, minutes: String(ALIAS_VERIFY_MINUTES), address: value }).then((e) => ({ ...e, to: value })));
  if (!outcome.ok) return { ok: false, error: outcome.error };

  const now = new Date().toISOString();
  if (!mine) {
    await env.DB.prepare(`INSERT INTO ${table} (user_id, ${col}, type, is_primary, verified, created_at) VALUES (?, ?, ?, 0, 0, ?)`).bind(user.id, value, kind === "phone" ? "mobile" : "work", now).run();
  }
  await env.SESSIONS_KV.put(kvKey(user.id, kind, value), JSON.stringify({ hash: await hashCode(user.id, kind, value, code), attempts: 0 } satisfies StoredCode), { expirationTtl: ALIAS_VERIFY_MINUTES * 60 });
  await env.SESSIONS_KV.put(sendKey(user.id), JSON.stringify({ count: (rate && rate.resetAt > Date.now() ? rate.count : 0) + 1, resetAt: rate && rate.resetAt > Date.now() ? rate.resetAt : Date.now() + SEND_WINDOW_SECONDS * 1000 }), { expirationTtl: SEND_WINDOW_SECONDS });
  return { ok: true, resent: Boolean(mine) };
}

export async function verifyAliasCode(env: Env, user: UserRow, kind: AliasKind, rawValue: string, code: string): Promise<"ok" | "wrong" | "locked" | "expired"> {
  const value = normalizeAlias(kind, rawValue);
  if (!value) return "expired";
  const key = kvKey(user.id, kind, value);
  const stored = await env.SESSIONS_KV.get<StoredCode>(key, "json");
  if (!stored) return "expired";
  if (stored.attempts >= MAX_WRONG_ATTEMPTS) return "locked";
  if ((await hashCode(user.id, kind, value, code.trim())) !== stored.hash) {
    await env.SESSIONS_KV.put(key, JSON.stringify({ ...stored, attempts: stored.attempts + 1 } satisfies StoredCode), { expirationTtl: ALIAS_VERIFY_MINUTES * 60 });
    return stored.attempts + 1 >= MAX_WRONG_ATTEMPTS ? "locked" : "wrong";
  }
  await env.SESSIONS_KV.delete(key);
  const table = kind === "phone" ? "user_phones" : "user_emails";
  const col = kind === "phone" ? "phone" : "email";
  await env.DB.prepare(`UPDATE ${table} SET verified = 1 WHERE user_id = ? AND ${col} = ?`).bind(user.id, value).run();
  return "ok";
}

/** Removes an alias row (self-service). Primary rows stay - reassignment is an admin job. */
export async function deleteAlias(env: Env, user: UserRow, kind: AliasKind, rawValue: string): Promise<void> {
  const value = normalizeAlias(kind, rawValue);
  if (!value) throw new AliasVerifyError("Not a valid address or number.");
  const table = kind === "phone" ? "user_phones" : "user_emails";
  const col = kind === "phone" ? "phone" : "email";
  const row = await env.DB.prepare(`SELECT id, is_primary FROM ${table} WHERE user_id = ? AND ${col} = ?`).bind(user.id, value).first<{ id: number; is_primary: number }>();
  if (!row) return;
  if (row.is_primary) throw new AliasVerifyError("The primary entry can't be removed here - ask an administrator.");
  await env.SESSIONS_KV.delete(kvKey(user.id, kind, value));
  await env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(row.id).run();
}

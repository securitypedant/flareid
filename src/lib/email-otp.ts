import type { Env } from "../env.js";
import { isFactorUsable } from "./auth-policy.js";
import { recipientFor, sendEmail } from "./email.js";
import { buildEmail } from "./email-templates.js";
import { recordRateAttempt } from "./rate-limit.js";
import type { UserRow } from "./types.js";

/**
 * Email one-time codes: six random digits, sent with the "Sign-in code"
 * template, stored only as a SHA-256 hash in KV under the scope they were
 * issued for - a pending sign-in (its mfa id) or a session enrolling or
 * turning the factor off. A code works once, for EMAIL_OTP_MINUTES, and five
 * wrong guesses invalidate it. Sending is limited per user. The code itself
 * never reaches the audit log or any other log.
 */
export const EMAIL_OTP_MINUTES = 10;
const MAX_WRONG_ATTEMPTS = 5;
const SENDS_PER_WINDOW = 5;
const SEND_WINDOW_MINUTES = 15;

/** The rate-limit bucket for sends, keyed on the user id (also cleared on user deletion). */
export function emailOtpSendKey(userId: number): string {
  return `email_otp:send:${userId}`;
}

export type EmailOtpPurpose = "login" | "enrol" | "disable" | "stepup";

interface StoredCode {
  hash: string;
  userId: number;
  purpose: EmailOtpPurpose;
  attempts: number;
  expiresAt: number;
}

/** Whether email codes can be used at all: the factor is switched on and email can be sent. */
export function emailOtpAvailable(env: Env): Promise<boolean> {
  return isFactorUsable(env, "email_otp");
}

/** Whether this user signs in with email codes right now. */
export async function userHasEmailOtp(env: Env, user: { email_otp_enabled: number }): Promise<boolean> {
  return Boolean(user.email_otp_enabled) && (await emailOtpAvailable(env));
}

export const loginScope = (mfaId: string) => `login:${mfaId}`;
export const accountScope = (sessionId: string) => `acct:${sessionId}`;
const kvKey = (scope: string) => `emailotp:${scope}`;

async function hashCode(scope: string, code: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`flareid email otp v1\n${scope}\n${code}`));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Six uniformly random digits (rejection sampling: 4,294,000,000 is a multiple of 10^6). */
function randomCode(): string {
  const buf = new Uint32Array(1);
  let n: number;
  do {
    crypto.getRandomValues(buf);
    n = buf[0]!;
  } while (n >= 4_294_000_000);
  return String(n % 1_000_000).padStart(6, "0");
}

/** A recipient address with most of the local part hidden, for pages a password alone can reach. */
export function maskEmail(address: string): string {
  const at = address.lastIndexOf("@");
  if (at < 1) return address;
  const local = address.slice(0, at);
  return `${local[0]}${"*".repeat(Math.min(Math.max(local.length - 1, 2), 8))}${address.slice(at)}`;
}

export type SendOutcome = { ok: true; to: string } | { ok: false; reason: "rate_limited" | "send_failed"; error?: string };

/**
 * Issues a fresh code for the scope (replacing any earlier one) and emails it.
 * Counts against the user's send budget before anything is sent.
 */
export async function sendEmailOtp(env: Env, user: UserRow, scope: string, purpose: EmailOtpPurpose, appName: string): Promise<SendOutcome> {
  if (await recordRateAttempt(env, emailOtpSendKey(user.id), SENDS_PER_WINDOW, SEND_WINDOW_MINUTES)) return { ok: false, reason: "rate_limited" };
  const code = randomCode();
  const record: StoredCode = { hash: await hashCode(scope, code), userId: user.id, purpose, attempts: 0, expiresAt: Date.now() + EMAIL_OTP_MINUTES * 60_000 };
  await env.SESSIONS_KV.put(kvKey(scope), JSON.stringify(record), { expirationTtl: EMAIL_OTP_MINUTES * 60 });
  const to = recipientFor(user);
  const result = await sendEmail(env, {
    to,
    ...(await buildEmail(env, "email_otp", { app_name: appName, name: user.display_name || user.username, code, minutes: String(EMAIL_OTP_MINUTES) })),
  });
  if (!result.ok) {
    await env.SESSIONS_KV.delete(kvKey(scope));
    return { ok: false, reason: "send_failed", error: result.error };
  }
  return { ok: true, to };
}

/**
 * Checks a code against the scope's current one:
 *  - "ok": it matched, and is now used up;
 *  - "wrong": it did not match (counted);
 *  - "locked": it did not match and that was the last allowed guess - the code is gone;
 *  - "expired": there is no current code for this scope, user and purpose (never sent, used, expired or invalidated).
 */
export async function verifyEmailOtp(env: Env, scope: string, userId: number, purpose: EmailOtpPurpose, code: string): Promise<"ok" | "wrong" | "locked" | "expired"> {
  const raw = await env.SESSIONS_KV.get(kvKey(scope));
  const record = raw ? (JSON.parse(raw) as StoredCode) : null;
  if (!record || record.userId !== userId || record.purpose !== purpose || Date.now() >= record.expiresAt || record.attempts >= MAX_WRONG_ATTEMPTS) {
    return "expired";
  }
  const submitted = code.replace(/\s+/g, "").slice(0, 12);
  if (/^\d{6}$/.test(submitted) && (await hashCode(scope, submitted)) === record.hash) {
    await env.SESSIONS_KV.delete(kvKey(scope));
    return "ok";
  }
  const attempts = record.attempts + 1;
  if (attempts >= MAX_WRONG_ATTEMPTS) {
    await env.SESSIONS_KV.delete(kvKey(scope));
    return "locked";
  }
  const ttl = Math.max(60, Math.ceil((record.expiresAt - Date.now()) / 1000));
  await env.SESSIONS_KV.put(kvKey(scope), JSON.stringify({ ...record, attempts }), { expirationTtl: ttl });
  return "wrong";
}

/** Drops any outstanding code for the scope. */
export async function discardEmailOtp(env: Env, scope: string): Promise<void> {
  await env.SESSIONS_KV.delete(kvKey(scope));
}

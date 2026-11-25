import type { Env } from "../env.js";
import { isFactorUsable } from "./auth-policy.js";
import { brandFor } from "./brands.js";
import { issueOtpCode, verifyOtpCode, type EmailOtpPurpose } from "./email-otp.js";
import { recordRateAttempt } from "./rate-limit.js";
import { getSmsConfig, sendSms, smsConfigured } from "./sms.js";
import type { UserRow } from "./types.js";

/**
 * SMS one-time codes: the email-code machinery (email-otp.ts - hashed in KV,
 * one use, five guesses, per-user send budget) delivered by text to the
 * person's verified phone number through the configured provider (sms.ts).
 *
 * Carriers filter A2P traffic that repeats one fixed body, so the wording
 * rotates between several phrasings; every one names the app, carries the
 * code and its lifetime, and ends with the WebOTP origin-bound line
 * ("@host #code") that lets phones offer the code for autofill on this site
 * only.
 */
export const SMS_OTP_MINUTES = 10;
const SENDS_PER_WINDOW = 5;
const SEND_WINDOW_MINUTES = 15;

export function smsOtpSendKey(userId: number): string {
  return `sms_otp:send:${userId}`;
}

export async function smsReady(env: Env): Promise<boolean> {
  return smsConfigured(await getSmsConfig(env));
}

/** Whether SMS codes can be used at all: the factor is switched on and a provider is configured. */
export function smsOtpAvailable(env: Env): Promise<boolean> {
  return isFactorUsable(env, "sms_otp");
}

/**
 * The number codes go to: the primary verified phone alias, else the first
 * verified one, else a phone-form sign-in name (admin-written, so attested).
 */
export async function routablePhone(env: Env, user: Pick<UserRow, "id" | "upn">): Promise<string | null> {
  const row = await env.DB.prepare("SELECT phone FROM user_phones WHERE user_id = ? AND verified = 1 ORDER BY is_primary DESC, id LIMIT 1").bind(user.id).first<{ phone: string }>();
  if (row) return row.phone;
  return /^\+[1-9]\d{6,14}$/.test(user.upn) ? user.upn : null;
}

/** Whether this user signs in with SMS codes right now. */
export async function userHasSmsOtp(env: Env, user: Pick<UserRow, "id" | "upn" | "sms_otp_enabled">): Promise<boolean> {
  if (!user.sms_otp_enabled) return false;
  if (!(await routablePhone(env, user))) return false;
  return smsOtpAvailable(env);
}

/** "+1•••••••4567" - enough to recognise your own number, on pages a password alone can reach. */
export function maskPhone(phone: string): string {
  return phone.length <= 6 ? phone : `${phone.slice(0, 2)}${"•".repeat(Math.max(phone.length - 6, 3))}${phone.slice(-4)}`;
}

const SIGN_IN_WORDINGS = [
  "{code} is your {app} sign-in code. It expires in {minutes} minutes.",
  "Your {app} verification code is {code}. Valid for {minutes} min.",
  "{app}: enter {code} to finish signing in. Don't share this code with anyone.",
  "Use {code} to sign in to {app}. This code expires in {minutes} minutes.",
  "{code} - your one-time {app} code. {app} will never ask you for it.",
  "Sign-in code for {app}: {code}. It works once, for {minutes} minutes.",
];

const VERIFY_WORDINGS = [
  "{code} is your {app} code to confirm this number. It expires in {minutes} minutes.",
  "{app}: use {code} to verify this phone number. Valid for {minutes} min.",
  "Confirm this number on {app} with code {code}. Don't share it.",
  "Your {app} phone verification code: {code}. It works once.",
];

/**
 * A code text in one of several phrasings. `pick` is injectable for tests;
 * by default it's uniform random.
 */
export function otpSmsText(opts: { app: string; code: string; minutes: number; host?: string; purpose: "signin" | "verify"; pick?: (n: number) => number }): string {
  const list = opts.purpose === "verify" ? VERIFY_WORDINGS : SIGN_IN_WORDINGS;
  const i = (opts.pick ?? ((n) => crypto.getRandomValues(new Uint32Array(1))[0]! % n))(list.length);
  const body = list[i]!.replace(/\{code\}/g, opts.code).replace(/\{app\}/g, opts.app).replace(/\{minutes\}/g, String(opts.minutes));
  return opts.host ? `${body}\n\n@${opts.host} #${opts.code}` : body;
}

export type SmsSendOutcome = { ok: true; to: string } | { ok: false; reason: "rate_limited" | "send_failed" | "no_phone"; error?: string };

export async function sendSmsOtp(env: Env, user: UserRow, scope: string, purpose: EmailOtpPurpose): Promise<SmsSendOutcome> {
  const to = await routablePhone(env, user);
  if (!to) return { ok: false, reason: "no_phone" };
  if (await recordRateAttempt(env, smsOtpSendKey(user.id), SENDS_PER_WINDOW, SEND_WINDOW_MINUTES)) return { ok: false, reason: "rate_limited" };
  const code = await issueOtpCode(env, "sms", scope, user.id, purpose, SMS_OTP_MINUTES);
  const brand = await brandFor(env, { upn: user.upn });
  const host = env.ISSUER_URL ? new URL(env.ISSUER_URL).hostname : undefined;
  const result = await sendSms(env, to, otpSmsText({ app: brand.appName, code, minutes: SMS_OTP_MINUTES, host, purpose: "signin" }));
  if (!result.ok) return { ok: false, reason: "send_failed", error: result.error };
  return { ok: true, to };
}

export function verifySmsOtp(env: Env, scope: string, userId: number, purpose: EmailOtpPurpose, code: string) {
  return verifyOtpCode(env, "sms", scope, userId, purpose, code);
}

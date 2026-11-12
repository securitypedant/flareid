import type { Env } from "../env.js";
import { getSetting, setSetting } from "./settings.js";
import type { UserRow } from "./types.js";

/**
 * Outbound email, through Cloudflare Email Sending's `send_email` binding.
 *
 * Optional: a deployment without the binding, or without a From address set
 * in Admin -> Integrations -> Email, simply has no email features - the
 * "Forgot password?" link and the invitation buttons do not appear, and the
 * admin flows fall back to showing a temporary password as before.
 */
export interface EmailSettings {
  fromAddress: string;
  fromName: string;
}

export async function getEmailSettings(env: Env): Promise<EmailSettings> {
  const [fromAddress, fromName] = await Promise.all([getSetting(env, "email_from_address"), getSetting(env, "email_from_name")]);
  return { fromAddress: fromAddress ?? "", fromName: fromName ?? "" };
}

const EMAIL_PATTERN = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;

export function isEmailAddress(value: string): boolean {
  return value.length <= 254 && EMAIL_PATTERN.test(value);
}

export async function setEmailSettings(env: Env, settings: EmailSettings): Promise<EmailSettings> {
  const clean = { fromAddress: settings.fromAddress.trim().toLowerCase(), fromName: settings.fromName.trim().slice(0, 80) };
  if (clean.fromAddress && !isEmailAddress(clean.fromAddress)) throw new RangeError("The From address is not a valid email address.");
  await Promise.all([setSetting(env, "email_from_address", clean.fromAddress), setSetting(env, "email_from_name", clean.fromName)]);
  return clean;
}

/** The on/off switch, kept apart from the From address so switching off loses no configuration. */
export async function isEmailEnabled(env: Env): Promise<boolean> {
  return (await getSetting(env, "email_enabled")) !== "false";
}
export async function setEmailEnabled(env: Env, on: boolean): Promise<void> {
  await setSetting(env, "email_enabled", on ? "true" : "false");
}

export async function isEmailConfigured(env: Env): Promise<boolean> {
  return Boolean(env.EMAIL) && Boolean((await getEmailSettings(env)).fromAddress) && (await isEmailEnabled(env));
}

/** Where email for this account goes: its contact address if it has one, else its UPN. */
export function recipientFor(user: Pick<UserRow, "upn" | "email">): string {
  return user.email || user.upn;
}

export interface OutboundEmail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export type SendResult = { ok: true; messageId: string } | { ok: false; error: string };

export async function sendEmail(env: Env, message: OutboundEmail): Promise<SendResult> {
  const { fromAddress, fromName } = await getEmailSettings(env);
  if (!env.EMAIL || !fromAddress) return { ok: false, error: "Email is not configured." };
  if (!(await isEmailEnabled(env))) return { ok: false, error: "Email is switched off (Admin -> Integrations -> Email)." };
  try {
    const result = await env.EMAIL.send({
      to: message.to,
      from: fromName ? { email: fromAddress, name: fromName } : fromAddress,
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
    return { ok: true, messageId: result.messageId };
  } catch (error) {
    const e = error as { code?: string; message?: string };
    return { ok: false, error: `${e.code ?? "error"}: ${e.message ?? String(error)}` };
  }
}

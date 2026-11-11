import type { Env } from "../env.js";
import { escapeHtml } from "./html.js";
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

/** One plain, readable layout for every email: a heading, a paragraph, a button, and the link as text. */
function linkEmail(opts: { appName: string; heading: string; body: string; action: string; url: string; footer: string }): { text: string; html: string } {
  const text = `${opts.heading}\n\n${opts.body}\n\n${opts.action}: ${opts.url}\n\n${opts.footer}\n`;
  const html = `<!doctype html><html><body style="margin:0;padding:24px;background:#f6f7f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#0f172a;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:28px;">
    <p style="margin:0 0 16px;font-weight:700;font-size:18px;">${escapeHtml(opts.appName)}</p>
    <h1 style="margin:0 0 12px;font-size:20px;">${escapeHtml(opts.heading)}</h1>
    <p style="margin:0 0 20px;line-height:1.5;color:#334155;">${escapeHtml(opts.body)}</p>
    <p style="margin:0 0 20px;"><a href="${escapeHtml(opts.url)}" style="display:inline-block;background:#f6821f;color:#fff;text-decoration:none;font-weight:600;padding:10px 18px;border-radius:8px;">${escapeHtml(opts.action)}</a></p>
    <p style="margin:0 0 6px;font-size:13px;color:#64748b;">Or paste this link into your browser:</p>
    <p style="margin:0 0 20px;font-size:13px;word-break:break-all;"><a href="${escapeHtml(opts.url)}" style="color:#f6821f;">${escapeHtml(opts.url)}</a></p>
    <p style="margin:0;font-size:13px;color:#64748b;">${escapeHtml(opts.footer)}</p>
  </div></body></html>`;
  return { text, html };
}

export function passwordResetEmail(appName: string, url: string): Omit<OutboundEmail, "to"> {
  return {
    subject: `Reset your ${appName} password`,
    ...linkEmail({
      appName,
      heading: "Reset your password",
      body: `Someone - hopefully you - asked to reset the password for your ${appName} account. The link works once, for the next hour.`,
      action: "Choose a new password",
      url,
      footer: "If you didn't ask for this, ignore this email: your password stays the same.",
    }),
  };
}

export function invitationEmail(appName: string, displayName: string, url: string): Omit<OutboundEmail, "to"> {
  return {
    subject: `You've been invited to ${appName}`,
    ...linkEmail({
      appName,
      heading: `Welcome, ${displayName}`,
      body: `An administrator has set up a ${appName} account for you. Choose a password to activate it. The link works once, for the next 7 days.`,
      action: "Activate your account",
      url,
      footer: "If you weren't expecting this, you can ignore this email.",
    }),
  };
}

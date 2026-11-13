import type { Env } from "../env.js";
import { issueAccountToken } from "./account-tokens.js";
import { recipientFor, sendEmail, type SendResult } from "./email.js";
import { buildEmail } from "./email-templates.js";
import { brandFor } from "./brands.js";
import type { UserRow } from "./types.js";

/**
 * The two account emails, issued the same way from every entry point: the
 * admin console, the provisioning API and the self-service recovery form.
 * Each is in the person's brand (their UPN's domain - brands.ts).
 * Links point at ISSUER_URL - the public hostname - never at whatever Host
 * header a request arrived with, so a forged Host cannot redirect a reset link.
 */
export async function sendInvitation(env: Env, user: UserRow): Promise<SendResult> {
  const token = await issueAccountToken(env, user.id, "invite");
  const brand = await brandFor(env, { upn: user.upn });
  return sendEmail(env, { to: recipientFor(user), ...(await buildEmail(env, "invitation", brand, { name: user.display_name || user.username }, `${env.ISSUER_URL}/invite/${token}`)) });
}

export async function sendPasswordReset(env: Env, user: UserRow): Promise<SendResult> {
  const token = await issueAccountToken(env, user.id, "reset");
  const brand = await brandFor(env, { upn: user.upn });
  return sendEmail(env, { to: recipientFor(user), ...(await buildEmail(env, "password_reset", brand, { name: user.display_name || user.username }, `${env.ISSUER_URL}/reset-password/${token}`)) });
}

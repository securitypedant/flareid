import type { Env } from "../env.js";
import { issueAccountToken } from "./account-tokens.js";
import { invitationEmail, passwordResetEmail, recipientFor, sendEmail, type SendResult } from "./email.js";
import { getAppName } from "./settings.js";
import type { UserRow } from "./types.js";

/**
 * The two account emails, issued the same way from every entry point: the
 * admin console, the provisioning API and the self-service recovery form.
 * Links point at ISSUER_URL - the public hostname - never at whatever Host
 * header a request arrived with, so a forged Host cannot redirect a reset link.
 */
export async function sendInvitation(env: Env, user: UserRow): Promise<SendResult> {
  const token = await issueAccountToken(env, user.id, "invite");
  const appName = await getAppName(env);
  return sendEmail(env, { to: recipientFor(user), ...invitationEmail(appName, user.display_name || user.username, `${env.ISSUER_URL}/invite/${token}`) });
}

export async function sendPasswordReset(env: Env, user: UserRow): Promise<SendResult> {
  const token = await issueAccountToken(env, user.id, "reset");
  const appName = await getAppName(env);
  return sendEmail(env, { to: recipientFor(user), ...passwordResetEmail(appName, `${env.ISSUER_URL}/reset-password/${token}`) });
}

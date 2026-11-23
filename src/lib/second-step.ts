import type { Env } from "../env.js";
import { isAdministrator, isFactorEnabled, userHasPasskey } from "./auth-policy.js";
import { hasUnusedBackupCodes } from "./backup-codes.js";
import { userHasEmailOtp } from "./email-otp.js";
import { userHasSecurityQuestions } from "./security-questions.js";
import type { MfaFactors } from "./login-views.js";
import type { UserRow } from "./types.js";

/** The second-step methods this user can use now: enrolled, and switched on by the administrator. */
export async function secondStepFactors(env: Env, user: UserRow): Promise<MfaFactors> {
  const [totpOn, passkeyOn, backupOn, emailOtp, securityQuestions, admin] = await Promise.all([
    isFactorEnabled(env, "totp"),
    isFactorEnabled(env, "passkey"),
    isFactorEnabled(env, "backup_codes"),
    userHasEmailOtp(env, user),
    userHasSecurityQuestions(env, user),
    isAdministrator(env, user.id),
  ]);
  return {
    totp: Boolean(user.mfa_enabled) && totpOn,
    passkey: passkeyOn && (await userHasPasskey(env, user.id)),
    backupCodes: backupOn && (await hasUnusedBackupCodes(env, user.id)),
    emailOtp,
    // Never offered to an administrator: too weak to be their second factor.
    securityQuestions: securityQuestions && !admin,
  };
}

/** Whether any second-step method is usable - the gate for an app's require_mfa step-up. */
export async function hasSecondStep(env: Env, user: UserRow): Promise<boolean> {
  const f = await secondStepFactors(env, user);
  return f.totp || f.passkey || Boolean(f.backupCodes) || Boolean(f.emailOtp) || Boolean(f.securityQuestions);
}

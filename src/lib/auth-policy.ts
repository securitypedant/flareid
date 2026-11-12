import type { Env } from "../env.js";
import { getUserGroupNames } from "./db.js";
import { isEmailConfigured } from "./email.js";
import { getSetting, setSetting } from "./settings.js";

/**
 * Authentication policies and factors.
 *
 * A policy says what a person must present: "password" (a password, or a
 * passkey) or "mfa" (a password plus a second factor, or a passkey, which is
 * multi-factor on its own). Policies are assigned to groups; the matching one
 * with the lowest priority number wins, otherwise the default applies.
 *
 * Factors are the second-factor methods the instance offers: authenticator
 * app (TOTP, with backup codes), passkeys and email one-time codes. The list
 * is the extension point for further methods.
 */

export type Requirement = "password" | "mfa";

export interface AuthPolicyRow {
  id: number;
  name: string;
  description: string;
  requirement: Requirement;
  priority: number;
  is_default: number;
  created_at: string;
}

export const FACTORS = [
  { key: "totp", label: "Authenticator app", description: "Six-digit codes from an app such as 1Password, Google Authenticator or Authy, with single-use backup codes.", available: true },
  { key: "passkey", label: "Passkeys", description: "WebAuthn credentials on a device or security key. Multi-factor on their own, and can replace the password.", available: true },
  { key: "email_otp", label: "Email one-time code", description: "A six-digit code sent to the user's email address, using the Sign-in code email template. Needs email to be configured.", available: true },
  { key: "security_questions", label: "Security questions", description: "Answers chosen by the user at enrolment.", available: false },
] as const;
export type FactorKey = "totp" | "passkey" | "email_otp";
export const FACTOR_KEYS: readonly FactorKey[] = ["totp", "passkey", "email_otp"];

export function isFactorKey(key: string): key is FactorKey {
  return (FACTOR_KEYS as readonly string[]).includes(key);
}

/**
 * The administrator's switch for a factor. TOTP and passkeys are on unless
 * switched off; email codes depend on email being configured, so they are off
 * until switched on.
 */
export async function isFactorEnabled(env: Env, key: FactorKey): Promise<boolean> {
  const value = await getSetting(env, `factor_${key}_enabled`);
  return key === "email_otp" ? value === "true" : value !== "false";
}
export async function setFactorEnabled(env: Env, key: FactorKey, on: boolean): Promise<void> {
  await setSetting(env, `factor_${key}_enabled`, on ? "true" : "false");
}

/** Whether a factor actually works right now: switched on, and (for email codes) email can be sent. */
export async function isFactorUsable(env: Env, key: FactorKey): Promise<boolean> {
  if (!(await isFactorEnabled(env, key))) return false;
  return key === "email_otp" ? isEmailConfigured(env) : true;
}

/** How many users have each factor enrolled (passkeys: users with at least one). */
export async function factorEnrolmentCounts(env: Env): Promise<Record<string, number>> {
  const [totp, passkey, email] = await env.DB.batch([
    env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE mfa_enabled = 1"),
    env.DB.prepare("SELECT COUNT(DISTINCT user_id) AS n FROM webauthn_credentials"),
    env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE email_otp_enabled = 1"),
  ]);
  const n = (r: D1Result | undefined) => (r!.results[0] as { n: number }).n;
  return { totp: n(totp), passkey: n(passkey), email_otp: n(email) };
}

export async function listPolicies(env: Env): Promise<(AuthPolicyRow & { groups: { id: number; name: string }[] })[]> {
  const { results } = await env.DB.prepare("SELECT * FROM auth_policies ORDER BY is_default DESC, priority, name").all<AuthPolicyRow>();
  const { results: links } = await env.DB.prepare("SELECT apg.policy_id, g.id, g.name FROM auth_policy_groups apg JOIN groups g ON g.id = apg.group_id ORDER BY g.name").all<{ policy_id: number; id: number; name: string }>();
  return results.map((p) => ({ ...p, groups: links.filter((l) => l.policy_id === p.id).map((l) => ({ id: l.id, name: l.name })) }));
}

/** The policy that applies to a user. */
export async function policyForUser(env: Env, userId: number): Promise<AuthPolicyRow | null> {
  const names = await getUserGroupNames(env, userId);
  if (names.length) {
    const { results } = await env.DB.prepare(
      `SELECT ap.* FROM auth_policies ap JOIN auth_policy_groups apg ON apg.policy_id = ap.id JOIN groups g ON g.id = apg.group_id
        WHERE g.name IN (SELECT value FROM json_each(?)) ORDER BY ap.priority, ap.id LIMIT 1`
    )
      .bind(JSON.stringify(names))
      .all<AuthPolicyRow>();
    if (results[0]) return results[0];
  }
  return env.DB.prepare("SELECT * FROM auth_policies WHERE is_default = 1 LIMIT 1").first<AuthPolicyRow>();
}

/** Whether this user must present a second factor (or a passkey) to sign in. */
export async function mfaRequiredFor(env: Env, userId: number): Promise<boolean> {
  return (await policyForUser(env, userId))?.requirement === "mfa";
}

/** Whether the user has a second factor enrolled that the instance currently accepts. */
export async function hasSecondFactor(env: Env, user: SecondFactorUser): Promise<boolean> {
  if (user.mfa_enabled && (await isFactorEnabled(env, "totp"))) return true;
  if (user.email_otp_enabled && (await isFactorUsable(env, "email_otp"))) return true;
  return (await userHasPasskey(env, user.id)) && (await isFactorEnabled(env, "passkey"));
}

/** What the second-factor checks need to know about a user. */
export interface SecondFactorUser {
  id: number;
  mfa_enabled: number;
  email_otp_enabled: number;
}

export async function userHasPasskey(env: Env, userId: number): Promise<boolean> {
  return Boolean(await env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1").bind(userId).first());
}

/** The legacy instance-wide switch, kept for /api/v1/setup: picks the default policy by requirement. */
export async function setDefaultRequirement(env: Env, requirement: Requirement): Promise<void> {
  const target = await env.DB.prepare("SELECT id FROM auth_policies WHERE requirement = ? ORDER BY priority, id LIMIT 1").bind(requirement).first<{ id: number }>();
  if (!target) return;
  await env.DB.batch([
    env.DB.prepare("UPDATE auth_policies SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END").bind(target.id),
  ]);
}

export async function defaultRequirement(env: Env): Promise<Requirement> {
  return ((await env.DB.prepare("SELECT requirement FROM auth_policies WHERE is_default = 1 LIMIT 1").first<{ requirement: Requirement }>())?.requirement ?? "password");
}

/**
 * What a session's sign-in still owes the user's policy:
 *  - "ok": nothing (policy needs only a password, or the session used a second factor or passkey);
 *  - "enrol": the policy needs a second factor and the user has none - send them to set one up;
 *  - "login": they have one but this session did not use it - they must sign in again.
 */
export async function secondFactorGate(env: Env, user: SecondFactorUser, amr: string[]): Promise<"ok" | "enrol" | "login"> {
  if (amr.some((a) => a === "mfa" || a === "hwk" || a === "mfa_remembered_device")) return "ok";
  if (!(await mfaRequiredFor(env, user.id))) return "ok";
  return (await hasSecondFactor(env, user)) ? "login" : "enrol";
}

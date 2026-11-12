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
 * app (TOTP, with backup codes), passkeys, email one-time codes and security
 * questions. The list is the extension point for further methods.
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
  {
    key: "security_questions",
    label: "Security questions",
    description:
      "Answers to questions the user picks from your list. The weakest factor: answers can often be guessed or found out, so combine it with the others rather than relying on it, and it never stands in for the step-up re-authentication Super Admins need for sensitive console actions.",
    available: true,
  },
] as const;
export type FactorKey = "totp" | "passkey" | "email_otp" | "security_questions";
export const FACTOR_KEYS: readonly FactorKey[] = ["totp", "passkey", "email_otp", "security_questions"];

export function isFactorKey(key: string): key is FactorKey {
  return (FACTOR_KEYS as readonly string[]).includes(key);
}

/** Factors that are off on a fresh install until an administrator switches them on. */
const OFF_BY_DEFAULT: readonly FactorKey[] = ["email_otp", "security_questions"];

/**
 * The administrator's switch for a factor. TOTP and passkeys are on unless
 * switched off; email codes (which depend on email being configured) and
 * security questions (the weakest factor) are off until switched on.
 */
export async function isFactorEnabled(env: Env, key: FactorKey): Promise<boolean> {
  const value = await getSetting(env, `factor_${key}_enabled`);
  return OFF_BY_DEFAULT.includes(key) ? value === "true" : value !== "false";
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
  const [totp, passkey, email, kba] = await env.DB.batch([
    env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE mfa_enabled = 1"),
    env.DB.prepare("SELECT COUNT(DISTINCT user_id) AS n FROM webauthn_credentials"),
    env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE email_otp_enabled = 1"),
    env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE security_questions_enabled = 1"),
  ]);
  const n = (r: D1Result | undefined) => (r!.results[0] as { n: number }).n;
  return { totp: n(totp), passkey: n(passkey), email_otp: n(email), security_questions: n(kba) };
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

/**
 * Whether this user must use a second factor. Anyone holding an admin role
 * always must, whatever the policies say: no policy, default or group
 * assignment can leave an administrator on a password alone.
 */
export async function mfaRequiredFor(env: Env, userId: number): Promise<boolean> {
  if (await isAdministrator(env, userId)) return true;
  return (await policyForUser(env, userId))?.requirement === "mfa";
}

/** Holds any admin role (beyond the self-service default). */
export async function isAdministrator(env: Env, userId: number): Promise<boolean> {
  const { accessFor } = await import("./admin-roles.js");
  return (await accessFor(env, userId)).isAdmin;
}

/** The second factors strong enough for administrators: everything but security questions. */
export const ADMIN_FACTORS: readonly FactorKey[] = ["totp", "passkey", "email_otp"];

/** Whether the user has a second factor enrolled that the instance currently accepts. */
export async function hasSecondFactor(env: Env, user: SecondFactorUser, opts: { admin?: boolean } = {}): Promise<boolean> {
  if (user.mfa_enabled && (await isFactorEnabled(env, "totp"))) return true;
  if (user.email_otp_enabled && (await isFactorUsable(env, "email_otp"))) return true;
  // Security questions are too weak to be an administrator's only second factor.
  if (!opts.admin && user.security_questions_enabled && (await isFactorUsable(env, "security_questions"))) return true;
  return (await userHasPasskey(env, user.id)) && (await isFactorEnabled(env, "passkey"));
}

/** What the second-factor checks need to know about a user. */
export interface SecondFactorUser {
  id: number;
  mfa_enabled: number;
  email_otp_enabled: number;
  security_questions_enabled: number;
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
  const admin = await isAdministrator(env, user.id);
  // A session that answered security questions is not enough for an administrator.
  const satisfied = amr.includes("hwk") || amr.includes("mfa_remembered_device") || (amr.includes("mfa") && !(admin && amr.includes("kba")));
  if (satisfied) return "ok";
  if (!admin && !(await mfaRequiredFor(env, user.id))) return "ok";
  return (await hasSecondFactor(env, user, { admin })) ? "login" : "enrol";
}

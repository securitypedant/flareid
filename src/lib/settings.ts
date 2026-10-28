import type { Env } from "../env.js";
import { generateTempPassword, hashPassword } from "./password.js";

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSymbol: boolean;
}

const DEFAULT_POLICY: PasswordPolicy = {
  minLength: 8,
  requireUppercase: false,
  requireLowercase: false,
  requireNumber: false,
  requireSymbol: false,
};

export async function getSetting(env: Env, key: string): Promise<string | null> {
  const row = await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(key).first<{
    value: string;
  }>();
  return row?.value ?? null;
}

export async function setSetting(env: Env, key: string, value: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  )
    .bind(key, value, new Date().toISOString())
    .run();
}

export interface ScimConfig {
  endpoint: string;
  secret: string;
}

export async function getScimConfig(env: Env): Promise<ScimConfig> {
  const [endpoint, secret] = await Promise.all([getSetting(env, "scim_endpoint"), getSetting(env, "scim_secret")]);
  return { endpoint: endpoint ?? "", secret: secret ?? "" };
}

export async function setScimConfig(env: Env, config: ScimConfig): Promise<void> {
  await Promise.all([
    setSetting(env, "scim_endpoint", config.endpoint.trim().replace(/\/$/, "")),
    setSetting(env, "scim_secret", config.secret.trim()),
  ]);
}

export interface ScimScope {
  mode: "all" | "selected";
  groupIds: number[];
}

export async function getScimScope(env: Env): Promise<ScimScope> {
  const [mode, idsRaw] = await Promise.all([
    getSetting(env, "scim_scope_mode"),
    getSetting(env, "scim_scope_group_ids"),
  ]);
  let groupIds: number[] = [];
  try {
    groupIds = idsRaw ? JSON.parse(idsRaw) : [];
  } catch {
    groupIds = [];
  }
  return { mode: mode === "selected" ? "selected" : "all", groupIds };
}

export async function setScimScope(env: Env, scope: ScimScope): Promise<void> {
  await Promise.all([
    setSetting(env, "scim_scope_mode", scope.mode),
    setSetting(env, "scim_scope_group_ids", JSON.stringify(scope.groupIds)),
  ]);
}

export type NewUserPasswordMode = "default" | "random";

export async function getNewUserPasswordMode(env: Env): Promise<NewUserPasswordMode> {
  return (await getSetting(env, "new_user_password_mode")) === "default" ? "default" : "random";
}

export async function setNewUserPasswordMode(env: Env, mode: NewUserPasswordMode): Promise<void> {
  await setSetting(env, "new_user_password_mode", mode);
}

export async function isMfaRequired(env: Env): Promise<boolean> {
  return (await getSetting(env, "require_mfa")) === "true";
}

export async function setMfaRequired(env: Env, required: boolean): Promise<void> {
  await setSetting(env, "require_mfa", required ? "true" : "false");
}

export async function isSetupCompleted(env: Env): Promise<boolean> {
  return (await getSetting(env, "setup_completed")) === "true";
}

export async function markSetupCompleted(env: Env): Promise<void> {
  await setSetting(env, "setup_completed", "true");
}

/**
 * The shared password new accounts get when `new_user_password_mode` is
 * 'default'. Empty unless an operator sets one - FlareID deliberately ships no
 * default credential, so "unset" has to be a state the callers handle rather
 * than a string baked in here.
 */
export async function getDefaultPassword(env: Env): Promise<string> {
  return (await getSetting(env, "default_password")) ?? "";
}

export async function setDefaultPassword(env: Env, password: string): Promise<void> {
  await setSetting(env, "default_password", password);
}

/**
 * The password to give a newly created account, and whether it was generated.
 *
 * One place rather than two, because the admin UI and the provisioning API have
 * to agree - and because both have to cope with 'default' mode being selected
 * while no default password is actually set, which is the state a fresh
 * install is in. Generating one is the safe answer there; creating an account
 * with an empty password is not.
 */
export async function resolveNewAccountPassword(env: Env): Promise<{ password: string; generated: boolean }> {
  if ((await getNewUserPasswordMode(env)) === "default") {
    const configured = await getDefaultPassword(env);
    if (configured) return { password: configured, generated: false };
  }
  return { password: generateTempPassword(await getPasswordPolicy(env)), generated: true };
}

/**
 * Rehashes every user's password to the configured default password (fresh
 * salt per user). Refuses when no default is set, rather than setting every
 * password in the directory to the empty string.
 */
export async function applyDefaultPasswordToAllUsers(env: Env): Promise<number> {
  const password = await getDefaultPassword(env);
  if (!password) return 0;
  const { results: users } = await env.DB.prepare("SELECT id FROM users").all<{ id: number }>();

  for (const user of users) {
    const { hash, salt, iterations } = await hashPassword(password);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?"
    )
      .bind(hash, salt, iterations, new Date().toISOString(), user.id)
      .run();
  }

  return users.length;
}

export async function setPasswordPolicy(env: Env, policy: PasswordPolicy): Promise<void> {
  await setSetting(env, "password_policy", JSON.stringify(policy));
}

export async function getPasswordPolicy(env: Env): Promise<PasswordPolicy> {
  const raw = await getSetting(env, "password_policy");
  if (!raw) return DEFAULT_POLICY;
  try {
    return { ...DEFAULT_POLICY, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_POLICY;
  }
}

/** Admin-configurable display name, shown everywhere the UI previously hardcoded "FlareID"/env.APP_NAME. */
export async function getAppName(env: Env): Promise<string> {
  return (await getSetting(env, "app_name")) || env.APP_NAME;
}

export async function setAppName(env: Env, name: string): Promise<void> {
  await setSetting(env, "app_name", name);
}

const DEFAULT_LOGIN_SUBTITLE = "Sign in to continue.";

/** The line under the product name on the sign-in page, editable in Branding. */
export async function getLoginSubtitle(env: Env): Promise<string> {
  return (await getSetting(env, "login_subtitle")) ?? DEFAULT_LOGIN_SUBTITLE;
}

export async function setLoginSubtitle(env: Env, subtitle: string): Promise<void> {
  await setSetting(env, "login_subtitle", subtitle.trim());
}

export interface LoginGradient {
  from: string;
  to: string;
}

const DEFAULT_LOGIN_GRADIENT: LoginGradient = { from: "#f7b733", to: "#f6821f" };

export async function getLoginGradient(env: Env): Promise<LoginGradient> {
  const [from, to] = await Promise.all([getSetting(env, "login_gradient_from"), getSetting(env, "login_gradient_to")]);
  return { from: from || DEFAULT_LOGIN_GRADIENT.from, to: to || DEFAULT_LOGIN_GRADIENT.to };
}

export async function setLoginGradient(env: Env, gradient: LoginGradient): Promise<void> {
  await Promise.all([
    setSetting(env, "login_gradient_from", gradient.from),
    setSetting(env, "login_gradient_to", gradient.to),
  ]);
}

export function validatePassword(password: string, policy: PasswordPolicy): string | null {
  if (password.length < policy.minLength) return `Password must be at least ${policy.minLength} characters.`;
  if (policy.requireUppercase && !/[A-Z]/.test(password)) return "Password must contain an uppercase letter.";
  if (policy.requireLowercase && !/[a-z]/.test(password)) return "Password must contain a lowercase letter.";
  if (policy.requireNumber && !/[0-9]/.test(password)) return "Password must contain a number.";
  if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(password)) return "Password must contain a symbol.";
  return null;
}

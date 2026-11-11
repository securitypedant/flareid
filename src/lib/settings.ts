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

/** Whether the default authentication policy requires a second factor (see auth-policy.ts). */
export async function isMfaRequired(env: Env): Promise<boolean> {
  return (await env.DB.prepare("SELECT requirement FROM auth_policies WHERE is_default = 1 LIMIT 1").first<{ requirement: string }>())?.requirement === "mfa";
}

/** The legacy instance-wide switch: makes the first policy with that requirement the default. */
export async function setMfaRequired(env: Env, required: boolean): Promise<void> {
  await setSetting(env, "require_mfa", required ? "true" : "false");
  const target = await env.DB.prepare("SELECT id FROM auth_policies WHERE requirement = ? ORDER BY priority, id LIMIT 1").bind(required ? "mfa" : "password").first<{ id: number }>();
  if (target) await env.DB.prepare("UPDATE auth_policies SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END").bind(target.id).run();
}

export const AUDIT_RETENTION_DEFAULT_DAYS = 365;
export const AUDIT_RETENTION_MIN_DAYS = 30;
export const AUDIT_RETENTION_MAX_DAYS = 3650;

/** How long audit-log entries are kept before the scheduled cleanup deletes them. */
export async function getAuditRetentionDays(env: Env): Promise<number> {
  const raw = Number(await getSetting(env, "audit_retention_days"));
  return Number.isFinite(raw) && raw > 0 ? raw : AUDIT_RETENTION_DEFAULT_DAYS;
}

export async function setAuditRetentionDays(env: Env, days: number): Promise<number> {
  const clamped = Math.min(AUDIT_RETENTION_MAX_DAYS, Math.max(AUDIT_RETENTION_MIN_DAYS, Math.round(days)));
  await setSetting(env, "audit_retention_days", String(clamped));
  return clamped;
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
 * Sets every user's password to the configured default password. Refuses when
 * no default is set, rather than setting every password in the directory to
 * the empty string.
 *
 * The password is hashed once and the same hash written to every row. A
 * per-user salt would protect nothing here - every account is being given the
 * same, admin-known password - and at ~100 ms of CPU per scrypt hash, hashing
 * per user would run a large directory past the Worker CPU limit.
 */
export async function applyDefaultPasswordToAllUsers(env: Env): Promise<number> {
  const password = await getDefaultPassword(env);
  if (!password) return 0;
  const { hash, salt, iterations } = await hashPassword(password, env);
  const result = await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ?")
    .bind(hash, salt, iterations, new Date().toISOString())
    .run();
  return Number(result.meta.changes ?? 0);
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

/** The only colour syntax accepted: these values are interpolated into the sign-in page's <style>. */
export function isHexColor(value: unknown): value is string {
  return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value);
}

export async function getLoginGradient(env: Env): Promise<LoginGradient> {
  const [from, to] = await Promise.all([getSetting(env, "login_gradient_from"), getSetting(env, "login_gradient_to")]);
  // A value stored before validation existed falls back rather than reaching the page.
  return { from: isHexColor(from) ? from : DEFAULT_LOGIN_GRADIENT.from, to: isHexColor(to) ? to : DEFAULT_LOGIN_GRADIENT.to };
}

/** Throws unless both are #rrggbb: a colour like `red;}</style><script>` would otherwise break out of the stylesheet. */
export async function setLoginGradient(env: Env, gradient: LoginGradient): Promise<void> {
  if (!isHexColor(gradient.from) || !isHexColor(gradient.to)) throw new RangeError("Gradient colours must be #rrggbb hex values.");
  await Promise.all([
    setSetting(env, "login_gradient_from", gradient.from),
    setSetting(env, "login_gradient_to", gradient.to),
  ]);
}

/**
 * The decorative symbols that drift away from the cursor on the sign-in pages.
 * On by default. `characters` empty means the built-in symbol set (picked at
 * random); otherwise its characters are cycled in order, so a company name
 * spells itself out behind the pointer.
 */
export interface CursorTrail {
  enabled: boolean;
  characters: string;
}

export const CURSOR_TRAIL_MAX_CHARACTERS = 64;

export async function getCursorTrail(env: Env): Promise<CursorTrail> {
  const [enabled, characters] = await Promise.all([getSetting(env, "login_cursor_trail"), getSetting(env, "login_cursor_characters")]);
  return { enabled: enabled !== "false", characters: characters ?? "" };
}

export async function setCursorTrail(env: Env, trail: CursorTrail): Promise<CursorTrail> {
  const clean = { enabled: trail.enabled, characters: trail.characters.trim().slice(0, CURSOR_TRAIL_MAX_CHARACTERS) };
  await Promise.all([
    setSetting(env, "login_cursor_trail", clean.enabled ? "true" : "false"),
    setSetting(env, "login_cursor_characters", clean.characters),
  ]);
  return clean;
}

/** Everything the sign-in, MFA and sign-in error pages need to look like the configured brand. */
export interface LoginAppearance {
  gradient: LoginGradient;
  subtitle: string;
  cursorTrail: CursorTrail;
  /** Whether "Forgot your password?" is offered: email is configured (see email.ts). */
  recoveryEnabled: boolean;
}

export async function getLoginAppearance(env: Env): Promise<LoginAppearance> {
  const [gradient, subtitle, cursorTrail, fromAddress] = await Promise.all([
    getLoginGradient(env),
    getLoginSubtitle(env),
    getCursorTrail(env),
    getSetting(env, "email_from_address"),
  ]);
  // Same rule as isEmailConfigured() in email.ts, inlined: email.ts imports this module.
  return { gradient, subtitle, cursorTrail, recoveryEnabled: Boolean(env.EMAIL) && Boolean(fromAddress) };
}

/**
 * How long a browser session lasts. `maxHours` is the absolute lifetime from
 * sign-in; `idleMinutes` ends a session that has not been used for that long
 * (0 turns the idle limit off). Both apply to existing sessions as soon as
 * they are changed, because they are checked on every request.
 */
export interface SessionPolicy {
  maxHours: number;
  idleMinutes: number;
}

export const SESSION_DEFAULTS: SessionPolicy = { maxHours: 12, idleMinutes: 0 };
export const SESSION_MAX_HOURS_RANGE = { min: 1, max: 720 } as const;
export const SESSION_IDLE_MINUTES_RANGE = { min: 5, max: 10080 } as const;

/** Clamps raw values into range; shared with sessions.ts, which reads both settings in the same query as the session. */
export function normalizeSessionPolicy(maxHours: unknown, idleMinutes: unknown): SessionPolicy {
  const max = Number(maxHours);
  const idle = Number(idleMinutes);
  return {
    maxHours:
      Number.isFinite(max) && max > 0
        ? Math.min(SESSION_MAX_HOURS_RANGE.max, Math.max(SESSION_MAX_HOURS_RANGE.min, Math.round(max)))
        : SESSION_DEFAULTS.maxHours,
    idleMinutes:
      Number.isFinite(idle) && idle > 0
        ? Math.min(SESSION_IDLE_MINUTES_RANGE.max, Math.max(SESSION_IDLE_MINUTES_RANGE.min, Math.round(idle)))
        : 0,
  };
}

export async function getSessionPolicy(env: Env): Promise<SessionPolicy> {
  const [maxHours, idleMinutes] = await Promise.all([getSetting(env, "session_max_hours"), getSetting(env, "session_idle_minutes")]);
  return normalizeSessionPolicy(maxHours, idleMinutes);
}

export async function setSessionPolicy(env: Env, policy: SessionPolicy): Promise<SessionPolicy> {
  const clean = normalizeSessionPolicy(policy.maxHours, policy.idleMinutes);
  await Promise.all([
    setSetting(env, "session_max_hours", String(clean.maxHours)),
    setSetting(env, "session_idle_minutes", String(clean.idleMinutes)),
  ]);
  return clean;
}

/** "At least 12 characters, with an uppercase letter and a number." - the policy as a sentence, shown next to password fields. */
export function passwordPolicySummary(policy: PasswordPolicy): string {
  const needs = [
    policy.requireUppercase && "an uppercase letter",
    policy.requireLowercase && "a lowercase letter",
    policy.requireNumber && "a number",
    policy.requireSymbol && "a symbol",
  ].filter(Boolean) as string[];
  const list = needs.length > 1 ? `${needs.slice(0, -1).join(", ")} and ${needs[needs.length - 1]}` : needs[0];
  return `At least ${policy.minLength} characters${list ? `, with ${list}` : ""}.`;
}

export function validatePassword(password: string, policy: PasswordPolicy): string | null {
  if (password.length < policy.minLength) return `Password must be at least ${policy.minLength} characters.`;
  if (policy.requireUppercase && !/[A-Z]/.test(password)) return "Password must contain an uppercase letter.";
  if (policy.requireLowercase && !/[a-z]/.test(password)) return "Password must contain a lowercase letter.";
  if (policy.requireNumber && !/[0-9]/.test(password)) return "Password must contain a number.";
  if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(password)) return "Password must contain a symbol.";
  return null;
}

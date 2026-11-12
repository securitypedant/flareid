import { isFactorEnabled, setFactorEnabled, type FactorKey } from "../lib/auth-policy.js";
import { isEmailAddress, sendEmail, setEmailEnabled, setEmailSettings, type SendResult } from "../lib/email.js";
import { escapeHtml } from "../lib/html.js";
import { setRateLimitPolicy } from "../lib/rate-limit.js";
import {
  AUDIT_RETENTION_DEFAULT_DAYS,
  applyDefaultPasswordToAllUsers,
  setAppName,
  setAuditRetentionDays,
  setCursorTrail,
  setDefaultPassword,
  setLoginGradient,
  setLoginSubtitle,
  setMfaRequired,
  setNewUserPasswordMode,
  setPasswordPolicy,
  setSessionPolicy,
  type CursorTrail,
  type NewUserPasswordMode,
  type PasswordPolicy,
  type SessionPolicy,
} from "../lib/settings.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";

/**
 * Instance settings, each with its audit entry, for the console's Security,
 * Branding and Email pages and their API twins. Values are normalised here
 * (missing or unparseable numbers fall back to the defaults), so a form and a
 * JSON body that say the same thing store the same thing.
 */

export async function savePasswordPolicy(ctx: ServiceCtx, p: Partial<Record<keyof PasswordPolicy, unknown>>): Promise<PasswordPolicy> {
  const policy: PasswordPolicy = {
    minLength: Number(p.minLength) || 8,
    requireUppercase: !!p.requireUppercase,
    requireLowercase: !!p.requireLowercase,
    requireNumber: !!p.requireNumber,
    requireSymbol: !!p.requireSymbol,
  };
  await setPasswordPolicy(ctx.env, policy);
  await audit(ctx, "settings.password_policy_changed");
  return policy;
}

export async function saveRateLimit(ctx: ServiceCtx, maxAttempts: unknown, windowMinutes: unknown): Promise<{ maxAttempts: number; windowMinutes: number }> {
  const policy = { maxAttempts: Number(maxAttempts) || 5, windowMinutes: Number(windowMinutes) || 15 };
  await setRateLimitPolicy(ctx.env, policy);
  await audit(ctx, "settings.rate_limit_changed");
  return { maxAttempts: Math.max(1, policy.maxAttempts), windowMinutes: Math.max(1, policy.windowMinutes) };
}

export async function saveSessionLimits(ctx: ServiceCtx, maxHours: unknown, idleMinutes: unknown): Promise<SessionPolicy> {
  const policy = await setSessionPolicy(ctx.env, { maxHours: Number(maxHours), idleMinutes: Number(idleMinutes) });
  await audit(ctx, "settings.session_limits_changed", undefined, { ...policy });
  return policy;
}

export async function saveAuditRetention(ctx: ServiceCtx, days: unknown): Promise<number> {
  const saved = await setAuditRetentionDays(ctx.env, Number(days) || AUDIT_RETENTION_DEFAULT_DAYS);
  await audit(ctx, "settings.audit_retention_changed", undefined, { days: saved });
  return saved;
}

export async function saveNewUserPasswordMode(ctx: ServiceCtx, mode: unknown): Promise<NewUserPasswordMode> {
  const m: NewUserPasswordMode = mode === "default" ? "default" : "random";
  await setNewUserPasswordMode(ctx.env, m);
  await audit(ctx, "settings.new_user_password_mode_changed", undefined, { mode: m });
  return m;
}

/** An empty password is ignored, not stored: "no default" is not a password. */
export async function saveDefaultPassword(ctx: ServiceCtx, password: string): Promise<boolean> {
  if (!password) return false;
  await setDefaultPassword(ctx.env, password);
  await audit(ctx, "settings.default_password_changed");
  return true;
}

/**
 * Sets every account's password - administrators' included - to the default.
 * The caller decides who may: it is Super Admin authority in the API.
 */
export async function applyDefaultPasswordToAll(ctx: ServiceCtx, password: string): Promise<number> {
  await saveDefaultPassword(ctx, password);
  const count = await applyDefaultPasswordToAllUsers(ctx.env);
  await audit(ctx, "settings.default_password_applied_to_all", undefined, { count });
  return count;
}

export async function saveRequireMfa(ctx: ServiceCtx, required: boolean): Promise<void> {
  await setMfaRequired(ctx.env, required);
  await audit(ctx, "settings.require_mfa_changed", undefined, { required });
}

/** Turning a factor off is refused while a policy requires a second factor and it is the last one on. */
export async function saveFactor(ctx: ServiceCtx, key: string, enabled: boolean): Promise<void> {
  if (key !== "totp" && key !== "passkey") throw new ServiceError(400, "Unknown factor.");
  if (!enabled) {
    const other: FactorKey = key === "totp" ? "passkey" : "totp";
    const mfaPolicies = await ctx.env.DB.prepare("SELECT COUNT(*) AS n FROM auth_policies WHERE requirement = 'mfa'").first<{ n: number }>();
    if (!(await isFactorEnabled(ctx.env, other)) && (mfaPolicies?.n ?? 0) > 0) {
      throw new ServiceError(400, "At least one second factor must stay on while a policy requires one.");
    }
  }
  await setFactorEnabled(ctx.env, key, enabled);
  await audit(ctx, "auth_factor.changed", key, { enabled });
}

// ---------------------------------------------------------------------------
// Branding
// ---------------------------------------------------------------------------

export async function saveAppName(ctx: ServiceCtx, name: string): Promise<void> {
  await setAppName(ctx.env, name);
  await audit(ctx, "settings.app_name_changed", name);
}

/** Empty is a valid choice - it means "show no message". */
export async function saveLoginSubtitle(ctx: ServiceCtx, subtitle: string): Promise<void> {
  await setLoginSubtitle(ctx.env, subtitle.trim());
  await audit(ctx, "settings.login_subtitle_changed", undefined, { subtitle: subtitle.trim() });
}

/** Throws (RangeError) unless both are #rrggbb. */
export async function saveLoginGradient(ctx: ServiceCtx, from: string, to: string): Promise<void> {
  await setLoginGradient(ctx.env, { from, to });
  await audit(ctx, "settings.login_gradient_changed", undefined, { from, to });
}

export async function saveCursorTrail(ctx: ServiceCtx, trail: CursorTrail): Promise<CursorTrail> {
  const saved = await setCursorTrail(ctx.env, trail);
  await audit(ctx, "settings.cursor_trail_changed", undefined, { ...saved });
  return saved;
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

export async function saveEmailSettings(ctx: ServiceCtx, fromAddress: string, fromName: string): Promise<{ fromAddress: string; fromName: string }> {
  const address = fromAddress.trim();
  if (address && !isEmailAddress(address)) throw new ServiceError(400, "That is not a valid email address.");
  const saved = await setEmailSettings(ctx.env, { fromAddress: address, fromName });
  await audit(ctx, "settings.email_changed", saved.fromAddress || undefined, { ...saved });
  return saved;
}

export async function switchEmail(ctx: ServiceCtx, on: boolean): Promise<void> {
  await setEmailEnabled(ctx.env, on);
  await audit(ctx, "settings.email_switched", undefined, { enabled: on });
}

export async function sendTestEmail(ctx: ServiceCtx, to: string, appName: string): Promise<SendResult> {
  const result = await sendEmail(ctx.env, {
    to,
    subject: `${appName} test email`,
    text: `This is a test email from ${appName}. Email delivery is working.`,
    html: `<p>This is a test email from <strong>${escapeHtml(appName)}</strong>. Email delivery is working.</p>`,
  });
  await audit(ctx, "settings.email_test_sent", to, { sent: result.ok, ...(result.ok ? {} : { error: result.error }) });
  return result;
}

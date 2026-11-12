import { ADMIN_FACTORS, FACTOR_KEYS, isFactorKey, isFactorUsable, setFactorEnabled } from "../lib/auth-policy.js";
import { isEmailAddress, isEmailConfigured, sendEmail, setEmailEnabled, setEmailSettings, type SendResult } from "../lib/email.js";
import { getTemplate, setAccent, setTemplate, type EmailTemplate, type TemplateKey } from "../lib/email-templates.js";
import { escapeHtml } from "../lib/html.js";
import { setRateLimitPolicy } from "../lib/rate-limit.js";
import {
  enabledSecurityQuestions,
  getKbaSettings,
  KBA_MAX_QUESTION,
  KBA_MAX_QUESTIONS,
  KBA_MAX_REQUIRED,
  setKbaSettings,
  type KbaSettings,
  type SecurityQuestionRow,
} from "../lib/security-questions.js";
import {
  AUDIT_RETENTION_DEFAULT_DAYS,
  applyDefaultPasswordToAllUsers,
  getTurnstileConfig,
  setAppName,
  setBreachedPasswordCheckEnabled,
  setTurnstileConfig,
  type TurnstileMode,
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

export async function saveBreachedPasswordCheck(ctx: ServiceCtx, enabled: boolean): Promise<boolean> {
  await setBreachedPasswordCheckEnabled(ctx.env, enabled);
  await audit(ctx, "settings.breached_password_check_changed", undefined, { enabled });
  return enabled;
}

const TURNSTILE_KEY_PATTERN = /^[A-Za-z0-9_-]{1,200}$/;

/**
 * Bot protection (Turnstile). Fields not given keep their value; a secret is
 * replaced only by a non-empty one, and is never part of the audit entry.
 * Turning it on needs a site key and a secret (stored, or the
 * TURNSTILE_SECRET_KEY Worker secret).
 */
export async function saveTurnstile(ctx: ServiceCtx, input: { mode?: unknown; siteKey?: unknown; secret?: unknown }): Promise<void> {
  if (input.mode !== undefined && input.mode !== "on" && input.mode !== "off") throw new ServiceError(400, 'mode must be "off" or "on".');
  const siteKey = input.siteKey === undefined ? undefined : String(input.siteKey).trim();
  const secret = input.secret === undefined ? "" : String(input.secret).trim();
  if (siteKey && !TURNSTILE_KEY_PATTERN.test(siteKey)) throw new ServiceError(400, "That does not look like a Turnstile site key.");
  if (secret && !TURNSTILE_KEY_PATTERN.test(secret)) throw new ServiceError(400, "That does not look like a Turnstile secret key.");
  const current = await getTurnstileConfig(ctx.env);
  const mode = (input.mode as TurnstileMode | undefined) ?? current.mode;
  const effectiveSiteKey = siteKey ?? current.siteKey;
  if (mode === "on" && (!effectiveSiteKey || !(secret || current.secret))) throw new ServiceError(400, "Turnstile needs a site key and a secret key before it can be switched on.");
  await setTurnstileConfig(ctx.env, { mode: input.mode === undefined ? undefined : mode, siteKey, secret });
  await audit(ctx, "settings.turnstile_changed", undefined, { mode, site_key: effectiveSiteKey, secret_changed: Boolean(secret) });
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
  if (!isFactorKey(key)) throw new ServiceError(400, "Unknown factor.");
  // Email codes can only be sent with email set up; switching them on before
  // that would offer people a factor that cannot work.
  if (enabled && key === "email_otp" && !(await isEmailConfigured(ctx.env))) {
    throw new ServiceError(400, "Email one-time codes need email: set up sending under Integrations > Email first.");
  }
  // People must be able to choose as many questions as they are asked to set.
  if (enabled && key === "security_questions") {
    const [{ required }, choices] = await Promise.all([getKbaSettings(ctx.env), enabledSecurityQuestions(ctx.env)]);
    if (choices.length < required) throw new ServiceError(400, `Security questions need at least ${required} enabled questions to choose from.`);
  }
  if (!enabled) {
    const mfaPolicies = await ctx.env.DB.prepare("SELECT COUNT(*) AS n FROM auth_policies WHERE requirement = 'mfa'").first<{ n: number }>();
    const othersUsable = await Promise.all(FACTOR_KEYS.filter((k) => k !== key).map((k) => isFactorUsable(ctx.env, k)));
    if (!othersUsable.some(Boolean) && (mfaPolicies?.n ?? 0) > 0) {
      throw new ServiceError(400, "At least one second factor must stay on while a policy requires one.");
    }
    // Administrators always need a second factor stronger than security questions.
    const adminUsable = await Promise.all(ADMIN_FACTORS.filter((k) => k !== key).map((k) => isFactorUsable(ctx.env, k)));
    if ((ADMIN_FACTORS as readonly string[]).includes(key) && !adminUsable.some(Boolean)) {
      throw new ServiceError(400, "Administrators always need a second factor: keep the authenticator app, passkeys or email codes on.");
    }
  }
  await setFactorEnabled(ctx.env, key, enabled);
  await audit(ctx, "auth_factor.changed", key, { enabled });
}

// ---------------------------------------------------------------------------
// Security questions (Security > Factors > Security questions)
// ---------------------------------------------------------------------------

async function enabledQuestionCount(ctx: ServiceCtx): Promise<number> {
  return (await enabledSecurityQuestions(ctx.env)).length;
}

/**
 * How many questions people set and how many are asked at sign-in. Fields not
 * given keep their value; asked can be at most required, and required at most
 * the number of enabled questions (people must be able to choose that many).
 */
export async function saveKbaSettings(ctx: ServiceCtx, input: { required?: unknown; asked?: unknown }): Promise<KbaSettings> {
  const current = await getKbaSettings(ctx.env);
  const required = input.required === undefined || input.required === "" ? current.required : Number(input.required);
  const asked = input.asked === undefined || input.asked === "" ? current.asked : Number(input.asked);
  if (!Number.isInteger(required) || required < 1 || required > KBA_MAX_REQUIRED) throw new ServiceError(400, `The number of questions each person sets must be between 1 and ${KBA_MAX_REQUIRED}.`);
  if (!Number.isInteger(asked) || asked < 1 || asked > required) throw new ServiceError(400, "The number of questions asked at sign-in must be at least 1 and no more than the number each person sets.");
  if (required > (await enabledQuestionCount(ctx))) throw new ServiceError(400, `Only ${await enabledQuestionCount(ctx)} questions are enabled: people could not choose ${required}.`);
  const saved = { required, asked };
  await setKbaSettings(ctx.env, saved);
  // Someone who set fewer questions than a raised "required" keeps them, and is asked min(asked, theirs).
  await audit(ctx, "settings.security_questions_changed", undefined, { ...saved });
  return saved;
}

function questionText(text: unknown): string {
  const t = String(text ?? "").normalize("NFKC").trim().replace(/\s+/g, " ");
  if (t.length < 5) throw new ServiceError(400, "A question needs at least 5 characters.");
  if (t.length > KBA_MAX_QUESTION) throw new ServiceError(400, `A question can be at most ${KBA_MAX_QUESTION} characters.`);
  return t;
}

export async function addSecurityQuestion(ctx: ServiceCtx, text: unknown): Promise<SecurityQuestionRow> {
  const t = questionText(text);
  const count = await ctx.env.DB.prepare("SELECT COUNT(*) AS n FROM security_questions").first<{ n: number }>();
  if ((count?.n ?? 0) >= KBA_MAX_QUESTIONS) throw new ServiceError(400, `There can be at most ${KBA_MAX_QUESTIONS} questions.`);
  if (await ctx.env.DB.prepare("SELECT 1 FROM security_questions WHERE lower(text) = lower(?)").bind(t).first()) throw new ServiceError(409, "That question is already in the list.");
  const row = await ctx.env.DB.prepare("INSERT INTO security_questions (text, enabled, created_at) VALUES (?, 1, ?) RETURNING id, text, enabled, created_at")
    .bind(t, new Date().toISOString())
    .first<SecurityQuestionRow>();
  await audit(ctx, "settings.security_question_added", t, { id: row!.id });
  return row!;
}

async function questionById(ctx: ServiceCtx, id: number): Promise<SecurityQuestionRow> {
  const row = Number.isInteger(id) ? await ctx.env.DB.prepare("SELECT id, text, enabled, created_at FROM security_questions WHERE id = ?").bind(id).first<SecurityQuestionRow>() : null;
  if (!row) throw new ServiceError(404, "No such question.");
  return row;
}

/**
 * Enables or disables a question. A disabled question is no longer offered
 * when people choose theirs; answers already given to it keep working.
 */
export async function setSecurityQuestionEnabled(ctx: ServiceCtx, id: number, enabled: boolean): Promise<SecurityQuestionRow> {
  const q = await questionById(ctx, id);
  if (!enabled && q.enabled) {
    const { required } = await getKbaSettings(ctx.env);
    if ((await enabledQuestionCount(ctx)) - 1 < required) throw new ServiceError(400, `At least ${required} questions must stay enabled, the number each person sets.`);
  }
  await ctx.env.DB.prepare("UPDATE security_questions SET enabled = ? WHERE id = ?").bind(enabled ? 1 : 0, id).run();
  await audit(ctx, "settings.security_question_changed", q.text, { id, enabled });
  return { ...q, enabled: enabled ? 1 : 0 };
}

/** Deletes a question nobody has answered; one with answers can only be disabled. */
export async function deleteSecurityQuestion(ctx: ServiceCtx, id: number): Promise<void> {
  const q = await questionById(ctx, id);
  if (await ctx.env.DB.prepare("SELECT 1 FROM user_security_answers WHERE question_id = ? LIMIT 1").bind(id).first()) {
    throw new ServiceError(409, "People have answered this question, so it can only be disabled.");
  }
  if (q.enabled) {
    const { required } = await getKbaSettings(ctx.env);
    if ((await enabledQuestionCount(ctx)) - 1 < required) throw new ServiceError(400, `At least ${required} questions must stay enabled, the number each person sets.`);
  }
  await ctx.env.DB.prepare("DELETE FROM security_questions WHERE id = ?").bind(id).run();
  await audit(ctx, "settings.security_question_deleted", q.text, { id });
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

// ---------------------------------------------------------------------------
// Email templates (Branding)
// ---------------------------------------------------------------------------

/** Saves a template (fields not given take the default wording), or resets it with null. */
export async function saveEmailTemplate(ctx: ServiceCtx, key: TemplateKey, t: Partial<EmailTemplate> | null): Promise<EmailTemplate> {
  try {
    await setTemplate(ctx.env, key, t);
  } catch (e) {
    throw new ServiceError(400, (e as Error).message);
  }
  await audit(ctx, t === null ? "settings.email_template_reset" : "settings.email_template_changed", key);
  return getTemplate(ctx.env, key);
}

export async function saveEmailAccent(ctx: ServiceCtx, accent: string): Promise<void> {
  try {
    await setAccent(ctx.env, accent);
  } catch (e) {
    throw new ServiceError(400, (e as Error).message);
  }
  await audit(ctx, "settings.email_accent_changed", undefined, { accent: accent.toLowerCase() });
}

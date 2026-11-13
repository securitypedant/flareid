import { z } from "@hono/zod-openapi";
import type { Env } from "../env.js";
import { listRoles, rolePermissions } from "../lib/admin-roles.js";
import { expand } from "../lib/permissions.js";
import { FACTORS, factorEnrolmentCounts, isFactorEnabled, isFactorUsable, listPolicies, type FactorKey } from "../lib/auth-policy.js";
import { getEmailSettings, isEmailAddress, isEmailConfigured, isEmailEnabled } from "../lib/email.js";
import { DEFAULT_TEMPLATES, getAccent, getTemplate, TEMPLATE_INFO, type TemplateKey } from "../lib/email-templates.js";
import { getRateLimitPolicy } from "../lib/rate-limit.js";
import {
  getAppName,
  getAuditRetentionDays,
  getCursorTrail,
  getDefaultLanguage,
  getDefaultPassword,
  getNewUserPasswordMode,
  getPasswordPolicy,
  getSessionPolicy,
  activeTurnstileSiteKey,
  getSetting,
  getTurnstileConfig,
  isBreachedPasswordCheckEnabled,
  isHexColor,
  isMfaRequired,
} from "../lib/settings.js";
import { listSigningKeys } from "../lib/signing-keys.js";
import { allLocales, isSupportedLocale, SUPPORTED_LOCALES } from "../lib/i18n.js";
import { getKbaSettings, listSecurityQuestions } from "../lib/security-questions.js";
import { createPolicy, createRole, deletePolicy, deleteRole, normalizePolicy, normalizeRole, updatePolicy, updateRole } from "../services/access.js";
import { apiCtx, ServiceError } from "../services/context.js";
import { rotateKey } from "../services/platform.js";
import {
  applyDefaultPasswordToAll,
  saveAppName,
  saveBreachedPasswordCheck,
  saveTurnstile,
  saveAuditRetention,
  saveCursorTrail,
  saveDefaultLanguage,
  saveDefaultPassword,
  saveEmailAccent,
  saveEmailSettings,
  saveEmailTemplate,
  saveFactor,
  saveKbaSettings,
  addSecurityQuestion,
  setSecurityQuestionEnabled,
  deleteSecurityQuestion,
  saveLoginGradient,
  saveLoginSubtitle,
  saveNewUserPasswordMode,
  savePasswordPolicy,
  saveRateLimit,
  saveRequireMfa,
  saveSessionLimits,
  sendTestEmail,
  switchEmail,
} from "../services/settings.js";
import { base64ToBytes, defaultBrand, defaultCustomCss, getBrandRow, listBrandRows, LOGO_MAX_BYTES, logoPath, mergeBrand, type BrandRow } from "../lib/brands.js";
import { cleanCustomCss, createBrand, deleteBrand, removeLogo, saveDefaultCustomCss, updateBrand, uploadLogo, type BrandInput } from "../services/branding.js";
import { badRequest, defineRoute, notFound, param, readJson, readOptionalJson, type ApiContext } from "./openapi.js";
import { IdParam, PasswordPolicySchema } from "./schemas.js";

/**
 * Email, branding, security settings, authentication policies, factors,
 * roles and signing keys: the console's Integrations -> Email, Branding and
 * Security pages.
 */

/** Group names to ids; an unknown name is an error. */
async function groupIdsByName(env: Env, names: string[]): Promise<number[]> {
  if (names.length === 0) return [];
  const { results } = await env.DB.prepare("SELECT id, name FROM groups WHERE name IN (SELECT value FROM json_each(?))").bind(JSON.stringify(names)).all<{ id: number; name: string }>();
  const missing = names.filter((n) => !results.some((r) => r.name === n));
  if (missing.length) throw new ServiceError(400, `No such group(s): ${missing.join(", ")}.`);
  return results.map((r) => r.id);
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

const EmailSchema = z.object({ enabled: z.boolean(), binding: z.boolean(), sending: z.boolean(), from_address: z.string(), from_name: z.string() }).openapi("EmailSettings");

async function emailJson(env: Env) {
  const [settings, enabled, sending] = await Promise.all([getEmailSettings(env), isEmailEnabled(env), isEmailConfigured(env)]);
  return { enabled, binding: Boolean(env.EMAIL), sending, from_address: settings.fromAddress, from_name: settings.fromName };
}

defineRoute(
  { method: "get", path: "/api/v1/email", tag: "Email", permission: "email:read", summary: "Read the email settings", description: "`sending` is true when the binding, a From address and the switch are all in place.", response: EmailSchema },
  async (c) => c.json(await emailJson(c.env))
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/email",
    tag: "Email",
    permission: "email:write",
    summary: "Set the From address and name",
    description: "The address must be on a domain onboarded to Cloudflare Email Sending.",
    body: z.object({ from_address: z.string(), from_name: z.string().optional() }),
    response: EmailSchema,
  },
  async (c) => {
    const body = await readJson<{ from_address: string; from_name?: string }>(c);
    await saveEmailSettings(apiCtx(c), String(body.from_address ?? ""), String(body.from_name ?? ""));
    return c.json(await emailJson(c.env));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/email/enabled",
    tag: "Email",
    permission: "email:write",
    summary: "Switch email on or off",
    description: "Off stops all sending and hides recovery and invitations, keeping the From address and name.",
    body: z.object({ enabled: z.boolean() }),
    response: EmailSchema,
  },
  async (c) => {
    await switchEmail(apiCtx(c), (await readJson<{ enabled: boolean }>(c)).enabled === true);
    return c.json(await emailJson(c.env));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/email/test",
    tag: "Email",
    permission: "email:write",
    summary: "Send a test email",
    body: z.object({ to: z.string().openapi({ example: "ops@example.com" }) }),
    errors: [502],
    response: z.object({ ok: z.literal(true), to: z.string() }),
  },
  async (c) => {
    const to = String((await readJson<{ to: string }>(c)).to ?? "").trim();
    if (!isEmailAddress(to)) return c.json(badRequest("to must be an email address."), 400);
    const result = await sendTestEmail(apiCtx(c), to, await getAppName(c.env));
    if (!result.ok) return c.json({ error: "send_failed", message: result.error }, 502);
    return c.json({ ok: true, to });
  }
);

// ---------------------------------------------------------------------------
// Branding
// ---------------------------------------------------------------------------

const GradientSchema = z.object({ from: z.string().openapi({ example: "#f7b733" }), to: z.string().openapi({ example: "#f6821f" }) });

const BrandingSchema = z
  .object({
    app_name: z.string(),
    login_subtitle: z.string(),
    login_gradient: GradientSchema,
    cursor_trail: z.object({ enabled: z.boolean(), characters: z.string() }),
    default_language: z.string().openapi({ description: "The sign-in pages' language when the browser asks for none FlareID has (no ?lang=, language cookie, OIDC ui_locales or supported Accept-Language). One of `available_languages`." }),
    available_languages: z.array(z.object({ code: z.string(), name: z.string(), native_name: z.string(), machine_assisted: z.boolean() })).openapi({ description: "The languages the sign-in pages are translated into (locales/*.json)." }),
    email_accent: z.string(),
    logo_url: z.string().nullable().openapi({ description: "Path of the uploaded logo (`/brand/logo/<id>-<hash>.png|jpg`, cached as immutable), or null for FlareID's own mark." }),
    custom_css: z.string().openapi({ description: "The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none." }),
    css_url: z.string().nullable().openapi({ description: "Where that stylesheet is served (`/brand/css/default-<hash>.css`), or null." }),
    preview_url: z.string().openapi({ description: "The sign-in page in this brand, for a signed-in administrator with branding:read." }),
  })
  .openapi("Branding");

async function brandingJson(env: Env) {
  const [brand, trail, css, language] = await Promise.all([defaultBrand(env), getCursorTrail(env), defaultCustomCss(env), getDefaultLanguage(env)]);
  return {
    app_name: brand.appName,
    login_subtitle: brand.subtitle,
    login_gradient: brand.gradient,
    cursor_trail: trail,
    default_language: language,
    available_languages: allLocales().map((l) => ({ code: l.code, name: l.name, native_name: l.nativeName, machine_assisted: l.machineAssisted })),
    email_accent: brand.accent,
    logo_url: brand.logoUrl,
    custom_css: css,
    css_url: brand.cssUrl,
    preview_url: "/login?brand_preview=default",
  };
}

defineRoute({ method: "get", path: "/api/v1/branding", tag: "Branding", permission: "branding:read", summary: "Read the default brand", response: BrandingSchema }, async (c) => c.json(await brandingJson(c.env)));

defineRoute(
  {
    method: "patch",
    path: "/api/v1/branding",
    tag: "Branding",
    permission: "branding:write",
    summary: "Change the default brand",
    description:
      "Fields not supplied keep their values. Colours are #rrggbb. An empty `login_subtitle` shows no message; empty cursor-trail `characters` uses the default symbols; `default_language` must be one of `available_languages`. `custom_css` (at most 20 KB; empty removes it) is refused if it contains `</style`, `@import`, `expression(`, `javascript:` or a `url(` that is not a same-origin path or a data: URL - the page's Content-Security-Policy blocks remote fonts and images anyway.",
    body: z.object({
      app_name: z.string().optional(),
      login_subtitle: z.string().optional(),
      login_gradient: GradientSchema.optional(),
      cursor_trail: z.object({ enabled: z.boolean().optional(), characters: z.string().optional() }).optional(),
      default_language: z.string().optional(),
      email_accent: z.string().optional(),
      custom_css: z.string().optional(),
    }),
    response: BrandingSchema,
  },
  async (c) => {
    const body = await readJson<{ app_name?: string; login_subtitle?: string; login_gradient?: { from: string; to: string }; cursor_trail?: { enabled?: boolean; characters?: string }; default_language?: string; email_accent?: string; custom_css?: string }>(c);
    // Everything validated before anything is saved.
    if (body.app_name !== undefined && !body.app_name.trim()) return c.json(badRequest("app_name cannot be empty."), 400);
    if (body.login_gradient && (!isHexColor(body.login_gradient.from) || !isHexColor(body.login_gradient.to))) return c.json(badRequest("login_gradient.from and .to must both be #rrggbb hex colours."), 400);
    if (body.email_accent !== undefined && !isHexColor(body.email_accent)) return c.json(badRequest("email_accent must be a #rrggbb hex colour."), 400);
    if (body.custom_css !== undefined) cleanCustomCss(body.custom_css);
    if (body.default_language !== undefined && !isSupportedLocale(body.default_language)) return c.json(badRequest(`default_language must be one of: ${SUPPORTED_LOCALES.join(", ")}.`), 400);
    const ctx = apiCtx(c);
    if (body.app_name !== undefined) await saveAppName(ctx, body.app_name.trim());
    if (body.login_subtitle !== undefined) await saveLoginSubtitle(ctx, body.login_subtitle);
    if (body.login_gradient) await saveLoginGradient(ctx, body.login_gradient.from, body.login_gradient.to);
    if (body.cursor_trail) {
      const current = await getCursorTrail(c.env);
      await saveCursorTrail(ctx, { enabled: body.cursor_trail.enabled ?? current.enabled, characters: body.cursor_trail.characters ?? current.characters });
    }
    if (body.default_language !== undefined) await saveDefaultLanguage(ctx, body.default_language);
    if (body.email_accent !== undefined) await saveEmailAccent(ctx, body.email_accent);
    if (body.custom_css !== undefined) await saveDefaultCustomCss(ctx, body.custom_css);
    return c.json(await brandingJson(c.env));
  }
);

const LogoBody = z.object({
  data: z.string().openapi({ description: "The image, base64-encoded (a `data:image/...;base64,` prefix is accepted). PNG or JPEG, at most 256 KB, recognised by its bytes; SVG is refused." }),
});

/** The image bytes from a LogoBody; a refusal for anything that is not base64. */
async function logoBytes(c: ApiContext): Promise<Uint8Array> {
  const body = await readJson<{ data?: unknown }>(c);
  const raw = typeof body.data === "string" ? body.data.replace(/^data:[^,]*;base64,/, "").replace(/\s+/g, "") : "";
  if (!raw) throw new ServiceError(400, "data must be the base64-encoded image.");
  // Bounded before decoding: base64 is 4/3 of the bytes.
  if (raw.length > Math.ceil((LOGO_MAX_BYTES * 4) / 3) + 4) throw new ServiceError(400, `A logo can be at most ${LOGO_MAX_BYTES / 1024} KB.`);
  try {
    return base64ToBytes(raw);
  } catch {
    throw new ServiceError(400, "data is not valid base64.");
  }
}

defineRoute(
  { method: "put", path: "/api/v1/branding/logo", tag: "Branding", permission: "branding:write", summary: "Upload the default brand's logo", description: "Shown on the sign-in pages, the top bar and emails. Replaces (and deletes) the previous upload.", body: LogoBody, response: BrandingSchema },
  async (c) => {
    await uploadLogo(apiCtx(c), null, await logoBytes(c));
    return c.json(await brandingJson(c.env));
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/branding/logo", tag: "Branding", permission: "branding:write", summary: "Remove the default brand's logo", description: "FlareID's own mark is shown again.", response: BrandingSchema },
  async (c) => {
    await removeLogo(apiCtx(c), null);
    return c.json(await brandingJson(c.env));
  }
);

// Brands attached to domains.

const BrandSchema = z
  .object({
    id: z.number(),
    name: z.string(),
    app_name: z.string().nullable().openapi({ description: "null: the default brand's." }),
    login_subtitle: z.string().nullable().openapi({ description: "null: the default brand's; empty: no message." }),
    login_gradient: GradientSchema.nullable().openapi({ description: "null: the default brand's." }),
    email_accent: z.string().nullable().openapi({ description: "null: the default brand's." }),
    logo_url: z.string().nullable().openapi({ description: "This brand's own upload; null uses the default brand's logo." }),
    custom_css: z.string().openapi({ description: "Empty uses the default brand's stylesheet." }),
    domains: z.array(z.string()).openapi({ description: "The domains whose people see this brand." }),
    effective: z
      .object({ app_name: z.string(), login_subtitle: z.string(), login_gradient: GradientSchema, email_accent: z.string(), logo_url: z.string().nullable(), css_url: z.string().nullable() })
      .openapi({ description: "What the pages and emails actually use, with the default brand filling the gaps." }),
    preview_url: z.string(),
    created_at: z.string(),
    updated_at: z.string(),
  })
  .openapi("Brand");

async function brandJson(env: Env, row: BrandRow) {
  const [def, css, domains] = await Promise.all([
    defaultBrand(env),
    env.DB.prepare("SELECT custom_css FROM brands WHERE id = ?").bind(row.id).first<{ custom_css: string }>(),
    env.DB.prepare("SELECT domain FROM domains WHERE brand_id = ? ORDER BY domain").bind(row.id).all<{ domain: string }>(),
  ]);
  const eff = mergeBrand(def, row);
  return {
    id: row.id,
    name: row.name,
    app_name: row.app_name || null,
    login_subtitle: row.login_subtitle,
    login_gradient: row.gradient_from && row.gradient_to ? { from: row.gradient_from, to: row.gradient_to } : null,
    email_accent: row.email_accent,
    logo_url: row.logo_asset_id && row.logo_sha && row.logo_type ? logoPath(row.logo_asset_id, row.logo_sha, row.logo_type) : null,
    custom_css: css?.custom_css ?? "",
    domains: domains.results.map((d) => d.domain),
    effective: { app_name: eff.appName, login_subtitle: eff.subtitle, login_gradient: eff.gradient, email_accent: eff.accent, logo_url: eff.logoUrl, css_url: eff.cssUrl },
    preview_url: `/login?brand_preview=${row.id}`,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

const BrandBody = z.object({
  name: z.string().optional(),
  app_name: z.string().nullable().optional(),
  login_subtitle: z.string().nullable().optional(),
  login_gradient: GradientSchema.nullable().optional(),
  email_accent: z.string().nullable().optional(),
  custom_css: z.string().nullable().optional(),
  domains: z.array(z.string()).optional().openapi({ description: "Replaces the set of domains using this brand; a domain moves from any brand it was on." }),
});

function brandId(c: ApiContext): number {
  const id = Number(param(c, "id"));
  if (!Number.isInteger(id)) throw new ServiceError(404, "No such brand.");
  return id;
}

async function brandOr404(c: ApiContext): Promise<BrandRow> {
  const row = await getBrandRow(c.env, brandId(c));
  if (!row) throw new ServiceError(404, "No such brand.");
  return row;
}

defineRoute(
  { method: "get", path: "/api/v1/branding/brands", tag: "Branding", permission: "branding:read", summary: "List the brands attached to domains", description: "The default brand is `GET /api/v1/branding`.", response: z.object({ brands: z.array(BrandSchema) }) },
  async (c) => c.json({ brands: await Promise.all((await listBrandRows(c.env)).map((r) => brandJson(c.env, r))) })
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/branding/brands",
    tag: "Branding",
    permission: "branding:write",
    summary: "Create a brand",
    description: "`name` is required and unique. Fields left out or null use the default brand's value. `custom_css` follows the rules of `PATCH /api/v1/branding`.",
    body: BrandBody.extend({ name: z.string() }),
    status: 201,
    errors: [409],
    response: BrandSchema,
  },
  async (c) => {
    const row = await createBrand(apiCtx(c), await readJson<BrandInput>(c));
    return c.json(await brandJson(c.env, row), 201);
  }
);

defineRoute(
  { method: "get", path: "/api/v1/branding/brands/{id}", tag: "Branding", permission: "branding:read", summary: "Read a brand", params: IdParam, errors: [404], response: BrandSchema },
  async (c) => c.json(await brandJson(c.env, await brandOr404(c)))
);

defineRoute(
  { method: "patch", path: "/api/v1/branding/brands/{id}", tag: "Branding", permission: "branding:write", summary: "Change a brand", description: "Fields not supplied keep their values; null resets one to the default brand's.", params: IdParam, body: BrandBody, errors: [404, 409], response: BrandSchema },
  async (c) => c.json(await brandJson(c.env, await updateBrand(apiCtx(c), brandId(c), await readJson<BrandInput>(c))))
);

defineRoute(
  { method: "delete", path: "/api/v1/branding/brands/{id}", tag: "Branding", permission: "branding:write", summary: "Delete a brand", description: "Its domains go back to the default brand; its logo is deleted.", params: IdParam, errors: [404] },
  async (c) => {
    await deleteBrand(apiCtx(c), brandId(c));
    return c.json({ ok: true as const });
  }
);

defineRoute(
  { method: "put", path: "/api/v1/branding/brands/{id}/logo", tag: "Branding", permission: "branding:write", summary: "Upload a brand's logo", params: IdParam, body: LogoBody, errors: [404], response: BrandSchema },
  async (c) => {
    const id = brandId(c);
    await uploadLogo(apiCtx(c), id, await logoBytes(c));
    return c.json(await brandJson(c.env, (await getBrandRow(c.env, id))!));
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/branding/brands/{id}/logo", tag: "Branding", permission: "branding:write", summary: "Remove a brand's logo", description: "The brand uses the default brand's logo again.", params: IdParam, errors: [404], response: BrandSchema },
  async (c) => {
    const id = brandId(c);
    await removeLogo(apiCtx(c), id);
    return c.json(await brandJson(c.env, (await getBrandRow(c.env, id))!));
  }
);

const TemplateSchema = z.object({ subject: z.string(), heading: z.string(), body: z.string(), action: z.string(), footer: z.string() }).openapi("EmailTemplate");
const TEMPLATE_KEYS = Object.keys(TEMPLATE_INFO) as TemplateKey[];

async function templateJson(env: Env, key: TemplateKey) {
  const info = TEMPLATE_INFO[key];
  return { key, label: info.label, placeholders: info.placeholders, has_link: info.hasLink, customised: Boolean(await getSetting(env, `email_template_${key}`)), ...(await getTemplate(env, key)) };
}

function templateKey(c: ApiContext): TemplateKey | null {
  const key = param(c, "key");
  return (TEMPLATE_KEYS as string[]).includes(key) ? (key as TemplateKey) : null;
}

const TemplateOut = TemplateSchema.extend({ key: z.string(), label: z.string(), placeholders: z.array(z.string()), has_link: z.boolean(), customised: z.boolean() });

defineRoute(
  {
    method: "get",
    path: "/api/v1/branding/email-templates",
    tag: "Branding",
    permission: "branding:read",
    summary: "List the email templates",
    description: `Keys: ${TEMPLATE_KEYS.join(", ")}. Text fields take {{placeholders}}; the layout is FlareID's own.`,
    response: z.object({ accent: z.string(), templates: z.array(TemplateOut) }),
  },
  async (c) => c.json({ accent: await getAccent(c.env), templates: await Promise.all(TEMPLATE_KEYS.map((k) => templateJson(c.env, k))) })
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/branding/email-templates/{key}",
    tag: "Branding",
    permission: "branding:write",
    summary: "Replace an email template",
    description: "Fields not supplied take the default wording. Subject and heading cannot be empty.",
    params: z.object({ key: z.enum(TEMPLATE_KEYS as [TemplateKey, ...TemplateKey[]]) }),
    body: TemplateSchema.partial(),
    errors: [404],
    response: TemplateOut,
  },
  async (c) => {
    const key = templateKey(c);
    if (!key) return notFound(c, "No such template.");
    await saveEmailTemplate(apiCtx(c), key, await readJson<Partial<(typeof DEFAULT_TEMPLATES)[TemplateKey]>>(c));
    return c.json(await templateJson(c.env, key));
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/branding/email-templates/{key}",
    tag: "Branding",
    permission: "branding:write",
    summary: "Reset an email template to the default",
    params: z.object({ key: z.enum(TEMPLATE_KEYS as [TemplateKey, ...TemplateKey[]]) }),
    errors: [404],
    response: TemplateOut,
  },
  async (c) => {
    const key = templateKey(c);
    if (!key) return notFound(c, "No such template.");
    await saveEmailTemplate(apiCtx(c), key, null);
    return c.json(await templateJson(c.env, key));
  }
);

// ---------------------------------------------------------------------------
// Security settings
// ---------------------------------------------------------------------------

const TurnstileSchema = z
  .object({
    mode: z.enum(["off", "on"]).openapi({ description: "`on` checks the password sign-in and password-recovery forms." }),
    active: z.boolean().openapi({ description: "`mode` is on and both keys are present, so the widget is shown." }),
    site_key: z.string(),
    secret_set: z.boolean().openapi({ description: "The secret is write-only: never returned." }),
    secret_from_env: z.boolean().openapi({ description: "The TURNSTILE_SECRET_KEY Worker secret is set and used instead of a stored secret." }),
  })
  .openapi("TurnstileSettings");

const SecuritySchema = z
  .object({
    password_policy: PasswordPolicySchema,
    rate_limit: z.object({ max_attempts: z.number(), window_minutes: z.number() }),
    session_limits: z.object({ max_hours: z.number(), idle_minutes: z.number() }),
    audit_retention_days: z.number(),
    new_user_password: z.object({ mode: z.enum(["default", "random"]), default_password_set: z.boolean() }),
    require_mfa: z.boolean(),
    breached_password_check: z.boolean().openapi({ description: "New passwords found in Have I Been Pwned's breach corpus are refused." }),
    turnstile: TurnstileSchema,
  })
  .openapi("SecuritySettings");

async function securityJson(env: Env) {
  const [policy, rate, session, retention, mode, defaultPassword, mfa, breached, turnstile] = await Promise.all([
    getPasswordPolicy(env),
    getRateLimitPolicy(env),
    getSessionPolicy(env),
    getAuditRetentionDays(env),
    getNewUserPasswordMode(env),
    getDefaultPassword(env),
    isMfaRequired(env),
    isBreachedPasswordCheckEnabled(env),
    getTurnstileConfig(env),
  ]);
  return {
    password_policy: policy,
    rate_limit: { max_attempts: rate.maxAttempts, window_minutes: rate.windowMinutes },
    session_limits: { max_hours: session.maxHours, idle_minutes: session.idleMinutes },
    audit_retention_days: retention,
    // Whether one is set, never the password itself.
    new_user_password: { mode, default_password_set: Boolean(defaultPassword) },
    require_mfa: mfa,
    breached_password_check: breached,
    // Whether a secret is set, never the secret itself.
    turnstile: {
      mode: turnstile.mode,
      active: activeTurnstileSiteKey(turnstile) !== null,
      site_key: turnstile.siteKey,
      secret_set: Boolean(turnstile.secret),
      secret_from_env: turnstile.secretFromEnv,
    },
  };
}

defineRoute(
  { method: "get", path: "/api/v1/security", tag: "Security", permission: "security:read", summary: "Read the security settings", response: SecuritySchema },
  async (c) => c.json(await securityJson(c.env))
);

defineRoute(
  { method: "put", path: "/api/v1/security/password-policy", tag: "Security", permission: "security:write", summary: "Set the password policy", description: "Omitted rules are off; minLength defaults to 8.", body: PasswordPolicySchema, response: SecuritySchema },
  async (c) => {
    await savePasswordPolicy(apiCtx(c), await readJson<Record<string, unknown>>(c));
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/security/breached-passwords",
    tag: "Security",
    permission: "security:write",
    summary: "Switch the breached-password check on or off",
    description:
      "When on (the default), passwords people choose - self-service changes, invitations, resets, passwords set by administrators and imported passwords (imports with up to 200 explicit passwords) - are refused if they appear in Have I Been Pwned's breach corpus. Only the first 5 characters of the password's SHA-1 hash are sent (k-anonymity). If the service cannot be reached the password is allowed.",
    body: z.object({ enabled: z.boolean() }),
    response: SecuritySchema,
  },
  async (c) => {
    await saveBreachedPasswordCheck(apiCtx(c), (await readJson<{ enabled: boolean }>(c)).enabled === true);
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/security/turnstile",
    tag: "Security",
    permission: "security:write",
    summary: "Configure bot protection (Cloudflare Turnstile)",
    description:
      "Fields not supplied keep their values; an empty or omitted `secret` keeps the saved one. The secret is write-only. `mode: on` needs a site key and a secret (or the TURNSTILE_SECRET_KEY Worker secret) and protects the password sign-in and password-recovery forms; passkey sign-in is not challenged.",
    body: z.object({ mode: z.enum(["off", "on"]).optional(), site_key: z.string().optional(), secret: z.string().optional() }),
    response: SecuritySchema,
  },
  async (c) => {
    const body = await readJson<{ mode?: string; site_key?: string; secret?: string }>(c);
    await saveTurnstile(apiCtx(c), { mode: body.mode, siteKey: body.site_key, secret: body.secret });
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  { method: "put", path: "/api/v1/security/rate-limit", tag: "Security", permission: "security:write", summary: "Set the sign-in rate limit", body: z.object({ max_attempts: z.number().int().positive(), window_minutes: z.number().int().positive() }), response: SecuritySchema },
  async (c) => {
    const body = await readJson<{ max_attempts: number; window_minutes: number }>(c);
    await saveRateLimit(apiCtx(c), body.max_attempts, body.window_minutes);
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/security/session-limits",
    tag: "Security",
    permission: "security:write",
    summary: "Set the session limits",
    description: "`max_hours` 1-720; `idle_minutes` 5-10080, or 0 for no idle limit. Out-of-range values are clamped. Applies to existing sessions at once.",
    body: z.object({ max_hours: z.number(), idle_minutes: z.number() }),
    response: SecuritySchema,
  },
  async (c) => {
    const body = await readJson<{ max_hours: number; idle_minutes: number }>(c);
    await saveSessionLimits(apiCtx(c), body.max_hours, body.idle_minutes);
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  { method: "put", path: "/api/v1/security/audit-retention", tag: "Security", permission: "security:write", summary: "Set how long the audit log is kept", description: "30-3650 days, clamped.", body: z.object({ days: z.number() }), response: SecuritySchema },
  async (c) => {
    await saveAuditRetention(apiCtx(c), (await readJson<{ days: number }>(c)).days);
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/security/new-user-password",
    tag: "Security",
    permission: "security:write",
    summary: "Set what password new accounts get",
    description: "`mode: default` gives new accounts the shared `default_password` (generated if none is set); `random` generates one per account.",
    body: z.object({ mode: z.enum(["default", "random"]).optional(), default_password: z.string().optional() }),
    response: SecuritySchema,
  },
  async (c) => {
    const body = await readJson<{ mode?: string; default_password?: string }>(c);
    if (body.default_password !== undefined) await saveDefaultPassword(apiCtx(c), String(body.default_password));
    if (body.mode !== undefined) await saveNewUserPasswordMode(apiCtx(c), body.mode);
    return c.json(await securityJson(c.env));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/security/new-user-password/apply-to-all",
    tag: "Security",
    permission: "admin",
    summary: "Set every account's password to the default password",
    description: "Administrators' accounts included, so it needs `*`. Optionally sets `default_password` first. Refused (0 changed) when no default is set.",
    body: z.object({ default_password: z.string().optional() }),
    response: z.object({ ok: z.literal(true), updated: z.number() }),
  },
  async (c) => {
    const body = await readOptionalJson<{ default_password?: string }>(c);
    return c.json({ ok: true, updated: await applyDefaultPasswordToAll(apiCtx(c), String(body.default_password ?? "")) });
  }
);

defineRoute(
  { method: "put", path: "/api/v1/security/require-mfa", tag: "Security", permission: "security:write", summary: "Require a second factor for everyone (legacy switch)", description: "Authentication policies are the finer-grained control.", body: z.object({ required: z.boolean() }), response: SecuritySchema },
  async (c) => {
    await saveRequireMfa(apiCtx(c), (await readJson<{ required: boolean }>(c)).required === true);
    return c.json(await securityJson(c.env));
  }
);

// ---------------------------------------------------------------------------
// Authentication policies
// ---------------------------------------------------------------------------

const PolicySchema = z
  .object({ id: z.number(), name: z.string(), description: z.string(), requirement: z.enum(["password", "mfa"]), priority: z.number(), is_default: z.boolean(), groups: z.array(z.string()) })
  .openapi("AuthPolicy");

async function policiesJson(env: Env) {
  return (await listPolicies(env)).map((p) => ({ id: p.id, name: p.name, description: p.description, requirement: p.requirement, priority: p.priority, is_default: p.is_default === 1, groups: p.groups.map((g) => g.name) }));
}

const PolicyWrite = {
  description: z.string().optional(),
  requirement: z.enum(["password", "mfa"]).optional().openapi({ description: "Password alone, or password plus a second factor; a passkey satisfies either." }),
  priority: z.number().int().optional().openapi({ description: "1-1000; lower wins when several policies match." }),
  groups: z.array(z.string()).optional().openapi({ description: "Group names the policy applies to." }),
};

defineRoute(
  { method: "get", path: "/api/v1/security/policies", tag: "Security", permission: "security:read", summary: "List authentication policies", response: z.object({ policies: z.array(PolicySchema) }) },
  async (c) => c.json({ policies: await policiesJson(c.env) })
);

defineRoute(
  { method: "post", path: "/api/v1/security/policies", tag: "Security", permission: "security:write", summary: "Create an authentication policy", body: z.object({ name: z.string(), ...PolicyWrite }), status: 201, response: PolicySchema },
  async (c) => {
    const body = await readJson<{ name: string; description?: string; requirement?: string; priority?: number; groups?: string[] }>(c);
    const id = await createPolicy(apiCtx(c), normalizePolicy({ ...body, groupIds: await groupIdsByName(c.env, body.groups ?? []) }));
    return c.json((await policiesJson(c.env)).find((p) => p.id === id), 201);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/security/policies/{id}",
    tag: "Security",
    permission: "security:write",
    summary: "Update an authentication policy",
    description: "Fields not supplied keep their values. `make_default: true` makes it the policy for everyone no other policy matches.",
    params: IdParam,
    body: z.object({ name: z.string().optional(), make_default: z.boolean().optional(), ...PolicyWrite }),
    errors: [404],
    response: PolicySchema,
  },
  async (c) => {
    const id = Number(param(c, "id"));
    const current = (await policiesJson(c.env)).find((p) => p.id === id);
    if (!current) return notFound(c, `No policy with id ${id}.`);
    const body = await readJson<{ name?: string; description?: string; requirement?: string; priority?: number; groups?: string[]; make_default?: boolean }>(c);
    await updatePolicy(
      apiCtx(c),
      id,
      normalizePolicy({
        name: body.name ?? current.name,
        description: body.description ?? current.description,
        requirement: body.requirement ?? current.requirement,
        priority: body.priority ?? current.priority,
        groupIds: await groupIdsByName(c.env, body.groups ?? current.groups),
        makeDefault: body.make_default,
      })
    );
    return c.json((await policiesJson(c.env)).find((p) => p.id === id));
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/security/policies/{id}", tag: "Security", permission: "security:write", summary: "Delete an authentication policy", description: "The default policy cannot be deleted.", params: IdParam, errors: [404] },
  async (c) => {
    await deletePolicy(apiCtx(c), Number(param(c, "id")));
    return c.json({ ok: true });
  }
);

// ---------------------------------------------------------------------------
// Factors
// ---------------------------------------------------------------------------

const FactorSchema = z
  .object({
    key: z.string(),
    label: z.string(),
    description: z.string(),
    available: z.boolean(),
    enabled: z.boolean().openapi({ description: "The administrator's switch." }),
    usable: z.boolean().openapi({ description: "Switched on and able to work now: email one-time codes also need email to be configured." }),
    enrolled_users: z.number().nullable(),
  })
  .openapi("Factor");

async function factorsJson(env: Env) {
  const enrolled = await factorEnrolmentCounts(env);
  return Promise.all(
    FACTORS.map(async (f) => ({
      key: f.key,
      label: f.label,
      description: f.description,
      available: f.available,
      enabled: f.available ? await isFactorEnabled(env, f.key as FactorKey) : false,
      usable: f.available ? await isFactorUsable(env, f.key as FactorKey) : false,
      enrolled_users: enrolled[f.key] ?? null,
    }))
  );
}

defineRoute(
  { method: "get", path: "/api/v1/security/factors", tag: "Security", permission: "security:read", summary: "List second factors", response: z.object({ factors: z.array(FactorSchema) }) },
  async (c) => c.json({ factors: await factorsJson(c.env) })
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/security/factors/{key}",
    tag: "Security",
    permission: "security:write",
    summary: "Turn a second factor on or off",
    description:
      "At least one factor must stay on while a policy requires a second factor. Email one-time codes (email_otp) are off on a fresh install and can be switched on only once email is configured. Security questions (security_questions) are off on a fresh install and need at least as many enabled questions as each person sets (see /api/v1/security/security-questions).",
    params: z.object({ key: z.enum(["totp", "passkey", "email_otp", "security_questions"]) }),
    body: z.object({ enabled: z.boolean() }),
    response: z.object({ factors: z.array(FactorSchema) }),
  },
  async (c) => {
    await saveFactor(apiCtx(c), param(c, "key"), (await readJson<{ enabled: boolean }>(c)).enabled === true);
    return c.json({ factors: await factorsJson(c.env) });
  }
);

// ---------------------------------------------------------------------------
// Security questions
// ---------------------------------------------------------------------------

const SecurityQuestionSchema = z
  .object({
    id: z.number(),
    text: z.string(),
    enabled: z.boolean().openapi({ description: "Offered when people choose their questions. Answers to a disabled question keep working." }),
    answered_by: z.number().openapi({ description: "How many people answered it. A question with answers cannot be deleted." }),
    created_at: z.string(),
  })
  .openapi("SecurityQuestion");

const SecurityQuestionsSchema = z
  .object({
    enabled: z.boolean().openapi({ description: "The factor's switch (PUT /api/v1/security/factors/security_questions)." }),
    required: z.number().openapi({ description: "How many questions each person sets." }),
    asked: z.number().openapi({ description: "How many of them are asked, picked at random, at each sign-in." }),
    questions: z.array(SecurityQuestionSchema),
  })
  .openapi("SecurityQuestions");

async function securityQuestionsJson(env: Env) {
  const [kba, questions, enabled] = await Promise.all([getKbaSettings(env), listSecurityQuestions(env), isFactorEnabled(env, "security_questions")]);
  return { enabled, required: kba.required, asked: kba.asked, questions: questions.map((q) => ({ id: q.id, text: q.text, enabled: q.enabled === 1, answered_by: q.answered_by, created_at: q.created_at })) };
}

defineRoute(
  {
    method: "get",
    path: "/api/v1/security/security-questions",
    tag: "Security",
    permission: "security:read",
    summary: "Read the security-questions settings and catalogue",
    description: "Answers are never exposed: they are stored only as salted hashes.",
    response: SecurityQuestionsSchema,
  },
  async (c) => c.json(await securityQuestionsJson(c.env))
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/security/security-questions",
    tag: "Security",
    permission: "security:write",
    summary: "Change how many security questions are set and asked",
    description: "`required` is 1-10 and at most the number of enabled questions; `asked` is 1 to `required`. Fields left out keep their value.",
    body: z.object({ required: z.number().int().optional(), asked: z.number().int().optional() }),
    response: SecurityQuestionsSchema,
  },
  async (c) => {
    const body = await readJson<{ required?: number; asked?: number }>(c);
    await saveKbaSettings(apiCtx(c), body);
    return c.json(await securityQuestionsJson(c.env));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/security/security-questions/questions",
    tag: "Security",
    permission: "security:write",
    summary: "Add a security question",
    description: "5-200 characters; a question already in the list (ignoring case) is a 409.",
    body: z.object({ text: z.string() }),
    status: 201,
    response: SecurityQuestionSchema,
    errors: [409],
  },
  async (c) => {
    const row = await addSecurityQuestion(apiCtx(c), (await readJson<{ text: string }>(c)).text);
    return c.json({ id: row.id, text: row.text, enabled: row.enabled === 1, answered_by: 0, created_at: row.created_at }, 201);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/security/security-questions/questions/{id}",
    tag: "Security",
    permission: "security:write",
    summary: "Enable or disable a security question",
    description: "At least as many questions as each person sets must stay enabled.",
    params: IdParam,
    body: z.object({ enabled: z.boolean() }),
    response: SecurityQuestionSchema,
    errors: [404],
  },
  async (c) => {
    const id = Number(param(c, "id"));
    await setSecurityQuestionEnabled(apiCtx(c), id, (await readJson<{ enabled: boolean }>(c)).enabled === true);
    return c.json((await securityQuestionsJson(c.env)).questions.find((q) => q.id === id));
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/security/security-questions/questions/{id}",
    tag: "Security",
    permission: "security:write",
    summary: "Delete a security question",
    description: "Only a question nobody has answered (409 otherwise: disable it instead).",
    params: IdParam,
    errors: [404, 409],
  },
  async (c) => {
    await deleteSecurityQuestion(apiCtx(c), Number(param(c, "id")));
    return c.json({ ok: true });
  }
);

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

const RoleSchema = z
  .object({ id: z.number(), name: z.string(), description: z.string(), builtin: z.boolean(), is_default: z.boolean(), permissions: z.array(z.string()), groups: z.array(z.string()) })
  .openapi("Role");

async function rolesJson(env: Env) {
  return (await listRoles(env)).map((r) => ({ id: r.id, name: r.name, description: r.description, builtin: r.builtin === 1, is_default: r.is_default === 1, permissions: rolePermissions(r), groups: r.groups.map((g) => g.name) }));
}

const RoleWrite = {
  description: z.string().optional(),
  permissions: z.array(z.string()).optional().openapi({ description: "Permissions (`users:read`, `oidc:write`, `signin`, `account:write`, `*`). None beyond what the calling token holds; `*` only with `*`." }),
  groups: z.array(z.string()).optional().openapi({ description: "Group names the role is granted to (ignored for a default role, which applies to everyone)." }),
};

defineRoute(
  { method: "get", path: "/api/v1/security/roles", tag: "Roles", permission: "roles:read", summary: "List roles", response: z.object({ roles: z.array(RoleSchema) }) },
  async (c) => c.json({ roles: await rolesJson(c.env) })
);

defineRoute(
  { method: "post", path: "/api/v1/security/roles", tag: "Roles", permission: "roles:write", summary: "Create a role", body: z.object({ name: z.string(), ...RoleWrite }), status: 201, response: RoleSchema },
  async (c) => {
    const body = await readJson<{ name: string; description?: string; permissions?: string[]; groups?: string[] }>(c);
    const f = normalizeRole({ name: body.name, description: body.description, permissions: body.permissions ?? [], groupIds: await groupIdsByName(c.env, body.groups ?? []) }, expand(c.get("apiActor").scopes));
    const id = await createRole(apiCtx(c), f);
    return c.json((await rolesJson(c.env)).find((r) => r.id === id), 201);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/security/roles/{id}",
    tag: "Roles",
    permission: "roles:write",
    summary: "Update a role",
    description: "Fields not supplied keep their values. Super Admin cannot be changed; a built-in role keeps its name.",
    params: IdParam,
    body: z.object({ name: z.string().optional(), ...RoleWrite }),
    errors: [404],
    response: RoleSchema,
  },
  async (c) => {
    const id = Number(param(c, "id"));
    const current = (await rolesJson(c.env)).find((r) => r.id === id);
    if (!current) return notFound(c, `No role with id ${id}.`);
    const body = await readJson<{ name?: string; description?: string; permissions?: string[]; groups?: string[] }>(c);
    const f = normalizeRole(
      { name: body.name ?? current.name, description: body.description ?? current.description, permissions: body.permissions ?? current.permissions, groupIds: await groupIdsByName(c.env, body.groups ?? current.groups) },
      expand(c.get("apiActor").scopes)
    );
    await updateRole(apiCtx(c), id, f);
    return c.json((await rolesJson(c.env)).find((r) => r.id === id));
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/security/roles/{id}", tag: "Roles", permission: "roles:write", summary: "Delete a role", description: "Built-in roles cannot be deleted.", params: IdParam, errors: [404] },
  async (c) => {
    await deleteRole(apiCtx(c), Number(param(c, "id")));
    return c.json({ ok: true });
  }
);

// ---------------------------------------------------------------------------
// Signing keys
// ---------------------------------------------------------------------------

const SigningKeySchema = z
  .object({ kid: z.string(), alg: z.enum(["RS256", "ES256"]), status: z.enum(["active", "retired"]), created_at: z.string(), retired_at: z.string().nullable(), public_jwk: z.record(z.string(), z.unknown()) })
  .openapi("SigningKey");

defineRoute(
  { method: "get", path: "/api/v1/security/signing-keys", tag: "Signing keys", permission: "signing_keys:read", summary: "List token signing keys", description: "Public parts only.", response: z.object({ keys: z.array(SigningKeySchema) }) },
  async (c) => {
    const keys = (await listSigningKeys(c.env)).map((k) => ({ kid: k.kid, alg: k.alg, status: k.status, created_at: k.created_at, retired_at: k.retired_at, public_jwk: JSON.parse(k.public_jwk) as Record<string, unknown> }));
    return c.json({ keys });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/security/signing-keys/{alg}/rotate",
    tag: "Signing keys",
    permission: "signing_keys:write",
    summary: "Rotate the signing key for an algorithm",
    description: "The old key is retired but stays published for 24 hours so tokens it signed still verify.",
    params: z.object({ alg: z.enum(["RS256", "ES256"]) }),
    response: z.object({ ok: z.literal(true), alg: z.string(), kid: z.string() }),
  },
  async (c) => c.json({ ok: true, alg: param(c, "alg"), kid: await rotateKey(apiCtx(c), param(c, "alg")) })
);

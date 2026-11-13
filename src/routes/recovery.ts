import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { authPage, AUTH_MESSAGES, fieldMsg, fieldText, formErrors, loginAppearance, msg, renderAuthMessage, requestLocale, type AppearanceHint, type AuthMessage, type Text } from "../lib/login-views.js";
import { html, t, tHtml, type Locale, type MessageKey } from "../lib/i18n.js";
import type { LoginAppearance } from "../lib/settings.js";
import { escapeHtml } from "../lib/html.js";
import { getUserById, getUserByLoginIdentifier } from "../lib/db.js";
import { hashPassword } from "../lib/password.js";
import { consumeAccountToken, peekAccountToken, revokeAccountTokens, type AccountTokenPurpose } from "../lib/account-tokens.js";
import { sendPasswordReset } from "../lib/account-email.js";
import { isEmailConfigured } from "../lib/email.js";
import { getPasswordPolicy, passwordPolicySummary } from "../lib/settings.js";
import { newPasswordError } from "../lib/breached-passwords.js";
import { allowTurnstileCsp, turnstileRefused, turnstileWidget } from "../lib/turnstile.js";
import { revokeAllSessionsForUser, revokeTokensForUser } from "../lib/sessions.js";
import { clearLoginAttempts, getClientIp, loginRateKey, rateLimitAddress, recordRateAttempt } from "../lib/rate-limit.js";
import { logAudit } from "../lib/audit.js";
import { isScimConfigured, pushUser } from "../lib/scim-client.js";
import type { UserRow } from "../lib/types.js";

/**
 * Self-service password recovery and invitation acceptance - the two flows
 * that start with a link in an email (see account-email.ts).
 *
 * Neither reveals whether an account exists: /forgot-password answers the
 * same way, in the same time, for any input, and does its real work - the
 * lookup, the per-account limit, the token and the send - after the response,
 * in waitUntil.
 */
export const recovery = new Hono<{ Bindings: Env }>();

/** Requests per account, and per address, per hour: enough for a typo or two, not for mail-bombing someone. */
const RESETS_PER_ACCOUNT_PER_HOUR = 3;
const RESETS_PER_IP_PER_HOUR = 10;

/**
 * A recovery page: in the person's brand once a link names them, else the
 * request's (hostname, ?domain=). The body is built for the page's language.
 */
async function page(c: Context<{ Bindings: Env }>, title: MessageKey, body: (appearance: LoginAppearance) => string, status: 200 | 400 = 200, hint: AppearanceHint = {}) {
  const appearance = await loginAppearance(c, hint);
  return c.html(authPage(t(appearance.locale, title), appearance, body(appearance)), status);
}

/** The new-password form. `intro` is markup (it emphasises the account name). The policy text describes the password field. */
function passwordForm(locale: Locale, action: string, policyText: string, error?: Text, intro?: string): string {
  const errors = formErrors(locale, error);
  return `
    ${intro ? `<p class="sub">${intro}</p>` : ""}
    ${errors.html}
    <form method="POST" action="${escapeHtml(action)}">
      <label for="password">${escapeHtml(t(locale, "password.new"))}</label>
      <input type="password" id="password" name="password" required autofocus autocomplete="new-password"${errors.attrs("password", { primary: true, hint: "password-policy" })} />
      <label for="confirm">${escapeHtml(t(locale, "password.confirmNew"))}</label>
      <input type="password" id="confirm" name="confirm" required autocomplete="new-password"${errors.attrs("confirm")} />
      <p class="muted" id="password-policy" style="margin-top:-6px; font-size:0.8125rem;">${escapeHtml(policyText)}</p>
      <div class="row"><button class="primary" type="submit">${escapeHtml(t(locale, "password.save"))}</button></div>
    </form>`;
}

const LINK_EXPIRED: AuthMessage = {
  title: msg("msg.linkExpired.title"),
  message: msg("msg.linkExpired.message"),
  action: { href: "/forgot-password", label: msg("msg.linkExpired.action") },
};

// ---------- Forgot password ----------

/** The recovery request form, with the Turnstile widget when bot protection is on. */
async function forgotPasswordForm(c: Context<{ Bindings: Env }>, error?: Text) {
  const appearance = await loginAppearance(c);
  const { locale } = appearance;
  const tx = (key: MessageKey) => escapeHtml(t(locale, key));
  allowTurnstileCsp(c, appearance.turnstileSiteKey);
  const errors = formErrors(locale, error);
  const body = `
    <h1>${tx("recovery.forgot.title")}</h1>
    <p class="sub">${tx("recovery.forgot.intro")}</p>
    ${errors.html}
    <form method="POST" action="/forgot-password">
      <label for="identifier">${tx("recovery.forgot.identifier")}</label>
      <input type="text" id="identifier" name="identifier" required autofocus autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false"${errors.attrs("identifier", { primary: true })} />
      ${turnstileWidget(appearance.turnstileSiteKey, "recovery", locale)}
      <div class="row"><button class="primary" type="submit">${tx("recovery.forgot.submit")}</button></div>
    </form>
    <p class="auth-alt"><a href="/login">${tx("common.backToSignIn")}</a></p>`;
  return c.html(authPage(t(locale, "recovery.forgot.title"), appearance, body), error ? 400 : 200);
}

recovery.get("/forgot-password", async (c) => {
  if (!(await isEmailConfigured(c.env))) return renderAuthMessage(c, 400, { title: msg("msg.recoveryUnavailable.title"), message: msg("msg.recoveryUnavailable.message"), action: null });
  return forgotPasswordForm(c);
});

recovery.post("/forgot-password", async (c) => {
  if (!(await isEmailConfigured(c.env))) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const body = await c.req.parseBody();
  // Before any lookup, rate-limit count or email: a refused check costs nothing.
  if (await turnstileRefused(c, body, "recovery")) return forgotPasswordForm(c, msg("turnstile.failed"));
  const identifier = String(body.identifier ?? "").slice(0, 254);
  const ip = getClientIp(c.req.raw);

  // Everything that depends on whether the account exists happens after the
  // response, so neither its content nor its timing says.
  c.executionCtx.waitUntil(
    (async () => {
      if (await recordRateAttempt(c.env, `recovery:ip:${rateLimitAddress(ip)}`, RESETS_PER_IP_PER_HOUR, 60)) return;
      const user = identifier ? await getUserByLoginIdentifier(c.env, identifier) : null;
      if (!user || user.status !== "active") return;
      if (await recordRateAttempt(c.env, `recovery:user:${user.id}`, RESETS_PER_ACCOUNT_PER_HOUR, 60)) {
        await logAudit(c.env, null, "user.password_reset_rate_limited", user.upn, { ip }, c.req.raw);
        return;
      }
      const sent = await sendPasswordReset(c.env, user);
      await logAudit(c.env, null, "user.password_reset_requested", user.upn, { ip, sent: sent.ok, ...(sent.ok ? {} : { error: sent.error }) }, c.req.raw);
    })().catch((err) => console.error(JSON.stringify({ event: "recovery_failed", error: String(err) })))
  );

  return page(
    c,
    "recovery.sent.title",
    ({ locale }) => `
    <h1>${escapeHtml(t(locale, "recovery.sent.title"))}</h1>
    <p class="sub" role="status">${escapeHtml(t(locale, "recovery.sent.message"))}</p>
    <p class="auth-alt"><a href="/login">${escapeHtml(t(locale, "common.backToSignIn"))}</a></p>`
  );
});

// ---------- The link targets: reset and invite ----------

async function linkTarget(c: Context<{ Bindings: Env }>, purpose: AccountTokenPurpose) {
  const token = c.req.param("token") ?? "";
  const userId = await peekAccountToken(c.env, token, purpose);
  const user = userId ? await getUserById(c.env, userId) : null;
  // A reset is for an active account; an invitation activates one.
  if (!user || (purpose === "reset" && user.status !== "active")) return { token, user: null };
  return { token, user };
}

recovery.get("/reset-password/:token", async (c) => {
  const { token, user } = await linkTarget(c, "reset");
  if (!user) return renderAuthMessage(c, 400, LINK_EXPIRED);
  const policy = await getPasswordPolicy(c.env);
  return page(
    c,
    "recovery.reset.title",
    ({ locale }) =>
      `<h1>${escapeHtml(t(locale, "recovery.reset.title"))}</h1>${passwordForm(locale, `/reset-password/${token}`, passwordPolicySummary(policy, locale), undefined, tHtml(locale, "recovery.reset.for", { upn: html(`<strong>${escapeHtml(user.upn)}</strong>`) }))}`,
    200,
    { userId: user.id }
  );
});

recovery.get("/invite/:token", async (c) => {
  const { token, user } = await linkTarget(c, "invite");
  if (!user) return renderAuthMessage(c, 400, { ...LINK_EXPIRED, action: null, message: msg("msg.inviteExpired.message") });
  const policy = await getPasswordPolicy(c.env);
  return page(
    c,
    "recovery.invite.title",
    ({ locale }) =>
      `<h1>${escapeHtml(t(locale, "recovery.invite.heading", { name: user.display_name || user.username }))}</h1>${passwordForm(locale, `/invite/${token}`, passwordPolicySummary(policy, locale), undefined, tHtml(locale, "recovery.invite.intro", { upn: html(`<strong>${escapeHtml(user.upn)}</strong>`) }))}`,
    200,
    { userId: user.id }
  );
});

/** Shared POST: validate, then use the token up, then set the password. Returns the user, or a response to send. */
async function acceptPassword(c: Context<{ Bindings: Env }>, purpose: AccountTokenPurpose): Promise<{ user: UserRow } | { response: Response }> {
  const token = c.req.param("token") ?? "";
  const body = await c.req.parseBody();
  const password = String(body.password ?? "");
  const policy = await getPasswordPolicy(c.env);
  const action = `/${purpose === "reset" ? "reset-password" : "invite"}/${token}`;

  // Validated before the token is used, so a weak password does not burn the link.
  // Worded in the page's language.
  const locale = await requestLocale(c);
  const policyError = password !== String(body.confirm ?? "") ? null : await newPasswordError(c.env, password, policy, locale);
  const error: Text | null = password !== String(body.confirm ?? "") ? fieldMsg("password.mismatch", undefined, "confirm") : policyError ? fieldText(policyError) : null;
  if (error) {
    const { user } = await linkTarget(c, purpose);
    if (!user) return { response: await renderAuthMessage(c, 400, LINK_EXPIRED) };
    return {
      response: await page(
        c,
        "recovery.choose.title",
        ({ locale }) => `<h1>${escapeHtml(t(locale, "recovery.choose.title"))}</h1>${passwordForm(locale, action, passwordPolicySummary(policy, locale), error)}`,
        400,
        { userId: user.id }
      ),
    };
  }

  const userId = await consumeAccountToken(c.env, token, purpose);
  const user = userId ? await getUserById(c.env, userId) : null;
  if (!user || (purpose === "reset" && user.status !== "active")) return { response: await renderAuthMessage(c, 400, LINK_EXPIRED) };

  const { hash, salt, iterations } = await hashPassword(password, c.env);
  const now = new Date().toISOString();
  await c.env.DB.prepare(
    `UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ?${purpose === "invite" ? ", status = 'active'" : ""} WHERE id = ?`
  )
    .bind(hash, salt, iterations, now, user.id)
    .run();
  // Whoever had the old password, or an older link, is out.
  await revokeAllSessionsForUser(c.env, user.id);
  await revokeTokensForUser(c.env, user.id);
  await clearLoginAttempts(c.env, loginRateKey(user.upn, user));
  return { user: { ...user, status: "active" } };
}

recovery.post("/reset-password/:token", async (c) => {
  const result = await acceptPassword(c, "reset");
  if ("response" in result) return result.response;
  await logAudit(c.env, result.user, "user.password_reset_completed", result.user.upn, undefined, c.req.raw);
  return renderAuthMessage(c, 200, { title: msg("msg.passwordChanged.title"), message: msg("msg.passwordChanged.message"), action: { href: "/login", label: msg("common.signIn") } }, { userId: result.user.id });
});

recovery.post("/invite/:token", async (c) => {
  const result = await acceptPassword(c, "invite");
  if ("response" in result) return result.response;
  await logAudit(c.env, result.user, "user.invitation_accepted", result.user.upn, undefined, c.req.raw);
  if (await isScimConfigured(c.env)) {
    const user = await getUserById(c.env, result.user.id);
    if (user) c.executionCtx.waitUntil(pushUser(c.env, user).then(() => undefined));
  }
  return renderAuthMessage(c, 200, { title: msg("msg.accountReady.title"), message: msg("msg.accountReady.message"), action: { href: "/login", label: msg("common.signIn") } }, { userId: result.user.id });
});

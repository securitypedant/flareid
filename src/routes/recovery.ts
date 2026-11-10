import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { authPage, AUTH_MESSAGES, renderAuthMessage } from "../lib/login-views.js";
import { escapeHtml } from "../lib/html.js";
import { getUserById, getUserByLoginIdentifier } from "../lib/db.js";
import { hashPassword } from "../lib/password.js";
import { consumeAccountToken, peekAccountToken, revokeAccountTokens, type AccountTokenPurpose } from "../lib/account-tokens.js";
import { sendPasswordReset } from "../lib/account-email.js";
import { isEmailConfigured } from "../lib/email.js";
import { getLoginAppearance, getPasswordPolicy, passwordPolicySummary, validatePassword } from "../lib/settings.js";
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

async function page(c: Context<{ Bindings: Env }>, title: string, body: string, status: 200 | 400 = 200) {
  return c.html(authPage(title, c.get("appName"), await getLoginAppearance(c.env), body), status);
}

function passwordForm(action: string, policyText: string, error?: string, intro?: string): string {
  return `
    ${intro ? `<p class="sub">${intro}</p>` : ""}
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="${escapeHtml(action)}">
      <label for="password">New password</label>
      <input type="password" id="password" name="password" required autofocus autocomplete="new-password" />
      <label for="confirm">Confirm new password</label>
      <input type="password" id="confirm" name="confirm" required autocomplete="new-password" />
      <p class="muted" style="margin-top:-6px; font-size:0.8125rem;">${escapeHtml(policyText)}</p>
      <div class="row"><button class="primary" type="submit">Save password</button></div>
    </form>`;
}

const LINK_EXPIRED = {
  title: "This link has expired",
  message: "Links in these emails work once, and only for a limited time. Ask for a new one, or contact your administrator.",
  action: { href: "/forgot-password", label: "Send a new link" },
};

// ---------- Forgot password ----------

recovery.get("/forgot-password", async (c) => {
  if (!(await isEmailConfigured(c.env))) return renderAuthMessage(c, 400, { title: "Password recovery is not available", message: "Ask your administrator to reset your password.", action: null });
  return page(
    c,
    "Reset your password",
    `
    <h1>Reset your password</h1>
    <p class="sub">Enter your username or email. If it matches an account, we'll send a link to choose a new password.</p>
    <form method="POST" action="/forgot-password">
      <label for="identifier">Username or email</label>
      <input type="text" id="identifier" name="identifier" required autofocus autocapitalize="off" autocorrect="off" />
      <div class="row"><button class="primary" type="submit">Send reset link</button></div>
    </form>
    <p class="auth-alt"><a href="/login">Back to sign in</a></p>`
  );
});

recovery.post("/forgot-password", async (c) => {
  if (!(await isEmailConfigured(c.env))) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const identifier = String((await c.req.parseBody()).identifier ?? "").slice(0, 254);
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
    "Check your email",
    `
    <h1>Check your email</h1>
    <p class="sub">If that matches an account, a link to reset its password is on its way. It works once, for the next hour.</p>
    <p class="auth-alt"><a href="/login">Back to sign in</a></p>`
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
  return page(c, "Choose a new password", `<h1>Choose a new password</h1>${passwordForm(`/reset-password/${token}`, passwordPolicySummary(policy), undefined, `For <strong>${escapeHtml(user.upn)}</strong>.`)}`);
});

recovery.get("/invite/:token", async (c) => {
  const { token, user } = await linkTarget(c, "invite");
  if (!user) return renderAuthMessage(c, 400, { ...LINK_EXPIRED, action: null, message: "Invitation links work once, for 7 days. Ask your administrator to send a new one." });
  const policy = await getPasswordPolicy(c.env);
  return page(
    c,
    "Activate your account",
    `<h1>Welcome, ${escapeHtml(user.display_name || user.username)}</h1>${passwordForm(`/invite/${token}`, passwordPolicySummary(policy), undefined, `Choose a password for <strong>${escapeHtml(user.upn)}</strong> to activate your account.`)}`
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
  const error = password !== String(body.confirm ?? "") ? "The two passwords do not match." : validatePassword(password, policy);
  if (error) {
    const { user } = await linkTarget(c, purpose);
    if (!user) return { response: await renderAuthMessage(c, 400, LINK_EXPIRED) };
    return { response: await page(c, "Choose a password", `<h1>Choose a password</h1>${passwordForm(action, passwordPolicySummary(policy), error)}`, 400) };
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
  return renderAuthMessage(c, 200, { title: "Password changed", message: "Your new password is set, and every other session has been signed out.", action: { href: "/login", label: "Sign in" } });
});

recovery.post("/invite/:token", async (c) => {
  const result = await acceptPassword(c, "invite");
  if ("response" in result) return result.response;
  await logAudit(c.env, result.user, "user.invitation_accepted", result.user.upn, undefined, c.req.raw);
  if (await isScimConfigured(c.env)) {
    const user = await getUserById(c.env, result.user.id);
    if (user) c.executionCtx.waitUntil(pushUser(c.env, user).then(() => undefined));
  }
  return renderAuthMessage(c, 200, { title: "Your account is ready", message: "Your password is set and your account is active.", action: { href: "/login", label: "Sign in" } });
});

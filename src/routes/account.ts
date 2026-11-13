import { errorPage, safeBackHref } from "../lib/html.js";
import { grants } from "../lib/permissions.js";
import { enrolledFactors, FACTOR_SHORT_LABELS, isFactorEnabled, isFactorUsable, secondFactorGate } from "../lib/auth-policy.js";
import { accountScope, emailOtpAvailable, sendEmailOtp, verifyEmailOtp } from "../lib/email-otp.js";
import { recipientFor } from "../lib/email.js";
import {
  answersFromForm,
  checkAnswers,
  clearAnswersStatements,
  enabledSecurityQuestions,
  getKbaSettings,
  KBA_ERRORS,
  KBA_MAX_ANSWER,
  saveAnswers,
  securityQuestionsAvailable,
  userSecurityQuestions,
  type SecurityQuestionRow,
} from "../lib/security-questions.js";
import { finishRegistration, listPasskeys, registrationOptions, removePasskey } from "../lib/passkeys.js";
import { PASSKEY_REGISTER_SCRIPT } from "../lib/passkey-scripts.js";
import { Hono, type Context, type MiddlewareHandler } from "hono";
import { brandFor } from "../lib/brands.js";
import QRCode from "qrcode";
import type { Env } from "../env.js";
import { requireSession } from "../lib/middleware.js";
import { attr, attrGrid, cancelLink, cardSection, confirmAttrs, escapeHtml, nav, page, scriptTag, successBanner } from "../lib/html.js";
import { buildOtpAuthUri, claimTotpCounter, generateBase32Secret, matchTotpCounter } from "../lib/totp.js";
import { deletePendingEnrollment, getPendingEnrollment, storePendingEnrollment } from "../lib/mfa-enrollment.js";
import { getUserById, getUserGroupNames } from "../lib/db.js";
import { attributeInput, getSchemaAttributes, parseCustomAttributes, ruleAttributeNames, splitUserAttributes, userAttributeValue, type SchemaAttributeRow } from "../lib/schemas.js";
import { isScimConfigured, pushUser } from "../lib/scim-client.js";
import type { UserRow } from "../lib/types.js";
import { verifyPassword, hashPassword } from "../lib/password.js";
import { getPasswordPolicy } from "../lib/settings.js";
import { newPasswordError } from "../lib/breached-passwords.js";
import { logAudit } from "../lib/audit.js";
import { getRateLimitPolicy, recordRateAttempt } from "../lib/rate-limit.js";
import { countRemainingBackupCodes, deleteBackupCodes, generateBackupCodes, verifyAndConsumeBackupCode } from "../lib/backup-codes.js";
import { listActiveSessionsForUser, revokeAllSessionsForUser, revokeSession, revokeTokensForUser } from "../lib/sessions.js";
import { bindFlowToUser, deleteLoginFlow, getLoginFlow, isSealedFlowId } from "../lib/authorize-state.js";
import { finishOidcAuthorize } from "./authorize.js";
import { safeNextPath } from "./login.js";
import { deleteTrustedDevicesForUser, listTrustedDevices, revokeTrustedDevice } from "../lib/trusted-devices.js";

export const account = new Hono<{ Bindings: Env }>();

account.use("/account/*", requireSession);
account.use("/account", requireSession);
// My account wears the person's brand (their UPN's domain - brands.ts): its
// name and logo in the top bar. Never its custom CSS, which is only for the
// sign-in pages.
const personalBrand: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const brand = await brandFor(c.env, { upn: c.get("user").upn });
  if (brand.id !== null) {
    c.set("appName", brand.appName);
    c.set("logoUrl", brand.logoUrl);
  }
  await next();
};
account.use("/account/*", personalBrand);
account.use("/account", personalBrand);
// Self-service is a permission like any other (the default "User" role grants both).
account.use("/account/*", async (c, next) => {
  const need = c.req.method === "GET" || c.req.method === "HEAD" ? "account:read" : "account:write";
  if (!grants(c.get("access").perms, need)) return c.html(errorPage(c.get("appName"), 403, "Your role doesn't allow changes to your account here.", safeBackHref(c.req.raw, "/account"), Boolean(c.get("access")?.isAdmin), c.get("logoUrl")), 403);
  return next();
});
account.use("/account", async (c, next) => (grants(c.get("access").perms, "account:read") ? next() : c.html(errorPage(c.get("appName"), 403, "Your role doesn't include My account. Ask an administrator.", "/", Boolean(c.get("access")?.isAdmin), c.get("logoUrl")), 403)));

function layout(c: Context<{ Bindings: Env }>, title: string, body: string, headerMeta?: string) {
  const appName = c.get("appName");
  return page(
    title,
    `<div class="page-header"><h1>${escapeHtml(title)}${headerMeta ? ` <span class="header-meta">${escapeHtml(headerMeta)}</span>` : ""}</h1></div>${body}`,
    appName,
    true,
    nav(appName, Boolean(c.get("access")?.isAdmin), c.get("logoUrl"))
  );
}

/**
 * Confirmations for the actions on this page.
 *
 * Every one of these redirects back to /account on success, which left the
 * page looking identical to a no-op - changing your password gave no sign it
 * had worked. The admin pages already use ?saved= plus a banner; this is the
 * same pattern, keyed so each action can say what actually happened.
 */
const SAVED_MESSAGES: Record<string, string> = {
  profile: "Your details have been saved.",
  password: "Your password has been changed.",
  "mfa-disabled": "Two-factor authentication is now disabled.",
  "sessions-others": "Every other session has been signed out.",
  session: "That session has been signed out.",
  device: "That device will need a verification code next time.",
  app: "Access for that app has been revoked.",
  "email-otp-enabled": "Email codes are on: you'll be asked for one when you sign in.",
  "email-otp-disabled": "Email codes are now off.",
  "kba-enabled": "Security questions are set: you can answer them when you sign in.",
  "kba-changed": "Your security questions have been changed.",
  "kba-removed": "Your security questions have been removed.",
};

const ERROR_MESSAGES: Record<string, string> = {
  "mfa-code": "That code was not correct, so two-factor authentication is still enabled. Try again with a current code or an unused backup code.",
  "too-many": "Too many attempts. Please wait a few minutes before trying again.",
  "email-code": "That code was not correct, or it has expired. Check the latest email, or send a new code.",
  "email-send": "We couldn't send the email. Try again in a moment.",
  "email-limit": "Too many codes requested. Please wait a few minutes before asking for another.",
  "email-unavailable": "Email codes aren't available right now.",
};

function savedBanner(c: Context<{ Bindings: Env }>): string {
  const error = ERROR_MESSAGES[c.req.query("error") ?? ""];
  if (error) return `<p class="error">${escapeHtml(error)}</p>`;
  const message = SAVED_MESSAGES[c.req.query("saved") ?? ""];
  return message ? successBanner(message) : "";
}

function relativeTime(iso: string): string {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/** The attributes this user may edit: their schema's user-editable ones, minus anything a rule now matches on. */
async function editableAttributes(env: Env, user: UserRow): Promise<SchemaAttributeRow[]> {
  if (!user.schema_id) return [];
  const [attrs, ruleFields] = await Promise.all([getSchemaAttributes(env, user.schema_id), ruleAttributeNames(env)]);
  return attrs.filter((a) => a.user_editable === 1 && a.type !== "reference" && a.name !== "manager" && !ruleFields.has(a.name));
}

account.get("/account", async (c) => {
  const user = c.get("user");
  const editable = await editableAttributes(c.env, user);
  const groups = await getUserGroupNames(c.env, user.id);
  const remainingBackupCodes = user.mfa_enabled ? await countRemainingBackupCodes(c.env, user.id) : 0;
  const currentSessionId = c.get("sessionId");
  const sessions = await listActiveSessionsForUser(c.env, user.id);
  const devices = await listTrustedDevices(c.env, user.id);
  const passkeys = await listPasskeys(c.env, user.id);
  const isAdmin = c.get("access").isAdmin;
  // Only factors that work right now: one switched off is not offered here at all.
  const enrolled = enrolledFactors({ ...user, has_passkey: passkeys.length > 0 });
  const usable = await Promise.all(enrolled.map((f) => isFactorUsable(c.env, f)));
  const factors = enrolled.filter((_, i) => usable[i]);
  const emailCard = (await emailOtpAvailable(c.env)) ? emailCodesCard(user, c.req.query("email_code") ?? "") : "";
  const kbaCard = (await securityQuestionsAvailable(c.env))
    ? c.get("access").isAdmin
      ? adminSecurityQuestionsCard(user, c.req.query("kba_error") ?? "")
      : await securityQuestionsCard(c.env, user, c.req.query("kba_error") ?? "")
    : "";
  const { results: connectedApps } = await c.env.DB.prepare(
    `SELECT DISTINCT oc.id, oc.name FROM access_tokens at
     JOIN oauth_clients oc ON oc.client_id = at.client_id
     WHERE at.user_id = ? AND at.expires_at > ?
     UNION
     SELECT DISTINCT oc.id, oc.name FROM refresh_tokens rt
     JOIN oauth_clients oc ON oc.client_id = rt.client_id
     WHERE rt.user_id = ? AND rt.revoked_at IS NULL`
  )
    .bind(user.id, new Date().toISOString(), user.id)
    .all<{ id: number; name: string }>();

  return c.html(
    layout(
      c,
      `${user.display_name}`,
      `
      ${savedBanner(c)}
      ${cardSection(`
        <h2>Profile</h2>
        <p class="muted">Everything this directory holds about you. These values are managed by your administrator - ask them if something is wrong.</p>
        ${attrGrid([
          attr("Display name", user.display_name),
          attr("First name", user.given_name),
          attr("Last name", user.family_name),
          attr("Username", user.username),
          attr("UPN", user.upn),
          attr("Job title", user.job_title),
          attr("Department", user.department),
          attr("Employee number", user.employee_number),
          attr("Location", user.location),
          attr("Hire date", user.hire_date),
          attr("Employment status", user.employment_status),
          attr("Employment type", user.employment_type),
          attr("Manager", user.manager_external_id),
          attr("Account status", user.status),
          attr("Administrator", user.is_admin ? "Yes" : "No"),
          attr("Created", new Date(user.created_at).toLocaleString()),
        ])}
      `)}

      ${
        editable.length
          ? cardSection(`
        <h2>Edit your details</h2>
        <p class="muted">Your administrator lets you keep these up to date yourself.</p>
        <form method="POST" action="/account/profile">
          <div class="form-grid">
            ${editable.map((a) => `<div><label for="attr_${escapeHtml(a.name)}">${escapeHtml(a.label)}</label>${attributeInput(a, userAttributeValue(user, a))}</div>`).join("")}
          </div>
          <div class="row" style="justify-content:flex-start; margin-top:12px;"><button class="primary" type="submit">Save my details</button></div>
        </form>
      `)
          : ""
      }

      ${cardSection(`
        <h2>Groups</h2>
        ${groups.length > 0 ? groups.map((g) => `<span class="pill">${escapeHtml(g)}</span>`).join("") : '<p class="muted">No group memberships</p>'}
      `)}

      <h2 class="section-title">Security</h2>
      <p class="muted" id="second-factors">${
        factors.length
          ? `Your second factors: ${factors.map((f) => FACTOR_SHORT_LABELS[f] + (f === "security_questions" && isAdmin ? " (not accepted for administrators)" : "")).join(", ")}.`
          : "You have no second factor yet. Set up an authenticator app, a passkey or another factor below."
      }</p>
      <div class="two-col">
        ${cardSection(`
          <div class="row between">
            <h2 style="margin:0;">Authenticator app</h2>
            <span class="badge ${user.mfa_enabled ? "badge-active" : "badge-disabled"}">${user.mfa_enabled ? "Enabled" : "Not set up"}</span>
          </div>
          ${
            user.mfa_enabled
              ? `<p class="muted" style="margin-top:8px;">${remainingBackupCodes} backup code(s) remaining.</p>
                 <form method="POST" action="/account/mfa/backup-codes/regenerate" style="margin-bottom:14px;" ${confirmAttrs("Your existing backup codes stop working immediately, and you will be shown a new set once.", { title: "Generate new backup codes?", action: "Regenerate" })}>
                   <label for="regen_code">Enter a current code from your authenticator (or a backup code)</label>
                   <input type="text" id="regen_code" name="code" maxlength="12" required autocomplete="one-time-code" style="max-width:160px" />
                   <button class="secondary" type="submit">Regenerate backup codes</button>
                 </form>
                 <form method="POST" action="/account/mfa/disable" ${confirmAttrs("Your authenticator and backup codes are removed, and every remembered device is forgotten.", { title: "Disable two-factor authentication?", action: "Disable MFA", danger: true })}>
                   <label for="mfa_code">Enter a current code, or a backup code if you lost your authenticator</label>
                   <div class="field-row" style="align-items:flex-start;">
                     <input type="text" id="mfa_code" name="code" maxlength="12" required autocomplete="one-time-code" style="max-width:160px" />
                     <div></div>
                   </div>
                   <button class="danger" type="submit">Disable MFA</button>
                 </form>`
              : `<p class="muted" style="margin-top:8px;">Protect your account with a standard authenticator app.</p>
                 <a href="/account/mfa/setup"><button class="primary" type="button">Set up MFA</button></a>`
          }
        `)}

        ${cardSection(`
          <h2>Change password</h2>
          <form method="POST" action="/account/password">
            <label for="current_password">Current password</label>
            <input type="password" id="current_password" name="current_password" required />
            <label for="new_password">New password</label>
            <input type="password" id="new_password" name="new_password" required />
            <label for="confirm_password">Confirm new password</label>
            <input type="password" id="confirm_password" name="confirm_password" required />
            <div class="row"><button class="primary" type="submit">Update password</button></div>
          </form>
        `)}
      </div>

      ${cardSection(`
        <h2>Passkeys</h2>
        <p class="muted">Sign in with your device's fingerprint, face or PIN instead of a password and code.</p>
        ${
          passkeys.length
            ? `<table><thead><tr><th>Name</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>
                ${passkeys.map((p) => `<tr><td>${escapeHtml(p.name)}</td><td>${escapeHtml(new Date(p.created_at).toLocaleDateString())}</td><td>${p.last_used_at ? escapeHtml(relativeTime(p.last_used_at)) : "never"}</td>
                  <td><form method="POST" action="/account/passkeys/${encodeURIComponent(p.id)}/remove" ${confirmAttrs("You will no longer be able to sign in with this passkey.", { title: "Remove this passkey?", action: "Remove passkey", danger: true })}><button class="link-button" type="submit">Remove</button></form></td></tr>`).join("")}
              </tbody></table>`
            : '<p class="muted">No passkeys yet.</p>'
        }
        <div class="row" style="justify-content:flex-start; gap:8px; margin-top:10px;">
          <input type="text" id="passkey-name" placeholder="Name (e.g. MacBook)" maxlength="60" style="max-width:220px; margin:0;" />
          <button class="secondary" type="button" data-passkey-register>Add a passkey</button>
        </div>
        <p class="muted" id="passkey-status" style="margin-top:8px;"></p>
        ${scriptTag(PASSKEY_REGISTER_SCRIPT)}
      `)}

      ${emailCard}

      ${kbaCard}

      <h2 class="section-title">Sessions and devices</h2>
      ${cardSection(`
        <div class="row between">
          <h2 style="margin:0;">Active sessions</h2>
          ${sessions.length > 1 ? `<form method="POST" action="/account/sessions/revoke-others" ${confirmAttrs("Every session except this one will be signed out. Other devices will need to sign in again.", { title: "Sign out all other sessions?", action: "Sign out others" })}><button class="secondary" type="submit">Sign out all other sessions</button></form>` : ""}
        </div>
        <table style="margin-top:10px;">
          <thead><tr><th>Started</th><th>Last active</th><th>IP</th><th></th></tr></thead>
          <tbody>
            ${sessions
              .map(
                (s) => `<tr>
                  <td>${escapeHtml(new Date(s.created_at).toLocaleString())}</td>
                  <td>${escapeHtml(relativeTime(s.last_seen_at))}</td>
                  <td class="muted">${escapeHtml(s.ip ?? "unknown")}</td>
                  <td>
                    ${
                      s.id === currentSessionId
                        ? '<span class="badge badge-active">This device</span>'
                        : `<form method="POST" action="/account/sessions/${escapeHtml(s.id)}/revoke" ${confirmAttrs("That device will need to sign in again.", { title: "Sign out this session?", action: "Sign out" })}><button class="link-button" type="submit">Sign out</button></form>`
                    }
                  </td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      `)}

      <div class="two-col">
      ${cardSection(`
        <h2>Remembered devices</h2>
        <p class="muted">Devices you chose "Remember this device" on - MFA is skipped on these until they expire or you remove them.</p>
        ${
          devices.length > 0
            ? `<table>
                <thead><tr><th>Added</th><th>Last used</th><th>IP</th><th></th></tr></thead>
                <tbody>
                  ${devices
                    .map(
                      (d) => `<tr>
                        <td>${escapeHtml(new Date(d.created_at).toLocaleString())}</td>
                        <td>${escapeHtml(relativeTime(d.last_used_at))}</td>
                        <td class="muted">${escapeHtml(d.ip ?? "unknown")}</td>
                        <td><form method="POST" action="/account/devices/${escapeHtml(d.id)}/revoke" ${confirmAttrs("This device will be asked for a verification code the next time it signs in.", { title: "Remove this remembered device?", action: "Remove device" })}><button class="link-button" type="submit">Remove</button></form></td>
                      </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
            : '<p class="muted">No remembered devices.</p>'
        }
      `)}

      ${cardSection(`
        <h2>Connected apps</h2>
        ${
          connectedApps.length > 0
            ? `<table>
                <thead><tr><th>App</th><th></th></tr></thead>
                <tbody>
                  ${connectedApps
                    .map(
                      (app) => `<tr>
                        <td>${escapeHtml(app.name)}</td>
                        <td><form method="POST" action="/account/apps/${app.id}/revoke" ${confirmAttrs(`You will need to sign in again the next time you use ${app.name}.`, { title: `Revoke access for ${app.name}?`, action: "Revoke access", danger: true })}><button class="link-button" type="submit">Revoke access</button></form></td>
                      </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
            : '<p class="muted">No connected apps yet.</p>'
        }
      `)}
      </div>
      `,
      user.upn
    )
  );
});

/**
 * My account > Security: email one-time codes. Turning them on and off each
 * takes a code sent to the address, so only someone who reads that inbox can
 * do either. `step` is "enrol" or "disable" once a code has been sent.
 */
function emailCodesCard(user: UserRow, step: string): string {
  const to = escapeHtml(recipientFor(user));
  const enrolled = Boolean(user.email_otp_enabled);
  const codeForm = (action: string, button: string, danger: boolean) => `
    <form method="POST" action="${action}" ${danger ? confirmAttrs("You will no longer be able to sign in with a code sent to your email.", { title: "Turn off email codes?", action: "Turn off", danger: true }) : ""}>
      <label for="email_otp_code">Enter the 6-digit code we sent to ${to}</label>
      <div class="field-row" style="align-items:flex-start;">
        <input type="text" id="email_otp_code" name="code" inputmode="numeric" maxlength="6" required autocomplete="one-time-code" style="max-width:160px" />
        <div></div>
      </div>
      <button class="${danger ? "danger" : "primary"}" type="submit">${button}</button>
    </form>`;
  const sendForm = (purpose: "enrol" | "disable", label: string, cls: string) =>
    `<form method="POST" action="/account/mfa/email/send" style="margin-top:8px;"><input type="hidden" name="purpose" value="${purpose}" /><button class="${cls}" type="submit">${label}</button></form>`;
  const body = !enrolled
    ? step === "enrol"
      ? codeForm("/account/mfa/email/enable", "Turn on email codes", false) + sendForm("enrol", "Send a new code", "link-button")
      : `<p class="muted" style="margin-top:8px;">Get a one-time code by email when you sign in.</p>${sendForm("enrol", `Send a code to ${to}`, "primary")}`
    : step === "disable"
      ? codeForm("/account/mfa/email/disable", "Turn off email codes", true) + sendForm("disable", "Send a new code", "link-button")
      : `<p class="muted" style="margin-top:8px;">When you sign in, you can ask for a code sent to ${to}. Turning this off takes a code sent there too.</p>${sendForm("disable", "Turn off", "secondary")}`;
  return cardSection(`
    <div class="row between" id="email-codes">
      <h2 style="margin:0;">Email codes</h2>
      <span class="badge ${enrolled ? "badge-active" : "badge-disabled"}">${enrolled ? "Enabled" : "Not enabled"}</span>
    </div>
    ${body}`);
}

/** The question pickers and answer boxes of an enrolment form: `count` rows, each a different question. */
function kbaFields(choices: SecurityQuestionRow[], count: number): string {
  return Array.from({ length: count }, (_, i) => {
    const n = i + 1;
    return `<div style="margin-bottom:10px;">
        <label for="kba_q${n}">Question ${n}</label>
        <select id="kba_q${n}" name="question_${n}" required>
          <option value="">Choose a question</option>
          ${choices.map((q, j) => `<option value="${q.id}" ${j === i ? "selected" : ""}>${escapeHtml(q.text)}</option>`).join("")}
        </select>
        <label for="kba_a${n}">Answer</label>
        <input type="text" id="kba_a${n}" name="answer_${n}" minlength="3" maxlength="${KBA_MAX_ANSWER}" required autocomplete="off" autocapitalize="off" spellcheck="false" />
      </div>`;
  }).join("");
}

const KBA_HELP = "Pick answers that only you know and that won't change. Capitals and extra spaces don't matter. Answers are stored hashed, like a password, and nobody can read them back.";

/**
 * My account > Security: security questions. Setting them the first time
 * needs only this session; changing or removing them needs the current
 * password, within the step-up budget.
 */
async function securityQuestionsCard(env: Env, user: UserRow, error: string): Promise<string> {
  const [choices, mine, { required }] = await Promise.all([enabledSecurityQuestions(env), userSecurityQuestions(env, user.id), getKbaSettings(env)]);
  const enrolled = Boolean(user.security_questions_enabled);
  const errorHtml = KBA_ERRORS[error] ? `<p class="error">${escapeHtml(KBA_ERRORS[error]!)}</p>` : "";
  const notEnough = choices.length < required ? `<p class="muted">Not enough questions are available to choose from right now. Ask your administrator.</p>` : "";
  const body = !enrolled
    ? `<p class="muted" style="margin-top:8px;">Answer ${required} questions you can be asked when you sign in. ${escapeHtml(KBA_HELP)}</p>
       ${errorHtml}
       ${notEnough || `<form method="POST" action="/account/mfa/questions">${kbaFields(choices, required)}<button class="primary" type="submit">Save security questions</button></form>`}`
    : `<p class="muted" style="margin-top:8px;">When you sign in you can answer some of these instead of using another method:</p>
       <ul style="margin:0 0 12px; padding-left:20px;">${mine.map((q) => `<li>${escapeHtml(q.text)}</li>`).join("")}</ul>
       ${errorHtml}
       <details ${error && error !== "kba-password" ? "open" : ""}><summary>Change your questions</summary>
         ${notEnough || `<form method="POST" action="/account/mfa/questions" style="margin-top:10px;">
           <label for="kba_current_password">Current password</label>
           <input type="password" id="kba_current_password" name="current_password" required autocomplete="current-password" style="max-width:320px;" />
           ${kbaFields(choices, required)}
           <button class="primary" type="submit">Save new questions</button>
         </form>`}
       </details>
       <form method="POST" action="/account/mfa/questions/remove" style="margin-top:12px;" ${confirmAttrs("You will no longer be able to sign in by answering security questions.", { title: "Remove your security questions?", action: "Remove", danger: true })}>
         <label for="kba_remove_password">Current password</label>
         <div class="field-row" style="align-items:flex-start;">
           <input type="password" id="kba_remove_password" name="current_password" required autocomplete="current-password" style="max-width:320px;" />
           <div></div>
         </div>
         <button class="danger" type="submit">Remove security questions</button>
       </form>`;
  return cardSection(`
    <div class="row between" id="security-questions">
      <h2 style="margin:0;">Security questions</h2>
      <span class="badge ${enrolled ? "badge-active" : "badge-disabled"}">${enrolled ? "Enabled" : "Not enabled"}</span>
    </div>
    ${body}`);
}

/** Why an administrator cannot set security questions: shown on My account and on a refused POST. */
const ADMIN_KBA_REFUSAL =
  "Security questions aren't available to administrators: answers can often be guessed or found out, which is too weak for an account that can change the directory. Use an authenticator app, a passkey or email codes instead.";

/**
 * The security-questions card for someone holding an admin role: no form to
 * set them, the reason, and - for questions set before the role was granted -
 * a way to remove them.
 */
function adminSecurityQuestionsCard(user: UserRow, error: string): string {
  const enrolled = Boolean(user.security_questions_enabled);
  const errorHtml = KBA_ERRORS[error] ? `<p class="error">${escapeHtml(KBA_ERRORS[error]!)}</p>` : "";
  return cardSection(`
    <div class="row between" id="security-questions">
      <h2 style="margin:0;">Security questions</h2>
      <span class="badge badge-disabled">${enrolled ? "Not accepted" : "Unavailable"}</span>
    </div>
    <p class="muted" style="margin-top:8px;">${escapeHtml(ADMIN_KBA_REFUSAL)}</p>
    ${errorHtml}
    ${
      enrolled
        ? `<form method="POST" action="/account/mfa/questions/remove" style="margin-top:12px;" ${confirmAttrs("Your security questions are removed.", { title: "Remove your security questions?", action: "Remove", danger: true })}>
         <label for="kba_remove_password">Current password</label>
         <div class="field-row" style="align-items:flex-start;">
           <input type="password" id="kba_remove_password" name="current_password" required autocomplete="current-password" style="max-width:320px;" />
           <div></div>
         </div>
         <button class="danger" type="submit">Remove security questions</button>
       </form>`
        : ""
    }`);
}

account.post("/account/profile", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  // Only what the schema allows, checked here again - the form is just a form.
  const editable = await editableAttributes(c.env, user);
  if (editable.length === 0) return c.redirect("/account", 302);
  const values = Object.fromEntries(editable.map((a) => [a.name, String(body[`attr_${a.name}`] ?? "").trim().slice(0, 500)]));
  const missing = editable.find((a) => a.required && !values[a.name]);
  if (missing) return c.html(errorRedirectPage(c, `${missing.label} is required.`));

  const { columns, custom } = splitUserAttributes(editable, values);
  const mergedCustom: Record<string, string> = { ...parseCustomAttributes(user.custom_attributes), ...custom };
  // A cleared custom field is removed, not kept at its old value.
  for (const a of editable) if (!values[a.name] && !(a.name in columns)) delete mergedCustom[a.name];
  const columnNames = Object.keys(columns).filter((k) => /^[a-z_]+$/.test(k));
  await c.env.DB.prepare(
    `UPDATE users SET ${[...columnNames.map((k) => `${k} = ?`), "custom_attributes = ?", "updated_at = ?"].join(", ")} WHERE id = ?`
  )
    .bind(...columnNames.map((k) => columns[k] ?? ""), JSON.stringify(mergedCustom), new Date().toISOString(), user.id)
    .run();
  await logAudit(c.env, user, "user.profile_updated_self", user.upn, { fields: editable.map((a) => a.name) }, c.req.raw);
  if (await isScimConfigured(c.env)) {
    const fresh = await getUserById(c.env, user.id);
    if (fresh) c.executionCtx.waitUntil(pushUser(c.env, fresh).then(() => undefined));
  }
  return c.redirect("/account?saved=profile", 302);
});

account.post("/account/devices/:id/revoke", async (c) => {
  const user = c.get("user");
  const deviceId = c.req.param("id");
  await revokeTrustedDevice(c.env, user.id, deviceId);
  await logAudit(c.env, user, "user.device_revoked_self", user.upn, undefined, c.req.raw);
  return c.redirect("/account?saved=device", 302);
});

account.post("/account/sessions/:id/revoke", async (c) => {
  const user = c.get("user");
  const sessionId = c.req.param("id");
  const sessions = await listActiveSessionsForUser(c.env, user.id);
  if (sessions.some((s) => s.id === sessionId)) {
    await revokeSession(c.env, sessionId);
    await logAudit(c.env, user, "user.session_revoked_self", user.upn, undefined, c.req.raw);
  }
  return c.redirect("/account?saved=session", 302);
});

account.post("/account/sessions/revoke-others", async (c) => {
  const user = c.get("user");
  const count = await revokeAllSessionsForUser(c.env, user.id, c.get("sessionId"));
  await logAudit(c.env, user, "user.sessions_revoked_all_others", user.upn, { count }, c.req.raw);
  return c.redirect("/account?saved=sessions-others", 302);
});

account.post("/account/apps/:clientDbId/revoke", async (c) => {
  const user = c.get("user");
  const clientDbId = Number(c.req.param("clientDbId"));
  const client = await c.env.DB.prepare("SELECT client_id, name FROM oauth_clients WHERE id = ?")
    .bind(clientDbId)
    .first<{ client_id: string; name: string }>();
  if (!client) return c.redirect("/account", 302);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?").bind(user.id, client.client_id),
    c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ?").bind(
      new Date().toISOString(),
      user.id,
      client.client_id
    ),
    // Revoking access withdraws consent too: the app has to ask again.
    c.env.DB.prepare("DELETE FROM oauth_consents WHERE user_id = ? AND client_id = ?").bind(user.id, client.client_id),
  ]);
  await logAudit(c.env, user, "user.app_access_revoked_self", client.name, undefined, c.req.raw);

  return c.redirect("/account?saved=app", 302);
});

/**
 * Step-up checks inside a session (current password, a second factor) get the
 * same per-account budget as the sign-in form: a stolen session must not be
 * an unlimited oracle for the password or the TOTP. Failures are audited.
 */
async function stepUpBudgetExceeded(c: Context<{ Bindings: Env }>): Promise<boolean> {
  const policy = await getRateLimitPolicy(c.env);
  return recordRateAttempt(c.env, `account:stepup:${c.get("user").id}`, policy.maxAttempts, policy.windowMinutes);
}

/** A current TOTP (claimed, so it cannot be replayed) or an unused backup code. */
async function secondFactorOk(c: Context<{ Bindings: Env }>, code: string): Promise<"totp" | "backup_code" | null> {
  const user = c.get("user");
  const counter = user.totp_secret ? await matchTotpCounter(user.totp_secret, code) : null;
  if (counter !== null && (await claimTotpCounter(c.env, user.id, counter))) return "totp";
  if (await verifyAndConsumeBackupCode(c.env, user.id, code)) return "backup_code";
  return null;
}

account.get("/account/passkeys/options", async (c) => {
  const user = c.get("user");
  return c.json(await registrationOptions(c.env, c.get("sessionId"), user));
});

account.post("/account/passkeys", async (c) => {
  const user = c.get("user");
  const body = await c.req.json<{ response?: unknown; name?: string }>().catch(() => ({}) as { response?: unknown; name?: string });
  const error = body.response ? await finishRegistration(c.env, c.get("sessionId"), user.id, body.response as never, String(body.name ?? "")) : "Missing response.";
  if (error) return c.json({ ok: false, error }, 400);
  await logAudit(c.env, user, "user.passkey_added", user.upn, { name: String(body.name ?? "").slice(0, 60) }, c.req.raw);
  return c.json({ ok: true });
});

account.post("/account/passkeys/:id/remove", async (c) => {
  const user = c.get("user");
  await removePasskey(c.env, user.id, decodeURIComponent(c.req.param("id") ?? ""));
  await logAudit(c.env, user, "user.passkey_removed", user.upn, undefined, c.req.raw);
  return c.redirect("/account?saved=passkey-removed", 302);
});

account.post("/account/password", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  if (await stepUpBudgetExceeded(c)) return c.html(errorRedirectPage(c, "Too many attempts. Please wait a few minutes before trying again."));
  const currentPassword = String(body.current_password ?? "");
  const newPassword = String(body.new_password ?? "");
  const confirmPassword = String(body.confirm_password ?? "");

  if (!(await verifyPassword(currentPassword, user))) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "password_change" }, c.req.raw);
    return c.html(errorRedirectPage(c, "Current password is incorrect."));
  }

  if (newPassword !== confirmPassword) {
    return c.html(errorRedirectPage(c, "New password and confirmation do not match."));
  }

  const policy = await getPasswordPolicy(c.env);
  const policyError = await newPasswordError(c.env, newPassword, policy);
  if (policyError) {
    return c.html(errorRedirectPage(c, policyError));
  }

  const { hash, salt, iterations } = await hashPassword(newPassword, c.env);
  await c.env.DB.prepare(
    "UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?"
  )
    .bind(hash, salt, iterations, new Date().toISOString(), user.id)
    .run();

  // A password change is a compromise response: end every other session,
  // keeping only the one that just proved knowledge of the old password.
  await revokeAllSessionsForUser(c.env, user.id, c.get("sessionId"));
  await revokeTokensForUser(c.env, user.id);

  await logAudit(c.env, user, "user.password_changed_self", user.upn, undefined, c.req.raw);

  return c.redirect("/account?saved=password", 302);
});

function errorRedirectPage(c: Context<{ Bindings: Env }>, message: string) {
  return layout(c, "My account", `<p class="error">${escapeHtml(message)}</p><a href="/account">Back to account</a>`);
}

account.get("/account/mfa/setup", async (c) => {
  const user = c.get("user");
  const resume = c.req.query("resume") ?? "";
  if (user.mfa_enabled) return c.redirect("/account", 302);
  const [totpOn, passkeyOn, emailAvailable, kbaAvailable] = await Promise.all([
    isFactorEnabled(c.env, "totp"),
    isFactorEnabled(c.env, "passkey"),
    emailOtpAvailable(c.env),
    securityQuestionsAvailable(c.env),
  ]);
  const emailOn = emailAvailable && !user.email_otp_enabled;
  // Administrators need a stronger second factor than security questions.
  const kbaOn = kbaAvailable && !user.security_questions_enabled && !c.get("access")?.isAdmin;
  const emailError = ERROR_MESSAGES[c.req.query("error") ?? ""];
  const to = escapeHtml(recipientFor(user));
  const emailHidden = `<input type="hidden" name="resume" value="${escapeHtml(resume)}" /><input type="hidden" name="from" value="setup" />`;
  const emailCard = !emailOn
    ? ""
    : cardSection(`
        <h2>${passkeyOn ? "Or use email codes" : "Use email codes"}</h2>
        <p class="muted">A one-time code sent to ${to} each time you sign in.</p>
        ${emailError ? `<p class="error">${escapeHtml(emailError)}</p>` : ""}
        ${
          c.req.query("email_code") === "enrol"
            ? `<form method="POST" action="/account/mfa/email/enable">
                ${emailHidden}
                <label for="email_otp_code">Enter the 6-digit code we sent to ${to}</label>
                <input type="text" id="email_otp_code" name="code" inputmode="numeric" maxlength="6" required autofocus autocomplete="one-time-code" style="max-width:160px;" />
                <button class="primary" type="submit">Turn on email codes</button>
              </form>
              <form method="POST" action="/account/mfa/email/send" style="margin-top:8px;">${emailHidden}<input type="hidden" name="purpose" value="enrol" /><button class="link-button" type="submit">Send a new code</button></form>`
            : `<form method="POST" action="/account/mfa/email/send">${emailHidden}<input type="hidden" name="purpose" value="enrol" /><button class="${passkeyOn ? "secondary" : "primary"}" type="submit">Send a code to ${to}</button></form>`
        }`);

  let kbaCard = "";
  if (kbaOn) {
    const [choices, { required }] = await Promise.all([enabledSecurityQuestions(c.env), getKbaSettings(c.env)]);
    const kbaError = KBA_ERRORS[c.req.query("kba_error") ?? ""];
    kbaCard =
      choices.length < required
        ? ""
        : cardSection(`
        <h2>${passkeyOn || emailOn ? "Or answer security questions" : "Answer security questions"}</h2>
        <p class="muted">Answer ${required} questions; when you sign in you'll be asked some of them. ${escapeHtml(KBA_HELP)} Security questions are easier for someone else to guess than the other methods, so use another one too if you can.</p>
        ${kbaError ? `<p class="error">${escapeHtml(kbaError)}</p>` : ""}
        <form method="POST" action="/account/mfa/questions">
          <input type="hidden" name="resume" value="${escapeHtml(resume)}" /><input type="hidden" name="from" value="setup" />
          ${kbaFields(choices, required)}
          <button class="${passkeyOn || emailOn ? "secondary" : "primary"}" type="submit">Save security questions</button>
        </form>`);
  }

  let secret = await getPendingEnrollment(c.env, c.get("sessionId"));
  if (!secret) {
    secret = generateBase32Secret();
    await storePendingEnrollment(c.env, c.get("sessionId"), secret);
  }

  const otpauthUri = buildOtpAuthUri({ secret, upn: user.upn, issuer: c.get("appName") });
  const qrSvg = await QRCode.toString(otpauthUri, { type: "svg", width: 220 });

  return c.html(
    layout(
      c,
      "Set up MFA",
      (passkeyOn
        ? cardSection(`
        <h2>Use a passkey</h2>
        <p class="muted">Your device's fingerprint, face or PIN. A passkey counts as multi-factor on its own, and you can sign in with it without a password.</p>
        <div class="row" style="justify-content:flex-start; gap:8px;">
          <input type="text" id="passkey-name" placeholder="Name (e.g. MacBook)" maxlength="60" style="max-width:220px; margin:0;" />
          <button class="primary" type="button" data-passkey-register data-done="/account/mfa/passkey-enrolled" data-resume="${escapeHtml(resume)}">Add a passkey</button>
        </div>
        <p class="muted" id="passkey-status" style="margin-top:8px;"></p>
        ${scriptTag(PASSKEY_REGISTER_SCRIPT)}`)
        : "") +
      emailCard +
      kbaCard +
      (!totpOn ? "" : cardSection(`
        <div style="text-align:center;">
          ${passkeyOn || emailOn || kbaCard ? "<h2>Or use an authenticator app</h2>" : ""}
          ${resume ? '<p class="sub">Multi-factor authentication is required before you can continue.</p>' : ""}
          ${c.req.query("error") === "1" ? '<p class="error">Incorrect code, please try again.</p>' : ""}
          <p class="sub">Scan this with Google Authenticator, Authy, or any standard TOTP app.</p>
          <div>${qrSvg}</div>
          <p class="muted">Or enter this code manually: <code>${escapeHtml(secret)}</code></p>
          <form method="POST" action="/account/mfa/setup" style="display:inline-block;">
            <input type="hidden" name="resume" value="${escapeHtml(resume)}" />
            <div style="display:flex; gap:10px; align-items:flex-end;">
              <div style="text-align:left;">
                <label for="code">Enter the 6-digit code to confirm</label>
                <input type="text" id="code" name="code" inputmode="numeric" maxlength="6" required autofocus style="margin-bottom:0; max-width:160px;" />
              </div>
              <button class="primary" type="submit">Enable MFA</button>
            </div>
          </form>
          <div class="form-actions" style="justify-content:center; margin-top:18px;">
            ${
              resume
                ? `<form method="POST" action="/logout" style="display:inline;"><button class="link-button" type="submit">Cancel and sign out</button></form>`
                : cancelLink("/account", "Cancel")
            }
          </div>
        </div>
      `))
    )
  );
});

/** Forced enrolment finished with a passkey instead of an authenticator app. */
account.post("/account/mfa/passkey-enrolled", async (c) => {
  const user = c.get("user");
  const resume = String((await c.req.parseBody()).resume ?? "");
  // The passkey this session just registered (within the last ten minutes) is the new second factor.
  const recent = await c.env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ? AND created_at > ?")
    .bind(user.id, new Date(Date.now() - 10 * 60 * 1000).toISOString())
    .first();
  if (!recent) return c.redirect(`/account/mfa/setup?resume=${encodeURIComponent(resume)}`, 302);
  await revokeAllSessionsForUser(c.env, user.id, c.get("sessionId"));
  await c.env.DB.prepare("UPDATE sessions SET amr = ? WHERE id = ?").bind(JSON.stringify(["pwd", "hwk", "mfa"]), c.get("sessionId")).run();
  await logAudit(c.env, user, "user.mfa_enrolled_passkey", user.upn, undefined, c.req.raw);
  return c.redirect(resume ? await resumeLoginFlow(c.env, resume, user.id, c.get("sessionId")) : "/account?saved=passkey-added", 302);
});

account.post("/account/mfa/setup", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const code = String(body.code ?? "");
  const resume = String(body.resume ?? "");

  const secret = await getPendingEnrollment(c.env, c.get("sessionId"));
  if (!secret) return c.html(errorPage(c.get("appName"), 400, "The set-up session expired. Start setting up the authenticator app again.", "/account/mfa/setup", Boolean(c.get("access")?.isAdmin), c.get("logoUrl")), 400);

  const counter = await matchTotpCounter(secret, code);
  if (counter === null) {
    return c.redirect(`/account/mfa/setup?error=1&resume=${encodeURIComponent(resume)}`, 302);
  }

  // totp_last_counter starts at the code that proved enrolment, so that very
  // code cannot be replayed at /login/mfa or /account/mfa/disable.
  await c.env.DB.prepare(
    "UPDATE users SET totp_secret = ?, mfa_enabled = 1, totp_last_counter = ?, updated_at = ? WHERE id = ?"
  )
    .bind(secret, counter, new Date().toISOString(), user.id)
    .run();
  await deletePendingEnrollment(c.env, c.get("sessionId"));
  // Every other session predates the second factor (a password-only session
  // from the forced-enrolment login, say): end them, as a password change does.
  await revokeAllSessionsForUser(c.env, user.id, c.get("sessionId"));
  await c.env.DB.prepare("UPDATE sessions SET amr = ? WHERE id = ?").bind(JSON.stringify(["pwd", "mfa"]), c.get("sessionId")).run();
  await logAudit(c.env, user, "user.mfa_enabled", user.upn, undefined, c.req.raw);

  const codes = await generateBackupCodes(c.env, user.id);
  const continueTo = resume ? await resumeLoginFlow(c.env, resume, user.id, c.get("sessionId")) : "/account";

  return c.html(layout(c, "MFA enabled", backupCodesPage(codes, continueTo)));
});

/** Completes a login flow that was paused for forced MFA enrollment, returning where to send the user next. */
async function resumeLoginFlow(env: Env, resumeFlowId: string, userId: number, sessionId: string, amr: string[] = ["pwd", "mfa"]): Promise<string> {
  // Only a flow this user parked after authenticating: never a sealed
  // anonymous one, which would let enrolment stand in for a fresh login.
  if (isSealedFlowId(resumeFlowId)) return "/account";
  const flow = await getLoginFlow(env, resumeFlowId);
  if (!flow || flow.resumeFor !== userId) return "/account";
  // The factor just enrolled must satisfy the gate (security questions never
  // do for an administrator): otherwise the flow stays parked at enrolment.
  const user = await getUserById(env, userId);
  if (!user || (await secondFactorGate(env, user, amr)) !== "ok") return `/account/mfa/setup?resume=${encodeURIComponent(resumeFlowId)}`;

  if (flow.kind === "direct") {
    await deleteLoginFlow(env, resumeFlowId);
    return safeNextPath(flow.next);
  }

  // A SAML flow can't finish here - it ends in a POST form, not a URL. The
  // flow stays in KV and /saml/complete issues the response when the user
  // clicks through. The binding is what marks it "paused after a completed
  // login": without it /saml/complete refuses the flow (see saml.ts).
  if (flow.kind === "saml") {
    await bindFlowToUser(env, resumeFlowId, userId);
    return `/saml/complete?flow=${resumeFlowId}`;
  }

  await deleteLoginFlow(env, resumeFlowId);
  const { redirectTo } = await finishOidcAuthorize(env, flow.request, userId, amr, sessionId);
  return redirectTo;
}

// ---------- Email one-time codes ----------
// Under /account/mfa so a session that still owes its policy a second factor
// (forced enrolment) can reach them, like the other enrolment routes.

/** Where an email-code action goes back to: the forced-enrolment page it came from, or My account. */
function emailCodeReturn(body: Record<string, unknown>, query: string): string {
  if (body.from === "setup") return `/account/mfa/setup?resume=${encodeURIComponent(String(body.resume ?? ""))}&${query}`;
  return `/account?${query}#email-codes`;
}

account.post("/account/mfa/email/send", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const purpose = body.purpose === "disable" ? "disable" : "enrol";
  if (!(await emailOtpAvailable(c.env))) return c.redirect(emailCodeReturn(body, "error=email-unavailable"), 302);
  if ((purpose === "enrol") === Boolean(user.email_otp_enabled)) return c.redirect("/account", 302);
  const sent = await sendEmailOtp(c.env, user, accountScope(c.get("sessionId")), purpose);
  if (!sent.ok) {
    if (sent.reason === "rate_limited") {
      await logAudit(c.env, user, "user.email_otp_rate_limited", user.upn, { purpose }, c.req.raw);
      return c.redirect(emailCodeReturn(body, "error=email-limit"), 302);
    }
    await logAudit(c.env, user, "user.email_otp_send_failed", user.upn, { purpose, error: sent.error }, c.req.raw);
    return c.redirect(emailCodeReturn(body, "error=email-send"), 302);
  }
  await logAudit(c.env, user, "user.email_otp_code_sent", user.upn, { purpose }, c.req.raw);
  return c.redirect(emailCodeReturn(body, `email_code=${purpose}`), 302);
});

/** Enrolment: the code sent to the address proves it is theirs; finishes a forced enrolment like the passkey path. */
account.post("/account/mfa/email/enable", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const resume = String(body.resume ?? "");
  const sessionId = c.get("sessionId");
  if (!(await emailOtpAvailable(c.env))) return c.redirect(emailCodeReturn(body, "error=email-unavailable"), 302);
  if (user.email_otp_enabled) return c.redirect("/account", 302);
  const result = await verifyEmailOtp(c.env, accountScope(sessionId), user.id, "enrol", String(body.code ?? ""));
  if (result !== "ok") {
    await logAudit(c.env, user, "user.email_otp_enrol_failed", user.upn, { reason: result }, c.req.raw);
    // A wrong code leaves the code form up; a used-up one goes back to "send".
    return c.redirect(emailCodeReturn(body, result === "wrong" ? "email_code=enrol&error=email-code" : "error=email-code"), 302);
  }

  await c.env.DB.prepare("UPDATE users SET email_otp_enabled = 1, updated_at = ? WHERE id = ?").bind(new Date().toISOString(), user.id).run();
  // As with the authenticator: every other session predates the second factor.
  await revokeAllSessionsForUser(c.env, user.id, sessionId);
  const current = await c.env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sessionId).first<{ amr: string }>();
  let previous: string[] = [];
  try {
    previous = current ? (JSON.parse(current.amr) as string[]) : [];
  } catch {
    previous = [];
  }
  const amr = [...new Set([...(previous.length ? previous : ["pwd"]), "otp", "mfa"])];
  await c.env.DB.prepare("UPDATE sessions SET amr = ? WHERE id = ?").bind(JSON.stringify(amr), sessionId).run();
  await logAudit(c.env, user, "user.email_otp_enabled", user.upn, undefined, c.req.raw);
  return c.redirect(resume ? await resumeLoginFlow(c.env, resume, user.id, sessionId, amr) : "/account?saved=email-otp-enabled", 302);
});

/** Turning email codes off takes a fresh code, within the step-up budget - as disabling the authenticator does. */
account.post("/account/mfa/email/disable", async (c) => {
  const user = c.get("user");
  if (!user.email_otp_enabled) return c.redirect("/account", 302);
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account?error=too-many#email-codes", 302);
  const result = await verifyEmailOtp(c.env, accountScope(c.get("sessionId")), user.id, "disable", String((await c.req.parseBody()).code ?? ""));
  if (result !== "ok") {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "email_otp_disable", reason: result }, c.req.raw);
    return c.redirect(`/account?${result === "wrong" ? "email_code=disable&" : ""}error=email-code#email-codes`, 302);
  }
  await c.env.DB.prepare("UPDATE users SET email_otp_enabled = 0, updated_at = ? WHERE id = ?").bind(new Date().toISOString(), user.id).run();
  await logAudit(c.env, user, "user.email_otp_disabled", user.upn, undefined, c.req.raw);
  return c.redirect("/account?saved=email-otp-disabled", 302);
});

// ---------- Security questions ----------
// Under /account/mfa so a session that still owes its policy a second factor
// (forced enrolment) can reach them, like the other enrolment routes.

/** Where a security-questions action goes back to: the forced-enrolment page it came from, or My account. */
function kbaReturn(body: Record<string, unknown>, query: string): string {
  if (body.from === "setup") return `/account/mfa/setup?resume=${encodeURIComponent(String(body.resume ?? ""))}&${query}`;
  return `/account?${query}#security-questions`;
}

/**
 * Sets (or, with the current password, replaces) the user's security
 * questions. Setting them the first time finishes a forced enrolment like the
 * email-code path: other sessions end, this one gains "kba" and "mfa", and a
 * paused sign-in resumes.
 */
account.post("/account/mfa/questions", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const resume = String(body.resume ?? "");
  const sessionId = c.get("sessionId");
  if (!(await securityQuestionsAvailable(c.env))) return c.redirect(kbaReturn(body, "kba_error=kba-unavailable"), 302);
  // Not a factor administrators may use (secondFactorGate, hasSecondFactor),
  // so not one they may set either - the forms are not offered, and a direct
  // POST is refused.
  if (c.get("access").isAdmin) {
    await logAudit(c.env, user, "user.security_questions_refused", user.upn, { reason: "administrator" }, c.req.raw);
    return c.html(errorPage(c.get("appName"), 403, ADMIN_KBA_REFUSAL, safeBackHref(c.req.raw, "/account"), true, c.get("logoUrl")), 403);
  }
  const changing = Boolean(user.security_questions_enabled);
  if (changing) {
    if (await stepUpBudgetExceeded(c)) return c.redirect(kbaReturn(body, "kba_error=kba-too-many"), 302);
    if (!(await verifyPassword(String(body.current_password ?? "").slice(0, 1024), user))) {
      await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "security_questions_change" }, c.req.raw);
      return c.redirect(kbaReturn(body, "kba_error=kba-password"), 302);
    }
  }
  const { required } = await getKbaSettings(c.env);
  const entries = answersFromForm(body, required);
  const problem = await checkAnswers(c.env, user, entries);
  if (problem) return c.redirect(kbaReturn(body, `kba_error=${problem}`), 302);

  await saveAnswers(c.env, user.id, entries);
  // Which questions were chosen is recorded; the answers never are.
  const details = { questions: entries.map((e) => e.questionId) };
  if (changing) {
    await logAudit(c.env, user, "user.security_questions_changed", user.upn, details, c.req.raw);
    return c.redirect("/account?saved=kba-changed", 302);
  }

  // As with the other factors: every other session predates the second factor.
  await revokeAllSessionsForUser(c.env, user.id, sessionId);
  const current = await c.env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sessionId).first<{ amr: string }>();
  let previous: string[] = [];
  try {
    previous = current ? (JSON.parse(current.amr) as string[]) : [];
  } catch {
    previous = [];
  }
  const amr = [...new Set([...(previous.length ? previous : ["pwd"]), "kba", "mfa"])];
  await c.env.DB.prepare("UPDATE sessions SET amr = ? WHERE id = ?").bind(JSON.stringify(amr), sessionId).run();
  await logAudit(c.env, user, "user.security_questions_enabled", user.upn, details, c.req.raw);
  return c.redirect(resume ? await resumeLoginFlow(c.env, resume, user.id, sessionId, amr) : "/account?saved=kba-enabled", 302);
});

/** Removing security questions takes the current password, within the step-up budget. */
account.post("/account/mfa/questions/remove", async (c) => {
  const user = c.get("user");
  if (!user.security_questions_enabled) return c.redirect("/account", 302);
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account?kba_error=kba-too-many#security-questions", 302);
  if (!(await verifyPassword(String((await c.req.parseBody()).current_password ?? "").slice(0, 1024), user))) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "security_questions_remove" }, c.req.raw);
    return c.redirect("/account?kba_error=kba-password#security-questions", 302);
  }
  await c.env.DB.batch(clearAnswersStatements(c.env, user.id));
  await logAudit(c.env, user, "user.security_questions_disabled", user.upn, undefined, c.req.raw);
  return c.redirect("/account?saved=kba-removed", 302);
});

function backupCodesPage(codes: string[], continueTo = "/account"): string {
  const fileContents = `${codes.join("\n")}\n`;
  const downloadHref = `data:text/plain;charset=utf-8,${encodeURIComponent(fileContents)}`;

  return cardSection(`
    <p class="success">MFA is now enabled.</p>
    <p>Save these backup codes somewhere safe - each one can be used once to sign in if you lose access to your authenticator app. They won't be shown again.</p>
    <div style="background:var(--fi-surface-2); border:1px solid var(--fi-line); border-radius:10px; padding:14px 16px; font-family:monospace; font-size:1rem; line-height:1.8;">
      ${codes.map(escapeHtml).join("<br/>")}
    </div>
    <div class="row" style="justify-content:flex-start; margin-top:12px;">
      <a href="${downloadHref}" download="backup-codes.txt"><button class="secondary" type="button">Download backup-codes.txt</button></a>
    </div>
    <div class="row" style="margin-top:16px;"><a href="${escapeHtml(continueTo)}"><button class="primary" type="button">Continue</button></a></div>
  `);
}

account.post("/account/mfa/backup-codes/regenerate", async (c) => {
  const user = c.get("user");
  if (!user.mfa_enabled) return c.redirect("/account", 302);
  // New codes are a second factor: issuing them needs one, as disabling MFA does.
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account?error=too-many", 302);
  const factor = await secondFactorOk(c, String((await c.req.parseBody()).code ?? ""));
  if (!factor) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "backup_codes_regenerate" }, c.req.raw);
    return c.redirect("/account?error=mfa-code", 302);
  }

  const codes = await generateBackupCodes(c.env, user.id);
  await logAudit(c.env, user, "user.mfa_backup_codes_regenerated", user.upn, undefined, c.req.raw);

  return c.html(layout(c, "Backup codes regenerated", backupCodesPage(codes)));
});

account.post("/account/mfa/disable", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const code = String(body.code ?? "");

  // A wrong code used to redirect here with no message at all, which was
  // indistinguishable from MFA having been switched off. The claim also makes
  // this a replay check: a code already accepted once cannot disable MFA.
  //
  // A backup code works too. It is the only factor left to someone who lost
  // their authenticator and signed in with one - and without it they could
  // never disable MFA to enrol a new device.
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account?error=too-many", 302);
  const factor = await secondFactorOk(c, code);
  const backupOk = factor === "backup_code";
  if (!factor) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "mfa_disable" }, c.req.raw);
    return c.redirect("/account?error=mfa-code", 302);
  }

  await c.env.DB.prepare(
    "UPDATE users SET totp_secret = NULL, mfa_enabled = 0, totp_last_counter = NULL, updated_at = ? WHERE id = ?"
  )
    .bind(new Date().toISOString(), user.id)
    .run();
  await deleteBackupCodes(c.env, user.id);
  await deleteTrustedDevicesForUser(c.env, user.id);
  await logAudit(c.env, user, "user.mfa_disabled", user.upn, { with: backupOk ? "backup_code" : "totp" }, c.req.raw);

  return c.redirect("/account?saved=mfa-disabled", 302);
});

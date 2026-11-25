import { accountScope, EMAIL_OTP_MINUTES, maskEmail, sendEmailOtp, userHasEmailOtp, verifyEmailOtp } from "../lib/email-otp.js";
import { clearRateKey, rateKeyOverLimit, recordRateAttempt } from "../lib/rate-limit.js";
import { verifyPassword } from "../lib/password.js";
import { claimTotpCounter, matchTotpCounter } from "../lib/totp.js";
import { hasUnusedBackupCodes, verifyAndConsumeBackupCode } from "../lib/backup-codes.js";
import { userHasPasskey } from "../lib/auth-policy.js";
import { isFreshlyAuthenticated, isSensitive, markSteppedUp, stashPendingAction, STEP_UP_WINDOW_MINUTES, takePendingAction } from "../lib/step-up.js";
import { authenticationOptions, finishAuthentication } from "../lib/passkeys.js";
import { PASSKEY_LOGIN_SCRIPT } from "../lib/passkey-scripts.js";
import { accessFor, adminRoleGroupIds, adminRoleGroupNames, groupRoleWriteMap, groupRolesMap, listRoles, rolePermissions, SUPER_ROLE, visibleSections, type Access, type RoleRow } from "../lib/admin-roles.js";
import { adminPolicies, adminsWithoutMfaPolicy } from "../lib/admin-mfa.js";
import { AREAS, grants, isPermission, SELF_PERMISSIONS } from "../lib/permissions.js";
import { anySecondFactorSql, assertPolicyExists, enrolledFactors, FACTOR_SHORT_LABELS, FACTORS, factorEnrolmentCounts, hasBackupCodesSql, hasPasskeySql, isAdministrator, isFactorEnabled, listPolicies, type AuthPolicyRow, type FactorKey } from "../lib/auth-policy.js";
import { getKbaSettings, KBA_MAX_QUESTION, KBA_MAX_REQUIRED, listSecurityQuestions } from "../lib/security-questions.js";
import { readPerformance, readPerformanceSeries, readSpanStats, readEventCounts } from "../lib/metrics.js";
import { Hono, type Context, type Next } from "hono";
import type { Env } from "../env.js";
import { requireAdmin, requireSession, SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { adminHelp } from "../docs/help.js";
import { attr, attrGrid, attrHtml, avatar, barChart, barLineChart, breadcrumbs, cancelLink, cardSection, codeBlock, confirmAttrs, copyButton, formButton, iconButton, iconLink, rowActions, errorCard, escapeHtml, formActions, helpLink, lineChart, multiSelect, nav, page, pageSizeSelect, paginationControls, rankedBars, remoteMultiSelect, safeBackHref, scriptTag, searchSelect, secretBlock, successBanner, ts, type Breadcrumb, type NotificationFeed } from "../lib/html.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import type { GroupRow, OAuthClientRow, SamlServiceProviderRow, UserRow } from "../lib/types.js";
import { isValidDomain, addDomain, applyDomainToAllUsers, listDomains, setDefaultDomain } from "../lib/domains.js";
import { listUserEmails, setUserEmails } from "../lib/user-emails.js";
import { listUserPhones } from "../lib/user-phones.js";
import { getSmsConfig, saveSmsConfig, smsConfigured, SMS_PROVIDERS } from "../lib/sms.js";
import { parseIdentifier } from "../lib/identifier.js";
import {
  getDefaultPassword,
  getPasswordPolicy,
  isSetupCompleted,
  markSetupCompleted,
  validatePassword,
} from "../lib/settings.js";
import { logAudit, verifyAuditChain } from "../lib/audit.js";
import { CORRELATION_KEYS, getCorrelationKeys, getMasteredFields, listScimMappings, MASTERING_FIELDS, masteringKeyFor, replaceScimMappings, setCorrelationKeys, setMasteredFields, USER_MAPPING_TARGETS } from "../lib/scim-mapping.js";
import { createScimTarget, deleteScimTarget, getScimTarget, listScimTargets, listScimTargetsForApp, updateScimTarget, type ScimTarget } from "../lib/scim-targets.js";
import { catalogValuePlaceholders, getCatalogEntry, listCatalog, renderInstructions, type CatalogEntry } from "../lib/catalog.js";
import { createUpstreamIdp, deleteUpstreamIdp, FederationError, getUpstreamIdp, idpConfig, listUpstreamIdps, oidcCallbackUrl, samlAcsUrl, samlSpEntityId, updateUpstreamIdp, upstreamJitGroups, type OidcIdpConfig, type UpstreamIdpInput, type UpstreamIdpRow } from "../lib/federation.js";
import { SOCIAL_PROVIDERS, socialIssuer, socialMeta, socialProvider, type SocialProvider } from "../lib/social.js";
import { campaignItems, closeCampaign, createCampaign, decideAccessRequest, decideCertItem, getAccessRequest, getCampaign, listAccessRequests, listCampaigns } from "../lib/access.js";
import { ACCESS_APPS_SYNC_HOURS, accessAppHref, accessAppsSyncHours, accessJwtFor, cfOneReady, configureAccessApp, enabledListSyncs, flagUser, getCfOne, grantHints, LIST_SYNCS, listAccessApps, listSyncStatus, riskScoreFor, saveCfOne, setEnabledListSyncs, sweepWatchlist, syncAccessApps, syncLists, unflagUser, watchedUser, watchlist } from "../lib/cfone.js";
import { drainSsfOutbox } from "../lib/ssf.js";
import { getRateLimitPolicy } from "../lib/rate-limit.js";
import { activeTurnstileSiteKey, getNewUserPasswordMode, getTurnstileConfig, isBreachedPasswordCheckEnabled, isMfaRequired } from "../lib/settings.js";
import {
  AUDIT_RETENTION_MAX_DAYS,
  AUDIT_RETENTION_MIN_DAYS,
  getAuditRetentionDays,
} from "../lib/settings.js";
import {
  passwordPolicySummary,
  CURSOR_TRAIL_MAX_CHARACTERS,
  getConsoleTimezone,
  getCursorTrail,
  getDefaultLanguage,
  getSessionPolicy,
  isHexColor,
  SESSION_IDLE_MINUTES_RANGE,
  SESSION_MAX_HOURS_RANGE,
} from "../lib/settings.js";
import { getDisabledAlgorithms, normalizeDisabledAlgorithms, setDisabledAlgorithms, setSetting } from "../lib/settings.js";
import { getLdapAppBySlug, listLdapApps, revokeLdapApp, revealLdapSecret, rotateLdapSecret, writeLdapApp, appGroupIds, LDAP_SECRET_PREFIX, type LdapAppInput } from "../ldap/apps.js";
import { disableLdap, domainToBaseDn, enableLdap, getLdapSettings } from "../ldap/settings.js";
import type { LdapAppRow } from "../lib/types.js";
import { importDirectory, ImportValidationError, type DirectoryBundle } from "../lib/directory-import.js";
import { allLocales } from "../lib/i18n.js";
import { getEmailSettings, isEmailConfigured, isEmailEnabled, recipientFor } from "../lib/email.js";
import { deleteUserStatements, listActiveSessionsForUser } from "../lib/sessions.js";
import { deleteGroupScim, deleteUserScim, syncAll, testScimConnection, drainScimDeprovisionQueue, scimDeprovisionStatementsForMany } from "../lib/scim-client.js";
import { CLAIM_GROUP_LABELS, CLAIM_GROUPS, isValidPostLogoutUri, parseAllowedClaims } from "../lib/oidc.js";
import { fetchSpMetadata, parseSpMetadata, SpMetadataError, upsertSpFromMetadata } from "../lib/saml/sp-metadata.js";
import { API_SCOPES, createApiKey, isApiScope, listApiKeys, parseScopes, type ApiKeyRow, type ApiScope } from "../lib/api-keys.js";
import { idpEntityId, supportedNameIdFormats, nameIdFormatUri } from "../lib/saml/messages.js";
import { isSamlConfigured } from "../lib/saml/sign.js";
import { certNotAfter, normalizeCertPem } from "../lib/saml/x509.js";
import { USER_ATTRIBUTE_FIELDS } from "../lib/saml/attributes.js";
import { normalizeAttributeDefinitions, parseAssignedGroupIds, parseAssignedUserIds, spAttributeDefinitions, type SpAttributeDefinition } from "../lib/saml/service-providers.js";
import { resolveManyGroupMemberUserIds, parseRule, userMatchesRule, ruleDescription, ruleFields, ruleFromForm, type RuleTerm } from "../lib/groups.js";
import {
  listSchemas,
  getSchema,
  findSchema,
  getSchemaAttributes,
  defaultSchemaId,
  parseCustomAttributes,
  userAttributeValue,
  attributesLostOnMove,
  createSchema,
  saveSchemaAttributes,
  applySchemaToAll,
  countConforming,
  attributeInput,
  type SchemaRow,
  type SchemaAttributeRow,
} from "../lib/schemas.js";

import { audit, consoleCtx, ServiceError } from "../services/context.js";
import { assertMayTouchUser } from "../services/guards.js";
import { unsealMaybe } from "../lib/sealed.js";
import { scimConfigured, applyScimScope } from "../services/scim-sync.js";
import {
  createUser,
  deleteUser,
  connectedApps,
  resetUserMfa,
  resetUserPassword,
  revokeUserAppAccess,
  revokeUserSessions,
  sendUserLink,
  setUserStatus,
  updateUserProfile,
} from "../services/users.js";
import { addGroupManagers, assertRuleAllowed, bulkAddMembers, bulkSetRequestable, createGroup, deleteGroup, freezeGroup, groupMembers, removeGroupManager, removeGroupMember, updateGroup } from "../services/groups.js";
import { groupManagers } from "../lib/group-managers.js";
import { notificationFeedFor } from "../lib/notifications.js";
import { describeReport, getReport, openReportsFor, resolveReport } from "../lib/account-reports.js";
import { avatarUrl } from "../lib/photos.js";
import { deleteClient, getClientById, ID_TOKEN_ALGS, isIdTokenAlg, rotateClientSecret, updateClient, validFrontchannelUri } from "../services/clients.js";
import { applyCatalogEntry, insertClient, insertServiceProvider, parseSpForm, readClientSettings, type SpFormValues } from "../services/apps.js";
import {
  addSecurityQuestion,
  applyDefaultPasswordToAll,
  deleteSecurityQuestion,
  saveBreachedPasswordCheck,
  saveTurnstile,
  saveKbaSettings,
  setSecurityQuestionEnabled,
  saveAppName,
  saveAuditRetention,
  saveConsoleTimezone,
  saveCursorTrail,
  saveDefaultLanguage,
  saveDefaultPassword,
  saveEmailAccent,
  saveEmailSettings,
  saveEmailTemplate,
  saveFactor,
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
import { createPolicy, createRole, deletePolicy, deleteRole, normalizePolicy, normalizeRole, updatePolicy, updateRole } from "../services/access.js";
import { removeDomain, revokeKey, rotateKey, updateKey } from "../services/platform.js";
import { emailLogoUrl, getAccent, getTemplate, renderEmail, TEMPLATE_INFO, type EmailTemplate, type TemplateKey } from "../lib/email-templates.js";
import { APP_NAME_MAX, BRAND_NAME_MAX, CUSTOM_CSS_MAX_BYTES, LOGO_MAX_BYTES, SUBTITLE_MAX, defaultBrand, defaultCustomCss, getBrandRow, listBrandRows, mergeBrand, type BrandRow } from "../lib/brands.js";
import { assignDomainBrand, createBrand, deleteBrand, removeLogo, saveDefaultCustomCss, updateBrand, uploadLogo, type BrandInput } from "../services/branding.js";
import { getSetting } from "../lib/settings.js";
import {
  effectiveMappings, getCollisionPolicy, JIT_MAPPING_TARGETS, listMappings, mappingOwners,
  MAPPING_CHANNELS, replaceMappings, SCIM_OUT_TARGETS, setCollisionPolicy,
  validateJitTarget, validateOidcClaimTarget, validateScimOutTarget, type MappingChannel, type MappingRow,
} from "../lib/mappings.js";
import { isValidMappingTarget } from "../lib/scim-mapping.js";
import { EXPRESSION_FUNCTIONS } from "../lib/expr.js";
import { listSigningKeys, RETIRED_PUBLISH_HOURS, SIGNING_ALGS } from "../lib/signing-keys.js";
import { DASHBOARD_DAYS, LOG_ACTORS, LOG_CATEGORIES, logFilters, overviewStats, PERF_RANGES, performanceReport, queryAuditLog } from "../services/monitoring.js";

export { validFrontchannelUri };

export const admin = new Hono<{ Bindings: Env }>();

// A refusal from a shared service (src/services) is rendered as the console
// always rendered its refusals: the message as text, with the status.
admin.onError((err, c) => {
  if (err instanceof ServiceError) return consoleError(c, err.message, err.status);
  console.error(err);
  return consoleError(c, "Something went wrong on our side. Try again; if it keeps happening, check the Worker logs.", 500);
});

/**
 * When a Cloudflare One connection names a team + Access application AUD, the
 * console must arrive through Access. The JWT in Cf-Access-Jwt-Assertion (or
 * the CF_Authorization cookie) is verified against the team's JWKS; a request
 * without it reached the origin directly and is refused before anything runs.
 */
admin.use("/admin", async (c, next) => accessGate(c, next));
admin.use("/admin/*", async (c, next) => accessGate(c, next));

admin.use("/admin", requireSession, requireAdmin);
admin.use("/admin/*", requireSession, requireAdmin);

/**
 * When a Cloudflare One connection names a team + Access application AUD, the
 * console must arrive through Access. The JWT in Cf-Access-Jwt-Assertion (or
 * the CF_Authorization cookie) is verified against the team's JWKS; a request
 * without it reached the origin directly and is refused before anything runs.
 */
async function accessGate(c: Context<{ Bindings: Env }>, next: Next) {
  const config = await getCfOne(c.env);
  if (config?.team && config.accessAud) {
    const jwt = await accessJwtFor(config, c.req.raw);
    if (!jwt) return consoleError(c, "This console requires Cloudflare Access. Open it through the Access-protected hostname.", 403);
  }
  await next();
}

/**
 * Below Super Admin, nobody can change who holds an admin role or act on an
 * account that holds one: a Directory Admin could otherwise make themselves
 * (or anyone) Super Admin, or reset a Super Admin's password.
 */
admin.use("/admin/*", async (c, next) => {
  if (c.req.method !== "POST" || c.get("isSuperAdmin")) return next();
  const path = c.req.path;
  const forbid = (why: string) => consoleError(c, `Forbidden: ${why} needs a Super Admin.`, 403);
  const roleGroupIds = await adminRoleGroupIds(c.env);
  const roleGroupNames = await adminRoleGroupNames(c.env);
  // The id segment accepts any spelling the route's Number() coercion does
  // ("+2", "0x2", "2e0"), so matching \d+ would be a bypass, not a filter.
  const userMatch = /^\/admin\/users\/([^/]+)(\/|$)/.exec(path);
  if (userMatch && userMatch[1] !== "import" && (await accessFor(c.env, Number(userMatch[1]))).isAdmin) return forbid("changing an account that holds an admin role");
  const groupMatch = /^\/admin\/groups\/([^/]+)(\/|$)/.exec(path);
  if (groupMatch && roleGroupIds.has(Number(groupMatch[1]))) return forbid("changing an admin role group");
  if (path === "/admin/users" || userMatch || path === "/admin/groups") {
    const form = await c.req.raw.clone().formData().catch(() => null);
    const ids = form ? [...form.getAll("group_ids"), ...form.getAll("add_group_ids")].map(Number) : [];
    if (ids.some((id) => roleGroupIds.has(id))) return forbid("giving someone an admin role");
    const name = String(form?.get("name") ?? "").trim();
    if (path === "/admin/groups" && roleGroupNames.includes(name)) return forbid("creating an admin role group");
  }
  return next();
});

/** Sensitive actions need a recent sign-in or re-authentication (step-up.ts). */
admin.use("/admin/*", async (c, next) => {
  if (!isSensitive(c.req.method, c.req.path) || (await isFreshlyAuthenticated(c.env, c.get("sessionId"), { superAdmin: Boolean(c.get("isSuperAdmin")) }))) return next();
  // Back to the page the form was on - and keep the POST itself stashed, so a
  // successful step-up replays it instead of making the admin retype the form.
  const ref = c.req.header("Referer");
  let back = "/admin";
  try {
    if (ref && new URL(ref).origin === new URL(c.req.url).origin) back = new URL(ref).pathname + new URL(ref).search;
  } catch {
    // A malformed Referer just means there is no page to go back to.
  }
  const pending = await stashPendingAction(c.env, c.get("sessionId"), c.req.raw, back);
  const dest = pending ? `/admin/reauth/resume?id=${pending}&to=${encodeURIComponent(back)}` : back;
  return c.redirect(`/admin/reauth?next=${encodeURIComponent(dest)}&back=${encodeURIComponent(back)}`, 303);
});

/** Page loads carry the pending-request count (nav badge) and the bell's feed. */
admin.use("/admin/*", async (c, next) => {
  if (c.req.method === "GET") {
    // The Access queue lives under the groups area - nobody else can act on it.
    const feed = grants(c.get("access")?.perms ?? [], "groups:read") ? await notificationFeedFor(c.env, c.get("user").id, true) : null;
    c.set("notifications", feed);
    c.set("accessPending", feed?.count ?? 0);
    c.set("avatarSrc", await avatarUrl(c.env, c.get("user").id));
  }
  await next();
});

function safeNext(next: string | undefined): string {
  return next && next.startsWith("/admin") && !next.startsWith("//") ? next : "/admin";
}

admin.get("/admin/reauth", async (c) => {
  const user = c.get("user");
  const next = safeNext(c.req.query("next"));
  const back = safeNext(c.req.query("back") ?? next);
  const hasPasskey = await userHasPasskey(c.env, user.id);
  const emailStep = await reauthNeedsEmailCode(c.env, user);
  const sentTo = c.req.query("sent");
  return c.html(
    layout(
      c,
      "Confirm it's you",
      `<div class="center-narrow">${cardSection(`
        ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
        <p class="muted" style="margin-top:0;">This action changes credentials or security settings, so it needs you to have signed in within the last ${STEP_UP_WINDOW_MINUTES} minutes. Confirm, and what you were doing carries on.</p>
        <form method="POST" action="/admin/reauth">
          <input type="hidden" name="next" value="${escapeHtml(next)}" />
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required autocomplete="current-password" style="max-width:320px;" />
          ${user.mfa_enabled ? `<label for="code">Authenticator code or backup code</label><input type="text" id="code" name="code" maxlength="12" required autocomplete="one-time-code" style="max-width:160px;" />` : ""}
          ${
            emailStep
              ? `<label for="email_code">Code from your email</label>
                 <input type="text" id="email_code" name="email_code" inputmode="numeric" maxlength="6" required autocomplete="one-time-code" style="max-width:160px;" />
                 <p class="muted" style="margin-top:-6px;">${sentTo ? `Sent to ${escapeHtml(sentTo)}. It works for ${EMAIL_OTP_MINUTES} minutes.` : "Send yourself a code first."}</p>`
              : ""
          }
          <div class="form-actions"><button class="primary" type="submit">Confirm</button>${emailStep ? `<button class="secondary" type="submit" formaction="/admin/reauth/email/send" formnovalidate>${sentTo ? "Send another code" : "Email me a code"}</button>` : ""}${cancelLink(back)}</div>
        </form>
        ${
          hasPasskey
            ? `<div class="auth-passkey" style="max-width:320px;">
                <button class="secondary" type="button" data-passkey-login data-param="next" data-flow="${escapeHtml(next)}" data-options="/admin/reauth/passkey/options" data-post="/admin/reauth/passkey" style="width:100%;">Or confirm with a passkey</button>
                <p class="muted" id="passkey-login-status" style="margin:6px 0 0; font-size:0.8125rem;"></p>
              </div>${scriptTag(PASSKEY_LOGIN_SCRIPT)}`
            : ""
        }
      `)}</div>`,
      [{ label: "Admin", href: "/admin" }, { label: "Confirm it's you" }]
    )
  );
});

// Replays a POST stashed for step-up: the fields go back out as an
// auto-submitting form against the original URL, which this time passes the
// freshness check. One-shot - the stash is consumed on read.
const RESUME_ACTION_SCRIPT = `(function(){var f=document.getElementById("resume-action");if(f)f.submit();})();`;

admin.get("/admin/reauth/resume", async (c) => {
  const back = safeNext(c.req.query("to"));
  const pending = await takePendingAction(c.env, c.get("sessionId"), String(c.req.query("id") ?? ""));
  if (!pending) return c.redirect(back, 303);
  return c.html(
    layout(
      c,
      "Continuing",
      `<div class="center-narrow">${cardSection(`
        <div class="spin-wrap"><div class="spinner" role="status" aria-label="Continuing"></div></div>
        <form id="resume-action" method="POST" action="${escapeHtml(pending.path)}">
          ${pending.fields.map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`).join("")}
          <noscript><div class="form-actions"><button class="primary" type="submit">Continue</button></div></noscript>
        </form>${scriptTag(RESUME_ACTION_SCRIPT)}`)}</div>`,
      [{ label: "Admin", href: "/admin" }, { label: "Continuing" }]
    )
  );
});

const stepUpKey = (userId: number) => `admin:stepup:${userId}`;

/** Read-only budget check: the attempt is charged by chargeStepUp when the proof actually fails, so good step-ups don't burn the budget. */
async function stepUpAttemptsExceeded(c: { env: Env; get: (k: "user") => UserRow }): Promise<boolean> {
  const policy = await getRateLimitPolicy(c.env);
  return rateKeyOverLimit(c.env, stepUpKey(c.get("user").id), policy.maxAttempts, policy.windowMinutes);
}

async function chargeStepUp(c: { env: Env; get: (k: "user") => UserRow }): Promise<void> {
  const policy = await getRateLimitPolicy(c.env);
  await recordRateAttempt(c.env, stepUpKey(c.get("user").id), policy.maxAttempts, policy.windowMinutes);
}

admin.post("/admin/reauth", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const next = safeNext(String(body.next ?? ""));
  const fail = async (msg: string) => {
    await chargeStepUp(c);
    await logAudit(c.env, user, "admin.step_up_failed", user.upn, undefined, c.req.raw);
    return c.redirect(`/admin/reauth?next=${encodeURIComponent(next)}&error=${encodeURIComponent(msg)}`, 302);
  };
  if (await stepUpAttemptsExceeded(c)) {
    await logAudit(c.env, user, "admin.step_up_failed", user.upn, { reason: "rate_limited" }, c.req.raw);
    return c.redirect(`/admin/reauth?next=${encodeURIComponent(next)}&error=${encodeURIComponent("Too many attempts. Please wait a few minutes.")}`, 302);
  }
  if (!(await verifyPassword(String(body.password ?? "").slice(0, 1024), user))) return fail("That password is not right.");
  if (user.mfa_enabled) {
    const code = String(body.code ?? "").slice(0, 12);
    const counter = user.totp_secret ? await matchTotpCounter((await unsealMaybe(c.env, user.totp_secret)) ?? "", code) : null;
    const ok = (counter !== null && (await claimTotpCounter(c.env, user.id, counter))) || (await verifyAndConsumeBackupCode(c.env, user.id, code));
    if (!ok) return fail("That code is not right.");
  }
  // Without an authenticator app, email codes are this person's second factor at
  // sign-in, so confirming needs one too - a password alone is weaker than their sign-in.
  const emailStep = await reauthNeedsEmailCode(c.env, user);
  if (emailStep) {
    const verdict = await verifyEmailOtp(c.env, accountScope(c.get("sessionId")), user.id, "stepup", String(body.email_code ?? "").trim().slice(0, 6));
    if (verdict !== "ok") return fail(verdict === "wrong" ? "That code is not right." : "That code has expired or was already used. Send yourself a new one.");
  }
  await markSteppedUp(c.env, c.get("sessionId"));
  await clearRateKey(c.env, stepUpKey(user.id));
  await logAudit(c.env, user, "admin.step_up", user.upn, { method: user.mfa_enabled ? "password+totp" : emailStep ? "password+email_otp" : "password" }, c.req.raw);
  return c.redirect(next, 302);
});

/** Whether confirming needs an emailed code: no authenticator app, but email codes enrolled and usable. */
async function reauthNeedsEmailCode(env: Env, user: UserRow): Promise<boolean> {
  return !user.mfa_enabled && (await userHasEmailOtp(env, user));
}

admin.post("/admin/reauth/email/send", async (c) => {
  const user = c.get("user");
  const next = safeNext(String((await c.req.parseBody()).next ?? ""));
  const back = (q: string) => c.redirect(`/admin/reauth?next=${encodeURIComponent(next)}&${q}`, 302);
  if (!(await reauthNeedsEmailCode(c.env, user))) return back("error=" + encodeURIComponent("Email codes are not set up for your account."));
  const sent = await sendEmailOtp(c.env, user, accountScope(c.get("sessionId")), "stepup");
  if (!sent.ok) return back("error=" + encodeURIComponent(sent.reason === "rate_limited" ? "Too many codes requested. Please wait a few minutes." : "The code could not be sent."));
  await logAudit(c.env, user, "admin.step_up_code_sent", user.upn, undefined, c.req.raw);
  return back(`sent=${encodeURIComponent(maskEmail(sent.to))}`);
});

admin.get("/admin/reauth/passkey/options", async (c) => {
  const attempt = randomToken(16);
  return c.json({ attempt, options: await authenticationOptions(c.env, attempt, c.get("user").id) });
});

admin.post("/admin/reauth/passkey", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const next = safeNext(String(body.next ?? ""));
  let response: unknown;
  try {
    response = JSON.parse(String(body.response ?? "").slice(0, 16_384));
  } catch {
    response = null;
  }
  const proved = response && !(await stepUpAttemptsExceeded(c)) ? await finishAuthentication(c.env, String(body.attempt ?? ""), response as never) : null;
  if (proved !== user.id) {
    await chargeStepUp(c);
    await logAudit(c.env, user, "admin.step_up_failed", user.upn, { method: "passkey" }, c.req.raw);
    return c.redirect(`/admin/reauth?next=${encodeURIComponent(next)}&error=${encodeURIComponent("That passkey could not confirm it's you.")}`, 302);
  }
  await markSteppedUp(c.env, c.get("sessionId"));
  await clearRateKey(c.env, stepUpKey(user.id));
  await logAudit(c.env, user, "admin.step_up", user.upn, { method: "passkey" }, c.req.raw);
  return c.redirect(next, 302);
});

/** Section labels (second breadcrumb) -> nav key, so detail pages highlight their section too. */
const CRUMB_SECTIONS: Record<string, string> = {
  Access: "access",
  Users: "users",
  Groups: "groups",
  Applications: "applications",
  Integrations: "integrations",
  Domains: "domains",
  Branding: "branding",
  Security: "security",
  Schemas: "schemas",
  Log: "audit",
};

function layout(
  c: {
    get: ((k: "appName") => string) &
      ((k: "access") => Access | undefined) &
      ((k: "logoUrl") => string | null) &
      ((k: "consoleTz") => string) &
      ((k: "notifications") => NotificationFeed | null | undefined) &
      ((k: "accessPending") => number | undefined) &
      ((k: "avatarSrc") => string | undefined) &
      ((k: "user") => UserRow);
  },
  title: string,
  body: string,
  crumbs?: Breadcrumb[],
  active?: string,
  headerActions = ""
) {
  const appName = c.get("appName");
  const crumbHtml = crumbs ? breadcrumbs(crumbs) : "";
  const section = active ?? (crumbs?.[1] ? (CRUMB_SECTIONS[crumbs[1].label] ?? "") : crumbs?.length === 1 ? "overview" : "");
  // Inside Integrations, the third crumb names the page (see integrationCrumb);
  // with no third crumb it is the section's own overview.
  const sub =
    section === "overview"
      ? (crumbs?.[1]?.label === "Performance" ? "performance" : "dashboard")
      : section === "security"
      ? ({ Policies: "policies", Factors: "factors", Roles: "roles", "Signing keys": "signing-keys" } as Record<string, string>)[crumbs?.[2]?.label ?? ""] ?? "settings"
      : section === "branding"
      ? ({ "Email templates": "email-templates", Brands: "brands" } as Record<string, string>)[crumbs?.[2]?.label ?? ""] ?? "settings"
      : section === "groups"
      ? "groups"
      : section === "applications"
      ? (crumbs?.[2]?.label === "App catalog" ? "catalog" : "all")
      : section !== "integrations"
      ? ""
      : crumbs?.length === 2
        ? "overview"
        : (INTEGRATION_PAGES.find((p) => p.label === crumbs?.[2]?.label)?.key ?? "");
  const guide = adminHelp(section, sub, crumbs?.[2]?.label);
  const help = guide ? helpLink(guide.href, guide.title) : "";
  const navMenu = adminNav(section, sub, c.get("access") ? visibleSections(c.get("access")!) : undefined, c.get("accessPending") ?? 0);
  return page(
    `${title}`,
    `<div class="admin-shell">
      <aside class="admin-side admin-side-desktop">${navMenu.html}</aside>
      <details class="admin-nav-mobile"><summary><span>${escapeHtml(navMenu.activeLabel)}</span><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 6l4 4 4-4"/></svg></summary>
        <div class="admin-side">${navMenu.html}</div>
      </details>
      <div class="admin-main">
        <div class="page-header">${crumbHtml}<div class="page-header-row"><div class="page-title"><h1>${escapeHtml(title)}</h1>${help}</div>${headerActions}</div></div>
        ${body}
      </div>
    </div>`,
    appName,
    true,
    nav(appName, true, c.get("logoUrl"), c.get("consoleTz"), c.get("notifications"), c.get("user")?.display_name ?? "", c.get("avatarSrc") ?? "")
  );
}

function copyableRow(label: string, value: string, widthStyle = ""): string {
  return `<tr><th${widthStyle}>${escapeHtml(label)}</th><td><div class="copy-value"><code>${escapeHtml(value)}</code>${copyButton(value)}</div></td></tr>`;
}

function oidcEndpointsBlock(env: Env, clientId: string) {
  return `
    <div class="info-panel">
      <p class="muted" style="margin:0 0 8px 0;">Use these when configuring this client as an OIDC login method (e.g. Cloudflare Access's App ID / Client secret / Auth URL / Token URL / Certificate URL fields):</p>
      <table style="margin:0;">
        ${copyableRow("App ID / Client ID", clientId, ' style="width:140px;"')}
        ${copyableRow("Auth URL", `${env.ISSUER_URL}/authorize`)}
        ${copyableRow("Token URL", `${env.ISSUER_URL}/token`)}
        ${copyableRow("Certificate URL", `${env.ISSUER_URL}/jwks.json`)}
        ${copyableRow("Issuer", env.ISSUER_URL)}
        ${copyableRow("Scopes", "openid email profile groups")}
      </table>
    </div>
  `;
}

/** The Integrations pages, which the sidebar lists under their section. Labels double as the third breadcrumb. */
const INTEGRATION_PAGES = [
  { key: "saml", label: "SAML" },
  { key: "scim", label: "SCIM provisioning" },
  { key: "ldap", label: "LDAP" },
  { key: "federation", label: "Federation" },
  { key: "social", label: "Social sign-in" },
  { key: "email", label: "Email" },
  { key: "sms", label: "SMS" },
  { key: "api-keys", label: "API keys" },
  { key: "cf-one", label: "Cloudflare One" },
  { key: "signals", label: "Signals" },
] as const;
type IntegrationPage = (typeof INTEGRATION_PAGES)[number]["key"];

const INTEGRATIONS_CRUMB: Breadcrumb = { label: "Integrations", href: "/admin/integrations" };
/** The Applications section's own crumb: the unified OIDC + SAML app list. */
const APPS_CRUMB: Breadcrumb = { label: "Applications", href: "/admin/apps" };
const APP_CATALOG_CRUMB: Breadcrumb = { label: "App catalog", href: "/admin/apps/catalog" };
function integrationCrumb(key: IntegrationPage): Breadcrumb {
  const p = INTEGRATION_PAGES.find((x) => x.key === key)!;
  return { label: p.label, href: `/admin/integrations/${p.key}` };
}

/** A refused or failed console action, as a page in the console rather than bare text. */
function consoleError(c: Context<{ Bindings: Env }>, message: string, status: number) {
  const title = status === 404 ? "Not found" : status === 403 ? "Not allowed" : status === 409 ? "Already exists" : "That didn't work";
  return c.html(layout(c, title, errorCard(status, message, safeBackHref(c.req.raw, "/admin")), [{ label: "Admin", href: "/admin" }, { label: title }]), status as 400);
}

function adminNav(active: string, sub = "", visible?: Set<string>, pending = 0) {
  const pendingBadge = pending > 0 ? `<span class="nav-badge">${pending > 99 ? "99+" : pending}</span>` : "";
  const items: [string, string, string][] = [
    ["overview", "/admin", "Overview"],
    ["access", "/admin/access", "Access"],
    ["users", "/admin/users", "Users"],
    ["groups", "/admin/groups", "Groups"],
    ["applications", "/admin/apps", "Applications"],
    ["integrations", "/admin/integrations", "Integrations"],
    ["security", "/admin/security", "Security"],
    ["domains", "/admin/domains", "Domains"],
    ["schemas", "/admin/schemas", "Schemas"],
    ["flows", "/admin/flows", "Flows"],
    ["branding", "/admin/branding", "Branding"],
    ["audit", "/admin/audit", "Log"],
  ];
  const activeLabel = items.find(([k]) => k === active)?.[2] ?? "Overview";
  const html = items
    .filter(([key]) => !visible || visible.has(key))
    .map(([key, href, label]) => {
      const link = `<a href="${href}" class="${active === key ? "active" : ""}">${label}${key === "access" ? pendingBadge : ""}</a>`;
      // A section's pages are listed only while you are in that section.
      if (key === "applications" && active === "applications") {
        return link + [["all", "/admin/apps", "All apps"], ["catalog", "/admin/apps/catalog", "App catalog"]]
          .map(([k, h, l]) => `<a href="${h}" class="sub${(sub || "all") === k ? " active" : ""}">${l}</a>`)
          .join("");
      }
      if (key === "overview" && active === "overview") {
        return link + [["dashboard", "/admin", "Dashboard"], ["performance", "/admin/performance", "Performance"]]
          .map(([k, h, l]) => `<a href="${h}" class="sub${(sub || "dashboard") === k ? " active" : ""}">${l}</a>`)
          .join("");
      }
      if (key === "branding" && active === "branding") {
        return link + [["settings", "/admin/branding", "Settings"], ["brands", "/admin/branding/brands", "Brands"], ["email-templates", "/admin/branding/email-templates", "Email templates"]]
          .map(([k, h, l]) => `<a href="${h}" class="sub${(sub || "settings") === k ? " active" : ""}">${l}</a>`)
          .join("");
      }
      if (key === "security" && active === "security") {
        return link + [["settings", "/admin/security", "Settings"], ["policies", "/admin/security/policies", "Policies"], ["factors", "/admin/security/factors", "Factors"], ["roles", "/admin/security/roles", "Roles"], ["signing-keys", "/admin/security/signing-keys", "Signing keys"]]
          .map(([k, h, l]) => `<a href="${h}" class="sub${(sub || "settings") === k ? " active" : ""}">${l}</a>`)
          .join("");
      }
      if (key !== "integrations" || active !== "integrations") return link;
      const children = [{ key: "overview", label: "Overview", href: "/admin/integrations" }, ...INTEGRATION_PAGES.filter((p) => p.key !== "api-keys" || !visible || visible.has("security")).map((p) => ({ ...p, href: `/admin/integrations/${p.key}` }))]
        .map((p) => `<a href="${p.href}" class="sub${sub === p.key ? " active" : ""}">${p.label}</a>`)
        .join("");
      return link + children;
    })
    .join("") + DOCS_NAV_LINK;
  return { html, activeLabel };
}

/** Last in the console menu, for every administrator: the public docs, in a new tab. */
const DOCS_NAV_LINK = `<a href="/docs" class="nav-docs" target="_blank" rel="noopener" aria-label="Docs (opens in a new tab)">Docs <svg viewBox="0 0 16 16" width="11" height="11" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 3H3v10h10v-3M9 2h5v5M14 2L7 9"/></svg></a>`;

// The account-password and SCIM helpers moved to src/services, shared with the API.

function splitUpn(upn: string): { username: string; domain: string } {
  const at = upn.lastIndexOf("@");
  return at === -1 ? { username: upn, domain: "" } : { username: upn.slice(0, at), domain: upn.slice(at + 1) };
}

// The sign-in name's shape on the user forms: a UPN needs the domain picker's
// value appended; a handle or a phone is the whole identifier by itself.
const IDENT_TYPE_SCRIPT = `(function(){var s=document.getElementById('identifier_type');if(!s)return;function t(){var w=document.getElementById('domain-wrap');if(w)w.style.display=s.value==='upn'?'':'none';var i=document.getElementById('username');if(i)i.placeholder=s.value==='upn'?'username':(s.value==='phone'?'+15551234567':'handle');}s.addEventListener('change',t);t();})();`;

function identifierTypeSelect(kind: "upn" | "handle" | "phone", disabled = false) {
  const opts: [string, string][] = [
    ["upn", "UPN (name@domain)"],
    ["handle", "Handle (no domain)"],
    ["phone", "Phone (+E.164)"],
  ];
  return `<select name="identifier_type" id="identifier_type" ${disabled ? "disabled" : ""} style="margin-bottom:0;">${opts.map(([v, l]) => `<option value="${v}" ${v === kind ? "selected" : ""}>${l}</option>`).join("")}</select>`;
}

/** Posted sign-in-name fields -> the identifier createUser/updateUserProfile stores. */
function postedIdentifier(body: Record<string, unknown>, fallbackKind: string): string {
  const kind = String(body.identifier_type ?? fallbackKind);
  const name = String(body.username ?? "").trim();
  return kind === "upn" ? `${name}@${String(body.domain ?? "").trim()}` : name;
}

function employmentStatusSelect(current: string, name = "employment_status") {
  const options: [string, string][] = [
    ["", "-"],
    ["active", "Active"],
    ["on_leave", "On leave"],
    ["terminated", "Terminated"],
  ];
  return `<select id="${name}" name="${name}">
    ${options.map(([value, label]) => `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`).join("")}
  </select>`;
}

function employmentTypeSelect(current: string, name = "employment_type") {
  const options: [string, string][] = [
    ["", "-"],
    ["full_time", "Full-time"],
    ["contractor", "Contractor"],
  ];
  return `<select id="${name}" name="${name}">
    ${options.map(([value, label]) => `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`).join("")}
  </select>`;
}

/**
 * Renders a user schema's attribute inputs - attr_<name> fields in a
 * two-column grid, using the specialized widgets where they exist. User
 * references (manager) are a searchable picker that never offers the user
 * being edited, since nobody can be their own manager.
 */
async function userSchemaAttributesHtml(c: { env: Env }, attributes: SchemaAttributeRow[], values: Record<string, string>, excludeUserId: number | null, mastered: Set<string>): Promise<string> {
  if (attributes.length === 0) return '<p class="muted">This schema defines no attributes beyond identity.</p>';

  // References are picked by searching the directory on the server; only the
  // people currently referenced are loaded here (a 10,000-person directory
  // used to put every user in every picker).
  const refValues = attributes.filter((a) => a.type === "reference").map((a) => values[a.name]).filter((v): v is string => Boolean(v));
  const referenced = new Map(
    refValues.length
      ? (
          await c.env.DB.prepare("SELECT external_id, display_name, upn FROM users WHERE external_id IN (SELECT value FROM json_each(?))")
            .bind(JSON.stringify(refValues))
            .all<{ external_id: string; display_name: string; upn: string }>()
        ).results.map((u) => [u.external_id, `${u.display_name} (${u.upn})`])
      : []
  );

  const masteredNote = ' <span class="muted" style="font-weight:400;">(mastered by provisioning)</span>';
  const cells = attributes.map((attr) => {
    const value = values[attr.name] ?? "";
    const label = `<label for="attr_${escapeHtml(attr.name)}">${escapeHtml(attr.label)}${attr.required ? " *" : ""}${mastered.has(masteringKeyFor(attr)) ? masteredNote : ""}</label>`;
    if (mastered.has(masteringKeyFor(attr))) {
      // Read-only echo of the current value - no input posts, and the service
      // keeps the existing value regardless.
      const shown = attr.type === "reference" ? (value ? referenced.get(value) ?? value : "") : value;
      return `<div>${label}<input type="text" value="${escapeHtml(shown)}" disabled /></div>`;
    }
    if (attr.name === "employment_status") return `<div>${label}${employmentStatusSelect(value, "attr_employment_status")}</div>`;
    if (attr.name === "employment_type") return `<div>${label}${employmentTypeSelect(value, "attr_employment_type")}</div>`;
    if (attr.type === "reference") {
      const current = value && referenced.has(value) ? [{ id: value, label: referenced.get(value)! }] : [];
      return `<div>${label}${remoteMultiSelect(`attr_${attr.name}`, `/admin/users/lookup?key=external_id${excludeUserId ? `&exclude=${excludeUserId}` : ""}`, current, "Search people...", true)}</div>`;
    }
    return `<div>${attributeInput(attr, value)}</div>`;
  });
  return `<div class="form-grid">${cells.join("")}</div>`;
}

/** The top-right account switch on the user page: posts immediately rather than waiting for Save. */
function accountStatusSwitch(userId: number, status: string, isSelf: boolean): string {
  const active = status === "active";
  return `<form method="POST" action="/admin/users/${userId}/status" style="margin:0;"
      ${active && !isSelf ? confirmAttrs("They are signed out of every session and cannot sign in until reactivated. Their account and data are kept.", { title: "Deactivate this account?", action: "Deactivate" }) : ""}>
      <input type="hidden" name="status" value="${active ? "disabled" : "active"}" />
      <label class="switch" title="${isSelf ? "You cannot deactivate your own account" : ""}">
        <input type="checkbox" ${active ? "checked" : ""} ${isSelf ? "disabled" : ""} data-autosubmit />
        <span class="track"></span>
        <span style="font-size:0.875rem; font-weight:600;">${active ? "Active" : "Inactive"}</span>
      </label>
    </form>`;
}

/** Groups whose dynamic rule matches this user - displayed read-only, since membership follows attributes. */
function dynamicGroupsFor(user: UserRow, groups: GroupRow[]): GroupRow[] {
  return groups.filter((g) => {
    const rule = parseRule(g.rule);
    return rule !== null && userMatchesRule(user, rule);
  });
}


async function domainSelect(env: Env, name: string, selectedDomain?: string, disabled = false) {
  const domains = await listDomains(env);
  const hasSelected = selectedDomain ? domains.some((d) => d.domain === selectedDomain) : false;
  return `<select name="${escapeHtml(name)}" ${disabled ? "disabled" : ""}>
    ${domains
      .map((d) => `<option value="${escapeHtml(d.domain)}" ${d.domain === selectedDomain ? "selected" : ""}>${escapeHtml(d.domain)}</option>`)
      .join("")}
    ${selectedDomain && !hasSelected ? `<option value="${escapeHtml(selectedDomain)}" selected>${escapeHtml(selectedDomain)} (not in domain list)</option>` : ""}
  </select>`;
}

// ---------- Dashboard ----------

// DASHBOARD_DAYS, dayKey and PERF_RANGES live in services/monitoring.ts, shared with the API.

// Auto-refreshing request strip on /admin/performance: polls the JSON
// endpoint and redraws DOM bars. A fixed string so the CSP hash covers it -
// all data arrives via fetch, nothing is interpolated.
const PERFORMANCE_LIVE_SCRIPT = `(function(){
  var el=document.getElementById('live-chart'),meta=document.getElementById('live-meta'),sp=document.getElementById('live-spans');
  if(!el)return;
  function bars(pts){
    var max=1,i;for(i=0;i<pts.length;i++)if(pts[i].requests>max)max=pts[i].requests;
    el.innerHTML=pts.map(function(p){
      var h=Math.round(p.requests/max*56),e=p.errors?'<div style="height:'+Math.max(1,Math.round(p.errors/max*56))+'px;background:var(--fi-red)"></div>':'';
      return '<div title="'+String(p.t).slice(11,16)+' - '+p.requests+' req, '+p.errors+' err" style="flex:1;min-width:2px;display:flex;flex-direction:column;justify-content:flex-end">'+(p.requests?'<div style="height:'+Math.max(2,h)+'px;background:var(--fi-accent)"></div>':'')+e+'</div>';
    }).join('');
  }
  function poll(){
    fetch('/admin/performance/live').then(function(r){return r.ok?r.json():null}).then(function(d){
      if(!d||!d.ok)return;
      bars(d.points||[]);
      if(meta)meta.textContent='Live - updated '+new Date(d.fetchedAt).toLocaleTimeString();
      if(sp)sp.innerHTML=(d.spans||[]).slice(0,4).map(function(s){return '<code>'+s.name+'</code> '+s.avgMs+'ms';}).join(' &middot; ');
    }).catch(function(){});
  }
  poll();setInterval(poll,10000);
})();`;

/** Live data for the performance page's auto-refreshing strip (same numbers, JSON). */
admin.get("/admin/performance/live", async (c) => {
  const [series, spans, events] = await Promise.all([readPerformanceSeries(c.env, 1, 1), readSpanStats(c.env, 1), readEventCounts(c.env, 30)]);
  if (!series.configured) return c.json({ configured: false });
  if (!series.ok) return c.json({ configured: true, ok: false, error: series.error });
  return c.json({ configured: true, ok: true, fetchedAt: new Date().toISOString(), points: series.points.slice(-30), spans: spans ?? [], events: events ?? [] });
});

admin.get("/admin/performance", async (c) => {
  const { rangeKey, range, family, series, totals } = await performanceReport(c.env, c.req.query("range"), c.req.query("endpoint"));
  const [spans, events] = series.configured ? await Promise.all([readSpanStats(c.env, range.hours), readEventCounts(c.env, range.hours * 60)]) : [null, null];
  const tabs = `<div class="range-tabs">${(Object.keys(PERF_RANGES) as (keyof typeof PERF_RANGES)[])
    .map((k) => `<a href="/admin/performance?range=${k}${family ? `&endpoint=${family}` : ""}" class="${k === rangeKey ? "active" : ""}">${PERF_RANGES[k].label}</a>`)
    .join("")}</div>`;
  let body: string;
  if (!series.configured || !totals.configured) {
    body = cardSection(`<h2>Turn on the performance dashboard</h2>
      <p>Every request already records a data point (route family, status, Worker time) in the Workers Analytics Engine dataset
        <code>flareid_requests</code>, at no D1 or KV cost. Reading them back needs an API token:</p>
      <ol>
        <li>Create an API token with <strong>Account Analytics: Read</strong> for this account.</li>
        <li><code>wrangler secret put CF_ANALYTICS_TOKEN</code></li>
        <li>Deploy with the <code>CF_ACCOUNT_ID</code> var set (<code>wrangler deploy --var CF_ACCOUNT_ID:&lt;account id&gt;</code>).</li>
      </ol>`);
  } else if (!series.ok || !totals.ok) {
    body = cardSection(`<p class="error">Could not read metrics: ${escapeHtml(!series.ok ? series.error : (totals as { error: string }).error)}</p>`);
  } else {
    const labels = series.points.map((p) => range.fmt(new Date(p.t)));
    const total = series.points.reduce((s, p) => s + p.requests, 0);
    const errors = series.points.reduce((s, p) => s + p.errors, 0);
    const worstP95 = Math.max(0, ...series.points.map((p) => p.p95));
    body = `
      <div class="stat-grid">
        <div class="stat-card"><div class="card"><h2>${total.toLocaleString("en")}</h2><p>Requests</p></div></div>
        <div class="stat-card"><div class="card"><h2>${total ? ((errors / total) * 100).toFixed(2) : "0.00"}%</h2><p>Server errors (5xx)</p></div></div>
        <div class="stat-card"><div class="card"><h2>${(totals.families.find((f) => !family || f.family === family)?.p50 ?? 0)} ms</h2><p>Median Worker time</p></div></div>
        <div class="stat-card"><div class="card"><h2>${worstP95} ms</h2><p>Worst p95 in a bucket</p></div></div>
      </div>
      ${cardSection(`<div class="row between" style="margin-bottom:12px;"><h2 style="margin:0;">Requests</h2><span class="muted">per ${range.bucket >= 60 ? `${range.bucket / 60} h` : `${range.bucket} min`}</span></div>
        ${barChart(series.points.map((p, i) => ({ label: labels[i]!, value: p.requests })), { width: 1280 })}`)}
      <div class="two-col">
        ${cardSection(`<h2>Latency</h2><p class="muted">Worker time per request, ms.</p>
          ${lineChart(labels, [{ name: "p50", className: "s-p50", values: series.points.map((p) => p.p50) }, { name: "p95", className: "s-p95", values: series.points.map((p) => p.p95) }], { width: 640, unit: "" })}
          <div class="chart-legend"><span><span class="chart-swatch" style="background:var(--fi-accent);"></span>p50</span><span><span class="chart-swatch" style="background:var(--fi-faint);"></span>p95</span></div>`)}
        ${cardSection(`<h2>Server errors</h2><p class="muted">Responses with status 500 and above.</p>
          ${barChart(series.points.map((p, i) => ({ label: labels[i]!, value: p.errors })), { width: 640, barClass: "err" })}`)}
      </div>
      ${cardSection(`<div class="row between" style="margin-bottom:8px;"><h2 style="margin:0;">Live</h2><span class="muted" id="live-meta">starting…</span></div>
        <div id="live-chart" style="display:flex;gap:1px;align-items:flex-end;height:64px;"></div>
        <p class="muted" style="margin:8px 0 0;">Requests per minute, last 30 minutes - refreshes every 10s. <span id="live-spans"></span></p>${scriptTag(PERFORMANCE_LIVE_SCRIPT)}`)}
      ${
        series.configured
          ? cardSection(`<h2>Where the time goes</h2><p class="muted">Instrumented operations inside requests (lib/metrics.ts spans), last ${range.label.toLowerCase()}.</p>
        ${
          spans === null
            ? `<p class="muted">Could not read the flareid_spans dataset - check CF_ANALYTICS_TOKEN and that the deploy included the METRICS_SPANS binding.</p>`
            : spans.length
              ? `<table><thead><tr><th>Operation</th><th>Calls</th><th>Total ms</th><th>Avg ms</th><th>p95 ms</th></tr></thead><tbody>
          ${spans.map((s) => `<tr><td><code>${escapeHtml(s.name)}</code></td><td>${s.calls.toLocaleString("en")}</td><td>${s.totalMs.toLocaleString("en")}</td><td>${s.avgMs}</td><td>${s.p95}</td></tr>`).join("")}
        </tbody></table>`
              : `<p class="muted">No spans recorded yet - they appear here a minute or two after traffic flows through instrumented operations.</p>`
        }`)
          : ""
      }
      ${
        series.configured
          ? cardSection(`<h2>Events</h2><p class="muted">Audited actions and outbound call outcomes counted as they happen, last ${range.label.toLowerCase()}. Outbound statuses (e.g. <code>scim.outbound &middot; 502</code>) are the target system's answers - they never become FlareID responses, so they cannot appear in the 5xx charts.</p>
        ${
          events === null
            ? `<p class="muted">Could not read the flareid_spans dataset - check CF_ANALYTICS_TOKEN and that the deploy included the METRICS_SPANS binding.</p>`
            : events.length
              ? `<table><thead><tr><th>Action</th><th>Detail</th><th>Count</th></tr></thead><tbody>
          ${events.slice(0, 15).map((e) => `<tr><td><code>${escapeHtml(e.name)}</code></td><td>${e.detail ? `<code>${escapeHtml(e.detail)}</code>` : '<span class="muted">&mdash;</span>'}</td><td>${e.count.toLocaleString("en")}</td></tr>`).join("")}
        </tbody></table>`
              : `<p class="muted">No events recorded yet - sign-ins, token grants, LDAP binds, SCIM push results and admin changes land here as they happen.</p>`
        }`)
          : ""
      }
      ${cardSection(`<h2>By endpoint</h2>
        <table><thead><tr><th>Endpoint</th><th>Requests</th><th>5xx</th><th>p50 ms</th><th>p95 ms</th></tr></thead><tbody>
          ${totals.families.map((f) => `<tr><td><a href="/admin/performance?range=${rangeKey}&endpoint=${escapeHtml(f.family)}">${escapeHtml(f.family)}</a></td><td>${f.requests.toLocaleString("en")}</td><td>${f.errors}</td><td>${f.p50}</td><td>${f.p95}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No requests recorded in this period.</td></tr>'}
        </tbody></table>`)}`;
  }
  return c.html(
    layout(
      c,
      family ? `Performance: ${family}` : "Performance",
      body,
      [{ label: "Admin", href: "/admin" }, { label: "Performance" }],
      "overview",
      `<div class="row" style="gap:10px;">${family ? `<a href="/admin/performance?range=${rangeKey}">All endpoints</a>` : ""}${tabs}</div>`
    )
  );
});

admin.get("/admin", async (c) => {
  // The same numbers GET /api/v1/stats returns (services/monitoring.ts) -
  // which is why the audit-derived sections need the same permission the API
  // demands (performance:read), with audit:read accepted as the console's
  // own monitor role. Directory counts are safe for every admin.
  const access = c.get("access");
  const monitor = Boolean(access && (access.isSuper || grants(access.perms, "performance:read") || grants(access.perms, "audit:read")));
  const [stats, perf, perfHour] = await Promise.all([overviewStats(c.env), readPerformance(c.env, 24), readPerformance(c.env, 1)]);
  const successSeries = stats.last_30d.sign_ins_by_day.map(({ day, success }) => ({
    label: day.slice(8, 10) === "01" ? day.slice(5, 10) : day.slice(8, 10),
    value: success,
  }));
  const failedSeries = stats.last_30d.sign_ins_by_day.map((d) => d.failed);
  const { users, groups, oidc_clients: oidcClients, saml_apps: samlApps, active_api_keys: apiKeys, active_users: activeUsers, active_sessions: activeSessions, mfa_enrolled: mfaEnrolled, live_refresh_grants: refreshLive, scim_deletions_queued: scimQueue } = stats.counts;
  const { sign_ins: ok24, failed_sign_ins: bad24, rate_limited_sign_ins: limited24, failed_step_ups: stepUpBad24, api_calls: api24, rejected_api_keys: apiBad24, scim_sync_failures: scimFail24 } = stats.last_24h;
  const { sign_ins: successTotal, failed_sign_ins: failedTotal, outcomes, top_actions: topActions, top_users: topUsers } = stats.last_30d;

  return c.html(
    layout(
      c,
      "Admin",
      `
            <div class="stat-grid">
        <a class="stat-card" href="/admin/users"><div class="card"><h2>${users}</h2><p>Users</p></div></a>
        <a class="stat-card" href="/admin/groups"><div class="card"><h2>${groups}</h2><p>Groups</p></div></a>
        <a class="stat-card" href="/admin/apps"><div class="card"><h2>${oidcClients}</h2><p>OIDC Clients</p></div></a>
        ${monitor ? `<a class="stat-card" href="/admin/log"><div class="card"><h2>${successTotal}</h2><p>Sign-ins (30d)</p></div></a>` : `<a class="stat-card" href="/admin/apps"><div class="card"><h2>${samlApps}</h2><p>SAML apps</p></div></a>`}
      </div>
      <div class="stat-grid">
        <a class="stat-card" href="/admin/users"><div class="card"><h2>${activeUsers}</h2><p>Active accounts</p></div></a>
        ${monitor ? `<a class="stat-card" href="/admin/apps"><div class="card"><h2>${samlApps}</h2><p>SAML apps</p></div></a>` : ""}
        <a class="stat-card" href="/admin/integrations/api-keys"><div class="card"><h2>${apiKeys}</h2><p>Active API keys</p></div></a>
        ${monitor ? `<a class="stat-card" href="/admin/log"><div class="card"><h2>${refreshLive}</h2><p>Live refresh grants</p></div></a>` : ""}
      </div>
      ${
        monitor
          ? `

      <div class="two-col">
        ${cardSection(`
          <h2>Last 24 hours</h2>
          ${attrGrid([
            attr("Sign-ins", ok24),
            attr("Failed sign-ins", bad24),
            attr("Rate-limited sign-ins", limited24),
            attr("Failed step-up checks", stepUpBad24),
            attr("API calls", api24),
            attr("Rejected API keys", apiBad24),
            attr("SCIM sync failures", scimFail24),
            attr("SCIM deletions queued", scimQueue),
          ])}
        `)}
        ${cardSection(`
          <div class="row between" style="margin-bottom:8px;"><h2 style="margin:0;">IdP performance</h2><a href="/admin/performance">Open the performance dashboard &rarr;</a></div>
          ${
            perf.configured && perf.ok
              ? (() => {
                  const busiest = perf.families.reduce<{ family: string; requests: number } | null>((w, f) => (w === null || f.requests > w.requests ? f : w), null);
                  const slowest = perf.families.reduce<{ family: string; p95: number } | null>((w, f) => (w === null || f.p95 > w.p95 ? f : w), null);
                  // The p50 of the family the median request lands in - an approximation of the
                  // whole-traffic median without a second query that tracks percentiles globally.
                  let seen = 0;
                  const median = [...perf.families].sort((a, b) => a.p50 - b.p50).find((f) => (seen += f.requests) >= perf.total / 2)?.p50 ?? 0;
                  return attrGrid([
                    attr("Requests (24h)", perf.total.toLocaleString("en")),
                    attr("Requests (1h)", perfHour.configured && perfHour.ok ? perfHour.total.toLocaleString("en") : null),
                    attr("Server errors (5xx)", perf.errors),
                    attr("Median Worker time", `${median} ms`),
                    attr("Active endpoints", perf.families.length),
                    ...(busiest ? [attr("Busiest endpoint", `${busiest.family} · ${busiest.requests.toLocaleString("en")}`)] : []),
                    ...(slowest ? [attr("Slowest endpoint (p95)", `${slowest.family} · ${slowest.p95} ms`)] : []),
                  ]);
                })()
              : '<p class="muted">Request volume, errors and latency for every endpoint, with graphs.</p>'
          }
        `)}
      </div>

      ${cardSection(`
        <div class="row between" style="margin-bottom:12px;">
          <h2 style="margin:0;">Successful sign-ins per day</h2>
          <span class="muted">last ${DASHBOARD_DAYS} days</span>
        </div>
        ${
          successTotal + failedTotal === 0
            ? '<p class="muted">No sign-in activity recorded yet. This fills in as people use the directory.</p>'
            : barLineChart(successSeries, { name: "failed", className: "s-err", values: failedSeries }, { width: 1280 })
        }
        <div class="chart-legend">
          <span><span class="chart-swatch" style="background:var(--fi-accent);"></span>${successTotal} successful</span>
          <span><span class="chart-swatch" style="background:var(--fi-err-line);"></span>${failedTotal} failed or rejected (right axis)</span>
        </div>
      `)}

      <div class="two-col">
        ${cardSection(`
          <h2>Sign-in outcomes</h2>
          <p class="muted">Every login-related event in the last ${DASHBOARD_DAYS} days.</p>
          ${rankedBars(outcomes.map((r) => ({ label: r.action.replace(/^login\./, "").replace(/_/g, " "), value: r.n })))}
        `)}
        ${cardSection(`
          <h2>Most active accounts</h2>
          <p class="muted">By successful sign-in, last ${DASHBOARD_DAYS} days.</p>
          ${rankedBars(topUsers.map((r) => ({ label: r.upn, value: r.n })))}
        `)}
      </div>

      <div class="two-col">
        ${cardSection(`
          <h2>Directory activity</h2>
          <p class="muted">Administrative and self-service changes, last ${DASHBOARD_DAYS} days.</p>
          ${rankedBars(topActions.map((r) => ({ label: r.action.replace(/_/g, " "), value: r.n })))}
        `)}
        ${cardSection(`
          <h2>Posture</h2>
          ${attrGrid([
            attr("Active sessions", activeSessions),
            attr("MFA enrolled", `${mfaEnrolled} of ${users}`),
            attr("MFA coverage", users ? `${Math.round((mfaEnrolled / users) * 100)}%` : "—"),
            attr("By factor", (["totp", "passkey", "backup_codes", "email_otp", "security_questions"] as const).map((f) => `${FACTOR_SHORT_LABELS[f]} ${stats.second_factors[f]}`).join(" · ")),
            attr("Failed sign-ins (30d)", failedTotal),
          ])}
          <div style="margin-top:14px;"><a href="/admin/log">View the full log</a></div>
        `)}
      </div>
`
          : ""
      }
      `,
      [{ label: "Admin" }]
    )
  );
});

// ---------- Setup wizard ----------

admin.get("/admin/setup", async (c) => {
  const domains = await listDomains(c.env);
  const defaultPassword = await getDefaultPassword(c.env);
  const currentUserId = c.get("user").id;

  const sampleUserCount = await c.env.DB.prepare("SELECT COUNT(*) as n FROM users WHERE id != ?")
    .bind(currentUserId)
    .first<{ n: number }>();
  const sampleGroupCount = await c.env.DB.prepare(
    `SELECT COUNT(*) as n FROM groups WHERE name NOT IN (?, 'All Employees')`
  )
    .bind(SUPER_ADMINS_GROUP)
    .first<{ n: number }>();

  return c.html(
    layout(
      c,
      "Welcome to FlareID",
      `
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <p class="sub">Before anyone else can sign in, confirm the basics below. You can change all of this later from Admin → Domains / Security.</p>
        <form method="POST" action="/admin/setup" ${confirmAttrs(
          "Every user except your own admin account is permanently deleted, along with every group except Super Admins and All Employees.",
          { title: "Remove the sample directory?", action: "Remove and finish", danger: true, when: 'input[name=sample_data][value=remove]' }
        )}>
          <div class="field-row">
            <div>
              <label for="domain">Primary domain for user accounts</label>
              <input type="text" id="domain" name="domain" value="${escapeHtml(domains[0]?.domain ?? "")}" required />
            </div>
            <div>
              <label for="default_password">Default password for new/seeded accounts</label>
              <input type="text" id="default_password" name="default_password" value="${escapeHtml(defaultPassword)}" required />
            </div>
          </div>

          <label>Sample data</label>
          <label style="font-weight:400;"><input type="radio" name="sample_data" value="keep" checked style="width:auto; display:inline; margin-right:6px;" /> Keep the ${sampleUserCount?.n ?? 0} sample users and ${sampleGroupCount?.n ?? 0} sample groups</label>
          <label style="font-weight:400; margin-bottom:16px;"><input type="radio" name="sample_data" value="remove" style="width:auto; display:inline; margin-right:6px;" /> Remove them and start with a clean, empty directory</label>

          <div class="form-actions">
            <button class="primary" type="submit">Finish setup</button>
            ${cancelLink("/admin", "Cancel")}
          </div>
        </form>
      `)}
      ${cardSection(`
        <h2>Change your own password</h2>
        <p class="muted">Recommended before finishing setup - the admin account starts with the default password above.</p>
        <a href="/account"><button class="secondary" type="button">Go to My account</button></a>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Setup" }]
    )
  );
});

admin.post("/admin/setup", async (c) => {
  const body = await c.req.parseBody();
  const domain = String(body.domain ?? "").trim().toLowerCase();
  const defaultPassword = String(body.default_password ?? "");
  const removeSampleData = body.sample_data === "remove";

  if (domain) {
    if (!isValidDomain(domain)) return c.redirect("/admin/setup?error=" + encodeURIComponent(`"${domain}" is not a valid DNS domain name.`), 302);
    const existing = await listDomains(c.env);
    if (!existing.some((d) => d.domain === domain)) {
      await addDomain(c.env, domain);
    }
    const row = (await listDomains(c.env)).find((d) => d.domain === domain);
    if (row) await setDefaultDomain(c.env, row.id);
  }
  if (defaultPassword) await saveDefaultPassword(consoleCtx(c), defaultPassword);

  if (removeSampleData) {
    await removeSampleDirectoryData(c);
  }

  await markSetupCompleted(c.env);
  await logAudit(c.env, c.get("user"), "idp.setup_completed", domain, { removeSampleData }, c.req.raw);

  return c.redirect("/admin", 302);
});

/** Wipes every seeded sample user/group except the current admin's own account and the Super Admins / All Employees groups. */
async function removeSampleDirectoryData(c: { env: Env; get: (k: "user") => UserRow; req: { raw: Request } }) {
  const currentUserId = c.get("user").id;

  const { results: sampleUsers } = await c.env.DB.prepare("SELECT * FROM users WHERE id != ?")
    .bind(currentUserId)
    .all<UserRow>();
  // The admin role groups and All Employees are FlareID's own, like Super
  // Admins: never sample data - the consent dialog promises both built-ins.
  const keepGroups = JSON.stringify([...(await adminRoleGroupNames(c.env)), "All Employees"]);
  const { results: sampleGroups } = await c.env.DB.prepare(
    `SELECT * FROM groups WHERE name NOT IN (SELECT value FROM json_each(?))`
  )
    .bind(keepGroups)
    .all<GroupRow>();

  // The shared deletion (every users(id)-referencing table), with the remote
  // ids queued in the same batch; downstream DELETEs drain from the queue.
  const sampleUserIds = sampleUsers.map((u) => u.id);
  await c.env.DB.batch([
    ...(await scimDeprovisionStatementsForMany(c.env, "user", sampleUsers.map((u) => ({ id: u.id, label: u.upn })))),
    ...(await scimDeprovisionStatementsForMany(c.env, "group", sampleGroups.map((g) => ({ id: g.id, label: g.name })))),
    ...(sampleUserIds.length > 0 ? deleteUserStatements(c.env, ...sampleUserIds) : []),
    c.env.DB.prepare("DELETE FROM groups WHERE name NOT IN (SELECT value FROM json_each(?))").bind(keepGroups),
  ]);
  if (await scimConfigured(c.env)) await drainScimDeprovisionQueue(c.env);
}

// ---------- Users ----------

async function superAdminUserIds(env: Env): Promise<Set<number>> {
  const { results } = await env.DB.prepare(
    "SELECT user_id FROM group_members WHERE group_id = (SELECT id FROM groups WHERE name = ?)"
  )
    .bind(SUPER_ADMINS_GROUP)
    .all<{ user_id: number }>();
  return new Set(results.map((r) => r.user_id));
}

/** A person's enrolled second factors, compact: "Authenticator app, Passkey", or "-". */
function factorList(factors: FactorKey[]): string {
  if (!factors.length) return '<span class="muted">-</span>';
  return factors
    .map((f) => (f === "security_questions" ? `<span title="Security questions do not count as an administrator's second factor">${FACTOR_SHORT_LABELS[f]}</span>` : FACTOR_SHORT_LABELS[f]))
    .join(", ");
}

admin.get("/admin/users", async (c) => {
  const search = c.req.query("search") ?? "";
  const statusFilter = c.req.query("status") ?? "";
  const mfaFilter = c.req.query("mfa") ?? "";
  const roleFilter = c.req.query("role") ?? "";
  const schemaFilter = c.req.query("schema") ?? "";
  const pageSize = [20, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 20;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const like = `%${search}%`;

  const conditions = ["(upn LIKE ? OR display_name LIKE ?)"];
  const params: (string | number)[] = [like, like];

  if (statusFilter === "active" || statusFilter === "disabled") {
    conditions.push("status = ?");
    params.push(statusFilter);
  }
  // Any second factor, the same definition as the column and the overview.
  if (mfaFilter === "enabled") conditions.push(anySecondFactorSql("users"));
  else if (mfaFilter === "disabled") conditions.push(`NOT ${anySecondFactorSql("users")}`);
  if (roleFilter === "admin" || roleFilter === "regular") {
    conditions.push(
      `id ${roleFilter === "admin" ? "IN" : "NOT IN"} (SELECT user_id FROM group_members WHERE group_id = (SELECT id FROM groups WHERE name = '${SUPER_ADMINS_GROUP}'))`
    );
  }
  if (schemaFilter && Number(schemaFilter)) {
    conditions.push("schema_id = ?");
    params.push(Number(schemaFilter));
  }
  const whereClause = `WHERE ${conditions.join(" AND ")}`;

  const batchResults = await c.env.DB.batch([
    c.env.DB.prepare(`SELECT COUNT(*) as n FROM users ${whereClause}`).bind(...params),
    c.env.DB.prepare(`SELECT *, ${hasPasskeySql("users")} AS has_passkey, ${hasBackupCodesSql("users")} AS has_backup_codes FROM users ${whereClause} ORDER BY display_name LIMIT ? OFFSET ?`).bind(
      ...params,
      pageSize,
      (page - 1) * pageSize
    ),
  ]);
  const countRows = batchResults[0]!.results;
  const users = batchResults[1]!.results;
  const total = Number((countRows[0] as { n: number } | undefined)?.n ?? 0);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const admins = await superAdminUserIds(c.env);
  const userSchemas = await listSchemas(c.env, "user");
  const schemaNames = new Map(userSchemas.map((s) => [s.id, s.name]));
  const currentUserId = c.get("user").id;

  const filterSelect = (name: string, current: string, options: [string, string][]) =>
    `<select name="${name}" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
      ${options.map(([value, label]) => `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`).join("")}
    </select>`;

  return c.html(
    layout(
      c,
      `Users (${total.toLocaleString("en")})`,
      `
            ${cardSection(`
        <form method="GET">
          <div class="row between" style="align-items:flex-start; gap:12px; flex-wrap:wrap;">
            <div style="display:flex; gap:8px; flex-wrap:wrap; flex:1;">
              <input type="text" name="search" placeholder="Search users" value="${escapeHtml(search)}" style="max-width:260px; margin-bottom:0;" />
              ${filterSelect("status", statusFilter, [
                ["", "All statuses"],
                ["active", "Active"],
                ["disabled", "Disabled"],
              ])}
              ${filterSelect("mfa", mfaFilter, [
                ["", "All MFA"],
                ["enabled", "Has a second factor"],
                ["disabled", "No second factor"],
              ])}
              ${filterSelect("role", roleFilter, [
                ["", "All roles"],
                ["admin", "Super Admin"],
                ["regular", "Regular"],
              ])}
              ${filterSelect("schema", schemaFilter, [["", "All schemas"], ...userSchemas.map((s): [string, string] => [String(s.id), s.name])])}
              <input type="hidden" name="page" value="1" />
              ${pageSizeSelect(pageSize)}
            </div>
            <a href="/admin/users/import"><button class="secondary" type="button">Import CSV</button></a>
            <a href="/admin/users/new"><button class="primary" type="button">+ New user</button></a>
          </div>
        </form>
      `)}
      ${cardSection(`
        <table>
          <thead><tr><th>Name</th><th>UPN</th><th>Status</th><th>MFA</th><th>Role</th><th>Schema</th><th style="width:72px;"></th></tr></thead>
          <tbody>
            ${(users as (UserRow & { has_passkey: number; has_backup_codes: number })[])
              .map(
                (u) => `<tr>
                  <td><a href="/admin/users/${u.id}">${avatar(u.id, u.display_name, "sm", { upn: u.upn })}${escapeHtml(u.display_name)}</a></td>
                  <td>${escapeHtml(u.upn)}</td>
                  <td><span class="badge badge-${u.status}">${u.status}</span></td>
                  <td>${factorList(enrolledFactors(u))}</td>
                  <td>${admins.has(u.id) ? '<span class="badge badge-admin">Super Admin</span>' : "-"}</td>
                  <td>${u.schema_id && schemaNames.has(u.schema_id) ? escapeHtml(schemaNames.get(u.schema_id)!) : '<span class="muted">-</span>'}</td>
                  <td>${rowActions(
                    iconLink(`/admin/users/${u.id}`, "edit", `Edit ${u.display_name}`),
                    u.id === currentUserId
                      ? ""
                      : `<form method="POST" action="/admin/users/${u.id}/delete"
                          ${confirmAttrs(`${u.display_name} (${u.upn}) is removed along with their sessions, tokens and group memberships. This cannot be undone.`, { title: "Delete this user?", action: "Delete user", danger: true })}>${iconButton("trash", `Delete ${u.display_name}`, { danger: true })}</form>`
                  )}</td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
        ${paginationControls("/admin/users", page, totalPages, { search, status: statusFilter, mfa: mfaFilter, role: roleFilter, schema: schemaFilter, pageSize })}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Users" }]
    )
  );
});

// ---------- CSV import ----------
//
// The browser parses the files and sends the directory in chunks, so a 10,000
// row CSV never has to fit in one request (or one Worker's CPU and D1 query
// budget). Groups go first, then users ordered so every manager arrives before
// their reports, then the server does exactly what /api/v1/directory/import
// does with each chunk. See docs/csv-import.md for the columns.

const CSV_IMPORT_SCRIPT = `
(function () {
  var form = document.getElementById("csv-import");
  if (!form) return;
  var log = document.getElementById("csv-log");
  var bar = document.getElementById("csv-progress");
  function say(t) { log.textContent += t + "\\n"; log.scrollTop = log.scrollHeight; }

  // RFC 4180: quoted fields, doubled quotes, commas and newlines inside quotes.
  function parseCsv(text) {
    var rows = [], row = [], field = "", q = false;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (q) {
        if (ch === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
        else field += ch;
      } else if (ch === '"') q = true;
      else if (ch === ",") { row.push(field); field = ""; }
      else if (ch === "\\n" || ch === "\\r") {
        if (ch === "\\r" && text[i + 1] === "\\n") i++;
        row.push(field); field = ""; if (row.length > 1 || row[0] !== "") rows.push(row); row = [];
      } else field += ch;
    }
    if (field !== "" || row.length) { row.push(field); rows.push(row); }
    if (!rows.length) return [];
    var head = rows[0].map(function (h) { return h.trim().toLowerCase(); });
    return rows.slice(1).map(function (r) { var o = {}; head.forEach(function (h, j) { o[h] = (r[j] || "").trim(); }); return o; });
  }

  var KNOWN = ["username","given_name","family_name","display_name","email","job_title","department","employee_number","hire_date","employment_status","employment_type","location","manager","status","groups","password","schema"];
  function toUser(r) {
    var u = { username: r.username };
    KNOWN.forEach(function (k) { if (k !== "username" && k !== "groups" && r[k] !== undefined && r[k] !== "") u[k] = r[k]; });
    if (r.groups !== undefined) u.groups = r.groups ? r.groups.split(";").map(function (g) { return g.trim(); }).filter(Boolean) : [];
    var extra = {};
    Object.keys(r).forEach(function (k) { if (KNOWN.indexOf(k) === -1 && r[k] !== "") extra[k] = r[k]; });
    if (Object.keys(extra).length) u.attributes = extra;
    return u;
  }
  // Managers before their reports, so each manager reference resolves.
  function managerFirst(users) {
    var byName = {}, out = [], seen = {};
    users.forEach(function (u) { byName[u.username] = u; });
    function visit(u, depth) {
      if (seen[u.username] || depth > 50) return;
      if (u.manager && byName[u.manager] && !seen[u.manager]) visit(byName[u.manager], depth + 1);
      if (!seen[u.username]) { seen[u.username] = 1; out.push(u); }
    }
    users.forEach(function (u) { visit(u, 0); });
    return out;
  }
  async function post(bundle) {
    var res = await fetch("/admin/users/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(bundle) });
    var body = await res.json().catch(function () { return { error: "HTTP " + res.status }; });
    if (!res.ok) throw new Error(body.message || body.error || ("HTTP " + res.status));
    return body;
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    var btn = form.querySelector("button[type=submit]");
    btn.disabled = true; log.textContent = "";
    var pw = form.querySelector("input[name=passwords]:checked");
    var passwords = pw ? pw.value : "none";
    var totals = { created: 0, updated: 0, skipped: 0, errors: 0 };
    try {
      var gEl = form.querySelector("#groups_csv"), uEl = form.querySelector("#users_csv");
      var gFile = gEl && gEl.files[0];
      var uFile = uEl && uEl.files[0];
      if (!gFile && !uFile) { say("Choose a groups CSV, a users CSV, or both."); return; }
      if (gFile) {
        var groups = parseCsv(await gFile.text()).filter(function (g) { return g.name; }).map(function (g) { var o = { name: g.name }; if (g.description) o.description = g.description; if (g.rule) o.rule = g.rule; return o; });
        say("Importing " + groups.length + " groups...");
        var gr = await post({ version: 1, groups: groups, users: [] });
        say("Groups: " + gr.groups.created + " created, " + gr.groups.updated + " updated" + (gr.errors.length ? ", " + gr.errors.length + " issue(s)" : ""));
        gr.errors.slice(0, 20).forEach(function (er) { say("  " + (er.group || er.username || "") + ": " + er.message); });
      }
      if (uFile) {
        var users = managerFirst(parseCsv(await uFile.text()).filter(function (r) { return r.username; }).map(toUser));
        var CHUNK = 50, started = Date.now();
        say("Importing " + users.length + " users in chunks of " + CHUNK + "...");
        for (var i = 0; i < users.length; i += CHUNK) {
          var r = await post({ version: 1, passwords: passwords, users: users.slice(i, i + CHUNK) });
          totals.created += r.users.created; totals.updated += r.users.updated; totals.skipped += r.users.skipped; totals.errors += r.errors.length;
          r.errors.slice(0, 5).forEach(function (er) { say("  " + (er.username || er.group || "") + ": " + er.message); });
          var done = Math.min(i + CHUNK, users.length);
          bar.value = done / users.length;
          if (done % 1000 === 0 || done === users.length) say(done + " / " + users.length + " (" + Math.round((Date.now() - started) / 1000) + "s)");
        }
        say("Users: " + totals.created + " created, " + totals.updated + " updated, " + totals.skipped + " skipped, " + totals.errors + " issue(s).");
      }
      say("Done.");
    } catch (err) {
      say("Stopped: " + err.message + ". Rows already sent were imported; fix the problem and run the import again - it converges.");
    } finally {
      btn.disabled = false;
    }
  });
})();
`;

/** The CSV import page: users and groups, or groups only (from the groups list). */
async function importPageHtml(env: Env, kind: "users" | "groups"): Promise<string> {
  const emailOn = await isEmailConfigured(env);
  const fileBox = (id: string, title: string, columns: string, hint: string) => `
    <label class="drop-zone" for="${id}">
      <span class="drop-title">${title}</span>
      <span class="muted">${columns}</span>
      <input type="file" id="${id}" accept=".csv,text/csv" />
      <span class="drop-hint">${hint}</span>
    </label>`;
  return `
    <div class="import-layout">
      ${cardSection(`
        <form id="csv-import">
          <h2>1. Choose ${kind === "users" ? "files" : "a file"}</h2>
          <div class="${kind === "users" ? "drop-grid" : ""}">
            ${fileBox("groups_csv", "Groups CSV", "name, description, rule", kind === "users" ? "Optional. Imported first, so users can reference these groups." : "Static groups have no rule; a rule makes the group dynamic.")}
            ${kind === "users" ? fileBox("users_csv", "Users CSV", "username, given_name, family_name, ... groups", "Managers are imported before the people who report to them.") : ""}
          </div>
          ${
            kind === "users"
              ? `<h2 style="margin-top:20px;">2. Passwords for new accounts</h2>
                 <p class="muted" style="margin-top:0;">Used only for rows without a <code>password</code> column.</p>
                 <label class="choice"><input type="radio" name="passwords" value="none" checked /> <span><strong>No password</strong><br /><span class="muted">They activate from ${emailOn ? "an invitation email or " : ""}an admin password reset. Fast for any size.</span></span></label>
                 <label class="choice"><input type="radio" name="passwords" value="default" /> <span><strong>The new-account password setting</strong><br /><span class="muted">Each one is hashed, which is slow for thousands of users.</span></span></label>`
              : ""
          }
          <div class="form-actions end" style="margin-top:18px;"><button class="primary" type="submit">Import</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Progress</h2>
        <progress id="csv-progress" value="0" max="1" class="import-progress"></progress>
        ${codeBlock("Nothing imported yet.", { id: "csv-log" })}
        <p class="muted" style="margin-bottom:0;">Idempotent by username and group name: running it again updates rather than duplicates.
          Columns are described in <code>docs/csv-import.md</code>; <code>npm run test-data</code> generates a 10,000-person example.</p>
      `)}
    </div>
    ${scriptTag(CSV_IMPORT_SCRIPT)}`;
}

/** Directory search for the console's pickers: up to 20 people matching ?q= by name, UPN or username. */
admin.get("/admin/users/lookup", async (c) => {
  const q = (c.req.query("q") ?? "").trim().toLowerCase().slice(0, 100);
  if (!q) return c.json([]);
  const key = c.req.query("key") === "external_id" ? "external_id" : "id";
  const exclude = Number(c.req.query("exclude")) || -1;
  const notInGroup = Number(c.req.query("not_in_group")) || -1;
  const like = `%${q.replace(/[%_]/g, (m) => `\\${m}`)}%`;
  const { results } = await c.env.DB.prepare(
    `SELECT id, external_id, display_name, upn FROM users
      WHERE id != ? AND (lower(display_name) LIKE ? ESCAPE '\\' OR lower(upn) LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\')
        AND id NOT IN (SELECT user_id FROM group_members WHERE group_id = ?)
      ORDER BY (lower(display_name) LIKE ? ESCAPE '\\') DESC, display_name LIMIT 20`
  )
    .bind(exclude, like, like, like, notInGroup, `${q.replace(/[%_]/g, (m) => `\\${m}`)}%`)
    .all<{ id: number; external_id: string; display_name: string; upn: string }>();
  return c.json(results.map((u) => ({ id: key === "external_id" ? u.external_id : u.id, label: `${u.display_name} (${u.upn})` })));
});

admin.get("/admin/users/import", async (c) =>
  c.html(layout(c, "Import users from CSV", await importPageHtml(c.env, "users"), [{ label: "Admin", href: "/admin" }, { label: "Users", href: "/admin/users" }, { label: "Import CSV" }]))
);

// Feeds group pickers search-as-you-type (e.g. the review form), returning
// {id, label, desc} items like /admin/users/lookup. static=1 limits to
// assigned-membership groups - the only kind an action over members can use.
admin.get("/admin/groups/lookup", async (c) => {
  const q = (c.req.query("q") ?? "").trim().toLowerCase().slice(0, 100);
  if (!q) return c.json([]);
  const staticOnly = c.req.query("static") === "1";
  const like = `%${q.replace(/[%_]/g, (m) => `\\${m}`)}%`;
  const { results } = await c.env.DB.prepare(
    `SELECT g.*, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) AS member_count
     FROM groups g
     WHERE (lower(g.name) LIKE ? ESCAPE '\\' OR lower(g.description) LIKE ? ESCAPE '\\')
       ${staticOnly ? "AND (g.rule IS NULL OR g.rule = '')" : ""}
     ORDER BY (lower(g.name) LIKE ? ESCAPE '\\') DESC, g.name LIMIT 20`
  )
    .bind(like, like, like)
    .all<GroupRow & { member_count: number }>();
  const roleMap = await groupRolesMap(c.env);
  return c.json(
    results.map((g) => {
      const roles = roleMap.get(g.id) ?? [];
      return {
        id: g.id,
        label: g.name,
        badges: roles.map((r) => ({ label: r.name, title: r.description })),
        desc: `${g.member_count} member${g.member_count === 1 ? "" : "s"}${roles.length ? ` · grants ${roles.map((r) => r.name).join(", ")}` : ""}${g.description ? ` · ${g.description}` : ""}`,
      };
    })
  );
});

admin.get("/admin/groups/import", async (c) =>
  c.html(layout(c, "Import groups from CSV", await importPageHtml(c.env, "groups"), [{ label: "Admin", href: "/admin" }, { label: "Groups", href: "/admin/groups" }, { label: "Import CSV" }]))
);

admin.post("/admin/users/import", async (c) => {
  let bundle: DirectoryBundle;
  try {
    bundle = (await c.req.json()) as DirectoryBundle;
  } catch {
    return c.json({ error: "invalid_request", message: "Body must be JSON." }, 400);
  }
  // The console is Super Admin authority already; replace mode is not offered here.
  bundle.mode = "merge";
  // The bundle's domain is ensured into the domains table, whose consumers
  // assume DNS names - the same gate as POST /admin/domains.
  const domain = String(bundle.domain ?? "").trim().toLowerCase();
  if (domain && !isValidDomain(domain)) return c.json({ error: "invalid_request", message: `"${domain}" is not a valid DNS domain name.` }, 400);
  try {
    // Same rule as the Active switch: an import cannot deactivate your own account.
    const me = c.get("user").username;
    if ((bundle.users ?? []).some((u) => String(u.username ?? "").trim().toLowerCase() === me && u.status !== undefined && u.status !== "active")) {
      return c.json({ error: "invalid_request", message: `The import would deactivate your own account (${me}). Remove that row or set it to active.` }, 400);
    }
    // Only Super Admins may assign admin roles or overwrite role holders through an import.
    const result = await importDirectory(c.env, bundle, { allowPrivileged: c.get("isSuperAdmin") });
    await logAudit(c.env, c.get("user"), "directory.imported", result.domain, { via: "csv", users: result.users, groups: result.groups, errors: result.errors.length }, c.req.raw);
    return c.json(result);
  } catch (e) {
    if (e instanceof ImportValidationError) return c.json({ error: "invalid_request", message: e.message }, 400);
    throw e;
  }
});

admin.get("/admin/users/new", async (c) => {
  const { results: groups } = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all<GroupRow>();
  const domains = await listDomains(c.env);
  const userSchemas = await listSchemas(c.env, "user");
  const requestedSchema = Number(c.req.query("schema"));
  const schema = (await getSchema(c.env, requestedSchema)) ?? (await getSchema(c.env, Number(await defaultSchemaId(c.env, "user"))));
  const schemaAttrs = schema ? await getSchemaAttributes(c.env, schema.id) : [];
  const emptyValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, ""]));
  const mastered = new Set(await getMasteredFields(c.env));

  return c.html(
    layout(
      c,
      "New user",
      cardSection(`
        <form method="POST" action="/admin/users">
          <div class="field-row">
            <div>
              <label for="given_name">First name</label>
              <input type="text" id="given_name" name="given_name" required />
            </div>
            <div>
              <label for="family_name">Last name</label>
              <input type="text" id="family_name" name="family_name" required />
            </div>
          </div>
          <label for="username">Sign-in name</label>
          <div class="field-row">
            <div style="flex:1;">${identifierTypeSelect("upn")}</div>
            <input type="text" id="username" name="username" placeholder="username" required style="flex:2;" />
            <div style="flex:1;" id="domain-wrap">${await domainSelect(c.env, "domain", domains[0]?.domain)}</div>
          </div>
          ${scriptTag(IDENT_TYPE_SCRIPT)}
          <div class="card-head" style="margin-top:8px;">
            <h2>Attributes</h2>
            <div class="inline-field">
              <label for="schema_id">Schema</label>
              <select id="schema_id" name="schema_id" style="margin-bottom:0;" data-navigate="/admin/users/new?schema=">
                ${userSchemas.map((s) => `<option value="${s.id}" ${schema?.id === s.id ? "selected" : ""}>${escapeHtml(s.name)}</option>`).join("")}
              </select>
            </div>
          </div>
          ${await userSchemaAttributesHtml(c, schemaAttrs, emptyValues, null, mastered)}
          <h2>Groups</h2>
          <p class="muted" style="margin-top:-6px;">Static groups only - dynamic groups pick people up from their attributes.</p>
          ${multiSelect(
            "group_ids",
            groups.filter((g) => !parseRule(g.rule)).map((g) => ({ id: g.id, label: g.name })),
            new Set<number>(),
            "Search groups..."
          )}
          <p class="muted">New accounts start inactive - activate them from their page once they're ready to sign in.</p>
          <div class="form-actions end">${cancelLink(`/admin/users`)}<button class="primary" type="submit">Create user</button></div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Users", href: "/admin/users" }, { label: "New user" }]
    )
  );
});

admin.post("/admin/users", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const schemaId = Number(body.schema_id) || undefined;
  const attributes = Object.fromEntries(Object.entries(body).filter(([k]) => k.startsWith("attr_")).map(([k, v]) => [k.slice(5), String(v ?? "")]));
  const postedGroupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];
  // Shared with POST /api/v1/users (services/users.ts). New accounts start inactive.
  const created = await createUser(consoleCtx(c), {
    username: String(body.username ?? ""),
    domain: String(body.domain ?? ""),
    identifier: postedIdentifier(body, "upn"),
    givenName: String(body.given_name ?? ""),
    familyName: String(body.family_name ?? ""),
    schemaId,
    attributes,
    groupIds: postedGroupIds,
    status: "disabled",
  });
  const userId = created.id;
  const upn = created.upn;
  const tempPassword = created.password;
  const displayName = `${String(body.given_name ?? "").trim()} ${String(body.family_name ?? "").trim()}`.trim();

  return c.html(
    layout(
      c,
      "User created",
      `${cardSection(`
        <p class="success" style="margin-top:0;">Created ${escapeHtml(displayName)} (${escapeHtml(upn)}). The account is inactive until you switch it on from their page.</p>
        ${secretBlock("Temporary password - share with the user securely", tempPassword)}
        <a href="/admin/users/${userId}"><button class="primary" type="button">Keep this password and continue</button></a>
      `)}
      ${
        (await isEmailConfigured(c.env))
          ? cardSection(`
        <h2>Or email them an invitation</h2>
        <p class="muted" style="margin-top:-6px;">They choose their own password from a link sent to <strong>${escapeHtml(upn)}</strong>, and that activates the account. The temporary password above stops mattering.</p>
        <form method="POST" action="/admin/users/${userId}/invite"><button class="primary" type="submit">Send invitation</button></form>
      `)
          : ""
      }
      ${cardSection(`
        <h2>Or set a password of your own</h2>
        <p class="muted" style="margin-top:-6px;">Replaces the temporary password above.</p>
        ${choosePasswordForm(Number(userId), await getPasswordPolicy(c.env))}
      `)}`,
      [{ label: "Admin", href: "/admin" }, { label: "Users", href: "/admin/users" }, { label: "User created" }]
    )
  );
});

admin.post("/admin/users/:id/reports/:rid/resolve", async (c) => {
  const id = Number(c.req.param("id"));
  const report = await getReport(c.env, Number(c.req.param("rid")));
  if (report && report.user_id === id && (await resolveReport(c.env, report.id, c.get("user").id))) {
    const target = await c.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(id).first<{ upn: string }>();
    await logAudit(c.env, c.get("user"), "user.report_resolved", target?.upn, { kind: report.kind }, c.req.raw);
  }
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

admin.get("/admin/users/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const emailOn = await isEmailConfigured(c.env);

  const { results: groups } = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all<GroupRow>();
  const { results: memberships } = await c.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?")
    .bind(id)
    .all<{ group_id: number }>();
  const memberGroupIds = new Set(memberships.map((m) => m.group_id));
  const sessions = await listActiveSessionsForUser(c.env, id);
  const apps = await connectedApps(c.env, id);
  const reports = await openReportsFor(c.env, id);
  const { username, domain } = splitUpn(user.upn);
  const isSelf = id === c.get("user").id;
  // What Reset MFA clears (passkeys are removed one by one, below).
  const anyMfa = Boolean(user.mfa_enabled || user.email_otp_enabled || user.security_questions_enabled);
  const factors = enrolledFactors({ ...user, has_passkey: await userHasPasskey(c.env, id), has_backup_codes: await hasUnusedBackupCodes(c.env, id) });
  const userIsAdmin = await isAdministrator(c.env, id);
  // An administrator's security questions are not a second factor they can use.
  const countedFactors = userIsAdmin ? factors.filter((f) => f !== "security_questions") : factors;

  // Schema: ?schema= previews a move before it is saved. The values shown
  // come from the user's row, so attributes with the same name in the target
  // schema carry over; the notice lists what saving would clear.
  const userSchemas = await listSchemas(c.env, "user");
  const currentSchemaId = user.schema_id ?? (await defaultSchemaId(c.env, "user"));
  const requestedSchema = Number(c.req.query("schema"));
  const schema = (requestedSchema ? await getSchema(c.env, requestedSchema) : null) ?? (currentSchemaId ? await getSchema(c.env, currentSchemaId) : null);
  const schemaAttrs = schema ? await getSchemaAttributes(c.env, schema.id) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, userAttributeValue(user, a)]));
  const lostBySchema = new Map<number, string[]>();
  for (const s of userSchemas) lostBySchema.set(s.id, attributesLostOnMove(user, await getSchemaAttributes(c.env, s.id)));
  const previewing = schema !== null && schema.id !== currentSchemaId;
  const previewLost = previewing ? (lostBySchema.get(schema.id) ?? []) : [];
  const currentSchemaName = userSchemas.find((s) => s.id === currentSchemaId)?.name ?? "none";
  const mastered = new Set(await getMasteredFields(c.env));
  const masteredNote = ' <span class="muted" style="font-weight:400;">(mastered by provisioning)</span>';
  const watch = await watchedUser(c.env, id);
  const cfConfig = await getCfOne(c.env);
  const risk = cfOneReady(cfConfig) ? await riskScoreFor(c.env, cfConfig!, user.upn) : null;

  const staticGroups = groups.filter((g) => !parseRule(g.rule));
  const dynamicGroups = dynamicGroupsFor(user, groups);

  // The record exactly as the API and provisioning syncs see it: the row plus
  // its parsed attributes, addresses and memberships - never the credential
  // material (hashes, salts, TOTP secrets).
  const { password_hash: _ph, password_salt: _ps, password_iterations: _pi, totp_secret: _ts, totp_last_counter: _tc, scim_id: _si, ...publicRow } = user;
  const userEmails = await listUserEmails(c.env, id);
  const userPhones = await listUserPhones(c.env, id);
  const { results: scimLinks } = await c.env.DB.prepare(
    "SELECT t.name AS target, l.scim_id FROM scim_user_links l JOIN scim_targets t ON t.id = l.target_id WHERE l.user_id = ? ORDER BY t.name"
  ).bind(id).all<{ target: string; scim_id: string }>();
  const rawUserJson = JSON.stringify(
    {
      ...publicRow,
      custom_attributes: JSON.parse(user.custom_attributes || "{}"),
      emails: userEmails.map((e) => ({ value: e.email, type: e.type, primary: e.is_primary === 1 })),
      ...(scimLinks.length ? { scim: Object.fromEntries(scimLinks.map((l) => [l.target, l.scim_id])) } : {}),
      groups: {
        static: groups.filter((g) => memberGroupIds.has(g.id) && !parseRule(g.rule)).map((g) => g.name),
        dynamic: dynamicGroups.map((g) => g.name),
      },
    },
    null,
    2
  );

  const schemaOptions = userSchemas
    .map((s) => {
      const lost = lostBySchema.get(s.id) ?? [];
      return `<option value="${s.id}" data-confirm-lost="${escapeHtml(lost.join(", "))}" ${schema?.id === s.id ? "selected" : ""}>${escapeHtml(s.name)}${s.id === currentSchemaId ? " (current)" : ""}</option>`;
    })
    .join("");

  return c.html(
    layout(
      c,
      user.display_name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("sent") === "invite" ? successBanner(`Invitation sent to ${recipientFor(user)}.`) : ""}
      ${c.req.query("sent") === "reset" ? successBanner(`Password reset link sent to ${recipientFor(user)}.`) : ""}
      ${c.req.query("send_error") ? `<p class="error">The email could not be sent: ${escapeHtml(c.req.query("send_error") ?? "")}</p>` : ""}
      ${reports
        .map(
          (r) => `<div class="notice-warn" style="display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:14px;">
          <div><strong>${escapeHtml(user.display_name)} reported ${escapeHtml(describeReport(r))} as not them</strong> on ${ts(r.created_at)}. It was signed out when they reported it. Review their sign-in history below, and consider resetting their password or MFA.</div>
          <form method="POST" action="/admin/users/${id}/reports/${r.id}/resolve" style="margin:0; flex-shrink:0;"><button class="secondary" type="submit">Mark reviewed</button></form>
        </div>`
        )
        .join("")}
      <form method="POST" action="/admin/users/${id}" id="user-form">
        ${cardSection(`
          <h2>Identity</h2>
          <div class="field-row">
            <div>
              <label for="given_name">First name${mastered.has("given_name") ? masteredNote : ""}</label>
              <input type="text" id="given_name" name="given_name" value="${escapeHtml(user.given_name)}" required ${mastered.has("given_name") ? "disabled" : ""} />
            </div>
            <div>
              <label for="family_name">Last name${mastered.has("family_name") ? masteredNote : ""}</label>
              <input type="text" id="family_name" name="family_name" value="${escapeHtml(user.family_name)}" ${mastered.has("family_name") ? "disabled" : ""} />
            </div>
          </div>
          <label for="username">Sign-in name${mastered.has("upn") ? masteredNote : ""}</label>
          <div class="field-row">
            <div style="flex:1; min-width:0;">${identifierTypeSelect(parseIdentifier(user.upn)?.kind ?? "upn", mastered.has("upn"))}</div>
            <input type="text" id="username" name="username" value="${escapeHtml(username)}" required style="flex:2; min-width:0;" ${mastered.has("upn") ? "disabled" : ""} />
            <div style="flex:1; min-width:0;" id="domain-wrap">${await domainSelect(c.env, "domain", domain, mastered.has("upn"))}</div>
          </div>
          ${scriptTag(IDENT_TYPE_SCRIPT)}
          <p class="muted" style="margin:0;">External ID <code>${escapeHtml(user.external_id)}</code> &middot; Created ${ts(user.created_at)}</p>
        `)}

        <div class="two-col">
        ${cardSection(`
          <h2>Email addresses${mastered.has("emails") ? masteredNote : ""}</h2>
          <p class="muted">Every address on the account; people can sign in and recover with any of them. The primary is where invitations and reset links go - and what the <code>email</code> claim reports.</p>
          <div class="email-row muted" style="font-size:0.75rem; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; margin-bottom:4px;">
            <span>Address</span><span>Type</span><span>Primary</span><span></span>
          </div>
          <div id="email-rows">${(userEmails.length ? userEmails : [undefined]).map((e) => userEmailRowHtml(e, mastered.has("emails"))).join("")}</div>
          ${
            mastered.has("emails")
              ? ""
              : `<template id="email-row-template">${userEmailRowHtml()}</template>
          <button type="button" class="secondary" data-append-template="email-row-template" data-append-to="email-rows">+ Add address</button>
          <datalist id="email-type-options"><option value="work"></option><option value="home"></option><option value="other"></option></datalist>`
          }
        `)}
        ${cardSection(`
          <h2>Phone numbers${mastered.has("phones") ? masteredNote : ""}</h2>
          <p class="muted">+E.164 numbers that also resolve this account at sign-in. One per line.</p>
          <textarea name="phones" rows="4" placeholder="+15551234567" ${mastered.has("phones") ? "disabled" : ""}>${escapeHtml(userPhones.map((p) => p.phone).join("\n"))}</textarea>
        `)}
        </div>

        <div class="two-col">

        ${cardSection(`
          <div class="card-head">
            <h2>Attributes</h2>
            <div class="inline-field">
              <label for="schema_id">Schema</label>
              <select id="schema_id" name="schema_id" style="margin-bottom:0;" data-navigate="/admin/users/${id}?schema=" data-current="${schema?.id ?? ""}">
                ${schemaOptions}
              </select>
            </div>
          </div>
          ${
            previewing
              ? `<div class="notice-warn">Previewing <strong>${escapeHtml(schema!.name)}</strong> - currently <strong>${escapeHtml(currentSchemaName)}</strong>. Nothing changes until you save.
                  ${previewLost.length > 0 ? `<br/>Saving will <strong>clear</strong>: ${previewLost.map((n) => `<code>${escapeHtml(n)}</code>`).join(", ")}.` : "<br/>No attribute values will be lost."}
                  <a href="/admin/users/${id}">Cancel</a></div>`
              : ""
          }
          ${await userSchemaAttributesHtml(c, schemaAttrs, attrValues, id, mastered)}
        `)}

        ${cardSection(`
          <h2>Groups</h2>
          <h3>Assigned</h3>
          <p class="muted" style="margin-top:-4px;">Static groups this person is added to directly.</p>
          ${multiSelect(
            "group_ids",
            staticGroups.map((g) => ({ id: g.id, label: g.name })),
            new Set([...memberGroupIds].filter((gid) => staticGroups.some((g) => g.id === gid))),
            "Search groups..."
          )}
          <h3>Dynamic</h3>
          <p class="muted" style="margin-top:-4px;">Groups whose rules match this person's attributes. Membership follows the attributes - change them to change it.</p>
          ${
            dynamicGroups.length > 0
              ? `<div style="display:flex; flex-wrap:wrap; gap:6px;">${dynamicGroups
                  .map((g) => `<a class="pill" href="/admin/groups/${g.id}" title="${escapeHtml(parseRule(g.rule) ? ruleDescription(parseRule(g.rule)!) : "invalid rule")}">${escapeHtml(g.name)}</a>`)
                  .join("")}</div>`
              : '<p class="muted">None.</p>'
          }
        `)}
        </div>

        <div class="form-actions end" style="margin:0 0 18px;">
          ${
            isSelf
              ? ""
              : formButton("Delete", `/admin/users/${id}/delete`, {
                  variant: "danger",
                  confirm: confirmAttrs(`Deleting ${user.display_name} cannot be undone. Their sessions, tokens and group memberships are removed with them. To keep the account but stop sign-ins, switch it to Inactive instead.`, { title: "Delete this user?", action: "Delete user", danger: true }),
                })
          }
          ${cancelLink(`/admin/users/${id}`)}
          <button class="primary" type="submit">Save</button>
        </div>
      </form>

      ${cardSection(`
        <h2>Security</h2>
        <div class="sec-row">
          <div>
            <h3>Password</h3>
            <p class="muted">Set a new password, or leave it blank to generate one. Their current password stops working.</p>
          </div>
          <form method="POST" action="/admin/users/${id}/reset-password"
            ${confirmAttrs("Their current password stops working immediately. A generated password is shown to you once.", { title: "Reset this user's password?", action: "Reset password" })}>
            <input type="password" name="password" placeholder="Leave blank to generate" autocomplete="new-password" style="width:220px; margin-bottom:0;" />
            <button class="secondary" type="submit">Reset password</button>
          </form>
        </div>
        ${
          emailOn
            ? `<div class="sec-row">
          <div>
            <h3>Email link</h3>
            <p class="muted">${user.status === "active" ? "Send a link that lets them choose a new password themselves." : "Send an invitation: they choose a password, and that activates the account."} Goes to ${escapeHtml(recipientFor(user))}.</p>
          </div>
          <form method="POST" action="/admin/users/${id}/${user.status === "active" ? "send-reset" : "invite"}">
            <button class="secondary" type="submit">${user.status === "active" ? "Send reset link" : "Send invitation"}</button>
          </form>
        </div>`
            : ""
        }
        <div class="sec-row">
          <div>
            <h3>Multi-factor authentication <span class="badge ${countedFactors.length ? "badge-active" : "badge-disabled"}">${countedFactors.length ? "Enrolled" : "Not enrolled"}</span></h3>
            <p class="muted">${(["totp", "passkey", "email_otp", "security_questions"] as const)
              .map((f) => `${f === "passkey" ? "Passkeys" : FACTOR_SHORT_LABELS[f]}: ${factors.includes(f) ? "enrolled" : "not enrolled"}${f === "security_questions" && userIsAdmin && factors.includes(f) ? " (does not count for an administrator)" : ""}`)
              .join(" &middot; ")}</p>
            <p class="muted">Resetting clears their authenticator, backup codes, email codes, security questions and remembered devices; they enrol again at next sign-in.</p>
          </div>
          <form method="POST" action="/admin/users/${id}/reset-mfa"
            ${confirmAttrs("Their authenticator, backup codes, email codes, security questions and remembered devices are removed. They will be asked to enrol again.", { title: "Reset MFA for this user?", action: "Reset MFA" })}>
            <button class="secondary" type="submit" ${anyMfa ? "" : "disabled"}>Reset MFA</button>
          </form>
        </div>
        <div class="sec-row">
          <div>
            <h3>Sessions</h3>
            <p class="muted">${sessions.length === 0 ? "No active sessions." : `${sessions.length} active session${sessions.length === 1 ? "" : "s"}.`}</p>
          </div>
          <form method="POST" action="/admin/users/${id}/sessions/revoke-all"
            ${confirmAttrs("Every active session for this user will be signed out immediately.", { title: "Sign this user out everywhere?", action: "Sign out everywhere" })}>
            <button class="secondary" type="submit" ${sessions.length > 0 ? "" : "disabled"}>Sign out everywhere</button>
          </form>
        </div>
        <div class="sec-row">
          <div>
            <h3>Risk ${watch ? '<span class="badge badge-disabled">On watchlist</span>' : '<span class="badge badge-active">Not flagged</span>'}${risk ? ` <span class="badge badge-pending">Cloudflare risk: ${escapeHtml(risk.level)}</span>` : ""}</h3>
            <p class="muted">${
              watch
                ? `${escapeHtml(watch.reason)} &middot; flagged ${ts(watch.flagged_at)} by ${escapeHtml(watch.source)}${watch.expires_at ? ` &middot; clears ${ts(watch.expires_at)}` : " until cleared"}.`
                : risk
                  ? `Cloudflare Zero Trust reports <strong>${escapeHtml(risk.level)}</strong>${risk.events.length ? ` (${risk.events.length} recent event${risk.events.length === 1 ? "" : "s"})` : ""}. Flagging puts them on the risk watchlist, syncable to Cloudflare One or SCIM.`
                  : `The risk watchlist tightens inspection for flagged people via Cloudflare One or SCIM group sync. ${cfOneReady(cfConfig) ? "" : "Connect Cloudflare One under Integrations to also show their Zero Trust risk score here."}`
            }</p>
          </div>
          ${
            watch
              ? `<form method="POST" action="/admin/users/${id}/unwatch"><button class="secondary" type="submit">Clear flag</button></form>`
              : `<form method="POST" action="/admin/users/${id}/watch"><input type="hidden" name="reason" value="Flagged from the user page" /><button class="secondary" type="submit">Flag on watchlist</button></form>`
          }
        </div>
      `)}

      <div class="two-col">
      ${cardSection(`
        <h2>Active sessions</h2>
        ${
          sessions.length > 0
            ? `<table>
                <thead><tr><th>Started</th><th>Last active</th><th>IP</th></tr></thead>
                <tbody>
                  ${sessions
                    .map(
                      (s) =>
                        `<tr><td>${ts(s.created_at)}</td><td>${ts(s.last_seen_at)}</td><td class="muted">${escapeHtml(s.ip ?? "unknown")}</td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
            : '<p class="muted">No active sessions.</p>'
        }
      `)}
      ${cardSection(`
        <h2>Connected apps</h2>
        ${
          apps.length > 0
            ? `<table>
                <thead><tr><th>App</th><th></th></tr></thead>
                <tbody>
                  ${apps
                    .map(
                      (app) =>
                        `<tr><td>${escapeHtml(app.name)}</td><td><div class="row-actions"><form method="POST" action="/admin/users/${id}/apps/${app.id}/revoke" ${confirmAttrs(`${user.display_name} will need to sign in to ${app.name} again.`, { title: `Revoke access to ${app.name}?`, action: "Revoke access", danger: true })}>${iconButton("logOut", "Revoke access", { danger: true })}</form></div></td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
            : '<p class="muted">No connected apps.</p>'
        }
      `)}
      </div>

      ${cardSection(`
        <details>
          <summary><h2 style="display:inline; margin:0;">Raw record</h2></summary>
          <p class="muted" style="margin-top:10px;">The user object exactly as the API and provisioning syncs see it - credential material (hashes, salts, TOTP secrets) excluded.</p>
          ${codeBlock(rawUserJson, { style: "max-height:420px; overflow:auto;" })}
        </details>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Users", href: "/admin/users" }, { label: user.display_name }],
      undefined,
      accountStatusSwitch(id, user.status, isSelf)
    )
  );
});

admin.post("/admin/users/:id/status", async (c) => {
  const id = Number(c.req.param("id"));
  const status = String((await c.req.parseBody()).status ?? "") === "active" ? "active" : "disabled";
  await setUserStatus(consoleCtx(c), id, status);
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

/** One editable address row (parallel email_addr/email_type/email_primary arrays); blank addresses are dropped on read. Read-only when emails are mastered. */
function userEmailRowHtml(e?: { email: string; type: string; is_primary: number }, readonly = false): string {
  if (readonly) {
    return `<div class="email-row">
      <input type="email" value="${escapeHtml(e?.email ?? "")}" disabled />
      <input type="text" value="${escapeHtml(e?.type ?? "")}" disabled />
      <label><input type="checkbox" ${e?.is_primary ? "checked" : ""} disabled style="width:auto; margin:0;" /> Primary</label>
      <span></span>
    </div>`;
  }
  return `<div class="email-row">
    <input type="email" name="email_addr" value="${escapeHtml(e?.email ?? "")}" placeholder="name@example.com" />
    <input type="text" name="email_type" value="${escapeHtml(e?.type ?? "work")}" placeholder="type" list="email-type-options" />
    <label><input type="hidden" name="email_primary" value="${e?.is_primary ? 1 : 0}" /><input type="checkbox" ${e?.is_primary ? "checked" : ""} data-mirror-prev style="width:auto; margin:0;" /> Primary</label>
    ${iconButton("trash", "Remove address", { danger: true, type: "button", attrs: 'data-remove-closest=".email-row"' })}
  </div>`;
}

admin.post("/admin/users/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  const postedGroupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const addrs = list(body.email_addr), types = list(body.email_type), primaries = list(body.email_primary);
  const emails = addrs.map((value, i) => ({ value, type: types[i] ?? "work", primary: primaries[i] === "1" })).filter((e) => e.value.trim() !== "");
  // Disabled (mastered) inputs post nothing; fall back to what's stored so a
  // mastered sign-in name survives a save untouched.
  const cur = await c.env.DB.prepare("SELECT upn, username FROM users WHERE id = ?").bind(id).first<{ upn: string; username: string }>();
  const curParts = cur ? splitUpn(cur.upn) : { username: "", domain: "" };
  const curKind = cur ? (parseIdentifier(cur.upn)?.kind ?? "upn") : "upn";
  const phones = body.phones !== undefined ? String(body.phones).split(/\r?\n/).map((v) => ({ value: v.trim() })).filter((p) => p.value) : undefined;
  // The form carries every value of the chosen schema (same-named values were
  // carried into it), so this is a full replace - PATCH /api/v1/users merges
  // into the current values and calls the same function.
  await updateUserProfile(consoleCtx(c), id, {
    username: body.username !== undefined ? String(body.username) : curParts.username,
    domain: body.domain !== undefined ? String(body.domain) : curParts.domain,
    identifier: postedIdentifier({ ...body, username: body.username ?? curParts.username, domain: body.domain ?? curParts.domain }, curKind),
    givenName: String(body.given_name ?? ""),
    familyName: String(body.family_name ?? ""),
    schemaId: Number(body.schema_id) || undefined,
    attributes: Object.fromEntries(Object.entries(body).filter(([k]) => k.startsWith("attr_")).map(([k, v]) => [k.slice(5), String(v ?? "")])),
    groupIds: postedGroupIds,
    emails,
    phones,
  });
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

/** Invitation (activates on acceptance) or reset link, by email. Back to the user page with what happened. */
async function emailUserLink(c: Context<{ Bindings: Env }>, kind: "invite" | "reset") {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const result = await sendUserLink(consoleCtx(c), user, kind);
  return c.redirect(`/admin/users/${id}?${result.ok ? `sent=${kind}` : `send_error=${encodeURIComponent(result.error)}`}`, 302);
}

admin.post("/admin/users/:id/invite", (c) => emailUserLink(c, "invite"));
admin.post("/admin/users/:id/send-reset", (c) => emailUserLink(c, "reset"));

admin.post("/admin/users/:id/reset-mfa", async (c) => {
  const id = Number(c.req.param("id"));
  await resetUserMfa(consoleCtx(c), id);
  return c.redirect(`/admin/users/${id}`, 302);
});


/** Form that sets a password of the admin's choosing - posts to reset-password, which enforces the policy. */
function choosePasswordForm(userId: number, policy: Awaited<ReturnType<typeof getPasswordPolicy>>, error?: string): string {
  return `
    <form method="POST" action="/admin/users/${userId}/reset-password">
      <input type="hidden" name="require_chosen" value="1" />
      ${error ? `<p class="error" style="margin-top:0;">${escapeHtml(error)}</p>` : ""}
      <label for="new_password">New password</label>
      <input type="password" id="new_password" name="password" required minlength="${policy.minLength}" autocomplete="new-password" style="max-width:340px;" />
      <p class="muted" style="margin-top:-8px;">${escapeHtml(passwordPolicySummary(policy))}</p>
      <button class="primary" type="submit">Set password</button>
    </form>`;
}

admin.post("/admin/users/:id/reset-password", async (c) => {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);

  const body = await c.req.parseBody();
  const chosen = String(body.password ?? "");
  const policy = await getPasswordPolicy(c.env);
  const crumbs = [{ label: "Admin", href: "/admin" }, { label: "Users", href: "/admin/users" }, { label: user.display_name, href: `/admin/users/${id}` }, { label: "Set password" }];

  // Blank means "generate one" - except from a form that exists to set a chosen password.
  const formError = (message: string) =>
    c.html(layout(c, "Set password", cardSection(`<h2>Set a password for ${escapeHtml(user.display_name)}</h2>${choosePasswordForm(id, policy, message)}`), crumbs), 400);
  const policyError = chosen ? validatePassword(chosen, policy) : body.require_chosen ? "Enter a password." : null;
  if (policyError) return formError(policyError);

  // A reset is a compromise response too: every existing session ends
  // (services/users.ts, shared with POST /api/v1/users/{username}/reset-password).
  // The service also runs the breached-password check on a chosen password.
  let password: string;
  try {
    ({ password } = await resetUserPassword(consoleCtx(c), id, chosen));
  } catch (e) {
    if (e instanceof ServiceError && e.status === 400) return formError(e.message);
    throw e;
  }

  return c.html(
    layout(
      c,
      chosen ? "Password set" : "Password reset",
      cardSection(`
        ${
          // A password the admin typed is not echoed back - they already know it.
          chosen
            ? `<p class="success">The password for ${escapeHtml(user.display_name)} (${escapeHtml(user.upn)}) has been set. Share it with them securely.</p>`
            : secretBlock(`New temporary password for ${user.display_name}`, password)
        }
        <a href="/admin/users/${id}"><button class="primary" type="button">Continue</button></a>
      `),
      crumbs
    )
  );
});

admin.post("/admin/users/:id/watch", async (c) => {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  // The same guard the CF One page's watch form runs (the API twin too).
  await assertMayTouchUser(consoleCtx(c), id);
  const reason = String((await c.req.parseBody()).reason ?? "").trim().slice(0, 300) || "Flagged manually";
  await flagUser(c.env, id, reason, "manual");
  await audit(consoleCtx(c), "cfone.user_flagged", user.upn, { reason });
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

admin.post("/admin/users/:id/unwatch", async (c) => {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(id).first<{ upn: string }>();
  if (!user) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  await assertMayTouchUser(consoleCtx(c), id);
  await unflagUser(c.env, id);
  await audit(consoleCtx(c), "cfone.user_unflagged", user.upn);
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

admin.post("/admin/users/:id/sessions/revoke-all", async (c) => {
  const id = Number(c.req.param("id"));
  await revokeUserSessions(consoleCtx(c), id);
  return c.redirect(`/admin/users/${id}`, 302);
});

admin.post("/admin/users/:id/apps/:clientDbId/revoke", async (c) => {
  const id = Number(c.req.param("id"));
  await revokeUserAppAccess(consoleCtx(c), id, Number(c.req.param("clientDbId")));
  return c.redirect(`/admin/users/${id}`, 302);
});

admin.post("/admin/users/:id/delete", async (c) => {
  await deleteUser(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/users", 302);
});

// ---------- Groups ----------

/**
 * A dynamic group's page lists at most this many of its computed members: the
 * 10,000-user load test put 8,153 people in "All Employees" and a 3 MB page.
 */
const MEMBER_PREVIEW_LIMIT = 200;

/** Identity attributes every user has regardless of schema - offered under every schema in the rule builder. */
const IDENTITY_RULE_ATTRIBUTES: { name: string; label: string }[] = [
  { name: "username", label: "Username" },
  { name: "given_name", label: "First name" },
  { name: "family_name", label: "Last name" },
  { name: "display_name", label: "Display name" },
  { name: "status", label: "Account status" },
];

interface RuleBuilderData {
  schemas: { name: string; attributes: { name: string; label: string }[] }[];
  /** Distinct values already in the directory per attribute - offered as suggestions so "full_time" isn't typed as "Full-time". */
  values: Record<string, string[]>;
  defaultSchema: string;
}

async function ruleBuilderData(env: Env): Promise<RuleBuilderData> {
  const schemas: RuleBuilderData["schemas"] = [];
  for (const s of await listSchemas(env, "user")) {
    // References hold another user's external_id - not something a person can type into a rule.
    const attrs = (await getSchemaAttributes(env, s.id)).filter((a) => a.type !== "reference").map((a) => ({ name: a.name, label: a.label }));
    const seen = new Set(attrs.map((a) => a.name));
    schemas.push({ name: s.name, attributes: [...IDENTITY_RULE_ATTRIBUTES.filter((a) => !seen.has(a.name)), ...attrs] });
  }

  const names = new Set(schemas.flatMap((s) => s.attributes.map((a) => a.name)));
  // Value suggestions only: a recent sample is plenty, and keeps the group
  // page from reading the whole directory.
  const { results: users } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC LIMIT 2000").all<UserRow>();
  const values: Record<string, string[]> = {};
  for (const name of names) {
    const distinct = new Set<string>();
    for (const u of users) {
      const v = ruleFields(u, parseCustomAttributes(u.custom_attributes))[name];
      if (v) distinct.add(v);
      if (distinct.size >= 50) break;
    }
    values[name] = [...distinct].sort();
  }

  const richest = [...schemas].sort((a, b) => b.attributes.length - a.attributes.length)[0];
  return { schemas, values, defaultSchema: richest?.name ?? "" };
}

function ruleRowHtml(data: RuleBuilderData, cond?: RuleTerm): string {
  const isExpr = cond !== undefined && "expr" in cond;
  const schemaName = !isExpr ? cond?.schema ?? data.schemas.find((s) => s.attributes.some((a) => a.name === cond?.field))?.name ?? data.defaultSchema : data.defaultSchema;
  const attrs = data.schemas.find((s) => s.name === schemaName)?.attributes ?? [];
  const field = !isExpr ? cond?.field ?? "" : "";
  return `<div class="rule-row${isExpr ? " rule-expr" : ""}">
    <div class="rule-schema">${searchSelect("rule_schema", data.schemas.map((s) => ({ value: s.name, label: s.name })), schemaName, "Schema")}</div>
    <div class="rule-attr">${searchSelect("rule_field", attrs.map((a) => ({ value: a.name, label: `${a.label} (${a.name})` })), field, "Attribute")}</div>
    <select name="rule_op">
      <option value="eq" ${!isExpr && cond?.op !== "ne" ? "selected" : ""}>=</option>
      <option value="ne" ${!isExpr && cond?.op === "ne" ? "selected" : ""}>!=</option>
      <option value="expr" ${isExpr ? "selected" : ""}>expr</option>
    </select>
    <input type="text" name="rule_value" class="rule-value" value="${escapeHtml(isExpr ? cond.expr : cond?.value ?? "")}" placeholder='Value, or expression: startsWith(department, "eng")' ${field ? `list="rv-${escapeHtml(field)}"` : ""} autocomplete="off" />
    ${iconButton("trash", "Remove condition", { danger: true, type: "button", attrs: 'data-remove-closest=".rule-row"' })}
  </div>`;
}

const GROUP_FORM_SCRIPT = `
(function () {
  var dataEl = document.getElementById("rule-data");
  if (!dataEl) return;
  var data = JSON.parse(dataEl.textContent);
  function attrsFor(name) { for (var i = 0; i < data.schemas.length; i++) if (data.schemas[i].name === name) return data.schemas[i].attributes; return []; }
  document.addEventListener("change", function (e) {
    if (e.target.name === "membership") {
      var dyn = e.target.value === "dynamic";
      document.getElementById("dynamic-section").style.display = dyn ? "" : "none";
      document.getElementById("static-section").style.display = dyn ? "none" : "";
      return;
    }
    var row = e.target.closest(".rule-row");
    if (!row) return;
    var valueInput = row.querySelector("input[name=rule_value]");
    if (e.target.name === "rule_schema") {
      var ss = row.querySelector(".rule-attr .searchselect");
      var menu = ss.querySelector(".ss-menu");
      menu.querySelectorAll(".ss-item").forEach(function (i) { i.remove(); });
      attrsFor(e.target.value).forEach(function (a) {
        var b = document.createElement("button");
        b.type = "button"; b.className = "ss-item";
        b.dataset.value = a.name; b.dataset.label = a.label + " (" + a.name + ")";
        b.textContent = b.dataset.label;
        menu.appendChild(b);
      });
      ss.querySelector("input[type=hidden]").value = "";
      ss.querySelector(".ss-label").textContent = "Attribute";
      valueInput.removeAttribute("list");
    }
    if (e.target.name === "rule_field") valueInput.setAttribute("list", "rv-" + e.target.value);
    if (e.target.name === "rule_op") row.classList.toggle("rule-expr", e.target.value === "expr");
  });
  document.querySelectorAll(".rule-row select[name=rule_op]").forEach(function (sel) {
    sel.closest(".rule-row").classList.toggle("rule-expr", sel.value === "expr");
  });
})();
`;

/** The new/edit group form: identity, membership type, rule builder or static members, group-schema attributes. */
async function groupFormHtml(c: { env: Env }, group: GroupRow | null, requestedSchemaId: number): Promise<string> {
  const rule = group ? parseRule(group.rule) : null;
  const isDynamic = rule !== null;
  const isSuperAdmins = group?.name === SUPER_ADMINS_GROUP;
  const data = await ruleBuilderData(c.env);

  const groupSchemas = await listSchemas(c.env, "group");
  const schema =
    (requestedSchemaId ? await getSchema(c.env, requestedSchemaId) : null) ??
    (group?.schema_id ? await getSchema(c.env, group.schema_id) : null) ??
    (await getSchema(c.env, Number(await defaultSchemaId(c.env, "group"))));
  const schemaAttrs = schema ? await getSchemaAttributes(c.env, schema.id) : [];
  const groupCustom = parseCustomAttributes(group?.custom_attributes);
  const reloadBase = group ? `/admin/groups/${group.id}` : "/admin/groups/new";


  return `
    <form method="POST" action="${group ? `/admin/groups/${group.id}` : "/admin/groups"}">
      ${cardSection(`
        <div class="field-row">
          <div>
            <label for="name">Name</label>
            <input type="text" id="name" name="name" value="${escapeHtml(group?.name ?? "")}" required />
          </div>
          <div>
            <label for="description">Description</label>
            <input type="text" id="description" name="description" value="${escapeHtml(group?.description ?? "")}" />
          </div>
        </div>
        ${
          schemaAttrs.length > 0 || groupSchemas.length > 1
            ? `<div class="card-head">
                <h3>Attributes</h3>
                <div class="inline-field">
                  <label for="schema_id">Schema</label>
                  <select id="schema_id" name="schema_id" style="margin-bottom:0;" data-navigate="${reloadBase}?schema=">
                    ${groupSchemas.map((s) => `<option value="${s.id}" ${schema?.id === s.id ? "selected" : ""}>${escapeHtml(s.name)}</option>`).join("")}
                  </select>
                </div>
              </div>
              <div class="form-grid">${schemaAttrs.map((a) => `<div>${attributeInput(a, groupCustom[a.name] ?? "")}</div>`).join("")}</div>`
            : `<input type="hidden" name="schema_id" value="${schema?.id ?? ""}" />`
        }
      `)}

      ${cardSection(`
        <h2>Membership</h2>
        ${
          isSuperAdmins
            ? `<input type="hidden" name="membership" value="static" /><p class="muted">Super Admins controls access to this console, so its membership is always assigned by hand.</p>`
            : !group
              ? `<div class="row" style="justify-content:flex-start; gap:20px; margin-bottom:14px;">
                <label style="font-weight:500; display:flex; align-items:center; gap:6px; margin:0;"><input type="radio" name="membership" value="static" checked style="width:auto; margin:0;" /> Static - members are assigned</label>
                <label style="font-weight:500; display:flex; align-items:center; gap:6px; margin:0;"><input type="radio" name="membership" value="dynamic" style="width:auto; margin:0;" /> Dynamic - members match rules</label>
              </div>
              <p class="muted" style="margin-top:-6px;">The type is chosen once. A dynamic group can later be frozen into a static one; a static group cannot become dynamic (create a new group instead, so assigned members are never silently dropped).</p>`
              : isDynamic
                ? `<input type="hidden" name="membership" value="dynamic" />
                   <p class="muted" style="margin-top:0;"><strong>Dynamic</strong> - members match rules.</p>`
                : `<input type="hidden" name="membership" value="static" /><p class="muted" style="margin-top:0;"><strong>Static</strong> - members are assigned.</p>`
        }

        <div id="dynamic-section" style="${isDynamic ? "" : "display:none;"}">
          <p class="muted" style="margin-top:0;">People who match <strong>every</strong> condition are members. Membership updates as their attributes change.</p>
          <div id="rule-rows">
            ${(rule?.all.length ? rule.all : [undefined]).map((cond) => ruleRowHtml(data, cond)).join("")}
          </div>
          <button type="button" class="secondary" data-append-template="rule-row-template" data-append-to="rule-rows">+ Add condition</button>
          <template id="rule-row-template">${ruleRowHtml(data)}</template>
          ${Object.entries(data.values)
            .map(([name, vals]) => `<datalist id="rv-${escapeHtml(name)}">${vals.map((v) => `<option value="${escapeHtml(v)}"></option>`).join("")}</datalist>`)
            .join("")}
          <script type="application/json" id="rule-data">${JSON.stringify(data).replace(/</g, "\\u003c")}</script>
        </div>

        <div id="static-section" style="${isDynamic ? "display:none;" : ""}">
          ${
            group
              ? group.system
                ? ""
                : `<label>Add members</label>
                 ${remoteMultiSelect("add_user_ids", `/admin/users/lookup?not_in_group=${group.id}`, [], "Search people to add...")}
                 <p class="muted" style="margin-top:-8px;">Current members are listed below, where they can be removed.</p>`
              : remoteMultiSelect("user_ids", "/admin/users/lookup", [], "Search people...")
          }
          ${group?.system ? "" : `<label style="display:flex; align-items:flex-start; gap:8px; font-weight:500; margin-top:14px;">
            <input type="checkbox" name="requestable" value="1" ${group?.requestable ? "checked" : ""} style="width:auto; margin:3px 0 0;" />
            <span>People can request membership<br/><span class="muted" style="font-weight:400;">The group shows up under My account &rarr; Access requests, and an admin approves or denies each ask.</span></span>
          </label>`}
        </div>

        ${group?.system ? "" : `
        <label style="display:flex; align-items:flex-start; gap:8px; font-weight:500; margin-top:14px;">
          <input type="checkbox" name="cf_list_sync" value="1" ${group?.cf_list_sync ? "checked" : ""} style="width:auto; margin:3px 0 0;" />
          <span>Sync member emails to a Cloudflare One list<br/><span class="muted" style="font-weight:400;">Kept in step by the scheduled sync while the Cloudflare One connection under Integrations is configured; usable in Gateway and Access policies.</span></span>
        </label>`}
      `)}

      <div class="form-actions end" style="margin-bottom:18px;">
        ${
          group && isDynamic
            ? `<button class="secondary" type="submit" formaction="/admin/groups/${group.id}/freeze" formnovalidate
                ${confirmAttrs("The rule is removed and today's matching members become assigned members. Membership stops following attributes. This cannot be turned back into a dynamic group.", { title: "Convert to a static group?", action: "Convert to static" })}>Convert to static</button>`
            : ""
        }
        ${
          group
            ? `<button class="danger" type="submit" formaction="/admin/groups/${group.id}/delete" formnovalidate
                ${confirmAttrs(`Members lose this group, and anything mapping to it - SCIM pushes, Access policies - stops matching.`, { title: `Delete the group "${group.name}"?`, action: "Delete group", danger: true })}>Delete group</button>`
            : ""
        }
        ${cancelLink("/admin/groups")}
        <button class="primary" type="submit">${group ? "Save" : "Create group"}</button>
      </div>
    </form>
    ${scriptTag(GROUP_FORM_SCRIPT)}
  `;
}

/** Reads the group form: name, description, schema attributes, and either a rule or explicit members (never both). */
async function readGroupForm(c: { env: Env; req: { parseBody: (o: { all: true }) => Promise<Record<string, unknown>> } }, existingName: string | null) {
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const name = String(body.name ?? "").trim();
  const description = String(body.description ?? "").trim();
  if (!name) throw new Error("A group name is required.");

  const superAdmins = existingName === SUPER_ADMINS_GROUP || name === SUPER_ADMINS_GROUP;
  const dynamic = !superAdmins && String(body.membership ?? "static") === "dynamic";
  const rule = dynamic ? ruleFromForm(list(body.rule_schema), list(body.rule_field), list(body.rule_op), list(body.rule_value)) : "";
  if (dynamic && !rule) throw new Error("A dynamic group needs at least one condition.");
  // The reverse of the schema-side check: a rule on a field users can set
  // themselves would let anyone choose their own groups (shared with the API).
  if (dynamic) await assertRuleAllowed(c.env, rule);
  // A new group posts its full member list; an existing static group posts only
  // additions (current members are removed one by one from the members panel).
  const userIds = dynamic ? [] : list(body.user_ids).map(Number).filter(Boolean);
  const addUserIds = dynamic ? [] : list(body.add_user_ids).map(Number).filter(Boolean);

  const schemaId = Number(body.schema_id) || (await defaultSchemaId(c.env, "group"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(c.env, schemaId) : [];
  // Conform: only the schema's attributes are kept.
  const custom = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(body[`attr_${a.name}`] ?? "").trim()]).filter(([, v]) => v));
  const requestable = !dynamic && String(body.requestable ?? "") === "1";
  const cfListSync = String(body.cf_list_sync ?? "") === "1";
  return { name, description, rule, userIds, addUserIds, schemaId, custom, requestable, cfListSync };
}

admin.get("/admin/groups", async (c) => {
  const search = c.req.query("search") ?? "";
  const typeFilter = c.req.query("type") ?? "";
  const rolesOnly = c.req.query("roles") === "1";
  const pageSize = [20, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 20;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const like = `%${search}%`;
  const roleMap = await groupRolesMap(c.env);

  const conditions = ["(name LIKE ? OR description LIKE ?)"];
  const params: (string | number)[] = [like, like];
  if (typeFilter === "dynamic") conditions.push("rule != ''");
  if (typeFilter === "static") conditions.push("rule = ''");
  if (rolesOnly) {
    const ids = [...roleMap.keys()];
    conditions.push(ids.length ? `id IN (${ids.map(() => "?").join(",")})` : "0");
    params.push(...ids);
  }
  const where = `WHERE ${conditions.join(" AND ")}`;

  const batchResults = await c.env.DB.batch([
    c.env.DB.prepare(`SELECT COUNT(*) as n FROM groups ${where}`).bind(...params),
    c.env.DB.prepare(
      `SELECT g.*, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
       FROM groups g ${where} ORDER BY g.name LIMIT ? OFFSET ?`
    ).bind(...params, pageSize, (page - 1) * pageSize),
  ]);
  const total = Number((batchResults[0]!.results[0] as { n: number } | undefined)?.n ?? 0);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const groups = batchResults[1]!.results as (GroupRow & { member_count: number })[];

  // Dynamic counts come from the rule, evaluated against one load of the directory.
  const { results: allUsers } = groups.some((g) => parseRule(g.rule))
    ? await c.env.DB.prepare("SELECT * FROM users").all<UserRow>()
    : { results: [] as UserRow[] };
  const countFor = (g: GroupRow & { member_count: number }) => {
    const rule = parseRule(g.rule);
    return rule ? allUsers.filter((u) => userMatchesRule(u, rule)).length : g.member_count;
  };

  return c.html(
    layout(
      c,
      `Groups (${total.toLocaleString("en")})`,
      `
      ${c.req.query("notice") ? successBanner(c.req.query("notice")!) : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <form method="GET" class="list-toolbar">
          <div class="list-toolbar-filters">
            <input type="text" name="search" placeholder="Search groups" value="${escapeHtml(search)}" />
            <select name="type" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
              ${[["", "All types"], ["static", "Static"], ["dynamic", "Dynamic"]].map(([v, l]) => `<option value="${v}" ${v === typeFilter ? "selected" : ""}>${l}</option>`).join("")}
            </select>
            <label class="switch" style="white-space:nowrap;" title="Only groups that grant an administrator role"><input type="checkbox" name="roles" value="1" ${rolesOnly ? "checked" : ""} data-autosubmit /><span class="track"></span><span>With roles</span></label>
            <input type="hidden" name="page" value="1" />
            ${pageSizeSelect(pageSize)}
          </div>
          <div class="list-toolbar-actions">
            <a href="/admin/groups/import"><button class="secondary" type="button">Import CSV</button></a>
            <a href="/admin/groups/new"><button class="primary" type="button">+ New group</button></a>
          </div>
        </form>
      `)}
      ${cardSection(`
        <div class="bulk-bar" id="bulk-bar" style="display:none;">
          <form method="POST" action="/admin/groups/bulk" class="bulk-bar-row">
            <div id="bulk-ids"></div>
            <span class="bulk-bar-count"><strong><span id="bulk-count">0</span></strong> selected</span>
            <select name="action" id="bulk-action" required style="margin:0; width:auto;">
              <option value="">Choose an action...</option>
              <option value="requestable_on">Allow membership requests</option>
              <option value="requestable_off">Stop membership requests</option>
              <option value="add_members">Add people to the selected groups</option>
            </select>
            <span id="bulk-people" style="display:none; flex:1; min-width:220px;">${remoteMultiSelect("user_ids", "/admin/users/lookup", [], "People to add...")}</span>
            <button class="secondary" type="submit" id="bulk-apply" disabled style="margin:0;">Apply</button>
            <a href="#" id="bulk-clear" class="cancel" style="margin-left:auto;">Clear</a>
          </form>
          <p class="muted" style="margin:6px 0 0; font-size:12px;">Selection survives paging and filtering. Only static groups can be selected.</p>
        </div>
        <table>
          <thead><tr><th style="width:28px;"><input type="checkbox" id="gsel-all" style="width:auto; margin:0;" title="Select all on this page" /></th><th>Name</th><th>Type</th><th>Role</th><th>Description</th><th>Members</th></tr></thead>
          <tbody>
            ${groups
              .map((g) => {
                const rule = parseRule(g.rule);
                const roles = roleMap.get(g.id) ?? [];
                return `<tr>
                  <td>${rule ? "" : `<input type="checkbox" data-gsel value="${g.id}" style="width:auto; margin:0;" />`}</td>
                  <td><a href="/admin/groups/${g.id}">${escapeHtml(g.name)}</a>${!rule && g.requestable ? ' <span class="pill" title="People can ask to join on My account">Requestable</span>' : ""}</td>
                  <td>${rule ? `<span class="badge badge-admin" title="${escapeHtml(ruleDescription(rule))}">Dynamic</span>` : '<span class="pill">Static</span>'}</td>
                  <td>${roles.length ? roles.map((r) => `<span class="badge badge-admin" title="${escapeHtml(r.description)}">${escapeHtml(r.name)}</span>`).join(" ") : '<span class="muted">-</span>'}</td>
                  <td>${escapeHtml(g.description ?? "")}</td>
                  <td>${countFor(g)}</td>
                </tr>`;
              })
              .join("")}
          </tbody>
        </table>
        ${paginationControls("/admin/groups", page, totalPages, { search, type: typeFilter, roles: rolesOnly ? "1" : "", pageSize })}
      `)}
      ${scriptTag(GROUP_SELECT_SCRIPT)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Groups" }]
    )
  );
});

/**
 * Checkbox selection on the groups list, kept in sessionStorage so it
 * survives paging and search/filter reloads; the bulk bar's hidden inputs are
 * rebuilt from it on every load and change.
 */
const GROUP_SELECT_SCRIPT = `
(function () {
  var KEY = "fi-group-sel";
  var sel;
  try { sel = new Set(JSON.parse(sessionStorage.getItem(KEY) || "[]")); } catch (e) { sel = new Set(); }
  var bar = document.getElementById("bulk-bar");
  var idsEl = document.getElementById("bulk-ids");
  var countEl = document.getElementById("bulk-count");
  var allBox = document.getElementById("gsel-all");
  function pageIds() {
    return Array.prototype.slice.call(document.querySelectorAll("input[data-gsel]")).map(function (b) { return Number(b.value); });
  }
  function render() {
    try { sessionStorage.setItem(KEY, JSON.stringify(Array.from(sel))); } catch (e) {}
    document.querySelectorAll("input[data-gsel]").forEach(function (b) { b.checked = sel.has(Number(b.value)); });
    var ids = pageIds();
    if (allBox) allBox.checked = ids.length > 0 && ids.every(function (id) { return sel.has(id); });
    if (countEl) countEl.textContent = String(sel.size);
    if (idsEl) idsEl.replaceChildren.apply(idsEl, Array.from(sel).map(function (id) {
      var i = document.createElement("input"); i.type = "hidden"; i.name = "group_ids"; i.value = String(id); return i;
    }));
    if (bar) bar.style.display = sel.size ? "" : "none";
  }
  document.querySelectorAll("input[data-gsel]").forEach(function (b) {
    b.addEventListener("change", function () { if (b.checked) sel.add(Number(b.value)); else sel.delete(Number(b.value)); render(); });
  });
  if (allBox) allBox.addEventListener("change", function () {
    pageIds().forEach(function (id) { if (allBox.checked) sel.add(id); else sel.delete(id); });
    render();
  });
  var clear = document.getElementById("bulk-clear");
  if (clear) clear.addEventListener("click", function (e) { e.preventDefault(); sel.clear(); render(); });
  // The action picker reveals the people field only when it needs it.
  var action = document.getElementById("bulk-action");
  var people = document.getElementById("bulk-people");
  var apply = document.getElementById("bulk-apply");
  if (action) action.addEventListener("change", function () {
    if (people) people.style.display = action.value === "add_members" ? "" : "none";
    if (apply) apply.disabled = !action.value;
  });
  render();
})();
`;

admin.get("/admin/groups/new", async (c) => {
  return c.html(
    layout(c, "New group", await groupFormHtml(c, null, Number(c.req.query("schema"))), [
      { label: "Admin", href: "/admin" },
      { label: "Groups", href: "/admin/groups" },
      { label: "New group" },
    ])
  );
});

admin.post("/admin/groups", async (c) => {
  let form;
  try {
    form = await readGroupForm(c, null);
  } catch (e) {
    return consoleError(c, e instanceof Error ? e.message : "Invalid group.", 400);
  }
  const id = await createGroup(consoleCtx(c), form, form.userIds);
  return c.redirect(`/admin/groups/${id}?saved=1`, 302);
});

const MEMBERS_PER_PAGE = 30;

/**
 * The group's current members - assigned ones for a static group, rule matches
 * for a dynamic one - searchable by name or UPN and paged, so "is this person
 * in the group?" has an answer at any directory size.
 */
async function groupMembersPanel(env: Env, group: GroupRow, search: string, page: number): Promise<string> {
  const rule = parseRule(group.rule);
  const needle = search.trim().toLowerCase();
  const { total, rows } = await groupMembers(env, group, search, MEMBERS_PER_PAGE, (page - 1) * MEMBERS_PER_PAGE);
  const pages = Math.max(1, Math.ceil(total / MEMBERS_PER_PAGE));
  const base = `/admin/groups/${group.id}?${search ? `msearch=${encodeURIComponent(search)}&` : ""}mpage=`;
  return cardSection(`
    <div class="card-head">
      <h2>Members <span class="muted" style="font-weight:500;">(${total}${needle ? " matching" : ""})</span></h2>
      ${group.system ? '<p class="muted" style="margin:0;">A system group - its membership is maintained automatically (see Integrations &rarr; Cloudflare One).</p>' : ""}
      <form method="GET" action="/admin/groups/${group.id}" class="inline-field" style="margin:0;">
        <input type="search" name="msearch" value="${escapeHtml(search)}" placeholder="Find a person by name or UPN" style="margin:0; width:280px;" />
        <button class="secondary" type="submit">Search</button>
        ${search ? `<a href="/admin/groups/${group.id}">Clear</a>` : ""}
      </form>
    </div>
    ${
      rows.length
        ? `<table><thead><tr><th>Name</th><th>UPN</th><th>Status</th>${rule || group.system ? "" : "<th></th>"}</tr></thead><tbody>
            ${rows.map((u) => `<tr><td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a></td><td>${escapeHtml(u.upn)}</td><td><span class="badge badge-${escapeHtml(u.status)}">${escapeHtml(u.status)}</span></td>${
              rule || group.system ? "" : `<td style="text-align:right;"><form method="POST" action="/admin/groups/${group.id}/members/${u.id}/remove" style="margin:0;">${iconButton("trash", "Remove", { danger: true })}</form></td>`
            }</tr>`).join("")}
          </tbody></table>
          ${pages > 1 ? `<div class="row" style="justify-content:space-between; margin-top:12px;">
            <span class="muted">Page ${page} of ${pages}</span>
            <span>${page > 1 ? `<a href="${base}${page - 1}">&larr; Previous</a>` : ""}${page > 1 && page < pages ? " &middot; " : ""}${page < pages ? `<a href="${base}${page + 1}">Next &rarr;</a>` : ""}</span>
          </div>` : ""}`
        : `<p class="muted">${needle ? `Nobody in this group matches "${escapeHtml(search)}".` : rule ? "Nobody matches these rules yet." : "No members yet."}</p>`
    }
  `);
}

/**
 * The delegation card on a static group's page: named managers change the
 * membership and answer access requests from My account without groups:write.
 */
async function groupManagersPanel(env: Env, group: GroupRow): Promise<string> {
  const managers = await groupManagers(env, group.id);
  return cardSection(`
    <div class="card-head"><h2>Managers</h2></div>
    <p class="muted">Managers can add and remove members and answer membership requests from My account - no console permission needed. They still cannot change an admin role group.</p>
    ${
      managers.length
        ? `<table><thead><tr><th>Name</th><th>UPN</th><th></th></tr></thead><tbody>
            ${managers
              .map((u) => `<tr><td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a></td><td>${escapeHtml(u.upn)}</td><td style="text-align:right;"><form method="POST" action="/admin/groups/${group.id}/managers/${u.id}/remove" style="margin:0;">${iconButton("trash", "Remove", { danger: true })}</form></td></tr>`)
              .join("")}
          </tbody></table>`
        : '<p class="muted">No managers yet.</p>'
    }
    <form method="POST" action="/admin/groups/${group.id}/managers" style="margin-top:12px;">
      <label>Add managers</label>
      ${remoteMultiSelect("manager_ids", "/admin/users/lookup", [], "Search people...")}
      <div class="form-actions end"><button class="secondary" type="submit">Add managers</button></div>
    </form>
  `);
}

admin.post("/admin/groups/:id/members/:uid/remove", async (c) => {
  const id = Number(c.req.param("id"));
  await removeGroupMember(consoleCtx(c), id, Number(c.req.param("uid")));
  return c.redirect(`/admin/groups/${id}?saved=1`, 302);
});

admin.post("/admin/groups/:id/freeze", async (c) => {
  const id = Number(c.req.param("id"));
  await freezeGroup(consoleCtx(c), id);
  return c.redirect(`/admin/groups/${id}?saved=1`, 302);
});

admin.post("/admin/groups/:id/managers", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  const userIds = (Array.isArray(body.manager_ids) ? body.manager_ids.map(String) : body.manager_ids === undefined ? [] : [String(body.manager_ids)]).map(Number).filter(Boolean);
  try {
    if (!userIds.length) throw new Error("Pick at least one person to make a manager.");
    await addGroupManagers(consoleCtx(c), id, userIds);
    return c.redirect(`/admin/groups/${id}?saved=1`, 302);
  } catch (e) {
    return c.redirect(`/admin/groups/${id}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post("/admin/groups/:id/managers/:uid/remove", async (c) => {
  const id = Number(c.req.param("id"));
  try {
    await removeGroupManager(consoleCtx(c), id, Number(c.req.param("uid")));
    return c.redirect(`/admin/groups/${id}?saved=1`, 302);
  } catch (e) {
    return c.redirect(`/admin/groups/${id}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.get("/admin/groups/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();
  if (!group) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const rule = parseRule(group.rule);
  const msearch = (c.req.query("msearch") ?? "").slice(0, 100);
  const mpage = Math.min(100_000, Math.max(1, Math.floor(Number(c.req.query("mpage")) || 1)));

  return c.html(
    layout(
      c,
      group.name,
      `${c.req.query("saved") ? successBanner("Saved.") : ""}${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}${await groupFormHtml(c, group, Number(c.req.query("schema")))}${await groupMembersPanel(c.env, group, msearch, mpage)}${rule || group.system ? "" : await groupManagersPanel(c.env, group)}`,
      [{ label: "Admin", href: "/admin" }, { label: "Groups", href: "/admin/groups" }, { label: group.name }],
      undefined,
      rule ? `<span class="badge badge-admin" title="${escapeHtml(ruleDescription(rule))}">Dynamic</span>` : '<span class="pill">Static</span>'
    )
  );
});

admin.post("/admin/groups/bulk", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const groupIds = list(body.group_ids).map(Number).filter(Boolean);
  const action = String(body.action ?? "");
  try {
    if (action === "requestable_on" || action === "requestable_off") {
      const on = action === "requestable_on";
      const result = await bulkSetRequestable(consoleCtx(c), groupIds, on);
      const note = `Requests ${on ? "allowed" : "stopped"} on ${result.applied.length} group${result.applied.length === 1 ? "" : "s"}.`;
      return c.redirect(`/admin/groups?notice=${encodeURIComponent(result.skipped.length ? `${note} Skipped: ${result.skipped.join(", ")}.` : note)}`, 302);
    }
    if (action === "add_members") {
      const userIds = list(body.user_ids).map(Number).filter(Boolean);
      if (!userIds.length) throw new Error("Pick at least one person to add.");
      const result = await bulkAddMembers(consoleCtx(c), groupIds, userIds);
      const note = `Added ${result.added} membership${result.added === 1 ? "" : "s"} across ${result.applied.length} group${result.applied.length === 1 ? "" : "s"}.`;
      return c.redirect(`/admin/groups?notice=${encodeURIComponent(result.skipped.length ? `${note} Skipped: ${result.skipped.join(", ")}.` : note)}`, 302);
    }
    throw new Error("Pick an action first.");
  } catch (e) {
    return c.redirect(`/admin/groups?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post("/admin/groups/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const existing = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();
  if (!existing) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);

  let form;
  try {
    form = await readGroupForm(c, existing.name);
  } catch (e) {
    return consoleError(c, e instanceof Error ? e.message : "Invalid group.", 400);
  }
  // The form posts only additions to a static group (current members are
  // removed one by one from the members panel), so its set is the union.
  const { results: before } = await c.env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(id).all<{ user_id: number }>();
  const members = form.rule ? [] : [...new Set([...before.map((b) => b.user_id), ...form.userIds, ...form.addUserIds])];
  await updateGroup(consoleCtx(c), id, form, members);
  return c.redirect(`/admin/groups/${id}?saved=1`, 302);
});

admin.post("/admin/groups/:id/delete", async (c) => {
  await deleteGroup(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/groups", 302);
});

// ---------- Access requests & reviews ----------

const REQUEST_STATUS_LABELS: Record<string, string> = { pending: "Pending", approved: "Approved", denied: "Denied", cancelled: "Withdrawn" };
const requestBadge = (status: string) =>
  status === "pending"
    ? '<span class="badge badge-pending">Pending</span>'
    : status === "approved"
      ? '<span class="badge badge-active">Approved</span>'
      : `<span class="badge badge-disabled">${REQUEST_STATUS_LABELS[status] ?? escapeHtml(status)}</span>`;

const ACCESS_CRUMBS: Breadcrumb[] = [{ label: "Admin", href: "/admin" }, { label: "Access", href: "/admin/access" }];

admin.get("/admin/access", async (c) => {
  const statusFilter = c.req.query("status") ?? "pending";
  const search = (c.req.query("search") ?? "").slice(0, 100);
  const pageSize = [20, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 20;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const [{ total, rows: requests }, campaigns, pendingRow, roleGroups] = await Promise.all([
    listAccessRequests(c.env, { status: statusFilter === "all" ? undefined : statusFilter, search, limit: pageSize, offset: (page - 1) * pageSize }),
    listCampaigns(c.env),
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM access_requests WHERE status = 'pending'").first<{ n: number }>(),
    adminRoleGroupIds(c.env),
  ]);
  const pendingCount = pendingRow?.n ?? 0;
  const privileged = Boolean(c.get("isSuperAdmin"));
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return c.html(
    layout(
      c,
      "Access",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <div class="card-head">
          <h2>Requests${pendingCount ? ` <span class="badge badge-pending">${pendingCount}</span>` : ""}</h2>
        </div>
        <form method="GET" class="list-toolbar">
          <div class="list-toolbar-filters">
            <input type="text" name="search" placeholder="Search person, group or reason" value="${escapeHtml(search)}" />
            <select name="status" data-autosubmit style="margin-bottom:0; width:auto;">
              ${[["pending", "Pending"], ["all", "All"], ["approved", "Approved"], ["denied", "Denied"], ["cancelled", "Withdrawn"]]
                .map(([v, l]) => `<option value="${v}" ${v === statusFilter ? "selected" : ""}>${l}</option>`)
                .join("")}
            </select>
            <input type="hidden" name="page" value="1" />
            ${pageSizeSelect(pageSize)}
          </div>
        </form>
        <p class="muted">People ask for a group from My account when the group allows requests. Approving adds them like editing the group does.</p>
        ${
          requests.length === 0
            ? `<p class="muted">No ${search ? `requests matching "${escapeHtml(search)}"` : statusFilter === "pending" ? "requests waiting for a decision" : statusFilter === "all" ? "requests yet" : `${statusFilter} requests`}.</p>`
            : `<table>
                <thead><tr><th>Person</th><th>For</th><th>Reason</th><th>Asked</th><th>Status</th><th></th></tr></thead>
                <tbody>
                  ${requests
                    .map(
                      (r) => `<tr>
                        <td><a href="/admin/users/${r.user_id}">${avatar(r.user_id, r.display_name, "sm", { upn: r.upn })}${escapeHtml(r.upn)}</a><br/><span class="muted">${escapeHtml(r.display_name)}</span></td>
                        <td>${
                          r.target_type === "group"
                            ? `<a href="/admin/groups/${r.target_id}">${escapeHtml(r.target_name)}</a>${roleGroups.has(r.target_id) ? `<br/><span class="badge badge-pending">Admin access</span>` : ""}`
                            : r.target_type === "cfapp"
                            ? `<a href="/admin/integrations/cf-one">${escapeHtml(r.target_name)}</a><br/><span class="badge">Access app</span>${r.cf_granting_group_name ? ` <span class="muted" style="font-size:12px;">&rarr; ${escapeHtml(r.cf_granting_group_name)}</span>` : ""}${r.cf_granting_group_id != null && roleGroups.has(r.cf_granting_group_id) ? ` <span class="badge badge-pending">Admin access</span>` : ""}`
                            : `<a href="${r.target_type === "oidc_app" ? `/admin/clients/${r.target_id}` : `/admin/saml/${r.target_id}`}">${escapeHtml(r.target_name)}</a><br/><span class="badge">${r.target_type === "oidc_app" ? "OIDC" : "SAML"} app</span>`
                        }</td>
                        <td class="muted">${escapeHtml(r.reason || "—")}</td>
                        <td class="muted">${ts(r.created_at)}</td>
                        <td>${requestBadge(r.status)}${r.status !== "pending" && r.decided_at ? `<br/><span class="muted" style="font-size:12px;">${ts(r.decided_at)}${r.note ? ` · ${escapeHtml(r.note)}` : ""}</span>` : ""}</td>
                        <td style="white-space:nowrap;">
                          ${
                            r.status !== "pending"
                              ? ""
                              : r.user_id === c.get("user").id
                              ? `<span class="muted" style="font-size:12px;">Your request - another approver must decide it.</span>`
                              : ((r.target_type === "group" && roleGroups.has(r.target_id)) || (r.target_type === "cfapp" && r.cf_granting_group_id != null && roleGroups.has(r.cf_granting_group_id))) && !privileged
                              ? `<span class="muted" style="font-size:12px;">Needs a Super Admin</span>`
                              : `<form method="POST" action="/admin/access/requests/${r.id}" style="display:flex; gap:6px; align-items:center; margin:0;">
                                  <input type="text" name="note" placeholder="Note (optional)" style="width:130px; margin:0;" />
                                  <button class="secondary" type="submit" name="decision" value="approved" style="margin:0;">Approve</button>
                                  <button class="secondary" type="submit" name="decision" value="denied" style="margin:0;">Deny</button>
                                </form>`
                          }
                        </td>
                      </tr>`
                    )
                    .join("")}
                </tbody>
              </table>
              ${paginationControls("/admin/access", page, totalPages, { search, status: statusFilter, pageSize })}`
        }
      `)}
      ${cardSection(`
        <div class="card-head">
          <h2>Reviews</h2>
          <a href="/admin/access/reviews/new"><button class="primary" type="button">+ New review</button></a>
        </div>
        <p class="muted">A review certifies the assigned members of chosen groups: every membership is kept or revoked, one by one. Members a rule assigns aren't reviewable - change the rule instead.</p>
        ${
          campaigns.length === 0
            ? '<p class="muted">No reviews yet.</p>'
            : `<table>
                <thead><tr><th>Review</th><th>Groups</th><th>Progress</th><th>Status</th><th>Started</th></tr></thead>
                <tbody>
                  ${campaigns
                    .map(
                      (camp) => `<tr>
                        <td><a href="/admin/access/reviews/${camp.id}">${escapeHtml(camp.name)}</a></td>
                        <td class="muted">${JSON.parse(camp.group_ids).length}</td>
                        <td>${camp.items - camp.pending} / ${camp.items}</td>
                        <td><span class="badge ${camp.status === "open" ? "badge-pending" : "badge-disabled"}">${camp.status === "open" ? "Open" : "Closed"}</span></td>
                        <td class="muted">${ts(camp.created_at)}</td>
                      </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      `,
      ACCESS_CRUMBS
    )
  );
});

admin.get("/admin/access/reviews/new", async (c) => {
  return c.html(
    layout(
      c,
      "New review",
      `
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      <form method="POST" action="/admin/access/reviews">
        ${cardSection(`
          <p class="sub">A review snapshots the chosen groups' assigned members and asks an admin to keep or revoke each one.</p>
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required placeholder="Quarterly contractors review" />
          <label>Groups to review</label>
          ${remoteMultiSelect("group_ids", "/admin/groups/lookup?static=1", [], "Search static groups...")}
          <p class="muted" style="margin-top:-8px;">Only assigned memberships can be reviewed - a dynamic group's members follow its rule, so it's never offered here.</p>
        `)}
        <div class="form-actions end" style="margin-bottom:18px;">
          ${cancelLink("/admin/access")}
          <button class="primary" type="submit">Start review</button>
        </div>
      </form>
      `,
      [...ACCESS_CRUMBS, { label: "New review" }]
    )
  );
});

admin.get("/admin/access/reviews/:id", async (c) => {
  const campaign = await getCampaign(c.env, Number(c.req.param("id")));
  if (!campaign) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const items = await campaignItems(c.env, campaign.id);
  const pending = items.filter((i) => i.decision === "pending").length;
  const decisionBadge = (d: string) =>
    d === "pending" ? '<span class="badge badge-pending">Pending</span>' : d === "certify" ? '<span class="badge badge-active">Kept</span>' : '<span class="badge badge-disabled">Revoked</span>';
  return c.html(
    layout(
      c,
      campaign.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <div class="row between" style="margin:0 0 8px 0; align-items:flex-start;">
          <p class="muted" style="margin:0;">${items.length - pending} of ${items.length} memberships decided${pending ? `, ${pending} to go` : ""}.</p>
          <span class="badge ${campaign.status === "open" ? "badge-pending" : "badge-disabled"}">${campaign.status === "open" ? "Open" : "Closed"}</span>
        </div>
        ${
          campaign.status === "open"
            ? `<form method="POST" action="/admin/access/reviews/${campaign.id}/close" style="margin:0 0 6px 0;" ${confirmAttrs(
                `Closing ends the review: ${pending} membership${pending === 1 ? "" : "s"} still pending stay as they are and count as unreviewed.`,
                { title: `Close "${campaign.name}"?`, action: "Close review" }
              )}>
                <button class="secondary" type="submit">Close review</button>
              </form>`
            : ""
        }
        <table>
          <thead><tr><th>Person</th><th>Group</th><th>Decision</th><th></th></tr></thead>
          <tbody>
            ${items
              .map(
                (i) => `<tr>
                  <td><a href="/admin/users/${i.user_id}">${escapeHtml(i.upn)}</a><br/><span class="muted">${escapeHtml(i.display_name)}</span></td>
                  <td><a href="/admin/groups/${i.group_id}">${escapeHtml(i.group_name)}</a></td>
                  <td>${decisionBadge(i.decision)}${i.decided_at ? `<br/><span class="muted" style="font-size:12px;">${ts(i.decided_at)}</span>` : ""}</td>
                  <td style="white-space:nowrap;">
                    ${
                      i.decision === "pending" && campaign.status === "open"
                        ? `<form method="POST" action="/admin/access/reviews/${campaign.id}/items/${i.id}" style="display:flex; gap:6px; margin:0;">
                            <button class="secondary" type="submit" name="decision" value="certify" style="margin:0;">Keep</button>
                            <button class="danger" type="submit" name="decision" value="revoke" style="margin:0;" ${confirmAttrs(
                              `Removes ${i.upn} from "${i.group_name}" immediately.`,
                              { title: `Revoke ${i.display_name}'s membership?`, action: "Revoke", danger: true }
                            )}>Revoke</button>
                          </form>`
                        : ""
                    }
                  </td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      `)}
      `,
      [...ACCESS_CRUMBS, { label: campaign.name }]
    )
  );
});

admin.post("/admin/access/requests/:id", async (c) => {
  const body = await c.req.parseBody();
  const decision = String(body.decision ?? "") === "approved" ? "approved" : "denied";
  try {
    // Approving an app request writes the app's assignees, so it asks for the
    // app's own write permission rather than the groups one this page runs on.
    const req = await getAccessRequest(c.env, Number(c.req.param("id")));
    // cfapp grants a group membership like a group request does; only the two
    // protocol app kinds need their own write permission here.
    if (req && req.target_type !== "group" && req.target_type !== "cfapp") {
      const access = c.get("access");
      const perm = req.target_type === "oidc_app" ? "oidc:write" : "saml:write";
      if (!access?.isSuper && !grants(access?.perms ?? [], perm)) throw new ServiceError(403, `Deciding this request needs ${perm}.`);
    }
    await decideAccessRequest(consoleCtx(c), Number(c.req.param("id")), decision, String(body.note ?? ""));
  } catch (e) {
    return c.redirect(`/admin/access?status=pending&error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  return c.redirect("/admin/access?status=pending&saved=1", 302);
});

admin.post("/admin/access/reviews", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const ids = (Array.isArray(body.group_ids) ? body.group_ids : body.group_ids === undefined ? [] : [body.group_ids]).map(Number);
  try {
    const campaign = await createCampaign(consoleCtx(c), String(body.name ?? ""), ids);
    return c.redirect(`/admin/access/reviews/${campaign.id}?saved=1`, 302);
  } catch (e) {
    return c.redirect(`/admin/access/reviews/new?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post("/admin/access/reviews/:id/close", async (c) => {
  const id = Number(c.req.param("id"));
  try {
    await closeCampaign(consoleCtx(c), id);
  } catch (e) {
    return c.redirect(`/admin/access?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  return c.redirect(`/admin/access/reviews/${id}?saved=1`, 302);
});

admin.post("/admin/access/reviews/:id/items/:itemId", async (c) => {
  const id = Number(c.req.param("id"));
  const decision = String((await c.req.parseBody()).decision ?? "") === "revoke" ? "revoke" : "certify";
  try {
    await decideCertItem(consoleCtx(c), id, Number(c.req.param("itemId")), decision);
  } catch (e) {
    return c.redirect(`/admin/access/reviews/${id}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  return c.redirect(`/admin/access/reviews/${id}?saved=1`, 302);
});

/** Test / Sync buttons on the Integrations page - data-scim="test|sync". */
const SCIM_SCRIPT = `
document.addEventListener("click", async function (e) {
  const btn = e.target.closest("[data-scim]");
  if (!btn) return;
  const kind = btn.dataset.scim;
  const tq = btn.dataset.scimTarget ? "?target=" + encodeURIComponent(btn.dataset.scimTarget) : "";
  const status = document.getElementById("scim-status");
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = kind === "test" ? "Testing..." : "Syncing...";
  status.replaceChildren();
  const p = document.createElement("p");
  p.style.marginTop = "12px";
  try {
    if (kind === "test") {
      const data = await (await fetch("/admin/scim/test" + tq, { method: "POST" })).json();
      p.className = data.ok ? "success" : "error";
      p.textContent = data.message;
    } else {
      // A full sync runs in batches: keep asking until the server says it is complete,
      // writing a line to the sync log for every step.
      status.appendChild(p);
      p.className = "muted";
      const logEl = document.getElementById("scim-log");
      const stamp = () => new Date().toLocaleTimeString();
      const line = (text) => {
        if (logEl.dataset.live !== "1") { logEl.textContent = ""; logEl.dataset.live = "1"; }
        logEl.textContent += "[" + stamp() + "] " + text + "\\n";
        logEl.scrollTop = logEl.scrollHeight;
      };
      line("Full sync started.");
      let users = 0, userErrors = 0, first = true, data;
      do {
        const t0 = Date.now();
        const res = await fetch("/admin/scim/sync" + tq + (first ? (tq ? "&" : "?") + "restart=1" : ""), { method: "POST" });
        if (!res.ok) { line("Stopped: the server answered " + res.status + ". Press Sync all now to carry on from here."); throw new Error("HTTP " + res.status); }
        data = await res.json();
        first = false;
        if (data.busy) {
          line("Another sync is already running; following it...");
          p.textContent = "Another sync is in progress; following it...";
          await new Promise((r) => setTimeout(r, 2500));
          continue;
        }
        const secs = ((Date.now() - t0) / 1000).toFixed(1);
        if (data.phase === "users") {
          users += data.users; userErrors += data.userErrors;
          line("Users: pushed " + data.users + (data.userErrors ? " (" + data.userErrors + " failed)" : "") + " in " + secs + " s; " + users.toLocaleString() + " done, " + data.remainingUsers.toLocaleString() + " to go.");
          if (data.remainingUsers === 0) line("Users done. Pushing groups...");
        } else {
          line("Groups: pushed " + data.groups + (data.groupErrors ? " (" + data.groupErrors + " failed)" : "") + " in " + secs + " s.");
        }
        (data.errors || []).forEach((e) => line("  ! " + e.target + (e.status ? " (HTTP " + e.status + ")" : "") + ": " + e.error));
        p.textContent = data.complete ? "" : (data.phase === "users" && data.remainingUsers > 0 ? "Pushed " + users.toLocaleString() + " user(s), " + data.remainingUsers.toLocaleString() + " to go..." : "Pushing groups...");
      } while (!data.complete);
      line("Full sync complete: " + users.toLocaleString() + " user(s)" + (userErrors ? " (" + userErrors + " failed)" : "") + ", " + data.groups + " group(s)" + (data.groupErrors ? " (" + data.groupErrors + " failed)" : "") + ".");
      p.className = userErrors || data.groupErrors ? "error" : "success";
      p.textContent = "Pushed " + users.toLocaleString() + " user(s)" + (userErrors ? " (" + userErrors + " failed)" : "") + " and " + data.groups + " group(s)" + (data.groupErrors ? " (" + data.groupErrors + " failed)" : "") + ".";
    }
  } catch (err) {
    p.className = "error";
    p.textContent = "Request failed: " + err;
  } finally {
    status.appendChild(p);
    btn.disabled = false;
    btn.textContent = original;
  }
});
`;

// ---------- Applications: one list for OIDC clients and SAML apps ----------
//
// An application is anything people sign in to through this directory,
// whichever protocol it speaks. The unified list at /admin/apps shows OIDC
// clients and SAML service providers together, each row gated by its own
// area's read; the catalog alongside offers guided templates. The older
// per-protocol list pages under Integrations still work.

admin.get("/admin/apps", async (c) => {
  const access = c.get("access")!;
  const canOidc = access.isSuper || grants(access.perms, "oidc:read");
  const canSaml = access.isSuper || grants(access.perms, "saml:read");
  const search = (c.req.query("search") ?? "").slice(0, 100).trim().toLowerCase();
  const protocolFilter = ["oidc", "saml"].includes(c.req.query("protocol") ?? "") ? c.req.query("protocol")! : "";
  const accessFilter = ["everyone", "restricted"].includes(c.req.query("access") ?? "") ? c.req.query("access")! : "";
  const pageSize = [25, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 25;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const [clients, sps] = await Promise.all([
    canOidc
      ? c.env.DB.prepare("SELECT id, name, logo_uri, access_mode, assigned_groups, assigned_users, require_mfa, created_at FROM oauth_clients").all<Pick<OAuthClientRow, "id" | "name" | "logo_uri" | "access_mode" | "assigned_groups" | "assigned_users" | "require_mfa" | "created_at">>().then((r) => r.results)
      : Promise.resolve([]),
    canSaml
      ? c.env.DB.prepare("SELECT id, name, logo_uri, access_mode, assigned_groups, assigned_users, require_mfa, created_at FROM saml_service_providers").all<Pick<SamlServiceProviderRow, "id" | "name" | "logo_uri" | "access_mode" | "assigned_groups" | "assigned_users" | "require_mfa" | "created_at">>().then((r) => r.results)
      : Promise.resolve([]),
  ]);
  const all = [
    ...clients.map((cl) => ({ name: cl.name, logo: cl.logo_uri, protocol: "OIDC", accessMode: cl.access_mode, assignedGroups: cl.assigned_groups, assignedUsers: cl.assigned_users, requireMfa: cl.require_mfa === 1, createdAt: cl.created_at, href: `/admin/clients/${cl.id}` })),
    ...sps.map((sp) => ({ name: sp.name, logo: sp.logo_uri, protocol: "SAML", accessMode: sp.access_mode, assignedGroups: sp.assigned_groups, assignedUsers: sp.assigned_users, requireMfa: sp.require_mfa === 1, createdAt: sp.created_at, href: `/admin/saml/${sp.id}` })),
  ]
    .sort((a, b) => a.name.localeCompare(b.name))
    .filter((r) => !search || r.name.toLowerCase().includes(search))
    .filter((r) => !protocolFilter || r.protocol.toLowerCase() === protocolFilter)
    .filter((r) => !accessFilter || (accessFilter === "everyone" ? r.accessMode === "everyone" : r.accessMode !== "everyone"));
  const totalPages = Math.max(1, Math.ceil(all.length / pageSize));
  const rows = all.slice((page - 1) * pageSize, page * pageSize);
  const restriction = (r: (typeof all)[number]) => {
    if (r.accessMode === "everyone") return "Everyone";
    const users = parseAssignedUserIds(r.assignedUsers).length;
    const groups = parseAssignedGroupIds(r.assignedGroups).length;
    if (users + groups === 0) return "Nobody";
    return [users ? `${users} ${users === 1 ? "person" : "people"}` : "", groups ? `${groups} group${groups === 1 ? "" : "s"}` : ""].filter(Boolean).join(", ");
  };
  // External logo URLs need their exact origins in img-src for this response.
  const logos = [...new Set(rows.map((r) => r.logo).filter((u): u is string => Boolean(u)))];
  if (logos.length) c.header("X-FlareID-Img-Src", logos.join(" "));
  const headerActions = [
    canOidc || canSaml ? `<a href="/admin/apps/catalog"><button class="primary" type="button">Add from catalog</button></a>` : "",
    grants(access.perms, "oidc:write") ? `<a href="/admin/clients/new"><button class="secondary" type="button">New OIDC client</button></a>` : "",
    grants(access.perms, "saml:write") ? `<a href="/admin/saml/new"><button class="secondary" type="button">New SAML app</button></a>` : "",
  ].filter(Boolean);
  return c.html(
    layout(
      c,
      "Applications",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      <p class="muted" style="margin:-6px 0 16px; max-width:720px;">Every application people sign in to through this directory - OIDC clients and SAML service providers in one list. Restrict an app to people or groups and only they see it on their launchpad and may sign in.</p>
      ${cardSection(`
        <form method="GET">
          <div class="row between" style="align-items:flex-start; gap:12px; flex-wrap:wrap;">
            <div style="display:flex; gap:8px; flex-wrap:wrap; flex:1;">
              <input type="text" name="search" placeholder="Search name" value="${escapeHtml(search)}" style="max-width:260px; margin-bottom:0;" />
              <select name="protocol" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
                ${[["", "All protocols"], ["oidc", "OIDC"], ["saml", "SAML"]].map(([v, l]) => `<option value="${v}" ${v === protocolFilter ? "selected" : ""}>${l}</option>`).join("")}
              </select>
              <select name="access" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
                ${[["", "Any access"], ["restricted", "Restricted"], ["everyone", "Everyone"]].map(([v, l]) => `<option value="${v}" ${v === accessFilter ? "selected" : ""}>${l}</option>`).join("")}
              </select>
              <input type="hidden" name="page" value="1" />
              ${pageSizeSelect(pageSize, [25, 50, 100])}
            </div>
            ${headerActions.join("")}
          </div>
        </form>
      `)}
      ${cardSection(`
        ${
          rows.length === 0
            ? `<p class="muted">${all.length === 0 && !search && !protocolFilter && !accessFilter ? (canOidc || canSaml ? "No applications yet - add one from the catalog, or create a blank one." : "Your roles do not cover any applications.") : `No applications matching ${search ? `"${escapeHtml(search)}"` : "those filters"}.`}</p>`
            : `<table>
                <thead><tr><th>Name</th><th>Protocol</th><th>Who can use it</th><th>Created</th></tr></thead>
                <tbody>
                  ${rows
                    .map(
                      (r) =>
                        `<tr><td><span style="display:inline-flex; align-items:center; gap:8px;">${r.logo ? `<img src="${escapeHtml(r.logo)}" alt="" style="width:18px; height:18px; object-fit:contain;" data-hide-on-error />` : ""}<a href="${r.href}">${escapeHtml(r.name)}</a></span></td><td><span class="badge">${r.protocol}</span>${r.requireMfa ? ' <span class="badge badge-pending" title="Sign-in must include a second factor">MFA</span>' : ""}</td><td>${restriction(r)}</td><td class="muted">${ts(r.createdAt, { dateOnly: true })}</td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>
              ${paginationControls("/admin/apps", page, totalPages, { search, protocol: protocolFilter, access: accessFilter, pageSize })}`
        }
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Applications" }]
    )
  );
});

/** App-side {placeholders} an administrator fills in before a catalog entry applies - {idp_*} resolve from the issuer, and {client_id}/{client_secret} only exist after the record is created. */
admin.get("/admin/apps/catalog", async (c) => {
  const search = (c.req.query("search") ?? "").slice(0, 100).trim().toLowerCase();
  const protocolFilter = ["oidc", "saml"].includes(c.req.query("protocol") ?? "") ? c.req.query("protocol")! : "";
  const pageSize = [25, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 25;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const filtered = listCatalog()
    .filter((e) => !search || e.name.toLowerCase().includes(search) || e.slug.includes(search))
    .filter((e) => !protocolFilter || e.protocol === protocolFilter);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const entries = filtered.slice((page - 1) * pageSize, page * pageSize);
  return c.html(
    layout(
      c,
      "App catalog",
      `
      <p class="muted" style="margin:-6px 0 16px; max-width:720px;">Guided setup for well-known applications: the steps for both sides of the integration, and a template that creates the FlareID record prefilled. Apps a template creates start restricted - assign people or groups on the app's page.</p>
      ${cardSection(`
        <form method="GET">
          <div class="row between" style="align-items:flex-start; gap:12px; flex-wrap:wrap;">
            <div style="display:flex; gap:8px; flex-wrap:wrap; flex:1;">
              <input type="text" name="search" placeholder="Search the catalog" value="${escapeHtml(search)}" style="max-width:260px; margin-bottom:0;" />
              <select name="protocol" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
                ${[["", "All protocols"], ["oidc", "OIDC"], ["saml", "SAML"]].map(([v, l]) => `<option value="${v}" ${v === protocolFilter ? "selected" : ""}>${l}</option>`).join("")}
              </select>
              <input type="hidden" name="page" value="1" />
              ${pageSizeSelect(pageSize, [25, 50, 100])}
            </div>
          </div>
        </form>
      `)}
      ${
        entries.length === 0
          ? cardSection(`<p class="muted">No catalog entries matching ${search ? `"${escapeHtml(search)}"` : "that filter"}.</p>`)
          : `<div class="three-col">
        ${entries
          .map(
            (e) =>
              cardSection(`
                <div class="row" style="margin:0 0 10px 0; align-items:center; gap:10px;">
                  <img src="/catalog-icons/${escapeHtml(e.logo.slice(6))}" alt="" style="width:28px; height:28px; object-fit:contain; flex-shrink:0;" />
                  <h2 style="margin:0; flex:1;"><a href="/admin/apps/catalog/${escapeHtml(e.slug)}">${escapeHtml(e.name)}</a></h2>
                  <span class="badge">${e.protocol.toUpperCase()}</span>
                </div>
                <div style="margin-top:12px;"><a href="/admin/apps/catalog/${escapeHtml(e.slug)}">Set up ${escapeHtml(e.name)} &rarr;</a></div>
              `)
          )
          .join("")}
      </div>
      ${paginationControls("/admin/apps/catalog", page, totalPages, { search, protocol: protocolFilter, pageSize })}`
      }
      `,
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: "App catalog" }]
    )
  );
});

admin.get("/admin/apps/catalog/:slug", async (c) => {
  const entry = getCatalogEntry(c.req.param("slug"));
  if (!entry) return consoleError(c, "That catalog entry does not exist.", 404);
  const rendered = renderInstructions(entry, { issuer: c.env.ISSUER_URL });
  const fields = catalogValuePlaceholders(entry);
  const steps = (list: string[]) => `<ol>${list.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>`;
  return c.html(
    layout(
      c,
      `${entry.name}`,
      `
      <p class="muted" style="margin:-6px 0 16px; display:flex; align-items:center; gap:8px;"><img src="/catalog-icons/${escapeHtml(entry.logo.slice(6))}" alt="" style="width:22px; height:22px; object-fit:contain;" /> <a href="${escapeHtml(entry.website)}" target="_blank" rel="noopener">${escapeHtml(entry.website.replace(/^https?:\/\//, ""))}</a> &middot; <span class="badge">${entry.protocol.toUpperCase()}</span></p>
      <div class="two-col">
        ${cardSection(`<h2>In the app</h2>${steps(rendered.app)}`)}
        ${cardSection(`<h2>In FlareID</h2>${steps(rendered.flareid)}`)}
      </div>
      ${cardSection(`
        <h2>Apply this template</h2>
        <p class="muted">Creates the ${entry.protocol === "saml" ? "SAML service provider" : "OIDC client"} with ${escapeHtml(entry.name)}'s settings filled in. ${
          fields.length ? "Fill in the values the steps mark in braces first - they land in the record and in the instructions." : "No app-side values are needed."
        } The generated <code>{client_id}</code> and <code>{client_secret}</code> appear on the record once it is created.</p>
        <form method="POST" action="/admin/apps/catalog/${escapeHtml(entry.slug)}/apply">
          ${fields
            .map(
              (f) =>
                `<label for="ph_${escapeHtml(f)}"><code>{${escapeHtml(f)}}</code></label><input type="text" id="ph_${escapeHtml(f)}" name="ph_${escapeHtml(f)}" required placeholder="e.g. ${f === "host" ? "app.example.com" : escapeHtml(f)}" />`
            )
            .join("")}
          <div class="form-actions end"><button class="primary" type="submit">Create ${escapeHtml(entry.name)} application</button></div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, APP_CATALOG_CRUMB, { label: entry.name }]
    )
  );
});

admin.post("/admin/apps/catalog/:slug/apply", async (c) => {
  const entry = getCatalogEntry(c.req.param("slug"));
  if (!entry) return consoleError(c, "That catalog entry does not exist.", 404);
  const body = await c.req.parseBody({ all: true });
  const values: Record<string, string> = {};
  for (const name of catalogValuePlaceholders(entry)) {
    const v = String(body[`ph_${name}`] ?? "").trim();
    if (v) values[name] = v;
  }

  // applyCatalogEntry (services/apps.ts) is the same path
  // POST /api/v1/app-catalog/{slug}/apply takes.
  const result = await applyCatalogEntry(c.env, entry, values, c.env.ISSUER_URL);
  if (!result.ok) return consoleError(c, result.error, 400);

  if (result.protocol === "saml") {
    await logAudit(c.env, c.get("user"), "saml_sp.created", entry.name, { via: `catalog:${entry.slug}` }, c.req.raw);
    return c.redirect(`/admin/saml/${result.id}?saved=1`, 302);
  }

  await logAudit(c.env, c.get("user"), "oidc_client.created", entry.name, { via: `catalog:${entry.slug}` }, c.req.raw);
  // A confidential client's secret exists only in this response, so it gets
  // the same once-only page the create form ends on; a public client has no
  // secret and goes straight to the new record.
  if (result.clientSecret === null) return c.redirect(`/admin/clients/${result.id}?saved=1`, 302);
  return c.html(
    layout(
      c,
      "Client created",
      cardSection(`
        <p class="success">Created "${escapeHtml(entry.name)}" from the catalog.</p>
        ${secretBlock("Client secret", result.clientSecret)}
        ${oidcEndpointsBlock(c.env, result.clientId)}
        <a href="/admin/clients/${result.id}"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, APP_CATALOG_CRUMB, { label: entry.name, href: `/admin/apps/catalog/${entry.slug}` }, { label: "Client created" }]
    )
  );
});

// ---------- Integrations: OIDC clients, SAML apps, API keys, SCIM ----------
//
// One section, because they are all how other systems connect to this
// directory - configuring Cloudflare Access means registering a client and
// then setting up SCIM, and that should not be a hunt across the nav. Each
// kind has its own page, listed under Integrations in the sidebar while you are
// in the section; /admin/integrations is an overview of all four. The older
// single-page paths still resolve so existing links and bookmarks survive.
admin.get("/admin/clients", (c) => c.redirect("/admin/apps", 302));
admin.get("/admin/scim", (c) => c.redirect(`/admin/integrations/scim${new URL(c.req.url).search}`, 302));

/** Page heading row: the page's description plus its primary action. */
function integrationIntro(description: string, action?: { href: string; label: string }): string {
  return `<div class="row between" style="margin:0 0 14px 0; align-items:flex-start; gap:16px;">
    <p class="muted" style="margin:0; max-width:720px;">${description}</p>
    ${action ? `<a href="${escapeHtml(action.href)}"><button class="primary" type="button">${escapeHtml(action.label)}</button></a>` : ""}
  </div>`;
}

/** One overview card: a heading with a count, up to five rows, and a link to the full page. */
function summaryCard(opts: { title: string; count: string; rows: string[]; empty: string; manage: IntegrationPage; extra?: string; href?: string }): string {
  const page = INTEGRATION_PAGES.find((p) => p.key === opts.manage)!;
  const shown = opts.rows.slice(0, 5);
  return cardSection(`
    <div class="row between" style="margin:0 0 10px 0;">
      <h2 style="margin:0;">${escapeHtml(opts.title)}</h2>
      <span class="muted">${opts.count}</span>
    </div>
    ${opts.extra ?? ""}
    ${
      shown.length === 0
        ? `<p class="muted">${opts.empty}</p>`
        : `<table><tbody>${shown.join("")}</tbody></table>${opts.rows.length > shown.length ? `<p class="muted" style="margin:8px 0 0;">and ${opts.rows.length - shown.length} more</p>` : ""}`
    }
    <div style="margin-top:12px;"><a href="${opts.href ?? `/admin/integrations/${page.key}`}">Manage ${escapeHtml(page.label)} &rarr;</a></div>
  `);
}

admin.get("/admin/integrations", async (c) => {
  const [apiKeys, scimTargets, ldapApps, ldapSettings, upstreamIdps] = await Promise.all([
    listApiKeys(c.env),
    listScimTargets(c.env),
    listLdapApps(c.env),
    getLdapSettings(c.env),
    listUpstreamIdps(c.env),
  ]);
  const activeKeys = apiKeys.filter((k) => !k.revoked_at);
  const revokedKeys = apiKeys.length - activeKeys.length;
  const socialIdps = upstreamIdps.filter((u) => u.protocol === "oidc" && idpConfig<OidcIdpConfig>(u).social);

  return c.html(
    layout(
      c,
      "Integrations",
      `
      <p class="muted" style="margin:-6px 0 16px;">The connections into and out of this directory: global SAML settings, API keys that automate it, where users are provisioned, and the upstream IdPs people sign in through. The apps users sign in to are under <a href="/admin/apps">Applications</a>.</p>
      <div class="two-col">
        ${summaryCard({
          title: "SAML",
          count: `<span class="badge ${isSamlConfigured(c.env) ? "badge-active" : "badge-disabled"}">${isSamlConfigured(c.env) ? "Configured" : "No signing cert"}</span>`,
          rows: [`<tr><td>Entity ID</td><td><code>${escapeHtml(idpEntityId(c.env))}</code></td></tr>`, `<tr><td>SSO URL</td><td><code>${escapeHtml(idpEntityId(c.env))}/saml/sso</code></td></tr>`],
          empty: "",
          manage: "saml",
        })}
        ${summaryCard({
          title: "SCIM provisioning",
          count: `${scimTargets.length} target${scimTargets.length === 1 ? "" : "s"}`,
          rows: scimTargets.map(
            (t) =>
              `<tr><td><a href="/admin/integrations/scim/${t.id}">${escapeHtml(t.name)}</a></td><td><code>${escapeHtml(scimHost(t.endpoint) || "—")}</code></td>${t.enabled ? "" : '<td><span class="badge badge-disabled">Disabled</span></td>'}</tr>`
          ),
          empty: "Users and groups are not being pushed anywhere.",
          manage: "scim",
        })}
        ${summaryCard({
          title: "LDAP",
          count: `<span class="badge ${ldapSettings.enabled ? "badge-active" : "badge-disabled"}">${ldapSettings.enabled ? "Enabled" : "Disabled"}</span>`,
          rows: ldapApps.map((a) => `<tr><td><a href="/admin/ldap/${escapeHtml(a.slug)}">${escapeHtml(a.name)}</a></td><td><code>${escapeHtml(a.slug)}</code></td>${a.revoked_at ? '<td><span class="badge badge-disabled">Revoked</span></td>' : ""}</tr>`),
          empty: ldapSettings.enabled ? "No LDAP apps registered yet." : "The LDAP interface is disabled.",
          manage: "ldap",
        })}
        ${summaryCard({
          title: "Federation",
          count: `${upstreamIdps.length} provider${upstreamIdps.length === 1 ? "" : "s"}`,
          rows: upstreamIdps.map(
            (u) =>
              `<tr><td><a href="/admin/integrations/federation/${u.id}">${escapeHtml(u.name)}</a></td><td class="muted">${u.protocol.toUpperCase()}${u.jit ? " · JIT" : ""}</td>${u.enabled ? "" : '<td><span class="badge badge-disabled">Disabled</span></td>'}</tr>`
          ),
          empty: "Nobody signs in through an upstream IdP.",
          manage: "federation",
        })}
        ${summaryCard({
          title: "Social sign-in",
          count: `${socialIdps.length} of ${SOCIAL_PROVIDERS.length} set up`,
          rows: socialIdps.map(
            (u) =>
              `<tr><td><a href="/admin/integrations/social/${idpConfig<OidcIdpConfig>(u).social}">${escapeHtml(u.name)}</a></td><td class="muted">${u.jit ? "JIT" : "link only"}</td>${u.enabled ? "" : '<td><span class="badge badge-disabled">Disabled</span></td>'}</tr>`
          ),
          empty: "No consumer providers set up - Google, GitHub, Microsoft and more are a client id and secret away.",
          manage: "social",
        })}
        ${summaryCard({
          title: "API keys",
          count: `${activeKeys.length} active${revokedKeys ? ` &middot; ${revokedKeys} revoked` : ""}`,
          rows: activeKeys.map(
            (k) =>
              `<tr><td>${escapeHtml(k.name)}</td><td>${parseScopes(k.scopes).map(escapeHtml).join(", ")}</td><td class="muted">${k.last_used_at ? `used ${ts(k.last_used_at)}` : "never used"}</td></tr>`
          ),
          empty: "No active API keys.",
          manage: "api-keys",
        })}
      </div>
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Integrations" }]
    )
  );
});

admin.get("/admin/integrations/email", async (c) => {
  const settings = await getEmailSettings(c.env);
  const hasBinding = Boolean(c.env.EMAIL);
  const enabled = await isEmailEnabled(c.env);
  const ready = hasBinding && Boolean(settings.fromAddress) && enabled;
  const notice = c.req.query("test");
  return c.html(
    layout(
      c,
      "Email",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${notice === "sent" ? successBanner(`Test email sent to ${c.get("user").email || c.get("user").upn}.`) : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error") ?? "")}</p>` : ""}
      ${cardSection(`
        ${integrationIntro("Outbound email through Cloudflare Email Sending, for password recovery and invitations. With email set up, the sign-in page offers &ldquo;Forgot your password?&rdquo; and user pages can send invitation and reset links instead of an administrator relaying a password.")}
        <table style="margin-bottom:14px;"><tbody>
          <tr><th style="width:180px;">Worker binding</th><td>${hasBinding ? '<span class="badge badge-active">EMAIL bound</span>' : '<span class="badge badge-disabled">Missing</span> &mdash; add <code>"send_email": [{ "name": "EMAIL" }]</code> to wrangler.jsonc and redeploy'}</td></tr>
          <tr><th>Status</th><td>${ready ? '<span class="badge badge-active">Sending</span>' : !enabled ? '<span class="badge badge-disabled">Switched off</span> &mdash; the settings below are kept' : '<span class="badge badge-disabled">Off</span>'}</td></tr>
        </tbody></table>
        <form method="POST" action="/admin/email/enabled" style="margin-bottom:16px;">
          <input type="hidden" name="enabled" value="${enabled ? "0" : "1"}" />
          <button class="${enabled ? "secondary" : "primary"}" type="submit">${enabled ? "Switch email off" : "Switch email on"}</button>
          <span class="muted" style="margin-left:8px;">${enabled ? "Stops all sending and hides &ldquo;Forgot your password?&rdquo; and invitation buttons, keeping the address and name." : "Email is off: nothing is sent, and recovery and invitations are hidden."}</span>
        </form>
        <form method="POST" action="/admin/email">
          <div class="field-row">
            <div>
              <label for="from_address">From address</label>
              <input type="email" id="from_address" name="from_address" value="${escapeHtml(settings.fromAddress)}" placeholder="no-reply@yourdomain.com" />
            </div>
            <div>
              <label for="from_name">From name</label>
              <input type="text" id="from_name" name="from_name" value="${escapeHtml(settings.fromName)}" maxlength="80" placeholder="${escapeHtml(c.get("appName"))}" />
            </div>
          </div>
          <p class="muted" style="margin-top:-4px;">The address must be on a domain onboarded to Cloudflare Email Sending (<code>wrangler email sending enable yourdomain.com</code>).</p>
          <div class="form-actions end">
            <button class="primary" type="submit">Save</button>
            ${ready ? '<button class="secondary" type="submit" formaction="/admin/email/test">Send a test email to me</button>' : ""}
          </div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "Email" }]
    )
  );
});

admin.post("/admin/email/enabled", async (c) => {
  await switchEmail(consoleCtx(c), String((await c.req.parseBody()).enabled) === "1");
  return c.redirect("/admin/integrations/email?saved=1", 302);
});

admin.post("/admin/email", async (c) => {
  const body = await c.req.parseBody();
  try {
    await saveEmailSettings(consoleCtx(c), String(body.from_address ?? ""), String(body.from_name ?? ""));
  } catch (e) {
    if (e instanceof ServiceError) return c.redirect(`/admin/integrations/email?error=${encodeURIComponent(e.message)}`, 302);
    throw e;
  }
  return c.redirect("/admin/integrations/email?saved=1", 302);
});

admin.post("/admin/email/test", async (c) => {
  const result = await sendTestEmail(consoleCtx(c), recipientFor(c.get("user")), c.get("appName"));
  return c.redirect(result.ok ? "/admin/integrations/email?test=sent" : `/admin/integrations/email?error=${encodeURIComponent(result.error)}`, 302);
});

// ---------- Integrations: SMS ----------
//
// The provider behind phone-number verification codes (account page -> add a
// number). Four vendors on one seam in lib/sms.ts; secrets are sealed at rest.

admin.get("/admin/integrations/sms", async (c) => {
  const config = await getSmsConfig(c.env);
  const ready = smsConfigured(config);
  const secretField = (id: string, label: string, set: boolean, placeholder = "Saved - leave blank to keep it") =>
    `<div><label for="${id}">${label}${set ? ' <span class="muted">(saved)</span>' : ""}</label><input type="password" id="${id}" name="${id}" value="" autocomplete="new-password" placeholder="${set ? placeholder : "Required"}" /></div>`;
  return c.html(
    layout(
      c,
      "SMS",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        ${integrationIntro("Outbound SMS for phone verification codes: when someone adds a number to their account, a six-digit code is sent here. Pick the vendor you already have - the credentials are write-only and stored sealed.")}
        <table style="margin-bottom:14px;"><tbody>
          <tr><th style="width:180px;">Status</th><td>${ready ? `<span class="badge badge-active">Sending via ${SMS_PROVIDERS.find((p) => p.key === config.provider)?.label}</span>` : '<span class="badge badge-disabled">Off</span> &mdash; phone verification is unavailable until this is configured'}</td></tr>
        </tbody></table>
        <form method="POST" action="/admin/sms">
          <label for="sms_provider">Provider</label>
          <select id="sms_provider" name="provider">
            <option value="">None (SMS off)</option>
            ${SMS_PROVIDERS.map((p) => `<option value="${p.key}" ${config.provider === p.key ? "selected" : ""}>${p.label} &mdash; ${p.fields}</option>`).join("")}
          </select>
          <div id="sms-fields">
            <div class="field-row" data-providers="twilio">
              ${secretField("account_sid", "Twilio Account SID", Boolean(config.accountSid), "ACxxxx...")}
              ${secretField("auth_token", "Twilio Auth Token", Boolean(config.authToken))}
            </div>
            <div class="field-row" data-providers="vonage">
              ${secretField("api_key", "Vonage API key", Boolean(config.apiKey))}
              ${secretField("api_secret", "Vonage API secret", Boolean(config.apiSecret))}
            </div>
            <div class="field-row" data-providers="telnyx">
              ${secretField("telnyx_key", "Telnyx API key", Boolean(config.telnyxKey))}
            </div>
            <div class="field-row" data-providers="plivo">
              ${secretField("plivo_id", "Plivo Auth ID", Boolean(config.plivoId), "MAxxxx...")}
              ${secretField("plivo_token", "Plivo Auth Token", Boolean(config.plivoToken))}
            </div>
            <div class="field-row" data-providers="twilio vonage telnyx plivo">
              <div>
                <label for="sms_from">From number / sender</label>
                <input type="text" id="sms_from" name="from" value="${escapeHtml(config.from)}" placeholder="+15551234567" />
                <p class="muted" style="margin-top:-4px;">E.164 number (or messaging profile / sender id where your provider allows one).</p>
              </div>
            </div>
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
        ${scriptTag(`(function(){var s=document.getElementById('sms_provider');if(!s)return;function t(){var v=s.value;document.querySelectorAll('#sms-fields [data-providers]').forEach(function(r){r.style.display=v&&r.getAttribute('data-providers').split(' ').indexOf(v)>=0?'':'none';});}s.addEventListener('change',t);t();})();`)}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "SMS" }]
    )
  );
});

admin.post("/admin/sms", async (c) => {
  const body = await c.req.parseBody();
  try {
    await saveSmsConfig(c.env, {
      provider: String(body.provider ?? ""),
      accountSid: String(body.account_sid ?? ""),
      authToken: String(body.auth_token ?? ""),
      apiKey: String(body.api_key ?? ""),
      apiSecret: String(body.api_secret ?? ""),
      telnyxKey: String(body.telnyx_key ?? ""),
      plivoId: String(body.plivo_id ?? ""),
      plivoToken: String(body.plivo_token ?? ""),
      from: String(body.from ?? ""),
    });
  } catch (e) {
    return c.redirect(`/admin/integrations/sms?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  await logAudit(c.env, c.get("user"), "integrations.sms_updated", "settings", { provider: String(body.provider ?? "") || "none" }, c.req.raw);
  return c.redirect("/admin/integrations/sms?saved=1", 302);
});

// ---------- Cloudflare One ----------

const CFONE = "/admin/integrations/cf-one";

admin.get(CFONE, async (c) => {
  const config = await getCfOne(c.env);
  const enabled = await enabledListSyncs(c.env);
  const status = await listSyncStatus(c.env);
  const watched = await watchlist(c.env);
  const accessApps = await listAccessApps(c.env);
  const appsSyncHours = await accessAppsSyncHours(c.env);
  const roleGroupSet = await adminRoleGroupIds(c.env);
  const grantableGroups = (await c.env.DB.prepare("SELECT id, name FROM groups WHERE (rule IS NULL OR rule = '') AND (system IS NULL OR system = '') ORDER BY name").all<{ id: number; name: string }>()).results.filter((g) => !roleGroupSet.has(g.id));
  const statusByKey = new Map(status.map((s) => [s.key, s]));
  const ready = cfOneReady(config);

  return c.html(
    layout(
      c,
      "Cloudflare One",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("synced") ? successBanner(`Sync ran: ${escapeHtml(c.req.query("synced")!)} list${c.req.query("synced") === "1" ? "" : "s"} updated${c.req.query("failed") ? `, ${escapeHtml(c.req.query("failed")!)} failed - see below` : ""}.`) : ""}
      ${c.req.query("apps_synced") ? successBanner(`Access applications synced: ${escapeHtml(c.req.query("apps_synced")!)} pulled${Number(c.req.query("apps_removed")) ? `, ${escapeHtml(c.req.query("apps_removed")!)} removed` : ""}.`) : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error") ?? "")}</p>` : ""}
      ${cardSection(`
        ${integrationIntro("Connects this directory to Cloudflare One (Zero Trust). The API token needs <strong>Zero Trust: Edit</strong> on the account. Once the team name and an Access application's AUD are set, the admin console only answers requests that arrive through that Access application.")}
        <form method="POST" action="${CFONE}">
          <div class="field-row">
            <div>
              <label for="account_id">Account ID</label>
              <input type="text" id="account_id" name="account_id" value="${escapeHtml(config?.accountId ?? "")}" placeholder="Cloudflare account id" />
            </div>
            <div>
              <label for="api_token">API token</label>
              <input type="password" id="api_token" name="api_token" value="" placeholder="${config?.apiToken ? "Stored - leave blank to keep" : "Zero Trust Edit token"}" autocomplete="off" />
            </div>
          </div>
          <div class="field-row">
            <div>
              <label for="team">Zero Trust team name</label>
              <input type="text" id="team" name="team" value="${escapeHtml(config?.team ?? "")}" placeholder="yourteam" />
              <p class="muted" style="margin:4px 0 0;">From <code>https://<strong>yourteam</strong>.cloudflareaccess.com</code>.</p>
            </div>
            <div>
              <label for="access_aud">Access application AUD</label>
              <input type="text" id="access_aud" name="access_aud" value="${escapeHtml(config?.accessAud ?? "")}" placeholder="Application protecting this console" />
              <p class="muted" style="margin:4px 0 0;">With a team and AUD set, every console page verifies the Access JWT &mdash; open the console through Access before saving, or you could lock yourself out.</p>
            </div>
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>List sync</h2>
        <p class="muted">Keeps Cloudflare One gateway lists in step with the directory, so Gateway and Access policies can reference them. A group's own sync switch is on its page under Groups.</p>
        ${
          ready
            ? `<form method="POST" action="${CFONE}">
          <input type="hidden" name="connection" value="1" />
          <div style="display:flex; flex-direction:column; gap:10px; margin-bottom:14px;">
            ${LIST_SYNCS.map(
              (l) => `<label style="display:flex; align-items:flex-start; gap:8px; font-weight:500;">
                <input type="checkbox" name="list_${l.key}" value="1" ${enabled.has(l.key) ? "checked" : ""} style="width:auto; margin:3px 0 0;" />
                <span>${escapeHtml(l.name)} <code class="muted">${l.kind}</code><br/><span class="muted" style="font-weight:400;">${escapeHtml(l.description)}${statusByKey.get(l.key) ? ` &middot; ${statusByKey.get(l.key)!.item_count} items, synced ${ts(statusByKey.get(l.key)!.synced_at ?? "")}` : ""}</span></span>
              </label>`
            ).join("")}
          </div>
          <div class="form-actions end">
            <button class="primary" type="submit">Save</button>
            <button class="secondary" type="submit" formaction="${CFONE}/sync">Sync now</button>
          </div>
        </form>
        ${status.filter((s) => s.key.startsWith("group:")).length ? `<p class="muted">Group lists synced: ${status.filter((s) => s.key.startsWith("group:")).map((s) => `<code>${escapeHtml(s.cf_list_id)}</code> (${s.item_count})`).join(" ")}</p>` : ""}`
            : `<p class="muted">Set the account ID and API token above first - without the token there is nothing to push with.</p>`
        }
      `)}
      ${cardSection(`
        <h2>Access applications</h2>
        <p class="muted">Cloudflare Access applications pulled read-only from this account. Map each app to the static group whose membership grants it: Access policies that Include that group then decide reachability, members see the app on their Applications page, and an approved access request is just a group-join. FlareID never writes Access config - changes made in Zero Trust land here on the next sync (on your cadence, or on demand).</p>
        ${
          ready
            ? `${accessApps.length
                ? `<table>
                    <thead><tr><th>Application</th><th>Granted by</th><th>Requestable</th><th></th></tr></thead>
                    <tbody>${accessApps
                      .map((a) => {
                        const hints = grantHints(a);
                        return `<tr>
                          <td>${escapeHtml(a.name)}${a.type ? ` <span class="badge">${escapeHtml(a.type)}</span>` : ""}${a.hostname ? `<br/><a class="muted" style="font-size:12px;" href="${escapeHtml(accessAppHref(a))}" target="_blank" rel="noopener">${escapeHtml(a.hostname)}</a>` : ""}
                            ${hints.length ? `<br/><span class="muted" style="font-size:12px;">Policies name: ${hints.map(escapeHtml).join(", ")}</span>` : ""}</td>
                          <td>
                            <select form="cfapp-${a.id}" name="granting_group_id" style="margin:0; min-width:170px;">
                              <option value="">- not mapped -</option>
                              ${grantableGroups.map((g) => `<option value="${g.id}" ${a.granting_group_id === g.id ? "selected" : ""}>${escapeHtml(g.name)}</option>`).join("")}
                            </select>
                          </td>
                          <td>
                            <label class="switch" title="People can ask for this app from My account">
                              <input form="cfapp-${a.id}" type="checkbox" name="requestable" value="1" ${a.requestable ? "checked" : ""} />
                              <span class="track"></span>
                            </label>
                          </td>
                          <td><form id="cfapp-${a.id}" method="POST" action="${CFONE}/apps/${a.id}" style="margin:0;"><button class="secondary" type="submit" style="margin:0;">Save</button></form></td>
                        </tr>`;
                      })
                      .join("")}</tbody>
                  </table>`
                : `<p class="muted">Nothing synced yet - pull this account's Access applications to map them here.</p>`}
              <div class="row" style="justify-content:flex-start; gap:16px; margin-top:12px; flex-wrap:wrap;">
                <form method="POST" action="${CFONE}/apps/sync" style="margin:0;">
                  <button class="secondary" type="submit">Sync applications now</button>
                </form>
                <form method="POST" action="${CFONE}/apps/schedule" style="margin:0; display:flex; align-items:center; gap:8px;">
                  <label for="apps_sync_hours" class="muted" style="margin:0; font-size:12px;">Refresh every</label>
                  <select id="apps_sync_hours" name="apps_sync_hours" data-autosubmit style="margin:0; width:auto;">
                    ${ACCESS_APPS_SYNC_HOURS.map((h) => `<option value="${h}" ${h === appsSyncHours ? "selected" : ""}>${h} hour${h === 1 ? "" : "s"}</option>`).join("")}
                  </select>
                </form>
                ${accessApps.some((a) => a.synced_at) ? `<span class="muted" style="font-size:12px;">Last synced ${ts(accessApps.map((a) => a.synced_at).sort().pop() ?? "")}</span>` : ""}
              </div>`
            : `<p class="muted">Set the account ID and API token above first - there is nothing to pull with.</p>`
        }
      `)}
      ${cardSection(`
        <h2>Risk watchlist</h2>
        <p class="muted">Flagged people land in the <em>Risk watchlist</em> system group - sync its emails to a Cloudflare list, or to any SCIM target, to tighten their inspection. A burst of failed sign-ins flags someone automatically for 24h.</p>
        ${
          watched.length
            ? `<table>
                <thead><tr><th>Person</th><th>Reason</th><th>Source</th><th>Flagged</th><th>Until</th><th></th></tr></thead>
                <tbody>${watched
                  .map(
                    (w) => `<tr>
                      <td><a href="/admin/users/${w.user_id}">${escapeHtml(w.display_name || w.upn)}</a><br/><span class="muted">${escapeHtml(w.upn)}</span></td>
                      <td>${escapeHtml(w.reason)}</td>
                      <td class="muted">${escapeHtml(w.source)}</td>
                      <td>${ts(w.flagged_at)}</td>
                      <td class="muted">${w.expires_at ? ts(w.expires_at) : "until cleared"}</td>
                      <td><form method="POST" action="${CFONE}/watch/${w.user_id}/remove"><button class="link-button" type="submit">Clear</button></form></td>
                    </tr>`
                  )
                  .join("")}</tbody>
              </table>`
            : '<p class="muted">Nobody is flagged.</p>'
        }
        <form method="POST" action="${CFONE}/watch" style="margin-top:12px;">
          <div class="field-row">
            <div>${remoteMultiSelect("user_id", "/admin/users/lookup", [], "Person to flag...", true)}</div>
            <div><input type="text" name="reason" placeholder="Reason - shown on the user page" maxlength="300" required /></div>
            <div><input type="number" name="ttl_hours" min="0" placeholder="Hours (blank = until cleared)" style="width:200px;" /></div>
          </div>
          <button class="secondary" type="submit">Flag on watchlist</button>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "Cloudflare One" }]
    )
  );
});

admin.post(CFONE, async (c) => {
  const body = await c.req.parseBody({ all: true });
  try {
    await saveCfOne(c.env, {
      accountId: String(body.account_id ?? "").trim(),
      apiToken: String(body.api_token ?? "").trim() || undefined,
      team: String(body.team ?? "").trim(),
      accessAud: String(body.access_aud ?? "").trim(),
    });
    const lists = LIST_SYNCS.map((l) => l.key).filter((k) => body[`list_${k}`] === "1");
    if (Object.keys(body).some((k) => k.startsWith("list_"))) await setEnabledListSyncs(c.env, lists);
    await audit(consoleCtx(c), "cfone.configured", "cloudflare-one", { lists });
  } catch (e) {
    return c.redirect(`${CFONE}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  return c.redirect(`${CFONE}?saved=1`, 302);
});

admin.post(`${CFONE}/sync`, async (c) => {
  const config = await getCfOne(c.env);
  if (!config?.apiToken) return c.redirect(`${CFONE}?error=${encodeURIComponent("Set the account ID and API token first.")}`, 302);
  const result = await syncLists(c.env, config);
  await sweepWatchlist(c.env);
  return c.redirect(`${CFONE}?synced=${result.synced.length}${Object.keys(result.failed).length ? `&failed=${Object.keys(result.failed).length}` : ""}`, 302);
});

admin.post(`${CFONE}/watch`, async (c) => {
  const body = await c.req.parseBody();
  const userId = Number(Array.isArray(body.user_id) ? body.user_id[0] : body.user_id);
  const reason = String(body.reason ?? "").trim().slice(0, 300);
  const ttl = Math.max(0, Number(body.ttl_hours ?? 0) || 0);
  if (!userId || !reason) return c.redirect(`${CFONE}?error=${encodeURIComponent("Pick a person and give a reason.")}`, 302);
  await assertMayTouchUser(consoleCtx(c), userId);
  await flagUser(c.env, userId, reason, "manual", ttl);
  const upn = (await c.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(userId).first<{ upn: string }>())?.upn ?? `#${userId}`;
  await audit(consoleCtx(c), "cfone.user_flagged", upn, { reason });
  return c.redirect(`${CFONE}?saved=1`, 302);
});

admin.post(`${CFONE}/watch/:uid/remove`, async (c) => {
  const userId = Number(c.req.param("uid"));
  await assertMayTouchUser(consoleCtx(c), userId);
  await unflagUser(c.env, userId);
  const upn = (await c.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(userId).first<{ upn: string }>())?.upn ?? `#${userId}`;
  await audit(consoleCtx(c), "cfone.user_unflagged", upn);
  return c.redirect(`${CFONE}?saved=1`, 302);
});

admin.post(`${CFONE}/apps/sync`, async (c) => {
  const config = await getCfOne(c.env);
  if (!config?.apiToken) return c.redirect(`${CFONE}?error=${encodeURIComponent("Set the account ID and API token first.")}`, 302);
  try {
    const result = await syncAccessApps(c.env, config);
    await audit(consoleCtx(c), "cfone.access_apps_synced", "cloudflare-one", { synced: result.synced, removed: result.removed });
    return c.redirect(`${CFONE}?apps_synced=${result.synced}&apps_removed=${result.removed}`, 302);
  } catch (e) {
    return c.redirect(`${CFONE}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post(`${CFONE}/apps/schedule`, async (c) => {
  const body = await c.req.parseBody();
  const hours = Number(body.apps_sync_hours);
  if (!(ACCESS_APPS_SYNC_HOURS as readonly number[]).includes(hours)) {
    return c.redirect(`${CFONE}?error=${encodeURIComponent("Pick a refresh interval from the list.")}`, 302);
  }
  await setSetting(c.env, "cfone.apps_sync_hours", String(hours));
  await audit(consoleCtx(c), "cfone.access_apps_schedule", "cloudflare-one", { hours });
  return c.redirect(`${CFONE}?saved=1`, 302);
});

admin.post(`${CFONE}/apps/:id`, async (c) => {
  const body = await c.req.parseBody();
  const gid = Number(body.granting_group_id ?? 0) || null;
  try {
    const app = await configureAccessApp(c.env, Number(c.req.param("id")), gid, body.requestable === "1");
    await audit(consoleCtx(c), "cfone.access_app_configured", app.name, { granting_group_id: gid, requestable: app.requestable });
  } catch (e) {
    return c.redirect(`${CFONE}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  return c.redirect(`${CFONE}?saved=1`, 302);
});

const SIGNALS = "/admin/integrations/signals";
const SSF_EVENT_LABELS: Record<string, string> = {
  "https://schemas.openid.net/secevent/caep/event-type/session-revoked": "Session revoked (CAEP)",
  "https://schemas.openid.net/secevent/caep/event-type/credential-change": "Credential change (CAEP)",
  "https://schemas.openid.net/secevent/risc/event-type/account-disabled": "Account disabled (RISC)",
  "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required": "Risk flag - re-auth required (RISC)",
};

interface SsfStreamView {
  id: number;
  name: string;
  endpoint_url: string;
  aud: string;
  events: string;
  disabled: number;
  last_push_at: string | null;
  last_error: string | null;
  queued: number;
}

admin.get(SIGNALS, async (c) => {
  const { results: streams } = await c.env.DB.prepare(
    `SELECT s.*, (SELECT COUNT(*) FROM ssf_outbox o WHERE o.stream_id = s.id) AS queued FROM ssf_streams s ORDER BY s.id`
  ).all<SsfStreamView>();
  const { results: transmitters } = await c.env.DB.prepare("SELECT * FROM ssf_transmitters ORDER BY id").all<{ id: number; name: string; issuer: string; jwks_url: string; created_at: string }>();
  const issuer = c.env.ISSUER_URL;
  const eventNames = (raw: string): string => {
    try {
      const evs = JSON.parse(raw || "[]") as string[];
      return evs.length ? evs.map((e) => SSF_EVENT_LABELS[e] ?? e).join(", ") : "all events";
    } catch {
      return "all events";
    }
  };
  const streamRows = streams.length
    ? streams
        .map(
          (s) => `<tr>
            <td>${escapeHtml(s.name)}<br/><span class="muted"><code>${escapeHtml(s.endpoint_url)}</code></span></td>
            <td class="muted">${escapeHtml(eventNames(s.events))}</td>
            <td class="muted">${s.disabled ? "disabled" : s.last_error ? `<span class="error">${escapeHtml(s.last_error)}</span>` : s.last_push_at ? `pushed ${ts(s.last_push_at)}` : "never pushed"}${s.queued ? `<br/>${s.queued} queued` : ""}</td>
            <td><div class="row-actions">
              <form method="POST" action="${SIGNALS}/streams/${s.id}/toggle" style="margin-right:6px;"><button class="link-button" type="submit">${s.disabled ? "Enable" : "Disable"}</button></form>
              <form method="POST" action="${SIGNALS}/streams/${s.id}/delete" ${confirmAttrs(`Delete stream "${s.name}"? Queued events go with it.`)}>${iconButton("trash", "Delete", { danger: true })}</form>
            </div></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="4" class="muted">No streams yet.</td></tr>`;
  const txRows = transmitters.length
    ? transmitters
        .map(
          (t) => `<tr>
            <td>${escapeHtml(t.name)}<br/><span class="muted"><code>${escapeHtml(t.issuer)}</code></span></td>
            <td class="muted"><code>${escapeHtml(t.jwks_url)}</code></td>
            <td>${rowActions(`<form method="POST" action="${SIGNALS}/transmitters/${t.id}/delete" ${confirmAttrs(`Stop trusting "${t.name}"?`)}>${iconButton("trash", "Delete", { danger: true })}</form>`)}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="3" class="muted">No trusted transmitters.</td></tr>`;

  return c.html(
    layout(
      c,
      "Signals",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("drained") ? successBanner(`Outbox drained: ${escapeHtml(c.req.query("drained")!)}.`) : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error") ?? "")}</p>` : ""}
      ${cardSection(`
        ${integrationIntro("Shared Signals Framework: push CAEP/RISC security events to receivers, and accept them from trusted transmitters. Metadata is at <code>/.well-known/ssf-configuration</code>; SETs are signed with the token signing keys at <code>/jwks.json</code>.")}
      `)}
      ${cardSection(`
        <h2>Outbound streams</h2>
        <p class="muted">Receivers we push signed Security Event Tokens to. Session revokes, credential changes, account disables and risk flags each queue a SET per stream; failed deliveries retry hourly.</p>
        <table>
          <thead><tr><th>Stream</th><th>Events</th><th>Status</th><th></th></tr></thead>
          <tbody>${streamRows}</tbody>
        </table>
        <h3 style="margin-top:18px;">Add a stream</h3>
        <form method="POST" action="${SIGNALS}/streams">
          <div class="field-row">
            <div><label for="s_name">Name</label><input type="text" id="s_name" name="name" placeholder="e.g. Okta SSF receiver" required /></div>
            <div><label for="s_ep">Endpoint URL</label><input type="url" id="s_ep" name="endpoint_url" placeholder="https://receiver.example.com/events" required /></div>
            <div><label for="s_aud">Audience</label><input type="text" id="s_aud" name="aud" placeholder="blank = endpoint host" /></div>
          </div>
          <div style="display:flex; gap:16px; flex-wrap:wrap; margin-bottom:12px;">
            ${Object.entries(SSF_EVENT_LABELS)
              .map(([uri, label]) => `<label style="display:flex; align-items:center; gap:6px; font-weight:500;"><input type="checkbox" name="events" value="${escapeHtml(uri)}" style="width:auto;" /> ${escapeHtml(label)}</label>`)
              .join("")}
          </div>
          <p class="muted" style="margin:0 0 12px;">Tick none to send every supported event.</p>
          <button class="secondary" type="submit">Add stream</button>
        </form>
        ${streams.some((s) => s.queued) ? `<form method="POST" action="${SIGNALS}/drain" style="margin-top:10px;"><button class="secondary" type="submit">Retry queued events now</button></form>` : ""}
      `)}
      ${cardSection(`
        <h2>Inbound transmitters</h2>
        <p class="muted">Issuers whose SETs we accept at <code>${escapeHtml(issuer)}/ssf/receive</code>, verified against their JWKS. A session-revoked event kills the person's sessions; a credential or risk event puts them on the risk watchlist for 24h.</p>
        <table>
          <thead><tr><th>Transmitter</th><th>JWKS</th><th></th></tr></thead>
          <tbody>${txRows}</tbody>
        </table>
        <h3 style="margin-top:18px;">Trust a transmitter</h3>
        <form method="POST" action="${SIGNALS}/transmitters">
          <div class="field-row">
            <div><label for="t_name">Name</label><input type="text" id="t_name" name="name" placeholder="e.g. Cloudflare risk stream" required /></div>
            <div><label for="t_iss">Issuer</label><input type="text" id="t_iss" name="issuer" placeholder="https://transmitter.example.com" required /></div>
            <div><label for="t_jwks">JWKS URL</label><input type="url" id="t_jwks" name="jwks_url" placeholder="https://transmitter.example.com/jwks.json" required /></div>
          </div>
          <button class="secondary" type="submit">Trust transmitter</button>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "Signals" }]
    )
  );
});

admin.post(`${SIGNALS}/streams`, async (c) => {
  const body = await c.req.parseBody({ all: true });
  const name = String(body.name ?? "").trim();
  const endpoint = String(body.endpoint_url ?? "").trim();
  const aud = String(body.aud ?? "").trim();
  const rawEvents = Array.isArray(body.events) ? body.events : body.events !== undefined ? [body.events] : [];
  const events = rawEvents.filter((e): e is string => typeof e === "string" && Boolean(SSF_EVENT_LABELS[e]));
  try {
    const url = new URL(endpoint);
    if (url.protocol !== "https:") throw new Error("Endpoint URL must be https.");
  } catch (e) {
    return c.redirect(`${SIGNALS}?error=${encodeURIComponent(e instanceof Error ? e.message : "Endpoint URL must be https.")}`, 302);
  }
  if (!name) return c.redirect(`${SIGNALS}?error=${encodeURIComponent("Name is required.")}`, 302);
  await c.env.DB.prepare("INSERT INTO ssf_streams (name, endpoint_url, aud, events, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(name, endpoint, aud, JSON.stringify(events), new Date().toISOString())
    .run();
  await audit(consoleCtx(c), "ssf.stream_created", name, { endpoint_url: endpoint });
  return c.redirect(`${SIGNALS}?saved=1`, 302);
});

admin.post(`${SIGNALS}/streams/:id/toggle`, async (c) => {
  const id = Number(c.req.param("id"));
  await c.env.DB.prepare("UPDATE ssf_streams SET disabled = 1 - disabled WHERE id = ?").bind(id).run();
  await audit(consoleCtx(c), "ssf.stream_toggled", String(id));
  return c.redirect(`${SIGNALS}?saved=1`, 302);
});

admin.post(`${SIGNALS}/streams/:id/delete`, async (c) => {
  const id = Number(c.req.param("id"));
  const name = (await c.env.DB.prepare("SELECT name FROM ssf_streams WHERE id = ?").bind(id).first<{ name: string }>())?.name ?? String(id);
  await c.env.DB.prepare("DELETE FROM ssf_streams WHERE id = ?").bind(id).run();
  await audit(consoleCtx(c), "ssf.stream_deleted", name);
  return c.redirect(`${SIGNALS}?saved=1`, 302);
});

admin.post(`${SIGNALS}/drain`, async (c) => {
  const r = await drainSsfOutbox(c.env);
  return c.redirect(`${SIGNALS}?drained=${encodeURIComponent(`${r.sent} sent, ${r.failed} failed`)}`, 302);
});

admin.post(`${SIGNALS}/transmitters`, async (c) => {
  const body = await c.req.parseBody();
  const name = String(body.name ?? "").trim();
  const issuer = String(body.issuer ?? "").trim();
  const jwksUrl = String(body.jwks_url ?? "").trim();
  try {
    const url = new URL(jwksUrl);
    if (url.protocol !== "https:") throw new Error("JWKS URL must be https.");
  } catch (e) {
    return c.redirect(`${SIGNALS}?error=${encodeURIComponent(e instanceof Error ? e.message : "JWKS URL must be https.")}`, 302);
  }
  if (!name || !issuer) return c.redirect(`${SIGNALS}?error=${encodeURIComponent("Name and issuer are required.")}`, 302);
  const dup = await c.env.DB.prepare("SELECT id FROM ssf_transmitters WHERE issuer = ?").bind(issuer).first();
  if (dup) return c.redirect(`${SIGNALS}?error=${encodeURIComponent(`A transmitter for issuer ${issuer} already exists.`)}`, 302);
  await c.env.DB.prepare("INSERT INTO ssf_transmitters (name, issuer, jwks_url, created_at) VALUES (?, ?, ?, ?)")
    .bind(name, issuer, jwksUrl, new Date().toISOString())
    .run();
  await audit(consoleCtx(c), "ssf.transmitter_created", name, { issuer });
  return c.redirect(`${SIGNALS}?saved=1`, 302);
});

admin.post(`${SIGNALS}/transmitters/:id/delete`, async (c) => {
  const id = Number(c.req.param("id"));
  const tx = await c.env.DB.prepare("SELECT name, issuer FROM ssf_transmitters WHERE id = ?").bind(id).first<{ name: string; issuer: string }>();
  await c.env.DB.prepare("DELETE FROM ssf_transmitters WHERE id = ?").bind(id).run();
  await audit(consoleCtx(c), "ssf.transmitter_deleted", tx?.name ?? String(id), { issuer: tx?.issuer });
  return c.redirect(`${SIGNALS}?saved=1`, 302);
});

// Outbound app registrations live under Applications (/admin/apps); the old
// list path still resolves so bookmarks survive.
admin.get("/admin/integrations/oidc", (c) => c.redirect("/admin/apps", 302));

// The instance-wide SAML settings: what this IdP publishes and the
// algorithm policy every outbound assertion follows. Per-app service
// providers are under Applications (/admin/apps).
admin.get("/admin/integrations/saml", async (c) => {
  const disabledAlgorithms = await getDisabledAlgorithms(c.env);
  return c.html(
    layout(
      c,
      "SAML",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${integrationIntro("This directory's SAML 2.0 identity provider - the endpoints and certificate service providers are pointed at. Service providers themselves are registered under <a href=\"/admin/apps\">Applications</a>.")}
      ${samlIdpBlock(c.env)}
      ${cardSection(`
        <h2>Disabled algorithms</h2>
        <p class="muted">An instance-wide deny list for SAML assertion encryption (IIP-ALG08): a service provider whose encryption policy selects a listed algorithm cannot be saved, and one already stored fails rather than emitting it. Entries match the content, key-transport, OAEP digest and MGF choices - a full URI or its short token (<code>aes256-cbc</code>, <code>rsa-oaep-mgf1p</code>, <code>sha1</code>) counts the same.</p>
        <form method="POST" action="/admin/saml/settings">
          <label for="disabled_algorithms">Algorithm URIs or tokens, one per line</label>
          <textarea id="disabled_algorithms" name="disabled_algorithms" rows="4" placeholder="http://www.w3.org/2001/04/xmlenc#aes256-cbc">${escapeHtml(disabledAlgorithms.join("\n"))}</textarea>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "SAML" }]
    )
  );
});

admin.post("/admin/saml/settings", async (c) => {
  const body = await c.req.parseBody();
  let saved: string[];
  try {
    saved = normalizeDisabledAlgorithms(String(body.disabled_algorithms ?? "").split("\n"));
  } catch (e) {
    return consoleError(c, e instanceof RangeError ? e.message : "Invalid algorithm list.", 400);
  }
  await setDisabledAlgorithms(c.env, saved);
  await logAudit(c.env, c.get("user"), "saml.disabled_algorithms_changed", undefined, { count: saved.length }, c.req.raw);
  return c.redirect("/admin/integrations/saml?saved=1", 302);
});

admin.get("/admin/integrations/api-keys", async (c) => {
  const apiKeys = await listApiKeys(c.env);
  return c.html(
    layout(
      c,
      "API keys",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        ${integrationIntro("Bearer tokens for the provisioning API at <code>/api/v1</code> &mdash; creating users and groups, registering clients and changing settings without a browser session. Every call a key makes is recorded in the log. See <code>docs/api.md</code>.", { href: "/admin/api-keys/new", label: "+ New key" })}
        ${
          apiKeys.length === 0
            ? '<p class="muted">No API keys yet.</p>'
            : `<table>
                <thead><tr><th>Name</th><th>Key</th><th>Scopes</th><th>Last used</th><th></th></tr></thead>
                <tbody>
                  ${apiKeys
                    .map(
                      (k) =>
                        `<tr${k.revoked_at ? ' style="opacity:.5;"' : ""}>
                          <td>${escapeHtml(k.name)}${k.revoked_at ? " <span class=\"muted\">(revoked)</span>" : ""}</td>
                          <td><code>${escapeHtml(k.prefix)}&hellip;</code></td>
                          <td>${parseScopes(k.scopes).map(escapeHtml).join(", ")}</td>
                          <td>${k.last_used_at ? ts(k.last_used_at) : '<span class="muted">never</span>'}</td>
                          <td><div class="row-actions">
                            <a href="/admin/audit?${new URLSearchParams({ actor: "api", search: `api-key:${k.name}` }).toString()}" style="margin-right:6px;">Activity</a>
                            ${
                              k.revoked_at
                                ? ""
                                : `${iconLink(`/admin/api-keys/${k.id}/edit`, "edit", "Edit")}<form method="POST" action="/admin/api-keys/${k.id}/revoke" ${confirmAttrs(
                                    `Anything using "${k.name}" stops working immediately. This cannot be undone.`,
                                    { title: "Revoke this API key?", action: "Revoke", danger: true }
                                  )}>${iconButton("logOut", "Revoke", { danger: true })}</form>`
                            }
                          </div></td>
                        </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "API keys" }]
    )
  );
});

/** The last SCIM events (syncs, failures, scope changes), newest last, as the log's starting content. */
async function scimLogTail(env: Env): Promise<string> {
  const { results: scimEvents } = await env.DB.prepare(
    "SELECT at, actor_upn, action, target, details FROM audit_log WHERE action LIKE 'scim.%' ORDER BY id DESC LIMIT 15"
  ).all<{ at: string; actor_upn: string | null; action: string; target: string | null; details: string | null }>();
  return scimEvents
    .reverse()
    .map((e) => {
      const d = e.details ? (JSON.parse(e.details) as Record<string, unknown>) : {};
      const summary =
        e.action === "scim.sync_all"
          ? `full sync: ${d.users ?? 0} user(s) in the last batch, ${d.groups ?? 0} group(s)${d.userErrors || d.groupErrors ? `, ${Number(d.userErrors ?? 0) + Number(d.groupErrors ?? 0)} failed` : ""}`
          : `${e.action.replace(/^scim\./, "").replace(/_/g, " ")}${e.target ? `: ${e.target}` : ""}`;
      return `[${e.at.slice(0, 19).replace("T", " ")}] ${summary}${e.actor_upn ? ` (${e.actor_upn})` : ""}`;
    })
    .join("\n");
}

/** A target's endpoint reduced to its host, for list displays. */
function scimHost(endpoint: string): string {
  try {
    return endpoint ? new URL(endpoint).host : "";
  } catch {
    return endpoint;
  }
}

/** One mapping row in the inbound-mapping table (parallel map_target/map_expr/map_enabled arrays). */
function scimMappingRowHtml(m?: { target: string; expression: string; enabled: boolean }): string {
  return `<tr class="mapping-row">
    <td><input type="text" name="map_target" value="${escapeHtml(m?.target ?? "")}" placeholder="display_name" list="scim-map-targets" required style="margin:0;" /></td>
    <td><input type="text" name="map_expr" value="${escapeHtml(m?.expression ?? "")}" placeholder='name.givenName + " " + name.familyName' required style="margin:0; font-family:monospace;" /></td>
    <td style="text-align:center;"><input type="hidden" name="map_enabled" value="${m && !m.enabled ? 0 : 1}" /><input type="checkbox" ${m && !m.enabled ? "" : "checked"} data-mirror-prev style="width:auto; margin:0;" /></td>
    <td>${iconButton("trash", "Remove mapping", { danger: true, type: "button", attrs: 'data-remove-closest=".mapping-row"' })}</td>
  </tr>`;
}

admin.get("/admin/integrations/scim", async (c) => {
  const targets = await listScimTargets(c.env);
  const mappings = await listScimMappings(c.env);
  const correlationKeys = await getCorrelationKeys(c.env);
  const masteredFields = await getMasteredFields(c.env);
  // Per-target pushed counts for the list (one grouped query each way).
  const [{ results: userCounts }, { results: groupCounts }] = await Promise.all([
    c.env.DB.prepare("SELECT target_id, COUNT(*) AS n FROM scim_user_links GROUP BY target_id").all<{ target_id: number; n: number }>(),
    c.env.DB.prepare("SELECT target_id, COUNT(*) AS n FROM scim_group_links GROUP BY target_id").all<{ target_id: number; n: number }>(),
  ]);
  const usersBy = new Map(userCounts.map((r) => [r.target_id, r.n]));
  const groupsBy = new Map(groupCounts.map((r) => [r.target_id, r.n]));
  const scimLog = await scimLogTail(c.env);
  return c.html(
    layout(
      c,
      "SCIM provisioning",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        ${integrationIntro("FlareID acts as a SCIM 2.0 <em>client</em>, pushing users and groups to one or more SCIM servers &mdash; for example the endpoint and secret Cloudflare generates once you enable SCIM on this IdP's Access identity provider. Each target has its own scope and push tuning.", { href: "/admin/integrations/scim/new", label: "+ New target" })}
        ${
          targets.length === 0
            ? '<p class="muted">No SCIM targets yet &mdash; users and groups are not being pushed anywhere.</p>'
            : `<table>
                <thead><tr><th>Name</th><th>Endpoint</th><th>Scope</th><th>Pushed</th><th>Status</th></tr></thead>
                <tbody>
                  ${targets
                    .map(
                      (t) =>
                        `<tr${t.enabled ? "" : ' style="opacity:.55;"'}>
                          <td><a href="/admin/integrations/scim/${t.id}">${escapeHtml(t.name)}</a></td>
                          <td><code>${escapeHtml(scimHost(t.endpoint) || "—")}</code></td>
                          <td>${t.scope.mode === "all" ? "All groups" : `${t.scope.groupIds.length} group${t.scope.groupIds.length === 1 ? "" : "s"}`}</td>
                          <td class="muted">${usersBy.get(t.id) ?? 0} user${(usersBy.get(t.id) ?? 0) === 1 ? "" : "s"}, ${groupsBy.get(t.id) ?? 0} group${(groupsBy.get(t.id) ?? 0) === 1 ? "" : "s"}</td>
                          <td><span class="badge ${t.enabled ? "badge-active" : "badge-disabled"}">${t.enabled ? "Enabled" : "Disabled"}</span></td>
                        </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      ${cardSection(`
        <h2>Inbound attribute mapping</h2>
        <p class="muted">FlareID is also a SCIM <em>server</em>: an upstream provisioner (an HR system or another IdP) writes users over <code>/scim/v2</code> with a <code>directory:write</code> API key. Each row rewrites one field with an expression evaluated over the incoming SCIM body &mdash; fields with no row keep the standard mapping. A row whose expression yields nothing leaves the field alone on PATCH but clears it on PUT. These rows are the <code>scim-in</code> channel on <a href="/admin/flows">Flows</a>, where the same engine drives JIT, outbound SCIM, OIDC claims and dynamic-group rules &mdash; the full function list lives there. Use <code>custom.&lt;key&gt;</code> for a custom attribute.</p>
        <datalist id="scim-map-targets">${USER_MAPPING_TARGETS.map((t) => `<option value="${t}"></option>`).join("")}</datalist>
        <form method="POST" action="/admin/scim/mappings">
          <table>
            <thead><tr><th style="width:220px;">Field</th><th>Expression</th><th style="width:60px;">On</th><th style="width:40px;"></th></tr></thead>
            <tbody id="mapping-rows">
              ${mappings.map(scimMappingRowHtml).join("")}
            </tbody>
          </table>
          <template id="mapping-row-template">${scimMappingRowHtml()}</template>
          <div class="form-actions end">
            <button type="button" class="secondary" data-append-template="mapping-row-template" data-append-to="mapping-rows">+ Add mapping</button>
            <button class="primary" type="submit">Save mappings</button>
          </div>
        </form>
      `)}
      ${cardSection(`
        <h2>Correlation</h2>
        <p class="muted">When an inbound create names a userName nobody holds, these keys are tried in order to adopt an existing account instead &mdash; a rehire, or a feed re-pointed at FlareID. The first key with a match decides; one match adopts, several is a conflict. Leave empty to refuse every duplicate as usual.</p>
        <form method="POST" action="/admin/scim/correlation">
          <label for="correlation_keys">Match keys, in order <span class="muted">(${CORRELATION_KEYS.join(", ")})</span></label>
          <input type="text" id="correlation_keys" name="correlation_keys" value="${escapeHtml(correlationKeys.join(", "))}" placeholder="emails, employee_number" />
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Field mastering</h2>
        <p class="muted">Fields mastered by the provisioner are read-only everywhere else: only inbound SCIM writes change them, the user editor shows them without inputs, and the admin API refuses them &mdash; so HR-owned data like job title or department can't drift between syncs.</p>
        <form method="POST" action="/admin/scim/mastering">
          <label for="mastered_fields">Mastered fields <span class="muted">(${MASTERING_FIELDS.join(", ")}, or custom.&lt;key&gt;)</span></label>
          <input type="text" id="mastered_fields" name="mastered_fields" value="${escapeHtml(masteredFields.join(", "))}" placeholder="job_title, department, manager" />
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Sync log</h2>
        ${codeBlock(scimLog || "No syncs yet.", { id: "scim-log" })}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "SCIM provisioning" }]
    )
  );
});

admin.get("/admin/integrations/scim/new", async (c) => {
  const { results: scopeGroups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<Pick<GroupRow, "id" | "name">>();
  // Reached from an app's "Set up provisioning" link: the target is stored
  // linked to that app and shows in its Provisioning card.
  const app = await linkedApp(c.env, c.req.query("app_type"), c.req.query("app_id"));
  return c.html(
    layout(
      c,
      "New SCIM target",
      `
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <p class="sub">Each target is one downstream SCIM server with its own credential, scope and push tuning.${app ? ` This one will be linked to <a href="${appEditUrl(app.type, app.id)}">${escapeHtml(app.name)}</a>.` : ""}</p>
        <form method="POST" action="/admin/scim/targets">
          ${app ? `<input type="hidden" name="app_type" value="${app.type}" /><input type="hidden" name="app_id" value="${app.id}" />` : ""}
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required placeholder="e.g. Cloudflare Access, Google Workspace" />
          <div class="field-row">
            <div>
              <label for="endpoint">SCIM endpoint (base URL)</label>
              <input type="text" id="endpoint" name="endpoint" required placeholder="https://api.cloudflare.com/client/v4/accounts/&lt;account_id&gt;/access/scim" />
            </div>
            <div>
              <label for="secret">SCIM secret</label>
              <input type="password" id="secret" name="secret" required autocomplete="new-password" placeholder="Bearer token from the target" />
              <p class="muted" style="margin-top:-6px;">Write-only: it is never shown again after saving.</p>
            </div>
          </div>
          <label style="font-weight:400;"><input type="checkbox" name="enabled" value="1" checked style="width:auto; display:inline; margin-right:6px;" /> Enabled &mdash; push to this target as soon as it saves</label>
          <h3 style="margin-top:18px;">Sync scope</h3>
          <label><input type="radio" name="mode" value="all" checked data-hide="scim-scope-groups" style="width:auto; display:inline; margin-right:6px;" /> All groups</label>
          <label><input type="radio" name="mode" value="selected" data-show="scim-scope-groups" style="width:auto; display:inline; margin-right:6px;" /> Specific groups only</label>
          <div id="scim-scope-groups" style="display:none; margin-top:8px;">
            ${multiSelect("group_ids", scopeGroups.map((g) => ({ id: g.id, label: g.name })), new Set<number>(), "Search groups...")}
          </div>
          <div class="form-actions" style="margin-top:16px;">
            <button class="primary" type="submit">Create target</button>
            ${cancelLink(app ? appEditUrl(app.type, app.id) : "/admin/integrations/scim", "Cancel")}
          </div>
        </form>
      `)}
      `,
      app
        ? [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: app.name, href: appEditUrl(app.type, app.id) }, { label: "New SCIM target" }]
        : [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("scim"), { label: "New target" }]
    )
  );
});

admin.get("/admin/integrations/scim/:id", async (c) => {
  const target = await getScimTarget(c.env, Number(c.req.param("id")));
  if (!target) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const { results: scopeGroups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<Pick<GroupRow, "id" | "name">>();
  const app = target.appType && target.appId ? await linkedApp(c.env, target.appType, target.appId) : null;
  const [{ n: pushedUsers }, { n: pushedGroups }, { n: queued }] = await Promise.all([
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM scim_user_links WHERE target_id = ?").bind(target.id).first<{ n: number }>().then((r) => r ?? { n: 0 }),
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM scim_group_links WHERE target_id = ?").bind(target.id).first<{ n: number }>().then((r) => r ?? { n: 0 }),
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM scim_deprovision_queue WHERE target_id = ?").bind(target.id).first<{ n: number }>().then((r) => r ?? { n: 0 }),
  ]);
  return c.html(
    layout(
      c,
      target.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      <form method="POST" action="/admin/scim/targets/${target.id}">
      ${cardSection(`
        <div class="row between" style="margin:0 0 14px 0; align-items:flex-start;">
          <h2 style="margin:0;">Connection</h2>
          <span class="badge ${target.enabled ? "badge-active" : "badge-disabled"}">${target.enabled ? "Enabled" : "Disabled"}</span>
        </div>
        <p class="muted">${pushedUsers} user${pushedUsers === 1 ? "" : "s"} and ${pushedGroups} group${pushedGroups === 1 ? "" : "s"} pushed${queued ? `; ${queued} deletion${queued === 1 ? "" : "s"} queued` : ""}.${app ? ` Linked to <a href="${appEditUrl(app.type, app.id)}">${escapeHtml(app.name)}</a>.` : ""} Pushed attributes follow <a href="/admin/flows/edit?channel=scim-out&owner=${target.id}">this target's mappings</a>.</p>
        <div class="field-row">
          <div>
            <label for="name">Name</label>
            <input type="text" id="name" name="name" required value="${escapeHtml(target.name)}" />
          </div>
          <div>
            <label for="endpoint">SCIM endpoint (base URL)</label>
            <input type="text" id="endpoint" name="endpoint" value="${escapeHtml(target.endpoint)}" placeholder="https://api.cloudflare.com/client/v4/accounts/&lt;account_id&gt;/access/scim" />
          </div>
        </div>
        <div class="field-row">
          <div>
            <label for="secret">SCIM secret</label>
            <input type="password" id="secret" name="secret" value="" autocomplete="new-password" placeholder="${target.secret ? "Saved - leave blank to keep it" : "Bearer token from the target"}" />
            <p class="muted" style="margin-top:-10px;">Write-only: it is never shown again after saving.</p>
          </div>
          <div style="display:flex; align-items:center;">
            <label style="font-weight:400; margin:0;"><input type="checkbox" name="enabled" value="1" ${target.enabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Enabled</label>
          </div>
        </div>
      `)}

      <div class="two-col">
        ${cardSection(`
          <h2>Sync scope</h2>
          <p class="muted">Push everyone, or only members of specific groups. Users and groups outside scope are removed from the SCIM server if they had previously been synced.</p>
          <label style="font-weight:400;"><input type="radio" name="mode" value="all" ${target.scope.mode === "all" ? "checked" : ""} data-hide="scim-scope-groups" style="width:auto; display:inline; margin-right:6px;" /> All groups</label>
          <label style="font-weight:400;"><input type="radio" name="mode" value="selected" ${target.scope.mode === "selected" ? "checked" : ""} data-show="scim-scope-groups" style="width:auto; display:inline; margin-right:6px;" /> Specific groups only</label>
          <div id="scim-scope-groups" style="display:${target.scope.mode === "selected" ? "block" : "none"}; margin-top:8px;">
            ${multiSelect("group_ids", scopeGroups.map((g) => ({ id: g.id, label: g.name })), new Set(target.scope.groupIds), "Search groups...")}
          </div>
        `)}
        ${cardSection(`
          <h2>Sync tuning</h2>
          <p class="muted">How hard to push against this SCIM server. Receivers backed by a single object (Cloudflare Access's endpoint is) reject large bodies and dense requests - lower both if syncs come back with errors.</p>
          <div class="field-row">
            <div>
              <label for="pace_ms">Pause between requests (ms)</label>
              <input type="number" id="pace_ms" name="pace_ms" min="0" max="10000" step="50" value="${target.paceMs}" />
            </div>
            <div>
              <label for="members_per_request">Members per group request</label>
              <input type="number" id="members_per_request" name="members_per_request" min="1" max="500" value="${target.membersPerRequest}" />
            </div>
          </div>
          <div class="field-row">
            <div>
              <label for="sync_batch">Users per sync batch</label>
              <input type="number" id="sync_batch" name="sync_batch" min="10" max="500" value="${target.syncBatchSize}" />
            </div>
            <div></div>
          </div>
        `)}
      </div>
      <div class="form-actions" style="margin:0 0 18px;">
        ${formButton("Delete", `/admin/scim/targets/${target.id}/delete`, {
          variant: "danger",
          confirm: confirmAttrs(`Deleting "${target.name}" stops pushing to it and forgets which users and groups were pushed. The objects already created on the SCIM server are left there.`, { title: `Delete the SCIM target "${target.name}"?`, action: "Delete", danger: true }),
        })}
        ${cancelLink("/admin/integrations/scim")}<button class="primary" type="submit">Save</button>
      </div>
      </form>

              ${cardSection(`
          <h2>Test &amp; sync</h2>
          <p class="muted">Test the connection, then push every in-scope user and group. New and changed users and groups are pushed automatically from then on.</p>
          <div class="form-actions end" style="margin-top:0;">
            <button class="secondary" type="button" data-scim="test" data-scim-target="${target.id}" ${target.enabled ? "" : "disabled"}>Test connection</button>
            <button class="primary" type="button" data-scim="sync" data-scim-target="${target.id}" ${target.enabled ? "" : "disabled"}>Sync all now</button>
          </div>
          <div id="scim-status"></div>
          <h3 style="margin-top:18px;">Sync log</h3>
          ${codeBlock((await scimLogTail(c.env)) || "No syncs yet.", { id: "scim-log" })}
        `)}

      ${scriptTag(SCIM_SCRIPT)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("scim"), { label: target.name }]
    )
  );
});

// ---------- API keys ----------

const SCOPE_DESCRIPTIONS: Record<ApiScope, string> = {
  "directory:read": "Read users, groups, domains and registered clients",
  "directory:write": "Create and update users and groups, manage domains (cannot grant or reset Super Admins)",
  "clients:write": "Register OIDC relying parties",
  "settings:write": "Change settings, branding and SCIM configuration (cannot create administrators)",
  admin: "Everything above, plus minting further API keys",
};

admin.get("/admin/api-keys/new", async (c) => {
  return c.html(
    layout(
      c,
      "New API key",
      cardSection(`
        <p class="sub">The token is shown once, when the key is created, and is stored only as a hash &mdash; there is no way to recover it afterwards.</p>
        <form method="POST" action="/admin/api-keys">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required placeholder="e.g. terraform, ci, laptop-deploy" />
          <p class="muted" style="margin:4px 0 14px;">What is using it. This is what appears in the audit log against everything the key does.</p>

          <label>Permissions</label>
          ${permissionMatrix(new Set(["*"]), { roles: await listRoles(c.env) })}

          <div class="form-actions" style="margin-top:16px;">
            <button class="primary" type="submit">Create key</button>
            ${cancelLink("/admin/integrations/api-keys", "Cancel")}
          </div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("api-keys"), { label: "New API key" }]
    )
  );
});

/**
 * The permission picker, shared by roles and API keys: one row per area with
 * none / read / write, a "full access" switch, and (for keys) a role to copy.
 */
function permissionMatrix(selected: Set<string>, opts: { roles?: RoleRow[]; self?: boolean } = {}): string {
  const full = selected.has("*");
  const level = (area: string) => (selected.has(`${area}:write`) ? "write" : selected.has(`${area}:read`) ? "read" : "");
  const rows = AREAS.map((a) => {
    const choices: [string, string][] = [["", "None"], ...("writeOnly" in a ? [] : [["read", "Read"] as [string, string]]), ...("readOnly" in a ? [] : [["write", "Change"] as [string, string]])];
    return `<tr><td>${escapeHtml(a.label)} <span class="muted">${escapeHtml(a.group)}</span></td><td>${choices
      .map(([v, l]) => `<label style="display:inline-flex; gap:4px; margin:0 12px 0 0; font-weight:400;"><input type="radio" name="perm_${a.key}" value="${v}" ${level(a.key) === v ? "checked" : ""} style="width:auto; margin:0;" /> ${l}</label>`)
      .join("")}</td></tr>`;
  }).join("");
  const selfRows = opts.self
    ? SELF_PERMISSIONS.map((p) => `<tr><td>${escapeHtml(p.label)} <span class="muted">Self-service</span></td><td><label style="font-weight:400; margin:0;"><input type="checkbox" name="perm_self" value="${p.key}" ${selected.has(p.key) ? "checked" : ""} style="width:auto; margin:0 6px 0 0;" /> Allowed</label></td></tr>`).join("")
    : "";
  const template = opts.roles?.length
    ? `<div class="row" style="justify-content:flex-start; gap:8px; margin-bottom:8px;"><label for="perm_template" style="margin:0;">Start from a role</label>
        <select id="perm_template" data-perm-template style="width:auto; margin:0;"><option value="">Choose...</option>${opts.roles
          .map((r) => `<option value="${escapeHtml(r.permissions)}">${escapeHtml(r.name)}</option>`)
          .join("")}</select></div>`
    : "";
  return `${template}
    <label style="font-weight:400;"><input type="checkbox" name="perm_full" value="1" ${full ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> <strong>Full access</strong> (everything, like a Super Admin)</label>
    <table class="perm-matrix" style="margin-top:8px;"><tbody>${rows}${selfRows}</tbody></table>
    ${opts.roles?.length ? scriptTag(PERM_TEMPLATE_SCRIPT) : ""}`;
}

/** Copies a role's permissions into the picker (API keys keep a copy, never a live link). */
const PERM_TEMPLATE_SCRIPT = `(function(){
  var sel=document.querySelector("[data-perm-template]"); if(!sel) return;
  sel.addEventListener("change",function(){
    if(!sel.value) return; var perms=JSON.parse(sel.value); var f=sel.closest("form");
    f.querySelector("input[name=perm_full]").checked=perms.indexOf("*")>=0;
    f.querySelectorAll("input[type=radio][name^=perm_]").forEach(function(r){
      var area=r.name.slice(5), lvl=perms.indexOf(area+":write")>=0?"write":perms.indexOf(area+":read")>=0?"read":"";
      r.checked=(r.value===lvl);
    });
  });
})();`;

function readPermissionMatrix(body: Record<string, unknown>): string[] {
  if (body.perm_full) return ["*"];
  const out: string[] = [];
  for (const a of AREAS) {
    const v = String(body[`perm_${a.key}`] ?? "");
    if (v === "read" || v === "write") out.push(`${a.key}:${v}`);
  }
  const self = body.perm_self;
  for (const p of Array.isArray(self) ? self : self ? [self] : []) if (SELF_PERMISSIONS.some((s) => s.key === String(p))) out.push(String(p));
  return out.filter(isPermission);
}

admin.post("/admin/api-keys", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const name = String(body.name ?? "").trim();
  if (!name) return consoleError(c, "Enter a name.", 400);

  const requested = readPermissionMatrix(body);
  // Same rule as roles: a key carries only permissions its creator holds ("*" only from a Super Admin).
  const mine = c.get("access");
  const beyond = requested.filter((p) => (p === "*" ? !mine.isSuper : !grants(mine.perms, p)));
  if (beyond.length) return consoleError(c, `You cannot give a key permissions you do not hold: ${beyond.join(", ")}.`, 403);
  // Choosing nothing used to mint an admin key. It now asks again.
  if (requested.length === 0) return consoleError(c, "Choose at least one permission for the key.", 400);
  const scopes: ApiScope[] = requested;

  const created = await createApiKey(c.env, { name, scopes, createdBy: c.get("user").upn });
  await logAudit(c.env, c.get("user"), "api_key.created", name, { scopes }, c.req.raw);

  return c.html(
    layout(
      c,
      "API key created",
      cardSection(`
        <p class="success">Created "${escapeHtml(name)}" with ${scopes.map((s) => `<code>${s}</code>`).join(", ")}.</p>
        ${secretBlock("API key - copy this now", created.token)}
        <p class="muted">Send it as <code>Authorization: Bearer &lt;token&gt;</code>.</p>
        <a href="/admin/integrations/api-keys"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("api-keys"), { label: "API key created" }]
    )
  );
});

admin.get("/admin/api-keys/:id/edit", async (c) => {
  const key = await c.env.DB.prepare("SELECT * FROM api_keys WHERE id = ?").bind(Number(c.req.param("id"))).first<ApiKeyRow>();
  if (!key) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  if (key.revoked_at) return consoleError(c, "That key is revoked - its permissions are history now.", 409);
  return c.html(
    layout(
      c,
      `Edit API key: ${key.name}`,
      cardSection(`
        <form method="POST" action="/admin/api-keys/${key.id}/edit">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required value="${escapeHtml(key.name)}" />
          <p class="muted" style="margin:4px 0 14px;">What is using it. This is what appears in the audit log against everything the key does.</p>

          <label>Permissions</label>
          ${permissionMatrix(new Set(parseScopes(key.scopes)), { roles: await listRoles(c.env) })}
          <p class="muted" style="margin-top:8px;">Changing permissions takes effect on the key's next request - the token itself stays the same.</p>

          <div class="form-actions" style="margin-top:16px;">
            <button class="primary" type="submit">Save</button>
            ${cancelLink("/admin/integrations/api-keys", "Cancel")}
          </div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("api-keys"), { label: key.name }]
    )
  );
});

admin.post("/admin/api-keys/:id/edit", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const name = String(body.name ?? "").trim();
  if (!name) return consoleError(c, "Enter a name.", 400);
  const requested = readPermissionMatrix(body);
  // Same rule as creation: a key can only carry permissions the editor holds.
  const mine = c.get("access");
  const beyond = requested.filter((p) => (p === "*" ? !mine.isSuper : !grants(mine.perms, p)));
  if (beyond.length) return consoleError(c, `You cannot give a key permissions you do not hold: ${beyond.join(", ")}.`, 403);
  if (requested.length === 0) return consoleError(c, "Choose at least one permission for the key.", 400);
  await updateKey(consoleCtx(c), Number(c.req.param("id")), { name, scopes: requested });
  return c.redirect("/admin/integrations/api-keys?saved=1", 302);
});

admin.post("/admin/api-keys/:id/revoke", async (c) => {
  await revokeKey(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/integrations/api-keys?saved=1", 302);
});

/** Labels for the assigned-people picker: upn plus display name when one is set. */
async function assignedUserLabels(env: Env, raw: string | null | undefined): Promise<{ id: number; label: string }[]> {
  const ids = parseAssignedUserIds(raw);
  if (ids.length === 0) return [];
  const { results } = await env.DB.prepare("SELECT id, upn, display_name FROM users WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(ids)).all<Pick<UserRow, "id" | "upn" | "display_name">>();
  const byId = new Map(results.map((u) => [u.id, u]));
  return ids.filter((id) => byId.has(id)).map((id) => {
    const u = byId.get(id)!;
    return { id, label: u.display_name ? `${u.upn} (${u.display_name})` : u.upn };
  });
}

/**
 * The "who can use this app" block shared by the OIDC and SAML forms:
 * everyone vs assigned people/groups, plus the sign-in strength and
 * requestability switches.
 */
/** Settings | Access | Policies | Provisioning nav for the two app edit pages. */
function appTabs(baseUrl: string, active: "settings" | "access" | "policies" | "provisioning"): string {
  const tabs: [string, string][] = [["settings", "Settings"], ["access", "Access"], ["policies", "Policies"], ["provisioning", "Provisioning"]];
  return `<div class="range-tabs" style="margin-bottom:16px;">${tabs
    .map(([key, label]) => `<a href="${baseUrl}${key === "settings" ? "" : `?tab=${key}`}" class="${key === active ? "active" : ""}">${label}</a>`)
    .join("")}</div>`;
}

function appAccessFields(opts: { accessMode?: string; groups: Pick<GroupRow, "id" | "name">[]; assignedGroups: number[]; assignedUsers: { id: number; label: string }[]; requireMfa: boolean; requestable: boolean }): string {
  const restricted = opts.accessMode !== "everyone";
  return `
    <label style="margin-top:12px;">Who can use this app</label>
    <label style="font-weight:400;"><input type="radio" name="access_mode" value="restricted" ${restricted ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Only the people and groups assigned below</label>
    <label style="font-weight:400;"><input type="radio" name="access_mode" value="everyone" ${restricted ? "" : "checked"} style="width:auto; display:inline; margin-right:6px;" /> Everyone</label>
    <div class="field-row" style="margin-top:10px;">
      <div>
        <label>Assigned people</label>
        <p class="muted" style="margin-top:-6px;">Individual users who may see and sign in to this app.</p>
        ${remoteMultiSelect("assigned_user_ids", "/admin/users/lookup", opts.assignedUsers, "Search people...")}
      </div>
      <div>
        <label>Assigned groups</label>
        <p class="muted" style="margin-top:-6px;">Members of these groups - static or rule-driven - may use the app.</p>
        ${multiSelect("assigned_group_ids", opts.groups.map((g) => ({ id: g.id, label: g.name })), new Set(opts.assignedGroups), "Search groups...")}
      </div>
    </div>
    <label style="font-weight:400; margin-top:12px;"><input type="checkbox" name="requestable" value="1" ${opts.requestable ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Let people request access</label>
    <p class="muted" style="margin-top:-6px;">A restricted app appears under My account &rarr; Access; approving a request adds the person to Assigned people.</p>`;
}

/** The Policies tab: which authentication policy a sign-in must satisfy before it may open this app. */
function appPolicyFields(opts: { policies: Pick<AuthPolicyRow, "id" | "name" | "requirement" | "device_cert" | "max_risk">[]; policyId: number | null | undefined; requireMfa: boolean }): string {
  const describe = (p: (typeof opts.policies)[number]) => {
    const bits = [p.requirement === "mfa" ? "second factor" : "password only"];
    if (p.device_cert) bits.push("device certificate");
    if (p.max_risk) bits.push(`risk at most ${p.max_risk}`);
    return bits.join(" + ");
  };
  return `
    <label for="policy_id">Authentication policy</label>
    <select id="policy_id" name="policy_id">
      <option value="0" ${!opts.policyId ? "selected" : ""}>Person's own policy (default)</option>
      ${opts.policies.map((p) => `<option value="${p.id}" ${opts.policyId === p.id ? "selected" : ""}>${escapeHtml(p.name)} (${describe(p)})</option>`).join("")}
    </select>
    <p class="muted" style="margin-top:2px;">The policy a sign-in must satisfy to open this app. Defined under <a href="/admin/security/policies">Security &rarr; Policies</a>; "Person's own policy" applies each sign-in's own requirement plus any extra needs below. A bound policy's device-certificate and risk conditions deny sign-in outright.</p>
    <label style="font-weight:400; margin-top:12px;"><input type="checkbox" name="require_mfa" value="1" ${opts.requireMfa ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require a second-factor sign-in</label>
    <p class="muted" style="margin-top:-6px;">The sign-in must have used a second factor - authenticator code, passkey, email code, security questions, backup code or a federated identity. Sessions without one are asked for it when they open the app. The simpler option when you do not need a named policy.</p>`;
}

/** The v3 client settings, shared by the new and edit forms. */
function clientSettingsFields(client: OAuthClientRow | undefined, groups: Pick<GroupRow, "id" | "name">[], assignedUsers: { id: number; label: string }[], opts: { includeAccess?: boolean } = {}): string {
  const allowed = new Set(client ? parseAllowedClaims(client) : CLAIM_GROUPS);
  const extraClaimsHint = client
    ? `<p class="muted" style="margin-top:4px;">Computed or renamed claims for this app are on <a href="/admin/flows/edit?channel=oidc&owner=${encodeURIComponent(client.client_id)}">Flows &rarr; OIDC claims</a>.</p>`
    : "";
  const logoutUris: string[] = client ? JSON.parse(client.post_logout_redirect_uris || "[]") : [];
  const redirectUris: string[] = client ? JSON.parse(client.redirect_uris || "[]") : [];
  const trusted = client ? client.trusted === 1 : true;
  const alg = client?.id_token_signed_response_alg ?? "RS256";
  const assigned = new Set(client ? parseAssignedGroupIds(client.assigned_groups) : []);
  return `
    <div class="field-row">
      <div>
        <label for="redirect_uris">Redirect URIs (one per line)</label>
        <textarea id="redirect_uris" name="redirect_uris" rows="3" placeholder="https://your-team.cloudflareaccess.com/cdn-cgi/access/callback">${escapeHtml(redirectUris.join("\n"))}</textarea>
      </div>
      <div>
        <label for="post_logout_redirect_uris">Post-logout redirect URIs (one per line)</label>
        <textarea id="post_logout_redirect_uris" name="post_logout_redirect_uris" rows="3" placeholder="https://app.example.com/signed-out">${escapeHtml(logoutUris.join("\n"))}</textarea>
        <p class="muted" style="margin-top:2px;">Where RP-initiated logout (<code>/oidc/logout</code>) may send the browser afterwards.</p>
      </div>
    </div>
    <div class="field-row">
      <div>
        <label for="id_token_signed_response_alg">ID token signing algorithm</label>
        <select id="id_token_signed_response_alg" name="id_token_signed_response_alg">
          ${ID_TOKEN_ALGS.map((a) => `<option value="${a}" ${a === alg ? "selected" : ""}>${a}${a === "RS256" ? " (default)" : ""}</option>`).join("")}
        </select>
        <p class="muted" style="margin-top:2px;">RS256 works with every OIDC library; choose ES256 only if the app supports it.</p>
      </div>
      <div>
        <label for="frontchannel_logout_uri">Front-channel logout URI</label>
        <input type="text" id="frontchannel_logout_uri" name="frontchannel_logout_uri" value="${escapeHtml(client?.frontchannel_logout_uri ?? "")}" placeholder="https://app.example.com/logout/frontchannel" />
        <p class="muted" style="margin-top:2px;">Loaded in a hidden frame on sign-out so the app can end its session. https only.</p>
      </div>
      <div>
        <label for="logo_uri">Logo URL (launchpad icon)</label>
        <input type="text" id="logo_uri" name="logo_uri" value="${escapeHtml(client?.logo_uri ?? "")}" placeholder="https://your-idp.example/catalog-icons/cloudflare.svg" />
        <p class="muted" style="margin-top:2px;">Shown on the sign-in page and the app tile in the user's Applications page. https only.</p>
      </div>
    </div>
    <label style="font-weight:400; margin-top:8px;"><input type="checkbox" name="trusted" value="1" ${trusted ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Trusted first-party app &mdash; skip the consent screen</label>
    ${opts.includeAccess === false ? "" : appAccessFields({ accessMode: client?.access_mode, groups, assignedGroups: [...assigned], assignedUsers, requireMfa: client?.require_mfa === 1, requestable: client?.requestable === 1 })}
    <label style="margin-top:12px;">Claims this app may receive</label>
    <p class="muted" style="margin-top:-6px;">Released only when the app also asks for them by scope (<code>email</code>, <code>profile</code>, <code>groups</code>). Untick anything it does not need.</p>
    ${CLAIM_GROUPS.map((g) => `<label style="font-weight:400;"><input type="checkbox" name="allowed_claims" value="${g}" ${allowed.has(g) ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> ${escapeHtml(CLAIM_GROUP_LABELS[g])}</label>`).join("")}
    ${extraClaimsHint}`;
}

admin.get("/admin/clients/new", async (c) => {
  const { results: groups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<Pick<GroupRow, "id" | "name">>();
  return c.html(
    layout(
      c,
      "New OIDC client",
      cardSection(`
        <form method="POST" action="/admin/clients">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" placeholder="Cloudflare Access" required />
          <label>Client type</label>
          <label style="font-weight:400;"><input type="radio" name="client_type" value="confidential" checked style="width:auto; display:inline; margin-right:6px;" /> Confidential &mdash; a server that can keep a secret (Cloudflare Access, a web backend)</label>
          <label style="font-weight:400;"><input type="radio" name="client_type" value="public" style="width:auto; display:inline; margin-right:6px;" /> Public &mdash; a single-page or native app: no secret, PKCE required, loopback redirects on any port</label>
          ${clientSettingsFields(undefined, groups, [])}
          <div class="form-actions end">${cancelLink("/admin/apps")}<button class="primary" type="submit">Create client</button></div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: "New client" }]
    )
  );
});

admin.post("/admin/clients", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const isPublic = body.client_type === "public";
  const settings = readClientSettings(body);
  const name = String(body.name ?? "").trim();
  const redirectUris = String(body.redirect_uris ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!name) return consoleError(c, "Enter a name.", 400);

  const { id, clientId, clientSecret } = await insertClient(c.env, {
    name,
    clientType: isPublic ? "public" : "confidential",
    redirectUris,
    settings,
    seededId: String(body.client_id ?? "").trim(),
    seededSecret: String(body.client_secret ?? "").trim(),
  });

  await logAudit(c.env, c.get("user"), "oidc_client.created", name, undefined, c.req.raw);

  return c.html(
    layout(
      c,
      "Client created",
      cardSection(`
        <p class="success">Created "${escapeHtml(name)}"${isPublic ? " as a public client: it has no secret, and must use PKCE (S256)" : ""}.</p>
        ${isPublic ? "" : secretBlock("Client secret", clientSecret)}
        ${oidcEndpointsBlock(c.env, clientId)}
        <a href="/admin/clients/${id}"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: "Client created" }]
    )
  );
});

admin.get("/admin/clients/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await c.env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(id).first<OAuthClientRow>();
  if (!client) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const tab = c.req.query("tab") ?? "settings";
  const [{ results: groups }, assignedUsers] = await Promise.all([
    c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<Pick<GroupRow, "id" | "name">>(),
    assignedUserLabels(c.env, client.assigned_users),
  ]);

  const base = `/admin/clients/${id}`;
  const tabs = appTabs(base, (["access", "policies", "provisioning"].includes(tab) ? tab : "settings") as "settings" | "access" | "policies" | "provisioning");
  let body: string;
  if (tab === "access") {
    body = cardSection(`
      <h2>Access</h2>
      <form method="POST" action="${base}/access">
        ${appAccessFields({ accessMode: client.access_mode, groups, assignedGroups: parseAssignedGroupIds(client.assigned_groups), assignedUsers, requireMfa: client.require_mfa === 1, requestable: client.requestable === 1 })}
        <div class="form-actions end">${cancelLink(base + "?tab=access")}<button class="primary" type="submit">Save</button></div>
      </form>`);
  } else if (tab === "policies") {
    const policies = await listPolicies(c.env);
    body = cardSection(`
      <h2>Policies</h2>
      <form method="POST" action="${base}/policies">
        ${appPolicyFields({ policies, policyId: client.policy_id, requireMfa: client.require_mfa === 1 })}
        <div class="form-actions end">${cancelLink(base + "?tab=policies")}<button class="primary" type="submit">Save</button></div>
      </form>`);
  } else if (tab === "provisioning") {
    body = await appProvisioningCard(c.env, "oidc", id);
  } else {
    body = cardSection(`
      ${oidcEndpointsBlock(c.env, client.client_id)}
      <form method="POST" action="${base}">
        <label for="name">Name</label>
        <input type="text" id="name" name="name" value="${escapeHtml(client.name)}" required />
        <p class="muted">Type: <strong>${client.client_type === "public" ? "Public (no secret, PKCE required)" : "Confidential"}</strong></p>
        ${clientSettingsFields(client, groups, assignedUsers, { includeAccess: false })}
        <div class="form-actions end">
          ${formButton("Delete", `${base}/delete`, { variant: "danger", confirm: confirmAttrs(`Anything still using this client_id will stop working immediately.`, { title: `Delete the OIDC client "${client.name}"?`, action: "Delete client", danger: true }) })}
          ${client.client_type === "public" ? "" : formButton("Rotate secret", `${base}/rotate-secret`)}
          ${cancelLink(base)}<button class="primary" type="submit">Save</button>
        </div>
      </form>`);
  }

  return c.html(
    layout(
      c,
      client.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${tabs}
      ${body}
      `,
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: client.name }]
    )
  );
});

admin.post("/admin/clients/:id/access", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await c.env.DB.prepare("SELECT name FROM oauth_clients WHERE id = ?").bind(id).first<{ name: string }>();
  if (!client) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v : v ? [v] : []).map(Number).filter((n) => Number.isInteger(n) && n > 0);
  await c.env.DB.prepare("UPDATE oauth_clients SET access_mode = ?, assigned_groups = ?, assigned_users = ?, requestable = ? WHERE id = ?")
    .bind(body.access_mode === "everyone" ? "everyone" : "restricted", JSON.stringify(list(body.assigned_group_ids)), JSON.stringify(list(body.assigned_user_ids)), body.requestable ? 1 : 0, id)
    .run();
  await logAudit(c.env, c.get("user"), "oidc_client.updated", client.name, { fields: "access" }, c.req.raw);
  return c.redirect(`/admin/clients/${id}?tab=access&saved=1`, 302);
});

admin.post("/admin/clients/:id/policies", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await c.env.DB.prepare("SELECT name FROM oauth_clients WHERE id = ?").bind(id).first<{ name: string }>();
  if (!client) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody();
  const policyId = Number(body.policy_id) > 0 ? Number(body.policy_id) : null;
  await assertPolicyExists(c.env, policyId);
  await c.env.DB.prepare("UPDATE oauth_clients SET require_mfa = ?, policy_id = ? WHERE id = ?")
    .bind(body.require_mfa ? 1 : 0, policyId, id)
    .run();
  await logAudit(c.env, c.get("user"), "oidc_client.updated", client.name, { fields: "policies" }, c.req.raw);
  return c.redirect(`/admin/clients/${id}?tab=policies&saved=1`, 302);
});

admin.post("/admin/clients/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  const settings = readClientSettings(body);
  const redirectUris = String(body.redirect_uris ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  await updateClient(consoleCtx(c), id, { name: String(body.name ?? "").trim(), redirectUris, ...settings });
  return c.redirect(`/admin/clients/${id}?saved=1`, 302);
});

admin.post("/admin/clients/:id/rotate-secret", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await getClientById(c.env, id);
  if (!client) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const clientSecret = await rotateClientSecret(consoleCtx(c), client);

  return c.html(
    layout(
      c,
      "Secret rotated",
      cardSection(`
        ${secretBlock(`New client secret for ${client.name}`, clientSecret)}
        ${oidcEndpointsBlock(c.env, client.client_id)}
        <a href="/admin/clients/${id}"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: client.name, href: `/admin/clients/${id}` }, { label: "Secret rotated" }]
    )
  );
});

admin.post("/admin/clients/:id/delete", async (c) => {
  const client = await getClientById(c.env, Number(c.req.param("id")));
  if (!client) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  await deleteClient(consoleCtx(c), client);
  return c.redirect("/admin/apps?saved=1", 302);
});

// ---------- SAML service providers ----------

/** What an SP administrator needs to point their service provider at this IdP. */
function samlIdpBlock(env: Env) {
  const entityId = idpEntityId(env);
  const expiry = env.SAML_SIGNING_CERT ? certNotAfter(env.SAML_SIGNING_CERT) : null;
  const expiryNote = expiry
    ? expiry.getTime() < Date.now()
      ? ` - <strong style="color:var(--fi-red);">expired ${ts(expiry.toISOString(), { dateOnly: true })}</strong>`
      : expiry.getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000
        ? ` - <strong style="color:var(--fi-amber);">expires ${ts(expiry.toISOString(), { dateOnly: true })}</strong>`
        : ` - expires ${ts(expiry.toISOString(), { dateOnly: true })}`
    : "";
  return `
    <div class="info-panel">
      <p class="muted" style="margin:0 0 8px 0;">Use these when configuring this service provider (e.g. Cloudflare Access's SAML identity provider fields):</p>
      <table style="margin:0;">
        ${copyableRow("Entity ID / Issuer", entityId, ' style="width:140px;"')}
        ${copyableRow("SSO URL", `${entityId}/saml/sso`)}
        ${copyableRow("Metadata URL", `${entityId}/saml/metadata`)}
        <tr><th>Signing certificate</th><td><a href="/saml/cert.pem">Download PEM</a>${expiryNote}</td></tr>
      </table>
      ${!isSamlConfigured(env) ? '<p class="error" style="margin:8px 0 0;">SAML_SIGNING_CERT / SAML_SIGNING_KEY_PKCS8 are not configured - run <code>npm run saml:keygen</code> and set them before this IdP can answer requests.</p>' : ""}
    </div>
  `;
}

/** Every cert-shaped thing in a pasted textarea: PEM blocks, or a single bare base64 blob. */
function spForm(v: Partial<SpFormValues>, action: string, submitLabel: string, groups: Pick<GroupRow, "id" | "name">[], assignedUsers: { id: number; label: string }[], opts: { includeAccess?: boolean; extraActions?: string } = {}): string {
  // Shown back in the write shape (name_format), not the stored one.
  const defsJson = (v.attributeDefinitions ?? []).map((d) => ({ name: d.name, field: d.field, ...(d.nameFormat ? { name_format: d.nameFormat } : {}) }));
  return `
    <form method="POST" action="${escapeHtml(action)}">
      <div class="field-row">
        <div>
          <label for="name">Name</label>
          <input type="text" id="name" name="name" value="${escapeHtml(v.name ?? "")}" placeholder="Cloudflare Access" required />
        </div>
        <div>
          <label for="entity_id">Entity ID (Issuer)</label>
          <input type="text" id="entity_id" name="entity_id" value="${escapeHtml(v.entityId ?? "")}" placeholder="https://your-team.cloudflareaccess.com" required />
        </div>
      </div>
      <div class="field-row">
        <div>
          <label for="logo_uri">Logo URL (launchpad icon)</label>
          <input type="text" id="logo_uri" name="logo_uri" value="${escapeHtml(v.logoUri ?? "")}" placeholder="https://your-idp.example/catalog-icons/slack.svg" />
          <p class="muted" style="margin-top:2px;">Shown on the app tile in the user's Applications page. https only; empty draws the app's initial.</p>
        </div>
        <div></div>
      </div>
      <label for="acs_urls">Assertion Consumer Service URLs (one per line)</label>
      <textarea id="acs_urls" name="acs_urls" rows="3" placeholder="https://your-team.cloudflareaccess.com/cdn-cgi/access/callback">${escapeHtml((v.acsUrls ?? []).join("\n"))}</textarea>
      <div class="field-row">
        <div>
          <label for="default_acs_url">Default ACS URL (used when the request omits one)</label>
          <input type="text" id="default_acs_url" name="default_acs_url" value="${escapeHtml(v.defaultAcsUrl ?? "")}" />
        </div>
        <div>
          <label for="nameid_format">NameID format</label>
          <select id="nameid_format" name="nameid_format">
            ${supportedNameIdFormats()
              .map((f) => `<option value="${f}" ${(v.nameidFormat ?? "transient") === f ? "selected" : ""}>${f}</option>`)
              .join("")}
            <option value="none" ${v.nameidFormat === "none" ? "selected" : ""}>none (no &lt;saml:NameID&gt; in the Subject)</option>
          </select>
        </div>
      </div>
      <label for="attribute_map">Attribute map (JSON - leave empty for the default email/name/groups map)</label>
      <textarea id="attribute_map" name="attribute_map" rows="4" placeholder='{"email": "email", "department": "department"}'>${escapeHtml(Object.keys(v.attributeMap ?? {}).length ? JSON.stringify(v.attributeMap, null, 2) : "")}</textarea>
      <p class="muted" style="margin:-8px 0 14px;">Fields: <code>${USER_ATTRIBUTE_FIELDS.join("</code>, <code>")}</code>, <code>custom.&lt;key&gt;</code>, or any expression &mdash; e.g. <code>given_name + " " + family_name</code>. See <a href="/admin/flows">Flows</a> for the language.</p>
      <label for="attribute_definitions">Attribute definitions (JSON - optional; when set it replaces the map above)</label>
      <textarea id="attribute_definitions" name="attribute_definitions" rows="4" placeholder='[{"name": "http://schemas.example/claims/dept", "field": "department", "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}]'>${escapeHtml(defsJson.length ? JSON.stringify(defsJson, null, 2) : "")}</textarea>
      <p class="muted" style="margin:-8px 0 14px;">One object per released attribute: an arbitrary <code>name</code>, the user <code>field</code> feeding it and an optional <code>name_format</code> (the default is <code>urn:oasis:names:tc:SAML:2.0:attrname-format:uri</code>).</p>
      <label for="signing_certs">SP signing certificates (PEM, one or more - leave empty if requests are unsigned)</label>
      <textarea id="signing_certs" name="signing_certs" rows="6" placeholder="-----BEGIN CERTIFICATE-----">${escapeHtml((v.signingCerts ?? []).join("\n"))}</textarea>
      <label style="font-weight:400;"><input type="checkbox" name="sign_response" value="1" ${v.signResponse !== false ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Sign the Response</label>
      <label style="font-weight:400;"><input type="checkbox" name="sign_assertion" value="1" ${v.signAssertion !== false ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Sign the Assertion</label>
      <label style="font-weight:400;"><input type="checkbox" name="want_authn_requests_signed" value="1" ${v.wantSigned ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require signed AuthnRequests from this SP</label>
      <label for="slo_url">Single Logout URL (HTTP-Redirect; leave empty to turn SLO off)</label>
      <input type="text" id="slo_url" name="slo_url" value="${escapeHtml(v.sloUrl ?? "")}" placeholder="https://sp.example.com/saml/slo" />
      <p class="muted" style="margin:-8px 0 14px;">LogoutRequests must be signed with one of the signing certificates above.</p>
      <label for="encryption_cert">SP encryption certificate (PEM)</label>
      <textarea id="encryption_cert" name="encryption_cert" rows="4" placeholder="-----BEGIN CERTIFICATE-----">${escapeHtml(v.encryptionCert ?? "")}</textarea>
      <label style="font-weight:400;"><input type="checkbox" name="encrypt_assertions" value="1" ${v.encryptAssertions ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Encrypt assertions (AES-256-GCM, RSA-OAEP)</label>
      <label for="subject_id" style="margin-top:12px;">Subject identifier attribute</label>
      <select id="subject_id" name="subject_id">
        ${[["", "None"], ["pairwise-id", "pairwise-id (different for every SP; recommended)"], ["subject-id", "subject-id (the same for every SP)"]].map(([val, label]) => `<option value="${val}" ${(v.subjectId ?? "") === val ? "selected" : ""}>${label}</option>`).join("")}
      </select>
      <p class="muted" style="margin:-8px 0 14px;">SAML V2.0 Subject Identifier Attributes Profile. Set automatically when the SP's metadata asks for one.</p>
      ${opts.includeAccess === false ? "" : appAccessFields({ accessMode: v.accessMode, groups, assignedGroups: v.assignedGroups ?? [], assignedUsers, requireMfa: !!v.requireMfa, requestable: !!v.requestable })}
      <div class="form-actions end">${opts.extraActions ?? ""}${cancelLink("/admin/apps")}<button class="primary" type="submit">${escapeHtml(submitLabel)}</button></div>
    </form>`;
}

admin.get("/admin/saml/new", async (c) => {
  const { results: groups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<Pick<GroupRow, "id" | "name">>();
  return c.html(
    layout(
      c,
      "New SAML service provider",
      `${samlIdpBlock(c.env)}
      ${cardSection(`
        <h2>Import from SP metadata</h2>
        <p class="muted">Paste the service provider's metadata XML. ACS URLs, certificates, Single Logout and NameID format are filled in; an SP with the same entity ID is updated.</p>
        <form method="POST" action="/admin/saml/import-metadata">
          <label for="sp_name">Name (optional)</label>
          <input type="text" id="sp_name" name="name" />
          <label for="metadata_url">Metadata URL</label>
          <input type="text" id="metadata_url" name="url" placeholder="https://sp.example.com/saml/metadata" />
          <p class="muted" style="margin-top:-8px;">Fetched now and re-read daily, so certificate rollovers and new endpoints are picked up. Or paste the XML instead:</p>
          <label for="metadata_xml">Metadata XML</label>
          <textarea id="metadata_xml" name="xml" rows="8" placeholder="&lt;md:EntityDescriptor entityID=&quot;...&quot;&gt;"></textarea>
          <div class="form-actions end"><button class="primary" type="submit">Import metadata</button></div>
        </form>
      `)}
      ${cardSection(`<h2>Or enter it by hand</h2>${spForm({}, "/admin/saml", "Create service provider", groups, [])}`)}`,
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: "New service provider" }]
    )
  );
});

admin.post("/admin/saml/import-metadata", async (c) => {
  const body = await c.req.parseBody();
  try {
    const url = String(body.url ?? "").trim();
    const meta = url ? await fetchSpMetadata(url) : parseSpMetadata(String(body.xml ?? ""));
    const id = await upsertSpFromMetadata(c.env, meta, String(body.name ?? "").trim() || undefined, url || undefined);
    await logAudit(c.env, c.get("user"), "saml_sp.metadata_imported", meta.entityId, { acs_urls: meta.acsUrls.length }, c.req.raw);
    return c.redirect(`/admin/saml/${id}?saved=1`, 302);
  } catch (e) {
    if (e instanceof SpMetadataError) return consoleError(c, e.message, 400);
    throw e;
  }
});

admin.post("/admin/saml", async (c) => {
  const v = parseSpForm(await c.req.parseBody({ all: true }));
  if (typeof v === "string") return consoleError(c, v, 400);

  const id = await insertServiceProvider(c.env, v);
  await logAudit(c.env, c.get("user"), "saml_sp.created", v.name, { entity_id: v.entityId }, c.req.raw);
  return c.redirect(`/admin/saml/${id}`, 302);
});

admin.get("/admin/saml/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const tab = c.req.query("tab") ?? "settings";
  const [{ results: groups }, assignedUsers] = await Promise.all([
    c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<Pick<GroupRow, "id" | "name">>(),
    assignedUserLabels(c.env, sp.assigned_users),
  ]);

  const base = `/admin/saml/${id}`;
  const tabs = appTabs(base, (["access", "policies", "provisioning"].includes(tab) ? tab : "settings") as "settings" | "access" | "policies" | "provisioning");
  let body: string;
  if (tab === "access") {
    body = cardSection(`
      <h2>Access</h2>
      <form method="POST" action="${base}/access">
        ${appAccessFields({ accessMode: sp.access_mode, groups, assignedGroups: parseAssignedGroupIds(sp.assigned_groups), assignedUsers, requireMfa: !!sp.require_mfa, requestable: !!sp.requestable })}
        <div class="form-actions end">${cancelLink(base + "?tab=access")}<button class="primary" type="submit">Save</button></div>
      </form>`);
  } else if (tab === "policies") {
    const policies = await listPolicies(c.env);
    body = cardSection(`
      <h2>Policies</h2>
      <form method="POST" action="${base}/policies">
        ${appPolicyFields({ policies, policyId: sp.policy_id, requireMfa: !!sp.require_mfa })}
        <div class="form-actions end">${cancelLink(base + "?tab=policies")}<button class="primary" type="submit">Save</button></div>
      </form>`);
  } else if (tab === "provisioning") {
    body = await appProvisioningCard(c.env, "saml", id);
  } else {
    body = `
      ${samlIdpBlock(c.env)}
      ${cardSection(`
        ${spForm(
          {
            name: sp.name,
            entityId: sp.entity_id,
            acsUrls: JSON.parse(sp.acs_urls),
            defaultAcsUrl: sp.default_acs_url ?? "",
            nameidFormat: sp.nameid_format,
            attributeMap: JSON.parse(sp.attribute_map),
            attributeDefinitions: spAttributeDefinitions(sp),
            signResponse: !!sp.sign_response,
            signAssertion: !!sp.sign_assertion,
            wantSigned: !!sp.want_authn_requests_signed,
            signingCerts: JSON.parse(sp.signing_certs),
            sloUrl: sp.slo_url ?? "",
            encryptionCert: sp.encryption_cert ?? "",
            subjectId: sp.subject_id ?? "",
            encryptAssertions: !!sp.encrypt_assertions,
            logoUri: sp.logo_uri ?? "",
            accessMode: sp.access_mode,
            assignedGroups: parseAssignedGroupIds(sp.assigned_groups),
            assignedUsers: [],
            requireMfa: !!sp.require_mfa,
            requestable: !!sp.requestable,
          },
          base,
          "Save",
          groups,
          assignedUsers,
          { includeAccess: false, extraActions: formButton("Delete", `${base}/delete`, { variant: "danger", confirm: confirmAttrs(`Users will no longer be able to sign in to this service provider.`, { title: `Delete "${sp.name}"?`, action: "Delete", danger: true }) }) }
        )}
      `)}`;
  }

  return c.html(
    layout(
      c,
      sp.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${tabs}
      ${body}
      `,
      [{ label: "Admin", href: "/admin" }, APPS_CRUMB, { label: sp.name }]
    )
  );
});

admin.post("/admin/saml/:id/access", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT name, entity_id FROM saml_service_providers WHERE id = ?").bind(id).first<{ name: string; entity_id: string }>();
  if (!sp) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v : v ? [v] : []).map(Number).filter((n) => Number.isInteger(n) && n > 0);
  await c.env.DB.prepare("UPDATE saml_service_providers SET access_mode = ?, assigned_groups = ?, assigned_users = ?, requestable = ?, updated_at = ? WHERE id = ?")
    .bind(body.access_mode === "everyone" ? "everyone" : "restricted", JSON.stringify(list(body.assigned_group_ids)), JSON.stringify(list(body.assigned_user_ids)), body.requestable ? 1 : 0, new Date().toISOString(), id)
    .run();
  await logAudit(c.env, c.get("user"), "saml_sp.updated", sp.name, { entity_id: sp.entity_id, fields: "access" }, c.req.raw);
  return c.redirect(`/admin/saml/${id}?tab=access&saved=1`, 302);
});

admin.post("/admin/saml/:id/policies", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT name, entity_id FROM saml_service_providers WHERE id = ?").bind(id).first<{ name: string; entity_id: string }>();
  if (!sp) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody();
  const policyId = Number(body.policy_id) > 0 ? Number(body.policy_id) : null;
  await assertPolicyExists(c.env, policyId);
  await c.env.DB.prepare("UPDATE saml_service_providers SET require_mfa = ?, policy_id = ?, updated_at = ? WHERE id = ?")
    .bind(body.require_mfa ? 1 : 0, policyId, new Date().toISOString(), id)
    .run();
  await logAudit(c.env, c.get("user"), "saml_sp.updated", sp.name, { entity_id: sp.entity_id, fields: "policies" }, c.req.raw);
  return c.redirect(`/admin/saml/${id}?tab=policies&saved=1`, 302);
});

admin.post("/admin/saml/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);

  const v = parseSpForm(await c.req.parseBody({ all: true }));
  if (typeof v === "string") return consoleError(c, v, 400);

  await c.env.DB.prepare(
    `UPDATE saml_service_providers SET entity_id = ?, name = ?, acs_urls = ?, default_acs_url = ?, nameid_format = ?, attribute_map = ?, attribute_definitions = ?, sign_response = ?, sign_assertion = ?, want_authn_requests_signed = ?, signing_certs = ?, slo_url = ?, encryption_cert = ?, encrypt_assertions = ?, logo_uri = ?, updated_at = ? WHERE id = ?`
  )
    .bind(v.entityId, v.name, JSON.stringify(v.acsUrls), v.defaultAcsUrl || null, v.nameidFormat, JSON.stringify(v.attributeMap), v.attributeDefinitions.length ? JSON.stringify(v.attributeDefinitions) : null, v.signResponse ? 1 : 0, v.signAssertion ? 1 : 0, v.wantSigned ? 1 : 0, JSON.stringify(v.signingCerts), v.sloUrl || null, v.encryptionCert || null, v.encryptAssertions ? 1 : 0, v.logoUri || null, new Date().toISOString(), id)
    .run();

  await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE id = ?").bind(v.subjectId, id).run();
  await logAudit(c.env, c.get("user"), "saml_sp.updated", v.name, { entity_id: v.entityId }, c.req.raw);
  return c.redirect(`/admin/saml/${id}?saved=1`, 302);
});

admin.post("/admin/saml/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM saml_service_providers WHERE id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM access_requests WHERE target_type = 'saml_app' AND target_id = ?").bind(id),
  ]);
  await logAudit(c.env, c.get("user"), "saml_sp.deleted", sp.name, { entity_id: sp.entity_id }, c.req.raw);
  return c.redirect("/admin/apps?saved=1", 302);
});

// ---------- Schemas ----------

const ATTRIBUTE_TYPE_OPTIONS: [string, string][] = [
  ["string", "Text"],
  ["number", "Number"],
  ["date", "Date"],
  ["boolean", "Yes / no"],
  ["reference", "Person (reference)"],
];

type AttributeInput = { name: string; label: string; type: string; required: boolean; ref_object: string | null; user_editable: boolean };

function attributeRowHtml(a?: { name: string; label: string; type: string; required: number; user_editable?: number }): string {
  const required = a?.required ? 1 : 0;
  const editable = a?.user_editable ? 1 : 0;
  return `<div class="attr-row">
    <input type="text" name="attr_name" value="${escapeHtml(a?.name ?? "")}" placeholder="name (e.g. cost_center)" pattern="[a-z][a-z0-9_]*" title="lowercase letters, digits and underscores, starting with a letter" />
    <input type="text" name="attr_label" value="${escapeHtml(a?.label ?? "")}" placeholder="Label (e.g. Cost center)" />
    <select name="attr_type">${ATTRIBUTE_TYPE_OPTIONS.map(([v, l]) => `<option value="${v}" ${(a?.type ?? "string") === v ? "selected" : ""}>${l}</option>`).join("")}</select>
    <label><input type="hidden" name="attr_required" value="${required}" /><input type="checkbox" ${required ? "checked" : ""} data-mirror-prev style="width:auto; margin:0;" /> Required</label>
    <label title="Users can change this themselves on their account page"><input type="hidden" name="attr_user_editable" value="${editable}" /><input type="checkbox" ${editable ? "checked" : ""} data-mirror-prev style="width:auto; margin:0;" /> User can edit</label>
    ${iconButton("trash", "Remove attribute", { danger: true, type: "button", attrs: 'data-remove-closest=".attr-row"' })}
  </div>`;
}

/** Reads the attribute rows (parallel attr_name/attr_label/attr_type/attr_required arrays); blank names are dropped. */
function readAttributeRows(body: Record<string, unknown>): AttributeInput[] {
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const names = list(body.attr_name);
  const labels = list(body.attr_label);
  const types = list(body.attr_type);
  const required = list(body.attr_required);
  const editable = list(body.attr_user_editable);
  const seen = new Set<string>();
  const out: AttributeInput[] = [];
  names.forEach((raw, i) => {
    const name = raw.trim();
    if (!name) return;
    if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error(`"${name}" is not a valid attribute name - use lowercase letters, digits and underscores, starting with a letter.`);
    if (seen.has(name)) throw new Error(`The attribute "${name}" is listed twice.`);
    seen.add(name);
    const type = ATTRIBUTE_TYPE_OPTIONS.some(([v]) => v === types[i]) ? types[i]! : "string";
    out.push({ name, label: (labels[i] ?? "").trim() || name, type, required: required[i] === "1", ref_object: type === "reference" ? "user" : null, user_editable: editable[i] === "1" });
  });
  return out;
}

admin.get("/admin/schemas", async (c) => {
  const schemas = await listSchemas(c.env);
  const rows = await Promise.all(
    schemas.map(async (s) => ({
      schema: s,
      attributes: (await getSchemaAttributes(c.env, s.id)).length,
      conforming: await countConforming(c.env, s.id, s.object_type),
    }))
  );

  const table = (objectType: "user" | "group") => {
    const list = rows.filter((r) => r.schema.object_type === objectType);
    return cardSection(`
      <h2>${objectType === "user" ? "User" : "Group"} schemas</h2>
      <table>
        <thead><tr><th>Name</th><th>Attributes</th><th>Conforming</th><th></th></tr></thead>
        <tbody>
          ${list
            .map(
              ({ schema: s, attributes, conforming }) => `<tr>
                <td><a href="/admin/schemas/${s.id}">${escapeHtml(s.name)}</a>${s.is_default ? ' <span class="badge badge-active">default</span>' : ""}${s.builtin ? ' <span class="pill">provided</span>' : ""}<br/><span class="muted">${escapeHtml(s.description ?? "")}</span></td>
                <td>${attributes}</td>
                <td>${conforming}</td>
                <td>${rowActions(iconLink(`/admin/schemas/${s.id}`, "edit", "Edit"))}</td>
              </tr>`
            )
            .join("")}
        </tbody>
      </table>
    `);
  };

  return c.html(
    layout(
      c,
      "Schemas",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      <p class="muted">A schema names the attributes an object has. New objects use the default schema; moving an object to another schema keeps attributes with the same name and clears the rest.</p>
      ${table("user")}
      ${table("group")}
      ${cardSection(`
        <h2>New schema</h2>
        <form method="POST" action="/admin/schemas">
          <div class="field-row">
            <div>
              <label for="object_type">Object type</label>
              <select id="object_type" name="object_type"><option value="user">User</option><option value="group">Group</option></select>
            </div>
            <div>
              <label for="name">Name</label>
              <input type="text" id="name" name="name" required />
            </div>
          </div>
          <label for="description">Description</label>
          <input type="text" id="description" name="description" />
          <div class="form-actions end"><button class="primary" type="submit">Create schema</button></div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Schemas" }]
    )
  );
});

admin.post("/admin/schemas", async (c) => {
  const body = await c.req.parseBody();
  const objectType = String(body.object_type ?? "") === "group" ? "group" : "user";
  const name = String(body.name ?? "").trim();
  const description = String(body.description ?? "").trim();
  if (!name) return consoleError(c, "Enter a name.", 400);
  if (await findSchema(c.env, objectType, name)) return consoleError(c, `A ${objectType} schema named "${name}" already exists.`, 409);

  const id = await createSchema(c.env, objectType, name, description);
  await logAudit(c.env, c.get("user"), "schema.created", `${objectType}:${name}`, undefined, c.req.raw);
  return c.redirect(`/admin/schemas/${id}`, 302);
});

admin.get("/admin/schemas/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const attributes = await getSchemaAttributes(c.env, id);
  const conforming = await countConforming(c.env, id, schema.object_type);
  const columnNote =
    schema.object_type === "user"
      ? `Names matching built-in fields (<code>job_title</code>, <code>department</code>, <code>manager</code>, <code>employee_number</code>, <code>hire_date</code>, <code>employment_status</code>, <code>employment_type</code>, <code>location</code>) use those fields; anything else is stored as a custom attribute.`
      : "Group attributes are stored as custom attributes on the group.";

  return c.html(
    layout(
      c,
      schema.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      <form method="POST" action="/admin/schemas/${id}">
        ${cardSection(`
          <div class="field-row">
            <div>
              <label for="name">Name</label>
              <input type="text" id="name" name="name" value="${escapeHtml(schema.name)}" required />
            </div>
            <div>
              <label for="description">Description</label>
              <input type="text" id="description" name="description" value="${escapeHtml(schema.description ?? "")}" />
            </div>
          </div>
          <p class="muted" style="margin:0;">${schema.object_type === "user" ? "User" : "Group"} schema${schema.is_default ? " &middot; the default for new objects" : ""}${schema.builtin ? " &middot; provided with FlareID" : ""}</p>
        `)}
        ${cardSection(`
          <h2>Attributes</h2>
          <p class="muted" style="margin-top:-4px;">${columnNote} Identity fields (names and UPN) are on every ${schema.object_type} and don't need listing.</p>
          <div class="attr-row muted" style="font-size:0.75rem; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; margin-bottom:4px;">
            <span>Name</span><span>Label</span><span>Type</span><span></span><span></span><span></span>
          </div>
          <div id="attr-rows">${(attributes.length ? attributes : [undefined]).map((a) => attributeRowHtml(a)).join("")}</div>
          <template id="attr-row-template">${attributeRowHtml()}</template>
          <button type="button" class="secondary" data-append-template="attr-row-template" data-append-to="attr-rows">+ Add attribute</button>
        `)}
        <div class="row between" style="margin-bottom:18px;">
          <div class="form-actions">
            ${
              schema.builtin
                ? ""
                : `<button class="danger" type="submit" formaction="/admin/schemas/${id}/delete" formnovalidate
                    ${confirmAttrs(`Objects using it move to the default schema, and attributes the default schema doesn't define are cleared.`, { title: `Delete the schema "${schema.name}"?`, action: "Delete schema", danger: true })}>Delete schema</button>`
            }
          </div>
          <div class="form-actions">
            ${cancelLink(`/admin/schemas`)}
            <button class="primary" type="submit">Save</button>
          </div>
        </div>
      </form>
      ${cardSection(`
        <h2>Apply to everyone</h2>
        <p class="muted">${conforming} ${schema.object_type}${conforming === 1 ? "" : "s"} currently use${conforming === 1 ? "s" : ""} this schema.</p>
        <form method="POST" action="/admin/schemas/${id}/apply">
          <button class="secondary" type="submit"
            ${confirmAttrs(`Every ${schema.object_type} moves to "${schema.name}". Attributes with the same name keep their values; attributes this schema doesn't define are cleared.`, { title: `Apply "${schema.name}" to all ${schema.object_type}s?`, action: "Apply to all", danger: true })}>Apply to all ${schema.object_type}s</button>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Schemas", href: "/admin/schemas" }, { label: schema.name }]
    )
  );
});

admin.post("/admin/schemas/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody({ all: true });
  const name = String(body.name ?? "").trim();
  const description = String(body.description ?? "").trim();
  if (!name) return consoleError(c, "Enter a name.", 400);

  const clash = await c.env.DB.prepare("SELECT id FROM schemas WHERE object_type = ? AND name = ? AND id != ?").bind(schema.object_type, name, id).first();
  if (clash) return consoleError(c, `A ${schema.object_type} schema named "${name}" already exists.`, 409);

  let attributes: AttributeInput[];
  try {
    attributes = readAttributeRows(body);
  } catch (e) {
    return consoleError(c, e instanceof Error ? e.message : "Invalid attributes.", 400);
  }

  try {
    // Checked before anything is written: a refused permission changes nothing.
    await saveSchemaAttributes(c.env, id, attributes);
  } catch (e) {
    if (e instanceof RangeError) return consoleError(c, e.message, 400);
    throw e;
  }
  await c.env.DB.prepare("UPDATE schemas SET name = ?, description = ? WHERE id = ?").bind(name, description || null, id).run();
  await logAudit(c.env, c.get("user"), "schema.updated", `${schema.object_type}:${name}`, { attributes: attributes.length }, c.req.raw);
  return c.redirect(`/admin/schemas/${id}?saved=1`, 302);
});

admin.post("/admin/schemas/:id/apply", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const count = await applySchemaToAll(consoleCtx(c), schema);
  await logAudit(c.env, c.get("user"), "schema.applied", `${schema.object_type}:${schema.name}`, { count }, c.req.raw);
  return c.redirect(`/admin/schemas/${id}?saved=1`, 302);
});

admin.post("/admin/schemas/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  if (schema.builtin) return consoleError(c, "Provided schemas cannot be deleted - remove their attributes instead.", 400);

  const fallback = await getSchema(c.env, Number(await defaultSchemaId(c.env, schema.object_type)));
  if (fallback) await applySchemaToAll(consoleCtx(c), fallback, id);
  await c.env.DB.prepare("DELETE FROM schemas WHERE id = ?").bind(id).run();
  await logAudit(c.env, c.get("user"), "schema.deleted", `${schema.object_type}:${schema.name}`, undefined, c.req.raw);
  return c.redirect("/admin/schemas?saved=1", 302);
});

// ---------- Domains ----------

admin.get("/admin/domains", async (c) => {
  const [domains, brands] = await Promise.all([listDomains(c.env), listBrandRows(c.env)]);
  // Changing a domain's brand needs domains:write; seeing the choice is enough to read.
  const brandCell = (d: { id: number; brand_id: number | null }) =>
    brands.length
      ? `<form method="POST" action="/admin/domains/${d.id}/brand" style="margin:0;">
          <select name="brand_id" data-autosubmit aria-label="Brand" style="width:auto; margin:0;">
            <option value="">Default</option>
            ${brands.map((b) => `<option value="${b.id}" ${d.brand_id === b.id ? "selected" : ""}>${escapeHtml(b.name)}</option>`).join("")}
          </select>
        </form>`
      : `<span class="muted">Default</span>`;
  return c.html(
    layout(
      c,
      "Domains",
      `
            ${c.req.query("saved") ? successBanner("Saved.") : ""}
            ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <form method="POST" action="/admin/domains">
          <div class="row between" style="margin:0; gap:12px;">
            <input type="text" name="domain" placeholder="example.com" required style="margin-bottom:0; max-width:320px;" />
            <button class="primary" type="submit">+ New domain</button>
          </div>
        </form>
      `)}
      ${cardSection(`
        <table>
          <thead><tr><th>Domain</th><th>Default</th><th>Brand</th><th></th></tr></thead>
          <tbody>
            ${domains
              .map(
                (d) => `<tr>
                  <td>${escapeHtml(d.domain)}</td>
                  <td>${d.is_default ? '<span class="badge badge-active">Default</span>' : ""}</td>
                  <td>${brandCell(d)}</td>
                  <td><div class="row-actions" style="gap:10px;">
                    ${!d.is_default ? `<form method="POST" action="/admin/domains/${d.id}/set-default"><button class="link-button" type="submit">Make default</button></form>` : ""}
                    ${c.get("isSuperAdmin") ? `<form method="POST" action="/admin/domains/${d.id}/apply-to-all" style="display:inline;" ${confirmAttrs(`Every user's UPN domain becomes ${d.domain}. Usernames are kept.`, { title: "Change the domain on every account?", action: "Apply to all" })}>
                      <button class="link-button" type="submit">Apply to all users</button>
                    </form>` : ""}
                    <form method="POST" action="/admin/domains/${d.id}/delete">
                      ${iconButton("trash", "Delete", { danger: true })}
                    </form>
                  </div></td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
        <p class="muted" style="margin-bottom:0;">The brand is what a domain's people see on the sign-in pages, My account and in emails. <a href="/admin/branding/brands">Manage brands</a>.</p>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Domains" }]
    )
  );
});

admin.post("/admin/domains", async (c) => {
  const body = await c.req.parseBody();
  const domain = String(body.domain ?? "").trim().toLowerCase();
  if (domain) {
    if (!isValidDomain(domain)) return c.redirect("/admin/domains?error=" + encodeURIComponent(`"${domain}" is not a valid DNS domain name.`), 302);
    await addDomain(c.env, domain);
    await logAudit(c.env, c.get("user"), "domain.added", domain, undefined, c.req.raw);
  }
  return c.redirect("/admin/domains?saved=1", 302);
});

admin.post("/admin/domains/:id/set-default", async (c) => {
  const id = Number(c.req.param("id"));
  if (!(await c.env.DB.prepare("SELECT 1 FROM domains WHERE id = ?").bind(id).first())) {
    return c.redirect("/admin/domains?error=" + encodeURIComponent("That domain does not exist."), 302);
  }
  await setDefaultDomain(c.env, id);
  await logAudit(c.env, c.get("user"), "domain.set_default", String(id), undefined, c.req.raw);
  return c.redirect("/admin/domains", 302);
});

admin.post("/admin/domains/:id/brand", async (c) => {
  const row = (await listDomains(c.env)).find((d) => d.id === Number(c.req.param("id")));
  if (!row) return consoleError(c, "Unknown domain", 404);
  const raw = String((await c.req.parseBody()).brand_id ?? "");
  await assignDomainBrand(consoleCtx(c), row.domain, raw ? Number(raw) : null);
  return c.redirect("/admin/domains?saved=1", 302);
});

admin.post("/admin/domains/:id/delete", async (c) => {
  try {
    await removeDomain(consoleCtx(c), Number(c.req.param("id")));
  } catch (e) {
    // Refusals are in the log; the page shows the domain still there.
    if (!(e instanceof ServiceError)) throw e;
  }
  return c.redirect("/admin/domains", 302);
});

admin.post("/admin/domains/:id/apply-to-all", async (c) => {
  const id = Number(c.req.param("id"));
  const domains = await listDomains(c.env);
  const domain = domains.find((d) => d.id === id);
  if (!domain) return c.redirect("/admin/domains", 302);

  const { updated, conflicts } = await applyDomainToAllUsers(c.env, domain.domain);
  await logAudit(c.env, c.get("user"), "domain.applied_to_all", domain.domain, { updated, conflicts }, c.req.raw);

  return c.html(
    layout(
      c,
      "Domain applied",
      cardSection(`
        <p class="success">Updated ${updated} user(s) to @${escapeHtml(domain.domain)}.</p>
        ${conflicts.length > 0 ? `<p class="error">Skipped due to username conflicts: ${conflicts.map(escapeHtml).join(", ")}</p>` : ""}
        <a href="/admin/domains"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Domains", href: "/admin/domains" }, { label: "Domain applied" }]
    )
  );
});

// ---------- Security (default password + policy) ----------

admin.get("/admin/security", async (c) => {
  const defaultPassword = await getDefaultPassword(c.env);
  const policy = await getPasswordPolicy(c.env);
  const rateLimit = await getRateLimitPolicy(c.env);
  const mfaRequired = await isMfaRequired(c.env);
  const newUserPasswordMode = await getNewUserPasswordMode(c.env);
  const auditRetentionDays = await getAuditRetentionDays(c.env);
  const sessionPolicy = await getSessionPolicy(c.env);
  const breachedCheck = await isBreachedPasswordCheckEnabled(c.env);
  const aliasSignin = (await getSetting(c.env, "alias_signin")) !== "false";
  const turnstile = await getTurnstileConfig(c.env);
  const turnstileActive = activeTurnstileSiteKey(turnstile) !== null;
  const radio = 'style="width:auto; display:inline; margin-right:6px;"';

  return c.html(
    layout(
      c,
      "Security",
      `
            ${c.req.query("saved") ? successBanner("Saved.") : ""}
            ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      <div class="two-col security-grid">
      ${cardSection(`
        <h2>Default password</h2>
        <p class="muted">Used for newly created accounts and available to bulk-apply to every existing account.</p>
        <form method="POST" action="/admin/security/default-password">
          <input type="password" name="default_password" value="" autocomplete="new-password" placeholder="${defaultPassword ? "Saved - leave blank to keep it" : "Choose a default password"}" ${defaultPassword ? "" : "required"} />
          <p class="muted" style="margin-top:-6px;">Write-only: it is never shown again after saving. Blank keeps the stored one.</p>
          <div class="form-actions end">
            <button class="primary" type="submit">Save</button>
            <button class="danger" type="submit" name="apply" value="1" formaction="/admin/security/apply-default-password"
              ${confirmAttrs("Every account's password is reset to the default shown above. Anyone mid-session stays signed in, but their old password stops working.", { title: "Reset every account's password?", action: "Reset all passwords", danger: true })}>Apply default password to all accounts</button>
          </div>
        </form>
      `)}
      ${cardSection(`
        <h2>New account password</h2>
        <p class="muted">What password a newly created account (or a manual password reset) gets. Randomly generated passwords always satisfy the complexity policy below.</p>
        <form method="POST" action="/admin/security/new-user-password-mode">
          <label><input type="radio" name="mode" value="default" ${newUserPasswordMode === "default" ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Use the default password</label>
          <label><input type="radio" name="mode" value="random" ${newUserPasswordMode === "random" ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Randomly generate one</label>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Password complexity policy</h2>
        <p class="muted">Enforced on self-service password changes and randomly generated account passwords.</p>
        <form method="POST" action="/admin/security/password-policy">
          <label for="minLength">Minimum length</label>
          <input type="number" id="minLength" name="minLength" min="4" max="64" value="${policy.minLength}" style="max-width:120px;" />
          <div class="field-row" style="margin-top:4px;">
            <div><label><input type="checkbox" name="requireUppercase" value="1" ${policy.requireUppercase ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require uppercase letter</label></div>
            <div><label><input type="checkbox" name="requireLowercase" value="1" ${policy.requireLowercase ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require lowercase letter</label></div>
            <div><label><input type="checkbox" name="requireNumber" value="1" ${policy.requireNumber ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require number</label></div>
            <div><label><input type="checkbox" name="requireSymbol" value="1" ${policy.requireSymbol ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require symbol</label></div>
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save policy</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Breached passwords</h2>
        <p class="muted">Refuses a password that appears in known data breaches (Have I Been Pwned's Pwned Passwords) wherever one is chosen: self-service changes, invitations, password resets, passwords an administrator sets, and imported passwords (imports with up to 200 of them). Generated passwords are not checked.
          Only the first 5 characters of the password's SHA-1 hash leave ${escapeHtml(c.get("appName"))}; the password itself never does. If the service can't be reached within 3 seconds, the password is allowed.</p>
        <form method="POST" action="/admin/security/breached-passwords">
          <label><input type="checkbox" name="enabled" value="1" ${breachedCheck ? "checked" : ""} ${radio} /> Reject passwords found in data breaches</label>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Bot protection (Turnstile)</h2>
        <p class="muted">Cloudflare Turnstile checks that a person, not a script, is behind the password sign-in and password-recovery forms, before any password is checked or email sent. Passkey sign-in is not challenged: passkeys cannot be phished or stuffed.
          Create a widget for this hostname in the Cloudflare dashboard (Turnstile) and paste its keys here.
          Currently <strong>${turnstileActive ? "on" : "off"}</strong>.</p>
        <form method="POST" action="/admin/security/turnstile">
          <label><input type="radio" name="mode" value="off" ${turnstile.mode === "off" ? "checked" : ""} ${radio} /> Off</label>
          <label><input type="radio" name="mode" value="on" ${turnstile.mode === "on" ? "checked" : ""} ${radio} /> On for sign-in and password recovery</label>
          <div class="field-row">
            <div>
              <label for="turnstile_site_key">Site key</label>
              <input type="text" id="turnstile_site_key" name="site_key" value="${escapeHtml(turnstile.siteKey)}" autocomplete="off" />
            </div>
            <div>
              <label for="turnstile_secret">Secret key</label>
              ${
                turnstile.secretFromEnv
                  ? `<p class="muted" style="margin-top:0;">Set by the <code>TURNSTILE_SECRET_KEY</code> Worker secret, which is used instead of a saved one.</p>`
                  : `<input type="password" id="turnstile_secret" name="secret" value="" autocomplete="new-password" placeholder="${turnstile.secret ? "Saved - leave blank to keep it" : "From the Cloudflare dashboard"}" />
              <p class="muted" style="margin-top:-6px;">Write-only: it is never shown again after saving.</p>`
              }
            </div>
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <div class="row between"><h2 style="margin:0;">Authentication policies</h2><a href="/admin/security/policies">Manage policies &rarr;</a></div>
        <p class="muted">What people must present to sign in is set per group by <a href="/admin/security/policies">authentication policies</a>.
          The default policy currently requires <strong>${mfaRequired ? "a password and a second factor (or a passkey)" : "a password (or a passkey)"}</strong>.
          Second-factor methods are switched on and off under <a href="/admin/security/factors">Factors</a>.</p>
      `)}
      ${cardSection(`
        <h2>Edge flood limits</h2>
        <p class="muted">Every route reachable without signing in sits behind Workers Rate Limiting, counted in memory per Cloudflare location (no storage writes).
          These are flood control, not the brute-force control: that is the per-account sign-in limit above. They are set at deploy time in
          <code>wrangler.jsonc</code> (<code>ratelimits</code>), not here, because the runtime cannot change them.</p>
        ${attrGrid([
          attr("Sign-in pages (login, authorize, SAML SSO, recovery, logout)", c.env.AUTH_LIMITER ? "120 requests / minute per IP" : "not bound"),
          attr("Machine endpoints (token, introspect, revoke, userinfo, API, SCIM)", c.env.API_LIMITER ? "600 requests / minute per IP and client" : "not bound"),
        ])}
      `)}
      ${cardSection(`
        <h2>Session limits</h2>
        <p class="muted">How long someone stays signed in to ${escapeHtml(c.get("appName"))} &mdash; and so how long single sign-on into apps works without a password. Changes apply to existing sessions straight away.</p>
        <form method="POST" action="/admin/security/session-limits">
          <div class="field-row">
            <div>
              <label for="session_max_hours">Maximum session length (hours)</label>
              <input type="number" id="session_max_hours" name="maxHours" min="${SESSION_MAX_HOURS_RANGE.min}" max="${SESSION_MAX_HOURS_RANGE.max}" value="${sessionPolicy.maxHours}" required />
            </div>
            <div>
              <label for="session_idle_minutes">Sign out after inactivity (minutes)</label>
              <input type="number" id="session_idle_minutes" name="idleMinutes" min="0" max="${SESSION_IDLE_MINUTES_RANGE.max}" value="${sessionPolicy.idleMinutes}" />
            </div>
          </div>
          <p class="muted" style="margin-top:-4px;">Maximum: ${SESSION_MAX_HOURS_RANGE.min}&ndash;${SESSION_MAX_HOURS_RANGE.max} hours from sign-in. Inactivity: 0 for no limit, otherwise at least ${SESSION_IDLE_MINUTES_RANGE.min} minutes. Tokens already issued to apps keep their own lifetimes.</p>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Login rate limiting</h2>
        <p class="muted">Locks out an account/IP combination after too many failed password or MFA-code attempts within the window below.</p>
        <form method="POST" action="/admin/security/rate-limit">
          <div class="field-row">
            <div>
              <label for="maxAttempts">Max failed attempts</label>
              <input type="number" id="maxAttempts" name="maxAttempts" min="1" max="100" value="${rateLimit.maxAttempts}" />
            </div>
            <div>
              <label for="windowMinutes">Window (minutes)</label>
              <input type="number" id="windowMinutes" name="windowMinutes" min="1" max="1440" value="${rateLimit.windowMinutes}" />
            </div>
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Sign-in names</h2>
        <p class="muted">Whether an account's listed email addresses and phone numbers work at the sign-in prompt, alongside its sign-in name (UPN, handle or phone). Off means aliases stay contact data: they still receive account mail and verification codes, they just can&rsquo;t authenticate. Only <em>verified</em> aliases ever sign in either way.</p>
        <form method="POST" action="/admin/security/alias-signin">
          <label style="font-weight:400;"><input type="checkbox" name="alias_signin" value="1" ${aliasSignin ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Allow sign-in by verified email / phone alias</label>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Audit log retention</h2>
        <p class="muted">Entries older than this are deleted by the hourly cleanup, along with expired codes, tokens, sessions and remembered devices. ${AUDIT_RETENTION_MIN_DAYS}-${AUDIT_RETENTION_MAX_DAYS} days.</p>
        <form method="POST" action="/admin/security/audit-retention">
          <label for="audit_retention_days">Keep audit entries for (days)</label>
          <input type="number" id="audit_retention_days" name="days" min="${AUDIT_RETENTION_MIN_DAYS}" max="${AUDIT_RETENTION_MAX_DAYS}" value="${auditRetentionDays}" style="max-width:160px;" />
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      </div>
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Security" }]
    )
  );
});

admin.post("/admin/security/alias-signin", async (c) => {
  const body = await c.req.parseBody();
  await setSetting(c.env, "alias_signin", String(body.alias_signin ?? "") === "1" ? "true" : "false");
  await logAudit(c.env, c.get("user"), "security.alias_signin_updated", "settings", { enabled: String(body.alias_signin ?? "") === "1" }, c.req.raw);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/default-password", async (c) => {
  await saveDefaultPassword(consoleCtx(c), String((await c.req.parseBody()).default_password ?? ""));
  return c.redirect("/admin/security?saved=1", 302);
});

// ---------- Branding (app name, sign-in message, login page appearance) ----------

/** Where the sign-in page can be seen in a brand (login.ts's brand_preview, for branding:read). */
const previewHref = (id: number | "default") => `/login?brand_preview=${id}`;

function previewLink(id: number | "default", label = "Preview the sign-in page"): string {
  return `<a href="${previewHref(id)}" target="_blank" rel="noopener"><button class="secondary" type="button">${escapeHtml(label)}</button></a>`;
}

/** A refusal from a branding form, back on the page it came from. */
function brandingBack(path: string, e: unknown) {
  if (!(e instanceof ServiceError)) throw e;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}error=${encodeURIComponent(e.message)}`;
}

function brandingBanner(q: Record<string, string>): string {
  if (q.error) return `<p class="error">${escapeHtml(q.error)}</p>`;
  return q.saved ? successBanner(q.saved === "logo" ? "Logo saved." : q.saved === "logo-removed" ? "Logo removed." : "Saved.") : "";
}

/** The logo upload card, for the default brand and for each brand. */
function logoCard(action: string, current: string | null, own: boolean, fallback: string): string {
  return cardSection(`
    <h2>Logo</h2>
    <p class="muted">Shown on the sign-in pages, in the top bar and at the top of emails. PNG or JPEG, up to ${LOGO_MAX_BYTES / 1024} KB; a transparent PNG about 100&ndash;200 px tall works best. SVG isn't accepted: an SVG is a document that can carry script, and most email clients don't display it.</p>
    <div style="display:flex; align-items:center; gap:14px; padding:12px; border:1px solid var(--fi-line); border-radius:10px; margin-bottom:14px; background:var(--fi-surface-2);">
      <img src="${escapeHtml(current ?? "/FlareID_Mark.png")}" alt="" style="max-height:56px; max-width:220px; object-fit:contain;" data-hide-on-error />
      <span class="muted">${own ? "Uploaded logo." : escapeHtml(fallback)}</span>
    </div>
    <form method="POST" action="${escapeHtml(action)}" enctype="multipart/form-data">
      <label for="logo">Upload a new logo</label>
      <input type="file" id="logo" name="logo" accept="image/png,image/jpeg" required />
      <div class="form-actions end"><button class="primary" type="submit">Upload</button></div>
    </form>
    ${
      own
        ? `<form method="POST" action="${escapeHtml(action)}/delete" style="margin-top:10px;" ${confirmAttrs(`The uploaded logo is deleted. ${fallback.replace(" is shown.", " is shown instead.")}`, { title: "Remove this logo?", action: "Remove" })}>
      <button class="secondary" type="submit">Remove logo</button>
    </form>`
        : ""
    }
  `);
}

/** What the custom CSS does and does not do, beside every editor for it. */
const CUSTOM_CSS_HELP = `<p class="muted">Applied, as a linked stylesheet, to the sign-in, two-step, consent, password-recovery, invitation and setup pages &mdash; never to the admin console or My account, so a stylesheet that breaks a page can't lock administrators out of fixing it. If it breaks sign-in, open <code>/login?nocustom=1</code>: that browser then signs in without custom CSS until <code>?nocustom=0</code>.</p>
  <p class="muted">The page's Content-Security-Policy blocks fonts and images from other sites, so <code>url()</code> can only be a path on this site or a <code>data:</code> URL; <code>@import</code>, <code>expression()</code>, <code>javascript:</code> and <code>&lt;/style&gt;</code> are refused. Useful selectors: <code>.auth-brand</code>, <code>.auth-brand img</code>, <code>.auth-brand span</code>, <code>.center-wrap .card</code>, <code>button.primary</code>, <code>.auth-foot</code>. At most ${CUSTOM_CSS_MAX_BYTES / 1024} KB.</p>`;

function cssTextarea(css: string, placeholder = "/* e.g. */ .auth-brand span { display: none; }"): string {
  return `<label for="custom_css">Custom CSS</label>
    <textarea id="custom_css" name="custom_css" rows="12" maxlength="${CUSTOM_CSS_MAX_BYTES}" spellcheck="false" style="font-family:ui-monospace,Menlo,monospace; font-size:0.8125rem;" placeholder="${escapeHtml(placeholder)}">${escapeHtml(css)}</textarea>`;
}

/** The uploaded file of a multipart form, as bytes (empty when none was chosen). */
async function uploadedBytes(c: Context<{ Bindings: Env }>): Promise<Uint8Array> {
  const file = (await c.req.parseBody()).logo;
  if (!(file instanceof File)) return new Uint8Array();
  // Refused before reading it into an array: the size is known already.
  if (file.size > LOGO_MAX_BYTES) throw new ServiceError(400, `That image is ${Math.ceil(file.size / 1024)} KB: a logo can be at most ${LOGO_MAX_BYTES / 1024} KB.`);
  return new Uint8Array(await file.arrayBuffer());
}

admin.get("/admin/branding", async (c) => {
  const [brand, cursorTrail, css, defaultLanguage, consoleTz] = await Promise.all([defaultBrand(c.env), getCursorTrail(c.env), defaultCustomCss(c.env), getDefaultLanguage(c.env), getConsoleTimezone(c.env)]);
  const q = c.req.query();

  return c.html(
    layout(
      c,
      "Branding",
      `
      ${brandingBanner(q)}
      <p class="muted" style="margin-top:0;">The default brand: what everyone sees unless their domain has a brand of its own (<a href="/admin/branding/brands">Brands</a>). The admin console, the issuer and the OIDC and SAML metadata always use it. ${previewLink("default")}</p>
      <div class="two-col security-grid">
      ${cardSection(`
        <h2>Branding</h2>
        <p class="muted">The display name shown in the nav, page titles, and on the sign-in page.</p>
        <form method="POST" action="/admin/branding/app-name">
          <label for="app_name">App name</label>
          <input type="text" id="app_name" name="app_name" value="${escapeHtml(brand.appName)}" required maxlength="${APP_NAME_MAX}" />
          <label for="login_subtitle">Sign-in page message</label>
          <input type="text" id="login_subtitle" name="login_subtitle" value="${escapeHtml(brand.subtitle)}" maxlength="${SUBTITLE_MAX}" placeholder="Use your company account to continue." />
          <p class="muted" style="margin-top:-8px;">Shown under the logo on the sign-in page. Leave empty for no message.</p>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${logoCard("/admin/branding/logo", brand.logoUrl, Boolean(brand.logoUrl), "FlareID's own mark is shown.")}
      ${cardSection(`
        <h2>Login page appearance</h2>
        <p class="muted">The background gradient shown behind the sign-in and MFA cards.</p>
        <form method="POST" action="/admin/branding/login-gradient">
          <div class="field-row" style="max-width:320px;">
            <div>
              <label for="gradient_from">Gradient start</label>
              <input type="color" id="gradient_from" name="from" value="${escapeHtml(brand.gradient.from)}" style="height:42px; padding:4px; cursor:pointer; margin-bottom:0;" />
            </div>
            <div>
              <label for="gradient_to">Gradient end</label>
              <input type="color" id="gradient_to" name="to" value="${escapeHtml(brand.gradient.to)}" style="height:42px; padding:4px; cursor:pointer; margin-bottom:0;" />
            </div>
          </div>
          <label style="margin-top:24px;">Preview</label>
          <div style="height:60px; border-radius:10px; margin-bottom:20px; background: linear-gradient(45deg, ${escapeHtml(brand.gradient.from)}, ${escapeHtml(brand.gradient.to)});"></div>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Cursor trail</h2>
        <p class="muted">Faint characters that drift away from the pointer on the sign-in and two-step pages. Purely decorative, and never shown on touch screens. The same for every brand.</p>
        <form method="POST" action="/admin/branding/cursor-trail">
          <label style="font-weight:400;"><input type="checkbox" name="enabled" value="1" ${cursorTrail.enabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Show the cursor trail</label>
          <label for="cursor_characters" style="margin-top:12px;">Characters</label>
          <input type="text" id="cursor_characters" name="characters" value="${escapeHtml(cursorTrail.characters)}" maxlength="${CURSOR_TRAIL_MAX_CHARACTERS}" placeholder="Leave empty for the default symbols, e.g. { } &lt; /&gt; &#955;" />
          <p class="muted" style="margin-top:-8px;">Shown one character at a time, in order &mdash; enter your company name and it spells itself out. Spaces are skipped. Empty uses a random mix of code symbols.</p>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Language</h2>
        <p class="muted">The sign-in, second-step, consent, sign-out, recovery and setup pages are translated. Each person sees the language they picked on the sign-in page, else the one their browser asks for (or an app asks for with OIDC <code>ui_locales</code>); this is the language when none of those is available. The same for every brand.</p>
        <form method="POST" action="/admin/branding/language">
          <label for="default_language">Default language</label>
          <select id="default_language" name="default_language">
            ${allLocales()
              .map((l) => `<option value="${escapeHtml(l.code)}" ${l.code === defaultLanguage ? "selected" : ""}>${escapeHtml(l.nativeName === l.name ? l.name : `${l.name} (${l.nativeName})`)}${l.machineAssisted ? " - machine-assisted translation" : ""}</option>`)
              .join("")}
          </select>
          <p class="muted" style="margin-top:-8px;">Translations live in <code>locales/</code> in the repository; see <a href="https://github.com/securitypedant/flareid/blob/main/docs/i18n.md">docs/i18n.md</a> to add one.</p>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Dates</h2>
        <p class="muted">Console pages show dates and times in each visitor's browser language and timezone. Set a zone here to pin them - for example so everyone reading the audit log sees the same wall clock.</p>
        <form method="POST" action="/admin/branding/timezone">
          <label for="console_timezone">Console timezone</label>
          <input type="text" id="console_timezone" name="console_timezone" list="tz-suggestions" value="${escapeHtml(consoleTz)}" placeholder="Empty: each browser's own timezone" />
          <datalist id="tz-suggestions">
            <option value="UTC"></option>
            <option value="Europe/London"></option>
            <option value="Europe/Berlin"></option>
            <option value="America/New_York"></option>
            <option value="America/Chicago"></option>
            <option value="America/Denver"></option>
            <option value="America/Los_Angeles"></option>
            <option value="America/Sao_Paulo"></option>
            <option value="Asia/Tokyo"></option>
            <option value="Asia/Singapore"></option>
            <option value="Australia/Sydney"></option>
          </datalist>
          <p class="muted" style="margin-top:-8px;">An IANA zone name (e.g. <code>Europe/London</code>), <code>UTC</code>, or empty for the browser default. The zone name shows next to times when pinned.</p>
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Email templates</h2>
        <p class="muted">The wording of the invitation, password reset and sign-in code emails, and the accent colour they share.</p>
        <a href="/admin/branding/email-templates"><button class="secondary" type="button">Edit email templates</button></a>
      `)}
      </div>
      ${cardSection(`
        <h2>Custom CSS</h2>
        ${CUSTOM_CSS_HELP}
        <form method="POST" action="/admin/branding/custom-css">
          ${cssTextarea(css)}
          <div class="form-actions end"><button class="primary" type="submit">Save</button>${previewLink("default", "Preview")}</div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Branding" }]
    )
  );
});

admin.post("/admin/branding/app-name", async (c) => {
  const body = await c.req.parseBody();
  const name = String(body.app_name ?? "").trim();
  if (name) await saveAppName(consoleCtx(c), name);

  // Empty is a valid choice here - it means "show no message" - so this is
  // saved whenever the field is present rather than only when non-empty.
  if (body.login_subtitle !== undefined) await saveLoginSubtitle(consoleCtx(c), String(body.login_subtitle ?? ""));
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/branding/login-gradient", async (c) => {
  const body = await c.req.parseBody();
  const from = String(body.from ?? "").trim();
  const to = String(body.to ?? "").trim();
  // Anything but two #rrggbb values is ignored, as the colour pickers never send one.
  if (isHexColor(from) && isHexColor(to)) await saveLoginGradient(consoleCtx(c), from, to);
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/branding/timezone", async (c) => {
  const body = await c.req.parseBody();
  try {
    await saveConsoleTimezone(consoleCtx(c), String(body.console_timezone ?? ""));
  } catch (e) {
    return c.redirect(brandingBack("/admin/branding", e), 302);
  }
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/branding/language", async (c) => {
  const body = await c.req.parseBody();
  try {
    await saveDefaultLanguage(consoleCtx(c), String(body.default_language ?? ""));
  } catch (e) {
    return c.redirect(brandingBack("/admin/branding", e), 302);
  }
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/branding/cursor-trail", async (c) => {
  const body = await c.req.parseBody();
  await saveCursorTrail(consoleCtx(c), { enabled: !!body.enabled, characters: String(body.characters ?? "") });
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/branding/logo", async (c) => {
  try {
    await uploadLogo(consoleCtx(c), null, await uploadedBytes(c));
  } catch (e) {
    return c.redirect(brandingBack("/admin/branding", e), 302);
  }
  return c.redirect("/admin/branding?saved=logo", 302);
});

admin.post("/admin/branding/logo/delete", async (c) => {
  await removeLogo(consoleCtx(c), null);
  return c.redirect("/admin/branding?saved=logo-removed", 302);
});

admin.post("/admin/branding/custom-css", async (c) => {
  const body = await c.req.parseBody();
  try {
    await saveDefaultCustomCss(consoleCtx(c), String(body.custom_css ?? ""));
  } catch (e) {
    return c.redirect(brandingBack("/admin/branding", e), 302);
  }
  return c.redirect("/admin/branding?saved=1", 302);
});

// ---------- Branding > Brands (per-domain branding) ----------

const BRANDS_CRUMBS = (extra: Breadcrumb[] = []): Breadcrumb[] => [{ label: "Admin", href: "/admin" }, { label: "Branding", href: "/admin/branding" }, { label: "Brands", href: "/admin/branding/brands" }, ...extra];

admin.get("/admin/branding/brands", async (c) => {
  const [brands, def, domains] = await Promise.all([listBrandRows(c.env), defaultBrand(c.env), listDomains(c.env)]);
  const q = c.req.query();
  const unbranded = domains.filter((d) => d.brand_id === null).map((d) => d.domain);
  const rows = brands
    .map((b) => {
      const eff = mergeBrand(def, b);
      return `<tr>
        <td><a href="/admin/branding/brands/${b.id}"><strong>${escapeHtml(b.name)}</strong></a></td>
        <td>${escapeHtml(eff.appName)}${b.app_name ? "" : ' <span class="muted">(default)</span>'}</td>
        <td>${b.domains.length ? b.domains.map(escapeHtml).join(", ") : '<span class="muted">No domains yet</span>'}</td>
        <td>${b.logo_asset_id ? `<img src="${escapeHtml(eff.logoUrl ?? "")}" alt="" style="max-height:24px; max-width:90px; object-fit:contain;" />` : '<span class="muted">Default</span>'}</td>
        <td>${rowActions(
          iconLink(previewHref(b.id), "eye", "Preview", { newTab: true }),
          iconLink(`/admin/branding/brands/${b.id}`, "edit", "Edit"),
          `<form method="POST" action="/admin/branding/brands/${b.id}/delete" ${confirmAttrs(`${b.domains.length ? `${b.domains.join(", ")} go back to the default brand. ` : ""}The brand's logo is deleted too.`, { title: `Delete ${b.name}?`, action: "Delete brand", danger: true })}>${iconButton("trash", "Delete", { danger: true })}</form>`
        )}</td>
      </tr>`;
    })
    .join("");
  return c.html(
    layout(
      c,
      "Brands",
      `
      ${brandingBanner(q)}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">A brand gives the people on a domain their own sign-in page, logo, colours, custom CSS and emails. Anything a brand leaves empty comes from the <a href="/admin/branding">default brand</a>.</p>
        <p class="muted">Which brand a page shows: once someone is identified (the second step, consent, My account, a reset or invitation link, and every email to them) the brand of their UPN's domain. Before that, on the sign-in page, the domain in an app's OIDC <code>login_hint</code> or a <code>/login?domain=example.com</code> link, else the hostname the page was opened on if it is a branded domain or a subdomain of one (never the issuer's own hostname, ${escapeHtml(new URL(c.env.ISSUER_URL).hostname)}), else the default brand.</p>
        <table>
          <thead><tr><th>Brand</th><th>App name</th><th>Domains</th><th>Logo</th><th></th></tr></thead>
          <tbody>
            <tr>
              <td><a href="/admin/branding"><strong>Default</strong></a></td>
              <td>${escapeHtml(def.appName)}</td>
              <td>${unbranded.length ? `${unbranded.map(escapeHtml).join(", ")}` : '<span class="muted">-</span>'} <span class="muted">and every sign-in with no hint</span></td>
              <td>${def.logoUrl ? `<img src="${escapeHtml(def.logoUrl)}" alt="" style="max-height:24px; max-width:90px; object-fit:contain;" />` : '<span class="muted">FlareID</span>'}</td>
              <td>${rowActions(iconLink(previewHref("default"), "eye", "Preview", { newTab: true }), iconLink("/admin/branding", "edit", "Edit"), '<span class="icon-btn" aria-hidden="true"></span>')}</td>
            </tr>
            ${rows}
          </tbody>
        </table>
      `)}
      ${cardSection(`
        <h2>New brand</h2>
        <form method="POST" action="/admin/branding/brands">
          <label for="brand_name">Name</label>
          <input type="text" id="brand_name" name="name" required maxlength="${BRAND_NAME_MAX}" placeholder="Acme" style="max-width:320px;" />
          <p class="muted" style="margin-top:-8px;">For you; people see the brand's app name. You choose its domains, logo and colours next.</p>
          <div class="form-actions end"><button class="primary" type="submit">Create brand</button></div>
        </form>
      `)}
      `,
      BRANDS_CRUMBS().slice(0, 2).concat({ label: "Brands" })
    )
  );
});

admin.post("/admin/branding/brands", async (c) => {
  const body = await c.req.parseBody();
  let id: number;
  try {
    id = (await createBrand(consoleCtx(c), { name: body.name })).id;
  } catch (e) {
    return c.redirect(brandingBack("/admin/branding/brands", e), 302);
  }
  return c.redirect(`/admin/branding/brands/${id}?saved=1`, 302);
});

async function brandRowOr404(c: Context<{ Bindings: Env }>): Promise<BrandRow | null> {
  return getBrandRow(c.env, Number(c.req.param("id")));
}

admin.get("/admin/branding/brands/:id", async (c) => {
  const row = await brandRowOr404(c);
  if (!row) return consoleError(c, "No such brand.", 404);
  const [def, domains, brands, cssRow] = await Promise.all([
    defaultBrand(c.env),
    listDomains(c.env),
    listBrandRows(c.env),
    c.env.DB.prepare("SELECT custom_css FROM brands WHERE id = ?").bind(row.id).first<{ custom_css: string }>(),
  ]);
  const eff = mergeBrand(def, row);
  const q = c.req.query();
  const brandName = new Map(brands.map((b) => [b.id, b.name]));
  const gradientInherited = !row.gradient_from || !row.gradient_to;
  const accentInherited = !row.email_accent;
  const domainBoxes = domains.length
    ? domains
        .map((d) => {
          const other = d.brand_id !== null && d.brand_id !== row.id ? brandName.get(d.brand_id) : null;
          return `<label style="font-weight:400; display:block;"><input type="checkbox" name="domains" value="${escapeHtml(d.domain)}" ${d.brand_id === row.id ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" />${escapeHtml(d.domain)}${other ? ` <span class="muted">(now ${escapeHtml(other)}: moves here)</span>` : ""}</label>`;
        })
        .join("")
    : '<p class="muted">No domains yet: add one under <a href="/admin/domains">Domains</a>.</p>';
  const colour = (id: string, name: string, value: string) => `<input type="color" id="${id}" name="${name}" value="${escapeHtml(value)}" style="height:42px; padding:4px; cursor:pointer; margin-bottom:0;" />`;

  return c.html(
    layout(
      c,
      row.name,
      `
      ${brandingBanner(q)}
      <div class="two-col">
      ${cardSection(`
        <h2>Brand</h2>
        <form method="POST" action="/admin/branding/brands/${row.id}">
          <input type="hidden" name="domains_present" value="1" />
          <label for="brand_name">Name</label>
          <input type="text" id="brand_name" name="name" value="${escapeHtml(row.name)}" required maxlength="${BRAND_NAME_MAX}" />
          <label for="app_name">App name</label>
          <input type="text" id="app_name" name="app_name" value="${escapeHtml(row.app_name)}" maxlength="${APP_NAME_MAX}" placeholder="${escapeHtml(def.appName)}" />
          <p class="muted" style="margin-top:-8px;">Shown on the sign-in pages, My account and in emails. Empty uses the default brand's (${escapeHtml(def.appName)}).</p>
          <label for="login_subtitle">Sign-in page message</label>
          <input type="text" id="login_subtitle" name="login_subtitle" value="${escapeHtml(row.login_subtitle ?? "")}" maxlength="${SUBTITLE_MAX}" placeholder="${escapeHtml(def.subtitle)}" />
          <p class="muted" style="margin-top:-8px;">Empty uses the default brand's message.</p>
          <label>Sign-in gradient</label>
          <label style="font-weight:400;"><input type="checkbox" name="gradient_default" value="1" ${gradientInherited ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Use the default brand's gradient</label>
          <div class="field-row" style="max-width:320px; margin-top:6px;">
            <div><label for="gradient_from">Start</label>${colour("gradient_from", "gradient_from", eff.gradient.from)}</div>
            <div><label for="gradient_to">End</label>${colour("gradient_to", "gradient_to", eff.gradient.to)}</div>
          </div>
          <label style="margin-top:18px;">Email accent colour</label>
          <label style="font-weight:400;"><input type="checkbox" name="accent_default" value="1" ${accentInherited ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Use the default brand's accent</label>
          <div style="max-width:120px; margin-top:6px;">${colour("email_accent", "email_accent", eff.accent)}</div>
          <label style="margin-top:18px;">Domains</label>
          <p class="muted" style="margin-top:0;">People whose UPN is on these domains see this brand.</p>
          ${domainBoxes}
          <div style="margin-top:18px;">
          ${cssTextarea(cssRow?.custom_css ?? "", "Empty uses the default brand's custom CSS")}
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save</button>${previewLink(row.id, "Preview")}</div>
        </form>
      `)}
      <div>
      ${logoCard(`/admin/branding/brands/${row.id}/logo`, eff.logoUrl, Boolean(row.logo_asset_id), def.logoUrl ? "The default brand's logo is shown." : "FlareID's own mark is shown.")}
      ${cardSection(`
        <h2>Custom CSS</h2>
        ${CUSTOM_CSS_HELP}
      `)}
      ${cardSection(`
        <h2>Delete brand</h2>
        <p class="muted">Its domains go back to the default brand, and its logo is deleted.</p>
        <form method="POST" action="/admin/branding/brands/${row.id}/delete" ${confirmAttrs(`People on ${row.name}'s domains see the default brand from now on.`, { title: "Delete this brand?", action: "Delete", danger: true })}>
          <button class="danger" type="submit">Delete brand</button>
        </form>
      `)}
      </div>
      </div>
      `,
      BRANDS_CRUMBS([{ label: row.name }])
    )
  );
});

admin.post("/admin/branding/brands/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const back = `/admin/branding/brands/${id}`;
  const body = await c.req.parseBody({ all: true });
  const one = (k: string) => (Array.isArray(body[k]) ? String((body[k] as unknown[])[0] ?? "") : body[k] === undefined ? undefined : String(body[k]));
  const input: BrandInput = {};
  if (one("name") !== undefined) input.name = one("name");
  if (one("app_name") !== undefined) input.app_name = one("app_name");
  // An empty message on this form means "the default brand's" (the API can say "none").
  if (one("login_subtitle") !== undefined) input.login_subtitle = one("login_subtitle")!.trim() || null;
  if (one("gradient_from") !== undefined) input.login_gradient = one("gradient_default") ? null : { from: one("gradient_from"), to: one("gradient_to") };
  if (one("email_accent") !== undefined) input.email_accent = one("accent_default") ? null : one("email_accent");
  if (one("custom_css") !== undefined) input.custom_css = one("custom_css");
  if (one("domains_present") !== undefined) input.domains = ([] as unknown[]).concat(body.domains ?? []).map(String);
  try {
    if (!(await getBrandRow(c.env, id))) return consoleError(c, "No such brand.", 404);
    await updateBrand(consoleCtx(c), id, input);
  } catch (e) {
    return c.redirect(brandingBack(back, e), 302);
  }
  return c.redirect(`${back}?saved=1`, 302);
});

admin.post("/admin/branding/brands/:id/delete", async (c) => {
  await deleteBrand(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/branding/brands?saved=1", 302);
});

admin.post("/admin/branding/brands/:id/logo", async (c) => {
  const id = Number(c.req.param("id"));
  const back = `/admin/branding/brands/${id}`;
  try {
    if (!(await getBrandRow(c.env, id))) return consoleError(c, "No such brand.", 404);
    await uploadLogo(consoleCtx(c), id, await uploadedBytes(c));
  } catch (e) {
    return c.redirect(brandingBack(back, e), 302);
  }
  return c.redirect(`${back}?saved=logo`, 302);
});

admin.post("/admin/branding/brands/:id/logo/delete", async (c) => {
  const id = Number(c.req.param("id"));
  await removeLogo(consoleCtx(c), id);
  return c.redirect(`/admin/branding/brands/${id}?saved=logo-removed`, 302);
});

// ---------- Branding > Email templates ----------

const TEMPLATE_KEYS = Object.keys(TEMPLATE_INFO) as TemplateKey[];
const TEMPLATE_FIELDS = ["subject", "heading", "body", "action", "footer"] as const;
const PLACEHOLDER_HELP: Record<string, string> = {
  app_name: "the app name",
  name: "the person's name",
  code: "the one-time code",
  minutes: "how many minutes the code works",
};
const isTemplateKey = (k: string | undefined): k is TemplateKey => !!k && (TEMPLATE_KEYS as string[]).includes(k);

/** The template as typed into the form (or a preview query), unsaved; missing fields keep the given values. */
function templateFromInput(input: Record<string, unknown>, base: EmailTemplate): EmailTemplate {
  const t = { ...base };
  for (const f of TEMPLATE_FIELDS) if (typeof input[f] === "string") t[f] = (input[f] as string).replace(/\r/g, "");
  return t;
}

/**
 * The rendered email for the editor: subject, HTML and plain text, filled in
 * with sample values. The HTML is renderEmail's own (inline styles, escaped
 * text), embedded in the page rather than framed - the CSP frames nothing,
 * so its <body> becomes a bordered container.
 */
function emailPreview(appName: string, key: TemplateKey, t: EmailTemplate, accent: string, logoUrl: string | null): string {
  const vars: Record<string, string> = { app_name: appName, name: "Ada Lovelace", ...(key === "email_otp" ? { code: "428 913", minutes: "10" } : {}) };
  const link = TEMPLATE_INFO[key].hasLink ? `https://example.com/${key === "invitation" ? "invite" : "reset-password"}/sample-link` : undefined;
  const r = renderEmail(t, accent, vars, link, logoUrl);
  const m = /<body style="([^"]*)">([\s\S]*)<\/body>/.exec(r.html);
  return `
    <label>Subject</label>
    <p style="margin:0 0 16px; font-weight:600;">${escapeHtml(r.subject)}</p>
    <label>HTML</label>
    <div style="${m?.[1] ?? ""} border:1px solid var(--fi-line); border-radius:10px; margin-bottom:16px;">${m?.[2] ?? ""}</div>
    <label>Plain text</label>
    ${codeBlock(r.text, { className: "", style: "white-space:pre-wrap; word-break:break-word; margin:0; padding:12px 72px 12px 12px; border:1px solid var(--fi-line); border-radius:10px; background:var(--fi-surface-2); color:var(--fi-body); font-size:0.8125rem;" })}`;
}

// Re-renders the preview as the form changes: the server renders it (one
// implementation), the page swaps it in. Without script, "Preview" does the same.
const EMAIL_PREVIEW_SCRIPT = `(function(){
  var form = document.getElementById("email-template-form");
  var out = document.getElementById("email-preview");
  if (!form || !out) return;
  var timer = null, seq = 0;
  function refresh() {
    var q = new URLSearchParams(new FormData(form));
    var n = ++seq;
    fetch("/admin/branding/email-templates/preview?" + q.toString(), { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (h) { if (h !== null && n === seq) out.innerHTML = h; })
      .catch(function () {});
  }
  function later() { clearTimeout(timer); timer = setTimeout(refresh, 250); }
  form.addEventListener("input", later);
})();`;

admin.get("/admin/branding/email-templates", async (c) => {
  const q = c.req.query();
  const key: TemplateKey = isTemplateKey(q.t) ? q.t : "invitation";
  const info = TEMPLATE_INFO[key];
  const saved = await getTemplate(c.env, key);
  // A no-script "Preview" submits the form here by GET: show the draft, unsaved.
  const draft = typeof q.subject === "string";
  const t = draft ? templateFromInput(q, saved) : saved;
  const accent = await getAccent(c.env);
  const customised = await Promise.all(TEMPLATE_KEYS.map(async (k) => Boolean(await getSetting(c.env, `email_template_${k}`))));
  const field = (f: (typeof TEMPLATE_FIELDS)[number], label: string, max: number) =>
    `<label for="tpl_${f}">${label}</label><input type="text" id="tpl_${f}" name="${f}" value="${escapeHtml(t[f])}" maxlength="${max}" ${f === "subject" || f === "heading" ? "required" : ""} />`;

  const tabs = TEMPLATE_KEYS.map((k, i) => {
    const on = k === key;
    return `<a href="/admin/branding/email-templates?t=${k}" style="display:inline-block; padding:8px 14px; border-radius:8px; text-decoration:none; font-weight:600; border:1px solid ${on ? "var(--fi-accent)" : "var(--fi-line)"}; background:${on ? "var(--fi-accent-soft)" : "var(--fi-surface)"}; color:${on ? "var(--fi-ink)" : "var(--fi-body)"};"${on ? ' aria-current="page"' : ""}>${escapeHtml(TEMPLATE_INFO[k].label)}${customised[i] ? ' <span class="pill" style="margin:0 0 0 6px;">Customised</span>' : ""}</a>`;
  }).join("");

  return c.html(
    layout(
      c,
      "Email templates",
      `
      ${q.saved ? successBanner(q.saved === "reset" ? "Reset to the default wording." : "Saved.") : ""}
      ${q.error ? `<p class="error">${escapeHtml(q.error)}</p>` : ""}
      ${draft ? `<p class="muted">Previewing unsaved changes. Save to use them.</p>` : ""}
      <nav aria-label="Templates" style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:18px;">${tabs}</nav>
      <div class="two-col">
      ${cardSection(`
        <h2>${escapeHtml(info.label)}</h2>
        <form method="POST" action="/admin/branding/email-templates/${key}" id="email-template-form">
          <input type="hidden" name="t" value="${key}" />
          ${field("subject", "Subject", 150)}
          ${field("heading", "Heading", 150)}
          <label for="tpl_body">Body</label>
          <textarea id="tpl_body" name="body" rows="6" maxlength="1500">${escapeHtml(t.body)}</textarea>
          <p class="muted" style="margin-top:-8px;">A blank line starts a new paragraph.${key === "email_otp" ? " The code is shown under the body." : " The button and the link are added under the body."}</p>
          ${info.hasLink ? field("action", "Button label", 60) : ""}
          ${field("footer", "Footer", 500)}
          <label for="email_accent" style="margin-top:18px;">Accent colour</label>
          <input type="color" id="email_accent" name="accent" value="${escapeHtml(accent)}" style="height:42px; max-width:120px; padding:4px; cursor:pointer; display:block;" />
          <p class="muted" style="margin-top:2px;">The top border, button and link colour of every email in the default brand (a <a href="/admin/branding/brands">brand</a> can have its own). The wording above is shared by every brand too: <code>{{app_name}}</code> is the person's brand's app name.</p>
          <p class="muted" style="margin-bottom:6px;">Placeholders:</p>
          <ul class="muted" style="margin:0 0 16px; padding-left:18px;">
            ${info.placeholders.map((p) => `<li><code>{{${escapeHtml(p)}}}</code> ${escapeHtml(PLACEHOLDER_HELP[p] ?? "")}</li>`).join("")}
          </ul>
          <div class="form-actions end">
            <button class="primary" type="submit">Save</button>
            <button class="secondary" type="submit" formmethod="get" formaction="/admin/branding/email-templates">Preview</button>
          </div>
        </form>
        <form method="POST" action="/admin/branding/email-templates/${key}/reset" style="margin-top:12px;" ${confirmAttrs(`Reset the ${info.label.toLowerCase()} email to FlareID's default wording? Your changes to it are lost.`, { title: "Reset to default", action: "Reset", danger: true })}>
          <button class="secondary" type="submit" ${customised[TEMPLATE_KEYS.indexOf(key)] ? "" : "disabled"}>Reset to default</button>
        </form>
      `)}
      ${cardSection(`
        <h2>Preview</h2>
        <p class="muted">With sample values: the person is Ada Lovelace${key === "email_otp" ? ", the code 428 913" : ""}.</p>
        <div id="email-preview">${emailPreview(c.get("appName"), key, t, accent, emailLogoUrl(c.env, { logoUrl: c.get("logoUrl") }))}</div>
      `)}
      </div>
      ${scriptTag(EMAIL_PREVIEW_SCRIPT)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Branding", href: "/admin/branding" }, { label: "Email templates" }]
    )
  );
});

/** The preview alone, for the editor's live refresh. Never saves anything. */
admin.get("/admin/branding/email-templates/preview", async (c) => {
  const q = c.req.query();
  if (!isTemplateKey(q.t)) return consoleError(c, "No such template.", 404);
  const accent = q.accent && isHexColor(q.accent) ? q.accent.toLowerCase() : await getAccent(c.env);
  return c.html(emailPreview(c.get("appName"), q.t, templateFromInput(q, await getTemplate(c.env, q.t)), accent, emailLogoUrl(c.env, { logoUrl: c.get("logoUrl") })));
});

admin.post("/admin/branding/email-templates/:key", async (c) => {
  const key = c.req.param("key");
  if (!isTemplateKey(key)) return consoleError(c, "No such template.", 404);
  const body = await c.req.parseBody();
  const t: Partial<EmailTemplate> = {};
  for (const f of TEMPLATE_FIELDS) if (typeof body[f] === "string") t[f] = body[f] as string;
  try {
    await saveEmailTemplate(consoleCtx(c), key, t);
    // The accent lives on the same form; only a real change is saved (and audited).
    const accent = String(body.accent ?? "").trim();
    if (accent && accent.toLowerCase() !== (await getAccent(c.env))) await saveEmailAccent(consoleCtx(c), accent);
  } catch (e) {
    if (!(e instanceof ServiceError)) throw e;
    return c.redirect(`/admin/branding/email-templates?t=${key}&error=${encodeURIComponent(e.message)}`, 302);
  }
  return c.redirect(`/admin/branding/email-templates?t=${key}&saved=1`, 302);
});

admin.post("/admin/branding/email-templates/:key/reset", async (c) => {
  const key = c.req.param("key");
  if (!isTemplateKey(key)) return consoleError(c, "No such template.", 404);
  await saveEmailTemplate(consoleCtx(c), key, null);
  return c.redirect(`/admin/branding/email-templates?t=${key}&saved=reset`, 302);
});

admin.post("/admin/branding/email-accent", async (c) => {
  const body = await c.req.parseBody();
  const key = isTemplateKey(String(body.t ?? "")) ? String(body.t) : "invitation";
  // Kept for older links; the editor posts the accent with the template form.
  await saveEmailAccent(consoleCtx(c), String(body.accent ?? "").trim());
  return c.redirect(`/admin/branding/email-templates?t=${key}&saved=1`, 302);
});

admin.post("/admin/security/apply-default-password", async (c) => {
  // It resets every password, Super Admins' included.
  if (!c.get("isSuperAdmin")) return consoleError(c, "Applying the default password to every account needs a Super Admin.", 403);
  const count = await applyDefaultPasswordToAll(consoleCtx(c), String((await c.req.parseBody()).default_password ?? ""));
  return c.html(
    layout(
      c,
      "Default password applied",
      cardSection(`
        <p class="success">Reset the password for ${count} account(s) to the default password.</p>
        <a href="/admin/security"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Security", href: "/admin/security" }, { label: "Default password applied" }]
    )
  );
});

admin.post("/admin/security/new-user-password-mode", async (c) => {
  await saveNewUserPasswordMode(consoleCtx(c), (await c.req.parseBody()).mode);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/password-policy", async (c) => {
  await savePasswordPolicy(consoleCtx(c), await c.req.parseBody());
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/breached-passwords", async (c) => {
  await saveBreachedPasswordCheck(consoleCtx(c), String((await c.req.parseBody()).enabled ?? "") === "1");
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/turnstile", async (c) => {
  const body = await c.req.parseBody();
  try {
    await saveTurnstile(consoleCtx(c), { mode: body.mode === undefined ? undefined : String(body.mode), siteKey: String(body.site_key ?? ""), secret: String(body.secret ?? "") });
  } catch (e) {
    if (!(e instanceof ServiceError)) throw e;
    return c.redirect(`/admin/security?error=${encodeURIComponent(e.message)}`, 302);
  }
  return c.redirect("/admin/security?saved=1", 302);
});

// ---------- Authentication policies and factors ----------

const SECURITY_CRUMB: Breadcrumb = { label: "Security", href: "/admin/security" };

/**
 * The Policies page's warning while any administrator can sign in with a
 * password alone: allowed (the instance's choice), but never silently.
 */
async function adminMfaWarning(env: Env): Promise<string> {
  const relaxed = await adminsWithoutMfaPolicy(env);
  if (!relaxed.length) return "";
  const { results } = await env.DB.prepare("SELECT display_name, upn FROM users WHERE id IN (SELECT value FROM json_each(?)) ORDER BY display_name LIMIT 6")
    .bind(JSON.stringify(relaxed))
    .all<{ display_name: string; upn: string }>();
  const names = results.slice(0, 5).map((u) => `<strong>${escapeHtml(u.display_name)}</strong> (${escapeHtml(u.upn)})`).join(", ") + (relaxed.length > 5 ? ` and ${relaxed.length - 5} more` : "");
  return `<div class="notice-warn" role="status"><strong>${relaxed.length === 1 ? "An administrator does" : `${relaxed.length} administrators do`} not need a second factor.</strong>
    The policy that applies to ${relaxed.length === 1 ? "them" : "each of them"} does not require one, so ${names} can sign in to the admin console with a password alone.
    To require one again, add their admin group (such as Super Admins) to a policy that requires a second factor, such as "Password and a second factor".</div>`;
}

admin.get("/admin/security/policies", async (c) => {
  const [policies, groups, warning] = await Promise.all([listPolicies(c.env), c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>(), adminMfaWarning(c.env)]);
  const reqLabel = (r: string) => (r === "mfa" ? "Password + second factor (or a passkey)" : "Password (or a passkey)");
  const row = (p: (typeof policies)[number]) => `
    <tr>
      <td><strong>${escapeHtml(p.name)}</strong>${p.is_default ? ' <span class="badge badge-active">Default</span>' : ""}<br /><span class="muted">${escapeHtml(p.description)}</span></td>
      <td>${reqLabel(p.requirement)}${p.device_cert ? '<br /><span class="badge badge-pending">WARP device cert</span>' : ""}${p.max_risk ? `<br /><span class="badge badge-pending">Risk cap: ${escapeHtml(p.max_risk)}</span>` : ""}</td>
      <td>${p.groups.map((g) => `<span class="pill">${escapeHtml(g.name)}</span>`).join(" ")}${p.is_default ? `${p.groups.length ? " and " : ""}<span class="muted">everyone not matched by another policy</span>` : p.groups.length ? "" : '<span class="muted">No groups yet</span>'}${p.apps.length ? `<br/>${p.apps.map((a) => `<a class="pill" href="${a.kind === "oidc" ? `/admin/clients/${a.id}` : `/admin/saml/${a.id}`}?tab=policies">${escapeHtml(a.name)}</a>`).join(" ")}` : ""}</td>
      <td>${p.groups.length ? p.priority : "&mdash;"}</td>
      <td>${rowActions(iconLink(`/admin/security/policies/${p.id}`, "edit", "Edit"))}</td>
    </tr>`;
  return c.html(
    layout(
      c,
      "Authentication policies",
      `${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        ${warning}
        <p class="muted" style="margin-top:0;">A policy says what someone must present to sign in. Each person gets the policy of their highest-priority group (lowest number);
          anyone not in a policy's groups gets the default. A passkey satisfies every policy: it is multi-factor on its own.
          Administrators follow their policy too: a fresh install puts Super Admins in "Password and a second factor", and taking them out of it lets them sign in with a password alone.
          When a policy does require a second factor of an administrator, security questions never count.</p>
        <p class="muted">Policies govern two things. <strong>FlareID sign-in</strong> - the built-in application everyone can log in to, covering the console and My account - resolves each person's policy from their groups.
          And any <strong>app</strong> can bind a policy on its Policies tab, making its device-certificate, risk and second-factor demands part of signing in to that app; bound apps appear beside the groups above.</p>
        <table><thead><tr><th>Policy</th><th>Requires</th><th>Applies to</th><th>Priority</th><th></th></tr></thead><tbody>${policies.map(row).join("")}</tbody></table>
      `)}
      ${cardSection(`
        <h2>New policy</h2>
        <form method="POST" action="/admin/security/policies">
          <div class="field-row">
            <div><label for="p_name">Name</label><input type="text" id="p_name" name="name" required maxlength="80" /></div>
            <div><label for="p_req">Requires</label><select id="p_req" name="requirement"><option value="mfa">Password + second factor (or a passkey)</option><option value="password">Password (or a passkey)</option></select></div>
          </div>
          <label for="p_desc">Description</label><input type="text" id="p_desc" name="description" maxlength="200" />
          <div class="field-row">
            <div>
              <label for="p_maxrisk">Cloudflare risk cap</label>
              <select id="p_maxrisk" name="max_risk">
                <option value="">No check</option>
                <option value="low">Deny above low</option>
                <option value="medium">Deny above medium</option>
              </select>
              <p class="muted" style="margin:4px 0 0;">Needs the Cloudflare One connection; an unconfigured or failing check does not block sign-in.</p>
            </div>
            <div>
              <label for="p_devcert" style="display:flex; align-items:flex-start; gap:8px; font-weight:500;">
                <input type="checkbox" id="p_devcert" name="device_cert" value="1" style="width:auto; margin:3px 0 0;" />
                <span>Require a WARP device certificate<br/><span class="muted" style="font-weight:400;">Sign-in only proceeds when Cloudflare verified a client certificate on the request (mTLS must be enforced on the zone).</span></span>
              </label>
            </div>
          </div>
          <label for="p_pri">Priority (lower wins)</label><input type="number" id="p_pri" name="priority" min="1" max="1000" value="10" style="max-width:120px;" />
          ${multiSelect("group_ids", groups.results.map((g) => ({ id: g.id, label: g.name })), new Set<number>(), "Search groups...")}
          <div class="form-actions end"><button class="primary" type="submit">Create policy</button></div>
        </form>
      `)}`,
      [{ label: "Admin", href: "/admin" }, SECURITY_CRUMB, { label: "Policies" }]
    )
  );
});

async function readPolicyForm(c: { req: { parseBody: (o: { all: true }) => Promise<Record<string, unknown>> } }) {
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  return normalizePolicy({ ...body, groupIds: list(body.group_ids), makeDefault: body.make_default, deviceCert: body.device_cert === "1", maxRisk: body.max_risk });
}

admin.post("/admin/security/policies", async (c) => {
  let f;
  try {
    f = await readPolicyForm(c);
  } catch (e) {
    return consoleError(c, (e as Error).message, 400);
  }
  await createPolicy(consoleCtx(c), f);
  return c.redirect("/admin/security/policies?saved=1", 302);
});

admin.get("/admin/security/policies/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const p = (await listPolicies(c.env)).find((x) => x.id === id);
  if (!p) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const [groups, admins, warning] = await Promise.all([c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>(), adminPolicies(c.env), adminMfaWarning(c.env)]);
  // Administrators this policy makes use a second factor: saving or deleting
  // it may take that away, so both ask first. A password policy made the
  // default would relax the administrators the MFA default covers.
  const covered = p.requirement === "mfa" ? admins.filter((a) => a.policyId === p.id).length : 0;
  const defaultId = (await c.env.DB.prepare("SELECT id FROM auth_policies WHERE is_default = 1").first<{ id: number }>())?.id;
  const viaDefault = p.requirement === "password" && !p.is_default ? admins.filter((a) => a.requiresMfa && a.policyId === defaultId).length : 0;
  const people = (n: number) => (n === 1 ? "1 administrator" : `${n} administrators`);
  const saveConfirm = covered
    ? confirmAttrs(
        `This policy makes ${people(covered)} use a second factor. If your change takes their group out of it or stops it requiring a second factor, they will sign in to the admin console with a password alone.`,
        { title: "Change the administrators' second-factor policy?", action: "Save", danger: true }
      )
    : viaDefault
      ? confirmAttrs(`Making this password-only policy the default lets ${people(viaDefault)} sign in to the admin console with a password alone: the default is what makes them use a second factor now.`, {
          title: "Let administrators sign in with a password alone?",
          action: "Save",
          danger: true,
          when: 'input[name="make_default"]',
        })
      : "";
  const deleteNote = covered ? ` It makes ${people(covered)} use a second factor: without it, their policy may let them sign in with a password alone.` : "";
  return c.html(
    layout(
      c,
      p.name,
      cardSection(`
        ${warning}
        <form method="POST" action="/admin/security/policies/${p.id}">
          <div class="field-row">
            <div><label for="p_name">Name</label><input type="text" id="p_name" name="name" required maxlength="80" value="${escapeHtml(p.name)}" /></div>
            <div><label for="p_req">Requires</label><select id="p_req" name="requirement">
              <option value="mfa" ${p.requirement === "mfa" ? "selected" : ""}>Password + second factor (or a passkey)</option>
              <option value="password" ${p.requirement === "password" ? "selected" : ""}>Password (or a passkey)</option></select></div>
          </div>
          <label for="p_desc">Description</label><input type="text" id="p_desc" name="description" maxlength="200" value="${escapeHtml(p.description)}" />
          ${p.is_default ? '<p class="muted">This is the default policy: it applies to everyone no other policy matches. It can also be assigned to groups, so they keep it if another policy becomes the default.</p>' : ""}
          <div class="field-row">
            <div>
              <label for="p_maxrisk">Cloudflare risk cap</label>
              <select id="p_maxrisk" name="max_risk">
                <option value="" ${p.max_risk === "" ? "selected" : ""}>No check</option>
                <option value="low" ${p.max_risk === "low" ? "selected" : ""}>Deny above low</option>
                <option value="medium" ${p.max_risk === "medium" ? "selected" : ""}>Deny above medium</option>
              </select>
              <p class="muted" style="margin:4px 0 0;">Needs the Cloudflare One connection; an unconfigured or failing check does not block sign-in.</p>
            </div>
            <div>
              <label for="p_devcert" style="display:flex; align-items:flex-start; gap:8px; font-weight:500;">
                <input type="checkbox" id="p_devcert" name="device_cert" value="1" ${p.device_cert ? "checked" : ""} style="width:auto; margin:3px 0 0;" />
                <span>Require a WARP device certificate<br/><span class="muted" style="font-weight:400;">Sign-in only proceeds when Cloudflare verified a client certificate on the request.</span></span>
              </label>
            </div>
          </div>
          <label for="p_pri">Priority (lower wins)</label><input type="number" id="p_pri" name="priority" min="1" max="1000" value="${p.priority}" style="max-width:120px;" />
          ${multiSelect("group_ids", groups.results.map((g) => ({ id: g.id, label: g.name })), new Set(p.groups.map((g) => g.id)), "Search groups...")}
          <label style="margin-top:12px;">Apps using this policy</label>
          ${p.apps.length
            ? `<p class="muted" style="margin-top:-6px;">${p.apps.map((a) => `<a href="${a.kind === "oidc" ? `/admin/clients/${a.id}` : `/admin/saml/${a.id}`}?tab=policies">${escapeHtml(a.name)}</a>`).join(", ")} &mdash; bound on each app's Policies tab.</p>`
            : '<p class="muted" style="margin-top:-6px;">None &mdash; apps bind a policy on their own Policies tab.</p>'}
          ${p.is_default ? "" : `<label style="font-weight:400;"><input type="checkbox" name="make_default" value="1" style="width:auto; display:inline; margin-right:6px;" /> Make this the default policy</label>`}
          <div class="form-actions end">
            ${p.is_default ? "" : `<button class="danger" type="submit" formaction="/admin/security/policies/${p.id}/delete" formnovalidate ${confirmAttrs(`Its groups fall back to another matching policy or the default.${deleteNote}`, { title: `Delete the policy "${p.name}"?`, action: "Delete policy", danger: true })}>Delete policy</button>`}
            ${cancelLink("/admin/security/policies")}
            <button class="primary" type="submit" ${saveConfirm}>Save</button>
          </div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, SECURITY_CRUMB, { label: "Policies", href: "/admin/security/policies" }, { label: p.name }]
    )
  );
});

admin.post("/admin/security/policies/:id", async (c) => {
  const id = Number(c.req.param("id"));
  if (!(await c.env.DB.prepare("SELECT 1 FROM auth_policies WHERE id = ?").bind(id).first())) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  let f;
  try {
    f = await readPolicyForm(c);
  } catch (e) {
    return consoleError(c, (e as Error).message, 400);
  }
  await updatePolicy(consoleCtx(c), id, f);
  return c.redirect("/admin/security/policies?saved=1", 302);
});

admin.post("/admin/security/policies/:id/delete", async (c) => {
  await deletePolicy(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/security/policies?saved=1", 302);
});

// ---------- Roles ----------

const ROLE_CRUMBS = (extra: Breadcrumb[] = []): Breadcrumb[] => [{ label: "Admin", href: "/admin" }, { label: "Security", href: "/admin/security" }, { label: "Roles", href: "/admin/security/roles" }, ...extra];

function permissionSummary(perms: string[]): string {
  if (perms.includes("*")) return "<strong>Everything</strong>";
  const byArea = AREAS.map((a) => (perms.includes(`${a.key}:write`) ? `${a.label} (change)` : perms.includes(`${a.key}:read`) ? `${a.label} (read)` : "")).filter(Boolean);
  const self = SELF_PERMISSIONS.filter((p) => perms.includes(p.key)).map((p) => p.label);
  return escapeHtml([...byArea, ...self].join(", ") || "Nothing");
}

/** The people each role reaches through its groups (or everyone, for a default role). */
async function roleMembers(env: Env, roles: Awaited<ReturnType<typeof listRoles>>): Promise<Map<number, number[]>> {
  const groupIds = [...new Set(roles.flatMap((r) => r.groups.map((g) => g.id)))];
  const groups = groupIds.length ? (await env.DB.prepare("SELECT * FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(groupIds)).all<GroupRow>()).results : [];
  const members = await resolveManyGroupMemberUserIds(env, groups);
  return new Map(roles.map((r) => [r.id, [...new Set(r.groups.flatMap((g) => members.get(g.id) ?? []))]]));
}

admin.get("/admin/security/roles", async (c) => {
  const roles = await listRoles(c.env);
  const members = await roleMembers(c.env, roles);
  const totalUsers = (await c.env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>())?.n ?? 0;
  // Administrators: everyone a non-default role reaches, with the roles that do it.
  const adminIds = [...new Set(roles.filter((r) => !r.is_default).flatMap((r) => members.get(r.id) ?? []))];
  const admins = adminIds.length
    ? (
        await c.env.DB.prepare(
          "SELECT id, display_name, upn, status, mfa_enabled, email_otp_enabled, (SELECT COUNT(*) FROM webauthn_credentials w WHERE w.user_id = users.id) AS passkeys FROM users WHERE id IN (SELECT value FROM json_each(?)) ORDER BY display_name"
        )
          .bind(JSON.stringify(adminIds))
          .all<{ id: number; display_name: string; upn: string; status: string; mfa_enabled: number; email_otp_enabled: number; passkeys: number }>()
      ).results
    : [];
  const rolesOf = (uid: number) => roles.filter((r) => !r.is_default && (members.get(r.id) ?? []).includes(uid));
  // Whose policy makes them use a second factor (secure by default; Security > Policies can relax it).
  const relaxed = new Set(await adminsWithoutMfaPolicy(c.env));
  return c.html(
    layout(
      c,
      "Roles",
      `${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        <div class="card-head"><p class="muted" style="margin:0;">A role is a set of permissions, given to groups. Everyone's access is the default role plus the roles of their groups. API keys use the same permissions.</p>
          <a href="/admin/security/roles/new"><button class="primary" type="button">+ New role</button></a></div>
        <table><thead><tr><th>Role</th><th>Permissions</th><th>Granted to</th><th>People</th><th></th></tr></thead><tbody>
          ${roles.map((r) => `<tr>
            <td><strong>${escapeHtml(r.name)}</strong>${r.is_default ? ' <span class="badge badge-active">Default</span>' : ""}${r.builtin ? ' <span class="pill">Built in</span>' : ""}<br /><span class="muted">${escapeHtml(r.description)}</span></td>
            <td style="max-width:420px;">${permissionSummary(rolePermissions(r))}</td>
            <td>${r.is_default ? '<span class="muted">Everyone</span>' : r.groups.map((g) => `<a class="pill" href="/admin/groups/${g.id}">${escapeHtml(g.name)}</a>`).join(" ") || '<span class="muted">No groups</span>'}</td>
            <td>${r.is_default ? totalUsers : (members.get(r.id) ?? []).length}</td>
            <td style="text-align:right;"><a href="/admin/security/roles/${r.id}">${r.name === SUPER_ROLE ? "View" : "Edit"}</a></td></tr>`).join("")}
        </tbody></table>
      `)}
      ${cardSection(`
        <h2>Administrators</h2>
        <p class="muted">Everyone with more than the default role, and what they can do. Administrators follow their <a href="/admin/security/policies">authentication policy</a> like everyone else; a fresh install puts Super Admins in "Password and a second factor". When their policy requires a second factor it must be the authenticator app, a passkey or email codes - never security questions - and without one they are sent to set one up before the console opens.</p>
        ${relaxed.size ? `<div class="notice-warn" role="status">${relaxed.size === 1 ? "1 administrator's policy lets them" : `${relaxed.size} administrators' policies let them`} sign in with a password alone. <a href="/admin/security/policies">Review the policies</a>.</div>` : ""}
        ${
          admins.length
            ? `<table><thead><tr><th>Person</th><th>Roles</th><th>Second factor</th><th>Can</th></tr></thead><tbody>${admins
                .map((u) => {
                  const rs = rolesOf(u.id);
                  const factors = [u.mfa_enabled ? "Authenticator app" : "", u.passkeys ? `Passkey${u.passkeys > 1 ? "s" : ""}` : "", u.email_otp_enabled ? "Email codes" : ""].filter(Boolean);
                  const none = relaxed.has(u.id) ? "Not required by their policy" : "Must set one up at their next sign-in";
                  const second = factors.length ? escapeHtml(factors.join(", ")) : `<span class="badge badge-disabled">None</span><br /><span class="muted">${none}</span>`;
                  return `<tr><td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a><br /><span class="muted">${escapeHtml(u.upn)}</span>${u.status !== "active" ? ' <span class="badge badge-disabled">Inactive</span>' : ""}</td><td>${rs.map((r) => escapeHtml(r.name)).join(", ")}</td><td>${second}</td><td style="max-width:460px;">${permissionSummary(rs.flatMap(rolePermissions))}</td></tr>`;
                })
                .join("")}</tbody></table>`
            : '<p class="muted">Nobody yet.</p>'
        }
      `)}`,
      ROLE_CRUMBS().slice(0, 3).concat([{ label: "Roles" }])
    )
  );
});

async function roleForm(c: { env: Env }, role: (Awaited<ReturnType<typeof listRoles>>)[number] | null): Promise<string> {
  const groups = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>();
  const locked = role?.name === SUPER_ROLE;
  return cardSection(`
    <form method="POST" action="${role ? `/admin/security/roles/${role.id}` : "/admin/security/roles"}">
      <div class="field-row">
        <div><label for="r_name">Name</label><input type="text" id="r_name" name="name" required maxlength="80" value="${escapeHtml(role?.name ?? "")}" ${role?.builtin ? "readonly" : ""} /></div>
        <div><label for="r_desc">Description</label><input type="text" id="r_desc" name="description" maxlength="200" value="${escapeHtml(role?.description ?? "")}" /></div>
      </div>
      ${
        locked
          ? '<p class="muted">Super Admin holds every permission and cannot be changed. Who holds it is set by membership of the Super Admins group.</p>'
          : `<h3 style="margin-top:12px;">Permissions</h3>${permissionMatrix(new Set(role ? rolePermissions(role) : []), { self: true })}
             <h3 style="margin-top:16px;">Granted to</h3>
             ${role?.is_default ? '<p class="muted">The default role applies to everyone.</p>' : multiSelect("group_ids", groups.results.map((g) => ({ id: g.id, label: g.name })), new Set(role?.groups.map((g) => g.id) ?? []), "Search groups...")}`
      }
      <div class="form-actions end">
        ${role && !role.builtin ? `<button class="danger" type="submit" formaction="/admin/security/roles/${role.id}/delete" formnovalidate ${confirmAttrs("Everyone who holds it through its groups loses these permissions.", { title: `Delete the role "${role.name}"?`, action: "Delete role", danger: true })}>Delete role</button>` : ""}
        ${cancelLink("/admin/security/roles")}
        ${locked ? "" : `<button class="primary" type="submit">${role ? "Save" : "Create role"}</button>`}
      </div>
    </form>`);
}

admin.get("/admin/security/roles/new", async (c) => c.html(layout(c, "New role", await roleForm(c, null), ROLE_CRUMBS([{ label: "New role" }]))));

admin.get("/admin/security/roles/:id", async (c) => {
  const role = (await listRoles(c.env)).find((r) => r.id === Number(c.req.param("id")));
  if (!role) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  return c.html(layout(c, role.name, await roleForm(c, role), ROLE_CRUMBS([{ label: role.name }])));
});

/** Reads and checks a role form: nobody can grant a permission they do not hold themselves (services/access.ts). */
async function readRoleForm(c: { env: Env; get: (k: "access") => Access; req: { parseBody: (o: { all: true }) => Promise<Record<string, unknown>> } }) {
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v : v === undefined ? [] : [v]);
  return normalizeRole({ name: body.name, description: body.description, permissions: readPermissionMatrix(body), groupIds: list(body.group_ids) }, c.get("access").perms);
}

admin.post("/admin/security/roles", async (c) => {
  let f;
  try {
    f = await readRoleForm(c);
  } catch (e) {
    return consoleError(c, (e as Error).message, 400);
  }
  await createRole(consoleCtx(c), f);
  return c.redirect("/admin/security/roles?saved=1", 302);
});

admin.post("/admin/security/roles/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const role = await c.env.DB.prepare("SELECT * FROM admin_roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!role) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  if (role.name === SUPER_ROLE) return consoleError(c, "Super Admin cannot be changed.", 400);
  let f;
  try {
    f = await readRoleForm(c);
  } catch (e) {
    return consoleError(c, (e as Error).message, 400);
  }
  await updateRole(consoleCtx(c), id, f);
  return c.redirect("/admin/security/roles?saved=1", 302);
});

admin.post("/admin/security/roles/:id/delete", async (c) => {
  await deleteRole(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/security/roles?saved=1", 302);
});

admin.get("/admin/security/factors", async (c) => {
  const states = await Promise.all(FACTORS.filter((f) => f.available).map(async (f) => [f.key, await isFactorEnabled(c.env, f.key as FactorKey)] as const));
  const on = new Map<string, boolean>(states);
  const enrolled = await factorEnrolmentCounts(c.env);
  // Email codes need email: say so instead of offering a switch that cannot work.
  const emailReady = await isEmailConfigured(c.env);
  const blocked = (key: string) => key === "email_otp" && !emailReady;
  const kba = await getKbaSettings(c.env);
  const note = (key: string) => {
    if (blocked(key)) {
      return `<br /><span class="muted"><strong>${on.get(key) ? "Not working: no codes can be sent until email is configured under" : "Needs email to be configured first, under"} <a href="/admin/integrations/email">Integrations &rarr; Email</a>.</strong></span>`;
    }
    if (key === "security_questions") {
      return `<br /><span class="muted">People set ${kba.required} and are asked ${kba.asked} at sign-in. <a href="/admin/security/factors/security-questions">Questions and settings</a></span>${
        on.get(key) ? `<br /><span class="muted"><strong>Recommended: keep a stronger factor on as well (authenticator app, passkeys, backup codes or email codes) and encourage people to enrol one; security questions alone are easy to guess or research.</strong></span>` : ""
      }`;
    }
    return "";
  };
  return c.html(
    layout(
      c,
      "Factors",
      `${c.req.query("saved") ? successBanner("Saved.") : ""}${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">The second-factor methods people can enrol and sign in with. A password is always available; turning a factor off stops it counting toward a policy and hides its enrolment.
          Security questions never count for an administrator, so while a <a href="/admin/security/policies">policy</a> requires an administrator to use a second factor, one of the authenticator app, passkeys, backup codes and email codes stays on.</p>
        <table><thead><tr><th>Factor</th><th>Enrolled users</th><th>Status</th><th></th></tr></thead><tbody>
          <tr><td><strong>Password</strong><br /><span class="muted">Always on; rules are under Security &rarr; Settings.</span></td><td>&mdash;</td><td><span class="badge badge-active">On</span></td><td></td></tr>
          ${FACTORS.map((f) =>
            f.available
              ? `<tr><td><strong>${escapeHtml(f.label)}</strong><br /><span class="muted">${escapeHtml(f.description)}</span>${note(f.key)}</td><td>${enrolled[f.key] ?? 0}</td>
                  <td><span class="badge ${on.get(f.key) ? "badge-active" : "badge-disabled"}">${on.get(f.key) ? "On" : "Off"}</span></td>
                  <td style="text-align:right;"><form method="POST" action="/admin/security/factors/${f.key}"><input type="hidden" name="enabled" value="${on.get(f.key) ? "0" : "1"}" /><button class="secondary" type="submit" ${!on.get(f.key) && blocked(f.key) ? "disabled" : ""}>${on.get(f.key) ? "Turn off" : "Turn on"}</button></form></td></tr>`
              : `<tr><td><strong>${escapeHtml(f.label)}</strong><br /><span class="muted">${escapeHtml(f.description)}</span></td><td>&mdash;</td><td><span class="pill">Planned</span></td><td></td></tr>`
          ).join("")}
        </tbody></table>
      `)}`,
      [{ label: "Admin", href: "/admin" }, SECURITY_CRUMB, { label: "Factors" }]
    )
  );
});

admin.get("/admin/security/factors/security-questions", async (c) => {
  const [questions, kba, on] = await Promise.all([listSecurityQuestions(c.env), getKbaSettings(c.env), isFactorEnabled(c.env, "security_questions")]);
  const enabledCount = questions.filter((q) => q.enabled).length;
  return c.html(
    layout(
      c,
      "Security questions",
      `${c.req.query("saved") ? successBanner("Saved.") : ""}${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">Security questions are <strong>${on ? "on" : "off"}</strong> (switched under <a href="/admin/security/factors">Factors</a>). They are the weakest second factor: answers can often be guessed, looked up or phished. Prefer the authenticator app, passkeys, backup codes or email codes, and if you use questions, keep one of those on too. Answers are normalised (case, spacing, Unicode) and stored hashed like passwords; nobody can read them back. A sign-in with security questions never counts as the step-up re-authentication Super Admins need for sensitive console actions.</p>
        <h2>Settings</h2>
        <form method="POST" action="/admin/security/factors/security-questions/settings">
          <div class="form-grid">
            <div><label for="kba_required">Questions each person sets</label><input type="number" id="kba_required" name="required" min="1" max="${KBA_MAX_REQUIRED}" value="${kba.required}" required /></div>
            <div><label for="kba_asked">Questions asked at sign-in</label><input type="number" id="kba_asked" name="asked" min="1" max="${KBA_MAX_REQUIRED}" value="${kba.asked}" required /></div>
          </div>
          <p class="muted">Every question asked must be answered correctly; wrong answers count toward the sign-in attempt limit under Security &rarr; Settings. Which questions are asked is chosen at random for each sign-in attempt.</p>
          <div class="form-actions"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Questions</h2>
        <p class="muted">${enabledCount} enabled. People choose from the enabled questions; disabling one stops it being offered, while answers already given to it keep working. A question someone has answered cannot be deleted.</p>
        <table><thead><tr><th>Question</th><th>Answered by</th><th>Status</th><th></th></tr></thead><tbody>
          ${questions
            .map(
              (q) => `<tr><td>${escapeHtml(q.text)}</td><td>${q.answered_by}</td>
                <td><span class="badge ${q.enabled ? "badge-active" : "badge-disabled"}">${q.enabled ? "Enabled" : "Disabled"}</span></td>
                <td><div class="row-actions" style="gap:8px;">
                  <form method="POST" action="/admin/security/factors/security-questions/questions/${q.id}"><input type="hidden" name="enabled" value="${q.enabled ? "0" : "1"}" /><button class="secondary" type="submit">${q.enabled ? "Disable" : "Enable"}</button></form>
                  ${q.answered_by === 0 ? `<form method="POST" action="/admin/security/factors/security-questions/questions/${q.id}/delete" ${confirmAttrs("The question is removed from the list.", { title: "Delete this question?", action: "Delete", danger: true })}>${iconButton("trash", "Delete", { danger: true })}</form>` : ""}
                </div></td></tr>`
            )
            .join("")}
        </tbody></table>
        <form method="POST" action="/admin/security/factors/security-questions/questions" style="margin-top:14px;">
          <label for="kba_new">Add a question</label>
          <div class="row" style="justify-content:flex-start; gap:8px;">
            <input type="text" id="kba_new" name="text" minlength="5" maxlength="${KBA_MAX_QUESTION}" required placeholder="What was the name of your first teacher?" style="max-width:480px; margin:0;" />
            <button class="secondary" type="submit">Add</button>
          </div>
          <p class="muted">Good questions have answers that are memorable, don't change, and aren't on social media or in public records.</p>
        </form>
      `)}`,
      [{ label: "Admin", href: "/admin" }, SECURITY_CRUMB, { label: "Factors", href: "/admin/security/factors" }, { label: "Security questions" }]
    )
  );
});

/** Runs a security-questions change and goes back to its page, with the refusal as a message. */
async function kbaAction(c: Context<{ Bindings: Env }>, run: () => Promise<unknown>) {
  try {
    await run();
  } catch (e) {
    if (!(e instanceof ServiceError)) throw e;
    if (e.status === 404) return consoleError(c, e.message, 404);
    return c.redirect(`/admin/security/factors/security-questions?error=${encodeURIComponent(e.message)}`, 302);
  }
  return c.redirect("/admin/security/factors/security-questions?saved=1", 302);
}

admin.post("/admin/security/factors/security-questions/settings", async (c) => {
  const body = await c.req.parseBody();
  return kbaAction(c, () => saveKbaSettings(consoleCtx(c), { required: String(body.required ?? ""), asked: String(body.asked ?? "") }));
});

admin.post("/admin/security/factors/security-questions/questions", async (c) => {
  const body = await c.req.parseBody();
  return kbaAction(c, () => addSecurityQuestion(consoleCtx(c), String(body.text ?? "")));
});

admin.post("/admin/security/factors/security-questions/questions/:id", async (c) => {
  const body = await c.req.parseBody();
  return kbaAction(c, () => setSecurityQuestionEnabled(consoleCtx(c), Number(c.req.param("id")), String(body.enabled) === "1"));
});

admin.post("/admin/security/factors/security-questions/questions/:id/delete", async (c) => {
  return kbaAction(c, () => deleteSecurityQuestion(consoleCtx(c), Number(c.req.param("id"))));
});

admin.post("/admin/security/factors/:key", async (c) => {
  try {
    await saveFactor(consoleCtx(c), c.req.param("key"), String((await c.req.parseBody()).enabled) === "1");
  } catch (e) {
    if (!(e instanceof ServiceError)) throw e;
    if (e.message === "Unknown factor.") return consoleError(c, e.message, 400);
    return c.redirect(`/admin/security/factors?error=${encodeURIComponent(e.message)}`, 302);
  }
  return c.redirect("/admin/security/factors?saved=1", 302);
});

// ---------- Signing keys ----------

admin.get("/admin/security/signing-keys", async (c) => {
  const keys = await listSigningKeys(c.env);
  const usage = await c.env.DB.prepare("SELECT id_token_signed_response_alg AS alg, COUNT(*) AS n FROM oauth_clients GROUP BY id_token_signed_response_alg").all<{ alg: string; n: number }>();
  const clientsUsing = (alg: string) => usage.results.find((r) => r.alg === alg)?.n ?? 0;
  const when = (iso: string) => ts(iso);
  const publishedUntil = (k: (typeof keys)[number]) => {
    if (k.status === "active") return '<span class="muted">While active</span>';
    const until = new Date(Date.parse(k.retired_at!) + RETIRED_PUBLISH_HOURS * 3600 * 1000);
    return until.getTime() > Date.now() ? when(until.toISOString()) : '<span class="muted">Expired &mdash; removed by the hourly cleanup</span>';
  };
  return c.html(
    layout(
      c,
      "Signing keys",
      `${c.req.query("rotated") ? successBanner(`Rotated. New key: ${c.req.query("rotated")}`) : ""}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">The keys that sign id_tokens and access tokens, published at <a href="/jwks.json"><code>/jwks.json</code></a>. Each algorithm has one active key. Rotating makes a new active key straight away &mdash; no redeploy &mdash; and retires the old one, which stays published for ${RETIRED_PUBLISH_HOURS} hours so tokens it already signed still verify. After that the hourly cleanup removes it.</p>
        <table><thead><tr><th>Algorithm</th><th>Active key</th><th>Since</th><th>Clients using it</th><th></th></tr></thead><tbody>
          ${SIGNING_ALGS.map((alg) => {
            const active = keys.find((k) => k.alg === alg && k.status === "active");
            return `<tr><td><strong>${alg}</strong></td><td>${active ? `<code>${escapeHtml(active.kid)}</code>` : '<span class="muted">None yet</span>'}</td><td>${active ? when(active.created_at) : "&mdash;"}</td><td>${clientsUsing(alg)}</td>
              <td style="text-align:right;"><form method="POST" action="/admin/security/signing-keys/${alg}/rotate" ${confirmAttrs(`A new ${alg} key signs every token from now on. The current key stays published for ${RETIRED_PUBLISH_HOURS} hours so tokens it signed still verify; relying parties that cache the key set pick up the new key on their next refresh.`, { title: `Rotate the ${alg} signing key?`, action: "Rotate key" })}><button class="secondary" type="submit">Rotate</button></form></td></tr>`;
          }).join("")}
        </tbody></table>
      `)}
      ${cardSection(`
        <h2>All keys</h2>
        <table><thead><tr><th>Key ID</th><th>Algorithm</th><th>Status</th><th>Created</th><th>Retired</th><th>Published until</th></tr></thead><tbody>
          ${keys
            .map((k) => `<tr${k.status === "active" ? ' class="key-active" style="background:var(--fi-green-soft);"' : ""}>
              <td>${k.status === "active" ? `<strong><code>${escapeHtml(k.kid)}</code></strong>` : `<code>${escapeHtml(k.kid)}</code>`}</td>
              <td>${escapeHtml(k.alg)}</td>
              <td><span class="badge ${k.status === "active" ? "badge-active" : "badge-disabled"}">${k.status === "active" ? "Active" : "Retired"}</span></td>
              <td>${when(k.created_at)}</td>
              <td>${k.retired_at ? when(k.retired_at) : "&mdash;"}</td>
              <td>${publishedUntil(k)}</td></tr>`)
            .join("")}
        </tbody></table>
      `)}`,
      [{ label: "Admin", href: "/admin" }, SECURITY_CRUMB, { label: "Signing keys" }]
    )
  );
});

admin.post("/admin/security/signing-keys/:alg/rotate", async (c) => {
  const kid = await rotateKey(consoleCtx(c), c.req.param("alg"));
  return c.redirect(`/admin/security/signing-keys?rotated=${encodeURIComponent(kid)}`, 302);
});

admin.post("/admin/security/require-mfa", async (c) => {
  await saveRequireMfa(consoleCtx(c), !!(await c.req.parseBody()).required);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/rate-limit", async (c) => {
  const body = await c.req.parseBody();
  await saveRateLimit(consoleCtx(c), body.maxAttempts, body.windowMinutes);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/session-limits", async (c) => {
  const body = await c.req.parseBody();
  await saveSessionLimits(consoleCtx(c), body.maxHours, body.idleMinutes);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/audit-retention", async (c) => {
  await saveAuditRetention(consoleCtx(c), (await c.req.parseBody()).days);
  return c.redirect("/admin/security?saved=1", 302);
});

// ---------- SCIM (push users/groups to e.g. Cloudflare Access) ----------

function scimScopeFrom(body: Record<string, unknown>): { mode: "all" | "selected"; groupIds: number[] } {
  return {
    mode: body.mode === "selected" ? "selected" : "all",
    groupIds: Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [],
  };
}

const scimTargetUrl = (id: number, extra = "") => `/admin/integrations/scim/${id}${extra}`;

/** The console edit page of the app a SCIM target is linked to. */
const appEditUrl = (appType: "oidc" | "saml", appId: number) => (appType === "oidc" ? `/admin/clients/${appId}` : `/admin/saml/${appId}`);

/** The app an app_type/app_id pair names, or null (standalone target / invalid linkage). */
async function linkedApp(env: Env, appType: unknown, appId: unknown): Promise<{ type: "oidc" | "saml"; id: number; name: string } | null> {
  const type = appType === "oidc" || appType === "saml" ? appType : null;
  const id = Number(appId);
  if (!type || !Number.isInteger(id) || id <= 0) return null;
  const table = type === "oidc" ? "oauth_clients" : "saml_service_providers";
  const app = await env.DB.prepare(`SELECT id, name FROM ${table} WHERE id = ?`).bind(id).first<{ id: number; name: string }>();
  return app ? { type, id: app.id, name: app.name } : null;
}

/** The Provisioning card on an app's edit page: the SCIM targets linked to it, and the link to add one. */
async function appProvisioningCard(env: Env, appType: "oidc" | "saml", appId: number): Promise<string> {
  const targets = await listScimTargetsForApp(env, appType, appId);
  return cardSection(`
    <h2>Provisioning</h2>
    <p class="muted">SCIM targets that push users and groups to this app's own provisioning endpoint. Standalone targets are managed under Integrations &rarr; SCIM provisioning.</p>
    ${
      targets.length === 0
        ? '<p class="muted">No provisioning is linked to this app yet.</p>'
        : `<table>
            <thead><tr><th>Name</th><th>Endpoint</th><th>Status</th></tr></thead>
            <tbody>
              ${targets
                .map(
                  (t) =>
                    `<tr><td><a href="/admin/integrations/scim/${t.id}">${escapeHtml(t.name)}</a></td><td><code>${escapeHtml(scimHost(t.endpoint) || "—")}</code></td><td><span class="badge ${t.enabled ? "badge-active" : "badge-disabled"}">${t.enabled ? "Enabled" : "Disabled"}</span></td></tr>`
                )
                .join("")}
            </tbody>
          </table>`
    }
    <div style="margin-top:12px;"><a href="/admin/integrations/scim/new?${new URLSearchParams({ app_type: appType, app_id: String(appId) }).toString()}"><button class="secondary" type="button">Set up provisioning</button></a></div>
  `);
}

admin.post("/admin/scim/targets", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const app = await linkedApp(c.env, body.app_type, body.app_id);
  const linkage = body.app_type || body.app_id ? `&app_type=${encodeURIComponent(String(body.app_type ?? ""))}&app_id=${encodeURIComponent(String(body.app_id ?? ""))}` : "";
  if ((body.app_type || body.app_id) && !app) return c.redirect(`/admin/integrations/scim/new?error=${encodeURIComponent("The app this target would be linked to does not exist.")}`, 302);
  try {
    const t = await createScimTarget(c.env, {
      name: String(body.name ?? ""),
      endpoint: String(body.endpoint ?? ""),
      secret: String(body.secret ?? ""),
      scope: scimScopeFrom(body),
      paceMs: 200,
      membersPerRequest: 50,
      syncBatchSize: 50,
      enabled: body.enabled === "1",
      ...(app ? { appType: app.type, appId: app.id } : {}),
    });
    await logAudit(c.env, c.get("user"), "settings.scim_target_created", t.name, app ? { app: `${app.type}:${app.id}` } : undefined, c.req.raw);
    return c.redirect(scimTargetUrl(t.id, "?saved=1"), 302);
  } catch (e) {
    return c.redirect(`/admin/integrations/scim/new?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}${linkage}`, 302);
  }
});

admin.post("/admin/scim/targets/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const target = await getScimTarget(c.env, id);
  if (!target) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  // One form: connection, scope and tuning (older clients may post only the connection).
  const body = await c.req.parseBody({ all: true });
  const one = (v: unknown) => String((Array.isArray(v) ? v[0] : v) ?? "");
  const endpoint = one(body.endpoint).trim();
  // The field renders write-only: blank keeps the stored secret, and clearing
  // the endpoint removes the credential with it.
  const secret = endpoint === "" ? "" : one(body.secret).trim();
  const hasTuning = body.pace_ms !== undefined;
  const int = (v: unknown) => {
    const n = Number(one(v));
    return Number.isInteger(n) ? n : NaN;
  };
  const tuning = { paceMs: int(body.pace_ms), membersPerRequest: int(body.members_per_request), syncBatchSize: int(body.sync_batch) };
  if (hasTuning && (!(tuning.paceMs >= 0 && tuning.paceMs <= 10_000) || !(tuning.membersPerRequest >= 1 && tuning.membersPerRequest <= 500) || !(tuning.syncBatchSize >= 10 && tuning.syncBatchSize <= 500))) {
    return c.redirect(`${scimTargetUrl(id)}?error=${encodeURIComponent("Tuning values out of range.")}`, 302);
  }
  try {
    await updateScimTarget(c.env, id, { name: one(body.name), endpoint, secret, enabled: one(body.enabled) === "1", ...(hasTuning ? tuning : {}) });
  } catch (e) {
    return c.redirect(`${scimTargetUrl(id)}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  await logAudit(c.env, c.get("user"), "settings.scim_target_changed", target.name, hasTuning ? { ...tuning } : undefined, c.req.raw);
  if (body.mode !== undefined) {
    const scope = scimScopeFrom(body);
    const same = scope.mode === target.scope.mode && JSON.stringify([...scope.groupIds].sort()) === JSON.stringify([...target.scope.groupIds].sort());
    // Re-evaluating everything already pushed is costly: only when the scope really changed (services/scim-sync.ts).
    if (!same) await applyScimScope(consoleCtx(c), id, scope, (p) => c.executionCtx.waitUntil(p));
  }
  return c.redirect(scimTargetUrl(id, "?saved=1"), 302);
});

admin.post("/admin/scim/targets/:id/scope", async (c) => {
  const id = Number(c.req.param("id"));
  if (!(await getScimTarget(c.env, id))) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody({ all: true });
  // Re-evaluates everything already pushed to this target against the new scope (services/scim-sync.ts).
  await applyScimScope(consoleCtx(c), id, scimScopeFrom(body), (p) => c.executionCtx.waitUntil(p));
  return c.redirect(scimTargetUrl(id, "?saved=1"), 302);
});

admin.post("/admin/scim/targets/:id/tuning", async (c) => {
  const id = Number(c.req.param("id"));
  if (!(await getScimTarget(c.env, id))) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody();
  const int = (v: unknown) => {
    const n = Number(v);
    return Number.isInteger(n) ? n : NaN;
  };
  const paceMs = int(body.pace_ms);
  const membersPerRequest = int(body.members_per_request);
  const syncBatchSize = int(body.sync_batch);
  if (!(paceMs >= 0 && paceMs <= 10_000) || !(membersPerRequest >= 1 && membersPerRequest <= 500) || !(syncBatchSize >= 10 && syncBatchSize <= 500)) {
    return c.redirect(`${scimTargetUrl(id)}?error=${encodeURIComponent("Tuning values out of range.")}`, 302);
  }
  await updateScimTarget(c.env, id, { paceMs, membersPerRequest, syncBatchSize });
  await logAudit(c.env, c.get("user"), "settings.scim_tuning_changed", undefined, { paceMs, membersPerRequest, syncBatchSize, target: id }, c.req.raw);
  return c.redirect(scimTargetUrl(id, "?saved=1"), 302);
});

admin.post("/admin/scim/targets/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const target = await getScimTarget(c.env, id);
  if (!target) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  await deleteScimTarget(c.env, id);
  await logAudit(c.env, c.get("user"), "settings.scim_target_deleted", target.name, undefined, c.req.raw);
  return c.redirect("/admin/integrations/scim?saved=1", 302);
});

admin.post("/admin/scim/mappings", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const targets = list(body.map_target), exprs = list(body.map_expr), enabled = list(body.map_enabled);
  try {
    await replaceScimMappings(c.env, "user", targets.map((target, i) => ({ target, expression: exprs[i] ?? "", enabled: enabled[i] === "1" })));
  } catch (e) {
    return c.redirect(`/admin/integrations/scim?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  await logAudit(c.env, c.get("user"), "settings.scim_mappings_changed", undefined, { count: targets.length }, c.req.raw);
  return c.redirect("/admin/integrations/scim?saved=1", 302);
});

admin.post("/admin/scim/correlation", async (c) => {
  const body = await c.req.parseBody();
  const keys = String(body.correlation_keys ?? "").split(",");
  try {
    await setCorrelationKeys(c.env, keys);
  } catch (e) {
    return c.redirect(`/admin/integrations/scim?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  await logAudit(c.env, c.get("user"), "settings.scim_correlation_changed", undefined, { keys: keys.map((k) => k.trim()).filter(Boolean) }, c.req.raw);
  return c.redirect("/admin/integrations/scim?saved=1", 302);
});

admin.post("/admin/scim/mastering", async (c) => {
  const body = await c.req.parseBody();
  const fields = String(body.mastered_fields ?? "").split(",");
  try {
    await setMasteredFields(c.env, fields);
  } catch (e) {
    return c.redirect(`/admin/integrations/scim?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  await logAudit(c.env, c.get("user"), "settings.scim_mastering_changed", undefined, { fields: fields.map((f) => f.trim()).filter(Boolean) }, c.req.raw);
  return c.redirect("/admin/integrations/scim?saved=1", 302);
});

/** The target the Test / Sync buttons act on: ?target=N, else the first enabled one. */
function scimTargetParam(c: Context<{ Bindings: Env }>): number | undefined {
  const n = Number(c.req.query("target"));
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

admin.post("/admin/scim/test", async (c) => {
  const result = await testScimConnection(c.env, scimTargetParam(c));
  await logAudit(c.env, c.get("user"), "scim.connection_tested", undefined, { ok: result.ok, target: scimTargetParam(c) }, c.req.raw);

  return c.json({
    ok: result.ok,
    message: result.ok
      ? `Connection succeeded (HTTP ${result.status}).`
      : `Connection failed${result.status ? ` (HTTP ${result.status})` : ""}: ${result.error ?? "unknown error"}`,
  });
});

admin.post("/admin/scim/sync", async (c) => {
  // One batch per request; the page calls again until `complete` (see SCIM_SCRIPT).
  const summary = await syncAll(c.env, { restart: c.req.query("restart") === "1", targetId: scimTargetParam(c) });
  if (summary.complete || summary.userErrors || summary.groupErrors) {
    await logAudit(c.env, c.get("user"), summary.complete ? "scim.sync_all" : "scim.sync_batch_errors", undefined, { ...summary, target: scimTargetParam(c) }, c.req.raw);
  }
  return c.json({ ok: summary.userErrors === 0 && summary.groupErrors === 0, ...summary });
});

// ---------- Federation (upstream identity providers) ----------

function upstreamFormFields(
  idp: UpstreamIdpRow | null,
  protocol: "oidc" | "saml",
  groups: { id: number; name: string }[],
  roleGrants: Map<number, { roles: string[]; writable: boolean }>,
  error?: string,
  extraActions = ""
): string {
  const cfg = idp ? idpConfig(idp) : ({} as Record<string, string>);
  const v = (k: string) => escapeHtml((cfg as Record<string, string>)[k] ?? "");
  const oidc = protocol === "oidc";
  return `
    <form method="POST" action="${idp ? `/admin/federation/idps/${idp.id}` : "/admin/federation/idps"}">
      <input type="hidden" name="protocol" value="${protocol}" />
      <label for="name">Name</label>
      <input type="text" id="name" name="name" required value="${escapeHtml(idp?.name ?? "")}" placeholder="e.g. Entra ID, Okta" />
      ${
        oidc
          ? `<div class="field-row">
              <div>
                <label for="issuer">Issuer URL</label>
                <input type="text" id="issuer" name="issuer" required value="${v("issuer")}" placeholder="https://login.microsoftonline.com/&lt;tenant&gt;/v2.0" />
              </div>
              <div>
                <label for="scopes">Scopes <span class="muted">(optional)</span></label>
                <input type="text" id="scopes" name="scopes" value="${v("scopes")}" placeholder="openid profile email" />
              </div>
            </div>
            <div class="field-row">
              <div>
                <label for="client_id">Client ID</label>
                <input type="text" id="client_id" name="client_id" required value="${v("client_id")}" />
              </div>
              <div>
                <label for="client_secret">Client secret</label>
                <input type="password" id="client_secret" name="client_secret" autocomplete="new-password" placeholder="${idp ? "Saved - leave blank to keep it" : "From the provider's app registration"}" ${idp ? "" : "required"} />
                <p class="muted" style="margin-top:-6px;">Write-only: it is never shown again after saving.</p>
              </div>
            </div>`
          : `<div class="field-row">
              <div>
                <label for="idp_entity_id">IdP entity ID <span class="muted">(optional)</span></label>
                <input type="text" id="idp_entity_id" name="idp_entity_id" value="${v("idp_entity_id")}" placeholder="https://sts.windows.net/&lt;tenant&gt;/" />
              </div>
              <div>
                <label for="sso_url">SSO URL (HTTP-Redirect)</label>
                <input type="text" id="sso_url" name="sso_url" required value="${v("sso_url")}" placeholder="https://login.example.com/&lt;id&gt;/sso/saml" />
              </div>
            </div>
            <label for="certificate">Signing certificate (PEM or base64)</label>
            <textarea id="certificate" name="certificate" rows="5" ${idp ? "" : "required"} placeholder="-----BEGIN CERTIFICATE-----">${v("certificate")}</textarea>
            <label for="nameid_format">NameID format <span class="muted">(optional)</span></label>
            <input type="text" id="nameid_format" name="nameid_format" value="${v("nameid_format")}" placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />`
      }
      ${jitFields(idp, groups, roleGrants)}
      ${
        idp
          ? `<label style="font-weight:400;"><input type="checkbox" name="enabled" value="1" ${idp.enabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Enabled &mdash; offered on the sign-in page</label>`
          : ""
      }
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
      <div class="form-actions" style="margin-top:16px;">
        ${extraActions}
        <button class="primary" type="submit">${idp ? "Save" : "Create provider"}</button>
        ${cancelLink("/admin/integrations/federation", "Cancel")}
      </div>
    </form>`;
}

/** The provisioning block every upstream-provider form shares. */
function jitFields(idp: UpstreamIdpRow | null, groups: { id: number; name: string }[], roleGrants: Map<number, { roles: string[]; writable: boolean }>): string {
  return `
      <h3 style="margin-top:18px;">Accounts</h3>
      <label style="font-weight:400;"><input type="checkbox" name="jit" value="1" ${idp?.jit ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Just-in-time provisioning &mdash; create an account for an upstream identity nobody here has</label>
      <label style="font-weight:400;"><input type="checkbox" name="allow_linking" value="1" ${idp ? (idp.allow_linking ? "checked" : "") : "checked"} style="width:auto; display:inline; margin-right:6px;" /> Account linking &mdash; let this provider claim an existing account when its verified claims match a sign-in name or email. Off means it only ever mints new accounts.</label>
      <label for="jit_domain">JIT domain <span class="muted">(optional - else the claim's email domain when managed, or the default)</span></label>
      <input type="text" id="jit_domain" name="jit_domain" value="${escapeHtml(idp?.jit_domain ?? "")}" placeholder="example.com" />
      ${idp ? `<p class="muted" style="margin:0 0 8px 0;">Claim-to-field rules for this provider's sign-ins are on <a href="/admin/flows/edit?channel=jit&owner=${idp.id}">Flows &rarr; Federation sign-in</a>.</p>` : ""}
      <label>Groups JIT accounts join <span class="muted">(optional - applied when the account is created)</span></label>
      ${multiSelect(
        "jit_groups",
        groups.map((g) => {
          const grant = roleGrants.get(g.id);
          const note = grant ? ` — grants ${grant.roles.join(", ")}${grant.writable ? " (write role - cannot be used here)" : ""}` : "";
          return { id: g.id, label: `${g.name}${note}` };
        }),
        new Set(idp ? upstreamJitGroups(idp) : []),
        "Search groups..."
      )}
      <p class="muted">Every account this provider provisions is added to these groups at creation - including, deliberately, groups that grant a read-only admin role. A group whose role can <em>write</em> is refused on save; give it a read-only role (like Auditor) instead.</p>`;
}

/** Which groups the body chose for JIT provisioning. */
function jitGroupsFrom(body: Record<string, unknown>): number[] {
  return (Array.isArray(body.jit_groups) ? body.jit_groups : body.jit_groups === undefined ? [] : [body.jit_groups]).map(Number).filter((n) => Number.isInteger(n) && n > 0);
}

function upstreamInputFrom(body: Record<string, unknown>, idp: UpstreamIdpRow | null): UpstreamIdpInput & { enabled: boolean; keepSecret: boolean } {
  const protocol = String(body.protocol ?? "") === "saml" ? "saml" : "oidc";
  const jitGroups = jitGroupsFrom(body);
  return {
    name: String(body.name ?? ""),
    protocol,
    jit: String(body.jit ?? "") === "1",
    jitDomain: String(body.jit_domain ?? ""),
    jitGroups,
    allowLinking: String(body.allow_linking ?? "") === "1",
    enabled: String(body.enabled ?? "") === "1" || !idp,
    keepSecret: idp !== null && String(body.client_secret ?? "") === "",
    config: {
      issuer: String(body.issuer ?? ""),
      client_id: String(body.client_id ?? ""),
      client_secret: String(body.client_secret ?? ""),
      scopes: String(body.scopes ?? ""),
      idp_entity_id: String(body.idp_entity_id ?? ""),
      sso_url: String(body.sso_url ?? ""),
      certificate: String(body.certificate ?? ""),
      nameid_format: String(body.nameid_format ?? ""),
    },
  };
}

admin.get("/admin/integrations/federation", async (c) => {
  const allIdps = await listUpstreamIdps(c.env);
  const idps = allIdps.filter((u) => !(u.protocol === "oidc" && idpConfig<OidcIdpConfig>(u).social));
  const socialCount = allIdps.length - idps.length;
  const { results: linkCounts } = await c.env.DB.prepare("SELECT idp_id, COUNT(*) AS n FROM federated_identities GROUP BY idp_id").all<{ idp_id: number; n: number }>();
  const linkedBy = new Map(linkCounts.map((r) => [r.idp_id, r.n]));
  return c.html(
    layout(
      c,
      "Federation",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        ${integrationIntro(`Sign in <em>through</em> an upstream identity provider &mdash; FlareID as the relying party. Each provider gets a &quot;Continue with ...&quot; button on the sign-in page; the first sign-in links the upstream identity to an account here (by address match, or by JIT provisioning when switched on).${socialCount ? ` Consumer providers like Google or GitHub are managed under <a href="/admin/integrations/social">Social sign-in</a> (${socialCount} set up).` : ""}`, { href: "/admin/integrations/federation/new", label: "+ New provider" })}
        ${
          idps.length === 0
            ? '<p class="muted">No upstream providers yet &mdash; everyone signs in with a password or passkey.</p>'
            : `<table>
                <thead><tr><th>Name</th><th>Protocol</th><th>Linked accounts</th><th>Status</th></tr></thead>
                <tbody>
                  ${idps
                    .map(
                      (u) =>
                        `<tr${u.enabled ? "" : ' style="opacity:.55;"'}>
                          <td><a href="/admin/integrations/federation/${u.id}">${escapeHtml(u.name)}</a></td>
                          <td>${u.protocol === "oidc" ? "OIDC" : "SAML"}${u.jit ? ' <span class="muted">+ JIT</span>' : ""}</td>
                          <td class="muted">${linkedBy.get(u.id) ?? 0}</td>
                          <td><span class="badge ${u.enabled ? "badge-active" : "badge-disabled"}">${u.enabled ? "Enabled" : "Disabled"}</span></td>
                        </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "Federation" }]
    )
  );
});

admin.get("/admin/integrations/federation/new", async (c) => {
  const protocol = c.req.query("protocol") === "saml" ? "saml" : "oidc";
  const { results: groups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>();
  return c.html(
    layout(
      c,
      "New upstream provider",
      `
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <p class="sub">One upstream identity provider people can sign in through. For a consumer provider (Google, GitHub, Apple, ...) use <a href="/admin/integrations/social">Social sign-in</a> - its details are already filled in.</p>
        <p class="muted">Protocol:
          <a href="/admin/integrations/federation/new?protocol=oidc"${protocol === "oidc" ? ' style="font-weight:600;"' : ""}>OIDC</a> &middot;
          <a href="/admin/integrations/federation/new?protocol=saml"${protocol === "saml" ? ' style="font-weight:600;"' : ""}>SAML</a>
        </p>
        ${upstreamFormFields(null, protocol, groups, await groupRoleWriteMap(c.env))}
      `)}
      ${cardSection(`
        <h2>Registering with the provider</h2>
        <p class="muted">Create the provider first, then take the callback details from its page to the upstream side:</p>
        <ul class="muted">
          <li><strong>OIDC</strong>: register an app for the redirect URI <code>${escapeHtml(new URL(c.req.url).origin)}/federation/oidc/callback</code>.</li>
          <li><strong>SAML</strong>: register FlareID as a service provider &mdash; its entity ID and ACS URL appear on the saved provider's page.</li>
        </ul>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("federation"), { label: "New provider" }]
    )
  );
});

admin.get("/admin/integrations/federation/:id", async (c) => {
  const idp = await getUpstreamIdp(c.env, Number(c.req.param("id")));
  if (!idp) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const socialKey = idp.protocol === "oidc" ? idpConfig<OidcIdpConfig>(idp).social : undefined;
  if (socialKey && socialProvider(socialKey)) return c.redirect(`/admin/integrations/social/${socialKey}`, 302);
  const { n: linked } = (await c.env.DB.prepare("SELECT COUNT(*) AS n FROM federated_identities WHERE idp_id = ?").bind(idp.id).first<{ n: number }>()) ?? { n: 0 };
  const { results: links } = await c.env.DB.prepare(
    "SELECT f.subject, f.email, f.last_login_at, u.upn FROM federated_identities f JOIN users u ON u.id = f.user_id WHERE f.idp_id = ? ORDER BY f.last_login_at DESC LIMIT 50"
  ).bind(idp.id).all<{ subject: string; email: string | null; last_login_at: string | null; upn: string }>();
  const { results: groups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>();
  const origin = new URL(c.req.url).origin;
  const registration =
    idp.protocol === "oidc"
      ? `<dl class="attr-list">
          ${attrHtml("Redirect URI (to register)", `<code>${escapeHtml(oidcCallbackUrl(origin))}</code>`)}
          ${attrHtml("Issuer", `<code>${escapeHtml(idpConfig<OidcIdpConfig>(idp).issuer)}</code>`)}
        </dl>`
      : `<dl class="attr-list">
          ${attrHtml("SP entity ID", `<code>${escapeHtml(samlSpEntityId(c.env.ISSUER_URL, idp.id))}</code>`)}
          ${attrHtml("ACS URL", `<code>${escapeHtml(samlAcsUrl(origin, idp.id))}</code>`)}
        </dl>`;
  return c.html(
    layout(
      c,
      idp.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <div class="row between" style="margin:0 0 14px 0; align-items:flex-start;">
          <p class="muted" style="margin:0;">${linked} linked account${linked === 1 ? "" : "s"}.</p>
          <span class="badge ${idp.enabled ? "badge-active" : "badge-disabled"}">${idp.enabled ? "Enabled" : "Disabled"}</span>
        </div>
        <h3 style="margin-top:0;">Give the provider</h3>
        ${registration}
        ${upstreamFormFields(
          idp,
          idp.protocol,
          groups,
          await groupRoleWriteMap(c.env),
          undefined,
          formButton("Delete", `/admin/federation/idps/${idp.id}/delete`, {
            variant: "danger",
            confirm: confirmAttrs(`Deleting "${idp.name}" removes its sign-in button and forgets ${linked} linked ${linked === 1 ? "account" : "accounts"} - the accounts themselves are kept.`, { title: `Delete the provider "${idp.name}"?`, action: "Delete provider", danger: true }),
          })
        )}
      `)}
      ${cardSection(`
        <h2>Linked identities</h2>
        ${
          links.length === 0
            ? '<p class="muted">Nobody has signed in through this provider yet.</p>'
            : `<table>
                <thead><tr><th>Account</th><th>Subject</th><th>Last sign-in</th></tr></thead>
                <tbody>
                  ${links
                    .map(
                      (l) =>
                        `<tr><td>${escapeHtml(l.upn)}</td><td><code>${escapeHtml(l.subject)}</code></td><td class="muted">${l.last_login_at ? ts(l.last_login_at) : "—"}</td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("federation"), { label: idp.name }]
    )
  );
});

admin.post("/admin/federation/idps", async (c) => {
  const body = await c.req.parseBody({ all: true });
  try {
    const created = await createUpstreamIdp(c.env, upstreamInputFrom(body, null));
    await logAudit(c.env, c.get("user"), "federation.idp_created", created.name, { protocol: created.protocol }, c.req.raw);
    return c.redirect(`/admin/integrations/federation/${created.id}?saved=1`, 302);
  } catch (e) {
    return c.redirect(`/admin/integrations/federation/new?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post("/admin/federation/idps/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  try {
    const updated = await updateUpstreamIdp(c.env, id, upstreamInputFrom(body, await getUpstreamIdp(c.env, id)));
    await logAudit(c.env, c.get("user"), "federation.idp_updated", updated.name, { protocol: updated.protocol, enabled: updated.enabled }, c.req.raw);
    return c.redirect(`/admin/integrations/federation/${id}?saved=1`, 302);
  } catch (e) {
    return c.redirect(`/admin/integrations/federation/${id}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post("/admin/federation/idps/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const idp = await getUpstreamIdp(c.env, id);
  if (idp) {
    await deleteUpstreamIdp(c.env, id);
    await logAudit(c.env, c.get("user"), "federation.idp_deleted", idp.name, { protocol: idp.protocol }, c.req.raw);
  }
  return c.redirect("/admin/integrations/federation?saved=1", 302);
});


// ---------- Integrations: Social sign-in ----------
//
// A curated set of consumer identity providers (lib/social.ts). Each is an
// ordinary upstream_idps OIDC row marked config.social = <key>; the catalog
// supplies issuer/endpoints/scopes so the admin only brings client
// credentials and the JIT choices every provider shares.

/** The upstream row a social provider is configured as, if any. */
async function socialIdpFor(env: Env, key: string): Promise<UpstreamIdpRow | null> {
  return env.DB.prepare("SELECT * FROM upstream_idps WHERE protocol = 'oidc' AND json_extract(config, '$.social') = ?").bind(key).first<UpstreamIdpRow>();
}

admin.get("/admin/integrations/social", async (c) => {
  const { results } = await c.env.DB.prepare("SELECT id, name, enabled, jit, config FROM upstream_idps WHERE protocol = 'oidc' AND json_extract(config, '$.social') IS NOT NULL").all<Pick<UpstreamIdpRow, "id" | "name" | "enabled" | "jit"> & { config: string }>();
  const configured = new Map(results.map((u) => [(JSON.parse(u.config) as OidcIdpConfig).social, u] as const));
  return c.html(
    layout(
      c,
      "Social sign-in",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        ${integrationIntro(`Sign-in buttons for consumer identity providers &mdash; &quot;Continue with Google&quot;, &quot;Continue with GitHub&quot; and friends. Each is an ordinary upstream provider under the hood (the same JIT provisioning, claim mappings and linked-identity tracking as <a href="/admin/integrations/federation">Federation</a>); this page just fills in the protocol details for you. Any other OIDC or SAML provider can be added there.`)}
        <table>
          <thead><tr><th>Provider</th><th></th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${SOCIAL_PROVIDERS.map((p) => {
              const idp = configured.get(p.key);
              return `<tr${idp && !idp.enabled ? ' style="opacity:.55;"' : ""}>
                <td><strong>${escapeHtml(p.name)}</strong><br /><span class="muted">${escapeHtml(p.blurb)}</span></td>
                <td class="muted">${p.kind === "oauth2" ? "OAuth 2.0" : "OIDC"}</td>
                <td>${idp ? `<span class="badge ${idp.enabled ? "badge-active" : "badge-disabled"}">${idp.enabled ? "Enabled" : "Disabled"}</span>` : '<span class="muted">Not set up</span>'}</td>
                <td style="text-align:right;"><a href="/admin/integrations/social/${p.key}">${idp ? "Manage" : "Set up"}</a></td>
              </tr>`;
            }).join("")}
          </tbody>
        </table>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("social")]
    )
  );
});

/** The credential fields a provider's form shows: client id plus a secret, or Apple's key material. */
function socialCredentialFields(p: SocialProvider, idp: UpstreamIdpRow | null): string {
  const cfg = idp ? idpConfig<OidcIdpConfig>(idp) : ({} as OidcIdpConfig);
  const cid = `<div>
      <label for="client_id">${p.kind === "apple" ? "Services ID (client ID)" : "Client ID"}</label>
      <input type="text" id="client_id" name="client_id" required value="${escapeHtml(cfg.client_id ?? "")}" />
    </div>`;
  if (p.kind === "apple") {
    return `<div class="field-row">
        <div>
          <label for="apple_team_id">Team ID</label>
          <input type="text" id="apple_team_id" name="apple_team_id" required value="${escapeHtml(cfg.apple?.team_id ?? "")}" placeholder="10 characters, from the Apple Developer membership page" />
        </div>
        <div>
          <label for="apple_key_id">Key ID</label>
          <input type="text" id="apple_key_id" name="apple_key_id" required value="${escapeHtml(cfg.apple?.key_id ?? "")}" placeholder="The Sign in with Apple key's id" />
        </div>
      </div>
      ${cid}
      <label for="apple_private_key">Private key (.p8)</label>
      <textarea id="apple_private_key" name="apple_private_key" rows="6" ${idp ? "" : "required"} placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
      <p class="muted" style="margin-top:-6px;">${idp ? "Saved - leave blank to keep it." : "Write-only: never shown again after saving."} FlareID signs the client secret JWT with it for each sign-in.</p>`;
  }
  return `<div class="field-row">
      ${cid}
      <div>
        <label for="client_secret">Client secret</label>
        <input type="password" id="client_secret" name="client_secret" autocomplete="new-password" placeholder="${idp ? "Saved - leave blank to keep it" : "From the provider's app registration"}" ${idp ? "" : "required"} />
        <p class="muted" style="margin-top:-6px;">Write-only: it is never shown again after saving.</p>
      </div>
    </div>`;
}

admin.get("/admin/integrations/social/:key", async (c) => {
  const p = socialProvider(c.req.param("key"));
  if (!p) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const idp = await socialIdpFor(c.env, p.key);
  const cfg = idp ? idpConfig<OidcIdpConfig>(idp) : null;
  const { results: groups } = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>();
  const origin = new URL(c.req.url).origin;
  // Microsoft's tenant survives in the stored issuer; pull it back out.
  const tenant = p.tenant && cfg ? /login\.microsoftonline\.com\/([^/]+)\/v2\.0/.exec(cfg.issuer)?.[1] ?? "" : "";
  const { n: linked } = idp ? ((await c.env.DB.prepare("SELECT COUNT(*) AS n FROM federated_identities WHERE idp_id = ?").bind(idp.id).first<{ n: number }>()) ?? { n: 0 }) : { n: 0 };
  const endpoints = p.kind === "oauth2" ? socialMeta(p) : null;
  return c.html(
    layout(
      c,
      p.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <h2 style="margin-top:0;">Register with ${escapeHtml(p.name)}</h2>
        <p class="muted">${escapeHtml(p.registerHint)} <a href="${escapeHtml(p.docsUrl)}" target="_blank" rel="noopener">${escapeHtml(p.docsUrl)}</a></p>
        <dl class="attr-list">
          ${attrHtml("Redirect URI (to register)", `<code>${escapeHtml(oidcCallbackUrl(origin))}</code>`)}
          ${endpoints ? attrHtml("Authorize URL", `<code>${escapeHtml(endpoints.authorization_endpoint)}</code>`) : attrHtml("Issuer", `<code>${escapeHtml(p.tenant ? socialIssuer(p, tenant) : p.issuer)}</code>`)}
        </dl>
        <form method="POST" action="/admin/social/${p.key}">
          <label for="name">Name <span class="muted">(the "Continue with" button's wording)</span></label>
          <input type="text" id="name" name="name" required value="${escapeHtml(idp?.name ?? p.name)}" />
          ${p.tenant ? `<label for="tenant">${escapeHtml(p.tenant.label)}</label><input type="text" id="tenant" name="tenant" value="${escapeHtml(tenant)}" placeholder="${escapeHtml(p.tenant.placeholder)}" /><p class="muted" style="margin-top:-6px;">${escapeHtml(p.tenant.help)}</p>` : ""}
          ${socialCredentialFields(p, idp)}
          <p class="muted">Scopes requested: <code>${escapeHtml(p.scopes)}</code>${p.key === "x" ? " - X returns no email address, so new accounts are named from the handle." : ""}</p>
          ${jitFields(idp, groups, await groupRoleWriteMap(c.env))}
          ${
            idp
              ? `<label style="font-weight:400;"><input type="checkbox" name="enabled" value="1" ${idp.enabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Enabled &mdash; offered on the sign-in page</label>`
              : ""
          }
          <div class="form-actions" style="margin-top:16px;">
            ${
              idp
                ? formButton("Delete", `/admin/social/${p.key}/delete`, {
                    variant: "danger",
                    confirm: confirmAttrs(`Removing ${p.name} deletes its sign-in button and forgets ${linked} linked ${linked === 1 ? "account" : "accounts"} - the accounts themselves are kept.`, { title: `Remove ${p.name}?`, action: "Remove provider", danger: true }),
                  })
                : ""
            }
            <button class="primary" type="submit">${idp ? "Save" : "Set up " + escapeHtml(p.name)}</button>
            ${cancelLink("/admin/integrations/social", "Cancel")}
          </div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("social"), { label: p.name }]
    )
  );
});

admin.post("/admin/social/:key", async (c) => {
  const p = socialProvider(c.req.param("key"));
  if (!p) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const body = await c.req.parseBody({ all: true });
  const existing = await socialIdpFor(c.env, p.key);
  try {
    if (p.kind === "apple" && !existing && !String(body.apple_private_key ?? "").trim()) {
      throw new FederationError("Apple needs the Sign in with Apple private key (.p8).");
    }
    const input = {
      name: String(body.name ?? "").trim() || p.name,
      protocol: "oidc" as const,
      jit: String(body.jit ?? "") === "1",
      jitDomain: String(body.jit_domain ?? ""),
      jitGroups: jitGroupsFrom(body),
      enabled: !existing || String(body.enabled ?? "") === "1",
      keepSecret: existing !== null && !String(body.client_secret ?? "").trim() && !String(body.apple_private_key ?? "").trim(),
      config: {
        social: p.key,
        issuer: socialIssuer(p, String(body.tenant ?? "")),
        client_id: String(body.client_id ?? ""),
        client_secret: String(body.client_secret ?? ""),
        scopes: p.scopes,
        ...(p.kind === "apple"
          ? {
              apple: {
                team_id: String(body.apple_team_id ?? ""),
                key_id: String(body.apple_key_id ?? ""),
                private_key: String(body.apple_private_key ?? ""),
              },
            }
          : {}),
      },
    };
    const saved = existing ? await updateUpstreamIdp(c.env, existing.id, input) : await createUpstreamIdp(c.env, input);
    await logAudit(c.env, c.get("user"), existing ? "federation.idp_updated" : "federation.idp_created", saved.name, { protocol: "oidc", social: p.key, enabled: saved.enabled }, c.req.raw);
    return c.redirect(`/admin/integrations/social/${p.key}?saved=1`, 302);
  } catch (e) {
    return c.redirect(`/admin/integrations/social/${p.key}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

admin.post("/admin/social/:key/delete", async (c) => {
  const p = socialProvider(c.req.param("key"));
  if (!p) return consoleError(c, "That item doesn't exist any more - it may have been deleted.", 404);
  const existing = await socialIdpFor(c.env, p.key);
  if (existing) {
    await deleteUpstreamIdp(c.env, existing.id);
    await logAudit(c.env, c.get("user"), "federation.idp_deleted", existing.name, { protocol: "oidc", social: p.key }, c.req.raw);
  }
  return c.redirect("/admin/integrations/social?saved=1", 302);
});

// ---------- Audit log ----------

// The page is called "Log" in the UI. Both paths serve it: /admin/audit is
// what older links and bookmarks use, /admin/log is what the name implies.
admin.get("/admin/log", (c) => c.redirect(`/admin/audit${new URL(c.req.url).search}`, 302));

// LOG_ACTORS and LOG_CATEGORIES live in services/monitoring.ts, shared with GET /api/v1/audit.

function logSelect(name: string, current: string, allLabel: string, options: Record<string, { label: string }>): string {
  return `<select name="${name}" data-autosubmit style="margin-bottom:0; width:auto;">
    <option value="">${escapeHtml(allLabel)}</option>
    ${Object.entries(options)
      .map(([value, o]) => `<option value="${value}" ${current === value ? "selected" : ""}>${escapeHtml(o.label)}</option>`)
      .join("")}
  </select>`;
}

admin.get("/admin/audit", async (c) => {
  const filters = logFilters({ search: c.req.query("search"), actor: c.req.query("actor"), category: c.req.query("category"), from: c.req.query("from"), to: c.req.query("to") });
  const { search, actor, category, from, to } = filters;
  const pageSize = [20, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 20;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const filtered = Boolean(search || actor || category || from || to);
  const { total, entries } = await queryAuditLog(c.env, filters, pageSize, (page - 1) * pageSize);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const filterParams = Object.fromEntries(Object.entries({ search, actor, category, from, to }).filter(([, v]) => v !== ""));
  const exportUrl = `/admin/audit/export${Object.keys(filterParams).length ? `?${new URLSearchParams(filterParams)}` : ""}`;
  const verifyParam = c.req.query("verify");
  let verifyBanner = "";
  if (verifyParam) {
    const result = await verifyAuditChain(c.env);
    verifyBanner =
      result.status === "ok" || result.status === "empty"
        ? successBanner(
            result.status === "empty"
              ? "Nothing to verify - the log is empty."
              : `Integrity verified: ${result.checked} entries chained end-to-end${result.unchained ? ` (${result.unchained} older entries predate chaining)` : ""}.`
          )
        : `<p class="error">Integrity check ${result.status === "fork" ? "found a fork" : "failed"} at entry ${result.at_id}: ${escapeHtml(result.message ?? "")}</p>`;
  }

  return c.html(
    layout(
      c,
      "Log",
      `
      ${verifyBanner}
            ${cardSection(`
        <form method="GET" class="log-filters">
          <input type="text" name="search" placeholder="Search actor, action, target, IP" value="${escapeHtml(search)}" style="margin-bottom:0;" />
          ${logSelect("actor", actor, "Anyone", LOG_ACTORS)}
          ${logSelect("category", category, "All actions", LOG_CATEGORIES)}
          <label class="log-date">From <input type="date" name="from" value="${from}" data-autosubmit style="margin-bottom:0;" /></label>
          <label class="log-date">To <input type="date" name="to" value="${to}" data-autosubmit style="margin-bottom:0;" /></label>
          <input type="hidden" name="page" value="1" />
          ${pageSizeSelect(pageSize)}
          <button class="secondary" type="submit">Filter</button>
          ${filtered ? '<a href="/admin/audit" class="muted">Clear</a>' : ""}
          <a href="${exportUrl}" class="muted" style="margin-left:auto;">Export</a>
          <a href="/admin/audit?verify=1" class="muted">Verify integrity</a>
        </form>
      `)}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">${total} ${total === 1 ? "entry" : "entries"}${filtered ? " match" : ""}. Click a row to see its IP and details. Dates are UTC.</p>
        <table>
          <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead>
          <tbody>
            ${entries
              .map((e) => {
                let parsedDetails = null;
                if (e.details) {
                  try {
                    parsedDetails = JSON.parse(e.details);
                  } catch {
                    parsedDetails = e.details;
                  }
                }
                const fullEntryJson = JSON.stringify(
                  {
                    time: e.at,
                    actor: e.actor_upn ?? "system",
                    action: e.action,
                    target: e.target ?? null,
                    ip: e.ip ?? null,
                    user_agent: e.user_agent ?? null,
                    details: parsedDetails,
                  },
                  null,
                  2
                );

                return `<tr class="audit-row" data-toggle-next="open">
                  <td class="muted">${ts(e.at)}</td>
                  <td>${escapeHtml(e.actor_upn ?? "system")}</td>
                  <td><code>${escapeHtml(e.action)}</code></td>
                  <td>${escapeHtml(e.target ?? "")}</td>
                </tr>
                <tr class="audit-detail">
                  <td colspan="4">
                    <div class="audit-detail-content">
                      <div class="row between" style="margin:0;">
                        <div><span class="muted">IP:</span> ${escapeHtml(e.ip ?? "unknown")}</div>
                        ${copyButton(fullEntryJson, "Copy JSON")}
                      </div>
                      <div><span class="muted">User-Agent:</span> ${escapeHtml(e.user_agent ?? "unknown")}</div>
                      ${e.details ? `<div><span class="muted">Details:</span> <code>${escapeHtml(e.details)}</code></div>` : ""}
                    </div>
                  </td>
                </tr>`;
              })
              .join("")}
          </tbody>
        </table>
        ${paginationControls("/admin/audit", page, totalPages, Object.fromEntries(Object.entries({ search, actor, category, from, to, pageSize }).filter(([, v]) => v !== "")))}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Log" }]
    )
  );
});

// The filter-bar Export link: the same view as an NDJSON download (the API
// answers CSV too, at GET /api/v1/audit/export?format=csv).
admin.get("/admin/audit/export", async (c) => {
  const filters = logFilters({ search: c.req.query("search"), actor: c.req.query("actor"), category: c.req.query("category"), from: c.req.query("from"), to: c.req.query("to") });
  const { entries } = await queryAuditLog(c.env, filters, 100_000, 0);
  const day = new Date().toISOString().slice(0, 10);
  const ndjson = entries.map(({ actor_user_id: _id, ...e }) => JSON.stringify(e)).join("\n");
  await audit(consoleCtx(c), "audit.exported", undefined, { entries: entries.length });
  return new Response(ndjson, {
    headers: { "content-type": "application/x-ndjson; charset=utf-8", "content-disposition": `attachment; filename="flareid-audit-${day}.ndjson"` },
  });
});

// ---------- LDAP ----------

/** Groups for the app's two pickers: user groups (who may bind) and exposed groups (which group entries exist). */
async function ldapGroupOptions(env: Env): Promise<{ id: number; label: string }[]> {
  const { results } = await env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>();
  return results.map((g) => ({ id: g.id, label: g.name }));
}

const MFA_MODES: [string, string][] = [
  ["password", "Password only"],
  ["otp_if_enrolled", "Password + OTP when the user has one (recommended)"],
  ["otp_required", "Always password + OTP"],
];

/** The once-only connection details shown after create or rotate (LDAP.md section 14). */
function ldapSecretPage(c: Context<{ Bindings: Env }>, app: LdapAppRow, secret: string, settings: Awaited<ReturnType<typeof getLdapSettings>>, verb: "created" | "rotated" | "revealed") {
  const base = settings.baseDn;
  const host = settings.hostname || "ldap." + settings.base.map((r) => r.value).join(".");
  const slug = app.slug;
  const bindDn = `cn=${slug},ou=services,${base}`;
  const appBase = `ou=${slug},${base}`;
  const userBase = `ou=people,${appBase}`;
  const groupBase = `ou=groups,${appBase}`;
  const userFilter = "(&(objectClass=inetOrgPerson)(uid=%s))";
  const adFilter = "(&(objectCategory=person)(sAMAccountName=%s))";
  const kv = (k: string, v: string) => `<tr><td class="muted" style="width:180px;">${k}</td><td><code>${escapeHtml(v)}</code></td><td style="width:70px;">${copyButton(v)}</td></tr>`;
  const snippet = (title: string, body: string) => `<details style="margin:8px 0;"><summary><strong>${escapeHtml(title)}</strong></summary><div style="margin-top:8px;">${codeBlock(body, { className: "", style: "margin:0; white-space:pre-wrap;" })}</div></details>`;
  const otpNote =
    app.mfa_mode === "password"
      ? ""
      : `<p class="muted">This app's password field takes a second factor as <code>&lt;password&gt;,&lt;6-digit-code&gt;</code>${app.mfa_mode === "otp_if_enrolled" ? " for users who have one enrolled" : " for every user"}.</p>`;
  return c.html(
    layout(
      c,
      `LDAP app ${verb}`,
      `${cardSection(`
        <h2>${escapeHtml(app.name)} ${verb === "created" ? "created" : verb === "rotated" ? "secret rotated" : "secret revealed"}</h2>
        <p><strong>${verb === "revealed" ? "This is the app's current bind secret - keep it private." : "Copy the secret now - it is never shown again."}</strong> Everything else on this page is safe to keep.</p>
        <table><tbody>
          ${kv("Server", `ldaps://${host}:636`)}
          ${kv("Global Catalog", `ldaps://${host}:3269`)}
          ${kv("Bind DN", bindDn)}
          ${kv("Secret", secret)}
          ${kv("Base DN", appBase)}
          ${kv("User search base", userBase)}
          ${kv("Group search base", groupBase)}
          ${kv("User filter", userFilter)}
          ${kv("User filter (AD mode)", adFilter)}
        </tbody></table>
        ${otpNote}
      `)}
      ${cardSection(`
        <h2>Client configs</h2>
        ${snippet("ldapsearch", `ldapsearch -x -H ldaps://${host}:636 \\\n  -D "${bindDn}" -w "${secret}" \\\n  -b "${userBase}" "(uid=alice)" dn memberOf`)}
        ${snippet("Grafana (ldap.toml)", `[[servers]]\nhost = "${host}"\nport = 636\nuse_ssl = true\nstart_tls = false\nbind_dn = "${bindDn}"\nbind_password = "${secret}"\nsearch_base_dns = ["${userBase}"]\nsearch_filter = "(uid=%s)"\n\n[servers.attributes]\nname = "givenName"\nsurname = "sn"\nusername = "uid"\nmember_of = "memberOf"\nemail = "mail"`)}
        ${snippet("sssd.conf", `[domain/flareid]\nid_provider = ldap\nldap_uri = ldaps://${host}:636\nldap_search_base = ${appBase}\nldap_user_search_base = ${userBase}\nldap_group_search_base = ${groupBase}\nldap_default_bind_dn = ${bindDn}\nldap_default_authtok = ${secret}\nldap_user_object_class = inetOrgPerson\nldap_user_name = uid`)}
        ${snippet("GitLab (gitlab.rb)", `gitlab_rails['ldap_enabled'] = true\ngitlab_rails['ldap_servers'] = {\n  'main' => {\n    'label' => 'FlareID',\n    'host' => '${host}',\n    'port' => 636,\n    'encryption' => 'simple_tls',\n    'uid' => 'uid',\n    'bind_dn' => '${bindDn}',\n    'password' => '${secret}',\n    'base' => '${userBase}',\n    'verify_certificates' => true\n  }\n}`)}
        ${snippet("Jenkins (LDAP plugin)", `Server: ldaps://${host}:636\nroot DN: ${appBase}\nUser search base: ${userBase}\nUser search filter: uid={0}\nGroup search base: ${groupBase}\nManager DN: ${bindDn}\nManager Password: ${secret}`)}
      `)}`,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("ldap"), { label: app.name }]
    )
  );
}

admin.get("/admin/integrations/ldap", async (c) => {
  const [settings, apps, domains, storedBaseDnRaw] = await Promise.all([getLdapSettings(c.env), listLdapApps(c.env), listDomains(c.env), getSetting(c.env, "ldap_base_dn")]);
  const storedBaseDn = storedBaseDnRaw ?? "";
  const groups = await ldapGroupOptions(c.env);
  const domainDns = domains.map((d) => ({ dn: domainToBaseDn(d.domain), domain: d.domain, isDefault: Boolean(d.is_default) }));
  const defaultDn = domainDns.find((d) => d.isDefault)?.dn ?? "";
  const baseDnIsCustom = storedBaseDn !== "" && !domainDns.some((d) => d.dn === storedBaseDn);
  const appRows = apps.map((a) => {
    const { userGroups, exposedGroups } = appGroupIds(a);
    const scope = userGroups === null ? "All users" : `${userGroups.length} group${userGroups.length === 1 ? "" : "s"}`;
    return `<tr>
      <td><a href="/admin/ldap/${escapeHtml(a.slug)}">${escapeHtml(a.name)}</a></td>
      <td><code>${escapeHtml(a.slug)}</code></td>
      <td>${escapeHtml(scope)}</td>
      <td>${a.last_used_at ? ts(a.last_used_at) : '<span class="muted">never</span>'}</td>
      <td>${a.revoked_at ? '<span class="badge badge-disabled">Revoked</span>' : '<span class="badge badge-active">Active</span>'}</td>
    </tr>`;
  });
  const appOptions = apps.filter((a) => !a.revoked_at).map((a) => `<option value="${escapeHtml(a.slug)}" ${settings.unscopedBindApp === a.slug ? "selected" : ""}>${escapeHtml(a.name)} (${escapeHtml(a.slug)})</option>`).join("");
  return c.html(
    layout(
      c,
      "LDAP",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<div class="error-banner">${escapeHtml(c.req.query("error")!)}</div>` : ""}
      ${cardSection(`
        <h2>LDAP interface</h2>
        <p class="muted">A read-only, LDAPS-only view of this directory over TCP 636 (and the Global Catalog on 3269), for apps that only speak LDAP - Grafana, GitLab, sssd, network devices. Each app gets its own branch of the tree and its own policy.</p>
        <form method="POST" action="/admin/integrations/ldap/settings">
          <label style="font-weight:400;"><input type="checkbox" name="enabled" value="1" ${settings.enabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> <strong>Enable LDAP</strong></label>
          <label for="ldap_hostname" style="margin-top:12px;">Hostname</label>
          <input type="text" id="ldap_hostname" name="hostname" value="${escapeHtml(settings.hostname)}" placeholder="ldap.${escapeHtml(settings.base.map((r) => r.value).join("."))}" />
          <p class="muted" style="margin:-8px 0 14px;">The DNS name the Spectrum apps listen on - shown in snippets and the root DSE.</p>
          <label for="ldap_base_dn">Base DN</label>
          <select id="ldap_base_dn" name="base_dn">
            <option value="" ${storedBaseDn === "" ? "selected" : ""}>Derive from the default domain${defaultDn ? ` (${escapeHtml(defaultDn)})` : ""}</option>
            ${domainDns.map((d) => `<option value="${escapeHtml(d.dn)}" ${storedBaseDn === d.dn ? "selected" : ""}>${escapeHtml(d.dn)}${d.isDefault ? " (default domain)" : ""}</option>`).join("")}
            ${baseDnIsCustom ? `<option value="${escapeHtml(storedBaseDn)}" selected>${escapeHtml(storedBaseDn)} (custom)</option>` : ""}
          </select>
          <p class="muted" style="margin:-8px 0 14px;">The naming context every branch hangs under. Changing it moves every existing bind DN - reconfigure clients when you change it.</p>
          <label for="ldap_netbios">NetBIOS name</label>
          <input type="text" id="ldap_netbios" name="netbios_name" value="${escapeHtml(settings.netbios)}" maxlength="15" />
          <label for="ldap_unscoped">Unattributed user binds land on</label>
          <select id="ldap_unscoped" name="unscoped_bind_app">
            <option value="">(deny - binds must name an app in the DN)</option>
            ${appOptions}
          </select>
          <p class="muted" style="margin:-8px 0 14px;">Bind names like <code>alice@example.com</code> carry no app; choose which app's policy they fall under, or deny them.</p>
          <h3 style="margin-top:18px;">POSIX and sessions</h3>
          <div class="two-col">
            <div><label for="uid_base">uidNumber base</label><input type="number" id="uid_base" name="posix_uid_base" value="${settings.posixUidBase}" min="0" /></div>
            <div><label for="gid_base">gidNumber base</label><input type="number" id="gid_base" name="posix_gid_base" value="${settings.posixGidBase}" min="0" /></div>
            <div><label for="def_gid">Default gidNumber</label><input type="number" id="def_gid" name="posix_default_gid" value="${settings.posixDefaultGid}" min="0" /></div>
            <div><label for="posix_shell">loginShell</label><input type="text" id="posix_shell" name="posix_shell" value="${escapeHtml(settings.posixShell)}" /></div>
            <div><label for="posix_home">homeDirectory template</label><input type="text" id="posix_home" name="posix_home" value="${escapeHtml(settings.posixHome)}" /></div>
            <div><label for="idle_to">Idle timeout (minutes)</label><input type="number" id="idle_to" name="idle_timeout_minutes" value="${settings.idleTimeoutMinutes}" min="1" max="1440" /></div>
            <div><label for="otp_rebind">OTP re-bind window (seconds)</label><input type="number" id="otp_rebind" name="otp_rebind_seconds" value="${settings.otpRebindSeconds}" min="0" max="3600" /></div>
          </div>
          <div class="form-actions end"><button class="primary" type="submit">Save settings</button></div>
        </form>
      `)}
      ${cardSection(`
        ${integrationIntro("LDAP apps. A service account per app: its bind DN names the app, which is how per-app policy applies even when apps rebind on fresh connections.", { href: "/admin/ldap/new", label: "+ New LDAP app" })}
        ${apps.length === 0 ? '<p class="muted">No LDAP apps registered yet.</p>' : `<table>
          <thead><tr><th>Name</th><th>Slug</th><th>Bindable users</th><th>Last used</th><th>Status</th></tr></thead>
          <tbody>${appRows.join("")}</tbody>
        </table>`}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "LDAP" }]
    )
  );
});

admin.post("/admin/integrations/ldap/settings", async (c) => {
  const body = await c.req.parseBody();
  const enabled = String(body.enabled ?? "") === "1";
  if (enabled) await enableLdap(c.env);
  else await disableLdap(c.env);
  const put = async (key: string, value: string) => setSetting(c.env, key, value);
  await put("ldap_hostname", String(body.hostname ?? "").trim());
  await put("ldap_base_dn", String(body.base_dn ?? "").trim());
  await put("ldap_netbios_name", String(body.netbios_name ?? "").trim());
  const unscoped = String(body.unscoped_bind_app ?? "").trim().toLowerCase();
  if (unscoped && !(await getLdapAppBySlug(c.env, unscoped))) return c.redirect(`/admin/integrations/ldap?error=${encodeURIComponent(`No LDAP app named '${unscoped}'.`)}`, 302);
  await put("ldap_unscoped_bind_app", unscoped);
  const num = (v: unknown, dflt: number, min = 0, max = 1_000_000) => Math.min(max, Math.max(min, Number(v) || dflt));
  await put("ldap_posix_uid_base", String(num(body.posix_uid_base, 10000)));
  await put("ldap_posix_gid_base", String(num(body.posix_gid_base, 20000)));
  await put("ldap_posix_default_gid", String(num(body.posix_default_gid, 100)));
  await put("ldap_posix_shell", String(body.posix_shell ?? "/bin/bash").trim());
  await put("ldap_posix_home", String(body.posix_home ?? "/home/{username}").trim());
  await put("ldap_idle_timeout_minutes", String(num(body.idle_timeout_minutes, 15, 1, 1440)));
  await put("ldap_otp_rebind_seconds", String(num(body.otp_rebind_seconds, 120, 0, 3600)));
  await logAudit(c.env, c.get("user"), "ldap.settings.updated", "ldap", {}, c.req.raw);
  return c.redirect("/admin/integrations/ldap?saved=1", 302);
});

function ldapAppForm(v: { name?: string; slug?: string; userGroups?: Set<number>; exposedGroups?: Set<number>; mfaMode?: string; includeDisabled?: boolean }, groups: { id: number; label: string }[], action: string, submitLabel: string, edit = false): string {
  return `<form method="POST" action="${escapeHtml(action)}">
    ${
      edit
        ? `<label for="ldap_app_name">Name</label>
    <input type="text" id="ldap_app_name" name="name" value="${escapeHtml(v.name ?? "")}" placeholder="Grafana" required />`
        : `<div class="field-row">
      <div>
        <label for="ldap_app_name">Name</label>
        <input type="text" id="ldap_app_name" name="name" value="${escapeHtml(v.name ?? "")}" placeholder="Grafana" required />
      </div>
      <div>
        <label for="ldap_app_slug">Slug</label>
        <input type="text" id="ldap_app_slug" name="slug" value="${escapeHtml(v.slug ?? "")}" placeholder="grafana" pattern="[a-z0-9][a-z0-9-]{0,63}" required />
        <p class="muted" style="margin:-8px 0 14px;">Lowercase, digits and dashes. Becomes <code>ou=&lt;slug&gt;</code> in the tree and the service bind DN. Cannot be changed.</p>
      </div>
    </div>`
    }
    <label>Bindable users</label>
    ${multiSelect("user_group_ids", groups, v.userGroups ?? new Set(), "All users - pick groups to restrict")}
    <p class="muted" style="margin:-8px 0 14px;">Members of these groups may bind and are visible. Leave empty for everyone.</p>
    <label>Exposed groups</label>
    ${multiSelect("exposed_group_ids", groups, v.exposedGroups ?? new Set(), "All groups - pick groups to restrict")}
    <p class="muted" style="margin:-8px 0 14px;">Which groups exist under <code>ou=groups</code> for this app. Leave empty for all.</p>
    <label for="ldap_mfa_mode" style="margin-top:12px;">Second factor</label>
    <select id="ldap_mfa_mode" name="mfa_mode">
      ${MFA_MODES.map(([val, label]) => `<option value="${val}" ${(v.mfaMode ?? "otp_if_enrolled") === val ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
    </select>
    <p class="muted" style="margin:-8px 0 14px;">OTP goes in the password field as <code>&lt;password&gt;,&lt;code&gt;</code>.</p>
    <label style="font-weight:400;"><input type="checkbox" name="include_disabled" value="1" ${v.includeDisabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Show disabled users too</label>
    <p class="muted" style="margin:-8px 0 14px;">They appear with <code>userAccountControl=514</code> so a sync can deactivate them, but they still can't bind.</p>
    <div class="form-actions end">${cancelLink("/admin/integrations/ldap")}<button class="primary" type="submit">${escapeHtml(submitLabel)}</button></div>
  </form>`;
}

function ldapFormIds(body: Record<string, unknown>, key: string): number[] {
  const raw = body[key];
  const arr = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return arr.map(Number).filter((n) => Number.isInteger(n) && n > 0);
}

admin.get("/admin/ldap/new", async (c) => {
  const settings = await getLdapSettings(c.env);
  if (!settings.enabled) return consoleError(c, "Enable LDAP under Integrations → LDAP first.", 400);
  const groups = await ldapGroupOptions(c.env);
  return c.html(
    layout(
      c,
      "New LDAP app",
      cardSection(`<h2>New LDAP app</h2><p class="muted">Registration mints a service-account secret, shown once on the next page.</p>${ldapAppForm({}, groups, "/admin/ldap", "Create LDAP app")}`),
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("ldap"), { label: "New LDAP app" }]
    )
  );
});

admin.post("/admin/ldap", async (c) => {
  const body = await c.req.parseBody();
  const input: LdapAppInput = {
    slug: String(body.slug ?? "").toLowerCase(),
    name: String(body.name ?? "").trim(),
    user_group_ids: ldapFormIds(body, "user_group_ids"),
    exposed_group_ids: ldapFormIds(body, "exposed_group_ids"),
    mfa_mode: (["password", "otp_if_enrolled", "otp_required"] as const).find((m) => m === body.mfa_mode) ?? "otp_if_enrolled",
    include_disabled: String(body.include_disabled ?? "") === "1",
  };
  try {
    if (await getLdapAppBySlug(c.env, input.slug)) return consoleError(c, `An app named '${input.slug}' already exists.`, 400);
    const { app, secret } = await writeLdapApp(c.env, input);
    await logAudit(c.env, c.get("user"), "ldap.app.created", app.slug, {}, c.req.raw);
    return ldapSecretPage(c, app, secret!, await getLdapSettings(c.env), "created");
  } catch (e) {
    return consoleError(c, e instanceof Error ? e.message : String(e), 400);
  }
});

admin.get("/admin/ldap/:slug", async (c) => {
  const app = await getLdapAppBySlug(c.env, c.req.param("slug").toLowerCase());
  if (!app) return consoleError(c, "That LDAP app doesn't exist.", 404);
  const [settings, groups] = await Promise.all([getLdapSettings(c.env), ldapGroupOptions(c.env)]);
  const { userGroups, exposedGroups } = appGroupIds(app);
  const revoked = app.revoked_at !== null;
  return c.html(
    layout(
      c,
      app.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${revoked ? `<div class="error-banner">Revoked ${escapeHtml(app.revoked_at!)} - binds and searches fail until a new app is registered.</div>` : ""}
      ${cardSection(`
        <h2>${escapeHtml(app.name)} <code class="muted">${escapeHtml(app.slug)}</code></h2>
        <table><tbody>
          <tr><td class="muted" style="width:180px;">Bind DN</td><td><code>cn=${escapeHtml(app.slug)},ou=services,${escapeHtml(settings.baseDn)}</code></td></tr>
          <tr><td class="muted">Branch</td><td><code>ou=${escapeHtml(app.slug)},${escapeHtml(settings.baseDn)}</code></td></tr>
          <tr><td class="muted">Secret</td><td><code>${escapeHtml(app.secret_prefix)}…</code></td></tr>
          <tr><td class="muted">Last used</td><td>${app.last_used_at ? ts(app.last_used_at) : "never"}</td></tr>
          <tr><td class="muted">Audit</td><td><a href="/admin/log?search=${encodeURIComponent(app.slug)}&category=ldap">ldap.* events for this app</a></td></tr>
        </tbody></table>
        <div class="form-actions end">
          ${revoked ? "" : `<form method="POST" action="/admin/ldap/${escapeHtml(app.slug)}/revoke" ${confirmAttrs(`Binds and searches stop immediately. This cannot be undone.`, { title: `Revoke ${app.name}?`, action: "Revoke", danger: true })}><button class="danger" type="submit">Revoke</button></form>`}
          ${revoked ? "" : `<form method="POST" action="/admin/ldap/${escapeHtml(app.slug)}/rotate" ${confirmAttrs("The current secret stops working immediately.", { title: "Rotate the secret?", action: "Rotate" })}><button class="secondary" type="submit">Rotate secret</button></form>`}
          ${revoked || !app.secret_enc ? "" : `<form method="POST" action="/admin/ldap/${escapeHtml(app.slug)}/reveal"><button class="secondary" type="submit">Reveal secret</button></form>`}
        </div>
      `)}
      ${revoked ? "" : cardSection(`<h2>Policy</h2>${ldapAppForm({ name: app.name, userGroups: new Set(userGroups ?? []), exposedGroups: new Set(exposedGroups ?? []), mfaMode: app.mfa_mode, includeDisabled: Boolean(app.include_disabled) }, groups, `/admin/ldap/${app.slug}`, "Save policy", true)}`)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("ldap"), { label: app.name }]
    )
  );
});

admin.post("/admin/ldap/:slug", async (c) => {
  const app = await getLdapAppBySlug(c.env, c.req.param("slug").toLowerCase());
  if (!app) return consoleError(c, "That LDAP app doesn't exist.", 404);
  const body = await c.req.parseBody();
  try {
    await writeLdapApp(c.env, {
      slug: app.slug,
      name: String(body.name ?? "").trim(),
      user_group_ids: ldapFormIds(body, "user_group_ids"),
      exposed_group_ids: ldapFormIds(body, "exposed_group_ids"),
      mfa_mode: (["password", "otp_if_enrolled", "otp_required"] as const).find((m) => m === body.mfa_mode) ?? (app.mfa_mode as LdapAppInput["mfa_mode"]),
      include_disabled: String(body.include_disabled ?? "") === "1",
    });
    await logAudit(c.env, c.get("user"), "ldap.app.updated", app.slug, {}, c.req.raw);
    return c.redirect(`/admin/ldap/${app.slug}?saved=1`, 302);
  } catch (e) {
    return consoleError(c, e instanceof Error ? e.message : String(e), 400);
  }
});

admin.post("/admin/ldap/:slug/reveal", async (c) => {
  const app = await getLdapAppBySlug(c.env, c.req.param("slug").toLowerCase());
  if (!app) return consoleError(c, "That LDAP app doesn't exist.", 404);
  const secret = await revealLdapSecret(c.env, app);
  if (!secret) return consoleError(c, "This app's secret predates reveal - rotate it once to enable reveal.", 400);
  await logAudit(c.env, c.get("user"), "ldap.app.secret_revealed", app.slug, {}, c.req.raw);
  return ldapSecretPage(c, app, secret, await getLdapSettings(c.env), "revealed");
});

admin.post("/admin/ldap/:slug/rotate", async (c) => {
  const app = await getLdapAppBySlug(c.env, c.req.param("slug").toLowerCase());
  if (!app) return consoleError(c, "That LDAP app doesn't exist.", 404);
  const secret = await rotateLdapSecret(c.env, app);
  await logAudit(c.env, c.get("user"), "ldap.app.secret_rotated", app.slug, {}, c.req.raw);
  return ldapSecretPage(c, app, secret, await getLdapSettings(c.env), "rotated");
});

admin.post("/admin/ldap/:slug/revoke", async (c) => {
  const app = await getLdapAppBySlug(c.env, c.req.param("slug").toLowerCase());
  if (!app) return consoleError(c, "That LDAP app doesn't exist.", 404);
  await revokeLdapApp(c.env, app);
  await logAudit(c.env, c.get("user"), "ldap.app.revoked", app.slug, {}, c.req.raw);
  return c.redirect(`/admin/ldap/${app.slug}`, 302);
});

// ---------------------------------------------------------------------------
// Flows: the central area where attribute mappings are defined
// ---------------------------------------------------------------------------

interface FlowChannelMeta {
  direction: "in" | "out";
  label: string;
  /** The document expressions evaluate over, for the editor's intro line. */
  doc: string;
  targets: string[];
  validate: (target: string) => string | null;
}

const FLOW_CHANNELS: Record<MappingChannel, FlowChannelMeta> = {
  "scim-in": {
    direction: "in", label: "SCIM provisioning", doc: "the incoming SCIM user body",
    targets: [...USER_MAPPING_TARGETS],
    validate: (t) => (isValidMappingTarget("user", t) ? null : `"${t}" is not a field a user mapping can feed.`),
  },
  jit: {
    direction: "in", label: "Federation sign-in", doc: "the upstream IdP's claims",
    targets: [...JIT_MAPPING_TARGETS],
    validate: validateJitTarget,
  },
  "scim-out": {
    direction: "out", label: "SCIM push", doc: "the FlareID user",
    targets: [...SCIM_OUT_TARGETS],
    validate: validateScimOutTarget,
  },
  oidc: {
    direction: "out", label: "OIDC claims", doc: "the FlareID user",
    targets: [],
    validate: validateOidcClaimTarget,
  },
};

/** Display name for a mapping set's owner - the record the rows belong to. */
async function flowOwnerLabel(env: Env, channel: MappingChannel, owner: string): Promise<string> {
  if (!owner) return "Defaults (all flows)";
  if (channel === "jit") {
    const row = await env.DB.prepare("SELECT name FROM upstream_idps WHERE id = ?").bind(owner).first<{ name: string }>();
    return row?.name ?? `IdP ${owner}`;
  }
  if (channel === "scim-out") {
    const row = await env.DB.prepare("SELECT name FROM scim_targets WHERE id = ?").bind(owner).first<{ name: string }>();
    return row?.name ?? `Target ${owner}`;
  }
  if (channel === "oidc") {
    const row = await env.DB.prepare("SELECT name FROM oauth_clients WHERE client_id = ?").bind(owner).first<{ name: string }>();
    return row?.name ?? owner;
  }
  return owner;
}

function flowEditHref(channel: string, owner: string, seed = false): string {
  return `/admin/flows/edit?channel=${encodeURIComponent(channel)}&owner=${encodeURIComponent(owner)}${seed ? "&seed=1" : ""}`;
}

function flowRowHtml(m?: { target: string; expression: string; enabled: boolean }): string {
  return `<tr class="mapping-row">
    <td><input type="text" name="map_target" value="${escapeHtml(m?.target ?? "")}" placeholder="field" list="flow-map-targets" required style="margin:0;" /></td>
    <td><input type="text" name="map_expr" value="${escapeHtml(m?.expression ?? "")}" placeholder='given_name + " " + family_name' required style="margin:0; font-family:monospace;" /></td>
    <td style="text-align:center;"><input type="hidden" name="map_enabled" value="${m && !m.enabled ? 0 : 1}" /><input type="checkbox" ${m && !m.enabled ? "" : "checked"} data-mirror-prev style="width:auto; margin:0;" /></td>
    <td>${iconButton("trash", "Remove mapping", { danger: true, type: "button", attrs: 'data-remove-closest=".mapping-row"' })}</td>
  </tr>`;
}

admin.get("/admin/flows", async (c) => {
  const { results: counts } = await c.env.DB.prepare("SELECT channel, owner, COUNT(*) AS n, SUM(enabled) AS on_n FROM mappings GROUP BY channel, owner")
    .all<{ channel: string; owner: string; n: number; on_n: number }>();
  const countFor = (channel: string, owner: string) => counts.find((r) => r.channel === channel && r.owner === owner);
  const [idps, targets, clients, sps, policy] = await Promise.all([
    listUpstreamIdps(c.env),
    listScimTargets(c.env),
    c.env.DB.prepare("SELECT id, client_id, name FROM oauth_clients ORDER BY name").all<{ id: number; client_id: string; name: string }>().then((r) => r.results),
    c.env.DB.prepare("SELECT id, name FROM saml_service_providers ORDER BY name").all<{ id: number; name: string }>().then((r) => r.results),
    getCollisionPolicy(c.env),
  ]);

  const flowRow = (label: string, detail: string, channel: MappingChannel, owner: string, fallback: string, ownerHref?: string) => {
    const n = countFor(channel, owner);
    return `<tr>
      <td>${escapeHtml(label)}${ownerHref ? ` <span class="muted">&middot; <a href="${ownerHref}">${escapeHtml(detail)}</a></span>` : ` <span class="muted">${escapeHtml(detail)}</span>`}</td>
      <td class="muted">${n ? `${n.n} row${n.n === 1 ? "" : "s"}${n.on_n < n.n ? ` (${n.n - n.on_n} off)` : ""}` : `<em>${escapeHtml(fallback)}</em>`}</td>
      <td>${rowActions(iconLink(flowEditHref(channel, owner), "edit", "Edit mappings"))}</td>
    </tr>`;
  };

  const inboundRows = [
    flowRow("SCIM provisioning", "all inbound writes", "scim-in", "", "standard attribute mapping"),
    flowRow("Federation sign-in", "JIT defaults for every IdP", "jit", "", "built-in claim names"),
    ...idps.map((idp) => flowRow("Federation sign-in", idp.name, "jit", String(idp.id), "inherits the defaults", `/admin/integrations/federation/${idp.id}`)),
  ];
  const outboundRows = [
    ...targets.map((t) => flowRow("SCIM push", t.name, "scim-out", String(t.id), "default document", `/admin/integrations/scim/${t.id}`)),
    ...clients.map((cl) => flowRow("OIDC claims", cl.name, "oidc", cl.client_id, "standard claims only", `/admin/clients/${cl.id}`)),
    ...sps.map(
      (sp) => `<tr>
        <td>SAML attributes <span class="muted">&middot; <a href="/admin/saml/${sp.id}">${escapeHtml(sp.name)}</a></span></td>
        <td class="muted"><em>attribute map on the app</em></td>
        <td>${rowActions(iconLink(`/admin/saml/${sp.id}`, "edit", "Edit on the app"))}</td>
      </tr>`
    ),
  ];

  return c.html(
    layout(
      c,
      "Flows",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      <p class="muted" style="margin-top:0;">Every attribute flow in one place: what inbound writes set on users, and what sign-ins and provisioning send out. Each flow's rules are expressions evaluated by the shared engine &mdash; a row's <em>target</em> is the field it writes (inbound) or the attribute name it emits (outbound); its <em>expression</em> computes the value. A flow with no rows of its own falls back to the channel's defaults.</p>
      ${cardSection(`
        <h2>Inbound</h2>
        <p class="muted">An upstream provisioner or identity provider's data lands on user fields. Schemas on the <a href="/admin/schemas">Schemas</a> page define the vocabulary targets refer to (<code>custom.&lt;key&gt;</code> for custom attributes).</p>
        <table><tbody>${inboundRows.join("")}</tbody></table>
      `)}
      ${cardSection(`
        <h2>Outbound</h2>
        <p class="muted">What applications and provisioning targets receive. SAML attribute maps stay on each app's settings (they're part of its contract); the field side of every entry is the same expression language.</p>
        ${outboundRows.length ? `<table><tbody>${outboundRows.join("")}</tbody></table>` : '<p class="muted">No SCIM targets, OIDC clients or SAML apps yet.</p>'}
      `)}
      ${cardSection(`
        <h2>Collision policy</h2>
        <p class="muted">What happens when an inbound write (JIT provisioning, SCIM) would create a sign-in name or attach an email address that already belongs to someone else.</p>
        <form method="POST" action="/admin/flows/collision">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px;">
            <div>
              <label for="collision_username">Sign-in name is taken</label>
              <select id="collision_username" name="collision_username">
                <option value="increment" ${policy.username === "increment" ? "selected" : ""}>Append a counter (jdoe, jdoe2, jdoe3&hellip;)</option>
                <option value="pattern" ${policy.username === "pattern" ? "selected" : ""}>Evaluate a pattern expression</option>
                <option value="fail" ${policy.username === "fail" ? "selected" : ""}>Refuse the sign-in / write</option>
              </select>
            </div>
            <div>
              <label for="collision_email">Email address is taken</label>
              <select id="collision_email" name="collision_email">
                <option value="skip" ${policy.email === "skip" ? "selected" : ""}>Don't attach it to the new account</option>
                <option value="fail" ${policy.email === "fail" ? "selected" : ""}>Refuse the sign-in / write</option>
              </select>
            </div>
          </div>
          <label for="collision_pattern">Username pattern <span class="muted">(expression over <code>local</code>, <code>n</code>, <code>domain</code>, <code>email</code> &mdash; retried with n = 2, 3, 4&hellip; until free)</span></label>
          <input type="text" id="collision_pattern" name="collision_pattern" value="${escapeHtml(policy.username_pattern)}" placeholder='local + n' style="font-family:monospace;" />
          <div class="form-actions end"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Expression reference</h2>
        <p class="muted" style="margin-bottom:8px;">Paths walk the source document (<code>name.givenName</code>, <code>emails[type eq "work"].value</code>); <code>+</code> concatenates; <code>attr("name")</code> reaches names the grammar can't carry. Inbound expressions see the SCIM body or the IdP's claims; outbound ones see the user (<code>upn</code>, <code>username</code>, <code>display_name</code>, <code>given_name</code>, <code>family_name</code>, <code>email</code>, <code>name</code>, <code>id</code>, <code>job_title</code>, <code>department</code>, <code>manager</code>, <code>employee_number</code>, <code>hire_date</code>, <code>employment_status</code>, <code>employment_type</code>, <code>location</code>, <code>status</code>, <code>groups</code>, <code>emails</code>, <code>custom.*</code> and bare custom names). Dynamic-group rules use the same engine for their <code>expr</code> conditions.</p>
        <p class="muted" style="font-family:monospace; font-size:12px; line-height:1.9; margin:0;">${EXPRESSION_FUNCTIONS.join(" &middot; ")}</p>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Flows" }],
      "flows"
    )
  );
});

admin.get("/admin/flows/edit", async (c) => {
  const channel = c.req.query("channel") ?? "";
  const meta = FLOW_CHANNELS[channel as MappingChannel];
  if (!meta) return c.redirect("/admin/flows?error=" + encodeURIComponent("Unknown flow."), 302);
  const owner = c.req.query("owner") ?? "";
  const ownerLabel = await flowOwnerLabel(c.env, channel as MappingChannel, owner);
  const globals = owner ? await listMappings(c.env, { channel, owner: "" }) : [];
  const own = await listMappings(c.env, { channel, owner });
  const rows = own.length || !c.req.query("seed") ? own : globals.map((g) => ({ ...g, id: 0 }));
  return c.html(
    layout(
      c,
      `${meta.label} · ${ownerLabel}`,
      `
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">${meta.direction === "in" ? "Each row rewrites one user field from an expression over" : "Each row emits one attribute whose value is an expression over"} ${escapeHtml(meta.doc)}.${owner ? ` This set replaces the global defaults for ${escapeHtml(ownerLabel)} only.` : " These are the channel's defaults &mdash; owners without their own rows use them."}${owner && !own.length ? ' This flow currently <strong>inherits the defaults</strong> &mdash; <a href="' + flowEditHref(channel, owner, true) + '">copy them here to customise</a>.' : ""}</p>
        <datalist id="flow-map-targets">${meta.targets.map((t) => `<option value="${t}"></option>`).join("")}</datalist>
        <form method="POST" action="/admin/flows/mappings">
          <input type="hidden" name="channel" value="${escapeHtml(channel)}" />
          <input type="hidden" name="owner" value="${escapeHtml(owner)}" />
          <table>
            <thead><tr><th style="width:220px;">${meta.direction === "in" ? "Field" : "Attribute / claim"}</th><th>Expression</th><th style="width:60px;">On</th><th style="width:40px;"></th></tr></thead>
            <tbody id="mapping-rows">
              ${rows.map(flowRowHtml).join("")}
            </tbody>
          </table>
          <template id="mapping-row-template">${flowRowHtml()}</template>
          <div class="form-actions end">
            <button type="button" class="secondary" data-append-template="mapping-row-template" data-append-to="mapping-rows">+ Add mapping</button>
            <button class="primary" type="submit">Save mappings</button>
            <a class="cancel" href="/admin/flows">Cancel</a>
          </div>
        </form>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Flows", href: "/admin/flows" }, { label: `${meta.label} · ${ownerLabel}` }],
      "flows"
    )
  );
});

admin.post("/admin/flows/mappings", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const channel = String(body.channel ?? "");
  const owner = String(body.owner ?? "");
  const meta = FLOW_CHANNELS[channel as MappingChannel];
  if (!meta) return c.redirect("/admin/flows?error=" + encodeURIComponent("Unknown flow."), 302);
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const targets = list(body.map_target), exprs = list(body.map_expr), enabled = list(body.map_enabled);
  const back = `${flowEditHref(channel, owner)}&error=`;
  try {
    await replaceMappings(c.env, { channel, owner, resource: "user" }, targets.map((target, i) => ({ target, expression: exprs[i] ?? "", enabled: enabled[i] === "1" })), meta.validate);
  } catch (e) {
    return c.redirect(back + encodeURIComponent(e instanceof Error ? e.message : String(e)), 302);
  }
  await logAudit(c.env, c.get("user"), "settings.mappings_changed", `${channel}${owner ? ` (${owner})` : ""}`, { count: targets.length }, c.req.raw);
  return c.redirect("/admin/flows?saved=1", 302);
});

admin.post("/admin/flows/collision", async (c) => {
  const body = await c.req.parseBody();
  try {
    await setCollisionPolicy(c.env, {
      username: String(body.collision_username ?? ""),
      username_pattern: String(body.collision_pattern ?? ""),
      email: String(body.collision_email ?? ""),
    });
  } catch (e) {
    return c.redirect(`/admin/flows?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
  await logAudit(c.env, c.get("user"), "settings.collision_policy_changed", undefined, {}, c.req.raw);
  return c.redirect("/admin/flows?saved=1", 302);
});

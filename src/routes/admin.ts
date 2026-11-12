import { recordRateAttempt } from "../lib/rate-limit.js";
import { verifyPassword } from "../lib/password.js";
import { claimTotpCounter, matchTotpCounter } from "../lib/totp.js";
import { verifyAndConsumeBackupCode } from "../lib/backup-codes.js";
import { userHasPasskey } from "../lib/auth-policy.js";
import { isFreshlyAuthenticated, isSensitive, markSteppedUp, STEP_UP_WINDOW_MINUTES } from "../lib/step-up.js";
import { authenticationOptions, finishAuthentication } from "../lib/passkeys.js";
import { PASSKEY_LOGIN_SCRIPT } from "../lib/passkey-scripts.js";
import { accessFor, adminRoleGroupIds, adminRoleGroupNames, listRoles, rolePermissions, SUPER_ROLE, visibleSections, type Access, type RoleRow } from "../lib/admin-roles.js";
import { AREAS, grants, isPermission, SELF_PERMISSIONS } from "../lib/permissions.js";
import { FACTORS, factorEnrolmentCounts, isFactorEnabled, listPolicies, type FactorKey } from "../lib/auth-policy.js";
import { getKbaSettings, KBA_MAX_QUESTION, KBA_MAX_REQUIRED, listSecurityQuestions } from "../lib/security-questions.js";
import { readPerformance } from "../lib/metrics.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { requireAdmin, requireSession, SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { attr, attrGrid, barChart, breadcrumbs, cancelLink, cardSection, confirmAttrs, copyButton, escapeHtml, formActions, lineChart, multiSelect, nav, page, pageSizeSelect, paginationControls, rankedBars, remoteMultiSelect, rowMenu, scriptTag, searchSelect, secretBlock, successBanner, type Breadcrumb } from "../lib/html.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import type { GroupRow, OAuthClientRow, SamlServiceProviderRow, UserRow } from "../lib/types.js";
import { addDomain, applyDomainToAllUsers, listDomains, setDefaultDomain } from "../lib/domains.js";
import {
  getDefaultPassword,
  getPasswordPolicy,
  isSetupCompleted,
  markSetupCompleted,
  setDefaultPassword,
  validatePassword,
} from "../lib/settings.js";
import { logAudit } from "../lib/audit.js";
import { getScimConfig, getScimScope, setScimConfig } from "../lib/settings.js";
import { getRateLimitPolicy } from "../lib/rate-limit.js";
import { getNewUserPasswordMode, isMfaRequired } from "../lib/settings.js";
import {
  AUDIT_RETENTION_MAX_DAYS,
  AUDIT_RETENTION_MIN_DAYS,
  getAuditRetentionDays,
} from "../lib/settings.js";
import {
  passwordPolicySummary,
  CURSOR_TRAIL_MAX_CHARACTERS,
  getCursorTrail,
  getLoginGradient,
  getLoginSubtitle,
  getSessionPolicy,
  isHexColor,
  SESSION_IDLE_MINUTES_RANGE,
  SESSION_MAX_HOURS_RANGE,
} from "../lib/settings.js";
import { importDirectory, ImportValidationError, type DirectoryBundle } from "../lib/directory-import.js";
import { getEmailSettings, isEmailConfigured, isEmailEnabled, recipientFor } from "../lib/email.js";
import { deleteUserStatements, listActiveSessionsForUser } from "../lib/sessions.js";
import { deleteGroupScim, deleteUserScim, syncAll, testScimConnection, drainScimDeprovisionQueue, queueScimDeprovision } from "../lib/scim-client.js";
import { CLAIM_GROUP_LABELS, CLAIM_GROUPS, isValidPostLogoutUri, parseAllowedClaims } from "../lib/oidc.js";
import { fetchSpMetadata, parseSpMetadata, SpMetadataError, upsertSpFromMetadata } from "../lib/saml/sp-metadata.js";
import { API_SCOPES, createApiKey, isApiScope, listApiKeys, parseScopes, type ApiScope } from "../lib/api-keys.js";
import { idpEntityId, supportedNameIdFormats, nameIdFormatUri } from "../lib/saml/messages.js";
import { isSamlConfigured } from "../lib/saml/sign.js";
import { certNotAfter, normalizeCertPem } from "../lib/saml/x509.js";
import { USER_ATTRIBUTE_FIELDS } from "../lib/saml/attributes.js";
import { resolveManyGroupMemberUserIds, parseRule, userMatchesRule, ruleDescription, ruleFields, ruleFromForm, type RuleCondition } from "../lib/groups.js";
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

import { consoleCtx, ServiceError } from "../services/context.js";
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
import { assertRuleAllowed, createGroup, deleteGroup, freezeGroup, groupMembers, removeGroupMember, updateGroup } from "../services/groups.js";
import { deleteClient, getClientById, ID_TOKEN_ALGS, isIdTokenAlg, rotateClientSecret, updateClient, validFrontchannelUri } from "../services/clients.js";
import {
  addSecurityQuestion,
  applyDefaultPasswordToAll,
  deleteSecurityQuestion,
  saveKbaSettings,
  setSecurityQuestionEnabled,
  saveAppName,
  saveAuditRetention,
  saveCursorTrail,
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
import { removeDomain, revokeKey, rotateKey } from "../services/platform.js";
import { getAccent, getTemplate, renderEmail, TEMPLATE_INFO, type EmailTemplate, type TemplateKey } from "../lib/email-templates.js";
import { getSetting } from "../lib/settings.js";
import { listSigningKeys, RETIRED_PUBLISH_HOURS, SIGNING_ALGS } from "../lib/signing-keys.js";
import { DASHBOARD_DAYS, LOG_ACTORS, LOG_CATEGORIES, logFilters, overviewStats, PERF_RANGES, performanceReport, queryAuditLog } from "../services/monitoring.js";

export { validFrontchannelUri };

export const admin = new Hono<{ Bindings: Env }>();

// A refusal from a shared service (src/services) is rendered as the console
// always rendered its refusals: the message as text, with the status.
admin.onError((err, c) => {
  if (err instanceof ServiceError) return c.text(err.message, err.status);
  console.error(err);
  return c.text("Internal server error", 500);
});

admin.use("/admin", requireSession, requireAdmin);
admin.use("/admin/*", requireSession, requireAdmin);

/**
 * Below Super Admin, nobody can change who holds an admin role or act on an
 * account that holds one: a Directory Admin could otherwise make themselves
 * (or anyone) Super Admin, or reset a Super Admin's password.
 */
admin.use("/admin/*", async (c, next) => {
  if (c.req.method !== "POST" || c.get("isSuperAdmin")) return next();
  const path = c.req.path;
  const forbid = (why: string) => c.text(`Forbidden: ${why} needs a Super Admin.`, 403);
  const roleGroupIds = await adminRoleGroupIds(c.env);
  const roleGroupNames = await adminRoleGroupNames(c.env);
  const userMatch = /^\/admin\/users\/(\d+)(\/|$)/.exec(path);
  if (userMatch && (await accessFor(c.env, Number(userMatch[1]))).isAdmin) return forbid("changing an account that holds an admin role");
  const groupMatch = /^\/admin\/groups\/(\d+)(\/|$)/.exec(path);
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
  // Back to the page the form was on, which the user resubmits after confirming.
  const ref = c.req.header("Referer");
  const back = ref && new URL(ref).origin === new URL(c.req.url).origin ? new URL(ref).pathname + new URL(ref).search : "/admin";
  return c.redirect(`/admin/reauth?next=${encodeURIComponent(back)}`, 303);
});

function safeNext(next: string | undefined): string {
  return next && next.startsWith("/admin") && !next.startsWith("//") ? next : "/admin";
}

admin.get("/admin/reauth", async (c) => {
  const user = c.get("user");
  const next = safeNext(c.req.query("next"));
  const hasPasskey = await userHasPasskey(c.env, user.id);
  return c.html(
    layout(
      c,
      "Confirm it's you",
      cardSection(`
        ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
        <p class="muted" style="margin-top:0;">This action changes credentials or security settings, so it needs you to have signed in within the last ${STEP_UP_WINDOW_MINUTES} minutes. Confirm, then repeat what you were doing.</p>
        <form method="POST" action="/admin/reauth">
          <input type="hidden" name="next" value="${escapeHtml(next)}" />
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required autocomplete="current-password" style="max-width:320px;" />
          ${user.mfa_enabled ? `<label for="code">Authenticator code or backup code</label><input type="text" id="code" name="code" maxlength="12" required autocomplete="one-time-code" style="max-width:160px;" />` : ""}
          <div class="form-actions"><button class="primary" type="submit">Confirm</button>${cancelLink(next)}</div>
        </form>
        ${
          hasPasskey
            ? `<div class="auth-passkey" style="max-width:320px;">
                <button class="secondary" type="button" data-passkey-login data-param="next" data-flow="${escapeHtml(next)}" data-options="/admin/reauth/passkey/options" data-post="/admin/reauth/passkey" style="width:100%;">Or confirm with a passkey</button>
                <p class="muted" id="passkey-login-status" style="margin:6px 0 0; font-size:0.8125rem;"></p>
              </div>${scriptTag(PASSKEY_LOGIN_SCRIPT)}`
            : ""
        }
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Confirm it's you" }]
    )
  );
});

async function stepUpAttemptsExceeded(c: { env: Env; get: (k: "user") => UserRow }): Promise<boolean> {
  const policy = await getRateLimitPolicy(c.env);
  return recordRateAttempt(c.env, `admin:stepup:${c.get("user").id}`, policy.maxAttempts, policy.windowMinutes);
}

admin.post("/admin/reauth", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const next = safeNext(String(body.next ?? ""));
  const fail = async (msg: string) => {
    await logAudit(c.env, user, "admin.step_up_failed", user.upn, undefined, c.req.raw);
    return c.redirect(`/admin/reauth?next=${encodeURIComponent(next)}&error=${encodeURIComponent(msg)}`, 302);
  };
  if (await stepUpAttemptsExceeded(c)) return fail("Too many attempts. Please wait a few minutes.");
  if (!(await verifyPassword(String(body.password ?? "").slice(0, 1024), user))) return fail("That password is not right.");
  if (user.mfa_enabled) {
    const code = String(body.code ?? "").slice(0, 12);
    const counter = user.totp_secret ? await matchTotpCounter(user.totp_secret, code) : null;
    const ok = (counter !== null && (await claimTotpCounter(c.env, user.id, counter))) || (await verifyAndConsumeBackupCode(c.env, user.id, code));
    if (!ok) return fail("That code is not right.");
  }
  await markSteppedUp(c.env, c.get("sessionId"));
  await logAudit(c.env, user, "admin.step_up", user.upn, { method: user.mfa_enabled ? "password+totp" : "password" }, c.req.raw);
  return c.redirect(next, 302);
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
    await logAudit(c.env, user, "admin.step_up_failed", user.upn, { method: "passkey" }, c.req.raw);
    return c.redirect(`/admin/reauth?next=${encodeURIComponent(next)}&error=${encodeURIComponent("That passkey could not confirm it's you.")}`, 302);
  }
  await markSteppedUp(c.env, c.get("sessionId"));
  await logAudit(c.env, user, "admin.step_up", user.upn, { method: "passkey" }, c.req.raw);
  return c.redirect(next, 302);
});

/** Section labels (second breadcrumb) -> nav key, so detail pages highlight their section too. */
const CRUMB_SECTIONS: Record<string, string> = {
  Users: "users",
  Groups: "groups",
  Integrations: "integrations",
  Domains: "domains",
  Branding: "branding",
  Security: "security",
  Schemas: "schemas",
  Log: "audit",
};

function layout(
  c: { get: ((k: "appName") => string) & ((k: "access") => Access | undefined) },
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
      ? (crumbs?.[2]?.label === "Email templates" ? "email-templates" : "settings")
      : section !== "integrations"
      ? ""
      : crumbs?.length === 2
        ? "overview"
        : (INTEGRATION_PAGES.find((p) => p.label === crumbs?.[2]?.label)?.key ?? "");
  return page(
    `${title}`,
    `<div class="admin-shell">
      <aside class="admin-side">${adminNav(section, sub, c.get("access") ? visibleSections(c.get("access")!) : undefined)}</aside>
      <div class="admin-main">
        <div class="page-header">${crumbHtml}<div class="page-header-row"><h1>${escapeHtml(title)}</h1>${headerActions}</div></div>
        ${body}
      </div>
    </div>`,
    appName,
    true,
    nav(appName, true)
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
  { key: "oidc", label: "OIDC clients" },
  { key: "saml", label: "SAML apps" },
  { key: "api-keys", label: "API keys" },
  { key: "scim", label: "SCIM provisioning" },
  { key: "email", label: "Email" },
] as const;
type IntegrationPage = (typeof INTEGRATION_PAGES)[number]["key"];

const INTEGRATIONS_CRUMB: Breadcrumb = { label: "Integrations", href: "/admin/integrations" };
function integrationCrumb(key: IntegrationPage): Breadcrumb {
  const p = INTEGRATION_PAGES.find((x) => x.key === key)!;
  return { label: p.label, href: `/admin/integrations/${p.key}` };
}

function adminNav(active: string, sub = "", visible?: Set<string>) {
  const items: [string, string, string][] = [
    ["overview", "/admin", "Overview"],
    ["users", "/admin/users", "Users"],
    ["groups", "/admin/groups", "Groups"],
    ["integrations", "/admin/integrations", "Integrations"],
    ["domains", "/admin/domains", "Domains"],
    ["branding", "/admin/branding", "Branding"],
    ["security", "/admin/security", "Security"],
    ["schemas", "/admin/schemas", "Schemas"],
    ["audit", "/admin/audit", "Log"],
  ];
  return items
    .filter(([key]) => !visible || visible.has(key))
    .map(([key, href, label]) => {
      const link = `<a href="${href}" class="${active === key ? "active" : ""}">${label}</a>`;
      // A section's pages are listed only while you are in that section.
      if (key === "overview" && active === "overview") {
        return link + [["dashboard", "/admin", "Dashboard"], ["performance", "/admin/performance", "Performance"]]
          .map(([k, h, l]) => `<a href="${h}" class="sub${(sub || "dashboard") === k ? " active" : ""}">${l}</a>`)
          .join("");
      }
      if (key === "branding" && active === "branding") {
        return link + [["settings", "/admin/branding", "Settings"], ["email-templates", "/admin/branding/email-templates", "Email templates"]]
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
    .join("");
}

// The account-password and SCIM helpers moved to src/services, shared with the API.

function splitUpn(upn: string): { username: string; domain: string } {
  const at = upn.lastIndexOf("@");
  return at === -1 ? { username: upn, domain: "" } : { username: upn.slice(0, at), domain: upn.slice(at + 1) };
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
async function userSchemaAttributesHtml(c: { env: Env }, attributes: SchemaAttributeRow[], values: Record<string, string>, excludeUserId: number | null): Promise<string> {
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

  const cells = attributes.map((attr) => {
    const value = values[attr.name] ?? "";
    const label = `<label for="attr_${escapeHtml(attr.name)}">${escapeHtml(attr.label)}${attr.required ? " *" : ""}</label>`;
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


async function domainSelect(env: Env, name: string, selectedDomain?: string) {
  const domains = await listDomains(env);
  const hasSelected = selectedDomain ? domains.some((d) => d.domain === selectedDomain) : false;
  return `<select name="${escapeHtml(name)}">
    ${domains
      .map((d) => `<option value="${escapeHtml(d.domain)}" ${d.domain === selectedDomain ? "selected" : ""}>${escapeHtml(d.domain)}</option>`)
      .join("")}
    ${selectedDomain && !hasSelected ? `<option value="${escapeHtml(selectedDomain)}" selected>${escapeHtml(selectedDomain)} (not in domain list)</option>` : ""}
  </select>`;
}

// ---------- Dashboard ----------

// DASHBOARD_DAYS, dayKey and PERF_RANGES live in services/monitoring.ts, shared with the API.

admin.get("/admin/performance", async (c) => {
  const { rangeKey, range, family, series, totals } = await performanceReport(c.env, c.req.query("range"), c.req.query("endpoint"));
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
        ${barChart(series.points.map((p, i) => ({ label: labels[i]!, value: p.requests })))}`)}
      <div class="two-col">
        ${cardSection(`<h2>Latency</h2><p class="muted">Worker time per request, ms.</p>
          ${lineChart(labels, [{ name: "p50", className: "s-p50", values: series.points.map((p) => p.p50) }, { name: "p95", className: "s-p95", values: series.points.map((p) => p.p95) }], { unit: "" })}
          <div class="chart-legend"><span><span class="chart-swatch" style="background:var(--fi-accent);"></span>p50</span><span><span class="chart-swatch" style="background:var(--fi-faint);"></span>p95</span></div>`)}
        ${cardSection(`<h2>Server errors</h2><p class="muted">Responses with status 500 and above.</p>
          ${barChart(series.points.map((p, i) => ({ label: labels[i]!, value: p.errors })), { barClass: "err" })}`)}
      </div>
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
  // The same numbers GET /api/v1/stats returns (services/monitoring.ts).
  const [stats, perf] = await Promise.all([overviewStats(c.env), readPerformance(c.env, 24)]);
  const successSeries = stats.last_30d.sign_ins_by_day.map(({ day, success }) => ({
    label: day.slice(8, 10) === "01" ? day.slice(5, 10) : day.slice(8, 10),
    value: success,
  }));
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
        <a class="stat-card" href="/admin/clients"><div class="card"><h2>${oidcClients}</h2><p>OIDC Clients</p></div></a>
        <a class="stat-card" href="/admin/log"><div class="card"><h2>${successTotal}</h2><p>Sign-ins (30d)</p></div></a>
      </div>
      <div class="stat-grid">
        <a class="stat-card" href="/admin/users"><div class="card"><h2>${activeUsers}</h2><p>Active accounts</p></div></a>
        <a class="stat-card" href="/admin/integrations/saml"><div class="card"><h2>${samlApps}</h2><p>SAML apps</p></div></a>
        <a class="stat-card" href="/admin/integrations/api-keys"><div class="card"><h2>${apiKeys}</h2><p>Active API keys</p></div></a>
        <a class="stat-card" href="/admin/log"><div class="card"><h2>${refreshLive}</h2><p>Live refresh grants</p></div></a>
      </div>

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
          ${perf.configured && perf.ok ? attrGrid([attr("Requests (24h)", perf.total.toLocaleString("en")), attr("Server errors (5xx)", perf.errors)]) : '<p class="muted">Request volume, errors and latency for every endpoint, with graphs.</p>'}
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
            : barChart(successSeries)
        }
        <div class="chart-legend">
          <span><span class="chart-swatch" style="background:var(--fi-accent);"></span>${successTotal} successful</span>
          <span><span class="chart-swatch" style="background:#cbd5e1;"></span>${failedTotal} failed or rejected</span>
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
            attr("Failed sign-ins (30d)", failedTotal),
          ])}
          <div style="margin-top:14px;"><a href="/admin/log">View the full log</a></div>
        `)}
      </div>
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
      ${cardSection(`
        <p class="sub">Before anyone else can sign in, confirm the basics below. You can change all of this later from Admin → Domains / Security.</p>
        <form method="POST" action="/admin/setup" ${confirmAttrs(
          "Every user except your own admin account is permanently deleted, along with every group except Super Admins and All Employees.",
          { title: "Remove the sample directory?", action: "Remove and finish", danger: true, when: 'input[name=sample_data][value=remove]' }
        )}>
          <label for="domain">Primary domain for user accounts</label>
          <input type="text" id="domain" name="domain" value="${escapeHtml(domains[0]?.domain ?? "")}" required />
          <label for="default_password">Default password for new/seeded accounts</label>
          <input type="text" id="default_password" name="default_password" value="${escapeHtml(defaultPassword)}" required />

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
    const existing = await listDomains(c.env);
    if (!existing.some((d) => d.domain === domain)) {
      await addDomain(c.env, domain);
    }
    const row = (await listDomains(c.env)).find((d) => d.domain === domain);
    if (row) await setDefaultDomain(c.env, row.id);
  }
  if (defaultPassword) await setDefaultPassword(c.env, defaultPassword);

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
  // The admin role groups are FlareID's own, like Super Admins: never sample data.
  const { results: sampleGroups } = await c.env.DB.prepare(
    `SELECT * FROM groups WHERE name NOT IN (SELECT value FROM json_each(?))`
  )
    .bind(JSON.stringify(await adminRoleGroupNames(c.env)))
    .all<GroupRow>();

  // The shared deletion (every users(id)-referencing table), with the remote
  // ids queued in the same batch; downstream DELETEs drain from the queue.
  const sampleUserIds = sampleUsers.map((u) => u.id);
  await c.env.DB.batch([
    ...sampleUsers.filter((u) => u.scim_id).map((u) => queueScimDeprovision(c.env, "user", u.scim_id!, u.upn)),
    ...sampleGroups.filter((g) => g.scim_id).map((g) => queueScimDeprovision(c.env, "group", g.scim_id!, g.name)),
    ...(sampleUserIds.length > 0 ? deleteUserStatements(c.env, ...sampleUserIds) : []),
    c.env.DB.prepare("DELETE FROM groups WHERE name NOT IN (SELECT value FROM json_each(?))").bind(JSON.stringify(await adminRoleGroupNames(c.env))),
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
  if (mfaFilter === "enabled" || mfaFilter === "disabled") {
    conditions.push("mfa_enabled = ?");
    params.push(mfaFilter === "enabled" ? 1 : 0);
  }
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
    c.env.DB.prepare(`SELECT * FROM users ${whereClause} ORDER BY display_name LIMIT ? OFFSET ?`).bind(
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
      "Users",
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
                ["enabled", "MFA enabled"],
                ["disabled", "MFA not enabled"],
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
          <thead><tr><th>Name</th><th>UPN</th><th>Status</th><th>MFA</th><th>Role</th><th>Schema</th><th style="width:40px;"></th></tr></thead>
          <tbody>
            ${(users as UserRow[])
              .map(
                (u) => `<tr>
                  <td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a></td>
                  <td>${escapeHtml(u.upn)}</td>
                  <td><span class="badge badge-${u.status}">${u.status}</span></td>
                  <td>${u.mfa_enabled ? "Enabled" : "-"}</td>
                  <td>${admins.has(u.id) ? '<span class="badge badge-admin">Super Admin</span>' : "-"}</td>
                  <td>${u.schema_id && schemaNames.has(u.schema_id) ? escapeHtml(schemaNames.get(u.schema_id)!) : '<span class="muted">-</span>'}</td>
                  <td style="text-align:right;">${rowMenu(`
                    <a href="/admin/users/${u.id}">Edit</a>
                    ${
                      u.id === currentUserId
                        ? ""
                        : `<form method="POST" action="/admin/users/${u.id}/delete" style="margin:0;"
                            ${confirmAttrs(`${u.display_name} (${u.upn}) is removed along with their sessions, tokens and group memberships. This cannot be undone.`, { title: "Delete this user?", action: "Delete user", danger: true })}>
                            <button type="submit" class="danger">Delete</button>
                          </form>`
                    }
                  `)}</td>
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
        <pre id="csv-log" class="import-log">Nothing imported yet.</pre>
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
          <label for="username">UPN</label>
          <div class="field-row">
            <input type="text" id="username" name="username" placeholder="username" required style="flex:2;" />
            <div style="flex:1;">${await domainSelect(c.env, "domain", domains[0]?.domain)}</div>
          </div>
          <div class="card-head" style="margin-top:8px;">
            <h2>Attributes</h2>
            <div class="inline-field">
              <label for="schema_id">Schema</label>
              <select id="schema_id" name="schema_id" style="margin-bottom:0;" data-navigate="/admin/users/new?schema=">
                ${userSchemas.map((s) => `<option value="${s.id}" ${schema?.id === s.id ? "selected" : ""}>${escapeHtml(s.name)}</option>`).join("")}
              </select>
            </div>
          </div>
          ${await userSchemaAttributesHtml(c, schemaAttrs, emptyValues, null)}
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

admin.get("/admin/users/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return c.text("Not found", 404);
  const emailOn = await isEmailConfigured(c.env);

  const { results: groups } = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all<GroupRow>();
  const { results: memberships } = await c.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?")
    .bind(id)
    .all<{ group_id: number }>();
  const memberGroupIds = new Set(memberships.map((m) => m.group_id));
  const sessions = await listActiveSessionsForUser(c.env, id);
  const apps = await connectedApps(c.env, id);
  const { username, domain } = splitUpn(user.upn);
  const isSelf = id === c.get("user").id;
  const anyMfa = Boolean(user.mfa_enabled || user.email_otp_enabled || user.security_questions_enabled);

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

  const staticGroups = groups.filter((g) => !parseRule(g.rule));
  const dynamicGroups = dynamicGroupsFor(user, groups);

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
      <form method="POST" action="/admin/users/${id}" id="user-form">
        ${cardSection(`
          <h2>Identity</h2>
          <div class="field-row">
            <div>
              <label for="given_name">First name</label>
              <input type="text" id="given_name" name="given_name" value="${escapeHtml(user.given_name)}" required />
            </div>
            <div>
              <label for="family_name">Last name</label>
              <input type="text" id="family_name" name="family_name" value="${escapeHtml(user.family_name)}" />
            </div>
          </div>
          <label for="username">UPN</label>
          <div class="field-row">
            <input type="text" id="username" name="username" value="${escapeHtml(username)}" required style="flex:2; min-width:0;" />
            <div style="flex:1; min-width:0;">${await domainSelect(c.env, "domain", domain)}</div>
          </div>
          <p class="muted" style="margin:0;">External ID <code>${escapeHtml(user.external_id)}</code> &middot; Created ${escapeHtml(new Date(user.created_at).toLocaleString())}</p>
        `)}

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
          ${await userSchemaAttributesHtml(c, schemaAttrs, attrValues, id)}
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

        <div class="form-actions end" style="margin-bottom:18px;">
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
            <h3>Multi-factor authentication <span class="badge ${anyMfa ? "badge-active" : "badge-disabled"}">${anyMfa ? "Enrolled" : "Not enrolled"}</span></h3>
            <p class="muted">Authenticator app: ${user.mfa_enabled ? "enrolled" : "not enrolled"} &middot; Email codes: ${user.email_otp_enabled ? "enrolled" : "not enrolled"} &middot; Security questions: ${user.security_questions_enabled ? "enrolled" : "not enrolled"}</p>
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
                        `<tr><td>${escapeHtml(new Date(s.created_at).toLocaleString())}</td><td>${escapeHtml(new Date(s.last_seen_at).toLocaleString())}</td><td class="muted">${escapeHtml(s.ip ?? "unknown")}</td></tr>`
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
                        `<tr><td>${escapeHtml(app.name)}</td><td><form method="POST" action="/admin/users/${id}/apps/${app.id}/revoke" ${confirmAttrs(`${user.display_name} will need to sign in to ${app.name} again.`, { title: `Revoke access to ${app.name}?`, action: "Revoke access", danger: true })}><button class="link-button" type="submit">Revoke access</button></form></td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
            : '<p class="muted">No connected apps.</p>'
        }
      `)}
      </div>

      ${
        isSelf
          ? ""
          : cardSection(`
        <h2>Delete user</h2>
        <p class="muted">Removes the account, its group memberships, and any tokens issued for it. To keep the account but stop sign-ins, switch it to Inactive instead.</p>
        <form method="POST" action="/admin/users/${id}/delete" ${confirmAttrs(`Deleting ${user.display_name} cannot be undone. Their sessions, tokens and group memberships are removed with them.`, { title: "Delete this user?", action: "Delete user", danger: true })}>
          <button class="danger" type="submit">Delete ${escapeHtml(user.display_name)}</button>
        </form>
      `)
      }
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

admin.post("/admin/users/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  const postedGroupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];
  // The form carries every value of the chosen schema (same-named values were
  // carried into it), so this is a full replace - PATCH /api/v1/users merges
  // into the current values and calls the same function.
  await updateUserProfile(consoleCtx(c), id, {
    username: String(body.username ?? ""),
    domain: String(body.domain ?? ""),
    givenName: String(body.given_name ?? ""),
    familyName: String(body.family_name ?? ""),
    schemaId: Number(body.schema_id) || undefined,
    attributes: Object.fromEntries(Object.entries(body).filter(([k]) => k.startsWith("attr_")).map(([k, v]) => [k.slice(5), String(v ?? "")])),
    groupIds: postedGroupIds,
  });
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

/** Invitation (activates on acceptance) or reset link, by email. Back to the user page with what happened. */
async function emailUserLink(c: Context<{ Bindings: Env }>, kind: "invite" | "reset") {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return c.text("Not found", 404);
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
  if (!user) return c.text("Not found", 404);

  const body = await c.req.parseBody();
  const chosen = String(body.password ?? "");
  const policy = await getPasswordPolicy(c.env);
  const crumbs = [{ label: "Admin", href: "/admin" }, { label: "Users", href: "/admin/users" }, { label: user.display_name, href: `/admin/users/${id}` }, { label: "Set password" }];

  // Blank means "generate one" - except from a form that exists to set a chosen password.
  const policyError = chosen ? validatePassword(chosen, policy) : body.require_chosen ? "Enter a password." : null;
  if (policyError) {
    return c.html(
      layout(c, "Set password", cardSection(`<h2>Set a password for ${escapeHtml(user.display_name)}</h2>${choosePasswordForm(id, policy, policyError)}`), crumbs),
      400
    );
  }

  // A reset is a compromise response too: every existing session ends
  // (services/users.ts, shared with POST /api/v1/users/{username}/reset-password).
  const { password } = await resetUserPassword(consoleCtx(c), id, chosen);

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

function ruleRowHtml(data: RuleBuilderData, cond?: RuleCondition): string {
  const schemaName = cond?.schema ?? data.schemas.find((s) => s.attributes.some((a) => a.name === cond?.field))?.name ?? data.defaultSchema;
  const attrs = data.schemas.find((s) => s.name === schemaName)?.attributes ?? [];
  const field = cond?.field ?? "";
  return `<div class="rule-row">
    ${searchSelect("rule_schema", data.schemas.map((s) => ({ value: s.name, label: s.name })), schemaName, "Schema")}
    <div class="rule-attr">${searchSelect("rule_field", attrs.map((a) => ({ value: a.name, label: `${a.label} (${a.name})` })), field, "Attribute")}</div>
    <select name="rule_op">
      <option value="eq" ${cond?.op !== "ne" ? "selected" : ""}>=</option>
      <option value="ne" ${cond?.op === "ne" ? "selected" : ""}>!=</option>
    </select>
    <input type="text" name="rule_value" value="${escapeHtml(cond?.value ?? "")}" placeholder="Value" ${field ? `list="rv-${escapeHtml(field)}"` : ""} autocomplete="off" />
    <button type="button" class="secondary" data-remove-closest=".rule-row" aria-label="Remove condition">&times;</button>
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
              ? `<label>Add members</label>
                 ${remoteMultiSelect("add_user_ids", `/admin/users/lookup?not_in_group=${group.id}`, [], "Search people to add...")}
                 <p class="muted" style="margin-top:-8px;">Current members are listed below, where they can be removed.</p>`
              : remoteMultiSelect("user_ids", "/admin/users/lookup", [], "Search people...")
          }
        </div>

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
  return { name, description, rule, userIds, addUserIds, schemaId, custom };
}

admin.get("/admin/groups", async (c) => {
  const search = c.req.query("search") ?? "";
  const typeFilter = c.req.query("type") ?? "";
  const pageSize = [20, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 20;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const like = `%${search}%`;

  const conditions = ["(name LIKE ? OR description LIKE ?)"];
  if (typeFilter === "dynamic") conditions.push("rule != ''");
  if (typeFilter === "static") conditions.push("rule = ''");
  const where = `WHERE ${conditions.join(" AND ")}`;

  const batchResults = await c.env.DB.batch([
    c.env.DB.prepare(`SELECT COUNT(*) as n FROM groups ${where}`).bind(like, like),
    c.env.DB.prepare(
      `SELECT g.*, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
       FROM groups g ${where} ORDER BY g.name LIMIT ? OFFSET ?`
    ).bind(like, like, pageSize, (page - 1) * pageSize),
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
      "Groups",
      `
      ${cardSection(`
        <form method="GET" class="list-toolbar">
          <div class="list-toolbar-filters">
            <input type="text" name="search" placeholder="Search groups" value="${escapeHtml(search)}" />
            <select name="type" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
              ${[["", "All types"], ["static", "Static"], ["dynamic", "Dynamic"]].map(([v, l]) => `<option value="${v}" ${v === typeFilter ? "selected" : ""}>${l}</option>`).join("")}
            </select>
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
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Description</th><th>Members</th></tr></thead>
          <tbody>
            ${groups
              .map((g) => {
                const rule = parseRule(g.rule);
                return `<tr>
                  <td><a href="/admin/groups/${g.id}">${escapeHtml(g.name)}</a>${g.name === SUPER_ADMINS_GROUP ? ' <span class="badge badge-admin">Admin access</span>' : ""}</td>
                  <td>${rule ? `<span class="badge badge-admin" title="${escapeHtml(ruleDescription(rule))}">Dynamic</span>` : '<span class="pill">Static</span>'}</td>
                  <td>${escapeHtml(g.description ?? "")}</td>
                  <td>${countFor(g)}</td>
                </tr>`;
              })
              .join("")}
          </tbody>
        </table>
        ${paginationControls("/admin/groups", page, totalPages, { search, type: typeFilter, pageSize })}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Groups" }]
    )
  );
});

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
    return c.text(e instanceof Error ? e.message : "Invalid group.", 400);
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
      <form method="GET" action="/admin/groups/${group.id}" class="inline-field" style="margin:0;">
        <input type="search" name="msearch" value="${escapeHtml(search)}" placeholder="Find a person by name or UPN" style="margin:0; width:280px;" />
        <button class="secondary" type="submit">Search</button>
        ${search ? `<a href="/admin/groups/${group.id}">Clear</a>` : ""}
      </form>
    </div>
    ${
      rows.length
        ? `<table><thead><tr><th>Name</th><th>UPN</th><th>Status</th>${rule ? "" : "<th></th>"}</tr></thead><tbody>
            ${rows.map((u) => `<tr><td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a></td><td>${escapeHtml(u.upn)}</td><td><span class="badge badge-${escapeHtml(u.status)}">${escapeHtml(u.status)}</span></td>${
              rule ? "" : `<td style="text-align:right;"><form method="POST" action="/admin/groups/${group.id}/members/${u.id}/remove" style="margin:0;"><button class="link-button" type="submit">Remove</button></form></td>`
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

admin.get("/admin/groups/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();
  if (!group) return c.text("Not found", 404);
  const rule = parseRule(group.rule);
  const msearch = (c.req.query("msearch") ?? "").slice(0, 100);
  const mpage = Math.min(100_000, Math.max(1, Math.floor(Number(c.req.query("mpage")) || 1)));

  return c.html(
    layout(
      c,
      group.name,
      `${c.req.query("saved") ? successBanner("Saved.") : ""}${await groupFormHtml(c, group, Number(c.req.query("schema")))}${await groupMembersPanel(c.env, group, msearch, mpage)}`,
      [{ label: "Admin", href: "/admin" }, { label: "Groups", href: "/admin/groups" }, { label: group.name }],
      undefined,
      rule ? `<span class="badge badge-admin" title="${escapeHtml(ruleDescription(rule))}">Dynamic</span>` : '<span class="pill">Static</span>'
    )
  );
});

admin.post("/admin/groups/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const existing = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();
  if (!existing) return c.text("Not found", 404);

  let form;
  try {
    form = await readGroupForm(c, existing.name);
  } catch (e) {
    return c.text(e instanceof Error ? e.message : "Invalid group.", 400);
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

/** Test / Sync buttons on the Integrations page - data-scim="test|sync". */
const SCIM_SCRIPT = `
document.addEventListener("click", async function (e) {
  const btn = e.target.closest("[data-scim]");
  if (!btn) return;
  const kind = btn.dataset.scim;
  const status = document.getElementById("scim-status");
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = kind === "test" ? "Testing..." : "Syncing...";
  status.replaceChildren();
  const p = document.createElement("p");
  p.style.marginTop = "12px";
  try {
    if (kind === "test") {
      const data = await (await fetch("/admin/scim/test", { method: "POST" })).json();
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
        const res = await fetch("/admin/scim/sync" + (first ? "?restart=1" : ""), { method: "POST" });
        if (!res.ok) { line("Stopped: the server answered " + res.status + ". Press Sync all now to carry on from here."); throw new Error("HTTP " + res.status); }
        data = await res.json();
        first = false;
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

// ---------- Integrations: OIDC clients, SAML apps, API keys, SCIM ----------
//
// One section, because they are all how other systems connect to this
// directory - configuring Cloudflare Access means registering a client and
// then setting up SCIM, and that should not be a hunt across the nav. Each
// kind has its own page, listed under Integrations in the sidebar while you are
// in the section; /admin/integrations is an overview of all four. The older
// single-page paths still resolve so existing links and bookmarks survive.
admin.get("/admin/clients", (c) => c.redirect("/admin/integrations/oidc", 302));
admin.get("/admin/scim", (c) => c.redirect(`/admin/integrations/scim${new URL(c.req.url).search}`, 302));

/** Page heading row: the page's description plus its primary action. */
function integrationIntro(description: string, action?: { href: string; label: string }): string {
  return `<div class="row between" style="margin:0 0 14px 0; align-items:flex-start; gap:16px;">
    <p class="muted" style="margin:0; max-width:720px;">${description}</p>
    ${action ? `<a href="${escapeHtml(action.href)}"><button class="primary" type="button">${escapeHtml(action.label)}</button></a>` : ""}
  </div>`;
}

/** One overview card: a heading with a count, up to five rows, and a link to the full page. */
function summaryCard(opts: { title: string; count: string; rows: string[]; empty: string; manage: IntegrationPage; extra?: string }): string {
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
    <div style="margin-top:12px;"><a href="/admin/integrations/${page.key}">Manage ${escapeHtml(page.label)} &rarr;</a></div>
  `);
}

admin.get("/admin/integrations", async (c) => {
  const [{ results: clients }, { results: sps }, apiKeys, scim, scope] = await Promise.all([
    c.env.DB.prepare("SELECT id, name, client_id FROM oauth_clients ORDER BY name").all<Pick<OAuthClientRow, "id" | "name" | "client_id">>(),
    c.env.DB.prepare("SELECT id, name, entity_id FROM saml_service_providers ORDER BY name").all<Pick<SamlServiceProviderRow, "id" | "name" | "entity_id">>(),
    listApiKeys(c.env),
    getScimConfig(c.env),
    getScimScope(c.env),
  ]);
  const activeKeys = apiKeys.filter((k) => !k.revoked_at);
  const revokedKeys = apiKeys.length - activeKeys.length;
  const scimConfigured = Boolean(scim.endpoint && scim.secret);
  let scimHost = "";
  try {
    scimHost = scim.endpoint ? new URL(scim.endpoint).host : "";
  } catch {
    scimHost = scim.endpoint;
  }

  return c.html(
    layout(
      c,
      "Integrations",
      `
      <p class="muted" style="margin:-6px 0 16px;">Everything that connects to this directory: apps that sign users in, keys that automate it, and where users are provisioned.</p>
      <div class="two-col">
        ${summaryCard({
          title: "OIDC clients",
          count: `${clients.length} registered`,
          rows: clients.map((cl) => `<tr><td><a href="/admin/clients/${cl.id}">${escapeHtml(cl.name)}</a></td><td><code>${escapeHtml(cl.client_id)}</code></td></tr>`),
          empty: "No clients registered yet.",
          manage: "oidc",
        })}
        ${summaryCard({
          title: "SAML apps",
          count: `${sps.length} registered`,
          rows: sps.map((sp) => `<tr><td><a href="/admin/saml/${sp.id}">${escapeHtml(sp.name)}</a></td><td><code>${escapeHtml(sp.entity_id)}</code></td></tr>`),
          empty: "No service providers registered yet.",
          manage: "saml",
        })}
      </div>
      <div class="two-col">
        ${summaryCard({
          title: "API keys",
          count: `${activeKeys.length} active${revokedKeys ? ` &middot; ${revokedKeys} revoked` : ""}`,
          rows: activeKeys.map(
            (k) =>
              `<tr><td>${escapeHtml(k.name)}</td><td>${parseScopes(k.scopes).map(escapeHtml).join(", ")}</td><td class="muted">${k.last_used_at ? `used ${escapeHtml(k.last_used_at.slice(0, 16).replace("T", " "))}` : "never used"}</td></tr>`
          ),
          empty: "No active API keys.",
          manage: "api-keys",
        })}
        ${summaryCard({
          title: "SCIM provisioning",
          count: `<span class="badge ${scimConfigured ? "badge-active" : "badge-disabled"}">${scimConfigured ? "Configured" : "Not configured"}</span>`,
          rows: scimConfigured
            ? [
                `<tr><td>Endpoint</td><td><code>${escapeHtml(scimHost)}</code></td></tr>`,
                `<tr><td>Scope</td><td>${scope.mode === "all" ? "All groups" : `${scope.groupIds.length} selected group${scope.groupIds.length === 1 ? "" : "s"}`}</td></tr>`,
              ]
            : [],
          empty: "Users and groups are not being pushed anywhere.",
          manage: "scim",
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
          <div class="row" style="justify-content:flex-start; gap:10px;">
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

admin.get("/admin/integrations/oidc", async (c) => {
  const { results: clients } = await c.env.DB.prepare("SELECT * FROM oauth_clients ORDER BY name").all<OAuthClientRow>();
  return c.html(
    layout(
      c,
      "OIDC clients",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        ${integrationIntro("The relying parties allowed to sign users in with this directory over OpenID Connect &mdash; Cloudflare Access, for example.", { href: "/admin/clients/new", label: "+ New client" })}
        ${
          clients.length === 0
            ? '<p class="muted">No clients registered yet.</p>'
            : `<table>
                <thead><tr><th>Name</th><th>Client ID</th><th>Redirect URIs</th></tr></thead>
                <tbody>
                  ${clients
                    .map(
                      (cl) =>
                        `<tr><td><a href="/admin/clients/${cl.id}">${escapeHtml(cl.name)}</a></td><td><code>${escapeHtml(cl.client_id)}</code></td><td>${JSON.parse(cl.redirect_uris).map(escapeHtml).join("<br/>")}</td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "OIDC clients" }]
    )
  );
});

admin.get("/admin/integrations/saml", async (c) => {
  const { results: sps } = await c.env.DB.prepare("SELECT * FROM saml_service_providers ORDER BY name").all<SamlServiceProviderRow>();
  return c.html(
    layout(
      c,
      "SAML apps",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        ${integrationIntro("Service providers allowed to sign users in over SAML 2.0 (SP-initiated, redirect binding). The IdP metadata they need is at <code>/saml/metadata</code>.", { href: "/admin/saml/new", label: "+ New service provider" })}
        ${
          sps.length === 0
            ? '<p class="muted">No service providers registered yet.</p>'
            : `<table>
                <thead><tr><th>Name</th><th>Entity ID</th><th>ACS URLs</th></tr></thead>
                <tbody>
                  ${sps
                    .map(
                      (sp) =>
                        `<tr><td><a href="/admin/saml/${sp.id}">${escapeHtml(sp.name)}</a></td><td><code>${escapeHtml(sp.entity_id)}</code></td><td>${JSON.parse(sp.acs_urls).map(escapeHtml).join("<br/>")}</td></tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "SAML apps" }]
    )
  );
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
                          <td>${k.last_used_at ? escapeHtml(k.last_used_at.slice(0, 19).replace("T", " ")) : '<span class="muted">never</span>'}</td>
                          <td style="white-space:nowrap;">
                            <a href="/admin/audit?${new URLSearchParams({ actor: "api", search: `api-key:${k.name}` }).toString()}">Activity</a>
                            ${
                              k.revoked_at
                                ? ""
                                : ` &middot; <form method="POST" action="/admin/api-keys/${k.id}/revoke" style="display:inline" ${confirmAttrs(
                                    `Anything using "${k.name}" stops working immediately. This cannot be undone.`,
                                    { title: "Revoke this API key?", action: "Revoke", danger: true }
                                  )}><button class="link-button" type="submit">Revoke</button></form>`
                            }
                          </td>
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

admin.get("/admin/integrations/scim", async (c) => {
  const config = await getScimConfig(c.env);
  const scope = await getScimScope(c.env);
  // The last SCIM events (syncs, failures, scope changes), newest last, as the log's starting content.
  const { results: scimEvents } = await c.env.DB.prepare(
    "SELECT at, actor_upn, action, target, details FROM audit_log WHERE action LIKE 'scim.%' ORDER BY id DESC LIMIT 15"
  ).all<{ at: string; actor_upn: string | null; action: string; target: string | null; details: string | null }>();
  const scimLog = scimEvents
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
  const { results: scopeGroups } = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all<GroupRow>();
  return c.html(
    layout(
      c,
      "SCIM provisioning",
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        ${integrationIntro("FlareID acts as a SCIM 2.0 <em>client</em>, pushing users and groups to a SCIM server &mdash; for example the endpoint and secret Cloudflare generates once you enable SCIM on this IdP's Access identity provider.")}
        <form method="POST" action="/admin/scim">
          <div class="field-row">
            <div>
              <label for="endpoint">SCIM endpoint (base URL)</label>
              <input type="text" id="endpoint" name="endpoint" value="${escapeHtml(config.endpoint)}" placeholder="https://api.cloudflare.com/client/v4/accounts/&lt;account_id&gt;/access/scim" />
            </div>
            <div>
              <label for="secret">SCIM secret</label>
              <input type="text" id="secret" name="secret" value="${escapeHtml(config.secret)}" placeholder="Bearer token from Cloudflare" />
            </div>
          </div>
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}

      <div class="two-col">
        ${cardSection(`
          <h2>Sync scope</h2>
          <p class="muted">Push everyone, or only members of specific groups. Users and groups outside scope are removed from the SCIM server if they had previously been synced.</p>
          <form method="POST" action="/admin/scim/scope">
            <label><input type="radio" name="mode" value="all" ${scope.mode === "all" ? "checked" : ""} data-hide="scim-scope-groups" style="width:auto; display:inline; margin-right:6px;" /> All groups</label>
            <label><input type="radio" name="mode" value="selected" ${scope.mode === "selected" ? "checked" : ""} data-show="scim-scope-groups" style="width:auto; display:inline; margin-right:6px;" /> Specific groups only</label>
            <div id="scim-scope-groups" style="display:${scope.mode === "selected" ? "block" : "none"}; margin-top:8px;">
              ${multiSelect(
                "group_ids",
                scopeGroups.map((g) => ({ id: g.id, label: g.name })),
                new Set(scope.groupIds),
                "Search groups..."
              )}
            </div>
            <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save scope</button></div>
          </form>
        `)}
        ${cardSection(`
          <h2>Test &amp; sync</h2>
          <p class="muted">Test the connection, then push every in-scope user and group. New and changed users and groups are pushed automatically from then on.</p>
          <div class="row" style="justify-content:flex-start; gap:10px;">
            <button class="secondary" type="button" id="scim-test-btn" data-scim="test">Test connection</button>
            <button class="primary" type="button" id="scim-sync-btn" data-scim="sync">Sync all now</button>
          </div>
          <div id="scim-status"></div>
          <h3 style="margin-top:18px;">Sync log</h3>
          <pre id="scim-log" class="import-log">${escapeHtml(scimLog || "No syncs yet.")}</pre>
        `)}
      </div>

      ${scriptTag(SCIM_SCRIPT)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, { label: "SCIM provisioning" }]
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
  if (!name) return c.text("name is required", 400);

  const requested = readPermissionMatrix(body);
  // Same rule as roles: a key carries only permissions its creator holds ("*" only from a Super Admin).
  const mine = c.get("access");
  const beyond = requested.filter((p) => (p === "*" ? !mine.isSuper : !grants(mine.perms, p)));
  if (beyond.length) return c.text(`You cannot give a key permissions you do not hold: ${beyond.join(", ")}.`, 403);
  // Choosing nothing used to mint an admin key. It now asks again.
  if (requested.length === 0) return c.text("Choose at least one permission for the key.", 400);
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

admin.post("/admin/api-keys/:id/revoke", async (c) => {
  await revokeKey(consoleCtx(c), Number(c.req.param("id")));
  return c.redirect("/admin/integrations/api-keys?saved=1", 302);
});

/** The v3 client settings, shared by the new and edit forms. */
function clientSettingsFields(client?: OAuthClientRow): string {
  const allowed = new Set(client ? parseAllowedClaims(client) : CLAIM_GROUPS);
  const logoutUris: string[] = client ? JSON.parse(client.post_logout_redirect_uris || "[]") : [];
  const trusted = client ? client.trusted === 1 : true;
  const alg = client?.id_token_signed_response_alg ?? "RS256";
  return `
    <label for="id_token_signed_response_alg">ID token signing algorithm</label>
    <select id="id_token_signed_response_alg" name="id_token_signed_response_alg">
      ${ID_TOKEN_ALGS.map((a) => `<option value="${a}" ${a === alg ? "selected" : ""}>${a}${a === "RS256" ? " (default)" : ""}</option>`).join("")}
    </select>
    <p class="muted" style="margin-top:-8px;">How this app's id_tokens are signed. RS256 works with every OIDC library; choose ES256 only if the app supports it. Keys are under Security &rarr; Signing keys.</p>
    <label for="post_logout_redirect_uris">Post-logout redirect URIs (one per line)</label>
    <textarea id="post_logout_redirect_uris" name="post_logout_redirect_uris" rows="2" placeholder="https://app.example.com/signed-out">${escapeHtml(logoutUris.join("\n"))}</textarea>
    <p class="muted" style="margin-top:-8px;">Where RP-initiated logout (<code>/oidc/logout</code>) may send the browser afterwards. Anything else is refused.</p>
    <label for="frontchannel_logout_uri">Front-channel logout URI</label>
    <input type="text" id="frontchannel_logout_uri" name="frontchannel_logout_uri" value="${escapeHtml(client?.frontchannel_logout_uri ?? "")}" placeholder="https://app.example.com/logout/frontchannel" />
    <p class="muted" style="margin-top:-8px;">Loaded in a hidden frame (with <code>iss</code> and <code>sid</code>) when the user signs out of FlareID, so the app can end its own session. https only.</p>
    <label style="font-weight:400; margin-top:8px;"><input type="checkbox" name="trusted" value="1" ${trusted ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Trusted first-party app &mdash; skip the consent screen</label>
    <label style="margin-top:12px;">Claims this app may receive</label>
    <p class="muted" style="margin-top:-6px;">Released only when the app also asks for them by scope (<code>email</code>, <code>profile</code>, <code>groups</code>). Untick anything it does not need.</p>
    ${CLAIM_GROUPS.map((g) => `<label style="font-weight:400;"><input type="checkbox" name="allowed_claims" value="${g}" ${allowed.has(g) ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> ${escapeHtml(CLAIM_GROUP_LABELS[g])}</label>`).join("")}`;
}

function readClientSettings(body: Record<string, string | File | (string | File)[]>) {
  const list = (v: unknown) => (Array.isArray(v) ? v : v ? [v] : []).map(String);
  return {
    trusted: body.trusted ? 1 : 0,
    allowedClaims: JSON.stringify(CLAIM_GROUPS.filter((g) => list(body.allowed_claims).includes(g))),
    // Unusable entries are dropped rather than stored: /oidc/logout follows only exact, valid matches.
    postLogoutRedirectUris: JSON.stringify(
      String(body.post_logout_redirect_uris ?? "")
        .split("\n")
        .map((s) => s.trim())
        .filter((u) => u && isValidPostLogoutUri(u))
    ),
    frontchannelLogoutUri: validFrontchannelUri(String(body.frontchannel_logout_uri ?? "").trim()),
    // Anything unrecognised falls back to the default rather than being stored.
    idTokenAlg: isIdTokenAlg(body.id_token_signed_response_alg) ? body.id_token_signed_response_alg : ("RS256" as const),
  };
}

// validFrontchannelUri lives in services/clients.ts (re-exported above).

admin.get("/admin/clients/new", async (c) => {
  return c.html(
    layout(
      c,
      "New OIDC client",
      cardSection(`
        <form method="POST" action="/admin/clients">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" placeholder="Cloudflare Access" required />
          <label for="redirect_uris">Redirect URIs (one per line)</label>
          <textarea id="redirect_uris" name="redirect_uris" rows="3" placeholder="https://your-team.cloudflareaccess.com/cdn-cgi/access/callback"></textarea>
          <label>Client type</label>
          <label style="font-weight:400;"><input type="radio" name="client_type" value="confidential" checked style="width:auto; display:inline; margin-right:6px;" /> Confidential &mdash; a server that can keep a secret (Cloudflare Access, a web backend)</label>
          <label style="font-weight:400;"><input type="radio" name="client_type" value="public" style="width:auto; display:inline; margin-right:6px;" /> Public &mdash; a single-page or native app: no secret, PKCE required, loopback redirects on any port</label>
          ${clientSettingsFields()}
          <div class="form-actions end">${cancelLink("/admin/integrations/oidc")}<button class="primary" type="submit">Create client</button></div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("oidc"), { label: "New client" }]
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
  if (!name) return c.text("name is required", 400);

  // Seeded credentials, for provisioning that has to know them in advance.
  //
  // A lab provisions Cloudflare Access with Terraform, which needs this client's
  // id and secret to create the Access identity provider - but Terraform cannot
  // read a value out of an app it has not deployed yet. So it generates the
  // credential, passes it in here, and the identity provider is correct on the
  // first apply with nothing having to flow back.
  //
  // No new privilege: this route is already admin-only and an admin can read a
  // generated secret anyway, so choosing one instead grants nothing. Both fields
  // must be present together and the secret has a floor, so a partial or
  // trivially short value falls back to a generated one rather than quietly
  // creating a weak client.
  const seededId = String(body.client_id ?? "").trim();
  const seededSecret = String(body.client_secret ?? "").trim();
  const seeded = seededId !== "" && seededSecret.length >= 24;

  const clientId = seeded ? seededId : `flareid_${randomToken(8)}`;
  // A public client has no secret at all - an empty hash never matches.
  const clientSecret = isPublic ? "" : seeded ? seededSecret : randomToken(24);
  const clientSecretHash = isPublic ? "" : await sha256Hex(clientSecret);

  const result = await c.env.DB.prepare(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, client_type, trusted, allowed_claims, post_logout_redirect_uris)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(clientId, clientSecretHash, name, JSON.stringify(redirectUris), new Date().toISOString(), isPublic ? "public" : "confidential", settings.trusted, settings.allowedClaims, settings.postLogoutRedirectUris)
    .run();
  await c.env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ?, id_token_signed_response_alg = ? WHERE client_id = ?").bind(settings.frontchannelLogoutUri, settings.idTokenAlg, clientId).run();

  await logAudit(c.env, c.get("user"), "oidc_client.created", name, undefined, c.req.raw);

  return c.html(
    layout(
      c,
      "Client created",
      cardSection(`
        <p class="success">Created "${escapeHtml(name)}"${isPublic ? " as a public client: it has no secret, and must use PKCE (S256)" : ""}.</p>
        ${isPublic ? "" : secretBlock("Client secret", clientSecret)}
        ${oidcEndpointsBlock(c.env, clientId)}
        <a href="/admin/clients/${result.meta.last_row_id}"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("oidc"), { label: "Client created" }]
    )
  );
});

admin.get("/admin/clients/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await c.env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(id).first<OAuthClientRow>();
  if (!client) return c.text("Not found", 404);

  return c.html(
    layout(
      c,
      client.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        ${oidcEndpointsBlock(c.env, client.client_id)}
        <form method="POST" action="/admin/clients/${id}">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" value="${escapeHtml(client.name)}" required />
          <label for="redirect_uris">Redirect URIs (one per line)</label>
          <textarea id="redirect_uris" name="redirect_uris" rows="3">${escapeHtml(JSON.parse(client.redirect_uris).join("\n"))}</textarea>
          <p class="muted" style="margin-top:-8px;">Type: <strong>${client.client_type === "public" ? "Public (no secret, PKCE required)" : "Confidential"}</strong></p>
          ${clientSettingsFields(client)}
          <div class="form-actions end">${cancelLink(`/admin/clients/${id}`)}<button class="primary" type="submit">Save</button></div>
        </form>
        <div class="row" style="justify-content:flex-start; gap:10px; margin-top:8px;">
          ${
            client.client_type === "public"
              ? ""
              : `<form method="POST" action="/admin/clients/${id}/rotate-secret">
            <button class="secondary" type="submit">Rotate secret</button>
          </form>`
          }
          <form method="POST" action="/admin/clients/${id}/delete" ${confirmAttrs(`Anything still using this client_id will stop working immediately.`, { title: `Delete the OIDC client "${client.name}"?`, action: "Delete client", danger: true })}>
            <button class="danger" type="submit">Delete client</button>
          </form>
        </div>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("oidc"), { label: client.name }]
    )
  );
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
  if (!client) return c.text("Not found", 404);
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
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("oidc"), { label: client.name, href: `/admin/clients/${id}` }, { label: "Secret rotated" }]
    )
  );
});

admin.post("/admin/clients/:id/delete", async (c) => {
  const client = await getClientById(c.env, Number(c.req.param("id")));
  if (!client) return c.text("Not found", 404);
  await deleteClient(consoleCtx(c), client);
  return c.redirect("/admin/integrations/oidc?saved=1", 302);
});

// ---------- SAML service providers ----------

/** What an SP administrator needs to point their service provider at this IdP. */
function samlIdpBlock(env: Env) {
  const entityId = idpEntityId(env);
  const expiry = env.SAML_SIGNING_CERT ? certNotAfter(env.SAML_SIGNING_CERT) : null;
  const expiryNote = expiry
    ? expiry.getTime() < Date.now()
      ? ` - <strong style="color:var(--fi-red);">expired ${escapeHtml(expiry.toISOString().slice(0, 10))}</strong>`
      : expiry.getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000
        ? ` - <strong style="color:var(--fi-amber);">expires ${escapeHtml(expiry.toISOString().slice(0, 10))}</strong>`
        : ` - expires ${escapeHtml(expiry.toISOString().slice(0, 10))}`
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
function parseCertsInput(input: string): { certs: string[]; invalid: boolean } {
  const blocks = input.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) {
    if (!input.trim()) return { certs: [], invalid: false };
    const single = normalizeCertPem(input);
    return { certs: single ? [single] : [], invalid: !single };
  }
  const certs: string[] = [];
  let invalid = false;
  for (const block of blocks) {
    const pem = normalizeCertPem(block);
    if (pem) certs.push(pem);
    else invalid = true;
  }
  return { certs, invalid };
}

interface SpFormValues {
  name: string;
  entityId: string;
  acsUrls: string[];
  defaultAcsUrl: string;
  nameidFormat: string;
  attributeMap: Record<string, string>;
  signResponse: boolean;
  signAssertion: boolean;
  wantSigned: boolean;
  signingCerts: string[];
  sloUrl: string;
  encryptionCert: string;
  subjectId: string;
  encryptAssertions: boolean;
}

/** Parses and validates the new/edit SP form. Returns the values, or a message for the admin. */
function parseSpForm(body: Record<string, unknown>): SpFormValues | string {
  const name = String(body.name ?? "").trim();
  const entityId = String(body.entity_id ?? "").trim();
  if (!name || !entityId) return "name and entity_id are required.";

  const acsUrls = String(body.acs_urls ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (acsUrls.length === 0) return "At least one ACS URL is required.";
  const defaultAcsUrl = String(body.default_acs_url ?? "").trim();

  const nameidFormat = String(body.nameid_format ?? "transient");
  if (!nameIdFormatUri(nameidFormat)) return `Unsupported NameID format "${nameidFormat}".`;

  let attributeMap: Record<string, string> = {};
  const rawMap = String(body.attribute_map ?? "").trim();
  if (rawMap) {
    try {
      const parsed = JSON.parse(rawMap);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error();
      attributeMap = parsed as Record<string, string>;
      for (const [k, v] of Object.entries(attributeMap)) {
        if (!USER_ATTRIBUTE_FIELDS.includes(v as (typeof USER_ATTRIBUTE_FIELDS)[number])) {
          return `"${v}" is not a user attribute field. Valid fields: ${USER_ATTRIBUTE_FIELDS.join(", ")}.`;
        }
      }
    } catch (e) {
      if (typeof e === "string") return e;
      return "attribute_map must be a JSON object of {\"saml-attribute-name\": \"field\"}.";
    }
  }

  const { certs, invalid } = parseCertsInput(String(body.signing_certs ?? ""));
  if (invalid) return "One of the pasted certificates could not be parsed.";
  if (body.want_authn_requests_signed && certs.length === 0) {
    return "Requiring signed requests needs at least one SP signing certificate.";
  }

  const sloUrl = String(body.slo_url ?? "").trim();
  if (sloUrl && !/^https:\/\//.test(sloUrl)) return "The Single Logout URL must be https.";
  const rawEnc = String(body.encryption_cert ?? "").trim();
  const encryptionCert = rawEnc ? normalizeCertPem(rawEnc) : "";
  if (rawEnc && !encryptionCert) return "The encryption certificate could not be parsed.";
  if (body.encrypt_assertions && !encryptionCert) return "Encrypting assertions needs the SP's encryption certificate.";

  return {
    name,
    entityId,
    acsUrls,
    defaultAcsUrl,
    nameidFormat,
    attributeMap,
    signResponse: !!body.sign_response,
    signAssertion: !!body.sign_assertion,
    wantSigned: !!body.want_authn_requests_signed,
    signingCerts: certs,
    sloUrl,
    encryptionCert: encryptionCert ?? "",
    encryptAssertions: !!body.encrypt_assertions,
    subjectId: ["subject-id", "pairwise-id"].includes(String(body.subject_id)) ? String(body.subject_id) : "",
  };
}

function spForm(v: Partial<SpFormValues>, action: string, submitLabel: string): string {
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
      <label for="acs_urls">Assertion Consumer Service URLs (one per line)</label>
      <textarea id="acs_urls" name="acs_urls" rows="3" placeholder="https://your-team.cloudflareaccess.com/cdn-cgi/access/callback">${escapeHtml((v.acsUrls ?? []).join("\n"))}</textarea>
      <label for="default_acs_url">Default ACS URL (used when the request omits one)</label>
      <input type="text" id="default_acs_url" name="default_acs_url" value="${escapeHtml(v.defaultAcsUrl ?? "")}" />
      <label for="nameid_format">NameID format</label>
      <select id="nameid_format" name="nameid_format">
        ${supportedNameIdFormats()
          .map((f) => `<option value="${f}" ${(v.nameidFormat ?? "transient") === f ? "selected" : ""}>${f}</option>`)
          .join("")}
      </select>
      <label for="attribute_map">Attribute map (JSON - leave empty for the default email/name/groups map)</label>
      <textarea id="attribute_map" name="attribute_map" rows="4" placeholder='{"email": "email", "department": "department"}'>${escapeHtml(Object.keys(v.attributeMap ?? {}).length ? JSON.stringify(v.attributeMap, null, 2) : "")}</textarea>
      <p class="muted" style="margin:-8px 0 14px;">Field names: <code>${USER_ATTRIBUTE_FIELDS.join("</code>, <code>")}</code></p>
      <label for="signing_certs">SP signing certificates (PEM, one or more - leave empty if requests are unsigned)</label>
      <textarea id="signing_certs" name="signing_certs" rows="6" placeholder="-----BEGIN CERTIFICATE-----">${escapeHtml((v.signingCerts ?? []).join("\n"))}</textarea>
      <label style="font-weight:400;"><input type="checkbox" name="sign_response" value="1" ${v.signResponse !== false ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Sign the Response</label>
      <label style="font-weight:400;"><input type="checkbox" name="sign_assertion" value="1" ${v.signAssertion !== false ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Sign the Assertion</label>
      <label style="font-weight:400;"><input type="checkbox" name="want_authn_requests_signed" value="1" ${v.wantSigned ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require signed AuthnRequests from this SP</label>
      <label for="slo_url" style="margin-top:12px;">Single Logout URL (HTTP-Redirect; leave empty to turn SLO off)</label>
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
      <div class="form-actions end">${cancelLink("/admin/integrations/saml")}<button class="primary" type="submit">${escapeHtml(submitLabel)}</button></div>
    </form>`;
}

admin.get("/admin/saml/new", async (c) => {
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
      ${cardSection(`<h2>Or enter it by hand</h2>${spForm({}, "/admin/saml", "Create service provider")}`)}`,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("saml"), { label: "New service provider" }]
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
    if (e instanceof SpMetadataError) return c.text(e.message, 400);
    throw e;
  }
});

admin.post("/admin/saml", async (c) => {
  const v = parseSpForm(await c.req.parseBody());
  if (typeof v === "string") return c.text(v, 400);

  const now = new Date().toISOString();
  const result = await c.env.DB.prepare(
    `INSERT INTO saml_service_providers (entity_id, name, acs_urls, default_acs_url, nameid_format, attribute_map, sign_response, sign_assertion, want_authn_requests_signed, signing_certs, slo_url, encryption_cert, encrypt_assertions, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(v.entityId, v.name, JSON.stringify(v.acsUrls), v.defaultAcsUrl || null, v.nameidFormat, JSON.stringify(v.attributeMap), v.signResponse ? 1 : 0, v.signAssertion ? 1 : 0, v.wantSigned ? 1 : 0, JSON.stringify(v.signingCerts), v.sloUrl || null, v.encryptionCert || null, v.encryptAssertions ? 1 : 0, now, now)
    .run();

  await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE id = ?").bind(v.subjectId, result.meta.last_row_id).run();
  await logAudit(c.env, c.get("user"), "saml_sp.created", v.name, { entity_id: v.entityId }, c.req.raw);
  return c.redirect(`/admin/saml/${result.meta.last_row_id}`, 302);
});

admin.get("/admin/saml/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return c.text("Not found", 404);

  return c.html(
    layout(
      c,
      sp.name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
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
            signResponse: !!sp.sign_response,
            signAssertion: !!sp.sign_assertion,
            wantSigned: !!sp.want_authn_requests_signed,
            signingCerts: JSON.parse(sp.signing_certs),
            sloUrl: sp.slo_url ?? "",
            encryptionCert: sp.encryption_cert ?? "",
            subjectId: sp.subject_id ?? "",
            encryptAssertions: !!sp.encrypt_assertions,
          },
          `/admin/saml/${id}`,
          "Save"
        )}
        <div class="row" style="justify-content:flex-start; gap:10px; margin-top:8px;">
          <form method="POST" action="/admin/saml/${id}/delete" ${confirmAttrs(`Users will no longer be able to sign in to this service provider.`, { title: `Delete "${sp.name}"?`, action: "Delete", danger: true })}>
            <button class="danger" type="submit">Delete service provider</button>
          </form>
        </div>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, INTEGRATIONS_CRUMB, integrationCrumb("saml"), { label: sp.name }]
    )
  );
});

admin.post("/admin/saml/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return c.text("Not found", 404);

  const v = parseSpForm(await c.req.parseBody());
  if (typeof v === "string") return c.text(v, 400);

  await c.env.DB.prepare(
    `UPDATE saml_service_providers SET entity_id = ?, name = ?, acs_urls = ?, default_acs_url = ?, nameid_format = ?, attribute_map = ?, sign_response = ?, sign_assertion = ?, want_authn_requests_signed = ?, signing_certs = ?, slo_url = ?, encryption_cert = ?, encrypt_assertions = ?, updated_at = ? WHERE id = ?`
  )
    .bind(v.entityId, v.name, JSON.stringify(v.acsUrls), v.defaultAcsUrl || null, v.nameidFormat, JSON.stringify(v.attributeMap), v.signResponse ? 1 : 0, v.signAssertion ? 1 : 0, v.wantSigned ? 1 : 0, JSON.stringify(v.signingCerts), v.sloUrl || null, v.encryptionCert || null, v.encryptAssertions ? 1 : 0, new Date().toISOString(), id)
    .run();

  await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE id = ?").bind(v.subjectId, id).run();
  await logAudit(c.env, c.get("user"), "saml_sp.updated", v.name, { entity_id: v.entityId }, c.req.raw);
  return c.redirect(`/admin/saml/${id}?saved=1`, 302);
});

admin.post("/admin/saml/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return c.text("Not found", 404);

  await c.env.DB.prepare("DELETE FROM saml_service_providers WHERE id = ?").bind(id).run();
  await logAudit(c.env, c.get("user"), "saml_sp.deleted", sp.name, { entity_id: sp.entity_id }, c.req.raw);
  return c.redirect("/admin/integrations/saml?saved=1", 302);
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
    <button type="button" class="secondary" data-remove-closest=".attr-row" aria-label="Remove attribute">&times;</button>
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
                <td style="text-align:right;">${rowMenu(`<a href="/admin/schemas/${s.id}">Edit</a>`)}</td>
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
  if (!name) return c.text("name is required", 400);
  if (await findSchema(c.env, objectType, name)) return c.text(`A ${objectType} schema named "${name}" already exists.`, 409);

  const id = await createSchema(c.env, objectType, name, description);
  await logAudit(c.env, c.get("user"), "schema.created", `${objectType}:${name}`, undefined, c.req.raw);
  return c.redirect(`/admin/schemas/${id}`, 302);
});

admin.get("/admin/schemas/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return c.text("Not found", 404);
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
  if (!schema) return c.text("Not found", 404);
  const body = await c.req.parseBody({ all: true });
  const name = String(body.name ?? "").trim();
  const description = String(body.description ?? "").trim();
  if (!name) return c.text("name is required", 400);

  const clash = await c.env.DB.prepare("SELECT id FROM schemas WHERE object_type = ? AND name = ? AND id != ?").bind(schema.object_type, name, id).first();
  if (clash) return c.text(`A ${schema.object_type} schema named "${name}" already exists.`, 409);

  let attributes: AttributeInput[];
  try {
    attributes = readAttributeRows(body);
  } catch (e) {
    return c.text(e instanceof Error ? e.message : "Invalid attributes.", 400);
  }

  try {
    // Checked before anything is written: a refused permission changes nothing.
    await saveSchemaAttributes(c.env, id, attributes);
  } catch (e) {
    if (e instanceof RangeError) return c.text(e.message, 400);
    throw e;
  }
  await c.env.DB.prepare("UPDATE schemas SET name = ?, description = ? WHERE id = ?").bind(name, description || null, id).run();
  await logAudit(c.env, c.get("user"), "schema.updated", `${schema.object_type}:${name}`, { attributes: attributes.length }, c.req.raw);
  return c.redirect(`/admin/schemas/${id}?saved=1`, 302);
});

admin.post("/admin/schemas/:id/apply", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return c.text("Not found", 404);
  const count = await applySchemaToAll(c.env, schema);
  await logAudit(c.env, c.get("user"), "schema.applied", `${schema.object_type}:${schema.name}`, { count }, c.req.raw);
  return c.redirect(`/admin/schemas/${id}?saved=1`, 302);
});

admin.post("/admin/schemas/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return c.text("Not found", 404);
  if (schema.builtin) return c.text("Provided schemas cannot be deleted - remove their attributes instead.", 400);

  const fallback = await getSchema(c.env, Number(await defaultSchemaId(c.env, schema.object_type)));
  if (fallback) await applySchemaToAll(c.env, fallback, id);
  await c.env.DB.prepare("DELETE FROM schemas WHERE id = ?").bind(id).run();
  await logAudit(c.env, c.get("user"), "schema.deleted", `${schema.object_type}:${schema.name}`, undefined, c.req.raw);
  return c.redirect("/admin/schemas?saved=1", 302);
});

// ---------- Domains ----------

admin.get("/admin/domains", async (c) => {
  const domains = await listDomains(c.env);
  return c.html(
    layout(
      c,
      "Domains",
      `
            ${c.req.query("saved") ? successBanner("Saved.") : ""}
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
          <thead><tr><th>Domain</th><th>Default</th><th></th></tr></thead>
          <tbody>
            ${domains
              .map(
                (d) => `<tr>
                  <td>${escapeHtml(d.domain)}</td>
                  <td>${d.is_default ? '<span class="badge badge-active">Default</span>' : ""}</td>
                  <td>
                    ${!d.is_default ? `<form method="POST" action="/admin/domains/${d.id}/set-default" style="display:inline;"><button class="link-button" type="submit">Make default</button></form> · ` : ""}
                    <form method="POST" action="/admin/domains/${d.id}/apply-to-all" style="display:inline;" ${confirmAttrs(`Every user's UPN domain becomes ${d.domain}. Usernames are kept.`, { title: "Change the domain on every account?", action: "Apply to all" })}>
                      <button class="link-button" type="submit">Apply to all users</button>
                    </form> ·
                    <form method="POST" action="/admin/domains/${d.id}/delete" style="display:inline;">
                      <button class="link-button" type="submit">Delete</button>
                    </form>
                  </td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
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
    await addDomain(c.env, domain);
    await logAudit(c.env, c.get("user"), "domain.added", domain, undefined, c.req.raw);
  }
  return c.redirect("/admin/domains?saved=1", 302);
});

admin.post("/admin/domains/:id/set-default", async (c) => {
  const id = Number(c.req.param("id"));
  await setDefaultDomain(c.env, id);
  await logAudit(c.env, c.get("user"), "domain.set_default", String(id), undefined, c.req.raw);
  return c.redirect("/admin/domains", 302);
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

  return c.html(
    layout(
      c,
      "Security",
      `
            ${c.req.query("saved") ? successBanner("Saved.") : ""}
      <div class="two-col security-grid">
      ${cardSection(`
        <h2>Default password</h2>
        <p class="muted">Used for newly created accounts and available to bulk-apply to every existing account.</p>
        <form method="POST" action="/admin/security/default-password">
          <input type="text" name="default_password" value="${escapeHtml(defaultPassword)}" required />
          <div class="row" style="justify-content:flex-start; gap:10px;">
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
          <div class="row" style="justify-content:flex-start; margin-top:12px;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Password complexity policy</h2>
        <p class="muted">Enforced on self-service password changes and randomly generated account passwords.</p>
        <form method="POST" action="/admin/security/password-policy">
          <label for="minLength">Minimum length</label>
          <input type="number" id="minLength" name="minLength" min="4" max="64" value="${policy.minLength}" style="max-width:120px;" />
          <label><input type="checkbox" name="requireUppercase" value="1" ${policy.requireUppercase ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require uppercase letter</label>
          <label><input type="checkbox" name="requireLowercase" value="1" ${policy.requireLowercase ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require lowercase letter</label>
          <label><input type="checkbox" name="requireNumber" value="1" ${policy.requireNumber ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require number</label>
          <label><input type="checkbox" name="requireSymbol" value="1" ${policy.requireSymbol ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require symbol</label>
          <div class="row" style="justify-content:flex-start; margin-top:12px;"><button class="primary" type="submit">Save policy</button></div>
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
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
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
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Audit log retention</h2>
        <p class="muted">Entries older than this are deleted by the hourly cleanup, along with expired codes, tokens, sessions and remembered devices. ${AUDIT_RETENTION_MIN_DAYS}-${AUDIT_RETENTION_MAX_DAYS} days.</p>
        <form method="POST" action="/admin/security/audit-retention">
          <label for="audit_retention_days">Keep audit entries for (days)</label>
          <input type="number" id="audit_retention_days" name="days" min="${AUDIT_RETENTION_MIN_DAYS}" max="${AUDIT_RETENTION_MAX_DAYS}" value="${auditRetentionDays}" style="max-width:160px;" />
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      </div>
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Security" }]
    )
  );
});

admin.post("/admin/security/default-password", async (c) => {
  await saveDefaultPassword(consoleCtx(c), String((await c.req.parseBody()).default_password ?? ""));
  return c.redirect("/admin/security?saved=1", 302);
});

// ---------- Branding (app name, sign-in message, login page appearance) ----------

admin.get("/admin/branding", async (c) => {
  const loginGradient = await getLoginGradient(c.env);
  const loginSubtitle = await getLoginSubtitle(c.env);
  const cursorTrail = await getCursorTrail(c.env);
  const appName = c.get("appName");

  return c.html(
    layout(
      c,
      "Branding",
      `
            ${c.req.query("saved") ? successBanner("Saved.") : ""}
      <div class="two-col security-grid">
      ${cardSection(`
        <h2>Branding</h2>
        <p class="muted">The display name shown in the nav, page titles, and on the sign-in page.</p>
        <form method="POST" action="/admin/branding/app-name">
          <label for="app_name">App name</label>
          <input type="text" id="app_name" name="app_name" value="${escapeHtml(appName)}" required maxlength="60" />
          <label for="login_subtitle">Sign-in page message</label>
          <input type="text" id="login_subtitle" name="login_subtitle" value="${escapeHtml(loginSubtitle)}" maxlength="140" placeholder="Use your company account to continue." />
          <p class="muted" style="margin-top:-8px;">Shown under the logo on the sign-in page. Leave empty for no message.</p>
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Login page appearance</h2>
        <p class="muted">The background gradient shown behind the sign-in and MFA cards.</p>
        <form method="POST" action="/admin/branding/login-gradient">
          <div class="field-row" style="max-width:320px;">
            <div>
              <label for="gradient_from">Gradient start</label>
              <input type="color" id="gradient_from" name="from" value="${escapeHtml(loginGradient.from)}" style="height:42px; padding:4px; cursor:pointer; margin-bottom:0;" />
            </div>
            <div>
              <label for="gradient_to">Gradient end</label>
              <input type="color" id="gradient_to" name="to" value="${escapeHtml(loginGradient.to)}" style="height:42px; padding:4px; cursor:pointer; margin-bottom:0;" />
            </div>
          </div>
          <label style="margin-top:24px;">Preview</label>
          <div style="height:60px; border-radius:10px; margin-bottom:20px; background: linear-gradient(45deg, ${escapeHtml(loginGradient.from)}, ${escapeHtml(loginGradient.to)});"></div>
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Cursor trail</h2>
        <p class="muted">Faint characters that drift away from the pointer on the sign-in and two-step pages. Purely decorative, and never shown on touch screens.</p>
        <form method="POST" action="/admin/branding/cursor-trail">
          <label style="font-weight:400;"><input type="checkbox" name="enabled" value="1" ${cursorTrail.enabled ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Show the cursor trail</label>
          <label for="cursor_characters" style="margin-top:12px;">Characters</label>
          <input type="text" id="cursor_characters" name="characters" value="${escapeHtml(cursorTrail.characters)}" maxlength="${CURSOR_TRAIL_MAX_CHARACTERS}" placeholder="Leave empty for the default symbols, e.g. { } &lt; /&gt; &#955;" />
          <p class="muted" style="margin-top:-8px;">Shown one character at a time, in order &mdash; enter your company name and it spells itself out. Spaces are skipped. Empty uses a random mix of code symbols.</p>
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${cardSection(`
        <h2>Email templates</h2>
        <p class="muted">The wording of the invitation, password reset and sign-in code emails, and the accent colour they share.</p>
        <a href="/admin/branding/email-templates"><button class="secondary" type="button">Edit email templates</button></a>
      `)}
      </div>
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

admin.post("/admin/branding/cursor-trail", async (c) => {
  const body = await c.req.parseBody();
  await saveCursorTrail(consoleCtx(c), { enabled: !!body.enabled, characters: String(body.characters ?? "") });
  return c.redirect("/admin/branding?saved=1", 302);
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
function emailPreview(appName: string, key: TemplateKey, t: EmailTemplate, accent: string): string {
  const vars: Record<string, string> = { app_name: appName, name: "Ada Lovelace", ...(key === "email_otp" ? { code: "428 913", minutes: "10" } : {}) };
  const link = TEMPLATE_INFO[key].hasLink ? `https://example.com/${key === "invitation" ? "invite" : "reset-password"}/sample-link` : undefined;
  const r = renderEmail(t, accent, vars, link);
  const m = /<body style="([^"]*)">([\s\S]*)<\/body>/.exec(r.html);
  return `
    <label>Subject</label>
    <p style="margin:0 0 16px; font-weight:600;">${escapeHtml(r.subject)}</p>
    <label>HTML</label>
    <div style="${m?.[1] ?? ""} border:1px solid var(--fi-line); border-radius:10px; margin-bottom:16px;">${m?.[2] ?? ""}</div>
    <label>Plain text</label>
    <pre style="white-space:pre-wrap; word-break:break-word; margin:0; padding:12px; border:1px solid var(--fi-line); border-radius:10px; background:var(--fi-surface-2); color:var(--fi-body); font-size:0.8125rem;">${escapeHtml(r.text)}</pre>`;
}

// Re-renders the preview as the form changes: the server renders it (one
// implementation), the page swaps it in. Without script, "Preview" does the same.
const EMAIL_PREVIEW_SCRIPT = `(function(){
  var form = document.getElementById("email-template-form");
  var out = document.getElementById("email-preview");
  var accent = document.getElementById("email_accent");
  if (!form || !out) return;
  var timer = null, seq = 0;
  function refresh() {
    var q = new URLSearchParams(new FormData(form));
    if (accent) q.set("accent", accent.value);
    var n = ++seq;
    fetch("/admin/branding/email-templates/preview?" + q.toString(), { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (h) { if (h !== null && n === seq) out.innerHTML = h; })
      .catch(function () {});
  }
  function later() { clearTimeout(timer); timer = setTimeout(refresh, 250); }
  form.addEventListener("input", later);
  if (accent) accent.addEventListener("input", later);
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
          <p class="muted" style="margin-bottom:6px;">Placeholders:</p>
          <ul class="muted" style="margin:0 0 16px; padding-left:18px;">
            ${info.placeholders.map((p) => `<li><code>{{${escapeHtml(p)}}}</code> ${escapeHtml(PLACEHOLDER_HELP[p] ?? "")}</li>`).join("")}
          </ul>
          <div class="row" style="justify-content:flex-start; gap:8px;">
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
        <div id="email-preview">${emailPreview(c.get("appName"), key, t, accent)}</div>
      `)}
      </div>
      ${cardSection(`
        <h2>Accent colour</h2>
        <p class="muted">The top border, button and link colour of every email.</p>
        <form method="POST" action="/admin/branding/email-accent">
          <input type="hidden" name="t" value="${key}" />
          <label for="email_accent">Accent colour</label>
          <input type="color" id="email_accent" name="accent" value="${escapeHtml(accent)}" style="height:42px; max-width:120px; padding:4px; cursor:pointer;" />
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Save</button></div>
        </form>
      `)}
      ${scriptTag(EMAIL_PREVIEW_SCRIPT)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Branding", href: "/admin/branding" }, { label: "Email templates" }]
    )
  );
});

/** The preview alone, for the editor's live refresh. Never saves anything. */
admin.get("/admin/branding/email-templates/preview", async (c) => {
  const q = c.req.query();
  if (!isTemplateKey(q.t)) return c.text("No such template.", 404);
  const accent = q.accent && isHexColor(q.accent) ? q.accent.toLowerCase() : await getAccent(c.env);
  return c.html(emailPreview(c.get("appName"), q.t, templateFromInput(q, await getTemplate(c.env, q.t)), accent));
});

admin.post("/admin/branding/email-templates/:key", async (c) => {
  const key = c.req.param("key");
  if (!isTemplateKey(key)) return c.text("No such template.", 404);
  const body = await c.req.parseBody();
  const t: Partial<EmailTemplate> = {};
  for (const f of TEMPLATE_FIELDS) if (typeof body[f] === "string") t[f] = body[f] as string;
  try {
    await saveEmailTemplate(consoleCtx(c), key, t);
  } catch (e) {
    if (!(e instanceof ServiceError)) throw e;
    return c.redirect(`/admin/branding/email-templates?t=${key}&error=${encodeURIComponent(e.message)}`, 302);
  }
  return c.redirect(`/admin/branding/email-templates?t=${key}&saved=1`, 302);
});

admin.post("/admin/branding/email-templates/:key/reset", async (c) => {
  const key = c.req.param("key");
  if (!isTemplateKey(key)) return c.text("No such template.", 404);
  await saveEmailTemplate(consoleCtx(c), key, null);
  return c.redirect(`/admin/branding/email-templates?t=${key}&saved=reset`, 302);
});

admin.post("/admin/branding/email-accent", async (c) => {
  const body = await c.req.parseBody();
  const key = isTemplateKey(String(body.t ?? "")) ? String(body.t) : "invitation";
  // Refused (400) unless #rrggbb; the colour picker never sends anything else.
  await saveEmailAccent(consoleCtx(c), String(body.accent ?? "").trim());
  return c.redirect(`/admin/branding/email-templates?t=${key}&saved=1`, 302);
});

admin.post("/admin/security/apply-default-password", async (c) => {
  // It resets every password, Super Admins' included.
  if (!c.get("isSuperAdmin")) return c.text("Applying the default password to every account needs a Super Admin.", 403);
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

// ---------- Authentication policies and factors ----------

const SECURITY_CRUMB: Breadcrumb = { label: "Security", href: "/admin/security" };

admin.get("/admin/security/policies", async (c) => {
  const [policies, groups] = await Promise.all([listPolicies(c.env), c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>()]);
  const reqLabel = (r: string) => (r === "mfa" ? "Password + second factor (or a passkey)" : "Password (or a passkey)");
  const row = (p: (typeof policies)[number]) => `
    <tr>
      <td><strong>${escapeHtml(p.name)}</strong>${p.is_default ? ' <span class="badge badge-active">Default</span>' : ""}<br /><span class="muted">${escapeHtml(p.description)}</span></td>
      <td>${reqLabel(p.requirement)}</td>
      <td>${p.groups.map((g) => `<span class="pill">${escapeHtml(g.name)}</span>`).join(" ")}${p.is_default ? `${p.groups.length ? " and " : ""}<span class="muted">everyone not matched by another policy</span>` : p.groups.length ? "" : '<span class="muted">No groups yet</span>'}</td>
      <td>${p.groups.length ? p.priority : "&mdash;"}</td>
      <td style="text-align:right;"><a href="/admin/security/policies/${p.id}">Edit</a></td>
    </tr>`;
  return c.html(
    layout(
      c,
      "Authentication policies",
      `${c.req.query("saved") ? successBanner("Saved.") : ""}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">A policy says what someone must present to sign in. Each person gets the policy of their highest-priority group (lowest number);
          anyone not in a policy's groups gets the default. A passkey satisfies every policy: it is multi-factor on its own.</p>
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
  return normalizePolicy({ ...body, groupIds: list(body.group_ids), makeDefault: body.make_default });
}

admin.post("/admin/security/policies", async (c) => {
  let f;
  try {
    f = await readPolicyForm(c);
  } catch (e) {
    return c.text((e as Error).message, 400);
  }
  await createPolicy(consoleCtx(c), f);
  return c.redirect("/admin/security/policies?saved=1", 302);
});

admin.get("/admin/security/policies/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const p = (await listPolicies(c.env)).find((x) => x.id === id);
  if (!p) return c.text("Not found", 404);
  const groups = await c.env.DB.prepare("SELECT id, name FROM groups ORDER BY name").all<{ id: number; name: string }>();
  return c.html(
    layout(
      c,
      p.name,
      cardSection(`
        <form method="POST" action="/admin/security/policies/${p.id}">
          <div class="field-row">
            <div><label for="p_name">Name</label><input type="text" id="p_name" name="name" required maxlength="80" value="${escapeHtml(p.name)}" /></div>
            <div><label for="p_req">Requires</label><select id="p_req" name="requirement">
              <option value="mfa" ${p.requirement === "mfa" ? "selected" : ""}>Password + second factor (or a passkey)</option>
              <option value="password" ${p.requirement === "password" ? "selected" : ""}>Password (or a passkey)</option></select></div>
          </div>
          <label for="p_desc">Description</label><input type="text" id="p_desc" name="description" maxlength="200" value="${escapeHtml(p.description)}" />
          ${p.is_default ? '<p class="muted">This is the default policy: it applies to everyone no other policy matches. It can also be assigned to groups, so they keep it if another policy becomes the default.</p>' : ""}
          <label for="p_pri">Priority (lower wins)</label><input type="number" id="p_pri" name="priority" min="1" max="1000" value="${p.priority}" style="max-width:120px;" />
          ${multiSelect("group_ids", groups.results.map((g) => ({ id: g.id, label: g.name })), new Set(p.groups.map((g) => g.id)), "Search groups...")}
          ${p.is_default ? "" : `<label style="font-weight:400;"><input type="checkbox" name="make_default" value="1" style="width:auto; display:inline; margin-right:6px;" /> Make this the default policy</label>`}
          <div class="form-actions end">
            ${p.is_default ? "" : `<button class="danger" type="submit" formaction="/admin/security/policies/${p.id}/delete" formnovalidate ${confirmAttrs("Its groups fall back to another matching policy or the default.", { title: `Delete the policy "${p.name}"?`, action: "Delete policy", danger: true })}>Delete policy</button>`}
            ${cancelLink("/admin/security/policies")}
            <button class="primary" type="submit">Save</button>
          </div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, SECURITY_CRUMB, { label: "Policies", href: "/admin/security/policies" }, { label: p.name }]
    )
  );
});

admin.post("/admin/security/policies/:id", async (c) => {
  const id = Number(c.req.param("id"));
  if (!(await c.env.DB.prepare("SELECT 1 FROM auth_policies WHERE id = ?").bind(id).first())) return c.text("Not found", 404);
  let f;
  try {
    f = await readPolicyForm(c);
  } catch (e) {
    return c.text((e as Error).message, 400);
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
    ? (await c.env.DB.prepare("SELECT id, display_name, upn, status FROM users WHERE id IN (SELECT value FROM json_each(?)) ORDER BY display_name").bind(JSON.stringify(adminIds)).all<{ id: number; display_name: string; upn: string; status: string }>()).results
    : [];
  const rolesOf = (uid: number) => roles.filter((r) => !r.is_default && (members.get(r.id) ?? []).includes(uid));
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
        <p class="muted">Everyone with more than the default role, and what they can do.</p>
        ${
          admins.length
            ? `<table><thead><tr><th>Person</th><th>Roles</th><th>Can</th></tr></thead><tbody>${admins
                .map((u) => {
                  const rs = rolesOf(u.id);
                  return `<tr><td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a><br /><span class="muted">${escapeHtml(u.upn)}</span>${u.status !== "active" ? ' <span class="badge badge-disabled">Inactive</span>' : ""}</td><td>${rs.map((r) => escapeHtml(r.name)).join(", ")}</td><td style="max-width:460px;">${permissionSummary(rs.flatMap(rolePermissions))}</td></tr>`;
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
  if (!role) return c.text("Not found", 404);
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
    return c.text((e as Error).message, 400);
  }
  await createRole(consoleCtx(c), f);
  return c.redirect("/admin/security/roles?saved=1", 302);
});

admin.post("/admin/security/roles/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const role = await c.env.DB.prepare("SELECT * FROM admin_roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!role) return c.text("Not found", 404);
  if (role.name === SUPER_ROLE) return c.text("Super Admin cannot be changed.", 400);
  let f;
  try {
    f = await readRoleForm(c);
  } catch (e) {
    return c.text((e as Error).message, 400);
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
        on.get(key) ? `<br /><span class="muted"><strong>Recommended: keep a stronger factor on as well (authenticator app, passkeys or email codes) and encourage people to enrol one; security questions alone are easy to guess or research.</strong></span>` : ""
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
        <p class="muted" style="margin-top:0;">The second-factor methods people can enrol and sign in with. A password is always available; turning a factor off stops it counting toward a policy and hides its enrolment.</p>
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
        <p class="muted" style="margin-top:0;">Security questions are <strong>${on ? "on" : "off"}</strong> (switched under <a href="/admin/security/factors">Factors</a>). They are the weakest second factor: answers can often be guessed, looked up or phished. Prefer the authenticator app, passkeys or email codes, and if you use questions, keep one of those on too. Answers are normalised (case, spacing, Unicode) and stored hashed like passwords; nobody can read them back. A sign-in with security questions never counts as the step-up re-authentication Super Admins need for sensitive console actions.</p>
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
                <td style="text-align:right; white-space:nowrap;">
                  <form method="POST" action="/admin/security/factors/security-questions/questions/${q.id}" style="display:inline;"><input type="hidden" name="enabled" value="${q.enabled ? "0" : "1"}" /><button class="secondary" type="submit">${q.enabled ? "Disable" : "Enable"}</button></form>
                  ${q.answered_by === 0 ? `<form method="POST" action="/admin/security/factors/security-questions/questions/${q.id}/delete" style="display:inline;" ${confirmAttrs("The question is removed from the list.", { title: "Delete this question?", action: "Delete", danger: true })}><button class="link-button" type="submit">Delete</button></form>` : ""}
                </td></tr>`
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
    if (e.status === 404) return c.text(e.message, 404);
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
    if (e.message === "Unknown factor.") return c.text(e.message, 400);
    return c.redirect(`/admin/security/factors?error=${encodeURIComponent(e.message)}`, 302);
  }
  return c.redirect("/admin/security/factors?saved=1", 302);
});

// ---------- Signing keys ----------

admin.get("/admin/security/signing-keys", async (c) => {
  const keys = await listSigningKeys(c.env);
  const usage = await c.env.DB.prepare("SELECT id_token_signed_response_alg AS alg, COUNT(*) AS n FROM oauth_clients GROUP BY id_token_signed_response_alg").all<{ alg: string; n: number }>();
  const clientsUsing = (alg: string) => usage.results.find((r) => r.alg === alg)?.n ?? 0;
  const when = (iso: string) => `<span title="${escapeHtml(iso)}">${escapeHtml(new Date(iso).toLocaleString("en-GB", { timeZone: "UTC", dateStyle: "medium", timeStyle: "short" }))} UTC</span>`;
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

admin.post("/admin/scim", async (c) => {
  const body = await c.req.parseBody();
  await setScimConfig(c.env, { endpoint: String(body.endpoint ?? ""), secret: String(body.secret ?? "") });
  await logAudit(c.env, c.get("user"), "settings.scim_config_changed", undefined, undefined, c.req.raw);
  return c.redirect("/admin/integrations/scim?saved=1", 302);
});

admin.post("/admin/scim/scope", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const mode = body.mode === "selected" ? "selected" : "all";
  const groupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];
  // Re-evaluates everything already pushed against the new scope (services/scim-sync.ts).
  await applyScimScope(consoleCtx(c), { mode, groupIds }, (p) => c.executionCtx.waitUntil(p));
  return c.redirect("/admin/integrations/scim?saved=1", 302);
});

admin.post("/admin/scim/test", async (c) => {
  const result = await testScimConnection(c.env);
  await logAudit(c.env, c.get("user"), "scim.connection_tested", undefined, { ok: result.ok }, c.req.raw);

  return c.json({
    ok: result.ok,
    message: result.ok
      ? `Connection succeeded (HTTP ${result.status}).`
      : `Connection failed${result.status ? ` (HTTP ${result.status})` : ""}: ${result.error ?? "unknown error"}`,
  });
});

admin.post("/admin/scim/sync", async (c) => {
  // One batch per request; the page calls again until `complete` (see SCIM_SCRIPT).
  const summary = await syncAll(c.env, { restart: c.req.query("restart") === "1" });
  if (summary.complete || summary.userErrors || summary.groupErrors) {
    await logAudit(c.env, c.get("user"), summary.complete ? "scim.sync_all" : "scim.sync_batch_errors", undefined, { ...summary }, c.req.raw);
  }
  return c.json({ ok: summary.userErrors === 0 && summary.groupErrors === 0, ...summary });
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

  return c.html(
    layout(
      c,
      "Log",
      `
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
                  <td class="muted">${escapeHtml(new Date(e.at).toLocaleString())}</td>
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

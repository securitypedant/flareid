import { Hono } from "hono";
import type { Env } from "../env.js";
import { requireAdmin, requireSession, SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { attr, attrGrid, barChart, breadcrumbs, cancelLink, cardSection, confirmAttrs, copyButton, escapeHtml, formActions, multiSelect, nav, page, pageSizeSelect, paginationControls, rankedBars, rowMenu, searchSelect, secretBlock, successBanner, type Breadcrumb } from "../lib/html.js";
import { generateTempPassword, hashPassword } from "../lib/password.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import type { AuditLogRow, GroupRow, OAuthClientRow, SamlServiceProviderRow, UserRow } from "../lib/types.js";
import { addDomain, applyDomainToAllUsers, deleteDomain, listDomains, setDefaultDomain } from "../lib/domains.js";
import {
  applyDefaultPasswordToAllUsers,
  getDefaultPassword,
  getPasswordPolicy,
  isSetupCompleted,
  markSetupCompleted,
  resolveNewAccountPassword,
  setDefaultPassword,
  setPasswordPolicy,
  validatePassword,
} from "../lib/settings.js";
import { logAudit } from "../lib/audit.js";
import { getScimConfig, getScimScope, setScimConfig, setScimScope } from "../lib/settings.js";
import { getRateLimitPolicy, setRateLimitPolicy } from "../lib/rate-limit.js";
import { getNewUserPasswordMode, isMfaRequired, setMfaRequired, setNewUserPasswordMode } from "../lib/settings.js";
import {
  AUDIT_RETENTION_DEFAULT_DAYS,
  AUDIT_RETENTION_MAX_DAYS,
  AUDIT_RETENTION_MIN_DAYS,
  getAuditRetentionDays,
  setAuditRetentionDays,
} from "../lib/settings.js";
import { getLoginGradient, getLoginSubtitle, setAppName, setLoginGradient, setLoginSubtitle } from "../lib/settings.js";
import { deleteBackupCodes } from "../lib/backup-codes.js";
import { deleteTrustedDevicesForUser } from "../lib/trusted-devices.js";
import { listActiveSessionsForUser, revokeAllSessionsForUser } from "../lib/sessions.js";
import { deactivateUserScim, deleteGroupScim, deleteUserScim, pushGroup, pushUser, syncAll, testScimConnection } from "../lib/scim-client.js";
import { API_SCOPES, createApiKey, isApiScope, listApiKeys, parseScopes, revokeApiKey, type ApiScope } from "../lib/api-keys.js";
import { idpEntityId, supportedNameIdFormats, nameIdFormatUri } from "../lib/saml/messages.js";
import { isSamlConfigured } from "../lib/saml/sign.js";
import { certNotAfter, normalizeCertPem } from "../lib/saml/x509.js";
import { USER_ATTRIBUTE_FIELDS } from "../lib/saml/attributes.js";
import { resolveGroupMemberUserIds, parseRule, userMatchesRule, ruleDescription, ruleFields, ruleFromForm, type RuleCondition } from "../lib/groups.js";
import {
  listSchemas,
  getSchema,
  findSchema,
  getSchemaAttributes,
  defaultSchemaId,
  parseCustomAttributes,
  userAttributeValue,
  splitUserAttributes,
  conformUserAttributes,
  attributesLostOnMove,
  createSchema,
  saveSchemaAttributes,
  applySchemaToAll,
  countConforming,
  attributeInput,
  type SchemaRow,
  type SchemaAttributeRow,
} from "../lib/schemas.js";

export const admin = new Hono<{ Bindings: Env }>();

admin.use("/admin", requireSession, requireAdmin);
admin.use("/admin/*", requireSession, requireAdmin);

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
  c: { get: (k: "appName") => string },
  title: string,
  body: string,
  crumbs?: Breadcrumb[],
  active?: string,
  headerActions = ""
) {
  const appName = c.get("appName");
  const crumbHtml = crumbs ? breadcrumbs(crumbs) : "";
  const section = active ?? (crumbs?.[1] ? (CRUMB_SECTIONS[crumbs[1].label] ?? "") : "");
  return page(
    `${title}`,
    `<div class="admin-shell">
      <aside class="admin-side">${adminNav(section)}</aside>
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
  return `<tr><th${widthStyle}>${escapeHtml(label)}</th><td><div style="display:flex; align-items:center; gap:8px;"><code>${escapeHtml(value)}</code>${copyButton(value)}</div></td></tr>`;
}

function oidcEndpointsBlock(env: Env, clientId: string) {
  return `
    <div style="background:#f9fafb; border-radius:10px; padding:14px 16px; margin:12px 0;">
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

function adminNav(active: string) {
  const items: [string, string][] = [
    ["users", "Users"],
    ["groups", "Groups"],
    ["integrations", "Integrations"],
    ["domains", "Domains"],
    ["branding", "Branding"],
    ["security", "Security"],
    ["schemas", "Schemas"],
    ["audit", "Log"],
  ];
  return items.map(([key, label]) => `<a href="/admin/${key}" class="${active === key ? "active" : ""}">${label}</a>`).join("");
}

/** Either the shared default password, or a freshly generated one that respects the configured complexity policy - per the "New account password" setting on /admin/security. */
async function generateAccountPassword(env: Env): Promise<string> {
  return (await resolveNewAccountPassword(env)).password;
}

async function scimConfigured(env: Env): Promise<boolean> {
  const { endpoint, secret } = await getScimConfig(env);
  return !!endpoint && !!secret;
}

/** Best-effort push - never blocks the admin action if SCIM isn't configured or the remote call fails. */
async function syncUserBestEffort(c: { env: Env; get: (k: "user") => UserRow; req: { raw: Request } }, userId: number, action: "push" | "deactivate" | "delete") {
  if (!(await scimConfigured(c.env))) return;
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first<UserRow>();
  if (!user && action !== "delete") return;

  const result =
    action === "push" && user
      ? await pushUser(c.env, user)
      : action === "deactivate" && user
        ? await deactivateUserScim(c.env, user)
        : { ok: true };

  if (!result.ok) await logAudit(c.env, c.get("user"), "scim.user_sync_failed", user?.upn, { action, error: result.error }, c.req.raw);
}

async function syncGroupBestEffort(c: { env: Env; get: (k: "user") => UserRow; req: { raw: Request } }, groupId: number) {
  if (!(await scimConfigured(c.env))) return;
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(groupId).first<GroupRow>();
  if (!group) return;

  const memberIds = await resolveGroupMemberUserIds(c.env, group);
  const { results: memberRows } = memberIds.length
    ? await c.env.DB.prepare(
        `SELECT scim_id as scimId, upn FROM users WHERE id IN (${memberIds.map(() => "?").join(",")}) AND scim_id IS NOT NULL`
      )
        .bind(...memberIds)
        .all<{ scimId: string; upn: string }>()
    : { results: [] as { scimId: string; upn: string }[] };

  const result = await pushGroup(c.env, group, memberRows);
  if (!result.ok) await logAudit(c.env, c.get("user"), "scim.group_sync_failed", group.name, { error: result.error }, c.req.raw);
}

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

  const people = attributes.some((a) => a.type === "reference" && (a.ref_object ?? "user") === "user")
    ? (
        await c.env.DB.prepare("SELECT external_id, display_name, upn FROM users WHERE id != ? ORDER BY display_name")
          .bind(excludeUserId ?? -1)
          .all<{ external_id: string; display_name: string; upn: string }>()
      ).results.map((u) => ({ value: u.external_id, label: `${u.display_name} (${u.upn})` }))
    : [];

  const cells = attributes.map((attr) => {
    const value = values[attr.name] ?? "";
    const label = `<label for="attr_${escapeHtml(attr.name)}">${escapeHtml(attr.label)}${attr.required ? " *" : ""}</label>`;
    if (attr.name === "employment_status") return `<div>${label}${employmentStatusSelect(value, "attr_employment_status")}</div>`;
    if (attr.name === "employment_type") return `<div>${label}${employmentTypeSelect(value, "attr_employment_type")}</div>`;
    if (attr.type === "reference") {
      return `<div>${label}${searchSelect(`attr_${attr.name}`, [{ value: "", label: "None" }, ...people], value, "None")}</div>`;
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
        <input type="checkbox" ${active ? "checked" : ""} ${isSelf ? "disabled" : ""} onchange="this.form.requestSubmit ? this.form.requestSubmit() : this.form.submit()" />
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

const DASHBOARD_DAYS = 30;

/** YYYY-MM-DD for a day offset from today, in UTC to match the audit log's timestamps. */
function dayKey(offsetDays: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

admin.get("/admin", async (c) => {
  const since = `${dayKey(-(DASHBOARD_DAYS - 1))}T00:00:00.000Z`;

  const [
    { results: userCount },
    { results: groupCount },
    { results: clientCount },
    { results: activeSessions },
    { results: mfaCount },
    { results: loginsByDay },
    { results: outcomes },
    { results: topActions },
    { results: topUsers },
  ] = await Promise.all([
    c.env.DB.prepare("SELECT COUNT(*) as n FROM users").all<{ n: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as n FROM groups").all<{ n: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as n FROM oauth_clients").all<{ n: number }>(),
    // Sessions carry no expiry column - validity is created_at plus the 12h TTL
    // in lib/sessions.ts, so the same rule is applied here rather than inventing
    // one that would over-count long-dead sessions.
    c.env.DB.prepare("SELECT COUNT(*) as n FROM sessions WHERE revoked_at IS NULL AND created_at > ?")
      .bind(new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString())
      .all<{ n: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as n FROM users WHERE mfa_enabled = 1").all<{ n: number }>(),

    // The audit log is the source of truth for activity: login.success and
    // login.failed have been recorded since the first version, so these charts
    // need no new instrumentation - just grouping.
    c.env.DB.prepare(
      `SELECT substr(at, 1, 10) AS day,
              SUM(CASE WHEN action = 'login.success' THEN 1 ELSE 0 END) AS ok,
              SUM(CASE WHEN action LIKE 'login.failed%' OR action LIKE 'login.mfa_failed%' THEN 1 ELSE 0 END) AS bad
         FROM audit_log
        WHERE at >= ? AND action LIKE 'login.%'
        GROUP BY day ORDER BY day`
    )
      .bind(since)
      .all<{ day: string; ok: number; bad: number }>(),
    c.env.DB.prepare(
      `SELECT action, COUNT(*) AS n FROM audit_log
        WHERE at >= ? AND action LIKE 'login.%' GROUP BY action ORDER BY n DESC`
    )
      .bind(since)
      .all<{ action: string; n: number }>(),
    c.env.DB.prepare(
      `SELECT action, COUNT(*) AS n FROM audit_log
        WHERE at >= ? AND action NOT LIKE 'login.%' GROUP BY action ORDER BY n DESC LIMIT 6`
    )
      .bind(since)
      .all<{ action: string; n: number }>(),
    c.env.DB.prepare(
      `SELECT actor_upn AS upn, COUNT(*) AS n FROM audit_log
        WHERE at >= ? AND action = 'login.success' AND actor_upn IS NOT NULL
        GROUP BY actor_upn ORDER BY n DESC LIMIT 6`
    )
      .bind(since)
      .all<{ upn: string; n: number }>(),
  ]);

  // Fill the gaps: a day with no logins has to be a zero-height bar, not a
  // missing one, or the shape of the chart lies about the period.
  const byDay = new Map(loginsByDay.map((r) => [r.day, r]));
  const days = Array.from({ length: DASHBOARD_DAYS }, (_, i) => dayKey(-(DASHBOARD_DAYS - 1 - i)));
  const successSeries = days.map((day) => ({
    label: day.slice(8, 10) === "01" ? day.slice(5, 10) : day.slice(8, 10),
    value: byDay.get(day)?.ok ?? 0,
  }));

  const successTotal = loginsByDay.reduce((sum, r) => sum + (r.ok ?? 0), 0);
  const failedTotal = loginsByDay.reduce((sum, r) => sum + (r.bad ?? 0), 0);
  const users = userCount[0]?.n ?? 0;
  const mfaEnrolled = mfaCount[0]?.n ?? 0;

  return c.html(
    layout(
      c,
      "Admin",
      `
            <div class="stat-grid">
        <a class="stat-card" href="/admin/users"><div class="card"><h2>${users}</h2><p>Users</p></div></a>
        <a class="stat-card" href="/admin/groups"><div class="card"><h2>${groupCount[0]?.n ?? 0}</h2><p>Groups</p></div></a>
        <a class="stat-card" href="/admin/clients"><div class="card"><h2>${clientCount[0]?.n ?? 0}</h2><p>OIDC Clients</p></div></a>
        <a class="stat-card" href="/admin/log"><div class="card"><h2>${successTotal}</h2><p>Sign-ins (30d)</p></div></a>
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
            attr("Active sessions", activeSessions[0]?.n ?? 0),
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
  const { results: sampleGroups } = await c.env.DB.prepare(
    `SELECT * FROM groups WHERE name != ?`
  )
    .bind(SUPER_ADMINS_GROUP)
    .all<GroupRow>();

  const scimEnabled = await scimConfigured(c.env);
  if (scimEnabled) {
    for (const user of sampleUsers) await deleteUserScim(c.env, user);
    for (const group of sampleGroups) await deleteGroupScim(c.env, group);
  }

  const sampleUserIds = sampleUsers.map((u) => u.id);
  const sampleGroupIds = sampleGroups.map((g) => g.id);

  if (sampleUserIds.length > 0) {
    const placeholders = sampleUserIds.map(() => "?").join(",");
    await c.env.DB.batch([
      c.env.DB.prepare(`DELETE FROM group_members WHERE user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`DELETE FROM sessions WHERE user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`DELETE FROM access_tokens WHERE user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`DELETE FROM refresh_tokens WHERE user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`DELETE FROM auth_codes WHERE user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`DELETE FROM mfa_backup_codes WHERE user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`UPDATE audit_log SET actor_user_id = NULL WHERE actor_user_id IN (${placeholders})`).bind(...sampleUserIds),
      c.env.DB.prepare(`DELETE FROM users WHERE id IN (${placeholders})`).bind(...sampleUserIds),
    ]);
  }

  if (sampleGroupIds.length > 0) {
    const placeholders = sampleGroupIds.map(() => "?").join(",");
    await c.env.DB.prepare(`DELETE FROM groups WHERE id IN (${placeholders})`).bind(...sampleGroupIds).run();
  }
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
    `<select name="${name}" onchange="this.form.querySelector('input[name=page]').value=1; this.form.submit();" style="width:auto; display:inline-block; margin-bottom:0;">
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
              <select id="schema_id" name="schema_id" style="margin-bottom:0;" onchange="location.href='/admin/users/new?schema='+this.value">
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
  const username = String(body.username ?? "").trim().toLowerCase();
  const domain = String(body.domain ?? "").trim().toLowerCase();
  const upn = `${username}@${domain}`;
  const givenName = String(body.given_name ?? "").trim();
  const familyName = String(body.family_name ?? "").trim();
  const displayName = `${givenName} ${familyName}`.trim();
  const schemaId = Number(body.schema_id) || (await defaultSchemaId(c.env, "user"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(c.env, schemaId) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(body[`attr_${a.name}`] ?? "").trim()]));
  const { columns, custom } = splitUserAttributes(schemaAttrs, attrValues);
  const postedGroupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];
  const staticIds = new Set((await c.env.DB.prepare("SELECT id FROM groups WHERE rule = ''").all<{ id: number }>()).results.map((g) => g.id));
  const groupIds = postedGroupIds.filter((gid) => staticIds.has(gid));

  if (!username || !domain || !givenName) return c.text("username, domain, and first name are required", 400);

  const existingUsername = await c.env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (existingUsername) {
    return c.text(`Username "${username}" is already taken by another account (usernames must be unique across every domain).`, 409);
  }

  const tempPassword = await generateAccountPassword(c.env);
  const { hash, salt, iterations } = await hashPassword(tempPassword);
  const now = new Date().toISOString();
  const externalId = crypto.randomUUID();

  const result = await c.env.DB.prepare(
    `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department, manager_external_id, employee_number, hire_date, employment_status, employment_type, location, password_hash, password_salt, password_iterations, status, schema_id, custom_attributes, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disabled', ?, ?, ?, ?)`
  )
    .bind(
      upn,
      username,
      displayName,
      givenName,
      familyName,
      externalId,
      String(columns.job_title ?? ""),
      String(columns.department ?? ""),
      (columns.manager_external_id as string | null) ?? null,
      String(columns.employee_number ?? ""),
      String(columns.hire_date ?? ""),
      String(columns.employment_status ?? ""),
      String(columns.employment_type ?? ""),
      String(columns.location ?? ""),
      hash,
      salt,
      iterations,
      schemaId,
      JSON.stringify(custom),
      now,
      now
    )
    .run();

  const userId = result.meta.last_row_id;
  if (groupIds.length > 0) {
    await c.env.DB.batch(
      groupIds.map((gid) =>
        c.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, userId)
      )
    );
  }

  await logAudit(c.env, c.get("user"), "user.created", upn, undefined, c.req.raw);
  await syncUserBestEffort(c, userId, "push");
  for (const gid of groupIds) await syncGroupBestEffort(c, gid);

  return c.html(
    layout(
      c,
      "User created",
      `${cardSection(`
        <p class="success" style="margin-top:0;">Created ${escapeHtml(displayName)} (${escapeHtml(upn)}). The account is inactive until you switch it on from their page.</p>
        ${secretBlock("Temporary password - share with the user securely", tempPassword)}
        <a href="/admin/users/${userId}"><button class="primary" type="button">Keep this password and continue</button></a>
      `)}
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

  const { results: groups } = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all<GroupRow>();
  const { results: memberships } = await c.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?")
    .bind(id)
    .all<{ group_id: number }>();
  const memberGroupIds = new Set(memberships.map((m) => m.group_id));
  const sessions = await listActiveSessionsForUser(c.env, id);
  const { results: connectedApps } = await c.env.DB.prepare(
    `SELECT DISTINCT oc.id, oc.name FROM access_tokens at
     JOIN oauth_clients oc ON oc.client_id = at.client_id
     WHERE at.user_id = ? AND at.expires_at > ?
     UNION
     SELECT DISTINCT oc.id, oc.name FROM refresh_tokens rt
     JOIN oauth_clients oc ON oc.client_id = rt.client_id
     WHERE rt.user_id = ? AND rt.revoked_at IS NULL`
  )
    .bind(id, new Date().toISOString(), id)
    .all<{ id: number; name: string }>();
  const { username, domain } = splitUpn(user.upn);
  const isSelf = id === c.get("user").id;

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
      return `<option value="${s.id}" data-lost="${escapeHtml(lost.join(", "))}" ${schema?.id === s.id ? "selected" : ""}>${escapeHtml(s.name)}${s.id === currentSchemaId ? " (current)" : ""}</option>`;
    })
    .join("");

  return c.html(
    layout(
      c,
      user.display_name,
      `
      ${c.req.query("saved") ? successBanner("Saved.") : ""}
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
              <select id="schema_id" name="schema_id" style="margin-bottom:0;" onchange="
                var lost = this.selectedOptions[0].dataset.lost;
                var msg = lost ? 'Moving to ' + this.selectedOptions[0].text + ' clears these attributes when you save: ' + lost + '. Attributes with the same name carry over.' : '';
                if (msg && !confirm(msg)) { this.value = '${schema?.id ?? ""}'; return; }
                location.href = '/admin/users/${id}?schema=' + this.value;">
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
                  .map((g) => `<a class="pill" href="/admin/groups/${g.id}" title="${escapeHtml(ruleDescription(parseRule(g.rule)!))}">${escapeHtml(g.name)}</a>`)
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
        <div class="sec-row">
          <div>
            <h3>Multi-factor authentication <span class="badge ${user.mfa_enabled ? "badge-active" : "badge-disabled"}">${user.mfa_enabled ? "Enrolled" : "Not enrolled"}</span></h3>
            <p class="muted">Resetting clears their authenticator, backup codes and remembered devices; they enrol again at next sign-in.</p>
          </div>
          <form method="POST" action="/admin/users/${id}/reset-mfa"
            ${confirmAttrs("Their authenticator, backup codes and remembered devices are removed. They will be asked to enrol again.", { title: "Reset MFA for this user?", action: "Reset MFA" })}>
            <button class="secondary" type="submit" ${user.mfa_enabled ? "" : "disabled"}>Reset MFA</button>
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
          connectedApps.length > 0
            ? `<table>
                <thead><tr><th>App</th><th></th></tr></thead>
                <tbody>
                  ${connectedApps
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
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return c.text("Not found", 404);
  if (id === c.get("user").id) return c.text("You cannot deactivate your own account.", 400);

  const status = String((await c.req.parseBody()).status ?? "") === "active" ? "active" : "disabled";
  await c.env.DB.prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ?").bind(status, new Date().toISOString(), id).run();
  // Deactivation should take effect now, not at the next sign-in.
  if (status === "disabled") await revokeAllSessionsForUser(c.env, id);

  await logAudit(c.env, c.get("user"), status === "active" ? "user.activated" : "user.deactivated", user.upn, undefined, c.req.raw);
  await syncUserBestEffort(c, id, status === "active" ? "push" : "deactivate");
  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

admin.post("/admin/users/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  const username = String(body.username ?? "").trim().toLowerCase();
  const domain = String(body.domain ?? "").trim().toLowerCase();
  const upn = `${username}@${domain}`;
  const givenName = String(body.given_name ?? "").trim();
  const familyName = String(body.family_name ?? "").trim();
  const displayName = `${givenName} ${familyName}`.trim();
  const existingRow = await c.env.DB.prepare("SELECT external_id, status FROM users WHERE id = ?").bind(id).first<{ external_id: string; status: string }>();
  if (!existingRow) return c.text("Not found", 404);
  const status = existingRow.status; // changed only through the account switch (/status)

  // Only static groups take explicit members - dynamic membership follows the rule.
  const postedGroupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];
  const { results: staticGroupRows } = await c.env.DB.prepare("SELECT id FROM groups WHERE rule = ''").all<{ id: number }>();
  const staticIds = new Set(staticGroupRows.map((g) => g.id));
  const groupIds = postedGroupIds.filter((gid) => staticIds.has(gid));

  // Conform to the chosen schema: what it defines is saved (same-named values
  // were carried into the form), everything else is cleared.
  const schemaId = Number(body.schema_id) || (await defaultSchemaId(c.env, "user"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(c.env, schemaId) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(body[`attr_${a.name}`] ?? "").trim()]));
  const { columns, custom } = conformUserAttributes(schemaAttrs, attrValues);
  const mergedCustom = custom;

  let managerExternalId = (columns.manager_external_id as string | null) ?? null;
  if (managerExternalId && managerExternalId === existingRow.external_id) managerExternalId = null; // can't manage yourself

  const usernameTaken = await c.env.DB.prepare("SELECT id FROM users WHERE username = ? AND id != ?").bind(username, id).first();
  if (usernameTaken) {
    return c.text(`Username "${username}" is already taken by another account (usernames must be unique across every domain).`, 409);
  }

  await c.env.DB.prepare(
    `UPDATE users SET upn = ?, username = ?, display_name = ?, given_name = ?, family_name = ?, job_title = ?, department = ?, manager_external_id = ?,
     employee_number = ?, hire_date = ?, employment_status = ?, employment_type = ?, location = ?, status = ?, schema_id = ?, custom_attributes = ?, updated_at = ? WHERE id = ?`
  )
    .bind(
      upn,
      username,
      displayName,
      givenName,
      familyName,
      String(columns.job_title ?? ""),
      String(columns.department ?? ""),
      managerExternalId,
      String(columns.employee_number ?? ""),
      String(columns.hire_date ?? ""),
      String(columns.employment_status ?? ""),
      String(columns.employment_type ?? ""),
      String(columns.location ?? ""),
      status,
      schemaId,
      JSON.stringify(mergedCustom),
      new Date().toISOString(),
      id
    )
    .run();

  const { results: previous } = await c.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?").bind(id).all<{ group_id: number }>();
  await c.env.DB.prepare("DELETE FROM group_members WHERE user_id = ?").bind(id).run();
  if (groupIds.length > 0) {
    await c.env.DB.batch(
      groupIds.map((gid) =>
        c.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, id)
      )
    );
  }

  await logAudit(c.env, c.get("user"), "user.updated", upn, undefined, c.req.raw);
  await syncUserBestEffort(c, id, status === "active" ? "push" : "deactivate");
  // Groups they left, groups they joined, and every dynamic group - an
  // attribute edit can move them in or out of any rule.
  const { results: dynamicRows } = await c.env.DB.prepare("SELECT id FROM groups WHERE rule != ''").all<{ id: number }>();
  const affected = new Set([...previous.map((p) => p.group_id), ...groupIds, ...dynamicRows.map((g) => g.id)]);
  for (const gid of affected) await syncGroupBestEffort(c, gid);

  return c.redirect(`/admin/users/${id}?saved=1`, 302);
});

admin.post("/admin/users/:id/reset-mfa", async (c) => {
  const id = Number(c.req.param("id"));
  await c.env.DB.prepare("UPDATE users SET totp_secret = NULL, mfa_enabled = 0, updated_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), id)
    .run();
  await deleteBackupCodes(c.env, id);
  await deleteTrustedDevicesForUser(c.env, id);
  await logAudit(c.env, c.get("user"), "user.mfa_reset", String(id), undefined, c.req.raw);
  return c.redirect(`/admin/users/${id}`, 302);
});

/** "At least 12 characters, with an uppercase letter and a number." - the policy as a sentence, shown next to password fields. */
function passwordPolicySummary(policy: Awaited<ReturnType<typeof getPasswordPolicy>>): string {
  const needs = [
    policy.requireUppercase && "an uppercase letter",
    policy.requireLowercase && "a lowercase letter",
    policy.requireNumber && "a number",
    policy.requireSymbol && "a symbol",
  ].filter(Boolean) as string[];
  const list = needs.length > 1 ? `${needs.slice(0, -1).join(", ")} and ${needs[needs.length - 1]}` : needs[0];
  return `At least ${policy.minLength} characters${list ? `, with ${list}` : ""}.`;
}

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

  const password = chosen || (await generateAccountPassword(c.env));
  const { hash, salt, iterations } = await hashPassword(password);
  await c.env.DB.prepare(
    "UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?"
  )
    .bind(hash, salt, iterations, new Date().toISOString(), id)
    .run();

  await logAudit(c.env, c.get("user"), "user.password_reset", user.upn, { chosen: Boolean(chosen) }, c.req.raw);

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
  const count = await revokeAllSessionsForUser(c.env, id);
  await logAudit(c.env, c.get("user"), "user.sessions_revoked_all", String(id), { count }, c.req.raw);
  return c.redirect(`/admin/users/${id}`, 302);
});

admin.post("/admin/users/:id/apps/:clientDbId/revoke", async (c) => {
  const id = Number(c.req.param("id"));
  const clientDbId = Number(c.req.param("clientDbId"));
  const client = await c.env.DB.prepare("SELECT client_id, name FROM oauth_clients WHERE id = ?")
    .bind(clientDbId)
    .first<{ client_id: string; name: string }>();
  if (!client) return c.redirect(`/admin/users/${id}`, 302);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?").bind(id, client.client_id),
    c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ?").bind(
      new Date().toISOString(),
      id,
      client.client_id
    ),
  ]);
  await logAudit(c.env, c.get("user"), "user.app_access_revoked", client.name, { userId: id }, c.req.raw);

  return c.redirect(`/admin/users/${id}`, 302);
});

admin.post("/admin/users/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
  if (!user) return c.text("Not found", 404);
  if (id === c.get("user").id) return c.text("You cannot delete your own account.", 400);

  if (await scimConfigured(c.env)) {
    const result = await deleteUserScim(c.env, user);
    if (!result.ok) await logAudit(c.env, c.get("user"), "scim.user_sync_failed", user.upn, { action: "delete", error: result.error }, c.req.raw);
  }

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM group_members WHERE user_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM access_tokens WHERE user_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM auth_codes WHERE user_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM mfa_backup_codes WHERE user_id = ?").bind(id),
    // Detach (but keep) audit history referencing this user, so the FK doesn't block deletion.
    c.env.DB.prepare("UPDATE audit_log SET actor_user_id = NULL WHERE actor_user_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id),
  ]);

  await logAudit(c.env, c.get("user"), "user.deleted", user.upn, undefined, c.req.raw);

  return c.redirect("/admin/users", 302);
});

// ---------- Groups ----------

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
  const { results: users } = await env.DB.prepare("SELECT * FROM users").all<UserRow>();
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
    <button type="button" class="secondary" onclick="ruleRemove(this)" aria-label="Remove condition">&times;</button>
  </div>`;
}

const GROUP_FORM_SCRIPT = `
(function () {
  var dataEl = document.getElementById("rule-data");
  if (!dataEl) return;
  var data = JSON.parse(dataEl.textContent);
  function attrsFor(name) { for (var i = 0; i < data.schemas.length; i++) if (data.schemas[i].name === name) return data.schemas[i].attributes; return []; }
  document.addEventListener("change", function (e) {
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
  window.ruleAdd = function () {
    var t = document.getElementById("rule-row-template");
    document.getElementById("rule-rows").appendChild(t.content.cloneNode(true));
  };
  window.ruleRemove = function (btn) { btn.closest(".rule-row").remove(); };
  window.groupTypeChanged = function () {
    var dyn = document.querySelector("input[name=membership]:checked").value === "dynamic";
    document.getElementById("dynamic-section").style.display = dyn ? "" : "none";
    document.getElementById("static-section").style.display = dyn ? "none" : "";
  };
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

  const { results: users } = await c.env.DB.prepare("SELECT * FROM users ORDER BY display_name").all<UserRow>();
  const explicit = group
    ? new Set((await c.env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(group.id).all<{ user_id: number }>()).results.map((m) => m.user_id))
    : new Set<number>();
  const matched = rule ? users.filter((u) => userMatchesRule(u, rule)) : [];

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
                  <select id="schema_id" name="schema_id" style="margin-bottom:0;" onchange="location.href='${reloadBase}?schema='+this.value">
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
            : `<div class="row" style="justify-content:flex-start; gap:20px; margin-bottom:14px;">
                <label style="font-weight:500; display:flex; align-items:center; gap:6px; margin:0;"><input type="radio" name="membership" value="static" ${isDynamic ? "" : "checked"} onchange="groupTypeChanged()" style="width:auto; margin:0;" /> Static - members are assigned</label>
                <label style="font-weight:500; display:flex; align-items:center; gap:6px; margin:0;"><input type="radio" name="membership" value="dynamic" ${isDynamic ? "checked" : ""} onchange="groupTypeChanged()" style="width:auto; margin:0;" /> Dynamic - members match rules</label>
              </div>`
        }

        <div id="dynamic-section" style="${isDynamic ? "" : "display:none;"}">
          <p class="muted" style="margin-top:0;">People who match <strong>every</strong> condition are members. Membership updates as their attributes change.</p>
          <div id="rule-rows">
            ${(rule?.all.length ? rule.all : [undefined]).map((cond) => ruleRowHtml(data, cond)).join("")}
          </div>
          <button type="button" class="secondary" onclick="ruleAdd()">+ Add condition</button>
          <template id="rule-row-template">${ruleRowHtml(data)}</template>
          ${Object.entries(data.values)
            .map(([name, vals]) => `<datalist id="rv-${escapeHtml(name)}">${vals.map((v) => `<option value="${escapeHtml(v)}"></option>`).join("")}</datalist>`)
            .join("")}
          <script type="application/json" id="rule-data">${JSON.stringify(data).replace(/</g, "\\u003c")}</script>
          ${
            group && isDynamic
              ? `<h3 style="margin-top:20px;">Members (${matched.length})</h3>
                ${
                  matched.length > 0
                    ? `<table><thead><tr><th>Name</th><th>UPN</th><th>Status</th></tr></thead><tbody>
                        ${matched.map((u) => `<tr><td><a href="/admin/users/${u.id}">${escapeHtml(u.display_name)}</a></td><td>${escapeHtml(u.upn)}</td><td><span class="badge badge-${u.status}">${u.status}</span></td></tr>`).join("")}
                      </tbody></table>`
                    : '<p class="muted">Nobody matches these rules yet.</p>'
                }`
              : ""
          }
        </div>

        <div id="static-section" style="${isDynamic ? "display:none;" : ""}">
          ${multiSelect(
            "user_ids",
            users.map((u) => ({ id: u.id, label: `${u.display_name} (${u.upn})` })),
            explicit,
            "Search people..."
          )}
        </div>
      `)}

      <div class="form-actions end" style="margin-bottom:18px;">
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
    <script>${GROUP_FORM_SCRIPT}</script>
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
  const userIds = dynamic ? [] : list(body.user_ids).map(Number).filter(Boolean);

  const schemaId = Number(body.schema_id) || (await defaultSchemaId(c.env, "group"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(c.env, schemaId) : [];
  // Conform: only the schema's attributes are kept.
  const custom = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(body[`attr_${a.name}`] ?? "").trim()]).filter(([, v]) => v));
  return { name, description, rule, userIds, schemaId, custom };
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
        <form method="GET" class="row between" style="margin-bottom:0; gap:12px; flex-wrap:wrap;">
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <input type="text" name="search" placeholder="Search groups" value="${escapeHtml(search)}" style="max-width:300px; margin-bottom:0;" />
            <select name="type" onchange="this.form.querySelector('input[name=page]').value=1; this.form.submit();" style="width:auto; display:inline-block; margin-bottom:0;">
              ${[["", "All types"], ["static", "Static"], ["dynamic", "Dynamic"]].map(([v, l]) => `<option value="${v}" ${v === typeFilter ? "selected" : ""}>${l}</option>`).join("")}
            </select>
            <input type="hidden" name="page" value="1" />
            ${pageSizeSelect(pageSize)}
          </div>
          <a href="/admin/groups/new"><button class="primary" type="button">+ New group</button></a>
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
  if (await c.env.DB.prepare("SELECT id FROM groups WHERE name = ?").bind(form.name).first()) {
    return c.text(`A group named "${form.name}" already exists.`, 409);
  }

  const result = await c.env.DB.prepare("INSERT INTO groups (name, description, rule, schema_id, custom_attributes) VALUES (?, ?, ?, ?, ?)")
    .bind(form.name, form.description || null, form.rule, form.schemaId, JSON.stringify(form.custom))
    .run();
  const id = Number(result.meta.last_row_id);
  if (form.userIds.length > 0) {
    await c.env.DB.batch(form.userIds.map((uid) => c.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)));
  }

  await logAudit(c.env, c.get("user"), "group.created", form.name, form.rule ? { rule: form.rule } : undefined, c.req.raw);
  await syncGroupBestEffort(c, id);
  return c.redirect(`/admin/groups/${id}?saved=1`, 302);
});

admin.get("/admin/groups/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();
  if (!group) return c.text("Not found", 404);
  const rule = parseRule(group.rule);

  return c.html(
    layout(
      c,
      group.name,
      `${c.req.query("saved") ? successBanner("Saved.") : ""}${await groupFormHtml(c, group, Number(c.req.query("schema")))}`,
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
  if (await c.env.DB.prepare("SELECT id FROM groups WHERE name = ? AND id != ?").bind(form.name, id).first()) {
    return c.text(`A group named "${form.name}" already exists.`, 409);
  }

  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE groups SET name = ?, description = ?, rule = ?, schema_id = ?, custom_attributes = ? WHERE id = ?").bind(
      form.name,
      form.description || null,
      form.rule,
      form.schemaId,
      JSON.stringify(form.custom),
      id
    ),
    // A dynamic group holds no explicit rows; a static one holds exactly the posted set.
    c.env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(id),
    ...form.userIds.map((uid) => c.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(id, uid)),
  ]);

  await logAudit(c.env, c.get("user"), "group.updated", form.name, form.rule ? { rule: form.rule } : undefined, c.req.raw);
  await syncGroupBestEffort(c, id);
  return c.redirect(`/admin/groups/${id}?saved=1`, 302);
});

admin.post("/admin/groups/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(id).first<GroupRow>();

  if (group && (await scimConfigured(c.env))) {
    const result = await deleteGroupScim(c.env, group);
    if (!result.ok) await logAudit(c.env, c.get("user"), "scim.group_sync_failed", group.name, { action: "delete", error: result.error }, c.req.raw);
  }

  await c.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(id).run();
  await logAudit(c.env, c.get("user"), "group.deleted", group?.name, undefined, c.req.raw);
  return c.redirect("/admin/groups", 302);
});

// ---------- Integrations: OIDC clients in, SCIM provisioning out ----------
//
// These were two pages. They are two halves of the same job - how other
// systems connect to this directory - and splitting them made configuring
// Cloudflare Access a hunt across the nav: register the client here, then find
// SCIM over there. Both old paths still resolve so existing links survive.

admin.get("/admin/clients", (c) => c.redirect("/admin/integrations", 302));
admin.get("/admin/scim", (c) => c.redirect(`/admin/integrations${new URL(c.req.url).search}`, 302));

admin.get("/admin/integrations", async (c) => {
  const { results: clients } = await c.env.DB.prepare("SELECT * FROM oauth_clients ORDER BY name").all<OAuthClientRow>();
  const { results: sps } = await c.env.DB.prepare("SELECT * FROM saml_service_providers ORDER BY name").all<SamlServiceProviderRow>();
  const config = await getScimConfig(c.env);
  const scope = await getScimScope(c.env);
  const { results: scopeGroups } = await c.env.DB.prepare("SELECT * FROM groups ORDER BY name").all<GroupRow>();
  const apiKeys = await listApiKeys(c.env);

  return c.html(
    layout(
      c,
      "Integrations",
      `
            ${c.req.query("saved") ? successBanner("Saved.") : ""}

      ${cardSection(`
        <div class="row between" style="margin:0 0 14px 0;">
          <div>
            <h2 style="margin:0;">OIDC clients</h2>
            <p class="muted" style="margin:4px 0 0;">The relying parties allowed to sign users in with this directory &mdash; Cloudflare Access, for example.</p>
          </div>
          <a href="/admin/clients/new"><button class="primary" type="button">+ New client</button></a>
        </div>
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

      ${cardSection(`
        <div class="row between" style="margin:0 0 14px 0;">
          <div>
            <h2 style="margin:0;">SAML service providers</h2>
            <p class="muted" style="margin:4px 0 0;">Applications allowed to sign users in over SAML 2.0 (SP-initiated, redirect binding). The IdP metadata they need is at <code>/saml/metadata</code>.</p>
          </div>
          <a href="/admin/saml/new"><button class="primary" type="button">+ New service provider</button></a>
        </div>
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

      ${cardSection(`
        <div class="row between" style="margin:0 0 14px 0;">
          <div>
            <h2 style="margin:0;">API keys</h2>
            <p class="muted" style="margin:4px 0 0;">Bearer tokens for the provisioning API at <code>/api/v1</code> &mdash; creating users and groups, registering clients and changing settings without a browser session. See <code>docs/api.md</code>.</p>
          </div>
          <a href="/admin/api-keys/new"><button class="primary" type="button">+ New key</button></a>
        </div>
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
                          <td>${
                            k.revoked_at
                              ? ""
                              : `<form method="POST" action="/admin/api-keys/${k.id}/revoke" style="display:inline" ${confirmAttrs(
                                  `Anything using "${k.name}" stops working immediately. This cannot be undone.`,
                                  { title: "Revoke this API key?", action: "Revoke", danger: true }
                                )}><button class="link-button" type="submit">Revoke</button></form>`
                          }</td>
                        </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
        }
      `)}

      ${cardSection(`
        <h2>User provisioning (SCIM)</h2>
        <p class="muted">FlareID acts as a SCIM 2.0 <em>client</em>, pushing users and groups to a SCIM server &mdash; for example
        the endpoint and secret Cloudflare generates once you enable SCIM on this IdP's Access identity provider.</p>
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
            <label><input type="radio" name="mode" value="all" ${scope.mode === "all" ? "checked" : ""} onclick="document.getElementById('scim-scope-groups').style.display='none';" style="width:auto; display:inline; margin-right:6px;" /> All groups</label>
            <label><input type="radio" name="mode" value="selected" ${scope.mode === "selected" ? "checked" : ""} onclick="document.getElementById('scim-scope-groups').style.display='block';" style="width:auto; display:inline; margin-right:6px;" /> Specific groups only</label>
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
            <button class="secondary" type="button" id="scim-test-btn" onclick="scimAction('test')">Test connection</button>
            <button class="primary" type="button" id="scim-sync-btn" onclick="scimAction('sync')">Sync all now</button>
          </div>
          <div id="scim-status"></div>
        `)}
      </div>

      <script>
        async function scimAction(kind) {
          const btn = document.getElementById('scim-' + kind + '-btn');
          const status = document.getElementById('scim-status');
          const original = btn.textContent;
          btn.disabled = true;
          btn.textContent = kind === 'test' ? 'Testing...' : 'Syncing...';
          status.innerHTML = '';
          try {
            const res = await fetch('/admin/scim/' + kind, { method: 'POST' });
            const data = await res.json();
            const p = document.createElement('p');
            p.className = data.ok ? 'success' : 'error';
            p.style.marginTop = '12px';
            p.textContent = data.message;
            status.appendChild(p);
          } catch (e) {
            const p = document.createElement('p');
            p.className = 'error';
            p.style.marginTop = '12px';
            p.textContent = 'Request failed: ' + e;
            status.appendChild(p);
          } finally {
            btn.disabled = false;
            btn.textContent = original;
          }
        }
      </script>
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Integrations" }]
    )
  );
});

// ---------- API keys ----------

const SCOPE_DESCRIPTIONS: Record<ApiScope, string> = {
  "directory:read": "Read users, groups, domains and registered clients",
  "directory:write": "Create and update users and groups, manage domains",
  "clients:write": "Register OIDC relying parties",
  "settings:write": "Change settings, branding and SCIM configuration",
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

          <label>Scopes</label>
          ${API_SCOPES.map(
            (s) =>
              `<label style="font-weight:400;"><input type="checkbox" name="scopes" value="${s}" ${s === "admin" ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> <code>${s}</code> &mdash; ${escapeHtml(SCOPE_DESCRIPTIONS[s])}</label>`
          ).join("")}

          <div class="form-actions" style="margin-top:16px;">
            <button class="primary" type="submit">Create key</button>
            ${cancelLink("/admin/integrations", "Cancel")}
          </div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: "New API key" }]
    )
  );
});

admin.post("/admin/api-keys", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const name = String(body.name ?? "").trim();
  if (!name) return c.text("name is required", 400);

  const requested = (Array.isArray(body.scopes) ? body.scopes : body.scopes ? [body.scopes] : [])
    .map(String)
    .filter(isApiScope);
  const scopes: ApiScope[] = requested.length > 0 ? requested : ["admin"];

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
        <a href="/admin/integrations"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: "API key created" }]
    )
  );
});

admin.post("/admin/api-keys/:id/revoke", async (c) => {
  const id = Number(c.req.param("id"));
  const key = await c.env.DB.prepare("SELECT name FROM api_keys WHERE id = ?").bind(id).first<{ name: string }>();
  if (!key) return c.text("Not found", 404);

  await revokeApiKey(c.env, id);
  await logAudit(c.env, c.get("user"), "api_key.revoked", key.name, undefined, c.req.raw);
  return c.redirect("/admin/integrations?saved=1", 302);
});

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
          <div class="form-actions end">${cancelLink(`/admin/integrations`)}<button class="primary" type="submit">Create client</button></div>
        </form>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: "New client" }]
    )
  );
});

admin.post("/admin/clients", async (c) => {
  const body = await c.req.parseBody();
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
  const clientSecret = seeded ? seededSecret : randomToken(24);
  const clientSecretHash = await sha256Hex(clientSecret);

  const result = await c.env.DB.prepare(
    "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(clientId, clientSecretHash, name, JSON.stringify(redirectUris), new Date().toISOString())
    .run();

  await logAudit(c.env, c.get("user"), "oidc_client.created", name, undefined, c.req.raw);

  return c.html(
    layout(
      c,
      "Client created",
      cardSection(`
        <p class="success">Created "${escapeHtml(name)}".</p>
        ${secretBlock("Client secret", clientSecret)}
        ${oidcEndpointsBlock(c.env, clientId)}
        <a href="/admin/clients/${result.meta.last_row_id}"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: "Client created" }]
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
          <div class="form-actions end">${cancelLink(`/admin/clients/${id}`)}<button class="primary" type="submit">Save</button></div>
        </form>
        <div class="row" style="justify-content:flex-start; gap:10px; margin-top:8px;">
          <form method="POST" action="/admin/clients/${id}/rotate-secret">
            <button class="secondary" type="submit">Rotate secret</button>
          </form>
          <form method="POST" action="/admin/clients/${id}/delete" ${confirmAttrs(`Anything still using this client_id will stop working immediately.`, { title: `Delete the OIDC client "${client.name}"?`, action: "Delete client", danger: true })}>
            <button class="danger" type="submit">Delete client</button>
          </form>
        </div>
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: client.name }]
    )
  );
});

admin.post("/admin/clients/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.parseBody();
  const name = String(body.name ?? "").trim();
  const redirectUris = String(body.redirect_uris ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  await c.env.DB.prepare("UPDATE oauth_clients SET name = ?, redirect_uris = ? WHERE id = ?")
    .bind(name, JSON.stringify(redirectUris), id)
    .run();

  await logAudit(c.env, c.get("user"), "oidc_client.updated", name, undefined, c.req.raw);

  return c.redirect(`/admin/clients/${id}?saved=1`, 302);
});

admin.post("/admin/clients/:id/rotate-secret", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await c.env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(id).first<OAuthClientRow>();
  if (!client) return c.text("Not found", 404);

  const clientSecret = randomToken(24);
  const clientSecretHash = await sha256Hex(clientSecret);
  await c.env.DB.prepare("UPDATE oauth_clients SET client_secret_hash = ? WHERE id = ?")
    .bind(clientSecretHash, id)
    .run();

  await logAudit(c.env, c.get("user"), "oidc_client.secret_rotated", client.name, undefined, c.req.raw);

  return c.html(
    layout(
      c,
      "Secret rotated",
      cardSection(`
        ${secretBlock(`New client secret for ${client.name}`, clientSecret)}
        ${oidcEndpointsBlock(c.env, client.client_id)}
        <a href="/admin/clients/${id}"><button class="primary" type="button">Continue</button></a>
      `),
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: client.name, href: `/admin/clients/${id}` }, { label: "Secret rotated" }]
    )
  );
});

admin.post("/admin/clients/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const client = await c.env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(id).first<OAuthClientRow>();
  if (!client) return c.text("Not found", 404);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM auth_codes WHERE client_id = ?").bind(client.client_id),
    c.env.DB.prepare("DELETE FROM access_tokens WHERE client_id = ?").bind(client.client_id),
    c.env.DB.prepare("DELETE FROM refresh_tokens WHERE client_id = ?").bind(client.client_id),
    c.env.DB.prepare("DELETE FROM oauth_clients WHERE id = ?").bind(id),
  ]);

  await logAudit(c.env, c.get("user"), "oidc_client.deleted", client.name, undefined, c.req.raw);

  return c.redirect("/admin/integrations", 302);
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
    <div style="background:#f9fafb; border-radius:10px; padding:14px 16px; margin:12px 0;">
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
      <div class="form-actions end">${cancelLink("/admin/integrations")}<button class="primary" type="submit">${escapeHtml(submitLabel)}</button></div>
    </form>`;
}

admin.get("/admin/saml/new", async (c) => {
  return c.html(
    layout(
      c,
      "New SAML service provider",
      `${samlIdpBlock(c.env)}${cardSection(spForm({}, "/admin/saml", "Create service provider"))}`,
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: "New service provider" }]
    )
  );
});

admin.post("/admin/saml", async (c) => {
  const v = parseSpForm(await c.req.parseBody());
  if (typeof v === "string") return c.text(v, 400);

  const now = new Date().toISOString();
  const result = await c.env.DB.prepare(
    `INSERT INTO saml_service_providers (entity_id, name, acs_urls, default_acs_url, nameid_format, attribute_map, sign_response, sign_assertion, want_authn_requests_signed, signing_certs, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(v.entityId, v.name, JSON.stringify(v.acsUrls), v.defaultAcsUrl || null, v.nameidFormat, JSON.stringify(v.attributeMap), v.signResponse ? 1 : 0, v.signAssertion ? 1 : 0, v.wantSigned ? 1 : 0, JSON.stringify(v.signingCerts), now, now)
    .run();

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
      [{ label: "Admin", href: "/admin" }, { label: "Integrations", href: "/admin/integrations" }, { label: sp.name }]
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
    `UPDATE saml_service_providers SET entity_id = ?, name = ?, acs_urls = ?, default_acs_url = ?, nameid_format = ?, attribute_map = ?, sign_response = ?, sign_assertion = ?, want_authn_requests_signed = ?, signing_certs = ?, updated_at = ? WHERE id = ?`
  )
    .bind(v.entityId, v.name, JSON.stringify(v.acsUrls), v.defaultAcsUrl || null, v.nameidFormat, JSON.stringify(v.attributeMap), v.signResponse ? 1 : 0, v.signAssertion ? 1 : 0, v.wantSigned ? 1 : 0, JSON.stringify(v.signingCerts), new Date().toISOString(), id)
    .run();

  await logAudit(c.env, c.get("user"), "saml_sp.updated", v.name, { entity_id: v.entityId }, c.req.raw);
  return c.redirect(`/admin/saml/${id}?saved=1`, 302);
});

admin.post("/admin/saml/:id/delete", async (c) => {
  const id = Number(c.req.param("id"));
  const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(id).first<SamlServiceProviderRow>();
  if (!sp) return c.text("Not found", 404);

  await c.env.DB.prepare("DELETE FROM saml_service_providers WHERE id = ?").bind(id).run();
  await logAudit(c.env, c.get("user"), "saml_sp.deleted", sp.name, { entity_id: sp.entity_id }, c.req.raw);
  return c.redirect("/admin/integrations", 302);
});

// ---------- Schemas ----------

const ATTRIBUTE_TYPE_OPTIONS: [string, string][] = [
  ["string", "Text"],
  ["number", "Number"],
  ["date", "Date"],
  ["boolean", "Yes / no"],
  ["reference", "Person (reference)"],
];

type AttributeInput = { name: string; label: string; type: string; required: boolean; ref_object: string | null };

function attributeRowHtml(a?: { name: string; label: string; type: string; required: number }): string {
  const required = a?.required ? 1 : 0;
  return `<div class="attr-row">
    <input type="text" name="attr_name" value="${escapeHtml(a?.name ?? "")}" placeholder="name (e.g. cost_center)" pattern="[a-z][a-z0-9_]*" title="lowercase letters, digits and underscores, starting with a letter" />
    <input type="text" name="attr_label" value="${escapeHtml(a?.label ?? "")}" placeholder="Label (e.g. Cost center)" />
    <select name="attr_type">${ATTRIBUTE_TYPE_OPTIONS.map(([v, l]) => `<option value="${v}" ${(a?.type ?? "string") === v ? "selected" : ""}>${l}</option>`).join("")}</select>
    <label><input type="hidden" name="attr_required" value="${required}" /><input type="checkbox" ${required ? "checked" : ""} onchange="this.previousElementSibling.value = this.checked ? '1' : '0'" style="width:auto; margin:0;" /> Required</label>
    <button type="button" class="secondary" onclick="this.closest('.attr-row').remove()" aria-label="Remove attribute">&times;</button>
  </div>`;
}

/** Reads the attribute rows (parallel attr_name/attr_label/attr_type/attr_required arrays); blank names are dropped. */
function readAttributeRows(body: Record<string, unknown>): AttributeInput[] {
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);
  const names = list(body.attr_name);
  const labels = list(body.attr_label);
  const types = list(body.attr_type);
  const required = list(body.attr_required);
  const seen = new Set<string>();
  const out: AttributeInput[] = [];
  names.forEach((raw, i) => {
    const name = raw.trim();
    if (!name) return;
    if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error(`"${name}" is not a valid attribute name - use lowercase letters, digits and underscores, starting with a letter.`);
    if (seen.has(name)) throw new Error(`The attribute "${name}" is listed twice.`);
    seen.add(name);
    const type = ATTRIBUTE_TYPE_OPTIONS.some(([v]) => v === types[i]) ? types[i]! : "string";
    out.push({ name, label: (labels[i] ?? "").trim() || name, type, required: required[i] === "1", ref_object: type === "reference" ? "user" : null });
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
            <span>Name</span><span>Label</span><span>Type</span><span></span><span></span>
          </div>
          <div id="attr-rows">${(attributes.length ? attributes : [undefined]).map((a) => attributeRowHtml(a)).join("")}</div>
          <template id="attr-row-template">${attributeRowHtml()}</template>
          <button type="button" class="secondary" onclick="document.getElementById('attr-rows').appendChild(document.getElementById('attr-row-template').content.cloneNode(true))">+ Add attribute</button>
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

  await c.env.DB.prepare("UPDATE schemas SET name = ?, description = ? WHERE id = ?").bind(name, description || null, id).run();
  await saveSchemaAttributes(c.env, id, attributes);
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
  const id = Number(c.req.param("id"));
  const { error } = await deleteDomain(c.env, id);
  await logAudit(c.env, c.get("user"), "domain.delete_attempted", String(id), error ? { error } : undefined, c.req.raw);
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
        <h2>Multi-factor authentication</h2>
        <p class="muted">When required, anyone without MFA enrolled is forced to set it up (with backup codes) the next time they sign in, before they can use anything else.</p>
        <form method="POST" action="/admin/security/require-mfa">
          <label><input type="checkbox" name="required" value="1" ${mfaRequired ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> Require MFA for every account</label>
          <div class="row" style="justify-content:flex-start; margin-top:12px;"><button class="primary" type="submit">Save</button></div>
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
  const body = await c.req.parseBody();
  const password = String(body.default_password ?? "");
  if (password) {
    await setDefaultPassword(c.env, password);
    await logAudit(c.env, c.get("user"), "settings.default_password_changed", undefined, undefined, c.req.raw);
  }
  return c.redirect("/admin/security?saved=1", 302);
});

// ---------- Branding (app name, sign-in message, login page appearance) ----------

admin.get("/admin/branding", async (c) => {
  const loginGradient = await getLoginGradient(c.env);
  const loginSubtitle = await getLoginSubtitle(c.env);
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
      </div>
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Branding" }]
    )
  );
});

admin.post("/admin/branding/app-name", async (c) => {
  const body = await c.req.parseBody();
  const name = String(body.app_name ?? "").trim();
  if (name) {
    await setAppName(c.env, name);
    await logAudit(c.env, c.get("user"), "settings.app_name_changed", name, undefined, c.req.raw);
  }

  // Empty is a valid choice here - it means "show no message" - so this is
  // saved whenever the field is present rather than only when non-empty.
  if (body.login_subtitle !== undefined) {
    const subtitle = String(body.login_subtitle ?? "").trim();
    await setLoginSubtitle(c.env, subtitle);
    await logAudit(c.env, c.get("user"), "settings.login_subtitle_changed", undefined, { subtitle }, c.req.raw);
  }
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/branding/login-gradient", async (c) => {
  const body = await c.req.parseBody();
  const from = String(body.from ?? "").trim();
  const to = String(body.to ?? "").trim();
  const isHexColor = (v: string) => /^#[0-9a-fA-F]{6}$/.test(v);

  if (isHexColor(from) && isHexColor(to)) {
    await setLoginGradient(c.env, { from, to });
    await logAudit(c.env, c.get("user"), "settings.login_gradient_changed", undefined, { from, to }, c.req.raw);
  }
  return c.redirect("/admin/branding?saved=1", 302);
});

admin.post("/admin/security/apply-default-password", async (c) => {
  const body = await c.req.parseBody();
  const password = String(body.default_password ?? "");
  if (password) {
    await setDefaultPassword(c.env, password);
    await logAudit(c.env, c.get("user"), "settings.default_password_changed", undefined, undefined, c.req.raw);
  }

  const count = await applyDefaultPasswordToAllUsers(c.env);
  await logAudit(c.env, c.get("user"), "settings.default_password_applied_to_all", undefined, { count }, c.req.raw);
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
  const body = await c.req.parseBody();
  const mode = body.mode === "default" ? "default" : "random";
  await setNewUserPasswordMode(c.env, mode);
  await logAudit(c.env, c.get("user"), "settings.new_user_password_mode_changed", undefined, { mode }, c.req.raw);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/password-policy", async (c) => {
  const body = await c.req.parseBody();
  await setPasswordPolicy(c.env, {
    minLength: Number(body.minLength) || 8,
    requireUppercase: !!body.requireUppercase,
    requireLowercase: !!body.requireLowercase,
    requireNumber: !!body.requireNumber,
    requireSymbol: !!body.requireSymbol,
  });
  await logAudit(c.env, c.get("user"), "settings.password_policy_changed", undefined, undefined, c.req.raw);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/require-mfa", async (c) => {
  const body = await c.req.parseBody();
  await setMfaRequired(c.env, !!body.required);
  await logAudit(c.env, c.get("user"), "settings.require_mfa_changed", undefined, { required: !!body.required }, c.req.raw);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/rate-limit", async (c) => {
  const body = await c.req.parseBody();
  await setRateLimitPolicy(c.env, {
    maxAttempts: Number(body.maxAttempts) || 5,
    windowMinutes: Number(body.windowMinutes) || 15,
  });
  await logAudit(c.env, c.get("user"), "settings.rate_limit_changed", undefined, undefined, c.req.raw);
  return c.redirect("/admin/security?saved=1", 302);
});

admin.post("/admin/security/audit-retention", async (c) => {
  const days = await setAuditRetentionDays(c.env, Number((await c.req.parseBody()).days) || AUDIT_RETENTION_DEFAULT_DAYS);
  await logAudit(c.env, c.get("user"), "settings.audit_retention_changed", undefined, { days }, c.req.raw);
  return c.redirect("/admin/security?saved=1", 302);
});

// ---------- SCIM (push users/groups to e.g. Cloudflare Access) ----------

admin.post("/admin/scim", async (c) => {
  const body = await c.req.parseBody();
  await setScimConfig(c.env, { endpoint: String(body.endpoint ?? ""), secret: String(body.secret ?? "") });
  await logAudit(c.env, c.get("user"), "settings.scim_config_changed", undefined, undefined, c.req.raw);
  return c.redirect("/admin/integrations?saved=1", 302);
});

admin.post("/admin/scim/scope", async (c) => {
  const body = await c.req.parseBody({ all: true });
  const mode = body.mode === "selected" ? "selected" : "all";
  const groupIds = Array.isArray(body.group_ids) ? body.group_ids.map(Number) : body.group_ids ? [Number(body.group_ids)] : [];

  await setScimScope(c.env, { mode, groupIds });
  await logAudit(c.env, c.get("user"), "settings.scim_scope_changed", undefined, { mode, groupIds }, c.req.raw);

  return c.redirect("/admin/integrations?saved=1", 302);
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
  const summary = await syncAll(c.env);
  await logAudit(c.env, c.get("user"), "scim.sync_all", undefined, summary, c.req.raw);

  return c.json({
    ok: summary.userErrors === 0 && summary.groupErrors === 0,
    message: `Pushed ${summary.users} user(s)${summary.userErrors ? ` (${summary.userErrors} failed)` : ""} and ${summary.groups} group(s)${summary.groupErrors ? ` (${summary.groupErrors} failed)` : ""}.`,
  });
});

// ---------- Audit log ----------

// The page is called "Log" in the UI. Both paths serve it: /admin/audit is
// what older links and bookmarks use, /admin/log is what the name implies.
admin.get("/admin/log", (c) => c.redirect(`/admin/audit${new URL(c.req.url).search}`, 302));

admin.get("/admin/audit", async (c) => {
  const search = c.req.query("search") ?? "";
  const pageSize = [20, 50, 100].includes(Number(c.req.query("pageSize"))) ? Number(c.req.query("pageSize")) : 20;
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const like = `%${search}%`;

  const whereClause = "WHERE actor_upn LIKE ? OR action LIKE ? OR target LIKE ? OR details LIKE ? OR ip LIKE ?";
  const params = [like, like, like, like, like];

  const batchResults = await c.env.DB.batch([
    c.env.DB.prepare(`SELECT COUNT(*) as n FROM audit_log ${whereClause}`).bind(...params),
    c.env.DB.prepare(`SELECT * FROM audit_log ${whereClause} ORDER BY at DESC LIMIT ? OFFSET ?`).bind(
      ...params,
      pageSize,
      (page - 1) * pageSize
    ),
  ]);
  const countRows = batchResults[0]!.results;
  const entries = batchResults[1]!.results as AuditLogRow[];
  const total = Number((countRows[0] as { n: number } | undefined)?.n ?? 0);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return c.html(
    layout(
      c,
      "Log",
      `
            ${cardSection(`
        <form method="GET" class="row between" style="margin-bottom:0;">
          <div style="display:flex; gap:8px;">
            <input type="text" name="search" placeholder="Search the log" value="${escapeHtml(search)}" style="max-width:300px; margin-bottom:0;" />
            <input type="hidden" name="page" value="1" />
            ${pageSizeSelect(pageSize)}
          </div>
        </form>
      `)}
      ${cardSection(`
        <p class="muted" style="margin-top:0;">Click a row to see its IP and details.</p>
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

                return `<tr class="audit-row" onclick="this.nextElementSibling.classList.toggle('open')">
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
        ${paginationControls("/admin/audit", page, totalPages, { search, pageSize })}
      `)}
      `,
      [{ label: "Admin", href: "/admin" }, { label: "Log" }]
    )
  );
});

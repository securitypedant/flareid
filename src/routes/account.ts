import { errorPage, safeBackHref } from "../lib/html.js";
import { grants } from "../lib/permissions.js";
import { enrolledFactors, FACTOR_SHORT_LABELS, hasSecondFactor, isFactorEnabled, isFactorUsable, secondFactorGate } from "../lib/auth-policy.js";
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
import { isFreshlyAuthenticated } from "../lib/step-up.js";
import { sealMaybe, unsealMaybe } from "../lib/sealed.js";
import { markConsumed } from "../lib/one-shot.js";
import { PASSKEY_REGISTER_SCRIPT } from "../lib/passkey-scripts.js";
import { Hono, type Context, type MiddlewareHandler } from "hono";
import { brandFor } from "../lib/brands.js";
import QRCode from "qrcode";
import type { Env } from "../env.js";
import { requireSession } from "../lib/middleware.js";
import { attr, attrGrid, attrHtml, avatar, cancelLink, cardSection, confirmAttrs, escapeHtml, nav, page, paginationControls, remoteMultiSelect, scriptTag, successBanner, ts } from "../lib/html.js";
import { buildOtpAuthUri, claimTotpCounter, generateBase32Secret, matchTotpCounter } from "../lib/totp.js";
import { deletePendingEnrollment, getPendingEnrollment, storePendingEnrollment } from "../lib/mfa-enrollment.js";
import { getUserById, getUserGroupIds, getUserGroupNames } from "../lib/db.js";
import { attributeInput, getSchemaAttributes, parseCustomAttributes, ruleAttributeNames, splitUserAttributes, userAttributeValue, type SchemaAttributeRow } from "../lib/schemas.js";
import { getMasteredFields, masteringKeyFor } from "../lib/scim-mapping.js";
import { isScimConfigured, pushUser } from "../lib/scim-client.js";
import type { OAuthClientRow, SamlServiceProviderRow, UserRow } from "../lib/types.js";
import { verifyPassword, hashPassword } from "../lib/password.js";
import { getPasswordPolicy } from "../lib/settings.js";
import { newPasswordError } from "../lib/breached-passwords.js";
import { logAudit } from "../lib/audit.js";
import { getRateLimitPolicy, recordRateAttempt } from "../lib/rate-limit.js";
import { countRemainingBackupCodes, deleteBackupCodes, generateBackupCodes, hasUnusedBackupCodes, verifyAndConsumeBackupCode } from "../lib/backup-codes.js";
import { createSession, listActiveSessionsForUser, revokeAllSessionsForUser, revokeSession, revokeTokensForUser } from "../lib/sessions.js";
import { emitAndDrain, SSF_EVENTS } from "../lib/ssf.js";
import { bindFlowToUser, deleteLoginFlow, getLoginFlow, isSealedFlowId } from "../lib/authorize-state.js";
import { finishOidcAuthorize, respondAuthorize } from "./authorize.js";
import { safeNextPath } from "./login.js";
import { deleteTrustedDevicesForUser, listTrustedDevices, revokeTrustedDevice } from "../lib/trusted-devices.js";
import { cancelAccessRequest, decideAccessRequest, getAccessRequest, listAccessRequests, myAccessRequests, requestAccess, requestableApps, requestableGroups, type AccessTargetType } from "../lib/access.js";
import { groupRolesMap } from "../lib/admin-roles.js";
import { isGroupManager, managedGroups } from "../lib/group-managers.js";
import { notificationFeedFor } from "../lib/notifications.js";
import { avatarUrl, deleteUserPhoto, getUserPhoto, getUserPhotoVersion, MAX_PHOTO_BYTES, setUserPhoto, sniffImageType } from "../lib/photos.js";
import { consoleCtx, ServiceError } from "../services/context.js";
import { addGroupMembers, getGroupById, groupMembers, removeGroupMember } from "../services/groups.js";
import { appAccessAllowed, parseAssignedGroupIds } from "../services/clients.js";
import { assertMayManageGroup } from "../services/guards.js";

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
/** The bell's feed for account pages: pending requests an admin sees globally, a manager sees for their groups. */
account.use("/account/*", async (c, next) => {
  if (c.req.method === "GET") {
    const [feed, avatar] = await Promise.all([notificationFeedFor(c.env, c.get("user").id, c.get("access")?.isAdmin ?? false), avatarUrl(c.env, c.get("user").id)]);
    c.set("notifications", feed);
    c.set("avatarSrc", avatar);
  }
  await next();
});
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
    nav(appName, Boolean(c.get("access")?.isAdmin), c.get("logoUrl"), c.get("consoleTz"), c.get("notifications"), c.get("user")?.display_name ?? "", c.get("avatarSrc") ?? "")
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
  "access-requested": "Your request is in - an administrator will take a look.",
  "access-cancelled": "Your request has been withdrawn.",
  members: "The group's membership has been updated.",
  request: "The request has been decided.",
  photo: "Your photo has been updated.",
  "backup-codes-removed": "Your backup codes have been removed.",
  "backup-codes": "Your backup codes are saved.",
};

const ERROR_MESSAGES: Record<string, string> = {
  "mfa-code": "That code was not correct, so two-factor authentication is still enabled. Try again with a current code or an unused backup code.",
  "too-many": "Too many attempts. Please wait a few minutes before trying again.",
  "email-code": "That code was not correct, or it has expired. Check the latest email, or send a new code.",
  "email-send": "We couldn't send the email. Try again in a moment.",
  "email-limit": "Too many codes requested. Please wait a few minutes before asking for another.",
  "email-unavailable": "Email codes aren't available right now.",
  "no-factor": "Set up a sign-in method like an authenticator app or a passkey first - backup codes are a fallback, not a first factor.",
  password: "Incorrect password, please try again.",
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

/** The attributes this user may edit: their schema's user-editable ones, minus anything a rule now matches on or provisioning masters. */
async function editableAttributes(env: Env, user: UserRow): Promise<SchemaAttributeRow[]> {
  if (!user.schema_id) return [];
  const [attrs, ruleFields, mastered] = await Promise.all([getSchemaAttributes(env, user.schema_id), ruleAttributeNames(env), getMasteredFields(env)]);
  const masteredSet = new Set(mastered);
  return attrs.filter((a) => a.user_editable === 1 && a.type !== "reference" && a.name !== "manager" && !ruleFields.has(a.name) && !masteredSet.has(masteringKeyFor(a)));
}

account.get("/account", async (c) => {
  const user = c.get("user");
  const [editable, mastered, photoV] = await Promise.all([editableAttributes(c.env, user), getMasteredFields(c.env), getUserPhotoVersion(c.env, user.id)]);
  const photoMastered = mastered.includes("photo");

  return c.html(
    layout(
      c,
      `${user.display_name}`,
      `
      ${savedBanner(c)}
      ${cardSection(`
        <div class="row between" style="align-items:flex-start; gap:18px;">
          <div style="flex:1; min-width:0;">
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
              attrHtml("Created", ts(user.created_at)),
            ])}
          </div>
          <div style="text-align:center; flex-shrink:0;">
            ${avatar(user.id, user.display_name, "lg", { upn: user.upn, v: photoV ?? "none" })}
            ${
              photoMastered
                ? '<p class="muted" style="font-size:11px; margin-top:6px; max-width:180px;">Your photo is managed by your HR system.</p>'
                : `<form method="POST" action="/account/photo" enctype="multipart/form-data" style="margin-top:10px;">
                    <label class="secondary photo-upload-btn" style="cursor:pointer; display:inline-block;">
                      Change photo
                      <input type="file" name="photo" accept="image/png,image/jpeg,image/webp,image/gif" data-autosubmit style="display:none;" />
                    </label>
                  </form>
                  <form method="POST" action="/account/photo/remove" style="margin-top:4px;"><button class="link-button" type="submit" style="font-size:11px;">Remove photo</button></form>
                  <p class="muted" style="font-size:11px; margin-top:6px; max-width:180px;">PNG, JPG, WebP or GIF up to 1 MB.</p>`
            }
          </div>
        </div>
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
      `,
      user.upn
    )
  );
});

account.get("/account/applications", async (c) => {
  const user = c.get("user");
  const [clients, sps] = await Promise.all([
    c.env.DB.prepare("SELECT * FROM oauth_clients ORDER BY name").all<OAuthClientRow>(),
    c.env.DB.prepare("SELECT * FROM saml_service_providers ORDER BY name").all<SamlServiceProviderRow>(),
  ]);
  // Memberships are only worth fetching when at least one app is restricted.
  const myGroupIds =
    clients.results.some((cl) => cl.access_mode !== "everyone") || sps.results.some((sp) => sp.access_mode !== "everyone")
      ? await getUserGroupIds(c.env, user.id)
      : [];

  // The launchpad: every app this person may sign in to - unrestricted apps,
  // plus assigned apps whose groups intersect theirs. Each card is the app's
  // own launch URL: a SAML SP's unsolicited-SSO endpoint, an OIDC client's
  // third-party login URI, else a bare authorization request.
  const launchpad = [
    ...clients.results
      .filter((cl) => appAccessAllowed(cl, myGroupIds, user.id))
      .map((cl) => {
        const firstRedirect = (JSON.parse(cl.redirect_uris || "[]") as string[])[0];
        const href =
          cl.initiate_login_uri ||
          (firstRedirect ? `/authorize?${new URLSearchParams({ client_id: cl.client_id, redirect_uri: firstRedirect, response_type: "code", scope: "openid" }).toString()}` : "");
        return { name: cl.name, logo: cl.logo_uri, href, kind: "OIDC" };
      }),
    ...sps.results
      .filter((sp) => appAccessAllowed(sp, myGroupIds, user.id))
      .map((sp) => ({ name: sp.name, logo: sp.logo_uri, href: `/saml/idp-initiated?sp=${encodeURIComponent(sp.entity_id)}`, kind: "SAML" })),
  ];
  // External client logos need their exact URLs admitted to img-src for this
  // response - security-headers reads the marker (same as the sign-in page).
  const logos = [...new Set(launchpad.map((a) => a.logo).filter((u): u is string => Boolean(u)))];
  if (logos.length) c.header("X-FlareID-Img-Src", logos.join(" "));

  const card = (a: (typeof launchpad)[number]) => {
    const inner = `
      <div style="width:40px; height:40px; border-radius:10px; background:var(--fi-surface); border:1px solid var(--fi-line); display:flex; align-items:center; justify-content:center; margin-bottom:10px; flex-shrink:0;">
        ${a.logo ? `<img src="${escapeHtml(a.logo)}" alt="" style="width:26px; height:26px; object-fit:contain;" data-hide-on-error />` : `<span style="font-weight:650; font-size:1rem; color:var(--fi-accent);">${escapeHtml(a.name.trim().charAt(0).toUpperCase() || "?")}</span>`}
      </div>
      <div style="font-weight:600; font-size:0.9rem; color:var(--fi-ink); line-height:1.25; overflow-wrap:anywhere; word-break:break-word; display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical; overflow:hidden;">${escapeHtml(a.name)}</div>
      <div class="muted" style="font-size:0.72rem; margin-top:5px; letter-spacing:0.03em; text-transform:uppercase;">${a.kind}</div>`;
    const style =
      'style="display:block; width:150px; min-height:112px; border:1px solid var(--fi-line); border-radius:var(--fi-radius); padding:14px; background:var(--fi-surface-2); color:var(--fi-body); text-decoration:none; overflow:hidden;"';
    return `<li>${a.href ? `<a href="${escapeHtml(a.href)}" ${style}>${inner}</a>` : `<div ${style}>${inner}</div>`}</li>`;
  };

  return c.html(
    layout(
      c,
      "Applications",
      cardSection(`
        ${launchpad.length
          ? `<ul style="list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:12px;">${launchpad.map(card).join("")}</ul>`
          : '<p class="muted">No apps assigned yet. Applications your administrator gives you access to will appear here.</p>'}
      `),
      `${launchpad.length} app${launchpad.length === 1 ? "" : "s"}`
    )
  );
});

account.get("/account/groups", (c) => c.redirect("/account/access", 301));

account.get("/account/access", async (c) => {
  const user = c.get("user");
  const [groups, requestable, apps, myRequests, managed] = await Promise.all([
    getUserGroupNames(c.env, user.id),
    requestableGroups(c.env, user.id),
    requestableApps(c.env, user.id, await getUserGroupIds(c.env, user.id)),
    myAccessRequests(c.env, user.id),
    managedGroups(c.env, user.id),
  ]);
  return c.html(
    layout(
      c,
      "Access",
      `
      ${savedBanner(c)}
      ${cardSection(`
        <h2>Your groups</h2>
        ${groups.length > 0 ? groups.map((g) => `<span class="pill">${escapeHtml(g)}</span>`).join("") : '<p class="muted">No group memberships</p>'}
        ${
          requestable.length || apps.length
            ? `<h3 style="margin-top:16px;">Request access</h3>
               <p class="muted">Some groups and apps accept self-service requests - an administrator approves or denies each ask.</p>
               <form method="POST" action="/account/access/request">
                 <label>Group or app</label>
                 ${remoteMultiSelect("target", "/account/access/targets", [], "Search groups and apps you can ask for...", true)}
                 <label for="access_reason">Reason (optional)</label>
                 <input type="text" id="access_reason" name="reason" maxlength="500" placeholder="Why you need it" />
                 <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Request access</button></div>
               </form>`
            : ""
        }
        ${
          myRequests.length
            ? `<h3 style="margin-top:16px;">Your requests</h3>
               <table>
                 <thead><tr><th>For</th><th>Asked</th><th>Status</th><th></th></tr></thead>
                 <tbody>
                   ${myRequests
                     .map(
                       (r) => `<tr>
                         <td>${escapeHtml(r.target_name)} <span class="badge">${r.target_type === "group" ? "Group" : r.target_type === "oidc_app" ? "OIDC app" : "SAML app"}</span>${r.reason ? `<br/><span class="muted" style="font-size:12px;">${escapeHtml(r.reason)}</span>` : ""}</td>
                         <td class="muted">${ts(r.created_at)}</td>
                         <td><span class="badge ${r.status === "pending" ? "badge-pending" : r.status === "approved" ? "badge-active" : "badge-disabled"}">${{ pending: "Waiting", approved: "Approved", denied: "Denied", cancelled: "Withdrawn" }[r.status] ?? r.status}</span>${
                           r.status !== "pending" && r.status !== "cancelled" && r.note ? `<br/><span class="muted" style="font-size:12px;">${escapeHtml(r.note)}</span>` : ""
                         }</td>
                         <td>${
                           r.status === "pending"
                             ? `<form method="POST" action="/account/access/requests/${r.id}/cancel"><button class="link-button" type="submit">Withdraw</button></form>`
                             : ""
                         }</td>
                       </tr>`
                     )
                     .join("")}
                 </tbody>
               </table>`
            : ""
        }
      `)}


      ${
        managed.length
          ? cardSection(`
        <h2>Groups you manage</h2>
        <p class="muted">You own these groups' membership - add or remove people and answer requests to join.</p>
        <table>
          <thead><tr><th>Group</th><th>Members</th><th>Waiting</th><th></th></tr></thead>
          <tbody>
            ${managed
              .map(
                (g) => `<tr>
                  <td>${escapeHtml(g.name)}${g.description ? `<br/><span class="muted" style="font-size:12px;">${escapeHtml(g.description)}</span>` : ""}</td>
                  <td class="muted">${g.member_count}</td>
                  <td>${g.pending ? `<span class="badge badge-pending">${g.pending}</span>` : '<span class="muted">-</span>'}</td>
                  <td style="text-align:right;"><a href="/account/groups/${g.id}"><button class="secondary" type="button">Manage</button></a></td>
                </tr>`
              )
              .join("")}
          </tbody>
        </table>
      `)
          : ""
      }
      `,
      user.upn
    )
  );
});

/**
 * A managed group's own page: the requests waiting on it (approve or deny
 * with a note), its members (remove one, search or page a big group), and a
 * picker to add people. Every write goes through assertMayManageGroup on the
 * POST - this page only decides what to show.
 */
account.get("/account/groups/:id", async (c) => {
  const user = c.get("user");
  const group = await getGroupById(c.env, Number(c.req.param("id")));
  if (!group || group.rule || !(await isGroupManager(c.env, user.id, group.id))) {
    return c.html(errorRedirectPage(c, "That group doesn't exist, isn't yours to manage, or assigns its members by rule."), 404);
  }
  const search = (c.req.query("search") ?? "").slice(0, 100);
  const page = Math.max(1, Number(c.req.query("page")) || 1);
  const [{ rows: pending }, members] = await Promise.all([
    listAccessRequests(c.env, { status: "pending", groupId: group.id }),
    groupMembers(c.env, group, search, 20, (page - 1) * 20),
  ]);
  const pages = Math.max(1, Math.ceil(members.total / 20));
  return c.html(
    layout(
      c,
      group.name,
      `
      ${savedBanner(c)}
      ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
      <p class="muted"><a href="/account/groups">&larr; Your groups</a></p>
      ${cardSection(`
        <h2>Requests ${pending.length ? `<span class="badge badge-pending">${pending.length}</span>` : ""}</h2>
        ${
          pending.length
            ? `<table>
                <thead><tr><th>Person</th><th>Reason</th><th>Asked</th><th></th></tr></thead>
                <tbody>
                  ${pending
                    .map(
                      (r) => `<tr>
                        <td>${avatar(r.user_id, r.display_name, "sm", { upn: r.upn })}${escapeHtml(r.display_name)}<br/><span class="muted" style="font-size:12px; padding-left:36px; display:block;">${escapeHtml(r.upn)}</span></td>
                        <td class="muted">${escapeHtml(r.reason || "—")}</td>
                        <td class="muted">${ts(r.created_at)}</td>
                        <td style="white-space:nowrap;">
                          ${
                            r.user_id === user.id
                              ? '<span class="muted" style="font-size:12px;">Your request - another approver must decide it.</span>'
                              : `<form method="POST" action="/account/groups/${group.id}/requests/${r.id}" style="display:flex; gap:6px; align-items:center; margin:0;">
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
              </table>`
            : '<p class="muted">No requests waiting for a decision.</p>'
        }
      `)}
      ${cardSection(`
        <div class="card-head">
          <h2>Members <span class="muted" style="font-weight:500;">(${members.total})</span></h2>
          <form method="GET" class="inline-field" style="margin:0;">
            <input type="search" name="search" value="${escapeHtml(search)}" placeholder="Find a person by name or UPN" style="margin:0; width:260px;" />
            <button class="secondary" type="submit">Search</button>
          </form>
        </div>
        ${
          members.rows.length
            ? `<table><thead><tr><th>Name</th><th>UPN</th><th></th></tr></thead><tbody>
                ${members.rows
                  .map(
                    (u) => `<tr><td>${avatar(u.id, u.display_name, "sm", { upn: u.upn })}${escapeHtml(u.display_name)}</td><td>${escapeHtml(u.upn)}</td><td style="text-align:right;"><form method="POST" action="/account/groups/${group.id}/members/${u.id}/remove" style="margin:0;" ${confirmAttrs(`Remove ${u.display_name} from ${group.name}?`, { title: "Remove this member?", action: "Remove" })}><button class="link-button" type="submit">Remove</button></form></td></tr>`
                  )
                  .join("")}
              </tbody></table>
              ${paginationControls(`/account/groups/${group.id}`, page, pages, { search })}`
            : `<p class="muted">${search ? `Nobody in this group matches "${escapeHtml(search)}".` : "No members yet."}</p>`
        }
        <form method="POST" action="/account/groups/${group.id}/members" style="margin-top:14px;">
          <label>Add people</label>
          ${remoteMultiSelect("user_ids", `/account/groups/${group.id}/people`, [], "Search people...")}
          <div class="row" style="justify-content:flex-start;"><button class="primary" type="submit">Add to group</button></div>
        </form>
      `)}
      `,
      user.upn
    )
  );
});

// People a manager can still add to their group: active and not already in it.
account.get("/account/groups/:id/people", async (c) => {
  const user = c.get("user");
  const groupId = Number(c.req.param("id"));
  const q = (c.req.query("q") ?? "").trim().toLowerCase().slice(0, 100);
  if (!q || !(await isGroupManager(c.env, user.id, groupId))) return c.json([]);
  const like = `%${q.replace(/[%_]/g, (m) => `\\${m}`)}%`;
  const { results } = await c.env.DB.prepare(
    `SELECT id, display_name, upn FROM users
     WHERE status = 'active' AND id NOT IN (SELECT user_id FROM group_members WHERE group_id = ?)
       AND (lower(display_name) LIKE ? ESCAPE '\\' OR lower(upn) LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\')
     ORDER BY display_name LIMIT 20`
  )
    .bind(groupId, like, like, like)
    .all<{ id: number; display_name: string; upn: string }>();
  return c.json(results.map((u) => ({ id: u.id, label: u.display_name, desc: u.upn })));
});

account.post("/account/groups/:id/members", async (c) => {
  const ctx = consoleCtx(c);
  const groupId = Number(c.req.param("id"));
  const body = await c.req.parseBody({ all: true });
  const userIds = (Array.isArray(body.user_ids) ? body.user_ids.map(String) : body.user_ids === undefined ? [] : [String(body.user_ids)]).map(Number).filter(Boolean);
  try {
    await assertMayManageGroup(ctx, groupId);
    await addGroupMembers(ctx, groupId, userIds);
    return c.redirect(`/account/groups/${groupId}?saved=members`, 302);
  } catch (e) {
    return c.redirect(`/account/groups/${groupId}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

account.post("/account/groups/:id/members/:uid/remove", async (c) => {
  const ctx = consoleCtx(c);
  const groupId = Number(c.req.param("id"));
  try {
    await assertMayManageGroup(ctx, groupId);
    await removeGroupMember(ctx, groupId, Number(c.req.param("uid")));
    return c.redirect(`/account/groups/${groupId}?saved=members`, 302);
  } catch (e) {
    return c.redirect(`/account/groups/${groupId}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

account.post("/account/groups/:id/requests/:rid", async (c) => {
  const ctx = consoleCtx(c);
  const groupId = Number(c.req.param("id"));
  const body = await c.req.parseBody();
  try {
    const req = await getAccessRequest(c.env, Number(c.req.param("rid")));
    if (!req || req.target_type !== "group" || req.target_id !== groupId) throw new ServiceError(404, "That request doesn't exist any more.");
    await assertMayManageGroup(ctx, groupId);
    const decision = String(body.decision ?? "");
    if (decision !== "approved" && decision !== "denied") throw new ServiceError(400, "Pick Approve or Deny.");
    await decideAccessRequest(ctx, req.id, decision, String(body.note ?? ""));
    return c.redirect(`/account/groups/${groupId}?saved=request`, 302);
  } catch (e) {
    return c.redirect(`/account/groups/${groupId}?error=${encodeURIComponent(e instanceof Error ? e.message : String(e))}`, 302);
  }
});

account.get("/account/security", async (c) => {
  const user = c.get("user");
  const remainingBackupCodes = await countRemainingBackupCodes(c.env, user.id);
  const currentSessionId = c.get("sessionId");
  const sessions = await listActiveSessionsForUser(c.env, user.id);
  const devices = await listTrustedDevices(c.env, user.id);
  const passkeys = await listPasskeys(c.env, user.id);
  const isAdmin = c.get("access").isAdmin;
  // Only factors that work right now: one switched off is not offered here at all.
  const enrolled = enrolledFactors({ ...user, has_passkey: passkeys.length > 0, has_backup_codes: remainingBackupCodes > 0 });
  const usable = await Promise.all(enrolled.map((f) => isFactorUsable(c.env, f)));
  const factors = enrolled.filter((_, i) => usable[i]);
  const emailCard = (await emailOtpAvailable(c.env)) ? emailCodesCard(user, c.req.query("email_code") ?? "") : "";
  const kbaCard = (await securityQuestionsAvailable(c.env))
    ? isAdmin
      ? adminSecurityQuestionsCard(user, c.req.query("kba_error") ?? "")
      : await securityQuestionsCard(c.env, user, c.req.query("kba_error") ?? "")
    : "";
  // A person with an authenticator manages its set inside that card; this one
  // serves everyone else who holds a real factor (or codes to refresh).
  const backupCard =
    !user.mfa_enabled && (await isFactorUsable(c.env, "backup_codes"))
      ? backupCodesCard(
          remainingBackupCodes,
          !(await isFreshlyAuthenticated(c.env, currentSessionId)),
          remainingBackupCodes > 0 || (await hasSecondFactor(c.env, user, { admin: isAdmin }))
        )
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
      "Security",
      `
      ${savedBanner(c)}
      <div class="two-col">
        ${cardSection(`
          <div class="row between">
            <h2 style="margin:0;">Authenticator app</h2>
            <span class="badge ${user.mfa_enabled ? "badge-active" : "badge-disabled"}">${user.mfa_enabled ? "Enabled" : "Not set up"}</span>
          </div>
          <p class="muted" id="second-factors" style="margin-top:8px;">${
            factors.length
              ? `Your second factors: ${factors.map((f) => FACTOR_SHORT_LABELS[f] + (f === "security_questions" && isAdmin ? " (not accepted for administrators)" : "")).join(", ")}.`
              : "You have no second factor yet. Set up an authenticator app, a passkey or another factor below."
          }</p>
          ${
            user.mfa_enabled
              ? `<p class="muted" style="margin-top:8px;">${remainingBackupCodes} backup code(s) remaining.</p>
                 <form method="POST" action="/account/mfa/backup-codes/regenerate" style="margin-bottom:14px;" ${confirmAttrs("Your existing backup codes stop working immediately, and you will be shown a new set once.", { title: "Generate new backup codes?", action: "Regenerate" })}>
                   <label for="regen_code">Enter a current code from your authenticator (or a backup code)</label>
                   <input type="text" id="regen_code" name="code" maxlength="12" required autocomplete="one-time-code" style="max-width:160px" />
                   <button class="secondary" type="submit">Regenerate backup codes</button>
                 </form>
                 <form method="POST" action="/account/mfa/disable" ${confirmAttrs("Your authenticator is removed and every remembered device is forgotten. Backup codes stay enrolled.", { title: "Disable two-factor authentication?", action: "Disable MFA", danger: true })}>
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
                ${passkeys.map((p) => `<tr><td>${escapeHtml(p.name)}</td><td>${ts(p.created_at, { dateOnly: true })}</td><td>${p.last_used_at ? escapeHtml(relativeTime(p.last_used_at)) : "never"}</td>
                  <td><form method="POST" action="/account/passkeys/${encodeURIComponent(p.id)}/remove" ${confirmAttrs("You will no longer be able to sign in with this passkey.", { title: "Remove this passkey?", action: "Remove passkey", danger: true })}><button class="link-button" type="submit">Remove</button></form></td></tr>`).join("")}
              </tbody></table>`
            : '<p class="muted">No passkeys yet.</p>'
        }
        <div class="row" style="justify-content:flex-start; gap:8px; margin-top:10px;">
          <input type="text" id="passkey-name" placeholder="Name (e.g. MacBook)" maxlength="60" style="max-width:220px; margin:0;" />
          <input type="password" id="passkey-confirm" placeholder="Current password" autocomplete="current-password" maxlength="1024" style="max-width:180px; margin:0; display:none;" />
          <button class="secondary" type="button" data-passkey-register>Add a passkey</button>
        </div>
        <p class="muted" id="passkey-status" style="margin-top:8px;"></p>
        ${scriptTag(PASSKEY_REGISTER_SCRIPT)}
      `)}

      ${emailCard}

      ${kbaCard}

      ${backupCard}

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
                  <td>${ts(s.created_at)}</td>
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
                        <td>${ts(d.created_at)}</td>
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

/**
 * My account > Security: the emergency backup-code set, for a user without an
 * authenticator app (one manages its set inside that card). A first set can't
 * be minted before a real factor exists - enrolment hands the set out - but
 * an existing set can be refreshed or removed here. Generating or removing
 * proves the session is fresh or knows the password, as a passkey enrolment.
 */
function backupCodesCard(remaining: number, needsPassword: boolean, canGenerate: boolean): string {
  const passwordField = (id: string) =>
    needsPassword ? `<label for="${id}">Confirm with your password</label><input type="password" id="${id}" name="password" autocomplete="current-password" required style="max-width:220px;" />` : "";
  const body =
    remaining > 0
      ? `<p class="muted" style="margin-top:8px;">${remaining} code(s) remaining - each can be used once to sign in.</p>
         <form method="POST" action="/account/mfa/backup-codes/generate" style="margin-bottom:14px;" ${confirmAttrs("Your existing backup codes stop working immediately, and you will be shown a new set once.", { title: "Generate new backup codes?", action: "Generate" })}>
           ${passwordField("bc_gen_password")}
           <button class="secondary" type="submit">Generate a new set</button>
         </form>
         <form method="POST" action="/account/backup-codes/remove" ${confirmAttrs("Your backup codes stop working immediately.", { title: "Remove backup codes?", action: "Remove codes", danger: true })}>
           ${passwordField("bc_rm_password")}
           <button class="danger" type="submit">Remove backup codes</button>
         </form>`
      : canGenerate
        ? `<p class="muted" style="margin-top:8px;">Ten single-use codes to print or keep somewhere safe; each one signs you in once, for when you cannot use another method.</p>
         <form method="POST" action="/account/mfa/backup-codes/generate">
           ${passwordField("bc_gen_password")}
           <button class="primary" type="submit">Generate backup codes</button>
         </form>`
        : `<p class="muted" style="margin-top:8px;">Single-use codes for when you cannot use another method. They are issued automatically when you set up a sign-in method such as an authenticator app or a passkey.</p>`;
  return cardSection(`
    <div class="row between" id="backup-codes">
      <h2 style="margin:0;">Backup codes</h2>
      <span class="badge ${remaining > 0 ? "badge-active" : "badge-disabled"}">${remaining > 0 ? "Enabled" : "Not set up"}</span>
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
  // A cleared custom field is removed, not kept at its old value. hasOwn:
  // the `in` check would treat an attribute named "constructor" as a column.
  for (const a of editable) if (!values[a.name] && !Object.hasOwn(columns, a.name)) delete mergedCustom[a.name];
  const columnNames = Object.keys(columns).filter((k) => /^[a-z_]+$/.test(k));
  await c.env.DB.prepare(
    `UPDATE users SET ${[...columnNames.map((k) => `${k} = ?`), "custom_attributes = ?", "updated_at = ?"].join(", ")} WHERE id = ?`
  )
    .bind(...columnNames.map((k) => columns[k] ?? ""), JSON.stringify(mergedCustom), new Date().toISOString(), user.id)
    .run();
  await logAudit(c.env, user, "user.profile_updated_self", user.upn, { fields: editable.map((a) => a.name) }, c.req.raw);
  if (await isScimConfigured(c.env)) {
    const fresh = await getUserById(c.env, user.id);
    if (fresh) c.executionCtx.waitUntil(pushUser(c.env, fresh).catch((err) => console.error(JSON.stringify({ event: "scim_push_failed", error: String(err) }))));
  }
  return c.redirect("/account?saved=profile", 302);
});

/**
 * Any signed-in person can view any user's photo - a directory shows faces.
 * Served from the account app so the session cookie gates it; images on
 * admin pages load through here too.
 */
account.get("/account/photo/:uid", async (c) => {
  const photo = await getUserPhoto(c.env, Number(c.req.param("uid")));
  // A miss must never cache: the pre-upload 404 would hide a new photo for
  // minutes. Hits keep a short private cache; ?v= busts it on replace.
  if (!photo) return c.body(null, 404, { "cache-control": "no-store" });
  return new Response(photo.data, {
    headers: {
      "content-type": photo.content_type,
      "content-length": String(photo.data.byteLength),
      "cache-control": "private, max-age=300",
      "x-content-type-options": "nosniff",
    },
  });
});

account.post("/account/photo", async (c) => {
  const user = c.get("user");
  if ((await getMasteredFields(c.env)).includes("photo")) return c.html(errorRedirectPage(c, "Your photo comes from your HR system - it can't be changed here."));
  const body = await c.req.parseBody();
  const file = body.photo;
  if (!(file instanceof File) || file.size === 0) return c.html(errorRedirectPage(c, "Choose an image file to upload."));
  if (file.size > MAX_PHOTO_BYTES) return c.html(errorRedirectPage(c, "Photos are limited to 1 MB - crop or resize it and try again."));
  const buf = await file.arrayBuffer();
  const type = sniffImageType(buf);
  if (!type) return c.html(errorRedirectPage(c, "That doesn't look like a PNG, JPG, WebP or GIF image."));
  await setUserPhoto(c.env, user.id, buf, type);
  await logAudit(c.env, user, "user.photo_updated_self", user.upn, undefined, c.req.raw);
  return c.redirect("/account?saved=photo", 302);
});

account.post("/account/photo/remove", async (c) => {
  const user = c.get("user");
  if ((await getMasteredFields(c.env)).includes("photo")) return c.html(errorRedirectPage(c, "Your photo comes from your HR system - it can't be changed here."));
  await deleteUserPhoto(c.env, user.id);
  return c.redirect("/account?saved=photo", 302);
});

// Feeds the request-access picker's search-as-you-type: only the requestable
// static groups this person could still ask for, as {id, label, desc} items.
account.get("/account/access/targets", async (c) => {
  const q = (c.req.query("q") ?? "").trim().toLowerCase().slice(0, 100);
  if (!q) return c.json([]);
  const user = c.get("user");
  const [groups, roleMap, apps] = await Promise.all([
    requestableGroups(c.env, user.id, q, 20),
    groupRolesMap(c.env),
    requestableApps(c.env, user.id, await getUserGroupIds(c.env, user.id), q),
  ]);
  return c.json([
    ...groups.map((g) => {
      const roles = roleMap.get(g.id) ?? [];
      return {
        id: `group:${g.id}`,
        label: g.name,
        // Asking for a role-bearing group is asking for the roles - name them,
        // with each role's own description, before the group's.
        badges: roles.map((r) => ({ label: r.name, title: r.description })),
        desc: [...roles.map((r) => `Grants ${r.name}${r.description ? ` — ${r.description}` : ""}`), ...(g.description ? [g.description] : [])].join(" · "),
      };
    }),
    ...apps.map((a) => ({
      id: `${a.target_type}:${a.id}`,
      label: a.name,
      badges: [{ label: a.protocol, title: `${a.protocol} application` }],
      desc: "Application - approved requests add you to its assigned people",
    })),
  ]);
});

account.post("/account/access/request", async (c) => {
  const body = await c.req.parseBody();
  try {
    const m = String(body.target ?? "").match(/^(group|oidc_app|saml_app):(\d+)$/);
    if (!m) throw new ServiceError(400, "Pick a group or app to ask for.");
    await requestAccess(consoleCtx(c), { type: m[1] as AccessTargetType, id: Number(m[2]) }, String(body.reason ?? ""));
  } catch (e) {
    return c.html(errorRedirectPage(c, e instanceof Error ? e.message : "That didn't work."));
  }
  return c.redirect("/account/access?saved=access-requested", 302);
});

account.post("/account/access/requests/:id/cancel", async (c) => {
  try {
    await cancelAccessRequest(consoleCtx(c), Number(c.req.param("id")));
  } catch (e) {
    return c.html(errorRedirectPage(c, e instanceof Error ? e.message : "That didn't work."));
  }
  return c.redirect("/account/access?saved=access-cancelled", 302);
});

account.post("/account/devices/:id/revoke", async (c) => {
  const user = c.get("user");
  const deviceId = c.req.param("id");
  await revokeTrustedDevice(c.env, user.id, deviceId);
  await logAudit(c.env, user, "user.device_revoked_self", user.upn, undefined, c.req.raw);
  return c.redirect("/account/security?saved=device", 302);
});

account.post("/account/sessions/:id/revoke", async (c) => {
  const user = c.get("user");
  const sessionId = c.req.param("id");
  const sessions = await listActiveSessionsForUser(c.env, user.id);
  if (sessions.some((s) => s.id === sessionId)) {
    await revokeSession(c.env, sessionId);
    await logAudit(c.env, user, "user.session_revoked_self", user.upn, undefined, c.req.raw);
    c.executionCtx.waitUntil(
      emitAndDrain(c.env, SSF_EVENTS["caep.session-revoked"], { format: "email", email: user.upn }).catch(() => undefined)
    );
  }
  return c.redirect("/account/security?saved=session", 302);
});

account.post("/account/sessions/revoke-others", async (c) => {
  const user = c.get("user");
  const count = await revokeAllSessionsForUser(c.env, user.id, c.get("sessionId"));
  await logAudit(c.env, user, "user.sessions_revoked_all_others", user.upn, { count }, c.req.raw);
  if (count > 0) {
    c.executionCtx.waitUntil(
      emitAndDrain(c.env, SSF_EVENTS["caep.session-revoked"], { format: "email", email: user.upn }).catch(() => undefined)
    );
  }
  return c.redirect("/account/security?saved=sessions-others", 302);
});

account.post("/account/apps/:clientDbId/revoke", async (c) => {
  const user = c.get("user");
  const clientDbId = Number(c.req.param("clientDbId"));
  const client = await c.env.DB.prepare("SELECT client_id, name FROM oauth_clients WHERE id = ?")
    .bind(clientDbId)
    .first<{ client_id: string; name: string }>();
  if (!client) return c.redirect("/account/security", 302);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?").bind(user.id, client.client_id),
    // An authorized-but-unexchanged code dies with the grant, the same
    // contract revokeTokensForUser applies to the whole account.
    c.env.DB.prepare("DELETE FROM auth_codes WHERE user_id = ? AND client_id = ?").bind(user.id, client.client_id),
    c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ?").bind(
      new Date().toISOString(),
      user.id,
      client.client_id
    ),
    // Revoking access withdraws consent too: the app has to ask again.
    c.env.DB.prepare("DELETE FROM oauth_consents WHERE user_id = ? AND client_id = ?").bind(user.id, client.client_id),
  ]);
  await logAudit(c.env, user, "user.app_access_revoked_self", client.name, undefined, c.req.raw);

  return c.redirect("/account/security?saved=app", 302);
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

/**
 * Adding or removing a sign-in credential needs a recent sign-in or the
 * current password, within the step-up budget - a session cookie left behind
 * (or stolen) must not mint a passkey, which thereafter signs in as a full
 * multi-factor credential. A freshly-signed-in session (including the forced
 * enrolment flow straight after login) passes without the extra proof.
 */
async function passkeyStepUp(c: Context<{ Bindings: Env }>, password: string): Promise<"fresh" | "password" | "denied" | "budget"> {
  if (await isFreshlyAuthenticated(c.env, c.get("sessionId"))) return "fresh";
  if (await stepUpBudgetExceeded(c)) return "budget";
  return password.length > 0 && (await verifyPassword(password.slice(0, 1024), c.get("user"))) ? "password" : "denied";
}

/** A current TOTP (claimed, so it cannot be replayed) or an unused backup code. */
async function secondFactorOk(c: Context<{ Bindings: Env }>, code: string): Promise<"totp" | "backup_code" | null> {
  const user = c.get("user");
  const counter = user.totp_secret ? await matchTotpCounter((await unsealMaybe(c.env, user.totp_secret)) ?? "", code) : null;
  if (counter !== null && (await claimTotpCounter(c.env, user.id, counter))) return "totp";
  if (await verifyAndConsumeBackupCode(c.env, user.id, code)) return "backup_code";
  return null;
}

account.get("/account/passkeys/options", async (c) => {
  if (!(await isFactorEnabled(c.env, "passkey"))) return c.json({ error: "Passkeys are not enabled." }, 403);
  const user = c.get("user");
  return c.json(await registrationOptions(c.env, c.get("sessionId"), user));
});

account.post("/account/passkeys", async (c) => {
  const user = c.get("user");
  const sessionId = c.get("sessionId");
  if (!(await isFactorEnabled(c.env, "passkey"))) return c.json({ ok: false, error: "Passkeys are not enabled." }, 403);
  const body = await c.req.json<{ response?: unknown; name?: string; password?: string }>().catch(() => ({}) as { response?: unknown; name?: string; password?: string });
  const step = await passkeyStepUp(c, String(body.password ?? ""));
  if (step === "budget") return c.json({ ok: false, error: "Too many attempts. Please wait a few minutes." }, 429);
  if (step === "denied") {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "passkey_add" }, c.req.raw);
    return c.json({ ok: false, error: "Enter your current password to add a passkey.", needsPassword: true }, 403);
  }
  const error = body.response ? await finishRegistration(c.env, sessionId, user.id, body.response as never, String(body.name ?? "")) : "Missing response.";
  if (error) return c.json({ ok: false, error }, 400);
  // Registering a passkey is itself a user-verified factor ceremony by this
  // session, so its amr gains hwk+mfa here - atomically with the credential.
  // (Doing it later, at /account/mfa/passkey-enrolled, left a window where the
  // stored credential made the gate say "login" and killed the mid-ceremony
  // session - and let a different session claim the upgrade.)
  const row = await c.env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sessionId).first<{ amr: string }>();
  const previous = row ? (JSON.parse(row.amr) as string[]) : ["pwd"];
  await c.env.DB.prepare("UPDATE sessions SET amr = ? WHERE id = ?").bind(JSON.stringify([...new Set([...previous, "hwk", "mfa"])]), sessionId).run();
  await logAudit(c.env, user, "user.passkey_added", user.upn, { name: String(body.name ?? "").slice(0, 60) }, c.req.raw);
  return c.json({ ok: true });
});

account.get("/account/passkeys/:id/remove", async (c) => {
  const user = c.get("user");
  const id = decodeURIComponent(c.req.param("id") ?? "");
  const passkey = (await listPasskeys(c.env, user.id)).find((p) => p.id === id);
  if (!passkey) return c.redirect("/account/security#passkeys", 302);
  const fresh = await isFreshlyAuthenticated(c.env, c.get("sessionId"));
  return c.html(
    layout(
      c,
      "Remove passkey",
      cardSection(`
        <h2>Remove this passkey?</h2>
        <p>You will no longer be able to sign in with <strong>${escapeHtml(passkey.name)}</strong>.</p>
        ${c.req.query("error") ? `<p class="error">${escapeHtml(c.req.query("error")!)}</p>` : ""}
        <form method="POST" action="/account/passkeys/${encodeURIComponent(id)}/remove">
          ${fresh ? "" : `<label for="pk_current_password">You signed in a while ago - confirm your password to remove it.</label><input type="password" id="pk_current_password" name="current_password" required autocomplete="current-password" maxlength="1024" style="max-width:320px;" />`}
          <div class="form-actions"><button class="danger" type="submit">Remove passkey</button><a class="button secondary" href="/account/security#passkeys">Cancel</a></div>
        </form>`)
    )
  );
});

account.post("/account/passkeys/:id/remove", async (c) => {
  const user = c.get("user");
  const id = decodeURIComponent(c.req.param("id") ?? "");
  const back = (q: string) => c.redirect(`/account/passkeys/${encodeURIComponent(id)}/remove${q ? `?error=${encodeURIComponent(q)}` : ""}`, 303);
  if (!(await isFreshlyAuthenticated(c.env, c.get("sessionId")))) {
    const body = await c.req.parseBody();
    const password = String(body.current_password ?? "");
    if (!password) return back(""); // the row form has no field for it - ask on the confirm page
    if (await stepUpBudgetExceeded(c)) return back("Too many attempts. Please wait a few minutes.");
    if (!(await verifyPassword(password.slice(0, 1024), user))) {
      await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "passkey_remove" }, c.req.raw);
      return back("That password is not right.");
    }
  }
  await removePasskey(c.env, user.id, id);
  await logAudit(c.env, user, "user.passkey_removed", user.upn, undefined, c.req.raw);
  return c.redirect("/account/security?saved=passkey-removed", 302);
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

  // A password change is a compromise response. Every session ends - this
  // one included, because a stolen copy of its cookie value must die with
  // the row - and the browser gets a fresh session id carrying the same
  // assurances, so the legitimate user is never interrupted. Passkeys go
  // too: one registered by a session the compromise included would keep
  // signing in without a password.
  const amr = JSON.parse((await c.env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(c.get("sessionId")).first<{ amr: string }>())?.amr ?? '["pwd"]') as string[];
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(new Date().toISOString(), user.id),
    c.env.DB.prepare("DELETE FROM webauthn_credentials WHERE user_id = ?").bind(user.id),
  ]);
  await revokeTokensForUser(c.env, user.id);
  const rotated = await createSession(c.env, user.id, amr, c.req.raw);

  await logAudit(c.env, user, "user.password_changed_self", user.upn, undefined, c.req.raw);
  c.executionCtx.waitUntil(
    emitAndDrain(c.env, SSF_EVENTS["caep.credential-change"], { format: "email", email: user.upn }).catch(() => undefined)
  );

  const res = c.redirect("/account/security?saved=password", 302);
  for (const sc of rotated.setCookies) res.headers.append("Set-Cookie", sc);
  return res;
});

function errorRedirectPage(c: Context<{ Bindings: Env }>, message: string) {
  return layout(c, "My account", `<p class="error">${escapeHtml(message)}</p><a href="/account">Back to account</a>`);
}

account.get("/account/mfa/setup", async (c) => {
  const user = c.get("user");
  const resume = c.req.query("resume") ?? "";
  // Redirect only when a usable second factor exists - mfa_enabled can outlive
  // its factor being switched off, and an 'enrol'-gated session would loop
  // between this page and the gate that sent it here.
  if (await hasSecondFactor(c.env, user, { admin: Boolean(c.get("access")?.isAdmin) })) return c.redirect("/account/security", 302);
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

  // Enrolling a credential from a session that isn't freshly authenticated
  // needs the password again - a hijacked session must not be able to plant a
  // factor that survives a password reset.
  const needsPassword = !(await isFreshlyAuthenticated(c.env, c.get("sessionId")));
  const passwordField = !needsPassword
    ? ""
    : `<div style="text-align:left; margin-top:10px;"><label for="enrol_password">Confirm with your password</label><input type="password" id="enrol_password" name="password" autocomplete="current-password" required style="max-width:220px;" /></div>`;

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
          ${needsPassword ? `<label for="kba_current_password">Confirm with your password</label><input type="password" id="kba_current_password" name="current_password" autocomplete="current-password" required />` : ""}
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
          ${c.req.query("error") === "2" ? '<p class="error">Incorrect password, please try again.</p>' : ""}
          ${c.req.query("error") === "3" ? '<p class="error">Too many attempts. Please wait a few minutes before trying again.</p>' : ""}
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
            ${passwordField}
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
  const sessionId = c.get("sessionId");
  const resume = String((await c.req.parseBody()).resume ?? "");
  // Only the session that ran the registration ceremony - its amr gained hwk
  // when the credential was stored - finishes here. Any other session with the
  // same credential recency gets sent back to start.
  const session = await c.env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sessionId).first<{ amr: string }>();
  const amr = session ? (JSON.parse(session.amr) as string[]) : [];
  if (!amr.includes("hwk")) return c.redirect(`/account/mfa/setup?resume=${encodeURIComponent(resume)}`, 302);
  await revokeAllSessionsForUser(c.env, user.id, sessionId);
  await logAudit(c.env, user, "user.mfa_enrolled_passkey", user.upn, undefined, c.req.raw);
  const passkeyDest = resume ? await resumeLoginFlow(c.env, c.req.raw, resume, user.id, sessionId) : { to: "/account/security?saved=passkey-added" };
  return finishEnrolment(c, user.id, passkeyDest, "Passkey added. Here are your emergency backup codes.");
});

account.post("/account/mfa/setup", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const code = String(body.code ?? "");
  const resume = String(body.resume ?? "");

  // The administrator's off switch is consulted when the page renders; it must
  // also gate the write, or a stale/forged form enrols a disabled factor.
  if (!(await isFactorEnabled(c.env, "totp"))) return c.redirect("/account/security", 302);
  // Enrolment changes account credentials: a session that isn't fresh must
  // prove the password again, the same rule passkey registration follows.
  const step = await passkeyStepUp(c, String(body.password ?? ""));
  if (step === "budget") return c.redirect(`/account/mfa/setup?error=3&resume=${encodeURIComponent(resume)}`, 302);
  if (step === "denied") return c.redirect(`/account/mfa/setup?error=2&resume=${encodeURIComponent(resume)}`, 302);

  const secret = await getPendingEnrollment(c.env, c.get("sessionId"));
  if (!secret) return c.html(errorPage(c.get("appName"), 400, "The set-up session expired. Start setting up the authenticator app again.", "/account/mfa/setup", Boolean(c.get("access")?.isAdmin), c.get("logoUrl")), 400);

  const counter = await matchTotpCounter(secret, code);
  if (counter === null) {
    return c.redirect(`/account/mfa/setup?error=1&resume=${encodeURIComponent(resume)}`, 302);
  }
  // One pending secret, one enrolment: claimed before the credential write so
  // a replayed submission cannot re-arm the factor.
  if (!(await markConsumed(c.env, `enroll:${c.get("sessionId")}`))) return c.redirect("/account/mfa/setup", 302);

  // totp_last_counter starts at the code that proved enrolment, so that very
  // code cannot be replayed at /login/mfa or /account/mfa/disable.
  await c.env.DB.prepare(
    "UPDATE users SET totp_secret = ?, mfa_enabled = 1, totp_last_counter = ?, updated_at = ? WHERE id = ?"
  )
    .bind(await sealMaybe(c.env, secret), counter, new Date().toISOString(), user.id)
    .run();
  await deletePendingEnrollment(c.env, c.get("sessionId"));
  // Every other session predates the second factor (a password-only session
  // from the forced-enrolment login, say): end them, as a password change does.
  await revokeAllSessionsForUser(c.env, user.id, c.get("sessionId"));
  await c.env.DB.prepare("UPDATE sessions SET amr = ? WHERE id = ?").bind(JSON.stringify(["pwd", "mfa"]), c.get("sessionId")).run();
  await logAudit(c.env, user, "user.mfa_enabled", user.upn, undefined, c.req.raw);

  const continueTo = resume ? await resumeLoginFlow(c.env, c.req.raw, resume, user.id, c.get("sessionId")) : { to: "/account" };
  return finishEnrolment(c, user.id, continueTo, "MFA is now enabled. Here are your emergency backup codes.");
});

/** Completes a login flow that was paused for forced MFA enrollment, returning where to send the user next. */
async function resumeLoginFlow(env: Env, request: Request, resumeFlowId: string, userId: number, sessionId: string, amr: string[] = ["pwd", "mfa"]): Promise<{ to: string; responseMode?: string }> {
  // Only a flow this user parked after authenticating: never a sealed
  // anonymous one, which would let enrolment stand in for a fresh login.
  if (isSealedFlowId(resumeFlowId)) return { to: "/account" };
  const flow = await getLoginFlow(env, resumeFlowId);
  if (!flow || flow.resumeFor !== userId) return { to: "/account" };
  // The factor just enrolled must satisfy the gate (security questions never
  // do for an administrator): otherwise the flow stays parked at enrolment.
  const user = await getUserById(env, userId);
  if (!user || (await secondFactorGate(env, user, amr)) !== "ok") return { to: `/account/mfa/setup?resume=${encodeURIComponent(resumeFlowId)}` };

  if (flow.kind === "direct") {
    await deleteLoginFlow(env, resumeFlowId);
    return { to: safeNextPath(flow.next) };
  }

  // A SAML flow can't finish here - it ends in a POST form, not a URL. The
  // flow stays in KV and /saml/complete issues the response when the user
  // clicks through. The binding is what marks it "paused after a completed
  // login": without it /saml/complete refuses the flow (see saml.ts).
  if (flow.kind === "saml") {
    await bindFlowToUser(env, resumeFlowId, userId);
    return { to: `/saml/complete?flow=${resumeFlowId}` };
  }

  await deleteLoginFlow(env, resumeFlowId);
  const { redirectTo } = await finishOidcAuthorize(env, request, flow.request, userId, amr, sessionId);
  return { to: redirectTo, responseMode: flow.request.responseMode };
}

// ---------- Email one-time codes ----------
// Under /account/mfa so a session that still owes its policy a second factor
// (forced enrolment) can reach them, like the other enrolment routes.

/** Where an email-code action goes back to: the forced-enrolment page it came from, or My account. */
function emailCodeReturn(body: Record<string, unknown>, query: string): string {
  if (body.from === "setup") return `/account/mfa/setup?resume=${encodeURIComponent(String(body.resume ?? ""))}&${query}`;
  return `/account/security?${query}#email-codes`;
}

account.post("/account/mfa/email/send", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const purpose = body.purpose === "disable" ? "disable" : "enrol";
  if (!(await emailOtpAvailable(c.env))) return c.redirect(emailCodeReturn(body, "error=email-unavailable"), 302);
  if ((purpose === "enrol") === Boolean(user.email_otp_enabled)) return c.redirect("/account/security", 302);
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
  if (user.email_otp_enabled) return c.redirect("/account/security", 302);
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
  const emailOtpDest = resume ? await resumeLoginFlow(c.env, c.req.raw, resume, user.id, sessionId, amr) : { to: "/account/security?saved=email-otp-enabled" };
  return finishEnrolment(c, user.id, emailOtpDest, "Email codes turned on. Here are your emergency backup codes.");
});

/** Turning email codes off takes a fresh code, within the step-up budget - as disabling the authenticator does. */
account.post("/account/mfa/email/disable", async (c) => {
  const user = c.get("user");
  if (!user.email_otp_enabled) return c.redirect("/account/security", 302);
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account/security?error=too-many#email-codes", 302);
  const result = await verifyEmailOtp(c.env, accountScope(c.get("sessionId")), user.id, "disable", String((await c.req.parseBody()).code ?? ""));
  if (result !== "ok") {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "email_otp_disable", reason: result }, c.req.raw);
    return c.redirect(`/account/security?${result === "wrong" ? "email_code=disable&" : ""}error=email-code#email-codes`, 302);
  }
  await c.env.DB.prepare("UPDATE users SET email_otp_enabled = 0, updated_at = ? WHERE id = ?").bind(new Date().toISOString(), user.id).run();
  await logAudit(c.env, user, "user.email_otp_disabled", user.upn, undefined, c.req.raw);
  return c.redirect("/account/security?saved=email-otp-disabled", 302);
});

// ---------- Security questions ----------
// Under /account/mfa so a session that still owes its policy a second factor
// (forced enrolment) can reach them, like the other enrolment routes.

/** Where a security-questions action goes back to: the forced-enrolment page it came from, or My account. */
function kbaReturn(body: Record<string, unknown>, query: string): string {
  if (body.from === "setup") return `/account/mfa/setup?resume=${encodeURIComponent(String(body.resume ?? ""))}&${query}`;
  return `/account/security?${query}#security-questions`;
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
  } else {
    // Setting questions for the first time mints a factor: same step-up rule
    // as TOTP and passkeys (fresh session, or the current password).
    const step = await passkeyStepUp(c, String(body.current_password ?? ""));
    if (step === "budget") return c.redirect(kbaReturn(body, "kba_error=kba-too-many"), 302);
    if (step === "denied") {
      await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "security_questions_set" }, c.req.raw);
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
    return c.redirect("/account/security?saved=kba-changed", 302);
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
  const kbaDest = resume ? await resumeLoginFlow(c.env, c.req.raw, resume, user.id, sessionId, amr) : { to: "/account/security?saved=kba-enabled" };
  return finishEnrolment(c, user.id, kbaDest, "Security questions saved. Here are your emergency backup codes.");
});

/** Removing security questions takes the current password, within the step-up budget. */
account.post("/account/mfa/questions/remove", async (c) => {
  const user = c.get("user");
  if (!user.security_questions_enabled) return c.redirect("/account/security", 302);
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account/security?kba_error=kba-too-many#security-questions", 302);
  if (!(await verifyPassword(String((await c.req.parseBody()).current_password ?? "").slice(0, 1024), user))) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "security_questions_remove" }, c.req.raw);
    return c.redirect("/account/security?kba_error=kba-password#security-questions", 302);
  }
  await c.env.DB.batch(clearAnswersStatements(c.env, user.id));
  await logAudit(c.env, user, "user.security_questions_disabled", user.upn, undefined, c.req.raw);
  return c.redirect("/account/security?saved=kba-removed", 302);
});

/**
 * Where a completed factor enrolment goes next. The first factor a user
 * enrols hands out the emergency backup-code set - once, and only when the
 * instance allows codes and they hold no unused set (adding a second factor
 * later must not silently replace the codes they saved).
 */
async function finishEnrolment(c: Context<{ Bindings: Env }>, userId: number, dest: { to: string; responseMode?: string }, heading: string): Promise<Response> {
  if ((await isFactorEnabled(c.env, "backup_codes")) && !(await hasUnusedBackupCodes(c.env, userId))) {
    const codes = await generateBackupCodes(c.env, userId);
    return c.html(layout(c, "Backup codes", backupCodesPage(codes, dest, heading)));
  }
  return respondAuthorize(c, dest.to, dest.responseMode);
}

function backupCodesPage(codes: string[], continueTo: string | { to: string; responseMode?: string } = "/account", heading = "MFA is now enabled."): string {
  const fileContents = `${codes.join("\n")}\n`;
  const downloadHref = `data:text/plain;charset=utf-8,${encodeURIComponent(fileContents)}`;
  const dest = typeof continueTo === "string" ? { to: continueTo } : continueTo;
  // A form_post authorization can't continue through a plain link: the code
  // must arrive at the RP in a POST body, so the Continue button is a form.
  const continueEl =
    dest.responseMode === "form_post"
      ? (() => {
          const u = new URL(dest.to);
          const fields = [...u.searchParams].map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}" />`).join("");
          return `<form method="POST" action="${escapeHtml(u.origin + u.pathname)}">${fields}<button class="primary" type="submit">Continue</button></form>`;
        })()
      : `<a href="${escapeHtml(dest.to)}"><button class="primary" type="button">Continue</button></a>`;

  return cardSection(`
    <p class="success">${escapeHtml(heading)}</p>
    <p>Save these backup codes somewhere safe - each one can be used once to sign in. They won't be shown again.</p>
    <div style="background:var(--fi-surface-2); border:1px solid var(--fi-line); border-radius:10px; padding:14px 16px; font-family:monospace; font-size:1rem; line-height:1.8;">
      ${codes.map(escapeHtml).join("<br/>")}
    </div>
    <div class="row" style="justify-content:flex-start; margin-top:12px;">
      <a href="${downloadHref}" download="backup-codes.txt"><button class="secondary" type="button">Download backup-codes.txt</button></a>
    </div>
    <div class="row" style="margin-top:16px;">${continueEl}</div>
  `);
}

account.post("/account/mfa/backup-codes/regenerate", async (c) => {
  const user = c.get("user");
  if (!user.mfa_enabled) return c.redirect("/account/security", 302);
  // New codes are a second factor: issuing them needs one, as disabling MFA does.
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account/security?error=too-many", 302);
  const factor = await secondFactorOk(c, String((await c.req.parseBody()).code ?? ""));
  if (!factor) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "backup_codes_regenerate" }, c.req.raw);
    return c.redirect("/account/security?error=mfa-code", 302);
  }

  const codes = await generateBackupCodes(c.env, user.id);
  await logAudit(c.env, user, "user.mfa_backup_codes_regenerated", user.upn, undefined, c.req.raw);

  return c.html(layout(c, "Backup codes regenerated", backupCodesPage(codes)));
});

// Minting or refreshing a set from My account. Codes are an emergency
// fallback for an enrolled factor, never the first factor: a user holding
// neither a factor nor a set is sent to enrol a real method (this is also
// what stops a forced-enrolment session from satisfying its gate with codes).
account.post("/account/mfa/backup-codes/generate", async (c) => {
  const user = c.get("user");
  const body = await c.req.parseBody();
  const back = (query: string) => `/account/security?${query}#backup-codes`;

  if (!(await isFactorEnabled(c.env, "backup_codes"))) return c.redirect("/account/security", 302);
  const step = await passkeyStepUp(c, String(body.password ?? ""));
  if (step === "budget") return c.redirect(back("error=too-many"), 302);
  if (step === "denied") {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "backup_codes_generate" }, c.req.raw);
    return c.redirect(back("error=password"), 302);
  }

  if (!(await hasUnusedBackupCodes(c.env, user.id)) && !(await hasSecondFactor(c.env, user, { admin: Boolean(c.get("access")?.isAdmin) }))) {
    return c.redirect(back("error=no-factor"), 302);
  }
  const codes = await generateBackupCodes(c.env, user.id);
  await logAudit(c.env, user, "user.mfa_backup_codes_generated", user.upn, undefined, c.req.raw);

  return c.html(layout(c, "Backup codes", backupCodesPage(codes, "/account/security?saved=backup-codes", "Your backup codes are ready.")));
});

/** Removing the set is the same step-up as generating it. */
account.post("/account/backup-codes/remove", async (c) => {
  const user = c.get("user");
  if (!(await hasUnusedBackupCodes(c.env, user.id))) return c.redirect("/account/security", 302);
  const step = await passkeyStepUp(c, String((await c.req.parseBody()).password ?? ""));
  if (step === "budget") return c.redirect("/account/security?error=too-many#backup-codes", 302);
  if (step === "denied") {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "backup_codes_remove" }, c.req.raw);
    return c.redirect("/account/security?error=password#backup-codes", 302);
  }
  await deleteBackupCodes(c.env, user.id);
  await logAudit(c.env, user, "user.mfa_backup_codes_removed", user.upn, undefined, c.req.raw);
  return c.redirect("/account/security?saved=backup-codes-removed", 302);
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
  if (await stepUpBudgetExceeded(c)) return c.redirect("/account/security?error=too-many", 302);
  const factor = await secondFactorOk(c, code);
  const backupOk = factor === "backup_code";
  if (!factor) {
    await logAudit(c.env, user, "user.step_up_failed", user.upn, { action: "mfa_disable" }, c.req.raw);
    return c.redirect("/account/security?error=mfa-code", 302);
  }

  await c.env.DB.prepare(
    "UPDATE users SET totp_secret = NULL, mfa_enabled = 0, totp_last_counter = NULL, updated_at = ? WHERE id = ?"
  )
    .bind(new Date().toISOString(), user.id)
    .run();
  // Backup codes stay enrolled: they are a factor of their own now, removed
  // from the security page's card rather than as a side effect here.
  await deleteTrustedDevicesForUser(c.env, user.id);
  await logAudit(c.env, user, "user.mfa_disabled", user.upn, { with: backupOk ? "backup_code" : "totp" }, c.req.raw);

  return c.redirect("/account/security?saved=mfa-disabled", 302);
});

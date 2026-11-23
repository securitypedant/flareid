import type { Env } from "../env.js";
import { addGroupMembers, removeGroupMember } from "../services/groups.js";
import { audit, ServiceError, type ServiceCtx } from "../services/context.js";
import { appAccessAllowed, parseAssignedUserIds } from "./saml/service-providers.js";
import { getUserGroupIds } from "./db.js";
import type { GroupRow, OAuthClientRow, SamlServiceProviderRow, UserRow } from "./types.js";

/**
 * Access governance: self-service requests for group membership, and
 * certification campaigns that review it periodically.
 *
 * Both only ever touch explicit `group_members` rows. A dynamic group's
 * membership follows its rule - it is neither requestable on My account nor
 * revocable in a review, and campaign scope lists it for completeness but it
 * contributes no items.
 *
 * Requests: anyone signs in and asks to join a requestable static group;
 * someone who can write groups approves or denies in the console, and an
 * approval is the same membership write as editing the group - the SCIM push
 * and admin-role-group guards ride along.
 *
 * Campaigns: an admin names a set of groups; the explicit memberships at that
 * moment become review items, each certified or revoked (a revocation is
 * again an ordinary member removal). Closing ends the review; items still
 * pending stay recorded as unreviewed.
 */

const now = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Access requests
// ---------------------------------------------------------------------------

/** What a request can ask for: a static group, or either kind of application. */
export type AccessTargetType = "group" | "oidc_app" | "saml_app";
export type AccessTarget = { type: AccessTargetType; id: number };

export interface AccessRequestRow {
  id: number;
  user_id: number;
  target_type: AccessTargetType;
  target_id: number;
  reason: string;
  status: "pending" | "approved" | "denied" | "cancelled";
  decided_by: number | null;
  decided_at: string | null;
  note: string;
  created_at: string;
  updated_at: string;
}

export type AccessRequestView = AccessRequestRow & { upn: string; display_name: string; target_name: string };

/** Resolves a request's target name whichever table it lives in. */
const TARGET_NAME_JOINS = `LEFT JOIN groups g ON r.target_type = 'group' AND g.id = r.target_id
  LEFT JOIN oauth_clients oc ON r.target_type = 'oidc_app' AND oc.id = r.target_id
  LEFT JOIN saml_service_providers sp ON r.target_type = 'saml_app' AND sp.id = r.target_id`;
const TARGET_NAME = "COALESCE(g.name, oc.name, sp.name) AS target_name";

/**
 * Requestable static groups `userId` could still ask for: not already a
 * member of, and with no request still waiting (a decided one can be asked
 * again, so the decided statuses don't exclude).
 */
export async function requestableGroups(env: Env, userId: number, search = "", limit = 200): Promise<GroupRow[]> {
  const like = `%${search.replace(/[%_]/g, (m) => `\\${m}`)}%`;
  return (
    await env.DB.prepare(
      `SELECT * FROM groups WHERE requestable = 1 AND (rule IS NULL OR rule = '') AND (system IS NULL OR system = '')
        AND id NOT IN (SELECT group_id FROM group_members WHERE user_id = ?)
        AND id NOT IN (SELECT target_id FROM access_requests WHERE user_id = ? AND target_type = 'group' AND status = 'pending')
        AND id NOT IN (SELECT group_id FROM group_managers WHERE user_id = ?)
        AND (name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')
        ORDER BY name LIMIT ?`
    )
      .bind(userId, userId, userId, like, like, limit)
      .all<GroupRow>()
  ).results;
}

export async function myAccessRequests(env: Env, userId: number): Promise<AccessRequestView[]> {
  return (
    await env.DB.prepare(
      `SELECT r.*, u.upn, u.display_name, ${TARGET_NAME} FROM access_requests r
        JOIN users u ON u.id = r.user_id ${TARGET_NAME_JOINS}
        WHERE r.user_id = ? ORDER BY r.created_at DESC LIMIT 50`
    )
      .bind(userId)
      .all<AccessRequestView>()
  ).results;
}

export interface RequestableApp {
  target_type: "oidc_app" | "saml_app";
  id: number;
  name: string;
  protocol: "OIDC" | "SAML";
}

/**
 * Restricted apps marked requestable that `userId` cannot already reach and
 * has no pending ask for - the app half of the self-service list.
 */
export async function requestableApps(env: Env, userId: number, groupIds: number[], search = ""): Promise<RequestableApp[]> {
  const { results } = await env.DB.prepare(
    `SELECT 'oidc_app' AS target_type, id, name, access_mode, assigned_groups, assigned_users FROM oauth_clients WHERE requestable = 1
      UNION ALL SELECT 'saml_app', id, name, access_mode, assigned_groups, assigned_users FROM saml_service_providers WHERE requestable = 1`
  ).all<{ target_type: "oidc_app" | "saml_app"; id: number; name: string; access_mode: string; assigned_groups: string | null; assigned_users: string | null }>();
  const needle = search.trim().toLowerCase();
  const { results: pending } = await env.DB.prepare(
    "SELECT target_type, target_id FROM access_requests WHERE user_id = ? AND status = 'pending' AND target_type IN ('oidc_app','saml_app')"
  )
    .bind(userId)
    .all<{ target_type: string; target_id: number }>();
  const pendingSet = new Set(pending.map((r) => `${r.target_type}:${r.target_id}`));
  return results
    .filter((a) => a.access_mode !== "everyone")
    .filter((a) => !appAccessAllowed(a, groupIds, userId))
    .filter((a) => !pendingSet.has(`${a.target_type}:${a.id}`))
    .filter((a) => !needle || a.name.toLowerCase().includes(needle))
    .map((a) => ({ target_type: a.target_type, id: a.id, name: a.name, protocol: a.target_type === "oidc_app" ? "OIDC" : "SAML" }));
}

export interface AccessRequestQuery {
  /** One status, or undefined for every request. */
  status?: string;
  /** Matches the person's UPN or display name, the group name, or the reason. */
  search?: string;
  /** One group's requests (the managed-group page). */
  groupId?: number;
  limit?: number;
  offset?: number;
}

export async function listAccessRequests(env: Env, q: AccessRequestQuery = {}): Promise<{ total: number; rows: AccessRequestView[] }> {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (q.status) {
    conditions.push("r.status = ?");
    params.push(q.status);
  }
  const needle = q.search?.trim().toLowerCase();
  if (needle) {
    const like = `%${needle.replace(/[%_]/g, (m) => `\\${m}`)}%`;
    conditions.push("(lower(u.upn) LIKE ? ESCAPE '\\' OR lower(u.display_name) LIKE ? ESCAPE '\\' OR lower(COALESCE(g.name, oc.name, sp.name)) LIKE ? ESCAPE '\\' OR lower(r.reason) LIKE ? ESCAPE '\\')");
    params.push(like, like, like, like);
  }
  if (q.groupId) {
    conditions.push("r.target_type = 'group' AND r.target_id = ?");
    params.push(q.groupId);
  }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const from = `FROM access_requests r JOIN users u ON u.id = r.user_id ${TARGET_NAME_JOINS} ${where}`;
  const limit = Math.min(q.limit ?? 100, 500);
  const offset = Math.max(q.offset ?? 0, 0);
  const [count, rows] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS n ${from}`).bind(...params),
    env.DB.prepare(`SELECT r.*, u.upn, u.display_name, ${TARGET_NAME} ${from} ORDER BY r.created_at DESC LIMIT ? OFFSET ?`).bind(...params, limit, offset),
  ]);
  return { total: Number((count?.results[0] as { n: number } | undefined)?.n ?? 0), rows: (rows?.results ?? []) as AccessRequestView[] };
}

export async function getAccessRequest(env: Env, id: number): Promise<AccessRequestView | null> {
  return env.DB.prepare(
    `SELECT r.*, u.upn, u.display_name, ${TARGET_NAME} FROM access_requests r
      JOIN users u ON u.id = r.user_id ${TARGET_NAME_JOINS} WHERE r.id = ?`
  )
    .bind(id)
    .first<AccessRequestView>();
}

/** The self-service ask. Throws ServiceError on anything not requestable. */
export async function requestAccess(ctx: ServiceCtx, target: AccessTarget, reason: string): Promise<AccessRequestRow> {
  const userId = ctx.selfId;
  if (!userId) throw new ServiceError(403, "Only a signed-in person can request access.");
  let name: string;
  if (target.type === "group") {
    const group = await ctx.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(target.id).first<GroupRow>();
    if (!group) throw new ServiceError(404, "That group does not exist.");
    if (group.rule) throw new ServiceError(400, `"${group.name}" assigns members by rule - its membership cannot be requested.`);
    if (group.system) throw new ServiceError(400, `"${group.name}" is maintained by the system - its membership cannot be requested.`);
    if (!group.requestable) throw new ServiceError(400, `"${group.name}" is not open to requests.`);
    if (await ctx.env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(target.id, userId).first()) {
      throw new ServiceError(409, `You are already a member of "${group.name}".`);
    }
    // A manager decides other people's requests, never their own - membership
    // is a direct add on the group's Manage page instead.
    if (await ctx.env.DB.prepare("SELECT 1 FROM group_managers WHERE group_id = ? AND user_id = ?").bind(target.id, userId).first()) {
      throw new ServiceError(400, `You manage "${group.name}" - add yourself on its Manage page instead of requesting.`);
    }
    name = group.name;
  } else {
    const app =
      target.type === "oidc_app"
        ? await ctx.env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(target.id).first<OAuthClientRow>()
        : await ctx.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(target.id).first<SamlServiceProviderRow>();
    if (!app) throw new ServiceError(404, "That application does not exist.");
    if (!app.requestable) throw new ServiceError(400, `"${app.name}" is not open to requests.`);
    if (app.access_mode === "everyone" || (await appAccessAllowed(app, await getUserGroupIds(ctx.env, userId), userId))) {
      throw new ServiceError(409, `You already have access to "${app.name}".`);
    }
    name = app.name;
  }
  if (await ctx.env.DB.prepare("SELECT 1 FROM access_requests WHERE target_type = ? AND target_id = ? AND user_id = ? AND status = 'pending'").bind(target.type, target.id, userId).first()) {
    throw new ServiceError(409, `A request for "${name}" is already waiting for a decision.`);
  }
  const t = now();
  const { meta } = await ctx.env.DB.prepare(
    "INSERT INTO access_requests (user_id, target_type, target_id, reason, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)"
  )
    .bind(userId, target.type, target.id, reason.trim().slice(0, 500), t, t)
    .run();
  await audit(ctx, "access.requested", name, { target_type: target.type, target_id: target.id });
  return (await ctx.env.DB.prepare("SELECT * FROM access_requests WHERE id = ?").bind(Number(meta.last_row_id)).first<AccessRequestRow>())!;
}

/** The requester withdraws their own pending request; a privileged actor (admin, groups:write key) may withdraw anyone's. */
export async function cancelAccessRequest(ctx: ServiceCtx, requestId: number): Promise<void> {
  const req = await ctx.env.DB.prepare("SELECT * FROM access_requests WHERE id = ?").bind(requestId).first<AccessRequestRow>();
  if (!req || (req.user_id !== ctx.selfId && !ctx.privileged)) throw new ServiceError(404, "That request doesn't exist any more.");
  if (req.status !== "pending") throw new ServiceError(409, "Only a request still waiting can be withdrawn.");
  await ctx.env.DB.prepare("UPDATE access_requests SET status = 'cancelled', decided_at = ?, updated_at = ? WHERE id = ?").bind(now(), now(), requestId).run();
  const target = await targetName(ctx.env, req);
  await audit(ctx, "access.request_cancelled", target);
}

/** Approve or deny a pending request. An approval writes the membership like an edit does. */
export async function decideAccessRequest(ctx: ServiceCtx, requestId: number, decision: "approved" | "denied", note: string): Promise<AccessRequestRow> {
  const req = await getAccessRequest(ctx.env, requestId);
  if (!req) throw new ServiceError(404, "That request doesn't exist any more.");
  if (req.status !== "pending") throw new ServiceError(409, `That request was already ${req.status}.`);
  // Nobody decides their own ask - approval has to come from someone else.
  if (ctx.selfId === req.user_id) throw new ServiceError(403, "You can't decide your own access request - another approver must.");
  // The grant write goes first: if the target is protected for this actor
  // (an admin role group) the request must stay pending, not read "approved".
  if (decision === "approved") {
    if (req.target_type === "group") await addGroupMembers(ctx, req.target_id, [req.user_id]);
    else await assignUserToApp(ctx, req);
  }
  const t = now();
  await ctx.env.DB.prepare("UPDATE access_requests SET status = ?, decided_by = ?, decided_at = ?, note = ?, updated_at = ? WHERE id = ?")
    .bind(decision, ctx.selfId, t, note.trim().slice(0, 500), t, requestId)
    .run();
  await audit(ctx, decision === "approved" ? "access.request_approved" : "access.request_denied", req.target_name, { user: req.upn, target_type: req.target_type });
  return (await getAccessRequest(ctx.env, requestId))!;
}

/** The name an access request points at, whichever table it lives in. */
async function targetName(env: Env, req: Pick<AccessRequestRow, "target_type" | "target_id">): Promise<string | undefined> {
  const table = req.target_type === "group" ? "groups" : req.target_type === "oidc_app" ? "oauth_clients" : "saml_service_providers";
  const row = await env.DB.prepare(`SELECT name FROM ${table} WHERE id = ?`).bind(req.target_id).first<{ name: string }>();
  return row?.name;
}

/** An approved app request assigns the person directly - the same grant an admin would make on the app's page. */
async function assignUserToApp(ctx: ServiceCtx, req: AccessRequestView): Promise<void> {
  const table = req.target_type === "oidc_app" ? "oauth_clients" : "saml_service_providers";
  const app = await ctx.env.DB.prepare(`SELECT id, name, assigned_users FROM ${table} WHERE id = ?`).bind(req.target_id).first<{ id: number; name: string; assigned_users: string | null }>();
  if (!app) throw new ServiceError(404, "That application doesn't exist any more.");
  const ids = new Set(parseAssignedUserIds(app.assigned_users));
  if (!ids.has(req.user_id)) {
    ids.add(req.user_id);
    await ctx.env.DB.prepare(`UPDATE ${table} SET assigned_users = ? WHERE id = ?`).bind(JSON.stringify([...ids]), app.id).run();
  }
}

// ---------------------------------------------------------------------------
// Certification campaigns
// ---------------------------------------------------------------------------

export interface CertCampaignRow {
  id: number;
  name: string;
  group_ids: string;
  status: "open" | "closed";
  created_by: number | null;
  created_at: string;
  closed_at: string | null;
}

export type CertItemView = {
  id: number;
  campaign_id: number;
  user_id: number;
  group_id: number;
  decision: "pending" | "certify" | "revoke";
  decided_by: number | null;
  decided_at: string | null;
  upn: string;
  display_name: string;
  group_name: string;
};

export async function listCampaigns(env: Env): Promise<(CertCampaignRow & { items: number; pending: number })[]> {
  return (
    await env.DB.prepare(
      `SELECT c.*, (SELECT COUNT(*) FROM cert_items i WHERE i.campaign_id = c.id) AS items,
        (SELECT COUNT(*) FROM cert_items i WHERE i.campaign_id = c.id AND i.decision = 'pending') AS pending
        FROM cert_campaigns c ORDER BY c.created_at DESC`
    ).all<CertCampaignRow & { items: number; pending: number }>()
  ).results;
}

export async function getCampaign(env: Env, id: number): Promise<CertCampaignRow | null> {
  return env.DB.prepare("SELECT * FROM cert_campaigns WHERE id = ?").bind(id).first<CertCampaignRow>();
}

export async function campaignItems(env: Env, campaignId: number): Promise<CertItemView[]> {
  return (
    await env.DB.prepare(
      `SELECT i.*, u.upn, u.display_name, g.name AS group_name FROM cert_items i
        JOIN users u ON u.id = i.user_id JOIN groups g ON g.id = i.group_id
        WHERE i.campaign_id = ? ORDER BY g.name, u.upn`
    )
      .bind(campaignId)
      .all<CertItemView>()
  ).results;
}

/**
 * Starts a campaign: every explicit membership in the named groups becomes a
 * review item. Dynamic groups in scope contribute nothing - their membership
 * follows a rule, not a grant, so there is nothing to revoke.
 */
export async function createCampaign(ctx: ServiceCtx, name: string, groupIds: number[]): Promise<CertCampaignRow> {
  const trimmed = name.trim();
  if (!trimmed) throw new ServiceError(400, "A campaign name is required.");
  const ids = [...new Set(groupIds)].filter((id) => Number.isInteger(id) && id > 0);
  if (!ids.length) throw new ServiceError(400, "Pick at least one group to review.");
  const { results: groups } = await ctx.env.DB.prepare(
    `SELECT * FROM groups WHERE id IN (SELECT value FROM json_each(?))`
  )
    .bind(JSON.stringify(ids))
    .all<GroupRow>();
  if (groups.length !== ids.length) throw new ServiceError(404, "One of the chosen groups no longer exists.");
  const t = now();
  const { meta } = await ctx.env.DB.prepare("INSERT INTO cert_campaigns (name, group_ids, status, created_by, created_at) VALUES (?, ?, 'open', ?, ?)")
    .bind(trimmed, JSON.stringify(ids), ctx.selfId, t)
    .run();
  const campaignId = Number(meta.last_row_id);
  const staticIds = groups.filter((g) => !g.rule).map((g) => g.id);
  let itemCount = 0;
  if (staticIds.length) {
    const { results: members } = await ctx.env.DB.prepare(
      `SELECT group_id, user_id FROM group_members WHERE group_id IN (SELECT value FROM json_each(?))`
    )
      .bind(JSON.stringify(staticIds))
      .all<{ group_id: number; user_id: number }>();
    itemCount = members.length;
    if (members.length) {
      await ctx.env.DB.batch(
        members.map((m) => ctx.env.DB.prepare("INSERT INTO cert_items (campaign_id, user_id, group_id) VALUES (?, ?, ?)").bind(campaignId, m.user_id, m.group_id))
      );
    }
  }
  await audit(ctx, "access.campaign_created", trimmed, { groups: groups.map((g) => g.name), items: itemCount });
  return (await getCampaign(ctx.env, campaignId))!;
}

/** Certify or revoke one membership under review. Revoke removes it immediately. */
export async function decideCertItem(ctx: ServiceCtx, campaignId: number, itemId: number, decision: "certify" | "revoke"): Promise<CertItemView> {
  const campaign = await getCampaign(ctx.env, campaignId);
  if (!campaign) throw new ServiceError(404, "That review doesn't exist any more.");
  if (campaign.status !== "open") throw new ServiceError(409, "That review is closed.");
  const item = (await campaignItems(ctx.env, campaignId)).find((i) => i.id === itemId);
  if (!item) throw new ServiceError(404, "That review item doesn't exist any more.");
  if (item.decision !== "pending") throw new ServiceError(409, "That membership already has a decision.");
  // Revoke first (see decideAccessRequest): a protected group keeps the item pending.
  if (decision === "revoke") await removeGroupMember(ctx, item.group_id, item.user_id);
  const t = now();
  await ctx.env.DB.prepare("UPDATE cert_items SET decision = ?, decided_by = ?, decided_at = ? WHERE id = ?").bind(decision, ctx.selfId, t, itemId).run();
  await audit(ctx, "access.cert_decided", item.group_name, { user: item.upn, decision, campaign: campaign.name });
  return (await campaignItems(ctx.env, campaignId)).find((i) => i.id === itemId)!;
}

export async function closeCampaign(ctx: ServiceCtx, campaignId: number): Promise<void> {
  const campaign = await getCampaign(ctx.env, campaignId);
  if (!campaign) throw new ServiceError(404, "That review doesn't exist any more.");
  if (campaign.status !== "open") return;
  await ctx.env.DB.prepare("UPDATE cert_campaigns SET status = 'closed', closed_at = ? WHERE id = ?").bind(now(), campaignId).run();
  await audit(ctx, "access.campaign_closed", campaign.name);
}

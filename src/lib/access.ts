import type { Env } from "../env.js";
import { addGroupMembers, removeGroupMember } from "../services/groups.js";
import { audit, ServiceError, type ServiceCtx } from "../services/context.js";
import type { GroupRow, UserRow } from "./types.js";

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

export interface AccessRequestRow {
  id: number;
  user_id: number;
  group_id: number;
  reason: string;
  status: "pending" | "approved" | "denied" | "cancelled";
  decided_by: number | null;
  decided_at: string | null;
  note: string;
  created_at: string;
  updated_at: string;
}

export type AccessRequestView = AccessRequestRow & { upn: string; display_name: string; group_name: string };

/**
 * Requestable static groups `userId` could still ask for: not already a
 * member of, and with no request still waiting (a decided one can be asked
 * again, so the decided statuses don't exclude).
 */
export async function requestableGroups(env: Env, userId: number, search = "", limit = 200): Promise<GroupRow[]> {
  const like = `%${search.replace(/[%_]/g, (m) => `\\${m}`)}%`;
  return (
    await env.DB.prepare(
      `SELECT * FROM groups WHERE requestable = 1 AND (rule IS NULL OR rule = '')
        AND id NOT IN (SELECT group_id FROM group_members WHERE user_id = ?)
        AND id NOT IN (SELECT group_id FROM access_requests WHERE user_id = ? AND status = 'pending')
        AND (name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')
        ORDER BY name LIMIT ?`
    )
      .bind(userId, userId, like, like, limit)
      .all<GroupRow>()
  ).results;
}

export async function myAccessRequests(env: Env, userId: number): Promise<AccessRequestView[]> {
  return (
    await env.DB.prepare(
      `SELECT r.*, u.upn, u.display_name, g.name AS group_name FROM access_requests r
        JOIN users u ON u.id = r.user_id JOIN groups g ON g.id = r.group_id
        WHERE r.user_id = ? ORDER BY r.created_at DESC LIMIT 50`
    )
      .bind(userId)
      .all<AccessRequestView>()
  ).results;
}

export interface AccessRequestQuery {
  /** One status, or undefined for every request. */
  status?: string;
  /** Matches the person's UPN or display name, the group name, or the reason. */
  search?: string;
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
    conditions.push("(lower(u.upn) LIKE ? ESCAPE '\\' OR lower(u.display_name) LIKE ? ESCAPE '\\' OR lower(g.name) LIKE ? ESCAPE '\\' OR lower(r.reason) LIKE ? ESCAPE '\\')");
    params.push(like, like, like, like);
  }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const from = `FROM access_requests r JOIN users u ON u.id = r.user_id JOIN groups g ON g.id = r.group_id ${where}`;
  const limit = Math.min(q.limit ?? 100, 500);
  const offset = Math.max(q.offset ?? 0, 0);
  const [count, rows] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS n ${from}`).bind(...params),
    env.DB.prepare(`SELECT r.*, u.upn, u.display_name, g.name AS group_name ${from} ORDER BY r.created_at DESC LIMIT ? OFFSET ?`).bind(...params, limit, offset),
  ]);
  return { total: Number((count?.results[0] as { n: number } | undefined)?.n ?? 0), rows: (rows?.results ?? []) as AccessRequestView[] };
}

export async function getAccessRequest(env: Env, id: number): Promise<AccessRequestView | null> {
  return env.DB.prepare(
    `SELECT r.*, u.upn, u.display_name, g.name AS group_name FROM access_requests r
      JOIN users u ON u.id = r.user_id JOIN groups g ON g.id = r.group_id WHERE r.id = ?`
  )
    .bind(id)
    .first<AccessRequestView>();
}

/** The self-service ask. Throws AccessError on anything not requestable. */
export async function requestAccess(ctx: ServiceCtx, groupId: number, reason: string): Promise<AccessRequestRow> {
  const userId = ctx.selfId;
  if (!userId) throw new ServiceError(403, "Only a signed-in person can request access.");
  const group = await ctx.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(groupId).first<GroupRow>();
  if (!group) throw new ServiceError(404, "That group does not exist.");
  if (group.rule) throw new ServiceError(400, `"${group.name}" assigns members by rule - its membership cannot be requested.`);
  if (!group.requestable) throw new ServiceError(400, `"${group.name}" is not open to requests.`);
  if (await ctx.env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(groupId, userId).first()) {
    throw new ServiceError(409, `You are already a member of "${group.name}".`);
  }
  if (await ctx.env.DB.prepare("SELECT 1 FROM access_requests WHERE group_id = ? AND user_id = ? AND status = 'pending'").bind(groupId, userId).first()) {
    throw new ServiceError(409, `A request for "${group.name}" is already waiting for a decision.`);
  }
  const t = now();
  const { meta } = await ctx.env.DB.prepare(
    "INSERT INTO access_requests (user_id, group_id, reason, status, created_at, updated_at) VALUES (?, ?, ?, 'pending', ?, ?)"
  )
    .bind(userId, groupId, reason.trim().slice(0, 500), t, t)
    .run();
  await audit(ctx, "access.requested", group.name, { group_id: groupId });
  return (await ctx.env.DB.prepare("SELECT * FROM access_requests WHERE id = ?").bind(Number(meta.last_row_id)).first<AccessRequestRow>())!;
}

/** The requester withdraws their own pending request. */
export async function cancelAccessRequest(ctx: ServiceCtx, requestId: number): Promise<void> {
  const req = await ctx.env.DB.prepare("SELECT * FROM access_requests WHERE id = ?").bind(requestId).first<AccessRequestRow>();
  if (!req || req.user_id !== ctx.selfId) throw new ServiceError(404, "That request doesn't exist any more.");
  if (req.status !== "pending") throw new ServiceError(409, "Only a request still waiting can be withdrawn.");
  await ctx.env.DB.prepare("UPDATE access_requests SET status = 'cancelled', decided_at = ?, updated_at = ? WHERE id = ?").bind(now(), now(), requestId).run();
  const g = await ctx.env.DB.prepare("SELECT name FROM groups WHERE id = ?").bind(req.group_id).first<{ name: string }>();
  await audit(ctx, "access.request_cancelled", g?.name);
}

/** Approve or deny a pending request. An approval writes the membership like an edit does. */
export async function decideAccessRequest(ctx: ServiceCtx, requestId: number, decision: "approved" | "denied", note: string): Promise<AccessRequestRow> {
  const req = await getAccessRequest(ctx.env, requestId);
  if (!req) throw new ServiceError(404, "That request doesn't exist any more.");
  if (req.status !== "pending") throw new ServiceError(409, `That request was already ${req.status}.`);
  // The membership write goes first: if the group is protected for this actor
  // (an admin role group) the request must stay pending, not read "approved".
  if (decision === "approved") await addGroupMembers(ctx, req.group_id, [req.user_id]);
  const t = now();
  await ctx.env.DB.prepare("UPDATE access_requests SET status = ?, decided_by = ?, decided_at = ?, note = ?, updated_at = ? WHERE id = ?")
    .bind(decision, ctx.selfId, t, note.trim().slice(0, 500), t, requestId)
    .run();
  await audit(ctx, decision === "approved" ? "access.request_approved" : "access.request_denied", req.group_name, { user: req.upn });
  return (await getAccessRequest(ctx.env, requestId))!;
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

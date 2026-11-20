import { z } from "@hono/zod-openapi";
import { campaignItems, cancelAccessRequest, closeCampaign, createCampaign, decideAccessRequest, decideCertItem, getAccessRequest, getCampaign, listAccessRequests, listCampaigns, requestAccess } from "../lib/access.js";
import { apiCtx } from "../services/context.js";
import { defineRoute, notFound, param, readJson } from "./openapi.js";
import { IdParam } from "./schemas.js";
import type { UserRow } from "../lib/types.js";

/**
 * Access governance: the requests people file on My account, and the
 * certification campaigns reviewing group membership. Both only touch a
 * static group's assigned members - a dynamic group's membership follows its
 * rule, so it is neither requestable nor revocable here.
 */

const RequestSchema = z
  .object({
    id: z.number(),
    user_id: z.number(),
    upn: z.string(),
    display_name: z.string(),
    group_id: z.number(),
    group_name: z.string(),
    reason: z.string(),
    status: z.enum(["pending", "approved", "denied", "cancelled"]),
    decided_by: z.number().nullable(),
    decided_at: z.string().nullable(),
    note: z.string(),
    created_at: z.string(),
  })
  .passthrough()
  .openapi("AccessRequest");

const CampaignSchema = z
  .object({
    id: z.number(),
    name: z.string(),
    group_ids: z.string().openapi({ description: "JSON array of the group ids under review." }),
    status: z.enum(["open", "closed"]),
    created_by: z.number().nullable(),
    created_at: z.string(),
    closed_at: z.string().nullable(),
    items: z.number().optional(),
    pending: z.number().optional(),
  })
  .passthrough()
  .openapi("AccessCampaign");

const CertItemSchema = z
  .object({
    id: z.number(),
    user_id: z.number(),
    upn: z.string(),
    display_name: z.string(),
    group_id: z.number(),
    group_name: z.string(),
    decision: z.enum(["pending", "certify", "revoke"]),
    decided_by: z.number().nullable(),
    decided_at: z.string().nullable(),
  })
  .passthrough()
  .openapi("AccessCertItem");

defineRoute(
  {
    method: "get",
    path: "/api/v1/access/requests",
    tag: "Access",
    permission: "groups:read",
    summary: "List access requests",
    description: "Defaults to requests still waiting; `status` filters, `all` lists every request, `search` matches the person, group or reason.",
    query: z.object({
      status: z.enum(["pending", "approved", "denied", "cancelled", "all"]).optional(),
      search: z.string().optional(),
      limit: z.string().optional().openapi({ description: "Default 100, at most 500." }),
      offset: z.string().optional(),
    }),
    response: z.object({ requests: z.array(RequestSchema), total: z.number() }),
  },
  async (c) => {
    const status = c.req.query("status") ?? "pending";
    const { total, rows } = await listAccessRequests(c.env, {
      status: status === "all" ? undefined : status,
      search: c.req.query("search"),
      limit: Math.min(Number(c.req.query("limit") ?? 100) || 100, 500),
      offset: Math.max(Number(c.req.query("offset") ?? 0) || 0, 0),
    });
    return c.json({ requests: rows, total });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/access/requests/{id}",
    tag: "Access",
    permission: "groups:write",
    summary: "Approve or deny an access request",
    description: "An approval adds the requester to the group exactly like a membership edit does. Touching an admin role group needs `*`.",
    params: IdParam,
    body: z.object({ decision: z.enum(["approved", "denied"]), note: z.string().optional() }),
    errors: [404, 409],
    response: z.object({ request: RequestSchema }),
  },
  async (c) => {
    const body = await readJson<{ decision: "approved" | "denied"; note?: string }>(c);
    return c.json({ request: await decideAccessRequest(apiCtx(c), Number(param(c, "id")), body.decision, body.note ?? "") });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/access/requests",
    tag: "Access",
    permission: "groups:write",
    summary: "File an access request",
    description:
      "Requests `group_id` for `username` - the same flow the My account requester follows: the group must be requestable and static, the user must not already belong or have a pending ask, and their own managed groups are refused.",
    body: z.object({ username: z.string(), group_id: z.number().int(), reason: z.string().optional() }),
    status: 201,
    errors: [404, 409],
    response: z.object({ request: RequestSchema }),
  },
  async (c) => {
    const body = await readJson<{ username: string; group_id: number; reason?: string }>(c);
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(String(body.username ?? "").toLowerCase()).first<UserRow>();
    if (!user) return notFound(c, `No user "${body.username}".`);
    // selfId is who the request is for; the token stays the audited actor.
    const request = await requestAccess({ ...apiCtx(c), selfId: user.id }, Number(body.group_id), String(body.reason ?? ""));
    return c.json({ request: (await getAccessRequest(c.env, request.id))! }, 201);
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/access/requests/{id}/cancel",
    tag: "Access",
    permission: "groups:write",
    summary: "Withdraw a pending access request",
    description: "Cancels a request still waiting for a decision. Withdrawing another user's request needs `*` (an admin key).",
    params: IdParam,
    errors: [404, 409],
    response: z.object({ request: RequestSchema }),
  },
  async (c) => {
    const id = Number(param(c, "id"));
    await cancelAccessRequest(apiCtx(c), id);
    return c.json({ request: (await getAccessRequest(c.env, id))! });
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/access/campaigns",
    tag: "Access",
    permission: "groups:read",
    summary: "List certification campaigns",
    response: z.object({ campaigns: z.array(CampaignSchema) }),
  },
  async (c) => c.json({ campaigns: await listCampaigns(c.env) })
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/access/campaigns",
    tag: "Access",
    permission: "groups:write",
    summary: "Start a certification campaign",
    description: "Every assigned membership of the named groups becomes a review item, snapshotted at creation. Dynamic groups in scope contribute nothing.",
    body: z.object({ name: z.string(), group_ids: z.array(z.number().int()) }),
    status: 201,
    errors: [404],
    response: z.object({ campaign: CampaignSchema }),
  },
  async (c) => {
    const body = await readJson<{ name: string; group_ids?: number[] }>(c);
    return c.json({ campaign: await createCampaign(apiCtx(c), String(body.name ?? ""), body.group_ids ?? []) }, 201);
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/access/campaigns/{id}",
    tag: "Access",
    permission: "groups:read",
    summary: "Get a campaign and its review items",
    params: IdParam,
    errors: [404],
    response: z.object({ campaign: CampaignSchema, items: z.array(CertItemSchema) }),
  },
  async (c) => {
    const campaign = await getCampaign(c.env, Number(param(c, "id")));
    if (!campaign) return notFound(c, `No campaign with id ${param(c, "id")}.`);
    return c.json({ campaign, items: await campaignItems(c.env, campaign.id) });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/access/campaigns/{id}/close",
    tag: "Access",
    permission: "groups:write",
    summary: "Close a campaign",
    description: "Items still pending keep their membership and count as unreviewed.",
    params: IdParam,
    errors: [404],
  },
  async (c) => {
    await closeCampaign(apiCtx(c), Number(param(c, "id")));
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/access/campaigns/{id}/items/{item_id}",
    tag: "Access",
    permission: "groups:write",
    summary: "Certify or revoke a membership under review",
    description: "`revoke` removes the member from the group immediately. Touching an admin role group needs `*`.",
    params: z.object({ id: z.string().openapi({ description: "Numeric campaign id." }), item_id: z.string().openapi({ description: "Numeric review item id." }) }),
    body: z.object({ decision: z.enum(["certify", "revoke"]) }),
    errors: [404, 409],
    response: z.object({ item: CertItemSchema }),
  },
  async (c) => {
    const body = await readJson<{ decision: "certify" | "revoke" }>(c);
    return c.json({ item: await decideCertItem(apiCtx(c), Number(param(c, "id")), Number(param(c, "item_id")), body.decision) });
  }
);

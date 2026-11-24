import { z } from "@hono/zod-openapi";
import { apiCtx, ServiceError } from "../services/context.js";
import { assertMayTouchUser } from "../services/guards.js";
import { configureAccessApp, enabledListSyncs, flagUser, getCfOne, grantHints, LIST_SYNCS, listAccessApps, listSyncStatus, saveCfOne, setEnabledListSyncs, sweepWatchlist, syncAccessApps, syncLists, unflagUser, watchlist } from "../lib/cfone.js";
import { logAudit } from "../lib/audit.js";
import { auditActor } from "../lib/api-auth.js";
import { defineRoute, notFound, param, readJson, type ApiContext } from "./openapi.js";
import type { UserRow } from "../lib/types.js";

/**
 * The Cloudflare One (Zero Trust) connection: account id + API token + the
 * Access tenant, the reusable-list syncs it drives, and the risk watchlist it
 * feeds. The console's Integrations -> Cloudflare One page.
 */

const CfOneSchema = z
  .object({
    configured: z.boolean(),
    account_id: z.string().openapi({ description: "The Cloudflare account Zero Trust lives in." }),
    team: z.string().openapi({ description: "Zero Trust team name - the Access tenant https://{team}.cloudflareaccess.com." }),
    access_aud: z.string().openapi({ description: "AUD tag of the Access application protecting the admin console; empty disables the JWT check." }),
    api_token_set: z.boolean().openapi({ description: "Whether an API token is stored; the token itself is never returned." }),
    lists: z.array(z.string()).openapi({ description: "The list syncs that run (see /sync for per-group syncs)." }),
    list_status: z.array(z.object({ key: z.string(), cf_list_id: z.string(), kind: z.string(), item_count: z.number(), synced_at: z.string().nullable() })),
    watchlist: z.array(z.object({ user_id: z.number(), upn: z.string(), reason: z.string(), source: z.string(), flagged_at: z.string(), expires_at: z.string().nullable() })),
  })
  .openapi("CloudflareOne");

async function cfOneJson(env: ApiContext["env"]) {
  const config = await getCfOne(env);
  return {
    configured: Boolean(config),
    account_id: config?.accountId ?? "",
    team: config?.team ?? "",
    access_aud: config?.accessAud ?? "",
    api_token_set: Boolean(config?.apiToken),
    lists: [...(await enabledListSyncs(env))],
    list_status: await listSyncStatus(env),
    watchlist: await watchlist(env),
  };
}

defineRoute(
  { method: "get", path: "/api/v1/integrations/cloudflare-one", tag: "Cloudflare One", permission: "cfone:read", summary: "Read the Cloudflare One connection and sync status", response: CfOneSchema },
  async (c) => c.json(await cfOneJson(c.env))
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/integrations/cloudflare-one",
    tag: "Cloudflare One",
    permission: "cfone:write",
    summary: "Configure the Cloudflare One connection",
    description:
      "An empty `api_token` keeps the stored one; `lists` names the reusable-list syncs to run (watchlist, deprovisioned, managed-domains, auth-fail-ips). Clearing `account_id` disconnects and stops the Access-JWT check.",
    body: z.object({
      account_id: z.string().openapi({ description: "Empty disconnects." }),
      api_token: z.string().optional().openapi({ description: "Zero Trust Read/Write token; omit to keep the stored one." }),
      team: z.string().optional(),
      access_aud: z.string().optional(),
      lists: z.array(z.enum(LIST_SYNCS.map((l) => l.key) as [string, ...string[]])).optional(),
    }),
    response: CfOneSchema,
  },
  async (c) => {
    const body = await readJson<{ account_id?: string; api_token?: string; team?: string; access_aud?: string; lists?: string[] }>(c);
    const current = await getCfOne(c.env);
    await saveCfOne(c.env, {
      accountId: String(body.account_id ?? "").trim(),
      apiToken: body.api_token?.trim() || undefined,
      team: String(body.team ?? "").trim(),
      accessAud: String(body.access_aud ?? "").trim(),
    });
    if (body.lists) await setEnabledListSyncs(c.env, body.lists);
    await logAudit(c.env, auditActor(c.get("apiActor")), "cfone.configured", current?.accountId ?? "cloudflare-one", undefined, c.req.raw);
    return c.json(await cfOneJson(c.env));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/integrations/cloudflare-one/sync",
    tag: "Cloudflare One",
    permission: "cfone:write",
    summary: "Run the list sync now",
    description: "Also runs the watchlist sweep (lapsed flags drop out). The scheduled job does the same on its own cadence.",
    response: z.object({ synced: z.array(z.string()), failed: z.record(z.string(), z.string()), swept: z.number() }),
  },
  async (c) => {
    const config = await getCfOne(c.env);
    if (!config?.apiToken) throw new ServiceError(400, "Cloudflare One is not configured: set the account id and API token first.");
    const result = await syncLists(c.env, config);
    const swept = await sweepWatchlist(c.env);
    await logAudit(c.env, auditActor(c.get("apiActor")), "cfone.synced", "cloudflare-one", { synced: result.synced.length, failed: Object.keys(result.failed).length }, c.req.raw);
    return c.json({ ...result, swept });
  }
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/users/{username}/watch",
    tag: "Cloudflare One",
    permission: "cfone:write",
    summary: "Flag a user on the risk watchlist",
    description: "The watchlist is a system group whose member emails Cloudflare One can consume (list sync or a SCIM target). `ttl_hours` 0 means the flag stays until cleared.",
    body: z.object({ reason: z.string(), ttl_hours: z.number().optional() }),
    errors: [404],
    response: z.object({ ok: z.literal(true), watched: z.literal(true) }),
  },
  async (c) => {
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(param(c, "username").toLowerCase()).first<UserRow>();
    if (!user) return notFound(c, `No user "${param(c, "username").toLowerCase()}".`);
    await assertMayTouchUser(apiCtx(c), user.id);
    const body = await readJson<{ reason?: string; ttl_hours?: number }>(c);
    if (!body.reason?.trim()) throw new ServiceError(400, "A reason is required.");
    await flagUser(c.env, user.id, body.reason.trim().slice(0, 300), "manual", Math.max(0, body.ttl_hours ?? 0));
    await logAudit(c.env, auditActor(c.get("apiActor")), "cfone.user_flagged", user.upn, { reason: body.reason.trim().slice(0, 300) }, c.req.raw);
    return c.json({ ok: true, watched: true });
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/users/{username}/watch",
    tag: "Cloudflare One",
    permission: "cfone:write",
    summary: "Clear a user from the risk watchlist",
    errors: [404],
    response: z.object({ ok: z.literal(true), watched: z.literal(false) }),
  },
  async (c) => {
    const user = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(param(c, "username").toLowerCase()).first<UserRow>();
    if (!user) return notFound(c, `No user "${param(c, "username").toLowerCase()}".`);
    await assertMayTouchUser(apiCtx(c), user.id);
    await unflagUser(c.env, user.id);
    await logAudit(c.env, auditActor(c.get("apiActor")), "cfone.user_unflagged", user.upn, undefined, c.req.raw);
    return c.json({ ok: true, watched: false });
  }
);


const CfAccessAppSchema = z
  .object({
    id: z.number(),
    cf_app_id: z.string().openapi({ description: "The application's UUID in the Cloudflare account." }),
    name: z.string(),
    type: z.string().openapi({ description: "The Access application type: self_hosted, saas, ssh, bookmark, ..." }),
    hostname: z.string().openapi({ description: "Launch target - the app's first self-hosted domain (or domain)." }),
    granting_group_id: z.number().nullable().openapi({ description: "Static group whose membership grants this app; Access policies should Include it." }),
    grant_hint: z.array(z.string()).openapi({ description: "FlareID group names the app's Allow policies selected at last sync." }),
    requestable: z.boolean(),
    synced_at: z.string(),
  })
  .openapi("CloudflareAccessApp");

const accessAppJson = (r: Awaited<ReturnType<typeof listAccessApps>>[number]) => ({
  id: r.id,
  cf_app_id: r.cf_app_id,
  name: r.name,
  type: r.type,
  hostname: r.hostname,
  granting_group_id: r.granting_group_id,
  grant_hint: grantHints(r),
  requestable: Boolean(r.requestable),
  synced_at: r.synced_at,
});

defineRoute(
  {
    method: "get",
    path: "/api/v1/integrations/cloudflare-one/access-apps",
    tag: "Cloudflare One",
    permission: "cfone:read",
    summary: "List synced Cloudflare Access applications",
    description: "Read-only mirror of the account's Access apps and their granting-group mapping. Sync fills the list; PATCH maps an app to the group whose membership grants it.",
    response: z.object({ access_apps: z.array(CfAccessAppSchema) }),
  },
  async (c) => c.json({ access_apps: (await listAccessApps(c.env)).map(accessAppJson) })
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/integrations/cloudflare-one/access-apps/sync",
    tag: "Cloudflare One",
    permission: "cfone:write",
    summary: "Pull Access applications from Cloudflare now",
    description: "Upserts the mirror from GET /access/apps plus each app's policies; granting mappings and requestable flags survive. Apps that vanished upstream are removed along with their pending requests.",
    errors: [400],
    response: z.object({ synced: z.number(), removed: z.number() }),
  },
  async (c) => {
    const config = await getCfOne(c.env);
    if (!config?.apiToken) throw new ServiceError(400, "Cloudflare One is not configured: set the account id and API token first.");
    const result = await syncAccessApps(c.env, config);
    await logAudit(c.env, auditActor(c.get("apiActor")), "cfone.access_apps_synced", "cloudflare-one", { synced: result.synced, removed: result.removed }, c.req.raw);
    return c.json(result);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/integrations/cloudflare-one/access-apps/{id}",
    tag: "Cloudflare One",
    permission: "cfone:write",
    summary: "Map an Access app to its granting group",
    description: "The granting group must be static and non-system - approving a request is a manual membership write. `requestable` needs a granting group; clearing the group drops requestable.",
    body: z.object({
      granting_group_id: z.number().nullable().optional().openapi({ description: "Null unmaps the app (and drops requestable)." }),
      requestable: z.boolean().optional(),
    }),
    errors: [400, 404],
    response: CfAccessAppSchema,
  },
  async (c) => {
    const id = Number(param(c, "id"));
    const current = await c.env.DB.prepare("SELECT * FROM cf_access_apps WHERE id = ?").bind(id).first<{ granting_group_id: number | null; requestable: number }>();
    if (!current) return notFound(c, `No synced Access application ${id}.`);
    const body = await readJson<{ granting_group_id?: number | null; requestable?: boolean }>(c);
    const gid = body.granting_group_id === undefined ? current.granting_group_id : body.granting_group_id;
    const app = await configureAccessApp(c.env, id, gid, body.requestable ?? Boolean(current.requestable));
    await logAudit(c.env, auditActor(c.get("apiActor")), "cfone.access_app_configured", app.name, { granting_group_id: app.granting_group_id, requestable: app.requestable }, c.req.raw);
    return c.json(accessAppJson(app));
  }
);

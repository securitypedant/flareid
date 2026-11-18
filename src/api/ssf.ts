import { z } from "@hono/zod-openapi";
import { drainSsfOutbox, SSF_EVENTS } from "../lib/ssf.js";
import { logAudit } from "../lib/audit.js";
import { auditActor } from "../lib/api-auth.js";
import { badRequest, defineRoute, notFound, readJson } from "./openapi.js";

/**
 * Shared Signals Framework configuration (the console's Integrations ->
 * Signals page): outbound streams we push CAEP/RISC Security Event Tokens to,
 * and inbound transmitters whose SETs we accept at POST /ssf/receive.
 * Discovery is at /.well-known/ssf-configuration.
 */

const EVENT_URIS = Object.values(SSF_EVENTS) as [string, ...string[]];

const StreamSchema = z
  .object({
    id: z.number(),
    name: z.string(),
    endpoint_url: z.string(),
    aud: z.string().openapi({ description: "Audience the receiver expects in the SET; empty uses the endpoint's host." }),
    events: z.array(z.string()).openapi({ description: "Event URIs this stream gets; empty means all supported." }),
    disabled: z.boolean(),
    created_at: z.string(),
    last_push_at: z.string().nullable(),
    last_error: z.string().nullable(),
    queued: z.number().openapi({ description: "Undelivered events waiting in the outbox." }),
  })
  .openapi("SsfStream");

const TransmitterSchema = z
  .object({
    id: z.number(),
    name: z.string(),
    issuer: z.string(),
    jwks_url: z.string(),
    created_at: z.string(),
  })
  .openapi("SsfTransmitter");

interface StreamRow {
  id: number;
  name: string;
  endpoint_url: string;
  aud: string;
  events: string;
  disabled: number;
  created_at: string;
  last_push_at: string | null;
  last_error: string | null;
  queued: number;
}

async function listStreams(env: { DB: D1Database }) {
  const { results } = await env.DB.prepare(
    `SELECT s.*, (SELECT COUNT(*) FROM ssf_outbox o WHERE o.stream_id = s.id) AS queued
     FROM ssf_streams s ORDER BY s.id`
  ).all<StreamRow>();
  return results.map((s) => ({ ...s, disabled: Boolean(s.disabled), events: safeEvents(s.events) }));
}

function safeEvents(raw: string): string[] {
  try {
    const v = JSON.parse(raw || "[]");
    return Array.isArray(v) ? v.filter((e): e is string => typeof e === "string") : [];
  } catch {
    return [];
  }
}

function validStreamInput(body: { name?: string; endpoint_url?: string; aud?: string; events?: string[] }): { error: string } | { name: string; endpoint_url: string; aud: string; events: string[] } {
  const name = String(body.name ?? "").trim();
  const endpoint = String(body.endpoint_url ?? "").trim();
  if (!name) return { error: "name is required." };
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return { error: "endpoint_url must be a URL." };
  }
  if (url.protocol !== "https:") return { error: "endpoint_url must be https." };
  const events = (body.events ?? []).filter((e): e is string => typeof e === "string");
  const bad = events.filter((e) => !EVENT_URIS.includes(e));
  if (bad.length) return { error: `Unknown events: ${bad.join(", ")}. Supported: ${EVENT_URIS.join(", ")}.` };
  return { name, endpoint_url: endpoint, aud: String(body.aud ?? "").trim(), events };
}

defineRoute(
  {
    method: "get",
    path: "/api/v1/ssf/streams",
    tag: "Signals",
    permission: "signals:read",
    summary: "List outbound signal streams",
    response: z.object({ streams: z.array(StreamSchema), events_supported: z.array(z.string()) }),
  },
  async (c) => c.json({ streams: await listStreams(c.env), events_supported: EVENT_URIS })
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/ssf/streams",
    tag: "Signals",
    permission: "signals:write",
    summary: "Register an outbound stream",
    description:
      "A receiver endpoint we push signed SETs to (application/secevent+jwt). `events` selects which of the supported CAEP/RISC URIs it gets; an empty list means all.",
    body: z.object({
      name: z.string(),
      endpoint_url: z.string(),
      aud: z.string().optional(),
      events: z.array(z.enum(EVENT_URIS)).optional(),
    }),
    response: StreamSchema,
    status: 201,
  },
  async (c) => {
    const body = await readJson<Record<string, unknown>>(c);
    const v = validStreamInput(body as { name?: string; endpoint_url?: string; aud?: string; events?: string[] });
    if ("error" in v) return c.json(badRequest(v.error), 400);
    const res = await c.env.DB.prepare("INSERT INTO ssf_streams (name, endpoint_url, aud, events, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(v.name, v.endpoint_url, v.aud, JSON.stringify(v.events), new Date().toISOString())
      .run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "ssf.stream_created", v.name, { endpoint_url: v.endpoint_url }, c.req.raw);
    const { results } = await c.env.DB.prepare("SELECT s.*, 0 AS queued FROM ssf_streams s WHERE s.id = ?").bind(res.meta.last_row_id).all<StreamRow>();
    const s = results[0]!;
    return c.json({ ...s, disabled: Boolean(s.disabled), events: safeEvents(s.events) }, 201);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/ssf/streams/{id}",
    tag: "Signals",
    permission: "signals:write",
    summary: "Update an outbound stream",
    body: z.object({
      name: z.string().optional(),
      endpoint_url: z.string().optional(),
      aud: z.string().optional(),
      events: z.array(z.enum(EVENT_URIS)).optional(),
      disabled: z.boolean().optional(),
    }),
    response: StreamSchema,
  },
  async (c) => {
    const id = Number(c.req.param("id"));
    const existing = await c.env.DB.prepare("SELECT * FROM ssf_streams WHERE id = ?").bind(id).first<StreamRow>();
    if (!existing) return notFound(c, "Stream");
    const body = await readJson<Record<string, unknown>>(c);
    const merged = {
      name: body.name !== undefined ? String(body.name) : existing.name,
      endpoint_url: body.endpoint_url !== undefined ? String(body.endpoint_url) : existing.endpoint_url,
      aud: body.aud !== undefined ? String(body.aud) : existing.aud,
      events: body.events !== undefined ? (body.events as string[]) : safeEvents(existing.events),
    };
    const v = validStreamInput(merged);
    if ("error" in v) return c.json(badRequest(v.error), 400);
    const disabled = body.disabled !== undefined ? (body.disabled ? 1 : 0) : existing.disabled;
    await c.env.DB.prepare("UPDATE ssf_streams SET name = ?, endpoint_url = ?, aud = ?, events = ?, disabled = ? WHERE id = ?")
      .bind(v.name, v.endpoint_url, v.aud, JSON.stringify(v.events), disabled, id)
      .run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "ssf.stream_updated", v.name, undefined, c.req.raw);
    const { results } = await c.env.DB.prepare(
      `SELECT s.*, (SELECT COUNT(*) FROM ssf_outbox o WHERE o.stream_id = s.id) AS queued FROM ssf_streams s WHERE s.id = ?`
    ).bind(id).all<StreamRow>();
    const s = results[0]!;
    return c.json({ ...s, disabled: Boolean(s.disabled), events: safeEvents(s.events) });
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/ssf/streams/{id}",
    tag: "Signals",
    permission: "signals:write",
    summary: "Delete an outbound stream",
    description: "Queued undelivered events for the stream go with it.",
  },
  async (c) => {
    const id = Number(c.req.param("id"));
    const existing = await c.env.DB.prepare("SELECT name FROM ssf_streams WHERE id = ?").bind(id).first<{ name: string }>();
    if (!existing) return notFound(c, "Stream");
    await c.env.DB.prepare("DELETE FROM ssf_streams WHERE id = ?").bind(id).run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "ssf.stream_deleted", existing.name, undefined, c.req.raw);
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/ssf/outbox/drain",
    tag: "Signals",
    permission: "signals:write",
    summary: "Retry undelivered events now",
    description: "The outbox drains on emit and on the hourly cron; this forces a pass - useful after fixing a receiver that was down.",
    response: z.object({ sent: z.number(), failed: z.number() }),
  },
  async (c) => c.json(await drainSsfOutbox(c.env))
);

// ---------------------------------------------------------------------------
// Inbound transmitters
// ---------------------------------------------------------------------------

async function listTransmitters(env: { DB: D1Database }) {
  const { results } = await env.DB.prepare("SELECT * FROM ssf_transmitters ORDER BY id").all<z.infer<typeof TransmitterSchema>>();
  return results;
}

defineRoute(
  {
    method: "get",
    path: "/api/v1/ssf/transmitters",
    tag: "Signals",
    permission: "signals:read",
    summary: "List trusted inbound transmitters",
    response: z.object({ transmitters: z.array(TransmitterSchema) }),
  },
  async (c) => c.json({ transmitters: await listTransmitters(c.env) })
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/ssf/transmitters",
    tag: "Signals",
    permission: "signals:write",
    summary: "Trust an inbound transmitter",
    description:
      "An issuer whose SETs we accept at POST /ssf/receive, verified against `jwks_url`. A `session-revoked` event for a user's email kills their sessions; a credential/risk event flags them on the risk watchlist for 24h.",
    body: z.object({ name: z.string(), issuer: z.string(), jwks_url: z.string() }),
    response: TransmitterSchema,
    status: 201,
  },
  async (c) => {
    const body = await readJson<{ name?: string; issuer?: string; jwks_url?: string }>(c);
    const name = String(body.name ?? "").trim();
    const issuer = String(body.issuer ?? "").trim();
    const jwksUrl = String(body.jwks_url ?? "").trim();
    if (!name || !issuer) return c.json(badRequest("name and issuer are required."), 400);
    let url: URL;
    try {
      url = new URL(jwksUrl);
    } catch {
      return c.json(badRequest("jwks_url must be a URL."), 400);
    }
    if (url.protocol !== "https:") return c.json(badRequest("jwks_url must be https."), 400);
    const dup = await c.env.DB.prepare("SELECT id FROM ssf_transmitters WHERE issuer = ?").bind(issuer).first();
    if (dup) return c.json({ error: "conflict", message: `A transmitter for issuer ${issuer} already exists.` }, 409);
    const res = await c.env.DB.prepare("INSERT INTO ssf_transmitters (name, issuer, jwks_url, created_at) VALUES (?, ?, ?, ?)")
      .bind(name, issuer, jwksUrl, new Date().toISOString())
      .run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "ssf.transmitter_created", name, { issuer }, c.req.raw);
    const row = await c.env.DB.prepare("SELECT * FROM ssf_transmitters WHERE id = ?").bind(res.meta.last_row_id).first();
    return c.json(row, 201);
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/ssf/transmitters/{id}",
    tag: "Signals",
    permission: "signals:write",
    summary: "Stop trusting a transmitter",
  },
  async (c) => {
    const id = Number(c.req.param("id"));
    const existing = await c.env.DB.prepare("SELECT name, issuer FROM ssf_transmitters WHERE id = ?").bind(id).first<{ name: string; issuer: string }>();
    if (!existing) return notFound(c, "Transmitter");
    await c.env.DB.prepare("DELETE FROM ssf_transmitters WHERE id = ?").bind(id).run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "ssf.transmitter_deleted", existing.name, { issuer: existing.issuer }, c.req.raw);
    return c.json({ ok: true });
  }
);

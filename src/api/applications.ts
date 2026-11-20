import { z } from "@hono/zod-openapi";
import { hasScope, isApiScope, listApiKeys, parseScopes } from "../lib/api-keys.js";
import { listDomains } from "../lib/domains.js";
import { CLAIM_GROUPS, isValidPostLogoutUri, parseAllowedClaims } from "../lib/oidc.js";
import { getScimTarget, listScimTargets, type ScimTarget } from "../lib/scim-targets.js";
import { getUpstreamIdp, idpConfig, listUpstreamIdps, upstreamJitGroups, type UpstreamIdpRow } from "../lib/federation.js";
import type { OAuthClientRow, SamlServiceProviderRow } from "../lib/types.js";
import { deleteClient, ID_TOKEN_ALGS, isIdTokenAlg, rotateClientSecret, updateClient, validFrontchannelUri } from "../services/clients.js";
import { spAttributeDefinitions } from "../lib/saml/service-providers.js";
import { apiCtx } from "../services/context.js";
import { applyCatalogEntry } from "../services/apps.js";
import { catalogIconUrl, catalogValuePlaceholders, getCatalogEntry, listCatalog, renderInstructions, type CatalogEntry } from "../lib/catalog.js";
import { auditActor } from "../lib/api-auth.js";
import { logAudit } from "../lib/audit.js";
import { removeDomain, revokeKey, updateKey } from "../services/platform.js";
import { AnyObject, badRequest, defineRoute, forbidden, notFound, param, readJson, type ApiContext } from "./openapi.js";
import { ClientSchema, IdParam, ServiceProviderSchema } from "./schemas.js";

/**
 * OIDC clients and SAML service providers one at a time, API keys, domain
 * removal and the SCIM configuration as read back.
 */

// ---------------------------------------------------------------------------
// OIDC clients
// ---------------------------------------------------------------------------

function clientJson(cl: OAuthClientRow) {
  return {
    id: cl.id,
    client_id: cl.client_id,
    name: cl.name,
    client_type: cl.client_type,
    redirect_uris: JSON.parse(cl.redirect_uris) as string[],
    post_logout_redirect_uris: JSON.parse(cl.post_logout_redirect_uris || "[]") as string[],
    frontchannel_logout_uri: cl.frontchannel_logout_uri || null,
    backchannel_logout_uri: cl.backchannel_logout_uri || null,
    initiate_login_uri: cl.initiate_login_uri || null,
    has_jwks: Boolean(cl.jwks || cl.jwks_uri),
    trusted: cl.trusted === 1,
    allowed_claims: cl.allowed_claims === null ? null : parseAllowedClaims(cl),
    id_token_signed_response_alg: isIdTokenAlg(cl.id_token_signed_response_alg) ? cl.id_token_signed_response_alg : "RS256",
    created_at: cl.created_at,
  };
}

async function clientFor(c: ApiContext): Promise<OAuthClientRow | null> {
  return c.env.DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(param(c, "client_id")).first<OAuthClientRow>();
}

const noClient = (c: ApiContext) => notFound(c, `No OIDC client "${param(c, "client_id")}".`);

defineRoute(
  { method: "get", path: "/api/v1/clients/{client_id}", tag: "OIDC clients", permission: "oidc:read", summary: "Get an OIDC client", description: "Never includes the secret.", errors: [404], response: ClientSchema },
  async (c) => {
    const client = await clientFor(c);
    return client ? c.json(clientJson(client)) : noClient(c);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/clients/{client_id}",
    tag: "OIDC clients",
    permission: "oidc:write",
    summary: "Update an OIDC client",
    description: "Fields not supplied keep their values. The client id, type and secret are not changed here (see rotate-secret).",
    body: z.object({
      name: z.string().optional(),
      redirect_uris: z.array(z.string()).optional(),
      trusted: z.boolean().optional(),
      allowed_claims: z.array(z.string()).nullable().optional().openapi({ description: "Claim groups this client may receive; null = every group." }),
      post_logout_redirect_uris: z.array(z.string()).optional(),
      frontchannel_logout_uri: z.string().optional().openapi({ description: "https URL; empty clears it." }),
      backchannel_logout_uri: z.string().optional().openapi({ description: "https URL; empty clears it." }),
      initiate_login_uri: z.string().optional().openapi({ description: "https URL; empty clears it." }),
      id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS).optional().openapi({ description: "How this client's id_tokens are signed." }),
    }),
    errors: [404],
    response: ClientSchema,
  },
  async (c) => {
    const client = await clientFor(c);
    if (!client) return noClient(c);
    const body = await readJson<{ name?: string; redirect_uris?: string[]; trusted?: boolean; allowed_claims?: string[] | null; post_logout_redirect_uris?: string[]; frontchannel_logout_uri?: string; backchannel_logout_uri?: string; initiate_login_uri?: string; id_token_signed_response_alg?: string }>(c);
    const current = clientJson(client);
    const name = String(body.name ?? current.name).trim();
    if (!name) return c.json(badRequest("name cannot be empty."), 400);
    const redirectUris = (body.redirect_uris ?? current.redirect_uris).map((u) => String(u).trim()).filter(Boolean);
    if (redirectUris.length === 0) return c.json(badRequest("At least one redirect_uri is required."), 400);
    const badClaim = (body.allowed_claims ?? []).find((g) => !(CLAIM_GROUPS as readonly string[]).includes(g));
    if (badClaim) return c.json(badRequest(`Unknown claim group "${badClaim}". Valid: ${CLAIM_GROUPS.join(", ")}.`), 400);
    const logout = (body.post_logout_redirect_uris ?? current.post_logout_redirect_uris).map((u) => String(u).trim()).filter(Boolean);
    const badLogout = logout.find((u) => !isValidPostLogoutUri(u));
    if (badLogout) return c.json(badRequest(`post_logout_redirect_uri "${badLogout}" must be https (or http on a loopback host).`), 400);
    const fcl = body.frontchannel_logout_uri === undefined ? (client.frontchannel_logout_uri ?? "") : validFrontchannelUri(String(body.frontchannel_logout_uri).trim());
    if (body.frontchannel_logout_uri && !fcl) return c.json(badRequest("frontchannel_logout_uri must be an https URL."), 400);
    const bcl = body.backchannel_logout_uri === undefined ? undefined : validFrontchannelUri(String(body.backchannel_logout_uri).trim());
    if (body.backchannel_logout_uri && !bcl) return c.json(badRequest("backchannel_logout_uri must be an https URL."), 400);
    const init = body.initiate_login_uri === undefined ? undefined : validFrontchannelUri(String(body.initiate_login_uri).trim());
    if (body.initiate_login_uri && !init) return c.json(badRequest("initiate_login_uri must be an https URL."), 400);
    if (body.id_token_signed_response_alg !== undefined && !isIdTokenAlg(body.id_token_signed_response_alg)) {
      return c.json(badRequest(`id_token_signed_response_alg must be one of ${ID_TOKEN_ALGS.join(", ")}.`), 400);
    }
    const claims = body.allowed_claims === undefined ? client.allowed_claims : body.allowed_claims === null ? null : JSON.stringify(CLAIM_GROUPS.filter((g) => body.allowed_claims!.includes(g)));
    await updateClient(apiCtx(c), client.id, {
      name,
      redirectUris,
      trusted: body.trusted === undefined ? client.trusted : body.trusted ? 1 : 0,
      allowedClaims: claims,
      postLogoutRedirectUris: JSON.stringify(logout),
      frontchannelLogoutUri: fcl,
      ...(bcl !== undefined ? { backchannelLogoutUri: bcl } : {}),
      ...(init !== undefined ? { initiateLoginUri: init } : {}),
      idTokenAlg: body.id_token_signed_response_alg as "RS256" | "ES256" | undefined,
    });
    return c.json(clientJson((await clientFor(c))!));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/clients/{client_id}/rotate-secret",
    tag: "OIDC clients",
    permission: "oidc:write",
    summary: "Rotate a confidential client's secret",
    description: "The new secret is returned once; the old one stops working immediately.",
    errors: [404],
    response: z.object({ ok: z.literal(true), client_id: z.string(), client_secret: z.string() }),
  },
  async (c) => {
    const client = await clientFor(c);
    if (!client) return noClient(c);
    return c.json({ ok: true, client_id: client.client_id, client_secret: await rotateClientSecret(apiCtx(c), client) });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/clients/{client_id}", tag: "OIDC clients", permission: "oidc:write", summary: "Delete an OIDC client", description: "With every code, token and consent issued to it.", errors: [404] },
  async (c) => {
    const client = await clientFor(c);
    if (!client) return noClient(c);
    await deleteClient(apiCtx(c), client);
    return c.json({ ok: true });
  }
);

// ---------------------------------------------------------------------------
// SAML service providers
// ---------------------------------------------------------------------------

defineRoute(
  {
    method: "get",
    path: "/api/v1/saml/service-providers/{id}",
    tag: "SAML",
    permission: "saml:read",
    summary: "Get a service provider",
    description: "Update with POST /api/v1/saml/service-providers (keyed on entity_id).",
    params: IdParam,
    errors: [404],
    response: ServiceProviderSchema,
  },
  async (c) => {
    const sp = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(Number(param(c, "id"))).first<SamlServiceProviderRow>();
    if (!sp) return notFound(c, `No service provider with id ${param(c, "id")}.`);
    return c.json({
      id: sp.id,
      entity_id: sp.entity_id,
      name: sp.name,
      acs_urls: JSON.parse(sp.acs_urls) as string[],
      default_acs_url: sp.default_acs_url,
      nameid_format: sp.nameid_format,
      attribute_map: JSON.parse(sp.attribute_map) as Record<string, string>,
      attribute_definitions: spAttributeDefinitions(sp).map((d) => ({ name: d.name, field: d.field, name_format: d.nameFormat ?? null })),
      sign_response: sp.sign_response === 1,
      sign_assertion: sp.sign_assertion === 1,
      want_authn_requests_signed: sp.want_authn_requests_signed === 1,
      signing_certs: JSON.parse(sp.signing_certs) as string[],
      slo_url: sp.slo_url,
      encryption_cert: sp.encryption_cert,
      encrypt_assertions: sp.encrypt_assertions === 1,
      encryption_policy: sp.encryption_policy ? (JSON.parse(sp.encryption_policy) as Record<string, unknown>) : null,
      subject_id: sp.subject_id ?? "",
      metadata_url: sp.metadata_url,
      created_at: sp.created_at,
      updated_at: sp.updated_at,
    });
  }
);

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

const ApiKeySchema = z
  .object({
    id: z.number(),
    name: z.string(),
    prefix: z.string().openapi({ description: "The non-secret start of the token, for recognising it." }),
    scopes: z.array(z.string()),
    created_at: z.string(),
    created_by: z.string().nullable(),
    last_used_at: z.string().nullable(),
    expires_at: z.string().nullable(),
    revoked_at: z.string().nullable(),
  })
  .openapi("ApiKey");

defineRoute(
  { method: "get", path: "/api/v1/api-keys", tag: "API keys", permission: "api_keys:read", summary: "List API keys", description: "Never the tokens or their hashes.", response: z.object({ api_keys: z.array(ApiKeySchema) }) },
  async (c) => {
    const keys = (await listApiKeys(c.env)).map((k) => ({
      id: k.id,
      name: k.name,
      prefix: k.prefix,
      scopes: parseScopes(k.scopes),
      created_at: k.created_at,
      created_by: k.created_by,
      last_used_at: k.last_used_at,
      expires_at: k.expires_at,
      revoked_at: k.revoked_at,
    }));
    return c.json({ api_keys: keys });
  }
);

defineRoute(
  {
    method: "patch", path: "/api/v1/api-keys/{id}", tag: "API keys", permission: "api_keys:write",
    summary: "Rename an API key or change its permissions",
    description: "Takes effect on the key's next request. The token itself never changes - rotate by revoking and minting a new one. Revoked keys are read-only.",
    params: IdParam,
    body: z.object({ name: z.string(), scopes: z.array(z.string()) }),
    errors: [400, 404, 409],
  },
  async (c) => {
    const body = await readJson<{ name?: string; scopes?: string[] }>(c);
    const name = String(body.name ?? "").trim();
    if (!name) return c.json(badRequest("name is required."), 400);
    if (!Array.isArray(body.scopes)) return c.json(badRequest("scopes is required."), 400);
    const requested = body.scopes.map(String);
    const invalid = requested.filter((s) => !isApiScope(s));
    if (invalid.length > 0) return c.json(badRequest(`Unknown scope(s): ${invalid.join(", ")}.`), 400);
    if (requested.length === 0) return c.json(badRequest("scopes cannot be empty."), 400);
    // Same rule the console enforces: a key can only carry scopes the caller
    // itself holds - otherwise api_keys:write alone could escalate itself to *.
    const actor = c.get("apiActor");
    const beyond = requested.filter((s) => !hasScope(actor.scopes, s));
    if (beyond.length) return forbidden(c, `This token cannot grant scopes it does not hold: ${beyond.join(", ")}.`);
    await updateKey(apiCtx(c), Number(param(c, "id")), { name, scopes: requested });
    return c.json({ ok: true });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/api-keys/{id}", tag: "API keys", permission: "api_keys:write", summary: "Revoke an API key", description: "Anything using it stops working immediately. Cannot be undone.", params: IdParam, errors: [404] },
  async (c) => {
    await revokeKey(apiCtx(c), Number(param(c, "id")));
    return c.json({ ok: true });
  }
);

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

defineRoute(
  { method: "delete", path: "/api/v1/domains/{domain}", tag: "Domains", permission: "domains:write", summary: "Remove a domain", description: "Refused while it is the last domain or any user's UPN is on it.", errors: [404, 409] },
  async (c) => {
    const domain = param(c, "domain").toLowerCase();
    const row = (await listDomains(c.env)).find((d) => d.domain === domain);
    if (!row) return notFound(c, `No such domain "${domain}".`);
    await removeDomain(apiCtx(c), row.id);
    return c.json({ ok: true });
  }
);

// ---------------------------------------------------------------------------
// SCIM
// ---------------------------------------------------------------------------

/** One target as the API sees it: the secret is write-only, reported only as set/unset. */
function targetJson(t: ScimTarget) {
  return {
    id: t.id,
    name: t.name,
    endpoint: t.endpoint,
    secret_set: Boolean(t.secret),
    scope: { mode: t.scope.mode, group_ids: t.scope.groupIds },
    tuning: { pace_ms: t.paceMs, members_per_request: t.membersPerRequest, sync_batch: t.syncBatchSize },
    enabled: t.enabled,
  };
}

const ScimTargetSchema = z.object({
  id: z.number(),
  name: z.string(),
  endpoint: z.string(),
  secret_set: z.boolean(),
  scope: z.object({ mode: z.enum(["all", "selected"]), group_ids: z.array(z.number()) }),
  tuning: z.object({ pace_ms: z.number(), members_per_request: z.number(), sync_batch: z.number() }),
  enabled: z.boolean(),
});

/** The first target, for the legacy single-target /scim/config view. */
async function defaultTarget(env: ApiContext["env"]): Promise<ScimTarget | null> {
  return (await listScimTargets(env)).sort((a, b) => a.id - b.id)[0] ?? null;
}

defineRoute(
  {
    method: "get",
    path: "/api/v1/scim/config",
    tag: "SCIM",
    permission: "scim:read",
    summary: "Read the first SCIM target's configuration",
    description: "The legacy single-target view: the first target in the list. Whether a secret is set, never the secret. `/api/v1/scim/targets` lists them all.",
    response: z.object({ endpoint: z.string(), secret_set: z.boolean(), scope: z.object({ mode: z.enum(["all", "selected"]), group_ids: z.array(z.number()) }) }),
  },
  async (c) => {
    const t = await defaultTarget(c.env);
    return c.json({ endpoint: t?.endpoint ?? "", secret_set: Boolean(t?.secret), scope: { mode: t?.scope.mode ?? "all", group_ids: t?.scope.groupIds ?? [] } });
  }
);

defineRoute({
  method: "get", path: "/api/v1/scim/targets", tag: "SCIM", permission: "scim:read", summary: "List outbound SCIM targets",
  description: "One row per downstream SCIM server, each with its own endpoint, credential (write-only), scope and tuning.",
  response: z.object({ targets: z.array(ScimTargetSchema) }),
}, async (c) => c.json({ targets: (await listScimTargets(c.env)).map(targetJson) }));

defineRoute(
  { method: "get", path: "/api/v1/scim/targets/{id}", tag: "SCIM", permission: "scim:read", summary: "Read one SCIM target", params: IdParam, errors: [404], response: ScimTargetSchema },
  async (c) => {
    const t = await getScimTarget(c.env, Number(c.req.param("id")));
    return t ? c.json(targetJson(t)) : notFound(c, "No such SCIM target.");
  }
);

// ---------------------------------------------------------------------------
// Federation (upstream identity providers)
// ---------------------------------------------------------------------------

const UpstreamIdpSchema = z.object({
  id: z.number(),
  name: z.string(),
  protocol: z.enum(["oidc", "saml"]),
  enabled: z.boolean(),
  jit: z.boolean(),
  jit_domain: z.string().nullable(),
  jit_groups: z.array(z.number()).openapi({ description: "Group ids every JIT-provisioned account joins at creation." }),
  config: z.record(z.string(), z.union([z.string(), z.boolean(), z.record(z.string(), z.string())])),
});

function idpJson(u: UpstreamIdpRow) {
  const cfg = { ...idpConfig(u) } as Record<string, unknown>;
  const secretSet = Boolean(cfg.client_secret);
  delete cfg.client_secret;
  return {
    id: u.id,
    name: u.name,
    protocol: u.protocol,
    enabled: u.enabled === 1,
    jit: u.jit === 1,
    jit_domain: u.jit_domain,
    jit_groups: upstreamJitGroups(u),
    config: { ...cfg, ...(u.protocol === "oidc" ? { secret_set: secretSet } : {}) },
  };
}

defineRoute({
  method: "get", path: "/api/v1/federation/idps", tag: "Federation", permission: "federation:read", summary: "List upstream identity providers",
  description: "Providers people can sign in through - FlareID as the relying party. `config` never carries the client secret, only whether one is stored.",
  response: z.object({ idps: z.array(UpstreamIdpSchema) }),
}, async (c) => c.json({ idps: (await listUpstreamIdps(c.env)).map(idpJson) }));

defineRoute(
  { method: "get", path: "/api/v1/federation/idps/{id}", tag: "Federation", permission: "federation:read", summary: "Read one upstream identity provider", params: IdParam, errors: [404], response: UpstreamIdpSchema },
  async (c) => {
    const u = await getUpstreamIdp(c.env, Number(c.req.param("id")));
    return u ? c.json(idpJson(u)) : notFound(c, "No such upstream identity provider.");
  }
);

// ---------------------------------------------------------------------------
// App catalog
// ---------------------------------------------------------------------------

const CatalogEntrySummary = z.object({
  slug: z.string(),
  name: z.string(),
  protocol: z.enum(["saml", "oidc"]),
  website: z.string(),
  logo_url: z.string().openapi({ description: "This deployment's URL for the entry's icon; applying the entry sets it as the created record's logo." }),
  placeholders: z.array(z.string()).openapi({ description: "The {name} tokens the caller supplies at apply time." }),
});

const catalogSummary = (issuer: string, e: CatalogEntry) => ({
  slug: e.slug,
  name: e.name,
  protocol: e.protocol,
  website: e.website,
  logo_url: catalogIconUrl(issuer, e),
  placeholders: catalogValuePlaceholders(e),
});

defineRoute(
  {
    method: "get",
    path: "/api/v1/app-catalog",
    tag: "App catalog",
    permissionAnyOf: ["oidc:read", "saml:read"],
    summary: "List the app catalog",
    description: "Templates for well-known applications: the placeholders each entry needs, ready for POST .../apply.",
    response: z.object({ entries: z.array(CatalogEntrySummary) }),
  },
  async (c) => c.json({ entries: listCatalog().map((e) => catalogSummary(c.env.ISSUER_URL, e)) })
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/app-catalog/{slug}",
    tag: "App catalog",
    permissionAnyOf: ["oidc:read", "saml:read"],
    summary: "Read a catalog entry",
    description:
      "The entry's setup instructions with the deployment's own values already substituted ({idp_*} tokens resolved); app-side placeholders stay wrapped in braces until apply supplies them. `saml`/`oidc` is the raw template the apply operation feeds.",
    errors: [404],
    response: CatalogEntrySummary.extend({
      instructions: z.object({
        app: z.array(z.string()).openapi({ description: "Steps to perform in the target application's admin console." }),
        flareid: z.array(z.string()).openapi({ description: "Steps to perform in FlareID." }),
      }),
      saml: AnyObject.optional(),
      oidc: AnyObject.optional(),
    }),
  },
  async (c) => {
    const e = getCatalogEntry(param(c, "slug"));
    if (!e) return notFound(c, `No catalog entry "${param(c, "slug")}".`);
    const instructions = renderInstructions(e, { issuer: c.env.ISSUER_URL });
    return c.json({ ...catalogSummary(c.env.ISSUER_URL, e), instructions: { app: instructions.app, flareid: instructions.flareid }, ...(e.saml ? { saml: e.saml } : {}), ...(e.oidc ? { oidc: e.oidc } : {}) });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/app-catalog/{slug}/apply",
    tag: "App catalog",
    permissionAnyOf: ["oidc:write", "saml:write"],
    summary: "Create an app from a catalog entry",
    description:
      "Builds the SAML service provider or OIDC client the entry templates - saml:write for a SAML entry, oidc:write for OIDC. `values` must fill every placeholder the entry lists. A confidential OIDC client's `client_secret` is returned once, here only.",
    body: z.object({ values: z.record(z.string(), z.string()).optional().openapi({ description: "{placeholder} names to values; every name the entry lists is required." }) }),
    status: 201,
    errors: [404, 409],
    response: z.object({
      ok: z.literal(true),
      protocol: z.enum(["saml", "oidc"]),
      id: z.number(),
      client_id: z.string().optional(),
      client_secret: z.string().optional().openapi({ description: "Only for a confidential OIDC client, and only in this response." }),
    }),
  },
  async (c) => {
    const entry = getCatalogEntry(param(c, "slug"));
    if (!entry) return notFound(c, `No catalog entry "${param(c, "slug")}".`);
    const need = entry.protocol === "saml" ? "saml:write" : "oidc:write";
    if (!hasScope(c.get("apiActor").scopes, need)) return forbidden(c, `Applying a ${entry.protocol.toUpperCase()} entry needs "${need}".`);

    const body = await readJson<{ values?: Record<string, string> }>(c);
    const known = new Set(catalogValuePlaceholders(entry));
    const values = Object.fromEntries(
      Object.entries(body.values ?? {})
        .map(([k, v]) => [k.trim(), String(v).trim()] as const)
        .filter(([k, v]) => v !== "" && known.has(k))
    );
    const missing = catalogValuePlaceholders(entry).filter((n) => !values[n]);
    if (missing.length) return c.json(badRequest(`Missing values for placeholders: ${missing.join(", ")}.`), 400);

    // applyCatalogEntry (services/apps.ts) is the same path the console's
    // apply wizard takes - one implementation for both.
    let result: Awaited<ReturnType<typeof applyCatalogEntry>>;
    try {
      result = await applyCatalogEntry(c.env, entry, values, c.env.ISSUER_URL);
    } catch (e) {
      if (e instanceof Error && /unique/i.test(e.message)) return c.json({ error: "conflict", message: "A record with this identity already exists - check the placeholder values." }, 409);
      throw e;
    }
    if (!result.ok) return c.json(badRequest(result.error), 400);

    const action = result.protocol === "saml" ? "saml_sp.created" : "oidc_client.created";
    await logAudit(c.env, auditActor(c.get("apiActor")), action, entry.name, { via: `catalog:${entry.slug}` }, c.req.raw);
    return c.json({ ok: true, protocol: result.protocol, id: result.id, ...(result.protocol === "oidc" ? { client_id: result.clientId, ...(result.clientSecret ? { client_secret: result.clientSecret } : {}) } : {}) }, 201);
  }
);

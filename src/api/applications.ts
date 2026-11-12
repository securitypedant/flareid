import { z } from "@hono/zod-openapi";
import { listApiKeys, parseScopes } from "../lib/api-keys.js";
import { listDomains } from "../lib/domains.js";
import { CLAIM_GROUPS, isValidPostLogoutUri, parseAllowedClaims } from "../lib/oidc.js";
import { getScimConfig, getScimScope } from "../lib/settings.js";
import type { OAuthClientRow, SamlServiceProviderRow } from "../lib/types.js";
import { deleteClient, ID_TOKEN_ALGS, isIdTokenAlg, rotateClientSecret, updateClient, validFrontchannelUri } from "../services/clients.js";
import { apiCtx } from "../services/context.js";
import { removeDomain, revokeKey } from "../services/platform.js";
import { badRequest, defineRoute, notFound, param, readJson, type ApiContext } from "./openapi.js";
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
      id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS).optional().openapi({ description: "How this client's id_tokens are signed." }),
    }),
    errors: [404],
    response: ClientSchema,
  },
  async (c) => {
    const client = await clientFor(c);
    if (!client) return noClient(c);
    const body = await readJson<{ name?: string; redirect_uris?: string[]; trusted?: boolean; allowed_claims?: string[] | null; post_logout_redirect_uris?: string[]; frontchannel_logout_uri?: string; id_token_signed_response_alg?: string }>(c);
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
      sign_response: sp.sign_response === 1,
      sign_assertion: sp.sign_assertion === 1,
      want_authn_requests_signed: sp.want_authn_requests_signed === 1,
      signing_certs: JSON.parse(sp.signing_certs) as string[],
      slo_url: sp.slo_url,
      encryption_cert: sp.encryption_cert,
      encrypt_assertions: sp.encrypt_assertions === 1,
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

defineRoute(
  {
    method: "get",
    path: "/api/v1/scim/config",
    tag: "SCIM",
    permission: "scim:read",
    summary: "Read the SCIM configuration",
    description: "Whether a secret is set, never the secret.",
    response: z.object({ endpoint: z.string(), secret_set: z.boolean(), scope: z.object({ mode: z.enum(["all", "selected"]), group_ids: z.array(z.number()) }) }),
  },
  async (c) => {
    const [config, scope] = await Promise.all([getScimConfig(c.env), getScimScope(c.env)]);
    return c.json({ endpoint: config.endpoint, secret_set: Boolean(config.secret), scope: { mode: scope.mode, group_ids: scope.groupIds } });
  }
);

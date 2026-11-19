import { Hono } from "hono";
import type { Env } from "../env.js";
import { isValidPostLogoutUri } from "../lib/oidc.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import type { OAuthClientRow } from "../lib/types.js";
import { deleteClient, ID_TOKEN_ALGS, isIdTokenAlg, validFrontchannelUri } from "../services/clients.js";

/**
 * Dynamic client registration (RFC 7591 create, RFC 7592 read/update/delete).
 *
 * Third parties register themselves at POST /connect/register with client
 * metadata and get back a client_id, a client_secret and a registration access
 * token that manages the record afterwards. Dynamically registered clients
 * are untrusted - the consent screen always shows - and public when their
 * token_endpoint_auth_method is "none".
 */

export const registration = new Hono<{ Bindings: Env }>();

const AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none", "private_key_jwt"] as const;
const GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"] as const;

interface ClientMetadata {
  redirect_uris?: string[];
  client_name?: string;
  post_logout_redirect_uris?: string[];
  frontchannel_logout_uri?: string;
  backchannel_logout_uri?: string;
  initiate_login_uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  client_uri?: string;
  token_endpoint_auth_method?: string;
  id_token_signed_response_alg?: string;
  jwks?: { keys?: unknown[] };
  jwks_uri?: string;
  grant_types?: string[];
  scope?: string;
  contacts?: string[];
}

function metadataError(message: string) {
  return { error: "invalid_client_metadata", error_description: message };
}

/** Redirect URIs follow the same rule as admin-created clients: https, or http on a loopback host. */
function validRedirectUri(u: string): boolean {
  try {
    const url = new URL(u);
    // OIDC Core 3.1.2.1: a redirect_uri MUST NOT include a fragment component.
    if (url.hash) return false;
    if (url.protocol === "https:") return true;
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  } catch {
    return false;
  }
}

/** Storage bounds for self-service rows: registered documents feed a per-request JSON.parse and live forever otherwise. */
const MAX_REDIRECT_URIS = 32;
const MAX_URI_CHARS = 2048;
const MAX_JWKS_CHARS = 65_536;
const MAX_DYNAMIC_CLIENTS = 5000;

function validate(body: ClientMetadata, isUpdate: boolean): { ok: true } | { ok: false; message: string } {
  const uris = (body.redirect_uris ?? []).map((u) => String(u).trim()).filter(Boolean);
  if (uris.length > MAX_REDIRECT_URIS || uris.some((u) => u.length > MAX_URI_CHARS)) {
    return { ok: false, message: `redirect_uris is limited to ${MAX_REDIRECT_URIS} entries of ${MAX_URI_CHARS} characters.` };
  }
  if (!isUpdate || body.redirect_uris !== undefined) {
    if (uris.length === 0) return { ok: false, message: "redirect_uris is required and must be non-empty." };
    const frag = uris.find((u) => {
      try {
        return Boolean(new URL(u).hash);
      } catch {
        return false;
      }
    });
    if (frag) return { ok: false, message: `redirect_uri "${frag}" must not contain a fragment component.` };
    const bad = uris.find((u) => !validRedirectUri(u));
    if (bad) return { ok: false, message: `redirect_uri "${bad}" must be https (or http on a loopback host).` };
  }
  const httpsFields: [string | undefined, string][] = [
    [body.frontchannel_logout_uri, "frontchannel_logout_uri"],
    [body.backchannel_logout_uri, "backchannel_logout_uri"],
    [body.initiate_login_uri, "initiate_login_uri"],
    [body.jwks_uri, "jwks_uri"],
    [body.logo_uri, "logo_uri"],
    [body.policy_uri, "policy_uri"],
    [body.tos_uri, "tos_uri"],
    [body.client_uri, "client_uri"],
  ];
  for (const [u, name] of httpsFields) {
    if (u !== undefined && u !== "" && !validFrontchannelUri(u)) return { ok: false, message: `${name} must be an https URL.` };
  }
  if (body.post_logout_redirect_uris !== undefined) {
    const bad = body.post_logout_redirect_uris.find((u) => !isValidPostLogoutUri(u));
    if (bad) return { ok: false, message: `post_logout_redirect_uri "${bad}" must be https (or http on a loopback host).` };
  }
  if (body.token_endpoint_auth_method !== undefined && !(AUTH_METHODS as readonly string[]).includes(body.token_endpoint_auth_method)) {
    return { ok: false, message: `token_endpoint_auth_method must be one of ${AUTH_METHODS.join(", ")}.` };
  }
  if (body.token_endpoint_auth_method === "private_key_jwt" && !body.jwks && !body.jwks_uri) {
    return { ok: false, message: "private_key_jwt needs jwks or jwks_uri." };
  }
  if (body.jwks !== undefined) {
    const keys = body.jwks?.keys;
    if (!body.jwks || typeof body.jwks !== "object" || !Array.isArray(keys) || keys.length === 0) {
      return { ok: false, message: "jwks must be a JSON Web Key Set object with a non-empty keys array." };
    }
    if (JSON.stringify(body.jwks).length > MAX_JWKS_CHARS) {
      return { ok: false, message: `jwks is limited to ${MAX_JWKS_CHARS} characters when serialised.` };
    }
  }
  if (body.id_token_signed_response_alg !== undefined && !isIdTokenAlg(body.id_token_signed_response_alg)) {
    return { ok: false, message: `id_token_signed_response_alg must be one of ${ID_TOKEN_ALGS.join(", ")}.` };
  }
  if (body.grant_types !== undefined) {
    const bad = body.grant_types.find((g) => !(GRANT_TYPES as readonly string[]).includes(g));
    if (bad) return { ok: false, message: `grant_type "${bad}" is not supported. Supported: ${GRANT_TYPES.join(", ")}.` };
  }
  return { ok: true };
}

/** The metadata document RFC 7592 expects back, plus the secrets that exist only at registration. */
function clientBody(env: Env, row: OAuthClientRow, opts: { secret?: string; registrationToken?: string } = {}) {
  const authMethod = row.client_type === "public" ? "none" : row.jwks || row.jwks_uri ? "private_key_jwt" : "client_secret_basic";
  return {
    client_id: row.client_id,
    client_id_issued_at: Math.floor(new Date(row.created_at).getTime() / 1000),
    ...(opts.secret !== undefined ? { client_secret: opts.secret, client_secret_expires_at: 0 } : {}),
    ...(opts.registrationToken !== undefined ? { registration_access_token: opts.registrationToken, registration_client_uri: `${env.ISSUER_URL}/connect/register/${row.client_id}` } : {}),
    client_name: row.name,
    redirect_uris: JSON.parse(row.redirect_uris) as string[],
    post_logout_redirect_uris: JSON.parse(row.post_logout_redirect_uris || "[]") as string[],
    token_endpoint_auth_method: authMethod,
    id_token_signed_response_alg: row.id_token_signed_response_alg,
    ...(row.frontchannel_logout_uri ? { frontchannel_logout_uri: row.frontchannel_logout_uri } : {}),
    ...(row.backchannel_logout_uri ? { backchannel_logout_uri: row.backchannel_logout_uri } : {}),
    ...(row.initiate_login_uri ? { initiate_login_uri: row.initiate_login_uri } : {}),
    ...(row.jwks ? { jwks: JSON.parse(row.jwks) } : {}),
    ...(row.jwks_uri ? { jwks_uri: row.jwks_uri } : {}),
    ...(row.logo_uri ? { logo_uri: row.logo_uri } : {}),
    ...(row.policy_uri ? { policy_uri: row.policy_uri } : {}),
    ...(row.tos_uri ? { tos_uri: row.tos_uri } : {}),
    ...(row.client_uri ? { client_uri: row.client_uri } : {}),
    ...(row.grant_types ? { grant_types: JSON.parse(row.grant_types) } : {}),
    ...(row.registered_scope ? { scope: row.registered_scope } : {}),
  };
}

registration.post("/connect/register", async (c) => {
  let body: ClientMetadata;
  try {
    body = (await c.req.json()) as ClientMetadata;
  } catch {
    return c.json(metadataError("The request body is not valid JSON."), 400);
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return c.json(metadataError("The request body is a JSON object."), 400);
  const ok = validate(body, false);
  if (!ok.ok) return c.json(metadataError(ok.message), 400);

  const dynamics = (await c.env.DB.prepare("SELECT COUNT(*) AS n FROM oauth_clients WHERE registration_token_hash IS NOT NULL AND registration_token_hash != ''").first<{ n: number }>())?.n ?? 0;
  if (dynamics >= MAX_DYNAMIC_CLIENTS) return c.json(metadataError("Dynamic client registration is at capacity."), 503);

  const authMethod = body.token_endpoint_auth_method ?? "client_secret_basic";
  const isPublic = authMethod === "none";
  const clientId = `flareid_${randomToken(8)}`;
  const clientSecret = isPublic ? "" : randomToken(24);
  const registrationToken = randomToken(24);
  const name = String(body.client_name ?? "").trim().slice(0, 200) || clientId;

  await c.env.DB.prepare(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, client_type, trusted, allowed_claims, post_logout_redirect_uris,
      frontchannel_logout_uri, backchannel_logout_uri, initiate_login_uri, registration_token_hash, jwks, jwks_uri, id_token_signed_response_alg, grant_types, registered_scope,
      logo_uri, policy_uri, tos_uri, client_uri)
     VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      clientId,
      isPublic ? "" : await sha256Hex(clientSecret),
      name,
      JSON.stringify((body.redirect_uris ?? []).map((u) => u.trim()).filter(Boolean)),
      new Date().toISOString(),
      isPublic ? "public" : "confidential",
      JSON.stringify((body.post_logout_redirect_uris ?? []).map((u) => u.trim()).filter(Boolean)),
      validFrontchannelUri(body.frontchannel_logout_uri ?? "") || "",
      validFrontchannelUri(body.backchannel_logout_uri ?? "") || "",
      validFrontchannelUri(body.initiate_login_uri ?? "") || "",
      await sha256Hex(registrationToken),
      body.jwks ? JSON.stringify(body.jwks) : null,
      validFrontchannelUri(body.jwks_uri ?? "") || null,
      body.id_token_signed_response_alg ?? "RS256",
      body.grant_types ? JSON.stringify([...new Set(body.grant_types)]) : null,
      body.scope !== undefined ? body.scope.trim().slice(0, 512) : null,
      body.logo_uri !== undefined ? validFrontchannelUri(body.logo_uri) || null : null,
      body.policy_uri !== undefined ? validFrontchannelUri(body.policy_uri) || null : null,
      body.tos_uri !== undefined ? validFrontchannelUri(body.tos_uri) || null : null,
      body.client_uri !== undefined ? validFrontchannelUri(body.client_uri) || null : null
    )
    .run();

  const row = await c.env.DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(clientId).first<OAuthClientRow>();
  return c.json(clientBody(c.env, row!, { secret: isPublic ? undefined : clientSecret, registrationToken }), 201);
});

/** Reads the RFC 7592 registration access token out of the Authorization header. */
async function registeredClient(env: Env, c: { req: { header: (n: string) => string | undefined }; clientId: string }): Promise<OAuthClientRow | "unauthorized" | null> {
  const client = await env.DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(c.clientId).first<OAuthClientRow>();
  if (!client) return null;
  if (!client.registration_token_hash) return "unauthorized";
  const token = (c.req.header("Authorization") ?? "").match(/^Bearer\s+(.+)$/)?.[1];
  if (!token || (await sha256Hex(token)) !== client.registration_token_hash) return "unauthorized";
  return client;
}

const unauth = () => ({ error: "invalid_token", error_description: "A valid registration access token is required." });

registration.get("/connect/register/:client_id", async (c) => {
  const client = await registeredClient(c.env, { req: c.req, clientId: c.req.param("client_id") });
  if (client === null) return c.json({ error: "invalid_client_id" }, 404);
  if (client === "unauthorized") return c.json(unauth(), 401);
  return c.json(clientBody(c.env, client, { registrationToken: undefined }));
});

registration.put("/connect/register/:client_id", async (c) => {
  const client = await registeredClient(c.env, { req: c.req, clientId: c.req.param("client_id") });
  if (client === null) return c.json({ error: "invalid_client_id" }, 404);
  if (client === "unauthorized") return c.json(unauth(), 401);

  let body: ClientMetadata;
  try {
    body = (await c.req.json()) as ClientMetadata;
  } catch {
    return c.json(metadataError("The request body is not valid JSON."), 400);
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return c.json(metadataError("The request body is a JSON object."), 400);
  const ok = validate(body, true);
  if (!ok.ok) return c.json(metadataError(ok.message), 400);

  const redirectUris = body.redirect_uris !== undefined ? JSON.stringify(body.redirect_uris.map((u) => u.trim()).filter(Boolean)) : client.redirect_uris;
  const postLogout = body.post_logout_redirect_uris !== undefined ? JSON.stringify(body.post_logout_redirect_uris.map((u) => u.trim()).filter(Boolean)) : client.post_logout_redirect_uris;
  const fcl = body.frontchannel_logout_uri !== undefined ? validFrontchannelUri(body.frontchannel_logout_uri) : client.frontchannel_logout_uri;
  const bcl = body.backchannel_logout_uri !== undefined ? validFrontchannelUri(body.backchannel_logout_uri) : client.backchannel_logout_uri;
  const init = body.initiate_login_uri !== undefined ? validFrontchannelUri(body.initiate_login_uri) : client.initiate_login_uri;
  const jwks = body.jwks !== undefined ? JSON.stringify(body.jwks) : client.jwks;
  const jwksUri = body.jwks_uri !== undefined ? validFrontchannelUri(body.jwks_uri) || null : client.jwks_uri;
  const alg = body.id_token_signed_response_alg !== undefined ? body.id_token_signed_response_alg : client.id_token_signed_response_alg;
  const name = body.client_name !== undefined ? String(body.client_name).trim() || client.name : client.name;
  const isPublic = body.token_endpoint_auth_method !== undefined ? body.token_endpoint_auth_method === "none" : client.client_type === "public";
  const grantTypes = body.grant_types !== undefined ? JSON.stringify([...new Set(body.grant_types)]) : client.grant_types;
  const registeredScope = body.scope !== undefined ? body.scope.trim().slice(0, 512) : client.registered_scope;
  const logo = body.logo_uri !== undefined ? validFrontchannelUri(body.logo_uri) || null : client.logo_uri;
  const policy = body.policy_uri !== undefined ? validFrontchannelUri(body.policy_uri) || null : client.policy_uri;
  const tos = body.tos_uri !== undefined ? validFrontchannelUri(body.tos_uri) || null : client.tos_uri;
  const clientUri = body.client_uri !== undefined ? validFrontchannelUri(body.client_uri) || null : client.client_uri;

  await c.env.DB.prepare(
    `UPDATE oauth_clients SET name = ?, redirect_uris = ?, post_logout_redirect_uris = ?, frontchannel_logout_uri = ?, backchannel_logout_uri = ?,
       initiate_login_uri = ?, jwks = ?, jwks_uri = ?, id_token_signed_response_alg = ?, client_type = ?, grant_types = ?, registered_scope = ?,
       logo_uri = ?, policy_uri = ?, tos_uri = ?, client_uri = ? WHERE id = ?`
  )
    .bind(name, redirectUris, postLogout, fcl, bcl, init, jwks, jwksUri, alg, isPublic ? "public" : "confidential", grantTypes, registeredScope, logo, policy, tos, clientUri, client.id)
    .run();

  const updated = await c.env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(client.id).first<OAuthClientRow>();
  return c.json(clientBody(c.env, updated!));
});

registration.delete("/connect/register/:client_id", async (c) => {
  const client = await registeredClient(c.env, { req: c.req, clientId: c.req.param("client_id") });
  if (client === null) return c.json({ error: "invalid_client_id" }, 404);
  if (client === "unauthorized") return c.json(unauth(), 401);
  const ctx = { env: c.env, actor: { id: null, upn: "registration" }, privileged: true, selfId: null };
  await deleteClient(ctx, client);
  return c.body(null, 204);
});

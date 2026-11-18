import { createLocalJWKSet, createRemoteJWKSet, jwtVerify, type JWTVerifyOptions } from "jose";
import type { Env } from "../env.js";
import { getClientByClientId } from "./db.js";
import { sha256Hex } from "./tokens.js";
import type { OAuthClientRow } from "./types.js";

const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** Remote JWKS documents change rarely; one getter per URI, keyed for the process. */
const remoteJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/**
 * RFC 7523 private_key_jwt: the client authenticates with a JWT it signed with
 * a private key whose public half it registered (jwks or jwks_uri metadata).
 * iss and sub are its client_id; aud is this OP's issuer or token endpoint.
 */
async function verifyClientAssertion(env: Env, client: OAuthClientRow, assertion: string): Promise<boolean> {
  let keySet: ReturnType<typeof createLocalJWKSet> | ReturnType<typeof createRemoteJWKSet>;
  if (client.jwks) {
    try {
      keySet = createLocalJWKSet(JSON.parse(client.jwks) as Parameters<typeof createLocalJWKSet>[0]);
    } catch {
      return false;
    }
  } else if (client.jwks_uri) {
    // Bound the getter cache: each entry is a distinct caller-registered https
    // endpoint this isolate will fetch, so the map's size bounds the SSRF
    // reach an anonymous request can give the worker.
    if (remoteJwks.size >= 500) remoteJwks.clear();
    let jwks = remoteJwks.get(client.jwks_uri);
    if (!jwks) {
      jwks = createRemoteJWKSet(new URL(client.jwks_uri), { timeoutDuration: 10_000 });
      remoteJwks.set(client.jwks_uri, jwks);
    }
    keySet = jwks;
  } else {
    return false;
  }
  try {
    const opts: JWTVerifyOptions = {
      issuer: client.client_id,
      subject: client.client_id,
      audience: [env.ISSUER_URL, `${env.ISSUER_URL}/token`],
      // RFC 7523 section 3: assertions must expire and carry a unique jti;
      // without them a captured assertion is replayable forever.
      requiredClaims: ["exp", "iat", "jti"],
      maxTokenAge: "5m",
    };
    const { payload } = await jwtVerify(assertion, keySet, opts);
    const jtiSeen = await env.DB.prepare(
      `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count`
    ).bind(`pkjwt:${client.client_id}:${String(payload.jti)}`, Date.now()).first<{ count: number }>();
    return (jtiSeen?.count ?? 1) === 1;
  } catch {
    return false;
  }
}

function parseBasicAuth(header: string | undefined): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice("Basic ".length));
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex === -1) return null;
    return { clientId: decodeURIComponent(decoded.slice(0, separatorIndex)), clientSecret: decodeURIComponent(decoded.slice(separatorIndex + 1)) };
  } catch {
    return null;
  }
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

/**
 * Authenticates an OAuth client at the token, introspection and revocation
 * endpoints.
 *
 * Confidential clients: HTTP Basic or client_id/client_secret in the body.
 * Public clients (token_endpoint_auth_method "none"): client_id alone, and
 * only where `allowPublic` - at /token, where PKCE binds the code to the app
 * that started the flow instead of a secret. A public client presenting a
 * secret is refused rather than ignored: it is misconfigured, and silently
 * accepting would hide that.
 */
export async function authenticateClient(
  env: Env,
  body: Record<string, unknown>,
  authHeader: string | undefined,
  opts: { allowPublic?: boolean } = {}
): Promise<OAuthClientRow | null> {
  const basic = parseBasicAuth(authHeader);
  const clientId = basic?.clientId ?? String(body.client_id ?? "");
  const clientSecret = basic?.clientSecret ?? String(body.client_secret ?? "");
  if (!clientId) return null;

  const client = await getClientByClientId(env, clientId);
  if (!client) return null;

  if (client.client_type === "public") return opts.allowPublic && !clientSecret ? client : null;
  if (!clientSecret) {
    if (String(body.client_assertion_type ?? "") === ASSERTION_TYPE && typeof body.client_assertion === "string" && (await verifyClientAssertion(env, client, body.client_assertion))) {
      return client;
    }
    return null;
  }
  if (!client.client_secret_hash) return null;
  return timingSafeEqualHex(await sha256Hex(clientSecret), client.client_secret_hash) ? client : null;
}

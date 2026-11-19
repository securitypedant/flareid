import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
  type JWTVerifyResult,
} from "jose";
import type { Env } from "../env.js";
import type { OAuthClientRow } from "./types.js";

/**
 * JAR - JWT-Secured Authorization Request (RFC 9101). A signed `request` JWT
 * (or one fetched from a registered `request_uri`) carries the authorization
 * parameters; its signature authenticates them the way client_secret auth
 * authenticates a token request.
 *
 * Policy choices:
 * - Only asymmetric object algs (RS256/ES256). `alg=none` and HS* are rejected -
 *   none offers no integrity, and HS* would let anyone holding the public
 *   client metadata forge requests.
 * - `request_uri` values must be registered on the client (`request_uris`).
 *   Fetching an arbitrary caller-supplied URL would turn /authorize into an
 *   SSRF proxy.
 */

const REQUEST_OBJECT_ALGS = ["RS256", "ES256"];
const MAX_REQUEST_OBJECT_CHARS = 64 * 1024;
const REQUEST_URI_TIMEOUT_MS = 5000;
const REGISTERED_CLAIMS = new Set(["iss", "aud", "exp", "nbf", "iat", "jti"]);

type RequestError = { ok: false; error: string; description: string };
export type ResolvedRequest = { ok: true; params: URLSearchParams } | RequestError;

function fail(error: string, description: string): RequestError {
  return { ok: false, error, description };
}

// createRemoteJWKSet caches keys inside the set it returns, so keep one set per
// jwks_uri and reuse it for the life of the isolate.
const remoteJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function clientKeyResolver(client: Pick<OAuthClientRow, "jwks" | "jwks_uri">): JWTVerifyGetKey | null {
  if (client.jwks) {
    try {
      return createLocalJWKSet(JSON.parse(client.jwks) as JSONWebKeySet);
    } catch {
      return null;
    }
  }
  if (client.jwks_uri) {
    let set = remoteJwks.get(client.jwks_uri);
    if (!set) {
      set = createRemoteJWKSet(new URL(client.jwks_uri));
      remoteJwks.set(client.jwks_uri, set);
    }
    return set;
  }
  return null;
}

async function fetchRequestUri(client: OAuthClientRow, uri: string): Promise<{ ok: true; jwt: string } | RequestError> {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return fail("invalid_request_uri", "request_uri is not a valid URL.");
  }
  if (parsed.protocol !== "https:") return fail("invalid_request_uri", "request_uri must be an https URL.");

  const registered = client.request_uris ? (JSON.parse(client.request_uris) as string[]) : [];
  if (!registered.includes(uri)) return fail("invalid_request_uri", "request_uri is not in the client's registered request_uris.");

  const res = await fetch(uri, { signal: AbortSignal.timeout(REQUEST_URI_TIMEOUT_MS), headers: { accept: "application/jwt" } }).catch(() => null);
  if (!res || !res.ok) return fail("invalid_request_uri", `request_uri could not be fetched (${res ? `HTTP ${res.status}` : "network error"}).`);
  const body = (await res.text()).trim();
  if (!body || body.length > MAX_REQUEST_OBJECT_CHARS) return fail("invalid_request_uri", "request_uri did not serve a request object.");
  return { ok: true, jwt: body };
}

/**
 * If the request carries `request`/`request_uri`, returns the merged
 * parameters (query values, overlaid by the object's claims - OIDC Core 6.1)
 * after verifying the object against the client's registered keys.
 */
export async function resolveRequestObject(env: Env, params: URLSearchParams, client: OAuthClientRow): Promise<ResolvedRequest> {
  let compact = params.get("request")?.trim();
  const requestUri = params.get("request_uri");

  if (!compact) {
    if (!requestUri) return { ok: true, params };
    const fetched = await fetchRequestUri(client, requestUri);
    if (!fetched.ok) return fetched;
    compact = fetched.jwt;
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(compact);
  } catch {
    return fail("invalid_request_object", "request object is not a valid JWT.");
  }
  if (!header.alg || header.alg === "none") return fail("invalid_request_object", "Unsigned request objects are not accepted.");
  if (!REQUEST_OBJECT_ALGS.includes(header.alg)) {
    return fail("invalid_request_object", `request object alg "${header.alg}" is not supported; use ${REQUEST_OBJECT_ALGS.join("/")}.`);
  }

  const keyResolver = clientKeyResolver(client);
  if (!keyResolver) return fail("invalid_request_object", "This client must register jwks or jwks_uri to use signed request objects.");

  let verified: JWTVerifyResult;
  try {
    verified = await jwtVerify(compact, keyResolver, { algorithms: REQUEST_OBJECT_ALGS });
  } catch (err) {
    return fail("invalid_request_object", `request object signature verification failed: ${err instanceof Error ? err.message : "unknown error"}.`);
  }
  const payload = verified.payload;

  // RFC 9101 4: iss names the client; aud names the authorization server.
  if (payload.iss !== client.client_id) return fail("invalid_request_object", "request object iss does not match the client_id.");
  const auds = [payload.aud ?? []].flat();
  if (!auds.includes(env.ISSUER_URL) && !auds.includes(`${env.ISSUER_URL}/authorize`)) {
    return fail("invalid_request_object", "request object aud does not name this authorization server.");
  }
  const objectClientId = typeof payload.client_id === "string" ? payload.client_id : payload.iss;
  const queryClientId = params.get("client_id");
  if (queryClientId && objectClientId && queryClientId !== objectClientId) {
    return fail("invalid_request_object", "request object client_id does not match the query client_id.");
  }

  // Merge: query params first, object claims overwrite (Core 6.1 - the object
  // is the authoritative form of the request). Registered JWT claims carry
  // metadata, not request parameters, so they are not copied.
  const merged = new URLSearchParams(params);
  merged.delete("request");
  merged.delete("request_uri");
  for (const [name, value] of Object.entries(payload)) {
    if (REGISTERED_CLAIMS.has(name) || value === undefined || value === null) continue;
    merged.set(name, typeof value === "string" ? value : JSON.stringify(value));
  }
  if (!merged.get("client_id") && objectClientId) merged.set("client_id", objectClientId);
  return { ok: true, params: merged };
}

import { SignJWT, importJWK, jwtVerify, decodeProtectedHeader, type JWTPayload } from "jose";
import { activeSigningKey, publishedKeys, type SigningAlg } from "./signing-keys.js";
import type { Env } from "../env.js";
import type { ClaimGroup } from "./oidc.js";

// Keys live in D1 (signing-keys.ts): one active RS256 and one active ES256.
export interface IdTokenClaims {
  sub: string;
  id: string;
  email: string;
  name: string;
  givenName: string;
  familyName: string;
  username: string;
  groups: string[];
  amr: string[];
  jobTitle: string;
  department: string;
  /** The manager's email, resolved at issuance time from their stable external_id reference. */
  managerEmail: string | null;
  /** Schema-defined attributes beyond the fixed vocabulary, surfaced under the "custom" claim. */
  customAttributes?: Record<string, string>;
  nonce?: string;
}

/**
 * Builds the claim set shared by the id_token and /userinfo, matching the
 * shape Cloudflare Access's own OIDC integrations surface: top-level
 * id/email/name/given_name/family_name/groups/amr, plus HR attributes
 * (job_title/department/manager) so Zero Trust policies can match on them,
 * and a nested "custom" object carrying the same attributes (some Access
 * policy/claim mapping UIs expect custom attributes namespaced under "custom").
 *
 * Only the claim groups in `release` are included (see oidc.ts): what the
 * client asked for by scope, intersected with what it is allowed.
 */
/** Names the IdP asserts itself: a schema attribute never takes them, released or not. */
export const RESERVED_CLAIM_NAMES = new Set(["id", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "groups", "job_title", "department", "manager", "sub", "amr", "acr", "custom"]);

export function buildClaims(claims: IdTokenClaims, release: Set<ClaimGroup>) {
  const attributes: Record<string, unknown> = {};
  if (release.has("profile")) {
    Object.assign(attributes, {
      id: claims.id,
      name: claims.name,
      given_name: claims.givenName,
      family_name: claims.familyName,
      preferred_username: claims.username,
    });
  }
  if (release.has("email")) Object.assign(attributes, { email: claims.email, email_verified: true });
  if (release.has("groups")) attributes.groups = claims.groups;
  if (release.has("hr")) Object.assign(attributes, { job_title: claims.jobTitle, department: claims.department, manager: claims.managerEmail });
  return {
    ...attributes,
    amr: claims.amr,
    ...(release.has("custom")
      ? { custom: { ...Object.fromEntries(Object.entries(claims.customAttributes ?? {}).filter(([k]) => !RESERVED_CLAIM_NAMES.has(k))), ...attributes } }
      : {}),
  };
}

export interface IdTokenProtocol {
  /** Epoch seconds when the user authenticated. */
  authTime: number;
  acr: string;
  sid?: string;
  /** Left half of the access token's SHA-256, base64url (OIDC Core 3.1.3.6). */
  atHash?: string;
}

export async function signIdToken(env: Env, clientId: string, claims: IdTokenClaims, release: Set<ClaimGroup>, protocol: IdTokenProtocol, alg: SigningAlg = "RS256"): Promise<string> {
  const { kid, key } = await activeSigningKey(env, alg);
  const jwt = new SignJWT({
    ...buildClaims(claims, release),
    auth_time: protocol.authTime,
    acr: protocol.acr,
    azp: clientId,
    ...(protocol.sid ? { sid: protocol.sid } : {}),
    ...(protocol.atHash ? { at_hash: protocol.atHash } : {}),
    ...(claims.nonce ? { nonce: claims.nonce } : {}),
  })
    .setProtectedHeader({ alg, kid })
    .setIssuer(env.ISSUER_URL)
    .setAudience(clientId)
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime("10m");

  return jwt.sign(key);
}

export async function atHash(accessToken: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken)));
  let bin = "";
  for (const b of digest.slice(0, 16)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Verifies an id_token this IdP issued, for id_token_hint on logout. The
 * signature and issuer must check out against a published key; expiry does
 * not matter - a hint from a session long since past its token is normal.
 */
export async function verifyOwnIdToken(env: Env, token: string): Promise<JWTPayload | null> {
  let header: { kid?: string; alg?: string };
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return null;
  }
  for (const jwk of await publishedKeys(env)) {
    if (header.kid && jwk.kid !== header.kid) continue;
    if (jwk.alg !== header.alg) continue;
    try {
      const key = await importJWK(jwk as Parameters<typeof importJWK>[0], String(jwk.alg));
      const { payload } = await jwtVerify(token, key, { issuer: env.ISSUER_URL, algorithms: [String(jwk.alg)], currentDate: new Date(0) });
      return payload;
    } catch {
      // try the next published key
    }
  }
  return null;
}

/** /jwks.json: every key a relying party may need to verify a token (see signing-keys.ts). */
export async function getPublicJwks(env: Env) {
  return publishedKeys(env);
}

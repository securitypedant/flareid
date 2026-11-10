import { SignJWT, importPKCS8, importJWK, jwtVerify, type JWTPayload } from "jose";
import type { Env } from "../env.js";
import type { ClaimGroup } from "./oidc.js";

const ALG = "RS256";
const DEFAULT_KEY_ID = "flareid-key-1";

function currentKeyId(env: Env): string {
  return env.SIGNING_KEY_ID || DEFAULT_KEY_ID;
}

async function getSigningKey(env: Env) {
  if (!env.SIGNING_KEY_PKCS8) {
    throw new Error("SIGNING_KEY_PKCS8 is not configured - run `npm run keygen` and set the secret");
  }
  return importPKCS8(env.SIGNING_KEY_PKCS8, ALG);
}

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

export async function signIdToken(env: Env, clientId: string, claims: IdTokenClaims, release: Set<ClaimGroup>, protocol: IdTokenProtocol): Promise<string> {
  const key = await getSigningKey(env);
  const jwt = new SignJWT({
    ...buildClaims(claims, release),
    auth_time: protocol.authTime,
    acr: protocol.acr,
    azp: clientId,
    ...(protocol.sid ? { sid: protocol.sid } : {}),
    ...(protocol.atHash ? { at_hash: protocol.atHash } : {}),
    ...(claims.nonce ? { nonce: claims.nonce } : {}),
  })
    .setProtectedHeader({ alg: ALG, kid: currentKeyId(env) })
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
  for (const jwk of getPublicJwks(env)) {
    try {
      const key = await importJWK(jwk as Parameters<typeof importJWK>[0], ALG);
      const { payload } = await jwtVerify(token, key, { issuer: env.ISSUER_URL, algorithms: [ALG], currentDate: new Date(0) });
      return payload;
    } catch {
      // try the next published key
    }
  }
  return null;
}

/**
 * Publishes every currently-valid public key for /jwks.json (generated by
 * scripts/generate-keypair.mjs). Normally just the current key, but during a
 * rotation window both the current and previous keys are published so tokens
 * signed moments before the rotation remain verifiable until they expire.
 */
export function getPublicJwks(env: Env) {
  const current = JSON.parse(env.SIGNING_PUBLIC_JWK) as Record<string, unknown>;
  const keys = [{ ...current, kid: currentKeyId(env), use: "sig", alg: ALG }];

  if (env.SIGNING_PUBLIC_JWK_PREVIOUS && env.SIGNING_KEY_ID_PREVIOUS) {
    const previous = JSON.parse(env.SIGNING_PUBLIC_JWK_PREVIOUS) as Record<string, unknown>;
    keys.push({ ...previous, kid: env.SIGNING_KEY_ID_PREVIOUS, use: "sig", alg: ALG });
  }

  return keys;
}

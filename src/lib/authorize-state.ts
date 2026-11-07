import type { Env } from "../env.js";
import { randomToken } from "./tokens.js";

export interface PendingAuthorizeRequest {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

export interface PendingSamlRequest {
  /** saml_service_providers.id of the SP this request came from. */
  spId: number;
  /** The AuthnRequest's ID - echoed as InResponseTo in the assertion. */
  requestId: string;
  /** The allowlisted ACS URL the response will be posted to. */
  acsUrl: string;
  relayState: string | null;
}

/**
 * A login flow is one of:
 *  - "oidc": triggered by an RP (e.g. Cloudflare Access) hitting /authorize -
 *    on success we issue an authorization code and redirect back to the RP.
 *  - "saml": triggered by an SP hitting /saml/sso - on success we POST a
 *    signed response to the SP's ACS instead of redirecting.
 *  - "direct": triggered by someone visiting /account or /admin directly in a
 *    browser with no active session - on success we just redirect to `next`.
 */
export type LoginFlow =
  | { kind: "oidc"; request: PendingAuthorizeRequest }
  | { kind: "saml"; request: PendingSamlRequest }
  | { kind: "direct"; next: string };

const FLOW_TTL_SECONDS = 600;
const MFA_TTL_SECONDS = 300;
const RESUME_TTL_SECONDS = 600;

/**
 * Marks a stored login flow as resumable only by the given user. Written only
 * by the post-enrolment resume path, after a completed login - a flow minted
 * by /saml/sso or /authorize has no binding, which is what lets /saml/complete
 * tell "paused after a completed login" apart from "fresh".
 */
export async function bindFlowToUser(env: Env, flowId: string, userId: number): Promise<void> {
  await env.SESSIONS_KV.put(`resume:${flowId}`, String(userId), { expirationTtl: RESUME_TTL_SECONDS });
}

/** The user a flow is bound to, or null when it was never paused after a completed login. */
export async function getFlowBinding(env: Env, flowId: string): Promise<number | null> {
  const raw = await env.SESSIONS_KV.get(`resume:${flowId}`);
  return raw === null ? null : Number(raw);
}

export async function storeLoginFlow(env: Env, flow: LoginFlow): Promise<string> {
  const flowId = randomToken(16);
  await env.SESSIONS_KV.put(`flow:${flowId}`, JSON.stringify(flow), { expirationTtl: FLOW_TTL_SECONDS });
  return flowId;
}

/**
 * Sealed (stateless) login flows, for the anonymous entry points.
 *
 * GET /login, /authorize and /saml/sso are reachable by anyone, and storing a
 * flow in KV for each meant every anonymous page load was a KV write - an easy
 * way to burn a plan's write quota (1,000 a day on the Free plan) and break
 * sign-in for everyone. A sealed flow carries its own state in the form instead:
 * the flow and an expiry, MACed with a key derived from the deployment's
 * signing key, so a client can neither forge nor alter one - an OIDC flow's
 * redirect_uri was checked against the client's allowlist when it was sealed,
 * and must not be changeable afterwards.
 *
 * Sealed ids start "s." (KV ids are hex). Flows created after a completed
 * login - the forced-enrolment resume, /saml/complete's binding - stay in KV:
 * those writes need a correct password first.
 */
const SEALED_PREFIX = "s.";

async function flowSealKey(env: Env): Promise<CryptoKey | null> {
  const material = env.SIGNING_KEY_PKCS8 ?? env.COOKIE_ENCRYPTION_KEY;
  if (!material) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`flareid login-flow seal v1\n${material}`));
  return crypto.subtle.importKey("raw", digest, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}

/** A flow id for an anonymous entry point: sealed when the deployment has key material, a KV flow otherwise. */
export async function sealLoginFlow(env: Env, flow: LoginFlow): Promise<string> {
  const key = await flowSealKey(env);
  if (!key) return storeLoginFlow(env, flow);
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ f: flow, exp: Date.now() + FLOW_TTL_SECONDS * 1000 })));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  return `${SEALED_PREFIX}${payload}.${b64url(mac)}`;
}

async function openSealedFlow(env: Env, flowId: string): Promise<LoginFlow | null> {
  const key = await flowSealKey(env);
  const [payload, mac] = flowId.slice(SEALED_PREFIX.length).split(".");
  if (!key || !payload || !mac) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", key, fromB64url(mac) as BufferSource, new TextEncoder().encode(payload));
    if (!ok) return null;
    const { f, exp } = JSON.parse(new TextDecoder().decode(fromB64url(payload))) as { f: LoginFlow; exp: number };
    return Date.now() < exp ? f : null;
  } catch {
    return null;
  }
}

export function isSealedFlowId(flowId: string): boolean {
  return flowId.startsWith(SEALED_PREFIX);
}

export async function getLoginFlow(env: Env, flowId: string): Promise<LoginFlow | null> {
  if (isSealedFlowId(flowId)) return openSealedFlow(env, flowId);
  const raw = await env.SESSIONS_KV.get(`flow:${flowId}`);
  return raw ? (JSON.parse(raw) as LoginFlow) : null;
}

export async function deleteLoginFlow(env: Env, flowId: string): Promise<void> {
  // A sealed flow has nothing stored to delete (and a KV delete is a write).
  if (isSealedFlowId(flowId)) return;
  await env.SESSIONS_KV.delete(`flow:${flowId}`);
}

interface PendingMfa {
  userId: number;
  flowId: string;
}

export async function storePendingMfa(env: Env, userId: number, flowId: string): Promise<string> {
  const mfaId = randomToken(16);
  await env.SESSIONS_KV.put(`mfa:${mfaId}`, JSON.stringify({ userId, flowId }), {
    expirationTtl: MFA_TTL_SECONDS,
  });
  return mfaId;
}

export async function getPendingMfa(env: Env, mfaId: string): Promise<PendingMfa | null> {
  const raw = await env.SESSIONS_KV.get(`mfa:${mfaId}`);
  return raw ? (JSON.parse(raw) as PendingMfa) : null;
}

export async function deletePendingMfa(env: Env, mfaId: string): Promise<void> {
  await env.SESSIONS_KV.delete(`mfa:${mfaId}`);
}

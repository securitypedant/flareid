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

export async function storeLoginFlow(env: Env, flow: LoginFlow): Promise<string> {
  const flowId = randomToken(16);
  await env.SESSIONS_KV.put(`flow:${flowId}`, JSON.stringify(flow), { expirationTtl: FLOW_TTL_SECONDS });
  return flowId;
}

export async function getLoginFlow(env: Env, flowId: string): Promise<LoginFlow | null> {
  const raw = await env.SESSIONS_KV.get(`flow:${flowId}`);
  return raw ? (JSON.parse(raw) as LoginFlow) : null;
}

export async function deleteLoginFlow(env: Env, flowId: string): Promise<void> {
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

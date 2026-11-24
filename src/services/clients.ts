import type { Env } from "../env.js";
import { assertPolicyExists } from "../lib/auth-policy.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import type { OAuthClientRow } from "../lib/types.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";

/** https only (frames from an http page would be blocked anyway); anything else is dropped. */
export function validFrontchannelUri(u: string): string {
  try {
    return u && new URL(u).protocol === "https:" ? new URL(u).toString() : "";
  } catch {
    return "";
  }
}

/** id_token signing algorithms a client may choose (OIDC Registration's id_token_signed_response_alg). */
export const ID_TOKEN_ALGS = ["RS256", "ES256"] as const;
export type IdTokenAlg = (typeof ID_TOKEN_ALGS)[number];
export const isIdTokenAlg = (v: unknown): v is IdTokenAlg => (ID_TOKEN_ALGS as readonly unknown[]).includes(v);

// App assignment is shared between OIDC clients and SAML service providers;
// the helpers live with the SP row utilities. Re-exported so callers touching
// either app kind use one spelling.
export { amrSatisfiesMfa, appAccessAllowed, appPolicy, appPostureDenied, appRequiresMfa, parseAssignedGroupIds, parseAssignedUserIds } from "../lib/saml/service-providers.js";

export async function getClientById(env: Env, id: number): Promise<OAuthClientRow | null> {
  return env.DB.prepare("SELECT * FROM oauth_clients WHERE id = ?").bind(id).first<OAuthClientRow>();
}

export interface ClientSettings {
  name: string;
  redirectUris: string[];
  trusted: number;
  /** JSON array of claim groups (or null for every group, the pre-v3 behaviour). */
  allowedClaims: string | null;
  /** JSON array of post-logout redirect URIs. */
  postLogoutRedirectUris: string;
  frontchannelLogoutUri: string;
  /** Back-channel logout and third-party-initiated-login targets; omitted keeps the current ones. */
  backchannelLogoutUri?: string;
  initiateLoginUri?: string;
  /** RFC 7591 logo_uri for the sign-in page and launchpad; omitted keeps the current one. */
  logoUri?: string | null;
  /** id_token signing algorithm; omitted keeps the current one. */
  idTokenAlg?: IdTokenAlg;
  /** JSON array of group ids allowed to use the app; omitted keeps the current one. */
  assignedGroups?: string;
  /** 'everyone' | 'restricted'; omitted keeps the current one. */
  accessMode?: string;
  /** JSON array of user ids assigned to the app; omitted keeps the current one. */
  assignedUsers?: string;
  /** 0|1: sessions must carry a second factor; omitted keeps the current one. */
  requireMfa?: number;
  /** 0|1: people without access may ask for it; omitted keeps the current one. */
  requestable?: number;
  /** Bound authentication policy; omitted keeps the current one. */
  policyId?: number | null;
}

/** Saves a client's editable settings; its id, type and secret stay as they are. */
export async function updateClient(ctx: ServiceCtx, id: number, s: ClientSettings): Promise<void> {
  await ctx.env.DB.prepare("UPDATE oauth_clients SET name = ?, redirect_uris = ?, trusted = ?, allowed_claims = ?, post_logout_redirect_uris = ? WHERE id = ?")
    .bind(s.name, JSON.stringify(s.redirectUris), s.trusted, s.allowedClaims, s.postLogoutRedirectUris, id)
    .run();
  await ctx.env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ? WHERE id = ?").bind(s.frontchannelLogoutUri, id).run();
  if (s.backchannelLogoutUri !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET backchannel_logout_uri = ? WHERE id = ?").bind(s.backchannelLogoutUri, id).run();
  if (s.initiateLoginUri !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET initiate_login_uri = ? WHERE id = ?").bind(s.initiateLoginUri, id).run();
  if (s.logoUri !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET logo_uri = ? WHERE id = ?").bind(s.logoUri, id).run();
  if (s.idTokenAlg) await ctx.env.DB.prepare("UPDATE oauth_clients SET id_token_signed_response_alg = ? WHERE id = ?").bind(s.idTokenAlg, id).run();
  if (s.assignedGroups !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET assigned_groups = ? WHERE id = ?").bind(s.assignedGroups, id).run();
  if (s.accessMode !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET access_mode = ? WHERE id = ?").bind(s.accessMode === "everyone" ? "everyone" : "restricted", id).run();
  if (s.assignedUsers !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET assigned_users = ? WHERE id = ?").bind(s.assignedUsers, id).run();
  if (s.requireMfa !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET require_mfa = ? WHERE id = ?").bind(s.requireMfa, id).run();
  if (s.requestable !== undefined) await ctx.env.DB.prepare("UPDATE oauth_clients SET requestable = ? WHERE id = ?").bind(s.requestable, id).run();
  if (s.policyId !== undefined) {
    await assertPolicyExists(ctx.env, s.policyId);
    await ctx.env.DB.prepare("UPDATE oauth_clients SET policy_id = ? WHERE id = ?").bind(s.policyId, id).run();
  }
  await audit(ctx, "oidc_client.updated", s.name);
}

/** A new secret, returned once; only its hash is kept. */
export async function rotateClientSecret(ctx: ServiceCtx, client: OAuthClientRow): Promise<string> {
  if (client.client_type === "public") throw new ServiceError(400, "Public clients have no secret.");
  const clientSecret = randomToken(24);
  await ctx.env.DB.prepare("UPDATE oauth_clients SET client_secret_hash = ? WHERE id = ?").bind(await sha256Hex(clientSecret), client.id).run();
  await audit(ctx, "oidc_client.secret_rotated", client.name);
  return clientSecret;
}

/** Deletes a client with every code, token and consent issued to it. */
export async function deleteClient(ctx: ServiceCtx, client: OAuthClientRow): Promise<void> {
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("DELETE FROM auth_codes WHERE client_id = ?").bind(client.client_id),
    ctx.env.DB.prepare("DELETE FROM access_tokens WHERE client_id = ?").bind(client.client_id),
    ctx.env.DB.prepare("DELETE FROM refresh_tokens WHERE client_id = ?").bind(client.client_id),
    ctx.env.DB.prepare("DELETE FROM oauth_consents WHERE client_id = ?").bind(client.client_id),
    ctx.env.DB.prepare("DELETE FROM access_requests WHERE target_type = 'oidc_app' AND target_id = ?").bind(client.id),
    ctx.env.DB.prepare("DELETE FROM oauth_clients WHERE id = ?").bind(client.id),
  ]);
  await audit(ctx, "oidc_client.deleted", client.name);
}

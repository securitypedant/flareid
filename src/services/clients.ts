import type { Env } from "../env.js";
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
  /** id_token signing algorithm; omitted keeps the current one. */
  idTokenAlg?: IdTokenAlg;
}

/** Saves a client's editable settings; its id, type and secret stay as they are. */
export async function updateClient(ctx: ServiceCtx, id: number, s: ClientSettings): Promise<void> {
  await ctx.env.DB.prepare("UPDATE oauth_clients SET name = ?, redirect_uris = ?, trusted = ?, allowed_claims = ?, post_logout_redirect_uris = ? WHERE id = ?")
    .bind(s.name, JSON.stringify(s.redirectUris), s.trusted, s.allowedClaims, s.postLogoutRedirectUris, id)
    .run();
  await ctx.env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ? WHERE id = ?").bind(s.frontchannelLogoutUri, id).run();
  if (s.idTokenAlg) await ctx.env.DB.prepare("UPDATE oauth_clients SET id_token_signed_response_alg = ? WHERE id = ?").bind(s.idTokenAlg, id).run();
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
    ctx.env.DB.prepare("DELETE FROM oauth_clients WHERE id = ?").bind(client.id),
  ]);
  await audit(ctx, "oidc_client.deleted", client.name);
}

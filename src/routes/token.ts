import { oidcSid } from "../lib/sessions.js";
import { Hono } from "hono";
import type { Env } from "../env.js";
import { getManagerEmail, getUserById, getUserGroupNames } from "../lib/db.js";
import { sha256Hex, randomToken } from "../lib/tokens.js";
import { atHash, signIdToken } from "../lib/jwt.js";
import { acrFor, effectiveClaimGroups } from "../lib/oidc.js";
import type { OAuthClientRow } from "../lib/types.js";
import { parseCustomAttributes } from "../lib/schemas.js";
import { authenticateClient } from "../lib/oauth-client-auth.js";
import { logAudit } from "../lib/audit.js";

export const token = new Hono<{ Bindings: Env }>();

const ACCESS_TOKEN_TTL_SECONDS = 600;
/** Each refresh token is good for 30 days from issue; using it rotates it, so an active client never hits this. */
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

async function base64UrlSha256(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

token.post("/token", async (c) => {
  const body = await c.req.parseBody();
  const grantType = String(body.grant_type ?? "");

  // Public clients authenticate by client_id alone here; PKCE (required for
  // them at /authorize) is what binds the code to the app that started it.
  const client = await authenticateClient(c.env, body, c.req.header("Authorization"), { allowPublic: true });
  if (!client) return c.json({ error: "invalid_client" }, 401);

  if (grantType === "authorization_code") {
    const code = String(body.code ?? "");
    const redirectUri = String(body.redirect_uri ?? "");
    const codeVerifier = body.code_verifier ? String(body.code_verifier) : undefined;

    const authCode = await c.env.DB.prepare("SELECT * FROM auth_codes WHERE code = ?").bind(code).first<{
      code: string;
      client_id: string;
      user_id: number;
      redirect_uri: string;
      scope: string;
      nonce: string | null;
      code_challenge: string | null;
      code_challenge_method: string | null;
      expires_at: string;
      used_at: string | null;
      claims: string | null;
      amr: string;
      auth_time: number | null;
      sid: string | null;
    }>();

    if (!authCode || authCode.client_id !== client.client_id || authCode.redirect_uri !== redirectUri) {
      return c.json({ error: "invalid_grant" }, 400);
    }
    const codeHash = await sha256Hex(code);
    const revokeIssued = async () => {
      await c.env.DB.batch([
        c.env.DB.prepare("DELETE FROM access_tokens WHERE code_hash = ?").bind(codeHash),
        c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id IN (SELECT family_id FROM refresh_tokens WHERE code_hash = ?) AND revoked_at IS NULL").bind(new Date().toISOString(), codeHash),
      ]);
      await logAudit(c.env, null, "oauth.code_reuse", client.name, { client_id: client.client_id }, c.req.raw);
      return c.json({ error: "invalid_grant", error_description: "Authorization code already used; tokens issued from it have been revoked." }, 400);
    };
    if (authCode.used_at) return revokeIssued();
    if (new Date(authCode.expires_at).getTime() < Date.now()) {
      await c.env.DB.prepare("DELETE FROM auth_codes WHERE code = ?").bind(code).run();
      return c.json({ error: "invalid_grant", error_description: "Code expired" }, 400);
    }

    if (authCode.code_challenge) {
      if (!codeVerifier) return c.json({ error: "invalid_grant", error_description: "Missing code_verifier" }, 400);
      // /authorize only accepts S256, so that is the only transform there is.
      if ((await base64UrlSha256(codeVerifier)) !== authCode.code_challenge) {
        return c.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
      }
    }

    // Single use, atomically: of two concurrent redemptions only one marks the
    // row used. A second use revokes whatever the first one was given.
    const claimed = await c.env.DB.prepare("UPDATE auth_codes SET used_at = ? WHERE code = ? AND used_at IS NULL").bind(new Date().toISOString(), code).run();
    if (claimed.meta.changes !== 1) return revokeIssued();

    const user = await getUserById(c.env, authCode.user_id);
    if (!user || user.status !== "active") return c.json({ error: "invalid_grant" }, 400);

    const amr: string[] = JSON.parse(authCode.amr || '["pwd"]');
    return issueTokenResponse(c.env, client, user.id, authCode.scope, amr, {
      nonce: authCode.nonce ?? undefined,
      authTime: authCode.auth_time ?? Math.floor(Date.now() / 1000),
      sid: authCode.sid,
      codeHash,
      claimGroups: authCode.claims ? (JSON.parse(authCode.claims) as string[]) : [],
    });
  }

  if (grantType === "refresh_token") {
    const refreshToken = String(body.refresh_token ?? "");
    const tokenHash = await sha256Hex(refreshToken);

    const row = await c.env.DB.prepare("SELECT * FROM refresh_tokens WHERE token_hash = ? AND client_id = ?")
      .bind(tokenHash, client.client_id)
      .first<RefreshTokenRow>();
    if (!row || row.revoked_at) return c.json({ error: "invalid_grant" }, 400);

    // Rotation: claim this token exactly once. A token that was already
    // rotated - or loses the race to be - is being replayed, which means
    // someone other than the client holds it. Revoke the whole family.
    const claimed = row.rotated_at
      ? 0
      : Number(
          (
            await c.env.DB.prepare("UPDATE refresh_tokens SET rotated_at = ? WHERE token_hash = ? AND rotated_at IS NULL AND revoked_at IS NULL")
              .bind(new Date().toISOString(), tokenHash)
              .run()
          ).meta.changes ?? 0
        );
    if (claimed !== 1) {
      await revokeRefreshFamily(c.env, row.family_id ?? row.token_hash);
      await logAudit(c.env, null, "oauth.refresh_token_reuse", client.name, { client_id: client.client_id, user_id: row.user_id }, c.req.raw);
      return c.json({ error: "invalid_grant", error_description: "Refresh token reuse detected; the token family has been revoked." }, 400);
    }

    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
      return c.json({ error: "invalid_grant", error_description: "Refresh token expired" }, 400);
    }

    const user = await getUserById(c.env, row.user_id);
    if (!user || user.status !== "active") return c.json({ error: "invalid_grant" }, 400);

    const amr: string[] = JSON.parse(row.amr || '["pwd"]');
    return issueTokenResponse(c.env, client, user.id, row.scope, amr, {
      authTime: row.auth_time ?? Math.floor(new Date(row.created_at).getTime() / 1000),
      sid: row.sid,
      refreshFamily: row.family_id ?? row.token_hash,
      claimGroups: row.claims ? (JSON.parse(row.claims) as string[]) : [],
    });
  }

  return c.json({ error: "unsupported_grant_type" }, 400);
});

interface RefreshTokenRow {
  claims: string | null;
  token_hash: string;
  user_id: number;
  scope: string;
  amr: string;
  revoked_at: string | null;
  rotated_at: string | null;
  expires_at: string | null;
  family_id: string | null;
  created_at: string;
  auth_time: number | null;
  sid: string | null;
}

async function revokeRefreshFamily(env: Env, familyId: string): Promise<void> {
  await env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
    .bind(new Date().toISOString(), familyId)
    .run();
}

/**
 * @param opts.refreshFamily - set when answering a refresh grant: a new token
 *   is always issued in that family (rotation). Without it, a refresh token is
 *   issued only if offline_access was granted, as the head of a new family.
 * @param opts.authTime - when the user authenticated (epoch seconds), carried
 *   unchanged through refreshes so auth_time keeps meaning "last login".
 */
async function issueTokenResponse(
  env: Env,
  client: OAuthClientRow,
  userId: number,
  scope: string,
  amr: string[],
  opts: { nonce?: string; authTime: number; sid: string | null; refreshFamily?: string; codeHash?: string; claimGroups?: string[] }
) {
  const user = await getUserById(env, userId);
  if (!user) return Response.json({ error: "server_error" }, { status: 500 });

  const groups = await getUserGroupNames(env, userId);
  const managerEmail = await getManagerEmail(env, user.manager_external_id);
  const amrJson = JSON.stringify(amr);
  const claimsJson = opts.claimGroups?.length ? JSON.stringify(opts.claimGroups) : null;

  const accessToken = randomToken(32);
  const accessTokenHash = await sha256Hex(accessToken);
  const accessExpiresAt = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at, amr, code_hash, claims) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(accessTokenHash, client.client_id, userId, scope, accessExpiresAt, amrJson, opts.codeHash ?? null, claimsJson)
    .run();

  let refreshToken: string | undefined;
  if (opts.refreshFamily || scope.split(" ").includes("offline_access")) {
    refreshToken = randomToken(32);
    const refreshTokenHash = await sha256Hex(refreshToken);
    const now = Date.now();
    await env.DB.prepare(
      `INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, created_at, amr, expires_at, family_id, auth_time, sid, code_hash, claims)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        refreshTokenHash,
        client.client_id,
        userId,
        scope,
        new Date(now).toISOString(),
        amrJson,
        new Date(now + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString(),
        opts.refreshFamily ?? refreshTokenHash,
        opts.authTime,
        opts.sid,
        opts.codeHash ?? null,
        claimsJson
      )
      .run();
  }

  const idToken = await signIdToken(
    env,
    client.client_id,
    {
      sub: String(user.id),
      id: user.external_id,
      email: user.upn,
      name: user.display_name,
      givenName: user.given_name,
      familyName: user.family_name,
      username: user.username,
      groups,
      amr,
      jobTitle: user.job_title,
      department: user.department,
      managerEmail,
      customAttributes: parseCustomAttributes(user.custom_attributes),
      nonce: opts.nonce,
    },
    effectiveClaimGroups(client, scope, opts.claimGroups),
    { authTime: opts.authTime, acr: acrFor(amr), sid: opts.sid ? await oidcSid(opts.sid) : undefined, atHash: await atHash(accessToken) }
  );

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    id_token: idToken,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    scope,
  });
}

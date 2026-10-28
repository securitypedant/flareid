import { Hono } from "hono";
import type { Env } from "../env.js";
import { getManagerEmail, getUserById, getUserGroupNames } from "../lib/db.js";
import { sha256Hex, randomToken } from "../lib/tokens.js";
import { signIdToken } from "../lib/jwt.js";
import type { OAuthClientRow } from "../lib/types.js";
import { authenticateClient } from "../lib/oauth-client-auth.js";

export const token = new Hono<{ Bindings: Env }>();

const ACCESS_TOKEN_TTL_SECONDS = 600;

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

  const client = await authenticateClient(c.env, body, c.req.header("Authorization"));
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
      amr: string;
    }>();

    if (!authCode || authCode.client_id !== client.client_id || authCode.redirect_uri !== redirectUri) {
      return c.json({ error: "invalid_grant" }, 400);
    }
    if (new Date(authCode.expires_at).getTime() < Date.now()) {
      await c.env.DB.prepare("DELETE FROM auth_codes WHERE code = ?").bind(code).run();
      return c.json({ error: "invalid_grant", error_description: "Code expired" }, 400);
    }

    if (authCode.code_challenge) {
      if (!codeVerifier) return c.json({ error: "invalid_grant", error_description: "Missing code_verifier" }, 400);
      const computed =
        authCode.code_challenge_method === "plain" ? codeVerifier : await base64UrlSha256(codeVerifier);
      if (computed !== authCode.code_challenge) {
        return c.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
      }
    }

    // Single use.
    await c.env.DB.prepare("DELETE FROM auth_codes WHERE code = ?").bind(code).run();

    const user = await getUserById(c.env, authCode.user_id);
    if (!user || user.status !== "active") return c.json({ error: "invalid_grant" }, 400);

    const amr: string[] = JSON.parse(authCode.amr || '["pwd"]');
    return issueTokenResponse(c.env, client, user.id, authCode.scope, amr, authCode.nonce ?? undefined);
  }

  if (grantType === "refresh_token") {
    const refreshToken = String(body.refresh_token ?? "");
    const tokenHash = await sha256Hex(refreshToken);

    const row = await c.env.DB.prepare(
      "SELECT * FROM refresh_tokens WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL"
    )
      .bind(tokenHash, client.client_id)
      .first<{ user_id: number; scope: string; amr: string }>();
    if (!row) return c.json({ error: "invalid_grant" }, 400);

    const user = await getUserById(c.env, row.user_id);
    if (!user || user.status !== "active") return c.json({ error: "invalid_grant" }, 400);

    const amr: string[] = JSON.parse(row.amr || '["pwd"]');
    return issueTokenResponse(c.env, client, user.id, row.scope, amr, undefined, { reuseRefreshToken: refreshToken });
  }

  return c.json({ error: "unsupported_grant_type" }, 400);
});

async function issueTokenResponse(
  env: Env,
  client: OAuthClientRow,
  userId: number,
  scope: string,
  amr: string[],
  nonce?: string,
  opts?: { reuseRefreshToken?: string }
) {
  const user = await getUserById(env, userId);
  if (!user) return Response.json({ error: "server_error" }, { status: 500 });

  const groups = await getUserGroupNames(env, userId);
  const managerEmail = await getManagerEmail(env, user.manager_external_id);
  const amrJson = JSON.stringify(amr);

  const accessToken = randomToken(32);
  const accessTokenHash = await sha256Hex(accessToken);
  const accessExpiresAt = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at, amr) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(accessTokenHash, client.client_id, userId, scope, accessExpiresAt, amrJson)
    .run();

  let refreshToken = opts?.reuseRefreshToken;
  if (!refreshToken && scope.includes("offline_access")) {
    refreshToken = randomToken(32);
    const refreshTokenHash = await sha256Hex(refreshToken);
    await env.DB.prepare(
      "INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, created_at, amr) VALUES (?, ?, ?, ?, ?, ?)"
    )
      .bind(refreshTokenHash, client.client_id, userId, scope, new Date().toISOString(), amrJson)
      .run();
  }

  const idToken = await signIdToken(env, client.client_id, {
    sub: String(user.id),
    id: user.external_id,
    email: user.upn,
    name: user.display_name,
    givenName: user.given_name,
    familyName: user.family_name,
    groups,
    amr,
    jobTitle: user.job_title,
    department: user.department,
    managerEmail,
    nonce,
  });

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    id_token: idToken,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    scope,
  });
}

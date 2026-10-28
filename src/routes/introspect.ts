import { Hono } from "hono";
import type { Env } from "../env.js";
import { sha256Hex } from "../lib/tokens.js";
import { authenticateClient } from "../lib/oauth-client-auth.js";

export const introspect = new Hono<{ Bindings: Env }>();

/** RFC 7662 - lets a client (that owns the token) check whether it's still valid. */
introspect.post("/introspect", async (c) => {
  const body = await c.req.parseBody();
  const client = await authenticateClient(c.env, body, c.req.header("Authorization"));
  if (!client) return c.json({ error: "invalid_client" }, 401);

  const token = String(body.token ?? "");
  if (!token) return c.json({ active: false });

  const tokenHash = await sha256Hex(token);

  const accessTokenRow = await c.env.DB.prepare(
    "SELECT * FROM access_tokens WHERE token_hash = ? AND client_id = ?"
  )
    .bind(tokenHash, client.client_id)
    .first<{ user_id: number; scope: string; expires_at: string }>();

  if (accessTokenRow) {
    const active = new Date(accessTokenRow.expires_at).getTime() > Date.now();
    if (!active) return c.json({ active: false });
    return c.json({
      active: true,
      sub: String(accessTokenRow.user_id),
      client_id: client.client_id,
      scope: accessTokenRow.scope,
      token_type: "Bearer",
      exp: Math.floor(new Date(accessTokenRow.expires_at).getTime() / 1000),
    });
  }

  const refreshTokenRow = await c.env.DB.prepare(
    "SELECT * FROM refresh_tokens WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL"
  )
    .bind(tokenHash, client.client_id)
    .first<{ user_id: number; scope: string }>();

  if (refreshTokenRow) {
    return c.json({
      active: true,
      sub: String(refreshTokenRow.user_id),
      client_id: client.client_id,
      scope: refreshTokenRow.scope,
      token_type: "refresh_token",
    });
  }

  return c.json({ active: false });
});

/**
 * RFC 7009 - lets a client revoke a token it holds. Always returns 200 (even
 * for unknown/already-revoked tokens), per spec, so this can't be used to
 * probe for valid tokens.
 */
introspect.post("/revoke", async (c) => {
  const body = await c.req.parseBody();
  const client = await authenticateClient(c.env, body, c.req.header("Authorization"));
  if (!client) return c.json({ error: "invalid_client" }, 401);

  const token = String(body.token ?? "");
  if (!token) return c.body(null, 200);

  const tokenHash = await sha256Hex(token);

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM access_tokens WHERE token_hash = ? AND client_id = ?").bind(tokenHash, client.client_id),
    c.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND client_id = ?").bind(
      new Date().toISOString(),
      tokenHash,
      client.client_id
    ),
  ]);

  return c.body(null, 200);
});

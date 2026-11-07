import { Hono } from "hono";
import type { Env } from "../env.js";
import { getManagerEmail, getUserById, getUserGroupNames } from "../lib/db.js";
import { sha256Hex } from "../lib/tokens.js";
import { buildClaims } from "../lib/jwt.js";
import { getClientByClientId } from "../lib/db.js";
import { effectiveClaimGroups } from "../lib/oidc.js";
import { parseCustomAttributes } from "../lib/schemas.js";

export const userinfo = new Hono<{ Bindings: Env }>();

userinfo.get("/userinfo", async (c) => {
  const header = c.req.header("Authorization");
  const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return c.json({ error: "invalid_token" }, 401);

  const tokenHash = await sha256Hex(token);
  const row = await c.env.DB.prepare("SELECT * FROM access_tokens WHERE token_hash = ?").bind(tokenHash).first<{
    user_id: number;
    client_id: string;
    scope: string;
    expires_at: string;
    amr: string;
  }>();

  if (!row || new Date(row.expires_at).getTime() < Date.now()) {
    return c.json({ error: "invalid_token" }, 401);
  }

  const user = await getUserById(c.env, row.user_id);
  if (!user || user.status !== "active") return c.json({ error: "invalid_token" }, 401);

  const groups = await getUserGroupNames(c.env, user.id);
  const managerEmail = await getManagerEmail(c.env, user.manager_external_id);
  const amr: string[] = JSON.parse(row.amr || '["pwd"]');
  // The same release rule as the id_token: the token's scopes, within the client's allowlist.
  const client = await getClientByClientId(c.env, row.client_id);
  const release = client ? effectiveClaimGroups(client, row.scope) : new Set<never>();

  return c.json({
    sub: String(user.id),
    ...buildClaims({
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
    }, release),
  });
});

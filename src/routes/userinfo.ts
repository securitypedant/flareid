import { Hono } from "hono";
import type { Env } from "../env.js";
import { getManagerEmail, getUserById, getUserGroupNames } from "../lib/db.js";
import { sha256Hex } from "../lib/tokens.js";
import { buildClaims } from "../lib/jwt.js";

export const userinfo = new Hono<{ Bindings: Env }>();

userinfo.get("/userinfo", async (c) => {
  const header = c.req.header("Authorization");
  const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return c.json({ error: "invalid_token" }, 401);

  const tokenHash = await sha256Hex(token);
  const row = await c.env.DB.prepare("SELECT * FROM access_tokens WHERE token_hash = ?").bind(tokenHash).first<{
    user_id: number;
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

  return c.json({
    sub: String(user.id),
    email_verified: true,
    ...buildClaims({
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
    }),
  });
});

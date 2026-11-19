import { canSignIn } from "../lib/admin-roles.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { getManagerEmail, getUserById, getUserGroupNames } from "../lib/db.js";
import { sha256Hex } from "../lib/tokens.js";
import { buildClaims } from "../lib/jwt.js";
import { getClientByClientId } from "../lib/db.js";
import { effectiveClaimGroups, parseRequestedClaims } from "../lib/oidc.js";
import { parseCustomAttributes } from "../lib/schemas.js";
import { subjectFor } from "../lib/subject.js";
import { SignJWT } from "jose";
import { activeSigningKey } from "../lib/signing-keys.js";

export const userinfo = new Hono<{ Bindings: Env }>();

/** RFC 6750 section 3: a refused bearer token says why, in WWW-Authenticate as well as the body. */
function invalidToken(c: Context<{ Bindings: Env }>, missing = false) {
  c.header("WWW-Authenticate", missing ? 'Bearer realm="flareid"' : 'Bearer realm="flareid", error="invalid_token"');
  return c.json({ error: "invalid_token" }, 401);
}

// GET or POST (OpenID Connect Core 5.3.1); the token in the Authorization
// header, or for POST in a form-encoded access_token field (RFC 6750 2.2).
userinfo.on(["GET", "POST"], "/userinfo", async (c) => {
  const header = c.req.header("Authorization");
  let token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token && c.req.method === "POST" && (c.req.header("Content-Type") ?? "").includes("application/x-www-form-urlencoded")) {
    const v = (await c.req.parseBody()).access_token;
    token = typeof v === "string" && v ? v : undefined;
  }
  if (!token) return invalidToken(c, true);

  const tokenHash = await sha256Hex(token);
  const row = await c.env.DB.prepare("SELECT * FROM access_tokens WHERE token_hash = ?").bind(tokenHash).first<{
    user_id: number;
    client_id: string;
    scope: string;
    expires_at: string;
    amr: string;
    claims: string | null;
  }>();

  if (!row || new Date(row.expires_at).getTime() < Date.now()) {
    return invalidToken(c);
  }

  const user = await getUserById(c.env, row.user_id);
  if (!user || user.status !== "active" || !(await canSignIn(c.env, user.id))) return invalidToken(c);

  const groups = await getUserGroupNames(c.env, user.id);
  const managerEmail = await getManagerEmail(c.env, user.manager_external_id);
  const amr: string[] = JSON.parse(row.amr || '["pwd"]');
  // The same release rule as the id_token: the token's scopes, within the client's allowlist.
  const client = await getClientByClientId(c.env, row.client_id);
  const release = client ? effectiveClaimGroups(client, row.scope, parseRequestedClaims(row.claims).userinfo) : new Set<never>();

  const sub = client ? await subjectFor(c.env, client, user.id) : String(user.id);

  const claims = {
    sub,
    ...buildClaims({
      sub,
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
  };

  // userinfo_signed_response_alg (OIDC Registration 2): when the client
  // registered one, /userinfo answers application/jwt signed with the IdP's
  // keys instead of plain JSON (OIDC Core 5.3.2.4).
  const alg = client?.userinfo_signed_response_alg;
  if (alg === "RS256" || alg === "ES256") {
    const { kid, key } = await activeSigningKey(c.env, alg);
    const jwt = await new SignJWT(claims)
      .setProtectedHeader({ alg, kid })
      .setIssuer(c.env.ISSUER_URL)
      .setAudience(client!.client_id)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key);
    return c.body(jwt, 200, { "Content-Type": "application/jwt" });
  }

  return c.json(claims);
});

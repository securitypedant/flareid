import { SignJWT } from "jose";
import type { Env } from "../env.js";
import { activeSigningKey } from "./signing-keys.js";
import { oidcSid } from "./sessions.js";

/**
 * OpenID Connect Back-Channel Logout 1.0: when a session ends, every client it
 * touched that registered a backchannel_logout_uri is POSTed a logout_token it
 * can verify against our JWKS - no browser involved. Delivery is best-effort
 * with a short timeout: a slow RP must never stall a logout or a password
 * change.
 */

const EVENT = "http://schemas.openid.net/event/backchannel-logout";

async function logoutToken(env: Env, clientId: string, sid: string): Promise<string> {
  const { kid, key } = await activeSigningKey(env, "RS256");
  return new SignJWT({ events: { [EVENT]: {} }, sid })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(env.ISSUER_URL)
    .setAudience(clientId)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(key);
}

/** Sends the logout_token for every (session, client) pair that asks for it. */
export async function notifySessionRevoked(env: Env, sessionIds: string[]): Promise<void> {
  if (sessionIds.length === 0) return;
  const { results } = await env.DB.prepare(
    `SELECT sc.session_id, oc.client_id, oc.backchannel_logout_uri AS uri
       FROM session_clients sc JOIN oauth_clients oc ON oc.client_id = sc.client_id
      WHERE sc.session_id IN (SELECT value FROM json_each(?)) AND oc.backchannel_logout_uri != ''`
  )
    .bind(JSON.stringify(sessionIds))
    .all<{ session_id: string; client_id: string; uri: string }>();
  await Promise.allSettled(
    results.map(async (r) => {
      const token = await logoutToken(env, r.client_id, await oidcSid(r.session_id));
      await fetch(r.uri, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ logout_token: token }).toString(),
        signal: AbortSignal.timeout(5000),
      });
    })
  );
}

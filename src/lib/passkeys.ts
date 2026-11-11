import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { Env } from "../env.js";
import { sha256Hex } from "./tokens.js";

/**
 * WebAuthn / passkeys. The relying party is the issuer's host; challenges live
 * in KV for five minutes, keyed per session (registration) or per sign-in
 * attempt (authentication), and are single-use.
 */

const CHALLENGE_TTL_SECONDS = 300;

export interface PasskeyRow {
  id: string;
  user_id: number;
  public_key: string;
  sign_count: number;
  transports: string;
  name: string;
  backed_up: number;
  created_at: string;
  last_used_at: string | null;
}

const b64u = {
  encode(bytes: Uint8Array): string {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(text: string): Uint8Array<ArrayBuffer> {
    const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    const out = new Uint8Array(new ArrayBuffer(s.length));
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

export function rpId(env: Env): string {
  return new URL(env.ISSUER_URL).hostname;
}
export function rpOrigin(env: Env): string {
  return new URL(env.ISSUER_URL).origin;
}

export async function listPasskeys(env: Env, userId: number): Promise<PasskeyRow[]> {
  return (await env.DB.prepare("SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at").bind(userId).all<PasskeyRow>()).results;
}

const challengeKey = async (scope: string) => `webauthn:${await sha256Hex(scope)}`;

/** Options for registering a new passkey for the signed-in user. */
export async function registrationOptions(env: Env, sessionId: string, user: { id: number; upn: string; display_name: string }) {
  const existing = await listPasskeys(env, user.id);
  const options = await generateRegistrationOptions({
    rpName: "FlareID",
    rpID: rpId(env),
    userName: user.upn,
    userDisplayName: user.display_name || user.upn,
    userID: new Uint8Array(new TextEncoder().encode(String(user.id))) as Uint8Array<ArrayBuffer>,
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.id, transports: JSON.parse(c.transports) })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });
  await env.SESSIONS_KV.put(await challengeKey(`reg:${sessionId}`), options.challenge, { expirationTtl: CHALLENGE_TTL_SECONDS });
  return options;
}

/** Verifies a registration response and stores the credential. Returns an error message, or null. */
export async function finishRegistration(env: Env, sessionId: string, userId: number, response: RegistrationResponseJSON, name: string): Promise<string | null> {
  const key = await challengeKey(`reg:${sessionId}`);
  const expectedChallenge = await env.SESSIONS_KV.get(key);
  if (!expectedChallenge) return "The registration expired. Please try again.";
  await env.SESSIONS_KV.delete(key);
  let verification;
  try {
    verification = await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: rpOrigin(env), expectedRPID: rpId(env), requireUserVerification: true });
  } catch (e) {
    return `The passkey could not be verified: ${String((e as Error).message ?? e).slice(0, 200)}`;
  }
  if (!verification.verified || !verification.registrationInfo) return "The passkey could not be verified.";
  const { credential, credentialBackedUp } = verification.registrationInfo;
  await env.DB.prepare(
    "INSERT INTO webauthn_credentials (id, user_id, public_key, sign_count, transports, name, backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(credential.id, userId, b64u.encode(credential.publicKey), credential.counter, JSON.stringify(response.response.transports ?? []), name.slice(0, 60) || "Passkey", credentialBackedUp ? 1 : 0, new Date().toISOString())
    .run();
  return null;
}

/**
 * Options for signing in with a passkey. Discoverable credentials: no user is
 * named, so the browser offers whatever passkeys it holds for this site.
 */
export async function authenticationOptions(env: Env, attemptId: string, forUserId?: number) {
  // As a second step the user is already known, so only their passkeys are offered.
  const allow = forUserId ? (await listPasskeys(env, forUserId)).map((c) => ({ id: c.id, transports: JSON.parse(c.transports) })) : undefined;
  const options = await generateAuthenticationOptions({ rpID: rpId(env), userVerification: "required", ...(allow ? { allowCredentials: allow } : {}) });
  await env.SESSIONS_KV.put(await challengeKey(`auth:${attemptId}`), options.challenge, { expirationTtl: CHALLENGE_TTL_SECONDS });
  return options;
}

/** Verifies a sign-in assertion. Returns the user id it proves, or null. */
export async function finishAuthentication(env: Env, attemptId: string, response: AuthenticationResponseJSON): Promise<number | null> {
  const key = await challengeKey(`auth:${attemptId}`);
  const expectedChallenge = await env.SESSIONS_KV.get(key);
  if (!expectedChallenge) return null;
  await env.SESSIONS_KV.delete(key);
  const row = await env.DB.prepare("SELECT * FROM webauthn_credentials WHERE id = ?").bind(response.id).first<PasskeyRow>();
  if (!row) return null;
  try {
    const v = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: rpOrigin(env),
      expectedRPID: rpId(env),
      requireUserVerification: true,
      credential: { id: row.id, publicKey: b64u.decode(row.public_key), counter: row.sign_count, transports: JSON.parse(row.transports) },
    });
    if (!v.verified) return null;
    // A counter that goes backwards means a cloned authenticator; refuse it.
    const next = v.authenticationInfo.newCounter;
    if (row.sign_count > 0 && next <= row.sign_count) return null;
    await env.DB.prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?").bind(next, new Date().toISOString(), row.id).run();
    return row.user_id;
  } catch {
    return null;
  }
}

export async function removePasskey(env: Env, userId: number, credentialId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?").bind(credentialId, userId).run();
}

export { b64u };

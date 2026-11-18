import { SignJWT, createRemoteJWKSet, jwtVerify } from "jose";
import type { Env } from "../env.js";
import { activeSigningKey } from "./signing-keys.js";
import { logAudit } from "./audit.js";
import { revokeAllSessionsForUser, revokeTokensForUser } from "./sessions.js";
import type { UserRow } from "./types.js";

/**
 * Shared Signals Framework: CAEP/RISC Security Event Tokens in and out.
 *
 * Outbound - receivers register a stream (POST /api/v1/ssf/streams or
 * Integrations -> Signals); an event queues one ssf_outbox row per stream
 * and drainSsfOutbox pushes a signed SET to each endpoint. Emission is cheap
 * (inserts only) so it can sit on the login path; delivery is retried by the
 * hourly cron.
 *
 * Inbound - trusted transmitters register issuer + JWKS URL and push SETs to
 * POST /ssf/receive. Verified events map onto local effects: a session-revoked
 * for a user's email kills their sessions; a credential/risk event flags them
 * on the risk watchlist (the same flag Cloudflare One syncs out).
 */

export const SSF_EVENTS = {
  "caep.session-revoked": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
  "caep.credential-change": "https://schemas.openid.net/secevent/caep/event-type/credential-change",
  "risc.account-disabled": "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
  "risc.credential-change-required": "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
} as const;

export type SsfEventName = keyof typeof SSF_EVENTS;

interface StreamRow {
  id: number;
  name: string;
  endpoint_url: string;
  aud: string;
  events: string;
  disabled: number;
}

export interface SsfSubId {
  format: string;
  email?: string;
  iss?: string;
  sub?: string;
}

/** Queue one SET per interested stream. Returns how many were queued. */
export async function emitSsfEvent(env: Env, eventUri: string, subId: SsfSubId): Promise<number> {
  const { results: streams } = await env.DB.prepare("SELECT * FROM ssf_streams WHERE disabled = 0").all<StreamRow>();
  let queued = 0;
  const now = new Date().toISOString();
  for (const s of streams) {
    let wanted: string[] = [];
    try {
      wanted = JSON.parse(s.events || "[]");
    } catch {
      wanted = [];
    }
    if (wanted.length && !wanted.includes(eventUri)) continue;
    await env.DB.prepare("INSERT INTO ssf_outbox (stream_id, event_uri, subject, queued_at) VALUES (?, ?, ?, ?)")
      .bind(s.id, eventUri, JSON.stringify(subId), now)
      .run();
    queued++;
  }
  return queued;
}

/** Emit + drain without blocking the caller: for ctx.waitUntil / afterResponse. */
export async function emitAndDrain(env: Env, eventUri: string, subId: SsfSubId): Promise<void> {
  if ((await emitSsfEvent(env, eventUri, subId)) > 0) await drainSsfOutbox(env);
}

async function signSet(env: Env, aud: string, eventUri: string, subId: SsfSubId): Promise<string> {
  const { kid, key } = await activeSigningKey(env, "RS256");
  return new SignJWT({ events: { [eventUri]: { subject: subId } } })
    .setProtectedHeader({ alg: "RS256", kid, typ: "secevent+jwt" })
    .setIssuer(env.ISSUER_URL)
    .setAudience(aud)
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(key);
}

interface OutboxRow {
  id: number;
  stream_id: number;
  event_uri: string;
  subject: string;
  attempts: number;
  endpoint_url: string;
  aud: string;
}

const MAX_ATTEMPTS = 8;

export async function drainSsfOutbox(env: Env): Promise<{ sent: number; failed: number }> {
  const { results } = await env.DB.prepare(
    `SELECT o.id, o.stream_id, o.event_uri, o.subject, o.attempts, s.endpoint_url, s.aud
     FROM ssf_outbox o JOIN ssf_streams s ON s.id = o.stream_id
     WHERE s.disabled = 0 AND o.attempts < ? ORDER BY o.id LIMIT 50`
  ).bind(MAX_ATTEMPTS).all<OutboxRow>();
  let sent = 0, failed = 0;
  const now = new Date().toISOString();
  for (const row of results) {
    try {
      const aud = row.aud || new URL(row.endpoint_url).host;
      const set = await signSet(env, aud, row.event_uri, JSON.parse(row.subject));
      const res = await fetch(row.endpoint_url, {
        method: "POST",
        headers: { "content-type": "application/secevent+jwt", accept: "application/json" },
        body: set,
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM ssf_outbox WHERE id = ?").bind(row.id),
        env.DB.prepare("UPDATE ssf_streams SET last_push_at = ?, last_error = NULL WHERE id = ?").bind(now, row.stream_id),
      ]);
      sent++;
    } catch (e) {
      const msg = String((e as Error).message ?? e).slice(0, 200);
      await env.DB.batch([
        env.DB.prepare("UPDATE ssf_outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?").bind(msg, row.id),
        env.DB.prepare("UPDATE ssf_streams SET last_error = ? WHERE id = ?").bind(msg, row.stream_id),
      ]);
      failed++;
    }
  }
  return { sent, failed };
}

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

const txJwks = new Map<string, { jwks: ReturnType<typeof createRemoteJWKSet>; at: number }>();
const JWKS_TTL_MS = 5 * 60 * 1000;

function transmitterJwks(issuer: string, jwksUrl: string): ReturnType<typeof createRemoteJWKSet> {
  const cached = txJwks.get(issuer);
  if (cached && Date.now() - cached.at < JWKS_TTL_MS) return cached.jwks;
  const jwks = createRemoteJWKSet(new URL(jwksUrl), { timeoutDuration: 10_000 });
  txJwks.set(issuer, { jwks, at: Date.now() });
  return jwks;
}

/** Test hook: drops the JWKS cache. */
export function ssfClearCaches(): void {
  txJwks.clear();
}

async function userByEmail(env: Env, email: string): Promise<UserRow | null> {
  // Deterministic precedence when an alias happens to spell another
  // account's upn: the direct sign-in name wins over the alias.
  return env.DB.prepare(
    `SELECT u.* FROM users u LEFT JOIN user_emails e ON e.user_id = u.id
      WHERE u.upn = ? OR e.email = ?
      ORDER BY CASE WHEN u.upn = ? THEN 0 ELSE 1 END LIMIT 1`
  ).bind(email, email, email).first<UserRow>();
}

function subjectEmail(subId: SsfSubId | undefined): string | null {
  if (!subId) return null;
  if (subId.format === "email" && subId.email) return subId.email;
  return null;
}

export interface SsfReceiveResult {
  accepted: string[];
  ignored: string[];
}

/**
 * Verify an inbound SET and act on its events. Throws {status,message} style
 * errors the route maps to 401/400; anything else returns the handled list.
 * Unknown event URIs are ignored, not rejected - a transmitter may support
 * more than we do.
 */
export async function receiveSet(env: Env, token: string): Promise<SsfReceiveResult> {
  // Find the issuer without trusting it, then verify against its JWKS.
  let payload: { iss?: string; aud?: string | string[]; events?: Record<string, { subject?: SsfSubId }> };
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(token.split(".")[1] ?? "")));
  } catch {
    throw new SsfReceiveError(400, "Not a JWT.");
  }
  const iss = payload.iss;
  if (!iss) throw new SsfReceiveError(400, "SET has no iss.");
  const tx = await env.DB.prepare("SELECT * FROM ssf_transmitters WHERE issuer = ?").bind(iss).first<{ id: number; name: string; jwks_url: string }>();
  if (!tx) throw new SsfReceiveError(401, `No trusted transmitter for issuer ${iss}.`);
  let verified;
  try {
    ({ payload: verified } = await jwtVerify(token, transmitterJwks(iss, tx.jwks_url), {
      // alg from the SET's own header is checked by jose; we allow RS256/ES256,
      // the algorithms transmitters actually use.
      algorithms: ["RS256", "ES256", "ES384", "RS384"],
    }));
  } catch (e) {
    throw new SsfReceiveError(401, `SET verification failed: ${(e as Error).message}`);
  }
  // aud must name us - a SET meant for someone else's receiver shouldn't
  // drive local effects here, and RFC 8417 requires the claim.
  const aud = Array.isArray(verified.aud) ? verified.aud : verified.aud ? [verified.aud] : [];
  if (!aud.includes(env.ISSUER_URL)) {
    throw new SsfReceiveError(401, `SET aud does not name this receiver (${env.ISSUER_URL}).`);
  }
  // Freshness bounds the replay window; jti dedupe (below) catches repeats
  // inside it. RFC 8417 requires both claims.
  const iat = typeof verified.iat === "number" ? verified.iat : 0;
  const nowSec = Date.now() / 1000;
  if (!iat || nowSec - iat > 900 || iat - nowSec > 300) {
    throw new SsfReceiveError(401, "SET iat is missing or outside the freshness window.");
  }
  if (!verified.jti) throw new SsfReceiveError(401, "SET has no jti.");
  // Replay ledger: a seen (issuer, jti) is refused. Rows piggyback rate_limits
  // and its cleanup sweep; the iat window above is far shorter than that
  // table's retention horizon, so a replay can never outlive its row.
  const jtiSeen = await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count`
  ).bind(`ssf:jti:${iss}:${String(verified.jti)}`, Date.now()).first<{ count: number }>();
  if ((jtiSeen?.count ?? 1) > 1) throw new SsfReceiveError(401, "SET jti already seen.");
  const accepted: string[] = [];
  const ignored: string[] = [];
  const events = (verified.events ?? {}) as Record<string, { subject?: SsfSubId }>;
  const eventEntries = Object.entries(events);
  if (eventEntries.length > 50) throw new SsfReceiveError(400, "SET contains too many events.");
  for (const [uri, body] of eventEntries) {
    const email = subjectEmail(body?.subject);
    const user = email ? await userByEmail(env, email) : null;
    if (uri === SSF_EVENTS["caep.session-revoked"] || uri === "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked") {
      if (!user) { ignored.push(uri); continue; }
      await revokeAllSessionsForUser(env, user.id);
      await revokeTokensForUser(env, user.id);
      await logAudit(env, { id: null, upn: `ssf:${tx.name}` }, "ssf.session_revoked", user.upn);
      accepted.push(uri);
    } else if (
      uri === SSF_EVENTS["risc.credential-change-required"] ||
      uri === "https://schemas.openid.net/secevent/risc/event-type/credential-compromise" ||
      uri === SSF_EVENTS["risc.account-disabled"]
    ) {
      if (!user) { ignored.push(uri); continue; }
      const { flagUser } = await import("./cfone.js");
      await flagUser(env, user.id, `Security signal from ${tx.name} (${uri.split("/").pop()})`, "ssf", 24);
      await logAudit(env, { id: null, upn: `ssf:${tx.name}` }, "ssf.user_flagged", user.upn, { event: uri });
      accepted.push(uri);
    } else {
      ignored.push(uri);
    }
  }
  return { accepted, ignored };
}

export class SsfReceiveError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function base64urlToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

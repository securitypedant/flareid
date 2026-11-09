import type { Env } from "../env.js";
import { sha256Hex } from "./tokens.js";

const ENROLLMENT_TTL_SECONDS = 600;

/**
 * A pending TOTP secret belongs to the session that started enrolment, not to
 * the user: otherwise a second session (one holding only the password, say)
 * would see - and could have chosen - the secret the real user then enrols.
 */
const key = async (sessionId: string) => `enroll:${await sha256Hex(sessionId)}`;

export async function storePendingEnrollment(env: Env, sessionId: string, secret: string): Promise<void> {
  await env.SESSIONS_KV.put(await key(sessionId), secret, { expirationTtl: ENROLLMENT_TTL_SECONDS });
}

export async function getPendingEnrollment(env: Env, sessionId: string): Promise<string | null> {
  return env.SESSIONS_KV.get(await key(sessionId));
}

export async function deletePendingEnrollment(env: Env, sessionId: string): Promise<void> {
  await env.SESSIONS_KV.delete(await key(sessionId));
}

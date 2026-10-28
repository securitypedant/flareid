import type { Env } from "../env.js";

const ENROLLMENT_TTL_SECONDS = 600;

export async function storePendingEnrollment(env: Env, userId: number, secret: string): Promise<void> {
  await env.SESSIONS_KV.put(`enroll:${userId}`, secret, { expirationTtl: ENROLLMENT_TTL_SECONDS });
}

export async function getPendingEnrollment(env: Env, userId: number): Promise<string | null> {
  return env.SESSIONS_KV.get(`enroll:${userId}`);
}

export async function deletePendingEnrollment(env: Env, userId: number): Promise<void> {
  await env.SESSIONS_KV.delete(`enroll:${userId}`);
}

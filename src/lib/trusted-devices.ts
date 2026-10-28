import type { Env } from "../env.js";
import { randomToken } from "./tokens.js";
import { getClientIp } from "./rate-limit.js";

const TRUSTED_DEVICE_COOKIE = "__Host-flareid_trusted_device";
const TRUSTED_DEVICE_TTL_DAYS = 30;

export interface TrustedDeviceRow {
  id: string;
  user_id: number;
  user_agent: string | null;
  ip: string | null;
  created_at: string;
  last_used_at: string;
  expires_at: string;
}

function readDeviceIdFromCookie(request: Request): string | null {
  const cookieHeader = request.headers.get("Cookie") ?? "";
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const target = cookies.find((c) => c.startsWith(`${TRUSTED_DEVICE_COOKIE}=`));
  return target ? target.substring(TRUSTED_DEVICE_COOKIE.length + 1) : null;
}

/** Checks whether the current browser has a still-valid "remember this device" cookie for this user. */
export async function isDeviceTrusted(env: Env, request: Request, userId: number): Promise<boolean> {
  const deviceId = readDeviceIdFromCookie(request);
  if (!deviceId) return false;

  const row = await env.DB.prepare("SELECT * FROM trusted_devices WHERE id = ? AND user_id = ?")
    .bind(deviceId, userId)
    .first<TrustedDeviceRow>();
  if (!row) return false;
  if (new Date(row.expires_at).getTime() < Date.now()) return false;

  await env.DB.prepare("UPDATE trusted_devices SET last_used_at = ? WHERE id = ?").bind(new Date().toISOString(), deviceId).run();
  return true;
}

/** Marks the current browser as trusted for this user, returning the Set-Cookie header to add. */
export async function trustDevice(env: Env, request: Request, userId: number): Promise<string> {
  const deviceId = randomToken(32);
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + TRUSTED_DEVICE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    "INSERT INTO trusted_devices (id, user_id, user_agent, ip, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(deviceId, userId, request.headers.get("User-Agent"), getClientIp(request), now, now, expiresAt)
    .run();

  return `${TRUSTED_DEVICE_COOKIE}=${deviceId}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${TRUSTED_DEVICE_TTL_DAYS * 24 * 60 * 60}`;
}

export async function listTrustedDevices(env: Env, userId: number): Promise<TrustedDeviceRow[]> {
  const { results } = await env.DB.prepare(
    "SELECT * FROM trusted_devices WHERE user_id = ? AND expires_at > ? ORDER BY last_used_at DESC"
  )
    .bind(userId, new Date().toISOString())
    .all<TrustedDeviceRow>();
  return results;
}

export async function revokeTrustedDevice(env: Env, userId: number, deviceId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM trusted_devices WHERE id = ? AND user_id = ?").bind(deviceId, userId).run();
}

export async function deleteTrustedDevicesForUser(env: Env, userId: number): Promise<void> {
  await env.DB.prepare("DELETE FROM trusted_devices WHERE user_id = ?").bind(userId).run();
}

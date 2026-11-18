import type { Env } from "../env.js";
import { base64ToBytes, bytesToBase64 } from "./brands.js";

/**
 * Profile photos live in user_photos (migration 0039): small,
 * single-purpose rows kept off the hot `users` table. They reach the table
 * from the My account upload or from inbound provisioning (the SCIM
 * `photos` attribute - a data URI, or an https URL fetched server-side).
 * Like brand_assets, the image is stored as base64 text: D1 does not
 * reliably round-trip a raw ArrayBuffer through bind() (it can come back
 * as the bytes' decimal string), so the column stays untyped.
 */

export const MAX_PHOTO_BYTES = 1_000_000;

/** The image type by magic bytes, or null - never trust the uploader's content-type. */
export function sniffImageType(buf: ArrayBuffer): "image/png" | "image/jpeg" | "image/gif" | "image/webp" | null {
  const b = new Uint8Array(buf.slice(0, 16));
  if (b.length < 4) return null;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";
  if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  return null;
}

export async function setUserPhoto(env: Env, userId: number, data: ArrayBuffer | Uint8Array, contentType: string): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO user_photos (user_id, content_type, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET content_type = excluded.content_type, data = excluded.data, updated_at = excluded.updated_at"
  )
    .bind(userId, contentType, bytesToBase64(data instanceof Uint8Array ? data : new Uint8Array(data)), new Date().toISOString())
    .run();
}

export async function getUserPhoto(env: Env, userId: number): Promise<{ content_type: string; data: Uint8Array } | null> {
  const row = await env.DB.prepare("SELECT content_type, data FROM user_photos WHERE user_id = ?").bind(userId).first<{ content_type: string; data: string | ArrayBuffer }>();
  if (!row) return null;
  // New rows hold base64 text. A raw BLOB written earlier comes back as an
  // ArrayBuffer, or - when the driver serializes it - as "137,80,…"; decode
  // whichever shape shows up rather than serving it back as an image.
  const data =
    typeof row.data === "string"
      ? /^\d+(,\d+)*$/.test(row.data)
        ? Uint8Array.from(row.data.split(",").map(Number))
        : base64ToBytes(row.data)
      : new Uint8Array(row.data);
  return { content_type: row.content_type, data };
}

/** The photo's own timestamp, for the ?v= cache-buster - users.updated_at doesn't move on a photo write. */
export async function getUserPhotoVersion(env: Env, userId: number): Promise<string | null> {
  return (await env.DB.prepare("SELECT updated_at FROM user_photos WHERE user_id = ?").bind(userId).first<{ updated_at: string }>())?.updated_at ?? null;
}

/** The versioned photo URL for a user, or "" when they have none - ?v= busts the private cache on replace. */
export async function avatarUrl(env: Env, userId: number): Promise<string> {
  const v = await getUserPhotoVersion(env, userId);
  return v ? `/account/photo/${userId}?v=${encodeURIComponent(v)}` : "";
}

export async function deleteUserPhoto(env: Env, userId: number): Promise<void> {
  await env.DB.prepare("DELETE FROM user_photos WHERE user_id = ?").bind(userId).run();
}

/**
 * Writes a photo from a SCIM `photos` value: either a `data:image/…;base64,`
 * URI decoded inline, or an https URL fetched with a size and type cap.
 * Returns true when something was stored; a value that is neither is simply
 * ignored (SCIM clients send profile URLs we can't always dereference).
 */
export async function applyInboundPhoto(env: Env, userId: number, value: string): Promise<boolean> {
  if (value.startsWith("data:")) {
    const m = /^data:image\/(png|jpeg|jpg|gif|webp);base64,(.+)$/is.exec(value);
    if (!m) return false;
    const buf = Uint8Array.from(atob(m[2]!.replace(/\s+/g, "")), (ch) => ch.charCodeAt(0)).buffer;
    if (buf.byteLength > MAX_PHOTO_BYTES || !sniffImageType(buf)) return false;
    await setUserPhoto(env, userId, buf, `image/${m[1] === "jpg" ? "jpeg" : m[1]}`);
    return true;
  }
  if (!value.startsWith("https://")) return false;
  try {
    const res = await fetch(value, { cf: { cacheTtl: 0 } });
    if (!res.ok) return false;
    const type = (res.headers.get("content-type") ?? "").split(";")[0]!.trim();
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_PHOTO_BYTES) return false;
    const sniffed = sniffImageType(buf);
    if (!sniffed || !type.startsWith("image/")) return false;
    await setUserPhoto(env, userId, buf, sniffed);
    return true;
  } catch {
    return false;
  }
}

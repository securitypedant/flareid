import { expand, grants, isPermission } from "./permissions.js";
import type { Env } from "../env.js";
import { randomToken, sha256Hex } from "./tokens.js";

/**
 * What a key is allowed to do. Deliberately coarse - this is provisioning
 * automation, not a public API with third-party consumers - but not a single
 * all-or-nothing flag either, so a key that only needs to push directory
 * updates cannot also mint more keys.
 */
export const API_SCOPES = [
  "directory:read",
  "directory:write",
  "clients:write",
  "settings:write",
  "admin",
] as const;

/** A legacy scope (API_SCOPES) or any permission from permissions.ts. */
export type ApiScope = string;

export interface ApiKeyRow {
  id: number;
  name: string;
  key_hash: string;
  prefix: string;
  scopes: string;
  created_at: string;
  created_by: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export const KEY_PREFIX = "flareid_sk_";

/** The non-secret leading part of a key, as stored and shown in the admin console. */
export function keyDisplayPrefix(token: string): string {
  return token.slice(0, KEY_PREFIX.length + 8);
}

export function isApiScope(value: string): value is ApiScope {
  return (API_SCOPES as readonly string[]).includes(value) || isPermission(value);
}

/** Parses a stored scopes column, falling back to no scopes rather than to full access if it is unreadable. */
export function parseScopes(raw: string): ApiScope[] {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((s): s is ApiScope => typeof s === "string" && isApiScope(s));
  } catch {
    return [];
  }
}

/**
 * The same check as admin roles: what a key holds (legacy scopes expanded to
 * permissions) must grant what the route needs.
 */
export function hasScope(held: ApiScope[], required: ApiScope): boolean {
  return grants(expand(held), required);
}

export interface CreatedApiKey {
  id: number;
  /** The only time the caller ever sees this. */
  token: string;
  prefix: string;
}

export async function createApiKey(
  env: Env,
  opts: { name: string; scopes: ApiScope[]; createdBy?: string | null; expiresAt?: string | null }
): Promise<CreatedApiKey> {
  const token = `${KEY_PREFIX}${randomToken(24)}`;
  const keyHash = await sha256Hex(token);
  const prefix = keyDisplayPrefix(token);

  const result = await env.DB.prepare(
    "INSERT INTO api_keys (name, key_hash, prefix, scopes, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      opts.name,
      keyHash,
      prefix,
      JSON.stringify(opts.scopes.length > 0 ? opts.scopes : ["admin"]),
      new Date().toISOString(),
      opts.createdBy ?? null,
      opts.expiresAt ?? null
    )
    .run();

  return { id: result.meta.last_row_id, token, prefix };
}

/**
 * Resolves a presented bearer token to a live key, or null.
 *
 * The lookup is by hash, so there is no plaintext to compare in constant time -
 * finding the row at all requires already knowing the key. Revocation and
 * expiry are checked here rather than by the caller so that no route can forget
 * to.
 */
export async function verifyApiKey(env: Env, token: string): Promise<ApiKeyRow | null> {
  if (!token.startsWith(KEY_PREFIX)) return null;

  const keyHash = await sha256Hex(token);
  const row = await env.DB.prepare("SELECT * FROM api_keys WHERE key_hash = ?").bind(keyHash).first<ApiKeyRow>();
  if (!row) return null;
  if (row.revoked_at) return null;
  // Fail closed on an expiry that does not parse (stored before validation existed).
  if (row.expires_at) {
    const expires = new Date(row.expires_at).getTime();
    if (!Number.isFinite(expires) || expires < Date.now()) return null;
  }

  return row;
}

/** Best-effort - a failed "last used" write must never fail the request it was recording. */
export async function touchApiKey(env: Env, id: number): Promise<void> {
  try {
    await env.DB.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").bind(new Date().toISOString(), id).run();
  } catch {
    // Deliberately swallowed.
  }
}

export function listApiKeys(env: Env): Promise<ApiKeyRow[]> {
  return env.DB.prepare("SELECT * FROM api_keys ORDER BY revoked_at IS NOT NULL, created_at DESC")
    .all<ApiKeyRow>()
    .then((r) => r.results);
}

export async function revokeApiKey(env: Env, id: number): Promise<void> {
  await env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
    .bind(new Date().toISOString(), id)
    .run();
}

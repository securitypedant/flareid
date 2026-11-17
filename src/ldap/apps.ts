import type { Env } from "../env.js";
import type { LdapAppRow } from "../lib/types.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";

/**
 * LDAP apps (LDAP.md section 7): a registered client with a service account
 * and a policy. Like api_keys, the service account is not a user - "a key is
 * not a person" - and its secret is generated, shown once, and stored as
 * SHA-256.
 */

export const LDAP_SECRET_PREFIX = "flareid_ldap_";
const SLUG_PATTERN = /^[a-z][a-z0-9-]{1,30}$/;
const RESERVED_SLUGS = new Set(["services", "people", "groups"]);

export function isLdapSlug(slug: string): boolean {
  return SLUG_PATTERN.test(slug) && !RESERVED_SLUGS.has(slug);
}

export async function getLdapAppBySlug(env: Env, slug: string): Promise<LdapAppRow | null> {
  return (await env.DB.prepare("SELECT * FROM ldap_apps WHERE slug = ?").bind(slug.toLowerCase()).first<LdapAppRow>()) ?? null;
}

export async function listLdapApps(env: Env): Promise<LdapAppRow[]> {
  return (await env.DB.prepare("SELECT * FROM ldap_apps ORDER BY slug").all<LdapAppRow>()).results;
}

export interface LdapAppInput {
  slug: string;
  name: string;
  user_group_ids?: number[];
  exposed_group_ids?: number[];
  mfa_mode?: "password" | "otp_if_enrolled" | "otp_required";
  include_disabled?: boolean;
}

/** Create (or, when `upsertSlug` matches, update) an app. Returns the row and, on create, the one-time secret. */
export async function writeLdapApp(env: Env, input: LdapAppInput, opts: { upsert?: boolean } = {}): Promise<{ app: LdapAppRow; secret: string | null }> {
  const slug = input.slug.toLowerCase();
  if (!isLdapSlug(slug)) throw new RangeError(`'${slug}' is not a usable app name (letters, digits, dashes; not services/people/groups).`);
  if (!input.name.trim()) throw new RangeError("The app needs a name.");
  const existing = await getLdapAppBySlug(env, slug);
  const now = new Date().toISOString();
  const userGroupIds = JSON.stringify(input.user_group_ids ?? []);
  const exposedGroupIds = JSON.stringify(input.exposed_group_ids ?? []);
  const mfaMode = input.mfa_mode ?? "otp_if_enrolled";
  const includeDisabled = input.include_disabled ? 1 : 0;
  if (existing && !opts.upsert) {
    await env.DB.prepare("UPDATE ldap_apps SET name = ?, user_group_ids = ?, exposed_group_ids = ?, mfa_mode = ?, include_disabled = ?, updated_at = ? WHERE id = ?")
      .bind(input.name.trim(), userGroupIds, exposedGroupIds, mfaMode, includeDisabled, now, existing.id)
      .run();
    return { app: (await env.DB.prepare("SELECT * FROM ldap_apps WHERE id = ?").bind(existing.id).first<LdapAppRow>())!, secret: null };
  }
  const secret = LDAP_SECRET_PREFIX + randomToken(24);
  await env.DB.prepare(
    "INSERT INTO ldap_apps (slug, name, secret_hash, secret_prefix, user_group_ids, exposed_group_ids, mfa_mode, include_disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      slug,
      input.name.trim(),
      await sha256Hex(secret),
      secret.slice(0, LDAP_SECRET_PREFIX.length + 8),
      userGroupIds,
      exposedGroupIds,
      mfaMode,
      includeDisabled,
      now,
      now
    )
    .run();
  return { app: (await getLdapAppBySlug(env, slug))!, secret };
}

export async function rotateLdapSecret(env: Env, app: LdapAppRow): Promise<string> {
  const secret = LDAP_SECRET_PREFIX + randomToken(24);
  await env.DB.prepare("UPDATE ldap_apps SET secret_hash = ?, secret_prefix = ?, updated_at = ? WHERE id = ?")
    .bind(await sha256Hex(secret), secret.slice(0, LDAP_SECRET_PREFIX.length + 8), new Date().toISOString(), app.id)
    .run();
  return secret;
}

export async function revokeLdapApp(env: Env, app: LdapAppRow): Promise<void> {
  await env.DB.prepare("UPDATE ldap_apps SET revoked_at = ?, updated_at = ? WHERE id = ? AND revoked_at IS NULL")
    .bind(new Date().toISOString(), new Date().toISOString(), app.id)
    .run();
}

/** The app's group-id lists as numbers. '[]' has the documented meaning in each column. */
export function appGroupIds(app: LdapAppRow): { userGroups: number[] | null; exposedGroups: number[] | null } {
  const parse = (raw: string): number[] | null => {
    try {
      const v = JSON.parse(raw);
      return Array.isArray(v) && v.length ? v.map(Number).filter(Number.isFinite) : null;
    } catch {
      return null;
    }
  };
  return { userGroups: parse(app.user_group_ids), exposedGroups: parse(app.exposed_group_ids) };
}

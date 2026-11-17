import type { Env } from "../env.js";
import type { LdapAppRow } from "../lib/types.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import { sealText, unsealText } from "../lib/sealed.js";

/**
 * LDAP apps (LDAP.md section 7): a registered client with a service account
 * and a policy. Like api_keys, the service account is not a user - "a key is
 * not a person" - and its secret is generated. Binds verify against the
 * SHA-256 hash; a KEK-sealed copy (secret_enc) lets the console reveal it
 * without a rotation.
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

/** Create an app, or update it when the slug already exists. Returns the row and, on create, the one-time secret. */
export async function writeLdapApp(env: Env, input: LdapAppInput): Promise<{ app: LdapAppRow; secret: string | null }> {
  const slug = input.slug.toLowerCase();
  if (!isLdapSlug(slug)) throw new RangeError(`'${slug}' is not a usable app name (letters, digits, dashes; not services/people/groups).`);
  if (!input.name.trim()) throw new RangeError("The app needs a name.");
  const existing = await getLdapAppBySlug(env, slug);
  const now = new Date().toISOString();
  // On update an omitted field keeps its stored value - omission is 'keep',
  // not 'reset to create default'. Defaults apply to INSERT only.
  const userGroupIds = input.user_group_ids !== undefined ? JSON.stringify(input.user_group_ids) : (existing?.user_group_ids ?? "[]");
  const exposedGroupIds = input.exposed_group_ids !== undefined ? JSON.stringify(input.exposed_group_ids) : (existing?.exposed_group_ids ?? "[]");
  const mfaMode = input.mfa_mode ?? (existing?.mfa_mode as LdapAppInput["mfa_mode"] | undefined) ?? "otp_if_enrolled";
  const includeDisabled = input.include_disabled !== undefined ? (input.include_disabled ? 1 : 0) : (existing?.include_disabled ?? 0);
  if (existing) {
    await env.DB.prepare("UPDATE ldap_apps SET name = ?, user_group_ids = ?, exposed_group_ids = ?, mfa_mode = ?, include_disabled = ?, updated_at = ? WHERE id = ?")
      .bind(input.name.trim(), userGroupIds, exposedGroupIds, mfaMode, includeDisabled, now, existing.id)
      .run();
    return { app: (await env.DB.prepare("SELECT * FROM ldap_apps WHERE id = ?").bind(existing.id).first<LdapAppRow>())!, secret: null };
  }
  const secret = LDAP_SECRET_PREFIX + randomToken(24);
  await env.DB.prepare(
    "INSERT INTO ldap_apps (slug, name, secret_hash, secret_prefix, secret_enc, user_group_ids, exposed_group_ids, mfa_mode, include_disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(
      slug,
      input.name.trim(),
      await sha256Hex(secret),
      secret.slice(0, LDAP_SECRET_PREFIX.length + 8),
      await sealText(env, secret),
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
  await env.DB.prepare("UPDATE ldap_apps SET secret_hash = ?, secret_prefix = ?, secret_enc = ?, updated_at = ? WHERE id = ?")
    .bind(await sha256Hex(secret), secret.slice(0, LDAP_SECRET_PREFIX.length + 8), await sealText(env, secret), new Date().toISOString(), app.id)
    .run();
  return secret;
}

/** The current secret, for the console's Reveal action. NULL when the app predates sealing - one rotate enables it. */
export async function revealLdapSecret(env: Env, app: LdapAppRow): Promise<string | null> {
  if (!app.secret_enc) return null;
  return unsealText(env, app.secret_enc);
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

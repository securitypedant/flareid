import type { Env } from "../env.js";
import type { OAuthClientRow, UserRow } from "./types.js";
import { dynamicGroupIdsForUser, dynamicGroupNamesForUser } from "./groups.js";
import { resolveLoginIdentifier } from "./identifier.js";

export function getUserByUpn(env: Env, upn: string): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE upn = ?")
    .bind(upn.trim().toLowerCase())
    .first<UserRow>()
    .then((row) => row ?? null);
}

/**
 * Looks a user up by login identifier: a full UPN, a bare handle, an E.164
 * phone, or a listed email/phone alias (identifier.ts). An ambiguous bare
 * name resolves to no user - indistinguishable from an unknown one.
 */
export async function getUserByLoginIdentifier(env: Env, identifier: string): Promise<UserRow | null> {
  return (await resolveLoginIdentifier(env, identifier)).user;
}

export function getUserById(env: Env, id: number): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE id = ?")
    .bind(id)
    .first<UserRow>()
    .then((row) => row ?? null);
}

export async function getUserGroupNames(env: Env, userId: number): Promise<string[]> {
  const [explicit, dynamic] = await Promise.all([
    env.DB.prepare("SELECT g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?")
      .bind(userId)
      .all<{ name: string }>(),
    // The whole row: rules evaluate attributes (employment_type, department,
    // custom_attributes...), so a partial SELECT silently matches nothing.
    env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first<UserRow>(),
  ]);
  const names = new Set(explicit.results.map((r) => r.name));
  if (dynamic) {
    for (const name of await dynamicGroupNamesForUser(env, dynamic)) names.add(name);
  }
  return [...names];
}

/**
 * The id-side of getUserGroupNames: explicit memberships plus the dynamic
 * groups whose rules match. App assignment (oauth_clients.assigned_groups,
 * saml_service_providers.assigned_groups) stores ids, so this is what the
 * launchpad and the SSO gates intersect against.
 */
export async function getUserGroupIds(env: Env, userId: number): Promise<number[]> {
  const [explicit, user] = await Promise.all([
    env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?").bind(userId).all<{ group_id: number }>(),
    env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first<UserRow>(),
  ]);
  const ids = new Set(explicit.results.map((r) => r.group_id));
  if (user) {
    for (const id of await dynamicGroupIdsForUser(env, user)) ids.add(id);
  }
  return [...ids];
}

export function getUserByExternalId(env: Env, externalId: string): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE external_id = ?")
    .bind(externalId)
    .first<UserRow>()
    .then((row) => row ?? null);
}

/** Resolves a manager's current email from their stable external_id reference (may have changed since it was set). */
export async function getManagerEmail(env: Env, managerExternalId: string | null): Promise<string | null> {
  if (!managerExternalId) return null;
  const row = await env.DB.prepare("SELECT upn FROM users WHERE external_id = ?")
    .bind(managerExternalId)
    .first<{ upn: string }>();
  return row?.upn ?? null;
}

export function getClientByClientId(env: Env, clientId: string): Promise<OAuthClientRow | null> {
  return env.DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?")
    .bind(clientId)
    .first<OAuthClientRow>()
    .then((row) => row ?? null);
}

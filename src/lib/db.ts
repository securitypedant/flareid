import type { Env } from "../env.js";
import type { OAuthClientRow, UserRow } from "./types.js";

export function getUserByUpn(env: Env, upn: string): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE upn = ?")
    .bind(upn.trim().toLowerCase())
    .first<UserRow>()
    .then((row) => row ?? null);
}

/**
 * Looks a user up by login identifier - either their full UPN, or just the
 * username part (unique across every domain, so this is unambiguous).
 */
export async function getUserByLoginIdentifier(env: Env, identifier: string): Promise<UserRow | null> {
  const normalized = identifier.trim().toLowerCase();
  if (normalized.includes("@")) return getUserByUpn(env, normalized);

  return env.DB.prepare("SELECT * FROM users WHERE username = ?")
    .bind(normalized)
    .first<UserRow>()
    .then((row) => row ?? null);
}

export function getUserById(env: Env, id: number): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE id = ?")
    .bind(id)
    .first<UserRow>()
    .then((row) => row ?? null);
}

export async function getUserGroupNames(env: Env, userId: number): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?"
  )
    .bind(userId)
    .all<{ name: string }>();
  return results.map((r) => r.name);
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

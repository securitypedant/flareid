import type { Env } from "../env.js";

export interface DomainRow {
  id: number;
  domain: string;
  is_default: number;
  created_at: string;
}

export function listDomains(env: Env): Promise<DomainRow[]> {
  return env.DB.prepare("SELECT * FROM domains ORDER BY is_default DESC, domain")
    .all<DomainRow>()
    .then((r) => r.results);
}

export async function getDefaultDomain(env: Env): Promise<string> {
  const row = await env.DB.prepare("SELECT domain FROM domains WHERE is_default = 1 LIMIT 1").first<{
    domain: string;
  }>();
  if (row) return row.domain;
  const any = await env.DB.prepare("SELECT domain FROM domains LIMIT 1").first<{ domain: string }>();
  return any?.domain ?? "example.com";
}

export async function addDomain(env: Env, domain: string): Promise<void> {
  await env.DB.prepare("INSERT INTO domains (domain, is_default, created_at) VALUES (?, 0, ?)")
    .bind(domain.trim().toLowerCase(), new Date().toISOString())
    .run();
}

export async function deleteDomain(env: Env, id: number): Promise<{ error?: string }> {
  const domain = await env.DB.prepare("SELECT * FROM domains WHERE id = ?").bind(id).first<DomainRow>();
  if (!domain) return { error: "Unknown domain" };

  const countRow = await env.DB.prepare("SELECT COUNT(*) as count FROM domains").first<{ count: number }>();
  if ((countRow?.count ?? 0) <= 1) return { error: "Cannot delete the last remaining domain" };

  const inUse = await env.DB.prepare("SELECT COUNT(*) as n FROM users WHERE upn LIKE ?")
    .bind(`%@${domain.domain}`)
    .first<{ n: number }>();
  if (inUse && inUse.n > 0) return { error: `${inUse.n} user(s) still use this domain - reassign them first` };

  await env.DB.prepare("DELETE FROM domains WHERE id = ?").bind(id).run();
  if (domain.is_default) {
    await env.DB.prepare("UPDATE domains SET is_default = 1 WHERE id = (SELECT id FROM domains LIMIT 1)").run();
  }
  return {};
}

export async function setDefaultDomain(env: Env, id: number): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE domains SET is_default = 0"),
    env.DB.prepare("UPDATE domains SET is_default = 1 WHERE id = ?").bind(id),
  ]);
}

/** Rewrites every user's UPN domain (keeping the local part) to the given domain. Returns any local-part collisions. */
export async function applyDomainToAllUsers(env: Env, domain: string): Promise<{ updated: number; conflicts: string[] }> {
  const { results: users } = await env.DB.prepare("SELECT id, upn FROM users").all<{ id: number; upn: string }>();

  const seenLocalParts = new Map<string, number>(); // localPart -> userId already assigned this run
  const conflicts: string[] = [];
  const updates: { id: number; newUpn: string }[] = [];

  for (const user of users) {
    const localPart = user.upn.split("@")[0] ?? user.upn;
    const newUpn = `${localPart}@${domain}`;
    if (seenLocalParts.has(localPart)) {
      conflicts.push(newUpn);
      continue;
    }
    seenLocalParts.set(localPart, user.id);
    updates.push({ id: user.id, newUpn });
  }

  if (updates.length > 0) {
    await env.DB.batch(
      updates.map((u) => env.DB.prepare("UPDATE users SET upn = ?, updated_at = ? WHERE id = ?").bind(u.newUpn, new Date().toISOString(), u.id))
    );
  }

  return { updated: updates.length, conflicts };
}

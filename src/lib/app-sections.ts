import type { Env } from "../env.js";

/**
 * A person's own grouping of their launchpad (account -> Applications):
 * named sections in their chosen order, and which section each app sits in.
 * Purely presentational - nothing here grants or limits access.
 */

export interface AppSection {
  id: number;
  name: string;
  position: number;
}

export const SECTION_NAME_MAX = 60;
const MAX_SECTIONS = 30;

export async function listAppSections(env: Env, userId: number): Promise<{ sections: AppSection[]; placements: Map<string, number> }> {
  const [{ results: sections }, { results: placed }] = await Promise.all([
    env.DB.prepare("SELECT id, name, position FROM user_app_sections WHERE user_id = ? ORDER BY position, id").bind(userId).all<AppSection>(),
    env.DB.prepare("SELECT app_key, section_id FROM user_app_placements WHERE user_id = ?").bind(userId).all<{ app_key: string; section_id: number }>(),
  ]);
  return { sections, placements: new Map(placed.map((p) => [p.app_key, p.section_id])) };
}

export class AppSectionError extends Error {}

function cleanName(raw: string): string {
  const name = raw.replace(/\s+/g, " ").trim().slice(0, SECTION_NAME_MAX);
  if (!name) throw new AppSectionError("Give the section a name.");
  return name;
}

export async function createAppSection(env: Env, userId: number, raw: string): Promise<number> {
  const name = cleanName(raw);
  const count = (await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(MAX(position), -1) AS top FROM user_app_sections WHERE user_id = ?").bind(userId).first<{ n: number; top: number }>())!;
  if (count.n >= MAX_SECTIONS) throw new AppSectionError(`You can have up to ${MAX_SECTIONS} sections.`);
  const r = await env.DB.prepare("INSERT INTO user_app_sections (user_id, name, position, created_at) VALUES (?, ?, ?, ?)").bind(userId, name, count.top + 1, new Date().toISOString()).run();
  return Number(r.meta.last_row_id);
}

export async function renameAppSection(env: Env, userId: number, id: number, raw: string): Promise<void> {
  await env.DB.prepare("UPDATE user_app_sections SET name = ? WHERE id = ? AND user_id = ?").bind(cleanName(raw), id, userId).run();
}

/** Deleting a section puts its apps back in the unsorted list (placements cascade). */
export async function deleteAppSection(env: Env, userId: number, id: number): Promise<void> {
  await env.DB.prepare("DELETE FROM user_app_sections WHERE id = ? AND user_id = ?").bind(id, userId).run();
}

/** Swaps a section with its neighbour above or below. */
export async function moveAppSection(env: Env, userId: number, id: number, dir: "up" | "down"): Promise<void> {
  const { sections } = await listAppSections(env, userId);
  const i = sections.findIndex((s) => s.id === id);
  const j = dir === "up" ? i - 1 : i + 1;
  if (i < 0 || j < 0 || j >= sections.length) return;
  const order = sections.map((s) => s.id);
  [order[i], order[j]] = [order[j]!, order[i]!];
  await env.DB.batch(order.map((sid, pos) => env.DB.prepare("UPDATE user_app_sections SET position = ? WHERE id = ? AND user_id = ?").bind(pos, sid, userId)));
}

/** Puts an app in one of the person's sections, or back in the unsorted list (sectionId null). */
export async function placeApp(env: Env, userId: number, appKey: string, sectionId: number | null): Promise<void> {
  if (!/^(oidc|saml|access):\d+$/.test(appKey)) throw new AppSectionError("Unknown app.");
  if (sectionId === null) {
    await env.DB.prepare("DELETE FROM user_app_placements WHERE user_id = ? AND app_key = ?").bind(userId, appKey).run();
    return;
  }
  const owns = await env.DB.prepare("SELECT 1 FROM user_app_sections WHERE id = ? AND user_id = ?").bind(sectionId, userId).first();
  if (!owns) throw new AppSectionError("That section doesn't exist any more.");
  await env.DB.prepare("INSERT INTO user_app_placements (user_id, app_key, section_id) VALUES (?, ?, ?) ON CONFLICT (user_id, app_key) DO UPDATE SET section_id = excluded.section_id")
    .bind(userId, appKey, sectionId)
    .run();
}

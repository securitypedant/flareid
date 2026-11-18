import type { Env } from "../env.js";
import type { NotificationFeed } from "./html.js";

/**
 * The bell's feed: work waiting on this person.
 *
 * An administrator sees every pending access request (they land on the
 * Access queue); a group manager sees the ones waiting on the groups they
 * own (they land on the managed group's page). Other alerts can join the
 * same shape later.
 */
export async function notificationFeedFor(env: Env, userId: number, isAdmin: boolean): Promise<NotificationFeed | null> {
  // A manager's feed skips their own requests - they can't decide those.
  const join = isAdmin ? "" : "JOIN group_managers m ON m.group_id = r.group_id AND m.user_id = ?";
  const own = isAdmin ? "" : " AND r.user_id != ?";
  const bind = isAdmin ? [] : [userId, userId];
  const [count, rows] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS n FROM access_requests r ${join} WHERE r.status = 'pending'${own}`).bind(...bind),
    env.DB.prepare(
      `SELECT r.id, r.group_id, u.display_name, g.name AS group_name, r.created_at
       FROM access_requests r ${join}
       JOIN users u ON u.id = r.user_id JOIN groups g ON g.id = r.group_id
       WHERE r.status = 'pending'${own} ORDER BY r.created_at DESC LIMIT 5`
    ).bind(...bind),
  ]);
  const results = (rows?.results ?? []) as { id: number; group_id: number; display_name: string; group_name: string; created_at: string }[];
  // A non-admin with nothing to manage has no bell at all.
  if (!isAdmin && !(await env.DB.prepare("SELECT 1 FROM group_managers WHERE user_id = ? LIMIT 1").bind(userId).first())) return null;
  return {
    count: Number((count?.results[0] as { n: number } | undefined)?.n ?? 0),
    items: results.map((r) => ({
      label: `${r.display_name} asked to join ${r.group_name}`,
      href: isAdmin ? "/admin/access" : `/account/groups/${r.group_id}`,
      when: r.created_at.slice(0, 10),
    })),
    seeAllHref: isAdmin ? "/admin/access" : "/account/groups",
  };
}

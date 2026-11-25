import type { Env } from "../env.js";
import type { NotificationFeed } from "./html.js";
import { countOpenReports, describeReport, listOpenReports } from "./account-reports.js";

/**
 * The bell's feed: work waiting on this person.
 *
 * An administrator sees every pending access request (they land on the
 * Access queue); a group manager sees the ones waiting on the groups they
 * own (they land on the managed group's page). Other alerts can join the
 * same shape later. Administrators also see open "this wasn't me" reports
 * (account-reports.ts), which land on the reported person's page.
 */
export async function notificationFeedFor(env: Env, userId: number, isAdmin: boolean): Promise<NotificationFeed | null> {
  // A manager's feed skips their own requests - they can't decide those, and
  // only groups can be managed anyway.
  const join = isAdmin ? "" : "JOIN group_managers m ON r.target_type = 'group' AND m.group_id = r.target_id AND m.user_id = ?";
  const own = isAdmin ? "" : " AND r.user_id != ?";
  const bind = isAdmin ? [] : [userId, userId];
  const names = `LEFT JOIN groups g ON r.target_type = 'group' AND g.id = r.target_id
    LEFT JOIN oauth_clients oc ON r.target_type = 'oidc_app' AND oc.id = r.target_id
    LEFT JOIN saml_service_providers sp ON r.target_type = 'saml_app' AND sp.id = r.target_id`;
  const [count, rows] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS n FROM access_requests r ${join} WHERE r.status = 'pending'${own}`).bind(...bind),
    env.DB.prepare(
      `SELECT r.id, r.target_type, r.target_id, u.display_name, COALESCE(g.name, oc.name, sp.name) AS target_name, r.created_at
       FROM access_requests r ${join}
       JOIN users u ON u.id = r.user_id ${names}
       WHERE r.status = 'pending'${own} ORDER BY r.created_at DESC LIMIT 5`
    ).bind(...bind),
  ]);
  const results = (rows?.results ?? []) as { id: number; target_type: string; target_id: number; display_name: string; target_name: string; created_at: string }[];
  // A non-admin with nothing to manage has no bell at all.
  if (!isAdmin && !(await env.DB.prepare("SELECT 1 FROM group_managers WHERE user_id = ? LIMIT 1").bind(userId).first())) return null;
  const requestItems = results.map((r) => ({
    at: r.created_at,
    label: r.target_type === "group" ? `${r.display_name} asked to join ${r.target_name}` : `${r.display_name} asked for access to ${r.target_name}`,
    href: isAdmin ? "/admin/access" : r.target_type === "group" ? `/account/groups/${r.target_id}` : "/account/access",
  }));
  const [reportCount, reports] = isAdmin ? await Promise.all([countOpenReports(env), listOpenReports(env, 5)]) : [0, []];
  const reportItems = reports.map((r) => ({ at: r.created_at, label: `${r.display_name} reported ${describeReport(r)}`, href: `/admin/users/${r.user_id}` }));
  return {
    count: Number((count?.results[0] as { n: number } | undefined)?.n ?? 0) + reportCount,
    items: [...reportItems, ...requestItems]
      .sort((a, b) => b.at.localeCompare(a.at))
      .slice(0, 5)
      .map(({ at, label, href }) => ({ label, href, when: at.slice(0, 10) })),
    seeAllHref: isAdmin ? (reportItems.length && !requestItems.length ? reportItems[0]!.href : "/admin/access") : "/account/access",
  };
}

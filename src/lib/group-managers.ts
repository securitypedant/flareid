import type { Env } from "../env.js";
import type { GroupRow, UserRow } from "./types.js";

/**
 * Delegated group ownership. A group's managers are ordinary accounts named
 * on the group's admin page; they can add and remove the group's members and
 * answer its access requests from My account, without holding the
 * groups:write console permission.
 *
 * Manager authority never exceeds admin authority: the shared guards still
 * refuse non-privileged actors touching admin-role groups, so naming a
 * manager on one grants them nothing.
 */

export async function isGroupManager(env: Env, userId: number, groupId: number): Promise<boolean> {
  return Boolean(await env.DB.prepare("SELECT 1 FROM group_managers WHERE group_id = ? AND user_id = ?").bind(groupId, userId).first());
}

/** Groups a person manages, with member and waiting-request counts. */
export async function managedGroups(env: Env, userId: number): Promise<(GroupRow & { member_count: number; pending: number })[]> {
  return (
    await env.DB.prepare(
      `SELECT g.*,
        (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) AS member_count,
        (SELECT COUNT(*) FROM access_requests ar WHERE ar.target_type = 'group' AND ar.target_id = g.id AND ar.status = 'pending') AS pending
       FROM group_managers m JOIN groups g ON g.id = m.group_id
       WHERE m.user_id = ? ORDER BY g.name`
    )
      .bind(userId)
      .all<GroupRow & { member_count: number; pending: number }>()
  ).results;
}

/** The people named as a group's managers. */
export async function groupManagers(env: Env, groupId: number): Promise<UserRow[]> {
  return (
    await env.DB.prepare(
      `SELECT u.* FROM group_managers m JOIN users u ON u.id = m.user_id WHERE m.group_id = ? ORDER BY u.display_name`
    )
      .bind(groupId)
      .all<UserRow>()
  ).results;
}

/** Access requests still waiting on the groups a person manages. */
export async function pendingRequestsForManager(env: Env, userId: number, limit = 50): Promise<{ id: number; user_id: number; group_id: number; reason: string; upn: string; display_name: string; group_name: string; created_at: string }[]> {
  return (
    await env.DB.prepare(
      `SELECT r.id, r.user_id, r.target_id AS group_id, r.reason, u.upn, u.display_name, g.name AS group_name, r.created_at
       FROM access_requests r
       JOIN group_managers m ON r.target_type = 'group' AND m.group_id = r.target_id AND m.user_id = ?
       JOIN users u ON u.id = r.user_id JOIN groups g ON g.id = r.target_id
       WHERE r.status = 'pending' AND r.user_id != ? ORDER BY r.created_at DESC LIMIT ?`
    )
      .bind(userId, userId, limit)
      .all<{ id: number; user_id: number; group_id: number; reason: string; upn: string; display_name: string; group_name: string; created_at: string }>()
  ).results;
}

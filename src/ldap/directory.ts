import type { Env } from "../env.js";
import type { GroupRow, LdapAppRow, UserRow } from "../lib/types.js";
import { parseRule, userMatchesRule } from "../lib/groups.js";
import { appGroupIds } from "./apps.js";

/**
 * The directory snapshot and the per-app view over it (LDAP.md section 10).
 * One snapshot serves a burst of searches on a connection; the app's view is
 * derived from it in memory - visible users, visible groups, and membership
 * restricted to what the app may see.
 */

export interface DirectorySnapshot {
  users: UserRow[];
  groups: GroupRow[];
  /** group_id -> effective member user_ids (explicit rows plus rule matches). */
  members: Map<number, number[]>;
}

/** One batch read: users, groups, and every explicit membership row. */
export async function loadSnapshot(env: Env): Promise<DirectorySnapshot> {
  const [users, groups, links] = await env.DB.batch([
    env.DB.prepare("SELECT * FROM users"),
    env.DB.prepare("SELECT * FROM groups"),
    env.DB.prepare("SELECT group_id, user_id FROM group_members"),
  ]);
  const groupRows = (groups?.results ?? []) as unknown as GroupRow[];
  const members = new Map<number, number[]>();
  for (const row of (links?.results ?? []) as unknown as { group_id: number; user_id: number }[]) {
    const list = members.get(row.group_id) ?? [];
    list.push(row.user_id);
    members.set(row.group_id, list);
  }
  // Dynamic membership evaluated in memory - a group with a rule ignores any
  // stray explicit rows, matching resolveGroupMemberUserIds.
  const userRows = (users?.results ?? []) as unknown as UserRow[];
  for (const g of groupRows) {
    const rule = parseRule(g.rule);
    if (rule) members.set(g.id, userRows.filter((u) => userMatchesRule(u, rule)).map((u) => u.id));
  }
  return { users: userRows, groups: groupRows, members };
}

/**
 * What one LDAP app may see: users it may bind/show, groups it may show, and
 * membership intersected with visible users.
 */
export interface DirectoryView {
  users: UserRow[];
  groups: GroupRow[];
  /** group.id -> member user ids, intersected with visible users. */
  groupMembers: Map<number, number[]>;
  /** user.id -> visible group ids the user belongs to. */
  userGroups: Map<number, number[]>;
  userById: Map<number, UserRow>;
}

export function viewForApp(snapshot: DirectorySnapshot, app: LdapAppRow): DirectoryView {
  const { userGroups, exposedGroups } = appGroupIds(app);
  const visibleUserIds = new Set(
    snapshot.users
      .filter((u) => {
        if (u.status !== "active" && !app.include_disabled) return false;
        if (userGroups === null) return true;
        return snapshot.groups.some((g) => userGroups.includes(g.id) && (snapshot.members.get(g.id) ?? []).includes(u.id));
      })
      .map((u) => u.id)
  );
  const visibleGroups = snapshot.groups.filter((g) => exposedGroups === null || exposedGroups.includes(g.id));

  const groupMembers = new Map<number, number[]>();
  const userGroups2 = new Map<number, number[]>();
  for (const g of visibleGroups) {
    const ids = (snapshot.members.get(g.id) ?? []).filter((id) => visibleUserIds.has(id));
    groupMembers.set(g.id, ids);
    for (const id of ids) {
      const list = userGroups2.get(id) ?? [];
      list.push(g.id);
      userGroups2.set(id, list);
    }
  }
  const users = snapshot.users.filter((u) => visibleUserIds.has(u.id));
  return { users, groups: visibleGroups, groupMembers, userGroups: userGroups2, userById: new Map(snapshot.users.map((u) => [u.id, u])) };
}

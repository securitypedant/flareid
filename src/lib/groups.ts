import type { Env } from "../env.js";
import type { GroupRow, UserRow } from "./types.js";

/**
 * Dynamic groups.
 *
 * A group's `rule` is a JSON conditions object evaluated against user
 * attributes at read time:
 *
 *   {"all":[{"field":"employment_type","op":"eq","value":"full_time"}]}
 *
 * `all` is a conjunction; `op` is "eq" or "ne". Fields are user columns plus
 * custom-attribute keys (schema attributes resolve against the user's
 * custom_attributes JSON). Effective group membership is the union of
 * explicit group_members rows and users the rule matches - so membership
 * follows attribute changes instead of a one-time join.
 *
 * Rules are deliberately limited to direct value comparison: no regex, no
 * nesting, no OR. That keeps evaluation a simple scan and keeps the admin UI
 * honest about what a rule can express.
 */

export interface GroupRule {
  all: { field: string; op: "eq" | "ne"; value: string }[];
}

/** Fields usable in rules: user columns, or `custom.<attribute>` for schema attributes. */
export function ruleFields(user: UserRow, custom: Record<string, string>): Record<string, string> {
  return {
    username: user.username,
    upn: user.upn,
    display_name: user.display_name,
    given_name: user.given_name,
    family_name: user.family_name,
    job_title: user.job_title,
    department: user.department,
    employee_number: user.employee_number,
    hire_date: user.hire_date,
    employment_status: user.employment_status,
    employment_type: user.employment_type,
    location: user.location,
    status: user.status,
    ...Object.fromEntries(Object.entries(custom).map(([k, v]) => [`custom.${k}`, v])),
  };
}

export function parseRule(raw: string | null | undefined): GroupRule | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as GroupRule;
    if (!parsed || !Array.isArray(parsed.all)) return null;
    const all = parsed.all.filter((c) => c && typeof c.field === "string" && typeof c.value === "string" && (c.op === "eq" || c.op === "ne"));
    return all.length > 0 ? { all } : null;
  } catch {
    return null;
  }
}

/** Serializes textarea input like "employment_type = full_time" (one per line) into rule JSON. */
export function ruleFromLines(text: string): string {
  const all = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const m = /^(\S+)\s*(=|!=)\s*(.+)$/.exec(line);
      if (!m) return null;
      return { field: m[1]!, op: m[2] === "!=" ? ("ne" as const) : ("eq" as const), value: m[3]!.trim() };
    });
  if (all.some((c) => c === null)) throw new Error('Each line must look like "field = value" or "field != value".');
  return all.length > 0 ? JSON.stringify({ all }) : "";
}

/** Inverse of ruleFromLines - for rendering the rule textarea. */
export function ruleToLines(raw: string | null | undefined): string {
  const rule = parseRule(raw);
  if (!rule) return "";
  return rule.all.map((c) => `${c.field} ${c.op === "ne" ? "!=" : "="} ${c.value}`).join("\n");
}

function userCustomAttrs(user: UserRow): Record<string, string> {
  try {
    return JSON.parse(user.custom_attributes || "{}") as Record<string, string>;
  } catch {
    return {};
  }
}

export function userMatchesRule(user: UserRow, rule: GroupRule): boolean {
  const fields = ruleFields(user, userCustomAttrs(user));
  return rule.all.every((c) => {
    const actual = fields[c.field] ?? "";
    return c.op === "eq" ? actual === c.value : actual !== c.value;
  });
}

/**
 * Every user who is effectively in a group: explicit group_members rows plus
 * dynamic rule matches.
 */
export async function resolveGroupMemberUserIds(env: Env, group: GroupRow): Promise<number[]> {
  const { results: explicit } = await env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(group.id).all<{ user_id: number }>();
  const rule = parseRule(group.rule);
  if (!rule) return explicit.map((r) => r.user_id);

  const { results: users } = await env.DB.prepare("SELECT * FROM users").all<UserRow>();
  const ids = new Set(explicit.map((r) => r.user_id));
  for (const u of users) if (userMatchesRule(u, rule)) ids.add(u.id);
  return [...ids];
}

/** Groups whose rule matches a user, for membership resolution everywhere claims need it. */
export async function dynamicGroupNamesForUser(env: Env, user: UserRow): Promise<string[]> {
  const { results: groups } = await env.DB.prepare("SELECT * FROM groups WHERE rule != ''").all<GroupRow>();
  return groups.filter((g) => userMatchesRule(user, parseRule(g.rule)!)).map((g) => g.name);
}

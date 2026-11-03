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
 * `all` is a conjunction; `op` is "eq" or "ne". `field` is an attribute name:
 * a user column, or a schema attribute stored in custom_attributes (the bare
 * name, or the older `custom.<name>` form). An optional `schema` names the
 * schema the attribute was picked from - it is for display in the rule
 * builder only, and does not restrict which users the rule matches.
 *
 * A dynamic group's membership is the rule's matches and nothing else: the
 * admin UI and import refuse explicit members for a group with a rule, so
 * membership follows attribute changes instead of a one-time join.
 *
 * Rules are deliberately limited to direct value comparison: no regex, no
 * nesting, no OR. That keeps evaluation a simple scan and keeps the admin UI
 * honest about what a rule can express.
 */

export interface RuleCondition {
  schema?: string;
  field: string;
  op: "eq" | "ne";
  value: string;
}

export interface GroupRule {
  all: RuleCondition[];
}

/** Fields usable in rules: user columns, plus schema attributes by bare name or as `custom.<attribute>`. */
export function ruleFields(user: UserRow, custom: Record<string, string>): Record<string, string> {
  return {
    ...custom,
    ...Object.fromEntries(Object.entries(custom).map(([k, v]) => [`custom.${k}`, v])),
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
    manager: user.manager_external_id ?? "",
  };
}

export function parseRule(raw: string | null | undefined): GroupRule | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as GroupRule;
    if (!parsed || !Array.isArray(parsed.all)) return null;
    const all = parsed.all
      .filter((c) => c && typeof c.field === "string" && c.field && typeof c.value === "string" && (c.op === "eq" || c.op === "ne"))
      .map((c) => ({ ...(typeof c.schema === "string" && c.schema ? { schema: c.schema } : {}), field: c.field, op: c.op, value: c.value }));
    return all.length > 0 ? { all } : null;
  } catch {
    return null;
  }
}

/**
 * Builds rule JSON from the rule-builder's parallel form arrays
 * (rule_schema[], rule_field[], rule_op[], rule_value[]). Rows with no field
 * are ignored, so an empty trailing row is harmless; a row with a field but
 * no value is an error rather than a silent match-the-empty-string.
 */
export function ruleFromForm(schemas: string[], fields: string[], ops: string[], values: string[]): string {
  const all: RuleCondition[] = [];
  fields.forEach((field, i) => {
    const f = field.trim();
    if (!f) return;
    const value = (values[i] ?? "").trim();
    if (!value) throw new Error(`The condition on "${f}" needs a value.`);
    const schema = (schemas[i] ?? "").trim();
    all.push({ ...(schema ? { schema } : {}), field: f, op: ops[i] === "ne" ? "ne" : "eq", value });
  });
  return all.length > 0 ? JSON.stringify({ all }) : "";
}

/** Human-readable rule, e.g. "FlareID HR › department = Sales AND employment_type != contractor". */
export function ruleDescription(rule: GroupRule): string {
  return rule.all.map((c) => `${c.schema ? `${c.schema} › ` : ""}${c.field} ${c.op === "ne" ? "!=" : "="} ${c.value}`).join(" AND ");
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
 * Every user who is effectively in a group: explicit group_members rows for a
 * static group, rule matches for a dynamic one.
 */
export async function resolveGroupMemberUserIds(env: Env, group: GroupRow): Promise<number[]> {
  const rule = parseRule(group.rule);
  if (!rule) {
    const { results: explicit } = await env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(group.id).all<{ user_id: number }>();
    return explicit.map((r) => r.user_id);
  }
  const { results: users } = await env.DB.prepare("SELECT * FROM users").all<UserRow>();
  return users.filter((u) => userMatchesRule(u, rule)).map((u) => u.id);
}

/** Groups whose rule matches a user, for membership resolution everywhere claims need it. */
export async function dynamicGroupNamesForUser(env: Env, user: UserRow): Promise<string[]> {
  const { results: groups } = await env.DB.prepare("SELECT * FROM groups WHERE rule != ''").all<GroupRow>();
  return groups.filter((g) => userMatchesRule(user, parseRule(g.rule)!)).map((g) => g.name);
}

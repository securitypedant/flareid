import type { Env } from "../env.js";
import type { GroupRow, UserRow } from "./types.js";
import { evalExpression, parseExpression, truthy, type ScimExpr } from "./expr.js";

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

/**
 * An expression condition: the shared expression language (src/lib/expr.ts)
 * evaluated over the user document; truthy means the condition holds. This is
 * the full predicate form - contains(), comparisons, coalesce chains - for
 * the rules the field = value builder can't express.
 */
export interface RuleExprCondition {
  expr: string;
  /** Pre-parsed by parseRule so the per-user scan never re-parses. */
  parsed?: ScimExpr;
}

export type RuleTerm = RuleCondition | RuleExprCondition;

export interface GroupRule {
  all: RuleTerm[];
}

export function isExprCondition(t: RuleTerm): t is RuleExprCondition {
  return "expr" in t;
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

/** Every rule is loaded and parsed on each authenticated request, so its size is bounded. */
export const MAX_RULE_BYTES = 4096;
export const MAX_RULE_CONDITIONS = 20;

export function parseRule(raw: string | null | undefined): GroupRule | null {
  if (!raw || raw.length > MAX_RULE_BYTES) return null;
  try {
    const parsed = JSON.parse(raw) as { all?: unknown };
    if (!parsed || !Array.isArray(parsed.all)) return null;
    const all: RuleTerm[] = [];
    for (const c of parsed.all as Record<string, unknown>[]) {
      if (c && typeof c.expr === "string" && c.expr) {
        // A stored expression that won't parse is dropped here; saved rules
        // are validated at write time, so this only protects hand-edited DBs.
        try {
          all.push({ expr: c.expr, parsed: parseExpression(c.expr) });
        } catch { /* skip */ }
        continue;
      }
      if (c && typeof c.field === "string" && c.field && typeof c.value === "string" && (c.op === "eq" || c.op === "ne")) {
        all.push({ ...(typeof c.schema === "string" && c.schema ? { schema: c.schema } : {}), field: c.field, op: c.op, value: c.value });
      }
    }
    return all.length > 0 && all.length <= MAX_RULE_CONDITIONS ? { all } : null;
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
  const all: RuleTerm[] = [];
  fields.forEach((field, i) => {
    const f = field.trim();
    const value = (values[i] ?? "").trim();
    if (ops[i] === "expr") {
      if (!value) return;
      // Validate at save so a stored rule can never fail to parse later.
      try {
        parseExpression(value);
      } catch (e) {
        throw new Error(`The expression "${value}" is invalid: ${e instanceof Error ? e.message : String(e)}`);
      }
      all.push({ expr: value });
      return;
    }
    if (!f) return;
    if (!value) throw new Error(`The condition on "${f}" needs a value.`);
    const schema = (schemas[i] ?? "").trim();
    all.push({ ...(schema ? { schema } : {}), field: f, op: ops[i] === "ne" ? "ne" : "eq", value });
  });
  if (all.length === 0) return "";
  const rule = JSON.stringify({ all });
  // The same bounds every reader applies (parseRule): a rule the evaluator
  // would refuse must not be stored.
  if (!parseRule(rule)) throw new Error(`A rule may have at most ${MAX_RULE_CONDITIONS} conditions and ${MAX_RULE_BYTES} bytes.`);
  return rule;
}

/** Human-readable rule, e.g. "FlareID HR › department = Sales AND employment_type != contractor". */
export function ruleDescription(rule: GroupRule): string {
  return rule.all.map((c) => (isExprCondition(c) ? c.expr : `${c.schema ? `${c.schema} › ` : ""}${c.field} ${c.op === "ne" ? "!=" : "="} ${c.value}`)).join(" AND ");
}

function userCustomAttrs(user: UserRow): Record<string, string> {
  try {
    return JSON.parse(user.custom_attributes || "{}") as Record<string, string>;
  } catch {
    return {};
  }
}

export function userMatchesRule(user: UserRow, rule: GroupRule): boolean {
  const custom = userCustomAttrs(user);
  const fields = ruleFields(user, custom);
  const doc = { ...fields, custom };
  return rule.all.every((c) => {
    if (isExprCondition(c)) {
      const parsed = c.parsed ?? parseExpression(c.expr);
      return truthy(evalExpression(parsed, doc));
    }
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

/**
 * Member ids for many groups at once: one load of the directory for all the
 * dynamic groups, instead of one per group (211 groups x 10,000 users made the
 * SCIM groups step scan two million rows).
 */
export async function resolveManyGroupMemberUserIds(env: Env, groups: GroupRow[]): Promise<Map<number, number[]>> {
  const out = new Map<number, number[]>();
  const dynamic = groups.map((g) => [g, parseRule(g.rule)] as const).filter(([, r]) => r);
  const users = dynamic.length ? (await env.DB.prepare("SELECT * FROM users").all<UserRow>()).results : [];
  for (const [g, rule] of dynamic) out.set(g.id, users.filter((u) => userMatchesRule(u, rule!)).map((u) => u.id));
  const staticIds = groups.filter((g) => !parseRule(g.rule)).map((g) => g.id);
  if (staticIds.length) {
    const { results } = await env.DB.prepare("SELECT group_id, user_id FROM group_members WHERE group_id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(staticIds)).all<{ group_id: number; user_id: number }>();
    for (const id of staticIds) out.set(id, []);
    for (const r of results) out.get(r.group_id)!.push(r.user_id);
  }
  return out;
}

/** Every dynamic group whose rule matches a user - the shared scan behind the name/id views. */
async function dynamicGroupsForUser(env: Env, user: UserRow): Promise<GroupRow[]> {
  const { results: groups } = await env.DB.prepare("SELECT * FROM groups WHERE rule != ''").all<GroupRow>();
  // A stored rule the parser refuses (legacy, oversized) matches nobody - it
  // must never break group resolution for every request.
  return groups.filter((g) => {
    const rule = parseRule(g.rule);
    return rule !== null && userMatchesRule(user, rule);
  });
}

/** Groups whose rule matches a user, for membership resolution everywhere claims need it. */
export async function dynamicGroupNamesForUser(env: Env, user: UserRow): Promise<string[]> {
  return (await dynamicGroupsForUser(env, user)).map((g) => g.name);
}

/** The id-side of dynamicGroupNamesForUser - for app assignment checks, which key on group ids. */
export async function dynamicGroupIdsForUser(env: Env, user: UserRow): Promise<number[]> {
  return (await dynamicGroupsForUser(env, user)).map((g) => g.id);
}

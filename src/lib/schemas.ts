import type { Env } from "../env.js";
import type { GroupRow, UserRow } from "./types.js";

/**
 * Directory schemas.
 *
 * A schema names the attribute vocabulary an object conforms to: which
 * fields the admin UI shows, which the import accepts, and (for types beyond
 * the fixed columns) where values live in the row's `custom_attributes` JSON.
 * Attribute names that match a user/group column map onto that column;
 * anything else is a custom attribute.
 *
 * A bare install ships "Basic" (identity fields only) as the default for each
 * object type, plus "FlareID HR" - the full built-in HR field set - as a
 * provided schema demos can apply.
 *
 * Moving an object to a schema CONFORMS it: attributes the target schema
 * defines keep their values (matched by name, so same-named attributes carry
 * over), and everything else is cleared. The admin UI warns before doing it.
 * Identity fields (names, UPN) are never part of that - every schema has them.
 */

export interface SchemaRow {
  id: number;
  object_type: "user" | "group";
  name: string;
  description: string | null;
  builtin: number;
  is_default: number;
  created_at: string;
}

export interface SchemaAttributeRow {
  id: number;
  schema_id: number;
  name: string;
  label: string;
  type: "string" | "number" | "date" | "boolean" | "reference";
  required: number;
  ref_object: string | null;
  position: number;
}

/** User columns a schema attribute can name to map onto the fixed field. */
export const USER_COLUMN_ATTRIBUTES = new Set([
  "display_name",
  "given_name",
  "family_name",
  "job_title",
  "department",
  "employee_number",
  "hire_date",
  "employment_status",
  "employment_type",
  "location",
]);

/** Attribute name -> user column, where the names differ. */
const USER_ATTR_TO_COLUMN: Record<string, keyof UserRow> = {
  manager: "manager_external_id",
};

/**
 * Columns a schema governs - cleared when the user conforms to a schema that
 * doesn't define them. Identity columns are deliberately absent.
 */
const SCHEMA_GOVERNED_COLUMNS: Record<string, string> = {
  job_title: "job_title",
  department: "department",
  employee_number: "employee_number",
  hire_date: "hire_date",
  employment_status: "employment_status",
  employment_type: "employment_type",
  location: "location",
  manager: "manager_external_id",
};

export async function listSchemas(env: Env, objectType?: "user" | "group"): Promise<SchemaRow[]> {
  const { results } = objectType
    ? await env.DB.prepare("SELECT * FROM schemas WHERE object_type = ? ORDER BY name").bind(objectType).all<SchemaRow>()
    : await env.DB.prepare("SELECT * FROM schemas ORDER BY object_type, name").all<SchemaRow>();
  return results;
}

export async function getSchema(env: Env, id: number): Promise<SchemaRow | null> {
  return env.DB.prepare("SELECT * FROM schemas WHERE id = ?").bind(id).first<SchemaRow>();
}

export async function findSchema(env: Env, objectType: "user" | "group", name: string): Promise<SchemaRow | null> {
  return env.DB.prepare("SELECT * FROM schemas WHERE object_type = ? AND name = ?").bind(objectType, name).first<SchemaRow>();
}

export async function getSchemaAttributes(env: Env, schemaId: number): Promise<SchemaAttributeRow[]> {
  const { results } = await env.DB.prepare("SELECT * FROM schema_attributes WHERE schema_id = ? ORDER BY position, name")
    .bind(schemaId)
    .all<SchemaAttributeRow>();
  return results;
}

/** The default schema for an object type (Basic, out of the box) - what new objects conform to. */
export async function defaultSchemaId(env: Env, objectType: "user" | "group"): Promise<number | null> {
  const row = await env.DB.prepare("SELECT id FROM schemas WHERE object_type = ? AND is_default = 1").bind(objectType).first<{ id: number }>();
  return row?.id ?? null;
}

/**
 * The column and custom-attribute values a user ends up with after conforming
 * to a schema. `values` are the incoming attribute values (from a form or an
 * import); schema-governed columns the schema doesn't define come back as ""
 * (or null for manager), and custom attributes are limited to the schema's.
 */
export function conformUserAttributes(
  attrs: SchemaAttributeRow[],
  values: Record<string, string>
): { columns: Record<string, string | null>; custom: Record<string, string> } {
  const columns: Record<string, string | null> = {};
  for (const column of Object.values(SCHEMA_GOVERNED_COLUMNS)) columns[column] = column === "manager_external_id" ? null : "";
  const split = splitUserAttributes(attrs, values);
  return { columns: { ...columns, ...split.columns }, custom: split.custom };
}

/** Every schema attribute value a user currently holds, keyed by attribute name. */
export function currentUserAttributeValues(user: UserRow, attrs: SchemaAttributeRow[]): Record<string, string> {
  return Object.fromEntries(attrs.map((a) => [a.name, userAttributeValue(user, a)]));
}

/** Names of attributes a user would lose by moving to `target` - values present now, undefined there. */
export function attributesLostOnMove(user: UserRow, target: SchemaAttributeRow[]): string[] {
  const kept = new Set(target.map((a) => a.name));
  const lost: string[] = [];
  for (const [attr, column] of Object.entries(SCHEMA_GOVERNED_COLUMNS)) {
    const value = (user as unknown as Record<string, unknown>)[column];
    if (value && !kept.has(attr)) lost.push(attr);
  }
  for (const [key, value] of Object.entries(parseCustomAttributes(user.custom_attributes))) {
    if (value && !kept.has(key)) lost.push(key);
  }
  return lost;
}

export function parseCustomAttributes(raw: string | null | undefined): Record<string, string> {
  try {
    const parsed = JSON.parse(raw || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, string>) : {};
  } catch {
    return {};
  }
}

/**
 * Resolves an attribute's display value for a user: column-mapped attributes
 * read the column (references resolve the target's name), everything else
 * reads custom_attributes.
 */
export function userAttributeValue(user: UserRow, attr: SchemaAttributeRow): string {
  if (attr.name === "manager" || USER_COLUMN_ATTRIBUTES.has(attr.name)) {
    const column = (USER_ATTR_TO_COLUMN[attr.name] ?? attr.name) as keyof UserRow;
    return String(user[column] ?? "");
  }
  return parseCustomAttributes(user.custom_attributes)[attr.name] ?? "";
}

/** Reads a single named attribute off a user row - column first, then custom attributes. Used by claim/attribute mappers. */
export function userNamedAttribute(user: UserRow, name: string): string | undefined {
  if (USER_COLUMN_ATTRIBUTES.has(name)) return String((user as unknown as Record<string, unknown>)[name] ?? "");
  if (name === "manager") return user.manager_external_id ?? "";
  const custom = parseCustomAttributes(user.custom_attributes);
  return custom[name];
}

/** Splits schema attribute form values into column updates and a merged custom_attributes object. */
export function splitUserAttributes(attrs: SchemaAttributeRow[], values: Record<string, string>): { columns: Record<string, string | null>; custom: Record<string, string> } {
  const columns: Record<string, string | null> = {};
  const custom: Record<string, string> = {};
  for (const attr of attrs) {
    const value = values[attr.name] ?? "";
    if (attr.name === "manager") {
      columns.manager_external_id = value || null;
    } else if (USER_COLUMN_ATTRIBUTES.has(attr.name)) {
      columns[attr.name] = value;
    } else if (value) {
      custom[attr.name] = value;
    }
  }
  return { columns, custom };
}

export async function createSchema(env: Env, objectType: "user" | "group", name: string, description: string): Promise<number> {
  const result = await env.DB.prepare("INSERT INTO schemas (object_type, name, description, builtin, created_at) VALUES (?, ?, ?, 0, ?)")
    .bind(objectType, name, description || null, new Date().toISOString())
    .run();
  return Number(result.meta.last_row_id);
}

export async function saveSchemaAttributes(
  env: Env,
  schemaId: number,
  attributes: { name: string; label: string; type: string; required?: boolean; ref_object?: string | null }[]
): Promise<void> {
  await env.DB.prepare("DELETE FROM schema_attributes WHERE schema_id = ?").bind(schemaId).run();
  if (attributes.length === 0) return;
  await env.DB.batch(
    attributes.map((a, i) =>
      env.DB.prepare("INSERT INTO schema_attributes (schema_id, name, label, type, required, ref_object, position) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(schemaId, a.name, a.label || a.name, a.type || "string", a.required ? 1 : 0, a.ref_object ?? null, (i + 1) * 10)
    )
  );
}

/**
 * Conforms every object of the schema's type to it - same-named attributes
 * carry over, the rest are cleared. With `fromSchemaId`, only objects
 * currently on that schema move (used when a schema is deleted).
 */
export async function applySchemaToAll(env: Env, schema: SchemaRow, fromSchemaId?: number): Promise<number> {
  const attrs = await getSchemaAttributes(env, schema.id);
  const now = new Date().toISOString();
  const scope = fromSchemaId === undefined ? "" : " WHERE schema_id = ?";
  const scopeArgs = fromSchemaId === undefined ? [] : [fromSchemaId];

  if (schema.object_type === "group") {
    const { results } = await env.DB.prepare(`SELECT id, custom_attributes FROM groups${scope}`).bind(...scopeArgs).all<{ id: number; custom_attributes: string }>();
    const keep = new Set(attrs.map((a) => a.name));
    if (results.length === 0) return 0;
    await env.DB.batch(
      results.map((g) => {
        const custom = Object.fromEntries(Object.entries(parseCustomAttributes(g.custom_attributes)).filter(([k]) => keep.has(k)));
        return env.DB.prepare("UPDATE groups SET schema_id = ?, custom_attributes = ? WHERE id = ?").bind(schema.id, JSON.stringify(custom), g.id);
      })
    );
    return results.length;
  }

  const { results: users } = await env.DB.prepare(`SELECT * FROM users${scope}`).bind(...scopeArgs).all<UserRow>();
  if (users.length === 0) return 0;
  await env.DB.batch(
    users.map((u) => {
      const { columns, custom } = conformUserAttributes(attrs, currentUserAttributeValues(u, attrs));
      return env.DB.prepare(
        `UPDATE users SET schema_id = ?, job_title = ?, department = ?, employee_number = ?, hire_date = ?, employment_status = ?,
           employment_type = ?, location = ?, manager_external_id = ?, custom_attributes = ?, updated_at = ? WHERE id = ?`
      ).bind(
        schema.id,
        columns.job_title ?? "",
        columns.department ?? "",
        columns.employee_number ?? "",
        columns.hire_date ?? "",
        columns.employment_status ?? "",
        columns.employment_type ?? "",
        columns.location ?? "",
        columns.manager_external_id ?? null,
        JSON.stringify(custom),
        now,
        u.id
      );
    })
  );
  return users.length;
}

export async function countConforming(env: Env, schemaId: number, objectType: "user" | "group"): Promise<number> {
  const table = objectType === "user" ? "users" : "groups";
  const row = await env.DB.prepare(`SELECT COUNT(*) as n FROM ${table} WHERE schema_id = ?`).bind(schemaId).first<{ n: number }>();
  return row?.n ?? 0;
}

/** Renders one schema attribute's input control. Group schemas only ever use string/number/date/boolean. */
export function attributeInput(attr: SchemaAttributeRow, value: string, userOptions?: { external_id: string; label: string }[]): string {
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const name = `attr_${attr.name}`;
  if (attr.type === "boolean") {
    return `<label><input type="checkbox" name="${esc(name)}" value="1" ${value === "1" || value === "true" ? "checked" : ""} style="width:auto; display:inline; margin-right:6px;" /> ${esc(attr.label)}</label>`;
  }
  if (attr.type === "reference" && userOptions) {
    return `<label for="${esc(name)}">${esc(attr.label)}</label>
      <select id="${esc(name)}" name="${esc(name)}">
        <option value=""></option>
        ${userOptions.map((u) => `<option value="${esc(u.external_id)}" ${u.external_id === value ? "selected" : ""}>${esc(u.label)}</option>`).join("")}
      </select>`;
  }
  const type = attr.type === "number" ? "number" : attr.type === "date" ? "date" : "text";
  return `<label for="${esc(name)}">${esc(attr.label)}</label>
    <input type="${type}" id="${esc(name)}" name="${esc(name)}" value="${esc(value)}" />`;
}

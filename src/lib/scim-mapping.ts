import type { Env } from "../env.js";
import { getUserByExternalId } from "./db.js";
import type { UserEmailInput } from "./user-emails.js";

/**
 * Inbound attribute mapping. When an upstream provisioner (an HR system, or
 * an IdP whose outbound SCIM dialect differs) writes users over the SCIM
 * server API, each enabled scim_mappings row overrides one FlareID field with
 * an expression evaluated over the incoming SCIM body. Fields with no mapping
 * keep the standard attribute mapping.
 *
 * Expressions:
 *   name.givenName                                attribute paths
 *   emails[type eq "work"].value                  multi-valued with a filter
 *   urn:ietf:...:enterprise:2.0:User:department   extension attributes
 *   lower(name.givenName + "." + name.familyName) + concatenation
 *   join(" ", name.givenName, name.familyName)    functions:
 *     lower upper trim concat join coalesce first split eq ne if
 *   "literal", 42, true, false, null
 */

export class ScimMappingError extends Error {}

export interface ScimMapping {
  id: number;
  resource: string;
  target: string;
  expression: string;
  position: number;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Expression language
// ---------------------------------------------------------------------------

type FilterOp = "eq" | "ne" | "co" | "sw" | "ew" | "pr";

interface PathSeg {
  attr: string;
  filter?: { attr: string; op: FilterOp; value?: unknown };
}

export type ScimExpr =
  | { kind: "lit"; value: string | number | boolean | null }
  | { kind: "path"; segs: PathSeg[] }
  | { kind: "call"; name: string; args: ScimExpr[] }
  | { kind: "cat"; parts: ScimExpr[] };

type Token = { t: "str" | "num" | "id"; v: string } | { t: "(" | ")" | "[" | "]" | "," | "+" | "." };

const IDENT_START = /[A-Za-z_$]/;
const IDENT_CHAR = /[A-Za-z0-9_:\-$]/;
const PUNCT = new Set(["(", ")", "[", "]", ",", "+", "."]);

function tokenize(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '"' || ch === "'") {
      let v = "";
      i++;
      while (i < src.length && src[i] !== ch) {
        if (src[i] === "\\" && i + 1 < src.length) { v += src[i + 1]; i += 2; continue; }
        v += src[i++];
      }
      if (i >= src.length) throw new ScimMappingError("Unterminated string literal.");
      i++;
      out.push({ t: "str", v });
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === "-" && i + 1 < src.length && /[0-9]/.test(src[i + 1]!))) {
      const m = /^-?\d+(\.\d+)?/.exec(src.slice(i))!;
      out.push({ t: "num", v: m[0] });
      i += m[0].length;
      continue;
    }
    if (IDENT_START.test(ch)) {
      let v = "";
      while (i < src.length && IDENT_CHAR.test(src[i]!)) v += src[i++];
      // A urn: attribute's version fragment (enterprise:2.0:User) keeps
      // reading past dots followed by digits; a dot before a letter stays a
      // path separator (manager.value).
      while (v.startsWith("urn:") && src[i] === "." && i + 1 < src.length && /[0-9]/.test(src[i + 1]!)) {
        v += src[i++];
        while (i < src.length && IDENT_CHAR.test(src[i]!)) v += src[i++];
      }
      out.push({ t: "id", v });
      continue;
    }
    if (PUNCT.has(ch)) { out.push({ t: ch } as Token); i++; continue; }
    throw new ScimMappingError(`Unexpected character "${ch}" in expression.`);
  }
  return out;
}

/** Parse an expression; throws ScimMappingError on malformed input. */
export function parseExpression(src: string): ScimExpr {
  const toks = tokenize(src);
  let pos = 0;
  const peek = () => toks[pos];
  const take = () => toks[pos++];
  const expect = (t: string) => {
    if (peek()?.t !== t) throw new ScimMappingError(`Expected "${t}" but found ${peek() ? JSON.stringify(peek()!.t === "id" || peek()!.t === "str" || peek()!.t === "num" ? (peek() as { v: string }).v : peek()!.t) : "end of expression"}.`);
    return take();
  };

  function parseExpr(): ScimExpr {
    const parts = [parseTerm()];
    while (peek()?.t === "+") { take(); parts.push(parseTerm()); }
    return parts.length === 1 ? parts[0]! : { kind: "cat", parts };
  }

  function parseTerm(): ScimExpr {
    const tok = peek();
    if (!tok) throw new ScimMappingError("Unexpected end of expression.");
    if (tok.t === "str") { take(); return { kind: "lit", value: tok.v! }; }
    if (tok.t === "num") { take(); return { kind: "lit", value: Number(tok.v) }; }
    if (tok.t === "(") { take(); const e = parseExpr(); expect(")"); return e; }
    if (tok.t === "id") {
      if (tok.v === "true") { take(); return { kind: "lit", value: true }; }
      if (tok.v === "false") { take(); return { kind: "lit", value: false }; }
      if (tok.v === "null") { take(); return { kind: "lit", value: null }; }
      const next = toks[pos + 1];
      if (next?.t === "(") {
        take(); take();
        const args: ScimExpr[] = [];
        if (peek()?.t !== ")") {
          args.push(parseExpr());
          while (peek()?.t === ",") { take(); args.push(parseExpr()); }
        }
        expect(")");
        return { kind: "call", name: tok.v!, args };
      }
      return parsePath();
    }
    throw new ScimMappingError(`Unexpected token "${"v" in tok ? tok.v : tok.t}".`);
  }

  function parsePath(): ScimExpr {
    const segs: PathSeg[] = [];
    for (;;) {
      const tok = take();
      if (tok?.t !== "id") throw new ScimMappingError("Expected an attribute name in path.");
      const seg: PathSeg = { attr: tok.v! };
      if (peek()?.t === "[") {
        take();
        const a = take();
        if (a?.t !== "id") throw new ScimMappingError("Expected an attribute name in filter.");
        const opTok = take();
        if (opTok?.t !== "id" || !["eq", "ne", "co", "sw", "ew", "pr"].includes(opTok.v!))
          throw new ScimMappingError("Expected a filter operator (eq, ne, co, sw, ew, pr).");
        const filter: PathSeg["filter"] = { attr: a.v!, op: opTok.v! as FilterOp };
        if (filter.op !== "pr") {
          const v = take();
          if (!v || (v.t !== "str" && v.t !== "num" && v.t !== "id")) throw new ScimMappingError("Expected a value in filter.");
          filter.value = v.t === "num" ? Number(v.v) : v.t === "str" ? v.v : v.v === "true" ? true : v.v === "false" ? false : v.v;
        }
        seg.filter = filter;
        expect("]");
      }
      segs.push(seg);
      if (peek()?.t === ".") { take(); continue; }
      break;
    }
    return { kind: "path", segs };
  }

  const expr = parseExpr();
  if (pos < toks.length) throw new ScimMappingError(`Unexpected trailing input in expression.`);
  return expr;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Read `attr` off `obj`; URN-style attrs fall back to a schema-prefixed lookup. */
function getAttr(obj: unknown, attr: string): unknown {
  if (!isObj(obj)) return undefined;
  if (attr in obj) return obj[attr];
  // "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department" is
  // the object key "urn:...:User" holding {"department": ...}. Try the longest
  // schema prefix first.
  for (let i = attr.lastIndexOf(":"); i > 0; i = attr.lastIndexOf(":", i - 1)) {
    const prefix = attr.slice(0, i);
    if (prefix in obj) {
      const rest = attr.slice(i + 1);
      return rest === "" ? obj[prefix] : getAttr(obj[prefix], rest);
    }
  }
  return undefined;
}

function strOf(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.map(strOf).join("");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function scalar(v: unknown): unknown {
  return Array.isArray(v) ? (v[0] ?? null) : v;
}

export function truthy(v: unknown): boolean {
  const s = scalar(v);
  if (typeof s === "boolean") return s;
  if (typeof s === "number") return s !== 0;
  if (s === null || s === undefined) return false;
  return !/^\s*(|false|0|no|disabled)\s*$/i.test(String(s));
}

function cmpScalar(v: unknown, w: unknown): boolean {
  if (typeof v === "string" || typeof w === "string") return String(v ?? "").toLowerCase() === String(w ?? "").toLowerCase();
  return v === w;
}

function testFilter(el: unknown, f: NonNullable<PathSeg["filter"]>): boolean {
  const v = getAttr(el, f.attr);
  switch (f.op) {
    case "pr": return v !== undefined && v !== null;
    case "eq": return cmpScalar(scalar(v), f.value);
    case "ne": return !cmpScalar(scalar(v), f.value);
    case "co": return strOf(scalar(v)).toLowerCase().includes(strOf(f.value).toLowerCase());
    case "sw": return strOf(scalar(v)).toLowerCase().startsWith(strOf(f.value).toLowerCase());
    case "ew": return strOf(scalar(v)).toLowerCase().endsWith(strOf(f.value).toLowerCase());
  }
}

function resolvePath(doc: unknown, segs: PathSeg[]): unknown {
  let cur: unknown = doc;
  for (const seg of segs) {
    let v: unknown;
    if (Array.isArray(cur)) {
      const vals = cur.map((el) => getAttr(el, seg.attr)).filter((x) => x !== undefined);
      v = vals.every((x) => !Array.isArray(x)) ? vals : vals.flat();
    } else {
      v = getAttr(cur, seg.attr);
    }
    if (seg.filter) {
      const f = seg.filter;
      const arr = Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
      v = arr.filter((el) => testFilter(el, f));
    }
    cur = v;
  }
  return cur === undefined ? null : cur;
}

const FUNCTIONS: Record<string, (args: unknown[]) => unknown> = {
  lower: ([a]) => strOf(scalar(a)).toLowerCase(),
  upper: ([a]) => strOf(scalar(a)).toUpperCase(),
  trim: ([a]) => strOf(scalar(a)).trim(),
  concat: (args) => args.map(strOf).join(""),
  join: ([sep, ...rest]) => {
    const parts: string[] = [];
    for (const a of rest) for (const el of Array.isArray(a) ? a : [a]) {
      const s = strOf(el);
      if (s !== "") parts.push(s);
    }
    return parts.join(strOf(sep));
  },
  coalesce: (args) => {
    for (const a of args) {
      if (a !== null && a !== undefined && strOf(scalar(a)) !== "") return a;
    }
    return null;
  },
  first: ([a]) => scalar(a),
  split: ([a, sep]) => {
    const s = strOf(scalar(a));
    return s === "" ? [] : s.split(strOf(scalar(sep)));
  },
  eq: ([a, b]) => cmpScalar(scalar(a), scalar(b)),
  ne: ([a, b]) => !cmpScalar(scalar(a), scalar(b)),
  if: ([cond, a, b]) => (truthy(cond) ? a : b),
};

export function evalExpression(expr: ScimExpr, doc: unknown): unknown {
  switch (expr.kind) {
    case "lit": return expr.value;
    case "path": return resolvePath(doc, expr.segs);
    case "cat": return expr.parts.map((p) => strOf(evalExpression(p, doc))).join("");
    case "call": {
      const fn = FUNCTIONS[expr.name.toLowerCase()];
      if (!fn) throw new ScimMappingError(`Unknown function "${expr.name}".`);
      return fn(expr.args.map((a) => evalExpression(a, doc)));
    }
  }
}

// ---------------------------------------------------------------------------
// Mappings
// ---------------------------------------------------------------------------

/** FlareID user fields an expression may feed. `custom.<key>` writes custom_attributes. */
const SCALAR_TARGETS = new Set([
  "display_name", "given_name", "family_name", "job_title", "department",
  "employee_number", "hire_date", "employment_status", "employment_type", "location",
]);
const SPECIAL_TARGETS = new Set(["upn", "active", "manager", "emails"]);
const CUSTOM_TARGET = /^custom\.[A-Za-z][\w-]*$/;

export function isValidMappingTarget(resource: string, target: string): boolean {
  if (resource !== "user") return false;
  return SCALAR_TARGETS.has(target) || SPECIAL_TARGETS.has(target) || CUSTOM_TARGET.test(target);
}

/** The fixed list shown in the console picker, before any custom.* entries. */
export const USER_MAPPING_TARGETS = ["upn", "display_name", "given_name", "family_name", "job_title", "department", "employee_number", "hire_date", "employment_status", "employment_type", "location", "active", "manager", "emails"];

export async function listScimMappings(env: Env, resource = "user", enabledOnly = false): Promise<ScimMapping[]> {
  const { results } = await env.DB.prepare(
    `SELECT id, resource, target, expression, position, enabled FROM scim_mappings WHERE resource = ?${enabledOnly ? " AND enabled = 1" : ""} ORDER BY position, id`
  ).bind(resource).all<Omit<ScimMapping, "enabled"> & { enabled: number }>();
  return results.map((r) => ({ ...r, enabled: r.enabled === 1 }));
}

export interface ScimMappingInput {
  target: string;
  expression: string;
  enabled?: boolean;
}

/** Validates every row, then replaces the resource's whole set. */
export async function replaceScimMappings(env: Env, resource: string, rows: ScimMappingInput[]): Promise<void> {
  const seen = new Set<string>();
  const clean: { target: string; expression: string; enabled: number }[] = [];
  for (const row of rows) {
    const target = String(row.target ?? "").trim();
    const expression = String(row.expression ?? "").trim();
    if (!target || !expression) throw new ScimMappingError("Every mapping needs a target field and an expression.");
    if (!isValidMappingTarget(resource, target)) throw new ScimMappingError(`"${target}" is not a field a user mapping can feed.`);
    if (seen.has(target)) throw new ScimMappingError(`"${target}" is mapped more than once.`);
    seen.add(target);
    parseExpression(expression);
    clean.push({ target, expression, enabled: row.enabled === false ? 0 : 1 });
  }
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM scim_mappings WHERE resource = ?").bind(resource),
    ...clean.map((r, i) =>
      env.DB.prepare("INSERT INTO scim_mappings (resource, target, expression, position, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(resource, r.target, r.expression, i, r.enabled, now, now)
    ),
  ]);
}

export interface MappedUser {
  /** Set when a 'upn' mapping produced a value (create path only). */
  userName?: string;
  cols: Record<string, string | null>;
  emails?: UserEmailInput[];
  /** custom_attributes changes; null deletes the key. */
  custom?: Record<string, string | null>;
}

function coerceEmails(v: unknown): UserEmailInput[] {
  const list = Array.isArray(v) ? v : v === null || v === undefined ? [] : [v];
  const out: UserEmailInput[] = [];
  for (const el of list) {
    if (typeof el === "object" && el !== null) {
      const o = el as { value?: unknown; type?: unknown; primary?: unknown };
      const value = strOf(o.value).trim();
      if (value) out.push({ value, type: strOf(o.type) || "work", primary: o.primary === true || String(o.primary).toLowerCase() === "true" });
    } else {
      const value = strOf(el).trim();
      if (value) out.push({ value, primary: out.length === 0 });
    }
  }
  if (out.length && !out.some((e) => e.primary)) out[0]!.primary = true;
  return out;
}

/**
 * Evaluates the enabled user mappings over `doc` (the incoming body, or for
 * PATCH the body merged onto the current resource). `partial` is PATCH
 * semantics: an expression yielding nothing leaves the field alone. On a full
 * write (POST/PUT) nothing yields an empty/cleared field instead.
 */
export async function applyUserMappings(env: Env, doc: unknown, opts: { partial: boolean }): Promise<MappedUser> {
  const mappings = await listScimMappings(env, "user", true);
  const out: MappedUser = { cols: {} };
  for (const m of mappings) {
    let value: unknown;
    try {
      value = evalExpression(parseExpression(m.expression), doc);
    } catch (e) {
      throw new ScimMappingError(`The mapping for ${m.target} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    const absent = value === null || value === undefined;
    if (m.target === "upn") {
      const s = strOf(scalar(value)).trim();
      if (s) out.userName = s;
    } else if (m.target === "active") {
      if (!absent) out.cols.status = truthy(value) ? "active" : "disabled";
    } else if (m.target === "manager") {
      const s = strOf(scalar(value)).trim();
      if (absent || s === "") {
        if (!opts.partial) out.cols.manager_external_id = null;
      } else {
        out.cols.manager_external_id = (await getUserByExternalId(env, s))?.external_id ?? null;
      }
    } else if (m.target === "emails") {
      if (absent) {
        if (!opts.partial) out.emails = [];
      } else {
        out.emails = coerceEmails(value);
      }
    } else if (m.target.startsWith("custom.")) {
      const key = m.target.slice(7);
      if (absent) {
        if (!opts.partial) (out.custom ??= {})[key] = null;
      } else {
        (out.custom ??= {})[key] = strOf(scalar(value));
      }
    } else {
      // Plain text column; the users table stores "" rather than NULL.
      if (absent) {
        if (!opts.partial) out.cols[m.target] = "";
      } else {
        out.cols[m.target] = strOf(scalar(value));
      }
    }
  }
  return out;
}

/** Merges patch keys onto a base SCIM resource: objects merge, arrays and scalars replace. */
export function mergeScimBody(base: unknown, patch: unknown): unknown {
  if (isObj(base) && isObj(patch)) {
    const merged: Record<string, unknown> = { ...base };
    for (const [k, v] of Object.entries(patch)) merged[k] = mergeScimBody(base[k], v);
    return merged;
  }
  return patch === undefined ? base : patch;
}

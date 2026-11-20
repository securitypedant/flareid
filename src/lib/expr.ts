/**
 * The FlareID expression language: a small, total function set evaluated over
 * a JSON document. Every attribute flow uses it - inbound SCIM and JIT writes
 * map a source document onto user fields, outbound SAML / OIDC / SCIM rows map
 * the user document onto external attributes and claims, and dynamic-group
 * rules use it as a match predicate.
 *
 * Expressions:
 *   name.givenName                                attribute paths
 *   emails[type eq "work"].value                  multi-valued with a filter
 *   urn:ietf:...:enterprise:2.0:User:department   extension attributes
 *   attr("http://schemas.../claims/emailaddress") arbitrary attribute names
 *   lower(name.givenName + "." + name.familyName) + concatenation
 *   join(" ", name.givenName, name.familyName)    functions, see FUNCTIONS
 *   "literal", 42, true, false, null
 *
 * Everything is synchronous, allocation-bounded and O(document size): no I/O,
 * no regex compilation beyond literal patterns the admin supplied, so mapping
 * evaluation stays cheap on the sign-in and sync hot paths.
 */

export class ExprError extends Error {}

export type ScimExpr =
  | { kind: "lit"; value: string | number | boolean | null }
  | { kind: "path"; segs: PathSeg[] }
  | { kind: "call"; name: string; args: ScimExpr[] }
  | { kind: "cat"; parts: ScimExpr[] };

type FilterOp = "eq" | "ne" | "co" | "sw" | "ew" | "pr";

interface PathSeg {
  attr: string;
  filter?: { attr: string; op: FilterOp; value?: unknown };
}

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
      if (i >= src.length) throw new ExprError("Unterminated string literal.");
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
    throw new ExprError(`Unexpected character "${ch}" in expression.`);
  }
  return out;
}

/** Parse an expression; throws ExprError on malformed input. */
export function parseExpression(src: string): ScimExpr {
  const toks = tokenize(src);
  let pos = 0;
  const peek = () => toks[pos];
  const take = () => toks[pos++];
  const expect = (t: string) => {
    if (peek()?.t !== t) throw new ExprError(`Expected "${t}" but found ${peek() ? JSON.stringify(peek()!.t === "id" || peek()!.t === "str" || peek()!.t === "num" ? (peek() as { v: string }).v : peek()!.t) : "end of expression"}.`);
    return take();
  };

  function parseExpr(): ScimExpr {
    const parts = [parseTerm()];
    while (peek()?.t === "+") { take(); parts.push(parseTerm()); }
    return parts.length === 1 ? parts[0]! : { kind: "cat", parts };
  }

  function parseTerm(): ScimExpr {
    const tok = peek();
    if (!tok) throw new ExprError("Unexpected end of expression.");
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
    throw new ExprError(`Unexpected token "${"v" in tok ? tok.v : tok.t}".`);
  }

  function parsePath(): ScimExpr {
    const segs: PathSeg[] = [];
    for (;;) {
      const tok = take();
      if (tok?.t !== "id") throw new ExprError("Expected an attribute name in path.");
      const seg: PathSeg = { attr: tok.v! };
      if (peek()?.t === "[") {
        take();
        const a = take();
        if (a?.t !== "id") throw new ExprError("Expected an attribute name in filter.");
        const opTok = take();
        if (opTok?.t !== "id" || !["eq", "ne", "co", "sw", "ew", "pr"].includes(opTok.v!))
          throw new ExprError("Expected a filter operator (eq, ne, co, sw, ew, pr).");
        const filter: PathSeg["filter"] = { attr: a.v!, op: opTok.v! as FilterOp };
        if (filter.op !== "pr") {
          const v = take();
          if (!v || (v.t !== "str" && v.t !== "num" && v.t !== "id")) throw new ExprError("Expected a value in filter.");
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
  if (pos < toks.length) throw new ExprError(`Unexpected trailing input in expression.`);
  return expr;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export function isObj(v: unknown): v is Record<string, unknown> {
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

export function strOf(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.map(strOf).join("");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

export function scalar(v: unknown): unknown {
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

function numOf(v: unknown): number {
  const n = typeof v === "number" ? v : Number(strOf(scalar(v)));
  return Number.isFinite(n) ? n : 0;
}

function listOf(v: unknown): unknown[] {
  return Array.isArray(v) ? v : v === null || v === undefined ? [] : [v];
}

/**
 * Ordered, case-insensitive-ish comparison for gt/lt/ge/le: numbers when both
 * sides read as numbers, otherwise locale-free string order (ISO dates sort
 * correctly this way).
 */
function cmp(a: unknown, b: unknown): number {
  const sa = scalar(a), sb = scalar(b);
  if (typeof sa === "number" && typeof sb === "number") return sa - sb;
  const as = strOf(sa), bs = strOf(sb);
  const an = Number(as), bn = Number(bs);
  if (as !== "" && bs !== "" && Number.isFinite(an) && Number.isFinite(bn)) return an - bn;
  return as < bs ? -1 : as > bs ? 1 : 0;
}

export const EXPRESSION_FUNCTIONS = [
  // Selection and literals
  "coalesce", "first", "if", "select", "attr",
  // Strings
  "lower", "upper", "title", "capitalize", "trim", "concat", "join", "split",
  "substr", "left", "right", "replace", "replaceRe", "match",
  "ascii", "alnum", "initials", "word", "localpart", "domainpart", "format",
  // Lists
  "len", "at", "take", "sort", "uniq", "reverse",
  // Logic and comparison
  "eq", "ne", "gt", "lt", "ge", "le", "and", "or", "not", "in",
  "contains", "startsWith", "endsWith",
  // Numbers and time
  "add", "sub", "mul", "div", "mod", "int", "round", "min", "max", "now", "year",
] as const;

const FUNCTIONS: Record<string, (args: unknown[]) => unknown> = {
  // -- Selection ------------------------------------------------------------
  coalesce: (args) => {
    for (const a of args) {
      if (a !== null && a !== undefined && strOf(scalar(a)) !== "") return a;
    }
    return null;
  },
  first: ([a]) => scalar(a),
  if: ([cond, a, b]) => (truthy(cond) ? a : b),
  select: (args) => {
    // select(cond, value, cond, value, ..., default?): the first value whose
    // condition is truthy; a trailing odd argument is the default.
    const pairs = Math.floor(args.length / 2);
    for (let i = 0; i < pairs; i++) {
      if (truthy(args[i * 2])) return args[i * 2 + 1];
    }
    return args.length % 2 === 1 ? args[args.length - 1] : null;
  },

  // -- Strings ---------------------------------------------------------------
  lower: ([a]) => strOf(scalar(a)).toLowerCase(),
  upper: ([a]) => strOf(scalar(a)).toUpperCase(),
  title: ([a]) => strOf(scalar(a)).toLowerCase().replace(/\b\w/g, (ch) => ch.toUpperCase()),
  capitalize: ([a]) => { const s = strOf(scalar(a)); return s ? s[0]!.toUpperCase() + s.slice(1) : s; },
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
  split: ([a, sep]) => {
    const s = strOf(scalar(a));
    return s === "" ? [] : s.split(strOf(scalar(sep)));
  },
  substr: ([a, start, len]) => {
    const s = strOf(scalar(a));
    return len === undefined || len === null ? s.slice(Math.trunc(numOf(start))) : s.slice(Math.trunc(numOf(start)), Math.trunc(numOf(start)) + Math.trunc(numOf(len)));
  },
  left: ([a, n]) => strOf(scalar(a)).slice(0, Math.max(0, Math.trunc(numOf(n)))),
  right: ([a, n]) => { const s = strOf(scalar(a)); return n === undefined ? s : s.slice(Math.max(0, s.length - Math.trunc(numOf(n)))); },
  replace: ([a, find, repl]) => strOf(scalar(a)).split(strOf(scalar(find))).join(strOf(repl)),
  replacere: ([a, pattern, repl]) => {
    try {
      return strOf(scalar(a)).replace(new RegExp(strOf(scalar(pattern)), "g"), strOf(repl));
    } catch {
      return strOf(scalar(a));
    }
  },
  match: ([a, pattern]) => {
    try {
      const m = new RegExp(strOf(scalar(pattern))).exec(strOf(scalar(a)));
      return m ? (m[1] ?? m[0]) : "";
    } catch {
      return "";
    }
  },
  // ASCII fold + strip: "José" -> "jose" then remove combining marks - the
  // pair turns display names into sign-in-name material.
  ascii: ([a]) => strOf(scalar(a)).normalize("NFD").replace(/[\u0300-\u036f]/g, ""),
  alnum: ([a]) => strOf(scalar(a)).replace(/[^A-Za-z0-9]/g, ""),
  initials: ([a]) => strOf(scalar(a)).split(/\s+/).filter(Boolean).map((w) => w[0]).join(""),
  word: ([a, n]) => strOf(scalar(a)).split(/\s+/).filter(Boolean)[Math.trunc(numOf(n))] ?? "",
  localpart: ([a]) => strOf(scalar(a)).split("@")[0] ?? "",
  domainpart: ([a]) => { const s = strOf(scalar(a)); const i = s.lastIndexOf("@"); return i < 0 ? "" : s.slice(i + 1); },
  // Interpolation: format("{0}.{1}", a, b). {{ and }} escape the braces.
  format: ([tpl, ...vals]) =>
    strOf(scalar(tpl))
      .replace(/\{\{|\}\}|\{(\d+)\}/g, (m, idx: string | undefined) => (m === "{{" ? "{" : m === "}}" ? "}" : strOf(vals[Number(idx)]))),

  // -- Lists -----------------------------------------------------------------
  len: ([a]) => (Array.isArray(a) ? a.length : strOf(scalar(a)).length),
  at: ([a, n]) => {
    const list = listOf(a);
    const i = Math.trunc(numOf(n));
    return list[i < 0 ? list.length + i : i] ?? null;
  },
  take: ([a, n]) => listOf(a).slice(0, Math.max(0, Math.trunc(numOf(n)))),
  sort: ([a]) => [...listOf(a)].map(strOf).sort(),
  uniq: ([a]) => {
    const seen = new Set<string>();
    return listOf(a).filter((el) => {
      const k = strOf(scalar(el));
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  },
  reverse: ([a]) => [...listOf(a)].reverse(),

  // -- Logic and comparison ---------------------------------------------------
  eq: ([a, b]) => cmpScalar(scalar(a), scalar(b)),
  ne: ([a, b]) => !cmpScalar(scalar(a), scalar(b)),
  gt: ([a, b]) => cmp(a, b) > 0,
  lt: ([a, b]) => cmp(a, b) < 0,
  ge: ([a, b]) => cmp(a, b) >= 0,
  le: ([a, b]) => cmp(a, b) <= 0,
  and: (args) => args.every(truthy),
  or: (args) => args.some(truthy),
  not: ([a]) => !truthy(a),
  in: ([v, ...vals]) => vals.some((w) => (Array.isArray(w) ? w : [w]).some((x) => cmpScalar(scalar(v), scalar(x)))),
  contains: ([a, b]) =>
    Array.isArray(a) ? a.some((x) => cmpScalar(scalar(x), scalar(b))) : strOf(scalar(a)).toLowerCase().includes(strOf(scalar(b)).toLowerCase()),
  startswith: ([a, b]) => strOf(scalar(a)).toLowerCase().startsWith(strOf(scalar(b)).toLowerCase()),
  endswith: ([a, b]) => strOf(scalar(a)).toLowerCase().endsWith(strOf(scalar(b)).toLowerCase()),

  // -- Numbers and time --------------------------------------------------------
  add: (args) => args.reduce<number>((n, a) => n + numOf(a), 0),
  sub: ([a, b]) => numOf(a) - numOf(b ?? 0),
  mul: (args) => args.reduce<number>((n, a) => n * numOf(a), 1),
  div: ([a, b]) => { const d = numOf(b); return d === 0 ? null : numOf(a) / d; },
  mod: ([a, b]) => { const d = numOf(b); return d === 0 ? null : numOf(a) % d; },
  int: ([a]) => Math.trunc(numOf(a)),
  round: ([a, d]) => { const p = 10 ** Math.trunc(numOf(d ?? 0)); return Math.round(numOf(a) * p) / p; },
  min: (args) => (args.length ? Math.min(...args.map(numOf)) : null),
  max: (args) => (args.length ? Math.max(...args.map(numOf)) : null),
  now: () => new Date().toISOString(),
  year: ([a]) => { const m = /(\d{4})/.exec(strOf(scalar(a))); return m ? Number(m[1]) : null; },
};

export function evalExpression(expr: ScimExpr, doc: unknown): unknown {
  switch (expr.kind) {
    case "lit": return expr.value;
    case "path": return resolvePath(doc, expr.segs);
    case "cat": return expr.parts.map((p) => strOf(evalExpression(p, doc))).join("");
    case "call": {
      // attr("name") escapes the grammar: attribute names the tokenizer can't
      // carry (WS-Federation claim URIs, names with spaces) resolve literally.
      if (expr.name.toLowerCase() === "attr") {
        const name = expr.args[0] ? strOf(scalar(evalExpression(expr.args[0], doc))) : "";
        return name ? getAttr(doc, name) ?? null : null;
      }
      const fn = FUNCTIONS[expr.name.toLowerCase()];
      if (!fn) throw new ExprError(`Unknown function "${expr.name}".`);
      return fn(expr.args.map((a) => evalExpression(a, doc)));
    }
  }
}

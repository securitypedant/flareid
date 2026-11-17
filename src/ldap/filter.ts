import { BerError, BerReader, ctx } from "./ber.js";
import { dnEquals, normalizeValue, parseDn } from "./dn.js";
import { OID } from "./protocol.js";

/**
 * Filter AST and evaluation, RFC 4511 4.5.1.7 and RFC 4515 (LDAP.md section
 * 10). Three-valued logic: an unknown attribute, an inappropriate matching
 * rule or a malformed assertion is Undefined, and Undefined is never TRUE.
 * Limits: depth 32, 256 nodes, 4 KiB assertions.
 */

export const MAX_FILTER_DEPTH = 32;
export const MAX_FILTER_NODES = 256;
export const MAX_ASSERTION_BYTES = 4096;

export type Filter =
  | { kind: "and" | "or"; items: Filter[] }
  | { kind: "not"; item: Filter }
  | { kind: "eq" | "ge" | "le" | "approx"; attr: string; value: Uint8Array }
  | { kind: "sub"; attr: string; initial: Uint8Array | null; any: Uint8Array[]; final: Uint8Array | null }
  | { kind: "present"; attr: string }
  | { kind: "ext"; type: string | null; rule: string | null; value: Uint8Array; dnAttributes: boolean };

const FILTER_TAGS = { and: 0xa0, or: 0xa1, not: 0xa2, eq: 0xa3, sub: 0xa4, ge: 0xa5, le: 0xa6, present: 0x87, approx: 0xa8, ext: 0xa9 };

export function parseFilter(raw: Uint8Array, depth = 0, budget = { nodes: MAX_FILTER_NODES }): Filter {
  if (depth > MAX_FILTER_DEPTH) throw new BerError("filter nesting too deep");
  if (--budget.nodes < 0) throw new BerError("filter has too many nodes");
  const el = new BerReader(raw).readElement();
  if (el.tag === FILTER_TAGS.present) {
    const attr = decodeText(el.content);
    return { kind: "present", attr };
  }
  const r = new BerReader(el.content);
  switch (el.tag) {
    case FILTER_TAGS.and:
    case FILTER_TAGS.or: {
      const items: Filter[] = [];
      while (!r.atEnd()) items.push(parseFilter(readChildTlv(r), depth + 1, budget));
      return { kind: el.tag === FILTER_TAGS.and ? "and" : "or", items };
    }
    case FILTER_TAGS.not:
      return { kind: "not", item: parseFilter(readChildTlv(r), depth + 1, budget) };
    case FILTER_TAGS.eq:
    case FILTER_TAGS.ge:
    case FILTER_TAGS.le:
    case FILTER_TAGS.approx: {
      const attr = r.readString();
      const value = r.readOctetString();
      if (value.length > MAX_ASSERTION_BYTES) throw new BerError("assertion too large");
      return { kind: el.tag === FILTER_TAGS.eq ? "eq" : el.tag === FILTER_TAGS.ge ? "ge" : el.tag === FILTER_TAGS.le ? "le" : "approx", attr, value };
    }
    case FILTER_TAGS.sub: {
      const attr = r.readString();
      const subs = r.readConstructed(0x30);
      let initial: Uint8Array | null = null;
      const any: Uint8Array[] = [];
      let fin: Uint8Array | null = null;
      while (!subs.atEnd()) {
        const p = subs.readElement();
        if (p.content.length > MAX_ASSERTION_BYTES) throw new BerError("substring assertion too large");
        if (p.tag === ctx(0)) initial = p.content;
        else if (p.tag === ctx(1)) any.push(p.content);
        else if (p.tag === ctx(2)) fin = p.content;
        else throw new BerError("bad substring component");
      }
      if (initial === null && any.length === 0 && fin === null) throw new BerError("empty substring filter");
      return { kind: "sub", attr, initial, any, final: fin };
    }
    case FILTER_TAGS.ext: {
      let rule: string | null = null;
      let type: string | null = null;
      let value: Uint8Array | null = null;
      let dnAttributes = false;
      while (!r.atEnd()) {
        const f = r.readElement();
        if (f.tag === ctx(1)) rule = decodeOid(f.content);
        else if (f.tag === ctx(2)) type = decodeText(f.content);
        else if (f.tag === ctx(3)) {
          value = f.content;
          if (value.length > MAX_ASSERTION_BYTES) throw new BerError("assertion too large");
        } else if (f.tag === ctx(4)) dnAttributes = f.content[0] !== 0;
      }
      return { kind: "ext", type, rule, value: value ?? new Uint8Array(0), dnAttributes };
    }
    default:
      throw new BerError(`unknown filter tag 0x${el.tag.toString(16)}`);
  }
}

function readChildTlv(r: BerReader): Uint8Array {
  // Re-wrap the next element as a complete TLV for the recursive call.
  const el = r.readElement();
  const len = el.content.length;
  const hdr = len < 0x80 ? [len] : [0x80 | byteCount(len), ...lenBytes(len)];
  return concat3(new Uint8Array([el.tag]), new Uint8Array(hdr), el.content);
}

function byteCount(n: number): number {
  let c = 0;
  for (let v = n; v > 0; v >>>= 8) c++;
  return c;
}
function lenBytes(n: number): number[] {
  const out: number[] = [];
  for (let v = n; v > 0; v >>>= 8) out.unshift(v & 0xff);
  return out;
}
function concat3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}

const td = new TextDecoder();
const decodeText = (b: Uint8Array) => td.decode(b);

/** OID bytes without the TLV wrapper (context-tagged fields carry the bare value). */
function decodeOid(b: Uint8Array): string {
  if (b.length === 0) return "";
  const out: number[] = [Math.floor(b[0]! / 40), b[0]! % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i]! & 0x7f);
    if (!(b[i]! & 0x80)) {
      out.push(v);
      v = 0;
    }
  }
  return out.join(".");
}

// ---- evaluation ----

/** An entry as the evaluator sees it: canonical DN plus lowercased attribute values. */
export interface EvalEntry {
  dn: string;
  attrs: Map<string, (string | Uint8Array)[]>;
}

/** Attributes compared as DNs (RFC 4517 distinguishedNameMatch). */
const DN_ATTRS = new Set(["member", "memberof", "uniquemember", "manager", "distinguishedname", "owner"]);
const INT_ATTRS = new Set(["uidnumber", "gidnumber", "useraccountcontrol", "grouptype", "samaccounttype"]);
const TIME_ATTRS = new Set(["whencreated", "createtimestamp", "modifytimestamp", "whenchanged"]);
const BINARY_ATTRS = new Set(["objectguid", "objectsid"]);

export type Tri = true | false | "undefined";

export function evaluateFilter(f: Filter, entry: EvalEntry): Tri {
  switch (f.kind) {
    case "and":
      if (f.items.length === 0) return true;
      let andResult: Tri = true;
      for (const item of f.items) {
        const r = evaluateFilter(item, entry);
        if (r === false) return false;
        if (r === "undefined") andResult = "undefined";
      }
      return andResult;
    case "or":
      if (f.items.length === 0) return false;
      let orResult: Tri = false;
      for (const item of f.items) {
        const r = evaluateFilter(item, entry);
        if (r === true) return true;
        if (r === "undefined") orResult = "undefined";
      }
      return orResult;
    case "not": {
      const r = evaluateFilter(f.item, entry);
      return r === "undefined" ? "undefined" : !r;
    }
    case "present":
      if (f.attr === "*") return true;
      return (entry.attrs.get(f.attr.toLowerCase())?.length ?? 0) > 0 ? true : false;
    case "eq":
    case "approx":
      return matchEquality(f.attr, f.value, entry);
    case "ge":
    case "le":
      return matchOrdering(f.attr, f.value, entry, f.kind);
    case "sub":
      return matchSubstring(f, entry);
    case "ext":
      return matchExtensible(f, entry);
  }
}

function attrValues(entry: EvalEntry, attr: string): (string | Uint8Array)[] | "undefined" {
  const v = entry.attrs.get(attr.toLowerCase());
  return v === undefined ? "undefined" : v;
}

function matchEquality(attr: string, value: Uint8Array, entry: EvalEntry): Tri {
  const a = attr.toLowerCase();
  const values = attrValues(entry, a);
  if (values === "undefined") return "undefined";
  if (a === "objectclass") {
    const want = decodeText(value).toLowerCase();
    return values.some((v) => typeof v === "string" && v.toLowerCase() === want) ? true : false;
  }
  if (a === "objectcategory") return matchObjectCategory(decodeText(value), entry) ? true : false;
  if (DN_ATTRS.has(a)) {
    const want = safeDn(value);
    if (want === "undefined") return "undefined";
    return values.some((v) => typeof v === "string" && safeDn(new TextEncoder().encode(v)) !== "undefined" && dnEquals(parseDn(v), want as ReturnType<typeof parseDn>)) ? true : false;
  }
  if (INT_ATTRS.has(a)) {
    const want = Number(decodeText(value));
    if (!Number.isFinite(want)) return "undefined";
    return values.some((v) => Number(v) === want) ? true : false;
  }
  if (BINARY_ATTRS.has(a)) {
    return values.some((v) => binaryEquals(v, value)) ? true : false;
  }
  if (TIME_ATTRS.has(a)) {
    const want = decodeText(value).replace(/\.$/, "");
    return values.some((v) => typeof v === "string" && v.replace(/\.$/, "") === want) ? true : false;
  }
  const want = normalizeValue(decodeText(value));
  return values.some((v) => typeof v === "string" && normalizeValue(v) === want) ? true : false;
}

/** AD's objectCategory: full DN, or the short names person/user (Person) and group. */
function matchObjectCategory(want: string, entry: EvalEntry): boolean {
  const w = want.toLowerCase();
  const have = entry.attrs.get("objectcategory") ?? [];
  const short = w === "user" ? "person" : w;
  return have.some((v) => {
    if (typeof v !== "string") return false;
    const hv = v.toLowerCase();
    return hv === w || hv.startsWith(`cn=${short},`);
  });
}

function safeDn(value: Uint8Array): ReturnType<typeof parseDn> | "undefined" {
  try {
    return parseDn(decodeText(value));
  } catch {
    return "undefined";
  }
}

function binaryEquals(have: string | Uint8Array, want: Uint8Array): boolean {
  const hv = typeof have === "string" ? new TextEncoder().encode(have) : have;
  if (eqBytes(hv, want)) return true;
  // The escaped-string form: \33\22\11...  (3 bytes of text per value byte)
  const txt = decodeText(want);
  if (/^(\\[0-9a-fA-F]{2})+$/.test(txt)) {
    const raw = new Uint8Array(txt.length / 3);
    for (let i = 0; i < raw.length; i++) raw[i] = parseInt(txt.slice(i * 3 + 1, i * 3 + 3), 16);
    return eqBytes(hv, raw);
  }
  return false;
}
function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function matchOrdering(attr: string, value: Uint8Array, entry: EvalEntry, dir: "ge" | "le"): Tri {
  const a = attr.toLowerCase();
  const values = attrValues(entry, a);
  if (values === "undefined") return "undefined";
  const cmp = (have: number | string, want: number | string): number => (have < want ? -1 : have > want ? 1 : 0);
  const want = decodeText(value);
  const any = values.some((v) => {
    if (INT_ATTRS.has(a)) {
      const w = Number(want);
      if (!Number.isFinite(w)) return false;
      const c = cmp(Number(v), w);
      return dir === "ge" ? c >= 0 : c <= 0;
    }
    const hv = typeof v === "string" ? v.toLowerCase() : "";
    const c = cmp(hv, want.toLowerCase());
    return dir === "ge" ? c >= 0 : c <= 0;
  });
  return any ? true : false;
}

function matchSubstring(f: Extract<Filter, { kind: "sub" }>, entry: EvalEntry): Tri {
  const values = attrValues(entry, f.attr);
  if (values === "undefined") return "undefined";
  // Substring matching is defined on strings only (caseIgnoreSubstringsMatch).
  const any = values.some((v) => {
    if (typeof v !== "string") return false;
    const hay = v.toLowerCase();
    let at = 0;
    if (f.initial !== null) {
      const init = decodeText(f.initial).toLowerCase();
      if (!hay.startsWith(init)) return false;
      at = init.length;
    }
    for (const part of f.any) {
      const needle = decodeText(part).toLowerCase();
      const found = hay.indexOf(needle, at);
      if (found < 0) return false;
      at = found + needle.length;
    }
    if (f.final !== null) {
      const fin = decodeText(f.final).toLowerCase();
      return hay.endsWith(fin) && hay.length - fin.length >= at;
    }
    return true;
  });
  return any ? true : false;
}

function matchExtensible(f: Extract<Filter, { kind: "ext" }>, entry: EvalEntry): Tri {
  if (f.dnAttributes) return "undefined";
  const rule = (f.rule ?? "").toLowerCase();
  const attr = f.type;
  // AD bitwise rules need an attribute and an integer assertion.
  if (rule === OID.matchBitAnd || rule === OID.matchBitOr) {
    if (!attr) return "undefined";
    const values = attrValues(entry, attr);
    if (values === "undefined") return "undefined";
    const want = Number(decodeText(f.value));
    if (!Number.isFinite(want)) return "undefined";
    const any = values.some((v) => {
      const hv = Number(v);
      if (!Number.isFinite(hv)) return false;
      return rule === OID.matchBitAnd ? (hv & want) === want : (hv & want) !== 0;
    });
    return any ? true : false;
  }
  // In-chain: flat groups make transitive membership equal to direct DN equality.
  if (rule === OID.matchInChain) {
    if (!attr) return "undefined";
    return matchEquality(attr, f.value, entry);
  }
  // Named matching rules on a normal equality: caseIgnoreMatch / caseExactMatch.
  if (rule === "caseignorematch" || rule === "caseexactmatch") {
    if (!attr) return "undefined";
    if (rule === "caseignorematch") return matchEquality(attr, f.value, entry);
    const values = attrValues(entry, attr);
    if (values === "undefined") return "undefined";
    const want = decodeText(f.value);
    return values.some((v) => v === want) ? true : false;
  }
  // A bare extensibleMatch without a rule defaults to equality semantics.
  if (!rule && attr) return matchEquality(attr, f.value, entry);
  return "undefined";
}

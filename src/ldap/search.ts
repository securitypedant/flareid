import type { Env } from "../env.js";
import type { GroupRow, LdapAppRow, UserRow } from "../lib/types.js";
import { BerError } from "./ber.js";
import { dnEquals, dnWithin, formatDn, parseDn, type Rdn } from "./dn.js";
import { parseFilter, evaluateFilter, type EvalEntry, type Filter } from "./filter.js";
import { RC, type Operation } from "./protocol.js";
import type { DirectoryView } from "./directory.js";
import { APP_BRANCH_DN, GROUP_RDN, USER_RDN, containerEntries, groupEntry, rootDse, subschemaEntry, userEntry, isReturnable } from "./entries.js";
import type { LdapSettings } from "./settings.js";

/**
 * Search evaluation (LDAP.md section 10): authorisation by bound identity,
 * branch confinement, three-valued filter logic, attribute selection, size
 * limits and Simple Paged Results.
 */

export interface SearchCtx {
  env: Env;
  settings: LdapSettings;
  /** Null only for anonymous binds, which never get past the root DSE check. */
  app: LdapAppRow | null;
  view: DirectoryView;
  /** What the connection is bound as - decides what the search may see. */
  bound: { kind: "anonymous" } | { kind: "service"; app: LdapAppRow } | { kind: "user"; user: UserRow; app: LdapAppRow | null };
}

export interface SearchOutcome {
  code: number;
  matchedDn: string;
  diagnostic: string;
  /** Entries with attributes already selected/filtered. */
  entries: EvalEntry[];
  /** Entries count before the size limit was applied. */
  total: number;
  typesOnly: boolean;
}

type SearchOp = Extract<Operation, { kind: "search" }>;

const SERVER_SIZE_LIMIT = 1000; // AD's MaxPageSize

/** Depth of a DN in RDNs. */
const depth = (rdns: Rdn[]) => rdns.length;

export async function executeSearch(ctx: SearchCtx, op: SearchOp): Promise<SearchOutcome> {
  const { settings } = ctx;
  const baseDn = settings.baseDn;
  let filter: Filter;
  try {
    filter = parseFilter(op.filterRaw);
  } catch (e) {
    return { code: RC.unwillingToPerform, matchedDn: "", diagnostic: e instanceof BerError ? `bad filter: ${e.message}` : "bad filter", entries: [], total: 0, typesOnly: op.typesOnly };
  }
  if (op.attributes.length > 100) return { code: RC.unwillingToPerform, matchedDn: "", diagnostic: "too many requested attributes", entries: [], total: 0, typesOnly: op.typesOnly };

  let baseRdns: Rdn[];
  try {
    baseRdns = parseDn(op.base);
  } catch {
    return { code: RC.invalidDNSyntax, matchedDn: "", diagnostic: "invalid base DN", entries: [], total: 0, typesOnly: op.typesOnly };
  }

  // The root DSE and the subschema are readable in every bind state - clients
  // (e.g. Directory Studio) fetch both after binding to discover the schema.
  if (baseRdns.length === 0 && op.scope !== 1) return { code: RC.success, matchedDn: "", diagnostic: "", entries: [select(rootDse(settings), op)], total: 1, typesOnly: op.typesOnly };
  if (baseRdns.length === 1 && baseRdns[0]!.type === "cn" && baseRdns[0]!.value.toLowerCase() === "subschema") {
    return { code: RC.success, matchedDn: "", diagnostic: "", entries: [select(subschemaEntry(), op)], total: 1, typesOnly: op.typesOnly };
  }
  // Anonymous connections read nothing else.
  if (ctx.bound.kind === "anonymous") {
    return { code: RC.insufficientAccessRights, matchedDn: "", diagnostic: "anonymous searches read the root DSE only", entries: [], total: 0, typesOnly: op.typesOnly };
  }
  if (!ctx.app) return { code: RC.insufficientAccessRights, matchedDn: "", diagnostic: "no app context", entries: [], total: 0, typesOnly: op.typesOnly };
  const app = ctx.app;

  // Resolve the base inside our tree.
  const baseDepth = settings.base.length;
  const baseInTree = baseRdns.length >= baseDepth && dnEquals(baseRdns.slice(baseRdns.length - baseDepth), settings.base);
  if (!baseInTree) {
    // Base outside our naming context (or a malformed tree DN): refuse with
    // the deepest ancestor that exists.
    const matched = deepestAncestor(baseRdns, settings);
    return { code: RC.noSuchObject, matchedDn: matched, diagnostic: "no such object", entries: [], total: 0, typesOnly: op.typesOnly };
  }
  const aboveBase = baseRdns.slice(0, baseRdns.length - baseDepth); // leading RDNs above the naming context
  // A base outside this app's branch is invisible, not forbidden. The app
  // branch is the RDN directly above the naming context: ou=<slug>,<base>.
  if (aboveBase.length > 0) {
    const parent = aboveBase[aboveBase.length - 1]!;
    if (parent.type !== "ou" || parent.value.toLowerCase() !== app.slug) {
      return { code: RC.noSuchObject, matchedDn: "", diagnostic: "", entries: [], total: 0, typesOnly: op.typesOnly };
    }
  }

  // Collect candidate entries for the scope. `rel` counts RDNs between a
  // candidate's DN and the requested base (0 = the base itself).
  const containers = containerEntries(app, settings);
  const candidates: { dn: string; rdns: Rdn[]; build: () => Promise<EvalEntry> }[] = [];
  for (const c of containers) {
    const rdns = parseDn(c.dn);
    candidates.push({ dn: c.dn, rdns, build: async () => c });
  }
  for (const u of ctx.view.users) {
    const rdns = parseDn(USER_RDN(u.username, app.slug, baseDn));
    candidates.push({ dn: USER_RDN(u.username, app.slug, baseDn), rdns, build: async () => await userEntry(u, ctx.view, app, settings) });
  }
  for (const g of ctx.view.groups) {
    const dn = GROUP_RDN(g.name, app.slug, baseDn);
    candidates.push({ dn, rdns: parseDn(dn), build: async () => await groupEntry(g, ctx.view, app, settings) });
  }

  // A base above the app branch confines the search to the branch but keeps
  // scope semantics: a one-level search on the naming context sees ou=<slug>.
  const eff = baseRdns.length <= baseDepth ? parseDn(APP_BRANCH_DN(app.slug, baseDn)) : baseRdns;

  const inScope = (rdns: Rdn[]): boolean => {
    if (op.scope === 0) return rdns.length === eff.length;
    if (op.scope === 1) return rdns.length === eff.length + 1;
    return rdns.length >= eff.length;
  };

  const matched: EvalEntry[] = [];
  const limit = op.sizeLimit === 0 ? SERVER_SIZE_LIMIT : Math.min(op.sizeLimit, SERVER_SIZE_LIMIT);
  // LDAP.md section 11: client timeLimit honoured, capped at 30s - and the cap
  // applies when the client sets none, so a scan can never run unbounded.
  const deadline = Date.now() + Math.min(op.timeLimit || 30, 30) * 1000;

  // A user-bound connection sees only their own entry and the groups they
  // actually belong to (LDAP.md section 10) - group visibility is matched per
  // entry against the user's group DNs, not just 'has any group'.
  const userBound = ctx.bound.kind === "user" ? ctx.bound.user : null;
  const ownGroupDns = userBound ? ownGroupDnSet(ctx, userBound, baseDn) : null;

  let code: number = RC.success;
  let diagnostic = "";
  for (const cand of candidates) {
    // Check per candidate, not only after a match: a scan that matches
    // nothing is exactly the one the limit exists to stop.
    if (Date.now() > deadline) {
      code = RC.timeLimitExceeded;
      diagnostic = "time limit exceeded";
      break;
    }
    if (!dnWithin(cand.rdns, eff)) continue;
    if (!inScope(cand.rdns)) continue;
    const entry = await cand.build();
    if (userBound) {
      const isSelf = entry.dn.toLowerCase() === USER_RDN(userBound.username, app.slug, baseDn).toLowerCase();
      const isOwnGroup = ownGroupDns!.has(entry.dn.toLowerCase());
      if (!isSelf && !isOwnGroup) continue;
      if (isOwnGroup) reduceGroupToSelf(entry, userBound, app, settings);
    }
    if (evaluateFilter(filter, entry) !== true) continue;
    matched.push(select(entry, op));
    if (matched.length > limit) {
      matched.pop();
      code = RC.sizeLimitExceeded;
      diagnostic = "size limit exceeded";
      break;
    }
  }

  return { code, matchedDn: "", diagnostic, entries: matched, total: matched.length, typesOnly: op.typesOnly };
}

/** DNs of the group entries a user-bound connection may see (LDAP.md section 10). */
function ownGroupDnSet(ctx: SearchCtx, user: UserRow, baseDn: string): Set<string> {
  return new Set(
    (ctx.view.userGroups.get(user.id) ?? [])
      .map((gid) => ctx.view.groups.find((g) => g.id === gid))
      .filter((g): g is GroupRow => g !== undefined)
      .map((g) => GROUP_RDN(g.name, ctx.app!.slug, baseDn).toLowerCase())
  );
}

/** A user-bound search sees a group they belong to with only themselves as member. */
function reduceGroupToSelf(entry: EvalEntry, user: UserRow, app: LdapAppRow, settings: LdapSettings): void {
  const selfDn = USER_RDN(user.username, app.slug, settings.baseDn);
  for (const attr of ["member", "uniquemember"]) {
    if (entry.attrs.has(attr)) entry.attrs.set(attr, [selfDn]);
  }
  if (entry.attrs.has("memberuid")) entry.attrs.set("memberuid", [user.username]);
}

function deepestAncestor(rdns: Rdn[], settings: LdapSettings): string {
  for (let n = Math.min(rdns.length, settings.base.length); n > 0; n--) {
    const tail = rdns.slice(rdns.length - n);
    if (dnEquals(tail, settings.base.slice(settings.base.length - n))) return formatDn(tail);
  }
  return "";
}

// ---- attribute selection (section 8) ----

const OPERATIONAL = new Set(["entryuuid", "entrydn", "createtimestamp", "modifytimestamp", "subschemasubentry", "hassubordinates"]);

const RANGE_RE = /^range=(\d+)-(\d+|\*)$/;

function select(entry: EvalEntry, op: SearchOp): EvalEntry {
  if (op.attributes.includes("1.1")) return { dn: entry.dn, attrs: new Map() };
  const wanted = op.attributes.filter((a) => a !== "1.1");
  const all = wanted.length === 0;
  const out = new Map<string, (string | Uint8Array)[]>();
  for (const [name, values] of entry.attrs) {
    if (!isReturnable(name)) continue;
    const isOp = OPERATIONAL.has(name);
    let include = all;
    let range: { lo: number; hi: number | null } | null = null;
    for (const w of wanted) {
      const lower = w.toLowerCase();
      if (w === "*") { if (!isOp) include = true; continue; }
      if (w === "+") { if (isOp) include = true; continue; }
      const [base, ...opts] = lower.split(";");
      if (base !== name) continue;
      const ropt = opts.find((o) => o.startsWith("range="));
      if (ropt) {
        const m = RANGE_RE.exec(ropt);
        if (m && !range) range = { lo: Number(m[1]), hi: m[2] === "*" ? null : Number(m[2]) };
        include = true;
        continue;
      }
      if (opts.length === 0) include = true;
      // Unknown options (;binary, ;lang-*) don't match: not returned.
    }
    if (!include) continue;
    // AD-style ranged retrieval: `member;range=L-H` returns values[L..H]
    // under the same tagged name; `-*` marks the returned end reaching the
    // last value. Out-of-range requests come back empty under `L-*`.
    if (range && !op.typesOnly) {
      const end = range.hi === null ? values.length - 1 : Math.min(range.hi, values.length - 1);
      if (range.lo >= values.length) {
        out.set(`${name};range=${range.lo}-*`, []);
      } else {
        const tag = end >= values.length - 1 ? `${name};range=${range.lo}-*` : `${name};range=${range.lo}-${end}`;
        out.set(tag, values.slice(range.lo, end + 1));
      }
      continue;
    }
    out.set(name, op.typesOnly ? [] : values);
  }
  // entryDN is synthesized on request rather than stored per entry.
  if (wanted.includes("+") || wanted.some((w) => w.toLowerCase().split(";")[0] === "entrydn")) out.set("entrydn", [entry.dn]);
  return { dn: entry.dn, attrs: out };
}

// ---- compare (section 10) ----

export async function executeCompare(ctx: SearchCtx, op: Extract<Operation, { kind: "compare" }>): Promise<{ code: number; matchedDn: string }> {
  if (op.attribute.toLowerCase() === "userpassword") return { code: RC.unwillingToPerform, matchedDn: "" };
  if (ctx.bound.kind === "anonymous" || !ctx.app) return { code: RC.insufficientAccessRights, matchedDn: "" };
  let rdns: Rdn[];
  try {
    rdns = parseDn(op.entry);
  } catch {
    return { code: RC.invalidDNSyntax, matchedDn: "" };
  }
  const candidates = await candidateEntries(ctx);
  const target = candidates.find((e) => {
    try {
      return dnEquals(parseDn(e.dn), rdns);
    } catch {
      return false;
    }
  });
  if (!target) return { code: RC.noSuchObject, matchedDn: "" };
  // Same authorisation as an equality filter (LDAP.md sections 10 + 11): a
  // user-bound compare may target only the bound user's own entry and the
  // groups they belong to - everything else is invisible.
  const userBound = ctx.bound.kind === "user" ? ctx.bound.user : null;
  if (userBound) {
    const baseDn = ctx.settings.baseDn;
    const isOwnGroup = ownGroupDnSet(ctx, userBound, baseDn).has(target.dn.toLowerCase());
    if (target.dn.toLowerCase() !== USER_RDN(userBound.username, ctx.app.slug, baseDn).toLowerCase() && !isOwnGroup) return { code: RC.noSuchObject, matchedDn: "" };
    if (isOwnGroup) reduceGroupToSelf(target, userBound, ctx.app, ctx.settings);
  }
  const values = target.attrs.get(op.attribute.toLowerCase());
  if (values === undefined) return { code: RC.undefinedAttributeType, matchedDn: "" };
  const text = new TextDecoder().decode(op.value);
  const ok = values.some((v) => {
    if (typeof v === "string" && typeof op.value !== "undefined") {
      if (["member", "uniquemember", "memberof", "manager"].includes(op.attribute.toLowerCase())) {
        try {
          return dnEquals(parseDn(v), parseDn(text));
        } catch {
          return false;
        }
      }
      return v === text || v.toLowerCase() === text.toLowerCase();
    }
    return v instanceof Uint8Array && v.length === op.value.length && v.every((b, i) => b === op.value[i]);
  });
  return { code: ok ? RC.compareTrue : RC.compareFalse, matchedDn: "" };
}

async function candidateEntries(ctx: SearchCtx): Promise<EvalEntry[]> {
  const { settings, app } = ctx;
  if (!app) return [];
  const out: EvalEntry[] = containerEntries(app, settings);
  for (const u of ctx.view.users) out.push(await userEntry(u, ctx.view, app, settings));
  for (const g of ctx.view.groups) out.push(await groupEntry(g, ctx.view, app, settings));
  return out;
}

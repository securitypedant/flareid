import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Env } from "../env.js";
import { ServiceError } from "../services/context.js";
import { getSetting, setSetting } from "./settings.js";
import { resolveGroupMemberUserIds } from "./groups.js";
import type { GroupRow } from "./types.js";
import { timed, recordEvent } from "./metrics.js";
import { sealMaybe, unsealMaybe } from "./sealed.js";

/**
 * Cloudflare One (Zero Trust) integrations.
 *
 * One connection per instance - a Cloudflare account id plus an API token with
 * Zero Trust Read/Write - feeds four things:
 *
 *  - Access JWT verification for the admin plane: when the deployment sits
 *    behind Cloudflare Access, /admin requires the CF_Authorization JWT minted
 *    for the configured application, so hitting the Worker origin directly
 *    cannot skip the front door.
 *  - Device-cert posture: an authentication policy can require a verified WARP
 *    device certificate (request.cf.tlsClientAuth) for sign-in.
 *  - User risk score: policies can cap the ZT risk level at sign-in, and user
 *    pages show the current level (GET /zt_risk_scoring/{user_id}).
 *  - Reusable list sync: gateway/lists kept in step with directory data -
 *    group member emails, the risk watchlist, deprovisioned users, managed
 *    domains, and source IPs with repeated sign-in failures.
 *
 * The token lives in idp_settings like other integration secrets
 * (scim_targets.secret). Every outbound call funnels through cfApi so status
 * is recorded and failures fail soft - a Cloudflare outage must not lock
 * people out of sign-in.
 */

const CF_API = "https://api.cloudflare.com/client/v4";
const CF_API_TIMEOUT_MS = 4000;

export interface CfOneConfig {
  accountId: string;
  apiToken: string;
  /** Zero Trust team name - the Access tenant host is https://{team}.cloudflareaccess.com. */
  team: string;
  /** AUD tag of the Access application protecting /admin ("" = JWT check off). */
  accessAud: string;
}

const cfOneCache = new Map<string, { config: CfOneConfig | null; at: number }>();
const CF_CONFIG_TTL_MS = 60_000;

/** Tests reset the database but not these isolate-level caches. */
export function cfOneClearCaches(): void {
  cfOneCache.clear();
  riskCache.clear();
  accessJwks.clear();
}

export async function getCfOne(env: Env): Promise<CfOneConfig | null> {
  const hit = cfOneCache.get("c");
  if (hit && Date.now() - hit.at < CF_CONFIG_TTL_MS) return hit.config;
  const { results } = await env.DB.prepare("SELECT key, value FROM idp_settings WHERE key LIKE 'cfone.%'").all<{ key: string; value: string }>();
  const s = new Map(results.map((r) => [r.key, r.value]));
  const accountId = (s.get("cfone.account_id") ?? "").trim();
  const apiToken = ((await unsealMaybe(env, s.get("cfone.api_token"))) ?? "").trim();
  const config = accountId ? { accountId, apiToken, team: (s.get("cfone.team") ?? "").trim(), accessAud: (s.get("cfone.access_aud") ?? "").trim() } : null;
  cfOneCache.set("c", { config, at: Date.now() });
  return config;
}

export async function saveCfOne(env: Env, input: { accountId: string; apiToken?: string; team: string; accessAud: string }): Promise<void> {
  const now = new Date().toISOString();
  // A different account (or none) means the Access-app mirror belongs to the
  // old one: drop it and any pending asks rather than leave stale cards and
  // requestable apps pointing at an account we no longer talk to.
  const previous = (await getSetting(env, "cfone.account_id"))?.trim() ?? "";
  if (input.accountId !== previous) {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM access_requests WHERE target_type = 'cfapp'"),
      env.DB.prepare("DELETE FROM cf_access_apps"),
    ]);
  }
  const pairs: [string, string][] = [
    ["cfone.account_id", input.accountId],
    ["cfone.team", input.team],
    ["cfone.access_aud", input.accessAud],
  ];
  // An empty token keeps the stored one, like the SCIM target secret.
  if (input.apiToken) pairs.push(["cfone.api_token", await sealMaybe(env, input.apiToken)]);
  await env.DB.batch(pairs.map(([k, v]) => env.DB.prepare("INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(k, v, now)));
  cfOneCache.delete("c");
}

/** True when list sync / risk-score pulls have the credential they need. */
export function cfOneReady(config: CfOneConfig | null): boolean {
  return Boolean(config && config.accountId && config.apiToken);
}

async function cfApi(env: Env, config: CfOneConfig, path: string, init: RequestInit = {}): Promise<{ success: boolean; result?: unknown; errors?: { message: string }[] }> {
  const res = await timed(env, "cf.api", fetch(`${CF_API}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${config.apiToken}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(CF_API_TIMEOUT_MS),
  }));
  const body = (await res.json()) as { success: boolean; result?: unknown; errors?: { message: string }[] };
  if (!res.ok || !body.success) throw new CfApiError(res.status, body.errors?.map((e) => e.message).join("; ") || `HTTP ${res.status}`);
  return body;
}

export class CfApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Access JWT for the admin plane
// ---------------------------------------------------------------------------

const accessJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function teamJwks(team: string) {
  let jwks = accessJwks.get(team);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`https://${team}.cloudflareaccess.com/cdn-cgi/access/certs`));
    accessJwks.set(team, jwks);
  }
  return jwks;
}

/**
 * The Access identity for the request, or null when there is none valid. The
 * JWT arrives in the CF_Authorization cookie or the Cf-Access-Jwt-Assertion
 * header (which takes precedence, matching Access's own order).
 */
export async function accessJwtFor(config: CfOneConfig, request: Request): Promise<JWTPayload | null> {
  if (!config.team || !config.accessAud) return null;
  const header = request.headers.get("Cf-Access-Jwt-Assertion");
  const cookie = /(?:^|;\s*)CF_Authorization=([^;]+)/.exec(request.headers.get("Cookie") ?? "")?.[1];
  const token = header || cookie;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, teamJwks(config.team), {
      issuer: `https://${config.team}.cloudflareaccess.com`,
      audience: config.accessAud,
    });
    return payload;
  } catch {
    return null;
  }
}

/** The person's email from a verified Access JWT ("" for service-token clients). */
export function accessJwtEmail(payload: JWTPayload): string {
  return typeof payload.email === "string" ? payload.email : "";
}

// ---------------------------------------------------------------------------
// Device-cert posture
// ---------------------------------------------------------------------------

interface TlsClientAuth {
  certPresented?: string;
  certVerified?: string;
  certSubjectDN?: string;
}

/** The request carries a client certificate Cloudflare verified (a WARP device cert under mTLS). */
export function deviceCertVerified(request: Request): boolean {
  const auth = (request as Request & { cf?: { tlsClientAuth?: TlsClientAuth } }).cf?.tlsClientAuth;
  return auth?.certPresented === "1" && auth?.certVerified === "SUCCESS";
}

// ---------------------------------------------------------------------------
// User risk score
// ---------------------------------------------------------------------------

export type RiskLevel = "info" | "low" | "medium" | "high";
const RISK_ORDER: RiskLevel[] = ["info", "low", "medium", "high"];

export function riskAtMost(level: RiskLevel | undefined, max: string): boolean {
  if (!max || !level) return true;
  return RISK_ORDER.indexOf(level) <= RISK_ORDER.indexOf(max as RiskLevel);
}

export interface RiskScore {
  level: RiskLevel;
  events: { id: string; name: string; risk_level: string; timestamp: string }[];
  fetchedAt: number;
}

// Sign-in and the user page both ask; a short per-isolate cache keeps a burst
// of attempts from becoming a burst of API calls.
const riskCache = new Map<string, { score: RiskScore | null; at: number }>();
const RISK_CACHE_MS = 5 * 60 * 1000;

/**
 * The user's Cloudflare ZT risk level: the Access user row keyed on their
 * email, then zt_risk_scoring/{id}. Null when the integration is off, the user
 * has no Cloudflare identity, or the API fails - callers decide whether a
 * policy's risk cap treats "unknown" as pass (it does: a broken integration
 * must not be an outage).
 */
export async function riskScoreFor(env: Env, config: CfOneConfig, email: string): Promise<RiskScore | null> {
  const key = email.toLowerCase();
  const hit = riskCache.get(key);
  if (hit && Date.now() - hit.at < RISK_CACHE_MS) return hit.score;
  let score: RiskScore | null = null;
  try {
    const users = await cfApi(env, config, `/accounts/${config.accountId}/access/users?email=${encodeURIComponent(key)}`);
    const ztUser = (users.result as { id?: string }[] | undefined)?.[0];
    if (ztUser?.id) {
      const risk = await cfApi(env, config, `/accounts/${config.accountId}/zt_risk_scoring/${ztUser.id}`);
      const r = risk.result as { risk_level?: string; events?: RiskScore["events"] } | undefined;
      const level = (RISK_ORDER as string[]).includes(r?.risk_level ?? "") ? (r!.risk_level as RiskLevel) : "info";
      score = { level, events: r?.events ?? [], fetchedAt: Date.now() };
    }
  } catch (err) {
    recordEvent(env, "cf.risk_error", err instanceof Error ? err.message : "error");
  }
  riskCache.set(key, { score, at: Date.now() });
  return score;
}

// ---------------------------------------------------------------------------
// Reusable list sync
// ---------------------------------------------------------------------------

export type CfListKind = "EMAIL" | "DOMAIN" | "IP";

interface CfListRow {
  key: string;
  cf_list_id: string;
  kind: string;
  item_count: number;
  synced_at: string | null;
}

/** The lists sync maintains; which ones run is the cfone.lists setting's business. */
export const LIST_SYNCS = [
  { key: "watchlist", name: "FlareID risk watchlist", kind: "EMAIL" as CfListKind, description: "Users flagged on FlareID's risk watchlist - tighten inspection or block" },
  { key: "deprovisioned", name: "FlareID deprovisioned", kind: "EMAIL" as CfListKind, description: "Accounts FlareID has disabled - block or tighten inspection" },
  { key: "managed-domains", name: "FlareID managed domains", kind: "DOMAIN" as CfListKind, description: "Directory's managed UPN domains - trusted senders for Email Security" },
  { key: "auth-fail-ips", name: "FlareID sign-in failures", kind: "IP" as CfListKind, description: "Source IPs with repeated recent sign-in failures - short-lived, CGNAT-safe" },
] as const;
export type ListSyncKey = (typeof LIST_SYNCS)[number]["key"] | `group:${number}`;

export async function enabledListSyncs(env: Env): Promise<Set<string>> {
  const raw = await getSetting(env, "cfone.lists");
  try {
    return new Set((JSON.parse(raw ?? "[]") as unknown[]).map(String));
  } catch {
    return new Set();
  }
}

export async function setEnabledListSyncs(env: Env, keys: string[]): Promise<void> {
  const valid = new Set<string>(LIST_SYNCS.map((l) => l.key));
  await setSetting(env, "cfone.lists", JSON.stringify([...new Set(keys)].filter((k) => valid.has(k))));
}

/** The remote list for a sync key, created when missing. */
async function ensureList(env: Env, config: CfOneConfig, key: string, name: string, kind: CfListKind, description: string): Promise<string> {
  const row = await env.DB.prepare("SELECT * FROM cf_lists WHERE key = ?").bind(key).first<CfListRow>();
  if (row) return row.cf_list_id;
  const created = await cfApi(env, config, `/accounts/${config.accountId}/gateway/lists`, {
    method: "POST",
    body: JSON.stringify({ name, type: kind, description }),
  });
  const id = (created.result as { id: string }).id;
  await env.DB.prepare("INSERT INTO cf_lists (key, cf_list_id, kind, item_count, synced_at) VALUES (?, ?, ?, 0, NULL)").bind(key, id, kind).run();
  return id;
}

/** Full-replace a list's items (PUT overwrites when items are supplied). */
async function replaceList(env: Env, config: CfOneConfig, key: string, cfListId: string, name: string, kind: CfListKind, values: string[], description: string): Promise<void> {
  try {
    await cfApi(env, config, `/accounts/${config.accountId}/gateway/lists/${cfListId}`, {
      method: "PUT",
      body: JSON.stringify({ name, items: values.map((value) => ({ value })) }),
    });
  } catch (err) {
    // Someone deleted the remote list out from under us: recreate and retry once.
    if (!(err instanceof CfApiError) || err.status !== 404) throw err;
    await env.DB.prepare("DELETE FROM cf_lists WHERE key = ?").bind(key).run();
    const fresh = await ensureList(env, config, key, name, kind, description);
    await cfApi(env, config, `/accounts/${config.accountId}/gateway/lists/${fresh}`, {
      method: "PUT",
      body: JSON.stringify({ name, items: values.map((value) => ({ value })) }),
    });
  }
  await env.DB.prepare("UPDATE cf_lists SET item_count = ?, synced_at = ? WHERE key = ?").bind(values.length, new Date().toISOString(), key).run();
}

// ---------------------------------------------------------------------------
// The risk watchlist
// ---------------------------------------------------------------------------

export const WATCHLIST_GROUP_NAME = "Risk watchlist";
export const WATCHLIST_SYSTEM = "watchlist";

/** The watchlist group, created on first use; members are the user_watch rows. */
export async function watchlistGroup(env: Env): Promise<GroupRow | null> {
  return env.DB.prepare("SELECT * FROM groups WHERE system = ?").bind(WATCHLIST_SYSTEM).first<GroupRow>();
}

export async function ensureWatchlistGroup(env: Env): Promise<GroupRow> {
  const existing = await watchlistGroup(env);
  if (existing) return existing;
  // The name is reserved at the group writers, but a squat from before the
  // reservation (or a direct DB write) must not surface as a bare UNIQUE
  // crash: skip the insert on conflict and then verify the row that wears
  // the name actually is the system group.
  await env.DB.prepare("INSERT INTO groups (name, description, system) VALUES (?, ?, ?) ON CONFLICT(name) DO NOTHING").bind(
    WATCHLIST_GROUP_NAME,
    "People flagged as risky - failed sign-in bursts or a manual flag. Sync it downstream to tighten their inspection.",
    WATCHLIST_SYSTEM
  ).run();
  const group = await watchlistGroup(env);
  if (!group) throw new Error(`The name "${WATCHLIST_GROUP_NAME}" is held by a group that is not the system watchlist - rename or delete it first.`);
  return group;
}

export async function watchlistUserIds(env: Env): Promise<number[]> {
  const { results } = await env.DB.prepare("SELECT user_id FROM user_watch WHERE expires_at IS NULL OR expires_at > ?").bind(new Date().toISOString()).all<{ user_id: number }>();
  return results.map((r) => r.user_id);
}

export async function watchedUser(env: Env, userId: number) {
  return env.DB.prepare("SELECT * FROM user_watch WHERE user_id = ?").bind(userId).first<{ user_id: number; reason: string; source: string; flagged_at: string; expires_at: string | null }>();
}

export interface WatchedRow {
  user_id: number;
  reason: string;
  source: string;
  flagged_at: string;
  expires_at: string | null;
  upn: string;
  display_name: string | null;
}

/** Everyone on the watchlist, with the user fields the console shows. */
export async function watchlist(env: Env): Promise<WatchedRow[]> {
  const { results } = await env.DB.prepare(
    `SELECT w.user_id, w.reason, w.source, w.flagged_at, w.expires_at, u.upn, u.display_name
       FROM user_watch w JOIN users u ON u.id = w.user_id
      WHERE w.expires_at IS NULL OR w.expires_at > ?
      ORDER BY w.flagged_at DESC`
  ).bind(new Date().toISOString()).all<WatchedRow>();
  return results;
}

/** Keeps the watchlist group's membership exactly the live user_watch rows. */
async function reconcileWatchlist(env: Env): Promise<void> {
  const group = await watchlistGroup(env);
  if (!group) return;
  const live = await watchlistUserIds(env);
  const { results } = await env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(group.id).all<{ user_id: number }>();
  const have = new Set(results.map((r) => r.user_id));
  const want = new Set(live);
  const add = live.filter((id) => !have.has(id));
  const del = results.map((r) => r.user_id).filter((id) => !want.has(id));
  if (!add.length && !del.length) return;
  await env.DB.batch([
    ...add.map((uid) => env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(group.id, uid)),
    ...del.map((uid) => env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").bind(group.id, uid)),
  ]);
}

/** Flags a user; a manual flag never lapses, an automatic one expires. */
export async function flagUser(env: Env, userId: number, reason: string, source: "manual" | "auto:fails" | "ssf", ttlHours = 0): Promise<void> {
  const already = await env.DB.prepare("SELECT 1 AS x FROM user_watch WHERE user_id = ?").bind(userId).first();
  await env.DB.prepare(
    `INSERT INTO user_watch (user_id, reason, source, flagged_at, expires_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       reason = CASE WHEN user_watch.expires_at IS NULL AND user_watch.source = 'manual' AND (excluded.expires_at IS NOT NULL OR excluded.source != 'manual') THEN user_watch.reason ELSE excluded.reason END,
       source = CASE WHEN user_watch.expires_at IS NULL AND user_watch.source = 'manual' AND (excluded.expires_at IS NOT NULL OR excluded.source != 'manual') THEN user_watch.source ELSE excluded.source END,
       expires_at = CASE WHEN user_watch.expires_at IS NULL AND user_watch.source = 'manual' AND (excluded.expires_at IS NOT NULL OR excluded.source != 'manual') THEN user_watch.expires_at ELSE excluded.expires_at END`
  )
    .bind(userId, reason, source, new Date().toISOString(), ttlHours ? new Date(Date.now() + ttlHours * 3600_000).toISOString() : null)
    .run();
  const group = await ensureWatchlistGroup(env);
  await env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(group.id, userId).run();
  const { pushUsersById } = await import("./scim-client.js");
  await pushUsersById(env, [userId]);
  // New flags are a risk signal: receivers should force re-auth/step-up.
  // Refreshed flags don't re-emit - a repeating auto-flag isn't new news.
  if (!already) {
    const upn = (await env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(userId).first<{ upn: string }>())?.upn;
    if (upn) {
      const { emitAndDrain, SSF_EVENTS } = await import("./ssf.js");
      await emitAndDrain(env, SSF_EVENTS["risc.credential-change-required"], { format: "email", email: upn }).catch(() => undefined);
    }
  }
}

export async function unflagUser(env: Env, userId: number): Promise<void> {
  await env.DB.prepare("DELETE FROM user_watch WHERE user_id = ?").bind(userId).run();
  const group = await watchlistGroup(env);
  if (group) {
    await env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").bind(group.id, userId).run();
    const { pushUsersById } = await import("./scim-client.js");
    await pushUsersById(env, [userId]);
  }
}

/** Cron: drop lapsed flags and keep the group row set exact. */
export async function sweepWatchlist(env: Env): Promise<number> {
  const { results } = await env.DB.prepare("SELECT user_id FROM user_watch WHERE expires_at IS NOT NULL AND expires_at <= ?").bind(new Date().toISOString()).all<{ user_id: number }>();
  if (results.length) {
    await env.DB.batch(results.map((r) => env.DB.prepare("DELETE FROM user_watch WHERE user_id = ?").bind(r.user_id)));
    await reconcileWatchlist(env);
    const { pushUsersById } = await import("./scim-client.js");
    await pushUsersById(env, results.map((r) => r.user_id));
  } else {
    await reconcileWatchlist(env);
  }
  return results.length;
}

// ---------------------------------------------------------------------------
// List sync content
// ---------------------------------------------------------------------------

/** Emails of a group's members - resolved for dynamic groups, rows for static. */
async function groupMemberEmails(env: Env, group: GroupRow): Promise<string[]> {
  const ids = await resolveGroupMemberUserIds(env, group);
  if (!ids.length) return [];
  const { results } = await env.DB.prepare("SELECT upn FROM users WHERE id IN (SELECT value FROM json_each(?)) AND upn LIKE '%@%'").bind(JSON.stringify(ids)).all<{ upn: string }>();
  return results.map((r) => r.upn);
}

async function watchlistEmails(env: Env): Promise<string[]> {
  const ids = await watchlistUserIds(env);
  if (!ids.length) return [];
  const { results } = await env.DB.prepare("SELECT upn FROM users WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(ids)).all<{ upn: string }>();
  return results.map((r) => r.upn);
}

async function deprovisionedEmails(env: Env): Promise<string[]> {
  const { results } = await env.DB.prepare("SELECT upn FROM users WHERE status != 'active' AND upn LIKE '%@%'").all<{ upn: string }>();
  return results.map((r) => r.upn);
}

async function managedDomains(env: Env): Promise<string[]> {
  const { results } = await env.DB.prepare("SELECT domain FROM domains ORDER BY domain").all<{ domain: string }>();
  return results.map((r) => r.domain);
}

/** Sign-in failures per source IP in the last hour; 8+ earns a list slot. */
async function authFailIps(env: Env): Promise<string[]> {
  const { results } = await env.DB.prepare(
    `SELECT ip, COUNT(*) AS n FROM audit_log
      WHERE action = 'login.failed' AND ip IS NOT NULL AND ip != '' AND at > ?
      GROUP BY ip HAVING n >= 8 LIMIT 500`
  ).bind(new Date(Date.now() - 3600_000).toISOString()).all<{ ip: string; n: number }>();
  return results.map((r) => r.ip);
}

/** Runs every enabled sync once; failures are logged per-list, not thrown. */
export async function syncLists(env: Env, config: CfOneConfig): Promise<{ synced: string[]; failed: Record<string, string> }> {
  const enabled = await enabledListSyncs(env);
  const synced: string[] = [];
  const failed: Record<string, string> = {};

  // Groups flagged for sync each get their own list.
  const { results: syncGroups } = await env.DB.prepare("SELECT * FROM groups WHERE cf_list_sync = 1 AND system = ''").all<GroupRow>();
  for (const g of syncGroups) enabled.add(`group:${g.id}`);

  const run = async (key: string, name: string, kind: CfListKind, description: string, values: () => Promise<string[]>) => {
    try {
      const listId = await ensureList(env, config, key, name, kind, description);
      await replaceList(env, config, key, listId, name, kind, await values(), description);
      synced.push(key);
    } catch (err) {
      failed[key] = err instanceof Error ? err.message : String(err);
      recordEvent(env, "cf.list_sync_error", `${key} ${failed[key]}`);
    }
  };

  const valueFns: Record<string, (env: Env) => Promise<string[]>> = { watchlist: watchlistEmails, deprovisioned: deprovisionedEmails, "managed-domains": managedDomains, "auth-fail-ips": authFailIps };
  for (const def of LIST_SYNCS) {
    if (enabled.has(def.key) && valueFns[def.key]) await run(def.key, def.name, def.kind, def.description, () => valueFns[def.key]!(env));
  }
  for (const g of syncGroups) {
    await run(`group:${g.id}`, `FlareID: ${g.name}`, "EMAIL", `Members of the ${g.name} group in FlareID`, () => groupMemberEmails(env, g));
  }
  return { synced, failed };
}

/** List-sync status for the console page. */
export async function listSyncStatus(env: Env): Promise<CfListRow[]> {
  const { results } = await env.DB.prepare("SELECT * FROM cf_lists ORDER BY key").all<CfListRow>();
  return results;
}

// ---------------------------------------------------------------------------
// Access applications (pull)
// ---------------------------------------------------------------------------

/**
 * Cloudflare Access applications, read-only pulled from the account. Access is
 * the authority for reachability - FlareID never writes app or policy config.
 * Each mirrored row maps the app to the static group whose membership grants
 * it: Access policies Include the group claim FlareID mints, so an approved
 * request is just a membership write and Access enforces from there.
 */

export interface CfAccessAppRow {
  id: number;
  cf_app_id: string;
  name: string;
  type: string;
  hostname: string;
  granting_group_id: number | null;
  /** JSON array: FlareID group names found in the app's Allow policies at last sync. */
  grant_hint: string;
  requestable: number;
  synced_at: string;
  updated_at: string;
}

export async function listAccessApps(env: Env): Promise<CfAccessAppRow[]> {
  return (await env.DB.prepare("SELECT * FROM cf_access_apps ORDER BY name").all<CfAccessAppRow>()).results;
}

export function grantHints(row: Pick<CfAccessAppRow, "grant_hint">): string[] {
  try {
    return (JSON.parse(row.grant_hint || "[]") as unknown[]).map(String);
  } catch {
    return [];
  }
}

interface CfAccessApp {
  id: string;
  name?: string;
  type?: string;
  domain?: string;
  self_hosted_domains?: string[];
}

/** A policy/group selector rule: only the shapes that name a group claim matter. */
interface CfSelector {
  oidc?: { group_id?: string };
  saml?: { attribute_name?: string; attribute_value?: string };
  group?: { id?: string };
}

interface CfPolicy {
  decision?: string;
  include?: CfSelector[];
}

/** Group-claim values a rule set names directly (IdP group selectors). */
function selectorClaims(rules: CfSelector[] | undefined, out: Set<string>): void {
  for (const r of rules ?? []) {
    if (r.oidc?.group_id) out.add(r.oidc.group_id);
    // A SAML attribute only counts when the attribute itself is groupish -
    // matching any attribute_value invites false hints (a "department" that
    // shares a name with a group).
    if (r.saml?.attribute_value && /group|memberof/i.test(r.saml.attribute_name ?? "")) out.add(r.saml.attribute_value);
  }
}

/** Reusable Access groups can themselves name group claims (and nest); one fetch each, seen-guarded. */
async function accessGroupClaims(env: Env, config: CfOneConfig, groupId: string, seen: Set<string>, out: Set<string>): Promise<void> {
  if (seen.has(groupId)) return;
  seen.add(groupId);
  const body = await cfApi(env, config, `/accounts/${config.accountId}/access/groups/${groupId}`);
  for (const r of ((body.result as { include?: CfSelector[] } | undefined)?.include ?? [])) {
    if (r.group?.id) await accessGroupClaims(env, config, r.group.id, seen, out);
    else selectorClaims([r], out);
  }
}

/**
 * Pulls the account's Access applications and upserts the mirror: name, type,
 * launch hostname, and a grant hint (the FlareID group names each app's Allow
 * policies select on, via IdP group claims or reusable Access groups).
 * granting_group_id/requestable survive re-syncs; apps that vanished upstream
 * are dropped along with their pending requests.
 */
export async function syncAccessApps(env: Env, config: CfOneConfig): Promise<{ synced: number; removed: number }> {
  const apps: CfAccessApp[] = [];
  for (let page = 1; page <= 20; page++) {
    const body = await cfApi(env, config, `/accounts/${config.accountId}/access/apps?per_page=50&page=${page}`);
    const page_ = (body.result as CfAccessApp[] | undefined) ?? [];
    apps.push(...page_);
    if (page_.length < 50) break;
  }

  // A hint is only worth keeping when it names a real FlareID group - that's
  // the claim Access would match at request time anyway.
  const nameByLower = new Map(
    (await env.DB.prepare("SELECT name FROM groups").all<{ name: string }>()).results.map((g) => [g.name.toLowerCase(), g.name])
  );

  // Per-app policies are a second call each; run them together. One app's
  // policy fetch failing only costs that app its hint - never sinks the sync.
  const hintsByCfId = new Map<string, string[]>();
  await Promise.all(
    apps.map(async (app) => {
      const candidates = new Set<string>();
      const seen = new Set<string>();
      try {
        const body = await cfApi(env, config, `/accounts/${config.accountId}/access/apps/${app.id}/policies`);
        for (const p of (body.result as CfPolicy[] | undefined) ?? []) {
          if (p.decision !== "allow") continue;
          for (const r of p.include ?? []) {
            if (r.group?.id) await accessGroupClaims(env, config, r.group.id, seen, candidates);
            else selectorClaims([r], candidates);
          }
        }
      } catch {
        /* no hint for this app */
      }
      hintsByCfId.set(
        app.id,
        [...new Set([...candidates].map((h) => nameByLower.get(h.toLowerCase())).filter((n): n is string => Boolean(n)))]
      );
    })
  );

  const t = new Date().toISOString();
  const existing = await listAccessApps(env);
  const liveIds = new Set(apps.map((a) => a.id));
  const gone = existing.filter((r) => !liveIds.has(r.cf_app_id));
  await env.DB.batch([
    ...apps.map((a) =>
      env.DB.prepare(
        `INSERT INTO cf_access_apps (cf_app_id, name, type, hostname, grant_hint, synced_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(cf_app_id) DO UPDATE SET name = excluded.name, type = excluded.type, hostname = excluded.hostname, grant_hint = excluded.grant_hint, synced_at = excluded.synced_at, updated_at = excluded.updated_at`
      ).bind(a.id, a.name ?? "", a.type ?? "", a.self_hosted_domains?.[0] ?? a.domain ?? "", JSON.stringify(hintsByCfId.get(a.id) ?? []), t, t)
    ),
    ...gone.flatMap((r) => [
      env.DB.prepare("DELETE FROM access_requests WHERE target_type = 'cfapp' AND target_id = ?").bind(r.id),
      env.DB.prepare("DELETE FROM cf_access_apps WHERE id = ?").bind(r.id),
    ]),
  ]);
  return { synced: apps.length, removed: gone.length };
}

/**
 * Sets the granting group and requestability for a synced Access app. The
 * granting group must be a static, non-system group - approving a request is a
 * manual membership write, which only those can take. Requestable needs a
 * granting group; clearing the group drops requestable too.
 */
export async function configureAccessApp(env: Env, appId: number, grantingGroupId: number | null, requestable: boolean): Promise<CfAccessAppRow> {
  const app = await env.DB.prepare("SELECT * FROM cf_access_apps WHERE id = ?").bind(appId).first<CfAccessAppRow>();
  if (!app) throw new ServiceError(404, "That Access application is not synced - run a sync first.");
  if (grantingGroupId !== null) {
    const g = await env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(grantingGroupId).first<GroupRow>();
    if (!g) throw new ServiceError(400, "That group does not exist.");
    if (g.rule) throw new ServiceError(400, `"${g.name}" fills itself by rule - a granting group has to be static.`);
    if (g.system) throw new ServiceError(400, `"${g.name}" is maintained by the system; it can't grant an app.`);
  }
  // Requestable needs a group to join: asking for it on an unmapped app is an
  // error, while unmapping an app quietly drops the flag (it can't work
  // without a group anyway).
  if (requestable && grantingGroupId === null && app.granting_group_id === null) {
    throw new ServiceError(400, "Pick the group that grants this app before making it requestable.");
  }
  const wants = requestable && grantingGroupId !== null;
  await env.DB.prepare("UPDATE cf_access_apps SET granting_group_id = ?, requestable = ?, updated_at = ? WHERE id = ?")
    .bind(grantingGroupId, wants ? 1 : 0, new Date().toISOString(), appId)
    .run();
  return (await env.DB.prepare("SELECT * FROM cf_access_apps WHERE id = ?").bind(appId).first<CfAccessAppRow>())!;
}

/** The launch target for a synced app - Access serves HTTPS on its domains. */
export function accessAppHref(row: Pick<CfAccessAppRow, "hostname">): string {
  const h = row.hostname.trim();
  if (!h) return "";
  return /^https?:\/\//i.test(h) ? h : `https://${h}`;
}

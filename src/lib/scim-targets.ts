import type { Env } from "../env.js";
import { sealMaybe } from "./sealed.js";

/** A literal host (IP or name) on an address the provisioning Bearer must never be sent to. */
function isLocalAddress(host: string): boolean {
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  // IPv6 literals contain ":" (hostnames cannot): loopback, unspecified,
  // link-local, unique-local, and IPv4-mapped forms.
  if (host.includes(":")) {
    if (host === "::1" || host === "::") return true;
    if (/^fe[89ab]/.test(host)) return true; // fe80::/10 link-local
    if (/^f[cd]/.test(host)) return true; // fc00::/7 unique-local
    if (host.startsWith("::ffff:")) {
      // IPv4-mapped: the parser normalizes ::ffff:1.2.3.4 to ::ffff:hhhh:hhhh.
      const tail = host.slice(7);
      if (!tail.includes(":")) return isLocalAddress(tail);
      const m = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (m) {
        const hi = parseInt(m[1]!, 16); const lo = parseInt(m[2]!, 16);
        return isLocalAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
      }
      return true;
    }
    return false;
  }
  // IPv4 literals (the URL parser has already normalized hex/octal/integer forms to dotted decimal).
  const parts = host.split(".");
  if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) {
    const a = Number(parts[0]); const b = Number(parts[1]);
    return (
      a === 0 || a === 10 || a === 127 || // this-net, private, loopback
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      (a === 169 && b === 254) || // link-local
      (a === 172 && b >= 16 && b <= 31) || // private
      (a === 192 && b === 168) || // private
      (a === 198 && (b === 18 || b === 19)) || // benchmarking
      a >= 224 // multicast + reserved
    );
  }
  return false;
}

/**
 * Where the SCIM client pushes the whole directory, with a Bearer credential:
 * an absolute https URL, no embedded credentials/query/fragment, and not a
 * loopback/private/link-local literal address. Returns the problem, or null.
 * (Checked on save, and again on use, so a stale or hand-edited row cannot aim
 * the credentialed fetch at an arbitrary origin.)
 */
export function validateScimEndpoint(endpoint: string): string | null {
  let u: URL;
  try {
    u = new URL(endpoint);
  } catch {
    return "The SCIM endpoint is not a valid URL.";
  }
  if (u.protocol !== "https:") return "The SCIM endpoint must use https.";
  if (u.username || u.password) return "The SCIM endpoint must not embed credentials.";
  if (u.search || u.hash) return "The SCIM endpoint must not include a query or fragment.";
  if (isLocalAddress(u.hostname.toLowerCase().replace(/^\[|\]$/g, ""))) return "The SCIM endpoint must not be a loopback or private address.";
  return null;
}

/**
 * Outbound SCIM targets (the `scim_targets` table, migration 0034). One row
 * per downstream SCIM server - each carries its own endpoint, write-only
 * credential, sync scope and push tuning, so receivers with different limits
 * (Cloudflare Access's Durable-Object-backed endpoint among them) get their
 * own profile rather than one compromise for all.
 */

export interface ScimScope {
  mode: "all" | "selected";
  groupIds: number[];
}

export interface ScimTarget {
  id: number;
  name: string;
  endpoint: string;
  secret: string;
  scope: ScimScope;
  /** Minimum milliseconds between outbound requests. 0 = back to back. */
  paceMs: number;
  /** Member references per group PATCH body. */
  membersPerRequest: number;
  /** Users pushed per sync invocation (the sync is re-called until complete). */
  syncBatchSize: number;
  enabled: boolean;
}

interface ScimTargetRow {
  id: number;
  name: string;
  endpoint: string;
  secret: string;
  scope_mode: string;
  scope_group_ids: string;
  pace_ms: number;
  members_per_request: number;
  sync_batch: number;
  enabled: number;
}

function toTarget(row: ScimTargetRow): ScimTarget {
  let groupIds: number[] = [];
  try {
    const parsed: unknown = JSON.parse(row.scope_group_ids);
    if (Array.isArray(parsed)) groupIds = parsed.map(Number).filter((n) => Number.isInteger(n));
  } catch {
    groupIds = [];
  }
  return {
    id: row.id,
    name: row.name,
    endpoint: row.endpoint,
    secret: row.secret,
    scope: { mode: row.scope_mode === "selected" ? "selected" : "all", groupIds },
    paceMs: row.pace_ms,
    membersPerRequest: row.members_per_request,
    syncBatchSize: row.sync_batch,
    enabled: !!row.enabled,
  };
}

export async function listScimTargets(env: Env): Promise<ScimTarget[]> {
  const { results } = await env.DB.prepare("SELECT * FROM scim_targets ORDER BY name").all<ScimTargetRow>();
  return results.map(toTarget);
}

export async function enabledScimTargets(env: Env): Promise<ScimTarget[]> {
  const { results } = await env.DB.prepare("SELECT * FROM scim_targets WHERE enabled = 1 ORDER BY name").all<ScimTargetRow>();
  return results.map(toTarget);
}

export async function getScimTarget(env: Env, id: number): Promise<ScimTarget | null> {
  const row = await env.DB.prepare("SELECT * FROM scim_targets WHERE id = ?").bind(id).first<ScimTargetRow>();
  return row ? toTarget(row) : null;
}

/** True when at least one enabled target has endpoint and secret - anything else skips pushes entirely. */
export async function isScimConfigured(env: Env): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 FROM scim_targets WHERE enabled = 1 AND endpoint != '' AND secret != '' LIMIT 1").first();
  return !!row;
}

export interface ScimTargetInput {
  name: string;
  endpoint: string;
  secret: string;
  scope: ScimScope;
  paceMs: number;
  membersPerRequest: number;
  syncBatchSize: number;
  enabled: boolean;
}

/** Name, endpoint format and tuning ranges checked once for every writer. An empty endpoint is legal on update (it unparks the credential with it); create requires one. */
export function validateScimTargetInput(input: ScimTargetInput): string | null {
  if (!input.name.trim()) return "The target needs a name.";
  if (input.name.trim().length > 80) return "The target name is too long.";
  if (input.endpoint) {
    const problem = validateScimEndpoint(input.endpoint);
    if (problem) return problem;
  }
  if (!(input.paceMs >= 0 && input.paceMs <= 10_000) || !(input.membersPerRequest >= 1 && input.membersPerRequest <= 500) || !(input.syncBatchSize >= 10 && input.syncBatchSize <= 500))
    return "Tuning values out of range (pace 0-10000ms, members per request 1-500, sync batch 10-500).";
  return null;
}

function normalize(input: ScimTargetInput): ScimTargetInput {
  return { ...input, name: input.name.trim(), endpoint: input.endpoint.trim().replace(/\/$/, "") };
}

/** Throws on a name collision (UNIQUE) or invalid input - callers map it to a 400/409. */
export async function createScimTarget(env: Env, raw: ScimTargetInput): Promise<ScimTarget> {
  const input = normalize(raw);
  if (!input.endpoint) throw new Error("The SCIM endpoint is required.");
  const problem = validateScimTargetInput(input);
  if (problem) throw new Error(problem);
  const res = await env.DB.prepare(
    `INSERT INTO scim_targets (name, endpoint, secret, scope_mode, scope_group_ids, pace_ms, members_per_request, sync_batch, enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      input.name,
      input.endpoint,
      await sealMaybe(env, input.secret.trim()),
      input.scope.mode,
      JSON.stringify(input.scope.groupIds),
      input.paceMs,
      input.membersPerRequest,
      input.syncBatchSize,
      input.enabled ? 1 : 0,
      new Date().toISOString(),
      new Date().toISOString()
    )
    .run();
  return (await getScimTarget(env, Number(res.meta.last_row_id)))!;
}

/**
 * Partial update: fields not supplied keep their values, and an empty `secret`
 * keeps the stored credential. Clearing the endpoint drops the credential with
 * it. Renaming is allowed - the name is display-only, every link is by id.
 */
export async function updateScimTarget(env: Env, id: number, raw: Partial<ScimTargetInput>): Promise<ScimTarget | null> {
  const current = await getScimTarget(env, id);
  if (!current) return null;
  const endpoint = raw.endpoint ?? current.endpoint;
  const merged: ScimTargetInput = normalize({
    name: raw.name ?? current.name,
    endpoint,
    secret: endpoint === "" ? "" : raw.secret !== undefined && raw.secret !== "" ? raw.secret : current.secret,
    scope: raw.scope ?? current.scope,
    paceMs: raw.paceMs ?? current.paceMs,
    membersPerRequest: raw.membersPerRequest ?? current.membersPerRequest,
    syncBatchSize: raw.syncBatchSize ?? current.syncBatchSize,
    enabled: raw.enabled ?? current.enabled,
  });
  const problem = validateScimTargetInput(merged);
  if (problem) throw new Error(problem);
  await env.DB.prepare(
    `UPDATE scim_targets SET name = ?, endpoint = ?, secret = ?, scope_mode = ?, scope_group_ids = ?, pace_ms = ?, members_per_request = ?, sync_batch = ?, enabled = ?, updated_at = ? WHERE id = ?`
  )
    .bind(
      merged.name,
      merged.endpoint,
      await sealMaybe(env, merged.secret.trim()),
      merged.scope.mode,
      JSON.stringify(merged.scope.groupIds),
      merged.paceMs,
      merged.membersPerRequest,
      merged.syncBatchSize,
      merged.enabled ? 1 : 0,
      new Date().toISOString(),
      id
    )
    .run();
  return getScimTarget(env, id);
}

/** Deleting a target drops its links, push state and deprovision queue (cascades) - the remote objects are left to their own fate. */
export async function deleteScimTarget(env: Env, id: number): Promise<boolean> {
  const res = await env.DB.prepare("DELETE FROM scim_targets WHERE id = ?").bind(id).run();
  return res.meta.changes > 0;
}

/** Remote resource id the user was pushed to under this target, if any. */
export async function targetUserScimId(env: Env, targetId: number, userId: number): Promise<string | null> {
  return (await env.DB.prepare("SELECT scim_id FROM scim_user_links WHERE target_id = ? AND user_id = ?").bind(targetId, userId).first<{ scim_id: string }>())?.scim_id ?? null;
}

export async function targetGroupScimId(env: Env, targetId: number, groupId: number): Promise<string | null> {
  return (await env.DB.prepare("SELECT scim_id FROM scim_group_links WHERE target_id = ? AND group_id = ?").bind(targetId, groupId).first<{ scim_id: string }>())?.scim_id ?? null;
}

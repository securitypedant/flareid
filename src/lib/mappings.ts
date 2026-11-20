import type { Env } from "../env.js";
import { evalExpression, parseExpression, scalar, strOf, ExprError } from "./expr.js";
import { getManagerEmail, getUserGroupNames } from "./db.js";
import { parseCustomAttributes } from "./schemas.js";
import { getSetting, setSetting } from "./settings.js";
import type { UserRow } from "./types.js";
import type { IdTokenClaims } from "./jwt.js";

/**
 * The unified attribute-mapping store. One table backs every direction the
 * directory's fields travel: inbound writes (SCIM provisioning, federation
 * JIT) map a source document onto user fields; outbound flows (SCIM push,
 * per-client OIDC claims) map the user document onto external attribute
 * names. Each row's `expression` is evaluated by the engine in expr.ts.
 *
 * Resolution: a channel's rows for `owner` win outright; when the owner has
 * none the channel's global rows (owner '') apply. There is no merge - a
 * per-owner set is the complete set, so "which rules apply" stays a
 * one-line answer for an administrator.
 */

export type MappingDirection = "in" | "out";
export type MappingChannel = "scim-in" | "jit" | "scim-out" | "oidc";

export const MAPPING_CHANNELS: { channel: MappingChannel; direction: MappingDirection; label: string }[] = [
  { channel: "scim-in", direction: "in", label: "SCIM provisioning (inbound)" },
  { channel: "jit", direction: "in", label: "Federation sign-in (JIT)" },
  { channel: "scim-out", direction: "out", label: "SCIM push (outbound)" },
  { channel: "oidc", direction: "out", label: "OIDC claims (per client)" },
];

export interface MappingRow {
  id: number;
  direction: MappingDirection;
  channel: string;
  owner: string;
  resource: string;
  target: string;
  expression: string;
  position: number;
  enabled: boolean;
}

export interface MappingInput {
  target: string;
  expression: string;
  enabled?: boolean;
}

export class MappingError extends ExprError {}

function channelDirection(channel: string): MappingDirection {
  return MAPPING_CHANNELS.find((c) => c.channel === channel)?.direction ?? "in";
}

export async function listMappings(env: Env, opts: { channel: string; owner?: string; resource?: string; enabledOnly?: boolean }): Promise<MappingRow[]> {
  const { results } = await env.DB.prepare(
    `SELECT id, direction, channel, owner, resource, target, expression, position, enabled
     FROM mappings WHERE channel = ? AND owner = ? AND resource = ?${opts.enabledOnly ? " AND enabled = 1" : ""} ORDER BY position, id`
  )
    .bind(opts.channel, opts.owner ?? "", opts.resource ?? "user")
    .all<Omit<MappingRow, "enabled"> & { enabled: number }>();
  return results.map((r) => ({ ...r, enabled: r.enabled === 1 }));
}

/** The rows that actually apply to an owner: its own set, else the channel's global set. */
export async function effectiveMappings(env: Env, channel: string, owner: string, resource = "user", enabledOnly = true): Promise<MappingRow[]> {
  const own = owner ? await listMappings(env, { channel, owner, resource, enabledOnly }) : [];
  if (own.length) return own;
  return listMappings(env, { channel, owner: "", resource, enabledOnly });
}

/** Owners with at least one stored row in a channel - for the Flows overview. */
export async function mappingOwners(env: Env, channel: string, resource = "user"): Promise<string[]> {
  const { results } = await env.DB.prepare("SELECT DISTINCT owner FROM mappings WHERE channel = ? AND resource = ? AND owner != '' ORDER BY owner")
    .bind(channel, resource)
    .all<{ owner: string }>();
  return results.map((r) => r.owner);
}

export interface EvaluatedMapping {
  target: string;
  value: unknown;
}

/**
 * Evaluates rows over `doc`. `onError` decides per-row failure behaviour:
 * "throw" for write paths (inbound provisioning must surface a bad mapping),
 * "skip" for read paths (a broken outbound claim shouldn't take sign-in
 * down for the whole directory).
 */
export function evalMappings(rows: MappingRow[], doc: unknown, onError: "throw" | "skip" = "throw"): EvaluatedMapping[] {
  const out: EvaluatedMapping[] = [];
  for (const m of rows) {
    try {
      out.push({ target: m.target, value: evalExpression(parseExpression(m.expression), doc) });
    } catch (e) {
      if (onError === "throw") throw new MappingError(`The mapping for "${m.target}" failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return out;
}

/**
 * Validates every row, then replaces the whole set for (channel, owner,
 * resource). `validateTarget` returns an error string, or null when the
 * target is acceptable for the channel.
 */
export async function replaceMappings(
  env: Env,
  scope: { channel: string; owner?: string; resource?: string },
  rows: MappingInput[],
  validateTarget?: (target: string) => string | null
): Promise<void> {
  const direction = channelDirection(scope.channel);
  const owner = scope.owner ?? "";
  const resource = scope.resource ?? "user";
  const seen = new Set<string>();
  const clean: { target: string; expression: string; enabled: number }[] = [];
  for (const row of rows) {
    const target = String(row.target ?? "").trim();
    const expression = String(row.expression ?? "").trim();
    if (!target || !expression) throw new MappingError("Every mapping needs a target field and an expression.");
    if (validateTarget) {
      const err = validateTarget(target);
      if (err) throw new MappingError(err);
    }
    const key = target.toLowerCase();
    if (seen.has(key)) throw new MappingError(`"${target}" is mapped more than once.`);
    seen.add(key);
    try {
      parseExpression(expression);
    } catch (e) {
      throw new MappingError(`The expression for "${target}" is invalid: ${e instanceof Error ? e.message : String(e)}`);
    }
    clean.push({ target, expression, enabled: row.enabled === false ? 0 : 1 });
  }
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM mappings WHERE channel = ? AND owner = ? AND resource = ?").bind(scope.channel, owner, resource),
    ...clean.map((r, i) =>
      env.DB.prepare("INSERT INTO mappings (direction, channel, owner, resource, target, expression, position, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(direction, scope.channel, owner, resource, r.target, r.expression, i, r.enabled, now, now)
    ),
  ]);
}

// ---------------------------------------------------------------------------
// Channel vocabularies and target validation
// ---------------------------------------------------------------------------

/**
 * Targets a JIT mapping may feed: the profile fields (email drives account
 * adoption; username becomes the sign-in name's local part) plus the same
 * scalar user columns inbound SCIM can write, and custom.* attributes.
 */
export const JIT_MAPPING_TARGETS = [
  "email", "username", "display_name", "given_name", "family_name",
  "job_title", "department", "employee_number", "hire_date",
  "employment_status", "employment_type", "location", "source_id",
];

export const JIT_COLUMN_TARGETS = new Set(JIT_MAPPING_TARGETS.filter((t) => t !== "email" && t !== "username"));

const CUSTOM_TARGET = /^custom\.[A-Za-z][\w-]*$/;

export function validateJitTarget(target: string): string | null {
  if (JIT_COLUMN_TARGETS.has(target) || target === "email" || target === "username" || CUSTOM_TARGET.test(target)) return null;
  return `"${target}" is not a field a JIT mapping can feed (use ${JIT_MAPPING_TARGETS.join(", ")} or custom.<key>).`;
}

/**
 * Outbound SCIM targets: the attribute names the pushed resource carries.
 * `name.givenName` style sub-attributes, `emails`, and URN extension
 * attributes are all accepted; the value side is always an expression.
 */
export const SCIM_OUT_TARGETS = [
  "userName", "name.givenName", "name.familyName", "displayName", "title",
  "emails", "active", "externalId",
  "enterprise.employeeNumber", "enterprise.department", "enterprise.manager",
];

export function validateScimOutTarget(target: string): string | null {
  if (!/^[A-Za-z][\w.:\-$]*$/.test(target)) return `"${target}" is not a valid SCIM attribute name.`;
  return null;
}

/** Claims a client mapping may not emit: the protocol's own assertions. */
export const OIDC_RESERVED_CLAIMS = new Set([
  "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "azp", "nonce",
  "auth_time", "at_hash", "c_hash", "sid", "acr", "amr", "scope", "custom",
]);

export function validateOidcClaimTarget(target: string): string | null {
  if (!/^[A-Za-z_][\w.:\-]*$/.test(target)) return `"${target}" is not a valid claim name.`;
  if (OIDC_RESERVED_CLAIMS.has(target)) return `"${target}" is a protocol claim and can't be mapped.`;
  return null;
}

// ---------------------------------------------------------------------------
// The outbound document
// ---------------------------------------------------------------------------

/**
 * The document outbound expressions evaluate: one user as a nested object.
 * Schema custom attributes appear twice - under `custom.<key>` and at top
 * level by bare name - matching both how rules and SAML's legacy field
 * lookup read them.
 */
export async function userExprDoc(env: Env, user: UserRow): Promise<Record<string, unknown>> {
  const custom = parseCustomAttributes(user.custom_attributes);
  const [groups, manager, { results: emails }] = await Promise.all([
    getUserGroupNames(env, user.id),
    getManagerEmail(env, user.manager_external_id),
    env.DB.prepare("SELECT email, type, is_primary FROM user_emails WHERE user_id = ? ORDER BY is_primary DESC, id").bind(user.id).all<{ email: string; type: string; is_primary: number }>(),
  ]);
  return {
    ...custom,
    custom,
    username: user.username,
    upn: user.upn,
    // The SAML/OIDC aliases the attribute vocabulary has always used.
    email: user.upn,
    name: user.display_name,
    display_name: user.display_name,
    given_name: user.given_name,
    family_name: user.family_name,
    id: user.external_id,
    job_title: user.job_title,
    department: user.department,
    employee_number: user.employee_number,
    hire_date: user.hire_date,
    employment_status: user.employment_status,
    employment_type: user.employment_type,
    location: user.location,
    status: user.status,
    manager: manager ?? "",
    groups,
    emails: emails.map((e) => ({ value: e.email, type: e.type || "work", primary: e.is_primary === 1 })),
  };
}

// ---------------------------------------------------------------------------
// Collision policy
// ---------------------------------------------------------------------------

/**
 * What an inbound write does when the identity it would create collides with
 * an existing account's identifiers.
 *
 *   username  'increment' - append a counter (jdoe, jdoe2, jdoe3...)
 *             'fail'      - refuse the sign-in / write
 *             'pattern'   - evaluate username_pattern over
 *                           { local, n, domain, email } until the result is free
 *   email     'skip'      - don't attach the colliding address (default)
 *             'fail'      - refuse
 */
export interface CollisionPolicy {
  username: "increment" | "fail" | "pattern";
  username_pattern: string;
  email: "skip" | "fail";
}

const COLLISION_SETTING = "identity_collisions";
const DEFAULT_COLLISION: CollisionPolicy = { username: "increment", username_pattern: 'local + n', email: "skip" };

export async function getCollisionPolicy(env: Env): Promise<CollisionPolicy> {
  const raw = await getSetting(env, COLLISION_SETTING);
  if (!raw) return { ...DEFAULT_COLLISION };
  try {
    const p = JSON.parse(raw) as Partial<CollisionPolicy>;
    return {
      username: p.username === "fail" || p.username === "pattern" ? p.username : "increment",
      username_pattern: typeof p.username_pattern === "string" && p.username_pattern.trim() ? p.username_pattern : DEFAULT_COLLISION.username_pattern,
      email: p.email === "fail" ? "fail" : "skip",
    };
  } catch {
    return { ...DEFAULT_COLLISION };
  }
}

export async function setCollisionPolicy(env: Env, input: { username?: string; username_pattern?: string; email?: string }): Promise<CollisionPolicy> {
  const username = input.username === "fail" || input.username === "pattern" ? input.username : "increment";
  const email = input.email === "fail" ? "fail" : "skip";
  const pattern = String(input.username_pattern ?? "").trim();
  if (username === "pattern") {
    if (!pattern) throw new MappingError("A pattern policy needs an expression, e.g. local + n or alnum(lower(local)) + right(\"0\" + n, 2).");
    parseExpression(pattern); // throws on malformed input
  }
  const policy: CollisionPolicy = { username, username_pattern: pattern || DEFAULT_COLLISION.username_pattern, email };
  await setSetting(env, COLLISION_SETTING, JSON.stringify(policy));
  return policy;
}

/** Next free username for a colliding `local` under the configured policy. */
export async function resolveUsernameCollision(
  env: Env,
  local: string,
  ctx: { domain: string; email: string },
  policy?: CollisionPolicy
): Promise<string | null> {
  const p = policy ?? (await getCollisionPolicy(env));
  const taken = async (candidate: string) => Boolean(await env.DB.prepare("SELECT 1 FROM users WHERE username = ?").bind(candidate).first());
  if (!(await taken(local))) return local;
  if (p.username === "fail") return null;
  // Bounded: 200 attempts is far past anything a real directory needs and
  // keeps a pathological pattern expression from looping forever.
  for (let n = 2; n <= 200; n++) {
    let candidate: string;
    if (p.username === "pattern") {
      const v = evalExpression(parseExpression(p.username_pattern), { local, n, domain: ctx.domain, email: ctx.email });
      candidate = strOf(scalar(v)).toLowerCase().replace(/[^a-z0-9._-]/g, "").replace(/^[^a-z0-9]+/, "");
      if (!candidate) continue;
    } else {
      candidate = `${local}${n}`;
    }
    if (!(await taken(candidate))) return candidate;
  }
  return null;
}

/**
 * Per-client OIDC claim mappings: the `oidc` channel's rows evaluate over the
 * issuing claim set and add (or refine) attributes on the id_token and
 * /userinfo responses. Protocol claims can't be targets - enforced both at
 * save time and here, so a hand-edited row can't forge `sub` or `aud`.
 */
export async function clientMappedClaims(env: Env, clientId: string, claims: IdTokenClaims): Promise<Record<string, unknown>> {
  const rows = await effectiveMappings(env, "oidc", clientId);
  if (!rows.length) return {};
  const doc = {
    ...(claims.customAttributes ?? {}),
    custom: claims.customAttributes ?? {},
    id: claims.id,
    email: claims.email,
    upn: claims.email,
    name: claims.name,
    display_name: claims.name,
    given_name: claims.givenName,
    family_name: claims.familyName,
    username: claims.username,
    preferred_username: claims.username,
    groups: claims.groups,
    job_title: claims.jobTitle,
    department: claims.department,
    manager: claims.managerEmail ?? "",
  };
  const out: Record<string, unknown> = {};
  for (const m of evalMappings(rows, doc, "skip")) {
    if (OIDC_RESERVED_CLAIMS.has(m.target)) continue;
    out[m.target] = m.value ?? null;
  }
  return out;
}

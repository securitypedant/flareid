import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { accessFor, adminRoleGroupIds, adminRoleGroupNames, grantsAdminRoleGroup } from "../lib/admin-roles.js";
import { auditActor, requireApiAuth, requireScope } from "../lib/api-auth.js";
import { hasScope } from "../lib/api-keys.js";
import { logAudit } from "../lib/audit.js";
import { getUserByExternalId } from "../lib/db.js";
import { listDomains, getDefaultDomain } from "../lib/domains.js";
import { isEmailAddress } from "../lib/email.js";
import { listUserEmails, setUserEmails, getUserByAnyEmail, assertEmailsUsable, UserEmailError, type UserEmailInput } from "../lib/user-emails.js";
import { applyInboundPhoto, deleteUserPhoto } from "../lib/photos.js";
import { parseRule, resolveGroupMemberUserIds, resolveManyGroupMemberUserIds, userMatchesRule } from "../lib/groups.js";
import { defaultSchemaId } from "../lib/schemas.js";
import { deleteUserStatements, revokeAllSessionsForUser, revokeTokensForUser } from "../lib/sessions.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { revokeAccountTokens } from "../lib/account-tokens.js";
import { applyUserMappings, correlateUser, mergeScimBody, resolveManagerRef, ScimMappingError } from "../lib/scim-mapping.js";
import { deactivateUserScim, drainScimDeprovisionQueue, isScimConfigured, pushChangedDynamicGroups, pushGroupCurrent, pushUser, pushUsersById, scimDeprovisionStatements, type ScimResult } from "../lib/scim-client.js";

/**
 * SCIM 2.0 server (RFC 7643/7644) for inbound provisioning: an HR system or
 * upstream directory creates, updates and deprovisions FlareID users and
 * groups. Mounted at /scim/v2, authenticated with a FlareID API key
 * (directory:read to read, directory:write to change).
 *
 * Mapping: a User's id is its external_id (a stable UUID), userName its UPN;
 * a Group's id is its numeric id as a string. The same boundaries as the
 * import API apply: admin roles - the groups that grant them, static or
 * dynamic, and the accounts that hold them - are out of a non-admin key's
 * reach, and dynamic groups take no members (their membership is their rule).
 */
export const scimServer = new Hono<{ Bindings: Env }>();

const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_PAGE = 200;

scimServer.use("/scim/v2/*", requireApiAuth);
scimServer.use("/scim/v2/*", async (c, next) => {
  await next();
  if ((c.res.headers.get("Content-Type") ?? "").startsWith("application/json")) c.res.headers.set("Content-Type", "application/scim+json");
});

/**
 * Inbound changes are passed on to the outbound SCIM target, as every other
 * directory writer does: a user HR deprovisions here must not stay active
 * downstream (Cloudflare Access, say). Best effort, after the response.
 */
function downstream(c: Context<{ Bindings: Env }>, work: () => Promise<ScimResult>, action: string, target: string) {
  c.executionCtx.waitUntil(
    (async () => {
      if (!(await isScimConfigured(c.env))) return;
      const result = await work().catch((e: unknown) => ({ ok: false, error: String(e) }) as ScimResult);
      if (!result.ok) await logAudit(c.env, auditActor(c.get("apiActor")), "scim.sync_failed", target, { action, error: result.error });
    })()
  );
}

/** The user, then every dynamic group: an attribute change can move them in or out of any rule. */
async function pushUserAndRules(env: Env, before: UserRow | null, user: UserRow): Promise<ScimResult> {
  const r = user.status === "active" ? await pushUser(env, user) : await deactivateUserScim(env, user);
  const groups = await pushChangedDynamicGroups(env, before, user);
  return r.ok ? groups : r;
}

/** Explicit members of a group now, to tell afterwards who a write removed. */
async function explicitMembers(env: Env, groupId: number): Promise<number[]> {
  const { results } = await env.DB.prepare("SELECT user_id FROM group_members WHERE group_id = ?").bind(groupId).all<{ user_id: number }>();
  return results.map((r) => r.user_id);
}

/** After a group write: push the group, then the members it lost (their SCIM scope may have changed). */
async function pushGroupAndRemoved(env: Env, group: GroupRow, before: number[]): Promise<ScimResult> {
  const after = new Set(await explicitMembers(env, group.id));
  const g = await pushGroupCurrent(env, group);
  const u = await pushUsersById(env, before.filter((id) => !after.has(id)));
  return g.ok ? u : g;
}

class ScimError extends Error {
  constructor(public status: number, message: string, public scimType?: string) {
    super(message);
  }
}

function scimError(c: Context<{ Bindings: Env }>, e: ScimError) {
  return c.json({ schemas: [ERROR], status: String(e.status), detail: e.message, ...(e.scimType ? { scimType: e.scimType } : {}) }, e.status as 400);
}

scimServer.onError((err, c) => {
  if (err instanceof ScimError) return scimError(c, err);
  console.error(err);
  return scimError(c, new ScimError(500, "Unexpected error."));
});

const base = (env: Env) => `${env.ISSUER_URL}/scim/v2`;

/** Holds any admin role, by static or dynamic membership in a role-linked group. */
async function holdsAdminRole(env: Env, userId: number): Promise<boolean> {
  return (await accessFor(env, userId)).isAdmin;
}

function requireAdminFor(c: Context<{ Bindings: Env }>, what: string) {
  if (!hasScope(c.get("apiActor").scopes, "admin")) throw new ScimError(403, `${what} requires an admin-scoped key.`);
}

// ---------------------------------------------------------------- discovery

scimServer.get("/scim/v2/ServiceProviderConfig", requireScope("directory:read"), (c) =>
  c.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_PAGE },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: "oauthbearertoken", name: "FlareID API key", description: "Authorization: Bearer <API key> (directory:read / directory:write)" }],
  })
);

scimServer.get("/scim/v2/ResourceTypes", requireScope("directory:read"), (c) =>
  c.json({
    schemas: [LIST],
    totalResults: 2,
    Resources: [
      { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: USER, schemaExtensions: [{ schema: ENTERPRISE, required: false }] },
      { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "Group", name: "Group", endpoint: "/Groups", schema: GROUP },
    ],
  })
);

// RFC 7643 §7 schema documents for the three URNs we emit. Clients like SCIM
// Verify and Entra read `attributes` to learn which fields the server
// supports and which are required, so list the emitted surface faithfully.
const SCHEMA_ATTRS: Record<string, unknown[]> = {
  [USER]: [
    { name: "userName", type: "string", multiValued: false, required: true, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "server" },
    { name: "name", type: "complex", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none",
      subAttributes: [
        { name: "formatted", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
        { name: "familyName", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
        { name: "givenName", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
      ] },
    { name: "displayName", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
    { name: "title", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
    { name: "active", type: "boolean", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
    { name: "externalId", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
    { name: "emails", type: "complex", multiValued: true, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none",
      subAttributes: [
        { name: "value", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
        { name: "type", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
        { name: "primary", type: "boolean", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
      ] },
    { name: "groups", type: "complex", multiValued: true, required: false, caseExact: false, mutability: "readOnly", returned: "default", uniqueness: "none",
      subAttributes: [
        { name: "value", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readOnly", returned: "default", uniqueness: "none" },
        { name: "$ref", type: "reference", multiValued: false, required: false, caseExact: false, mutability: "readOnly", returned: "default", uniqueness: "none", referenceTypes: ["Group"] },
        { name: "display", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readOnly", returned: "default", uniqueness: "none" },
      ] },
  ],
  [ENTERPRISE]: [
    { name: "department", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
    { name: "employeeNumber", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
    { name: "manager", type: "complex", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none",
      subAttributes: [
        { name: "value", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none" },
        { name: "$ref", type: "reference", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none", referenceTypes: ["User"] },
        { name: "displayName", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readOnly", returned: "default", uniqueness: "none" },
      ] },
  ],
  [GROUP]: [
    { name: "displayName", type: "string", multiValued: false, required: true, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "server" },
    { name: "members", type: "complex", multiValued: true, required: false, caseExact: false, mutability: "readWrite", returned: "request", uniqueness: "none",
      subAttributes: [
        { name: "value", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "request", uniqueness: "none" },
        { name: "$ref", type: "reference", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "request", uniqueness: "none", referenceTypes: ["User"] },
        { name: "display", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readOnly", returned: "request", uniqueness: "none" },
      ] },
  ],
};

scimServer.get("/scim/v2/Schemas", requireScope("directory:read"), (c) =>
  c.json({
    schemas: [LIST],
    totalResults: 3,
    Resources: [
      { id: USER, name: "User", description: "User account" },
      { id: ENTERPRISE, name: "EnterpriseUser", description: "Enterprise user extension" },
      { id: GROUP, name: "Group", description: "Group" },
    ].map((s) => ({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"], ...s, attributes: SCHEMA_ATTRS[s.id] })),
  })
);

// ----------------------------------------------------------------- mapping

async function userResource(env: Env, u: UserRow) {
  const manager = u.manager_external_id ? await getUserByExternalId(env, u.manager_external_id) : null;
  const { results: groups } = await env.DB.prepare("SELECT g.id, g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?")
    .bind(u.id)
    .all<{ id: number; name: string }>();
  const emails = await listUserEmails(env, u.id);
  return {
    schemas: [USER, ENTERPRISE],
    id: u.external_id,
    userName: u.upn,
    ...(u.source_id ? { externalId: u.source_id } : {}),
    name: { givenName: u.given_name, familyName: u.family_name, formatted: u.display_name },
    displayName: u.display_name,
    title: u.job_title || undefined,
    active: u.status === "active",
    emails: emails.length > 0
      ? emails.map((e) => ({ value: e.email, type: e.type, primary: e.is_primary === 1 }))
      : [{ value: u.email || u.upn, primary: true, type: "work" }],
    groups: groups.map((g) => ({ value: String(g.id), display: g.name, $ref: `${base(env)}/Groups/${g.id}` })),
    [ENTERPRISE]: {
      department: u.department || undefined,
      employeeNumber: u.employee_number || undefined,
      ...(manager ? { manager: { value: manager.external_id, displayName: manager.display_name } } : {}),
    },
    meta: { resourceType: "User", created: u.created_at, lastModified: u.updated_at, location: `${base(env)}/Users/${u.external_id}` },
  };
}

type MemberRef = { id: number; external_id: string; display_name: string };

/** SCIM member references for user ids, in one query. */
async function memberRefs(env: Env, ids: number[]): Promise<Map<number, MemberRef>> {
  if (!ids.length) return new Map();
  const { results } = await env.DB.prepare("SELECT id, external_id, display_name FROM users WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(ids)).all<MemberRef>();
  return new Map(results.map((r) => [r.id, r]));
}

/**
 * A Group resource. `members` is the resolved member list (user ids plus their
 * references), or null to leave the attribute out - a list asked not to return
 * it resolves nobody.
 */
function groupResourceFrom(env: Env, g: GroupRow, members: MemberRef[] | null) {
  return {
    schemas: [GROUP],
    id: String(g.id),
    displayName: g.name,
    ...(members ? { members: members.map((m) => ({ value: m.external_id, display: m.display_name, $ref: `${base(env)}/Users/${m.external_id}` })) } : {}),
    meta: { resourceType: "Group", location: `${base(env)}/Groups/${g.id}` },
  };
}

async function groupResource(env: Env, g: GroupRow) {
  const ids = await resolveGroupMemberUserIds(env, g);
  const refs = await memberRefs(env, ids);
  return groupResourceFrom(env, g, ids.map((id) => refs.get(id)).filter((m): m is MemberRef => Boolean(m)));
}

/**
 * Whether a list request wants the members attribute (RFC 7644 3.4.2.5): not
 * when `excludedAttributes` names it, nor when `attributes` is given without it.
 */
function wantsMembers(c: Context<{ Bindings: Env }>): boolean {
  const names = (q: string | undefined) =>
    (q ?? "").split(",").map((a) => a.trim().toLowerCase().replace(`${GROUP.toLowerCase()}:`, "").split(".")[0]!).filter(Boolean);
  if (names(c.req.query("excludedAttributes")).includes("members")) return false;
  const attributes = names(c.req.query("attributes"));
  return attributes.length === 0 || attributes.includes("members");
}

/** Only `attr eq "value"` is supported - what SCIM clients actually send to look a resource up. */
function parseFilter(filter: string | undefined, allowed: Record<string, string>): { column: string; value: string } | null {
  if (!filter) return null;
  const m = /^\s*([A-Za-z.]+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i.exec(filter);
  const key = m ? m[1]!.toLowerCase() : "";
  const column = m && Object.hasOwn(allowed, key) ? allowed[key] : undefined;
  if (!m || !column) throw new ScimError(400, `Unsupported filter. Supported: ${Object.keys(allowed).join(", ")} eq "value".`, "invalidFilter");
  return { column, value: m[2]!.replace(/\\(.)/g, "$1") };
}

function paging(c: Context<{ Bindings: Env }>) {
  const startIndex = Math.min(1_000_000, Math.max(1, Math.floor(Number(c.req.query("startIndex")) || 1)));
  const count = Math.min(MAX_PAGE, Math.max(0, Number(c.req.query("count") ?? 100) || 0));
  return { startIndex, count };
}

// ------------------------------------------------------------------- Users

/**
 * RFC 7644 §3.4.2.3 sorting: an ORDER BY clause for the attributes clients
 * actually sort on; anything else falls back to insertion order rather than
 * erroring, so a provisioner sending an unsupported sortBy still works.
 */
function sorting(c: Context<{ Bindings: Env }>, map: Record<string, string>): string {
  const col = map[(c.req.query("sortBy") ?? "").toLowerCase()];
  if (!col) return " ORDER BY id";
  const dir = (c.req.query("sortOrder") ?? "").toLowerCase() === "descending" ? "DESC" : "ASC";
  return ` ORDER BY ${col} COLLATE NOCASE ${dir}`;
}

scimServer.get("/scim/v2/Users", requireScope("directory:read"), async (c) => {
  const f = parseFilter(c.req.query("filter"), { username: "upn", externalid: "external_id", "emails.value": "email" });
  const { startIndex, count } = paging(c);
  const where = f ? `WHERE ${f.column} = ?` : "";
  const args = f ? [f.column === "upn" || f.column === "email" ? f.value.toLowerCase() : f.value] : [];
  const order = sorting(c, { username: "upn", displayname: "display_name" });
  const total = (await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM users ${where}`).bind(...args).first<{ n: number }>())?.n ?? 0;
  const { results } = await c.env.DB.prepare(`SELECT * FROM users ${where}${order} LIMIT ? OFFSET ?`).bind(...args, count, startIndex - 1).all<UserRow>();
  return c.json({ schemas: [LIST], totalResults: total, startIndex, itemsPerPage: results.length, Resources: await Promise.all(results.map((u) => userResource(c.env, u))) });
});

async function loadUser(c: Context<{ Bindings: Env }>): Promise<UserRow> {
  const user = await getUserByExternalId(c.env, c.req.param("id") ?? "");
  if (!user) throw new ScimError(404, "No such user.");
  return user;
}

scimServer.get("/scim/v2/Users/:id", requireScope("directory:read"), async (c) => c.json(await userResource(c.env, await loadUser(c))));

interface ScimUserBody {
  userName?: string;
  externalId?: string;
  name?: { givenName?: string; familyName?: string; formatted?: string };
  displayName?: string;
  title?: string;
  active?: boolean;
  emails?: { value?: string; primary?: boolean; type?: string }[];
  photos?: { value?: string; primary?: boolean; type?: string }[];
  [ENTERPRISE]?: { department?: string; employeeNumber?: string; manager?: { value?: string } | string };
  [key: string]: unknown;
}

/**
 * Columns a SCIM user body sets, plus its address list, custom-attribute
 * changes, and any mapping-derived userName. Only what is present is changed
 * (PUT callers send everything anyway). `doc` is the document configured
 * mappings evaluate over: the body itself for POST/PUT, or the body merged
 * onto the current resource for PATCH, where `partial` keeps an expression
 * yielding nothing from clearing the field.
 */
async function columnsFrom(env: Env, body: ScimUserBody, opts?: { doc?: unknown; partial?: boolean }): Promise<{ cols: Record<string, string | null>; emails: UserEmailInput[] | undefined; custom: Record<string, string | null> | undefined; userName: string | undefined; photo: string | null | undefined }> {
  const cols: Record<string, string | null> = {};
  if (body.externalId !== undefined) cols.source_id = String(body.externalId) || null;
  if (body.name?.givenName !== undefined) cols.given_name = String(body.name.givenName);
  if (body.name?.familyName !== undefined) cols.family_name = String(body.name.familyName);
  if (body.displayName !== undefined || body.name?.formatted !== undefined) cols.display_name = String(body.displayName ?? body.name?.formatted);
  if (body.title !== undefined) cols.job_title = String(body.title);
  if (body.active !== undefined) {
    const active = typeof body.active === "string" ? (body.active as string).trim().toLowerCase() === "true" : body.active === true;
    cols.status = active ? "active" : "disabled";
  }
  const ent = body[ENTERPRISE];
  if (ent?.department !== undefined) cols.department = String(ent.department);
  if (ent?.employeeNumber !== undefined) cols.employee_number = String(ent.employeeNumber);
  if (ent?.manager !== undefined) {
    const ref = typeof ent.manager === "string" ? ent.manager : ent.manager?.value;
    cols.manager_external_id = ref ? await resolveManagerRef(env, ref) : null;
  }
  // The whole list lands in user_emails; the primary mirrors into users.email.
  // Format is refused here, before anything has been written (ownership is
  // enforced inside setUserEmails, where the target user is known).
  let emails: UserEmailInput[] | undefined = body.emails
    ? body.emails
        .filter((e) => e && typeof e.value === "string" && e.value.trim())
        .map((e) => ({ value: String(e.value), type: e.type ?? "work", primary: e.primary === true }))
    : undefined;
  let custom: Record<string, string | null> | undefined;
  let userName: string | undefined;
  try {
    const mapped = await applyUserMappings(env, opts?.doc ?? body, { partial: opts?.partial ?? false });
    Object.assign(cols, mapped.cols);
    if (mapped.emails !== undefined) emails = mapped.emails;
    if (mapped.custom) custom = mapped.custom;
    userName = mapped.userName;
  } catch (e) {
    if (e instanceof ScimMappingError) throw new ScimError(400, e.message, "invalidValue");
    throw e;
  }
  for (const e of emails ?? []) {
    if (!isEmailAddress(e.value.trim())) throw new ScimError(400, `"${e.value}" is not a valid email address.`, "invalidValue");
  }
  // photos[] comes along for the side write in applyColumns: the primary (or
  // first) value, an empty list clearing the stored photo.
  let photo: string | null | undefined;
  if (Array.isArray(body.photos)) {
    const list = body.photos.filter((p) => p && typeof p.value === "string" && p.value.trim());
    photo = list.length ? String((list.find((p) => p.primary) ?? list[0])!.value) : null;
  }
  return { cols, emails, custom, userName, photo };
}

/**
 * The custom-attribute merge, done BEFORE the admin-role guard runs - a rule
 * on a dynamic group can match an attribute, so the guard must see the
 * post-merge set, not just the mapped columns. `currentJson` is the row's
 * stored attributes; null deletes a key. Returns nothing when there is no
 * custom write.
 */
function mergedCustomAttributes(currentJson: string | null | undefined, custom: Record<string, string | null> | undefined): string | undefined {
  if (!custom || !Object.keys(custom).length) return undefined;
  const attrs = JSON.parse(currentJson ?? "{}") as Record<string, unknown>;
  for (const [k, v] of Object.entries(custom)) {
    if (v === null) delete attrs[k];
    else attrs[k] = v;
  }
  return JSON.stringify(attrs);
}

async function applyColumns(env: Env, userId: number, cols: Record<string, string | null>, emails: UserEmailInput[] | undefined, photo?: string | null) {
  const keys = Object.keys(cols);
  if (keys.length > 0) {
    await env.DB.prepare(`UPDATE users SET ${keys.map((k) => `${k} = ?`).join(", ")}, updated_at = ? WHERE id = ?`)
      .bind(...keys.map((k) => cols[k]), new Date().toISOString(), userId)
      .run();
  }
  let emailsChanged = false;
  if (emails !== undefined) {
    try {
      emailsChanged = await setUserEmails(env, userId, emails);
    } catch (err) {
      if (err instanceof UserEmailError) throw new ScimError(409, err.message, "uniqueness");
      throw err;
    }
  }
  if (photo !== undefined) {
    if (photo === null) await deleteUserPhoto(env, userId);
    else await applyInboundPhoto(env, userId, photo);
  }
  // Deactivation over SCIM takes effect now, the same as in the console.
  if (cols.status === "disabled") {
    await revokeAllSessionsForUser(env, userId);
    await revokeTokensForUser(env, userId);
  } else if (emailsChanged || "email" in cols) {
    // A link already sent to the previous address must not outlive the correction.
    await revokeAccountTokens(env, userId);
  }
}

scimServer.post("/scim/v2/Users", requireScope("directory:write"), async (c) => {
  const body = await c.req.json<ScimUserBody>();
  const { cols, emails, custom, userName: mappedName, photo } = await columnsFrom(c.env, body);
  const userName = String(mappedName ?? body.userName ?? "").trim().toLowerCase();
  if (!userName) throw new ScimError(400, "userName is required.", "invalidSyntax");
  const [local, domainPart] = userName.includes("@") ? userName.split("@") : [userName, await getDefaultDomain(c.env)];
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(local!)) throw new ScimError(400, `"${local}" is not a valid username.`, "invalidValue");
  if (!(await listDomains(c.env)).some((d) => d.domain === domainPart)) throw new ScimError(400, `The domain "${domainPart}" is not configured in FlareID.`, "invalidValue");
  const upn = `${local}@${domainPart}`;
  // Correlation: the configured keys can adopt an existing account instead of
  // conflicting - a rehired person, a feed re-pointed at this IdP. The first
  // configured key with a match decides; several matches on one key is a 409.
  try {
    const matched = await correlateUser(c.env, { upn, cols, emails });
    if (matched) {
      if (await holdsAdminRole(c.env, matched.user.id)) requireAdminFor(c, "Changing an account that holds an admin role");
      const merged = mergedCustomAttributes(matched.user.custom_attributes, custom);
      if (merged !== undefined) cols.custom_attributes = merged;
      await assertNoAdminRoleGrant(c, matched.user, { ...cols, ...(emails ? { email: emails.find((e) => e.primary)?.value ?? emails[0]?.value ?? null } : {}) });
      await applyColumns(c.env, matched.user.id, cols, emails, photo);
      await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_correlated", matched.user.upn, { key: matched.key }, c.req.raw);
      const fresh = (await getUserByExternalId(c.env, matched.user.external_id))!;
      downstream(c, () => pushUserAndRules(c.env, matched.user, fresh), "update", fresh.upn);
      return c.json(await userResource(c.env, fresh), 200, { Location: `${base(c.env)}/Users/${fresh.external_id}` });
    }
  } catch (e) {
    if (e instanceof ScimMappingError) throw new ScimError(409, e.message, "uniqueness");
    throw e;
  }
  if (await c.env.DB.prepare("SELECT 1 FROM users WHERE upn = ? OR username = ?").bind(upn, local).first()) throw new ScimError(409, "A user with that userName already exists.", "uniqueness");
  if (await c.env.DB.prepare("SELECT 1 FROM user_emails WHERE email = ?").bind(upn).first()) throw new ScimError(409, "A user with that userName already exists.", "uniqueness");

  const now = new Date().toISOString();
  const externalId = crypto.randomUUID();
  // An address another account already holds refuses the create outright -
  // checked here so nothing is left behind.
  if (emails?.length) {
    try {
      await assertEmailsUsable(c.env, null, emails);
    } catch (err) {
      if (err instanceof UserEmailError) throw new ScimError(409, err.message, "uniqueness");
      throw err;
    }
  }
  // Refuse before anything is written: the check needs the row the request
  // would leave behind - the insert defaults plus the SCIM columns.
  const after = {
    upn, username: local, display_name: local, given_name: "", family_name: "", external_id: externalId,
    job_title: "", department: "", employee_number: "", hire_date: "", employment_status: "", employment_type: "",
    location: "", status: "disabled", manager_external_id: null, source_id: null, custom_attributes: "{}", ...cols,
  } as UserRow;
  const mergedAttrs = mergedCustomAttributes("{}", custom);
  if (mergedAttrs !== undefined) {
    after.custom_attributes = mergedAttrs;
    cols.custom_attributes = mergedAttrs;
  }
  if (!hasScope(c.get("apiActor").scopes, "admin")) {
    const granted = await grantsAdminRoleGroup(c.env, null, after);
    if (granted) throw new ScimError(403, `Provisioning into ${granted}, an admin role group, requires an admin-scoped key.`);
  }
  // No usable password ("!"): an inbound-provisioned account activates by invitation or reset.
  const inserted = await c.env.DB.prepare(
    `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department, employee_number, hire_date, employment_status, employment_type, location, password_hash, password_salt, password_iterations, is_admin, status, schema_id, custom_attributes, created_at, updated_at)
     VALUES (?, ?, ?, '', '', ?, '', '', '', '', '', '', '', '!', '', 0, 0, 'disabled', ?, '{}', ?, ?) RETURNING id`
  )
    .bind(upn, local, local, externalId, await defaultSchemaId(c.env, "user"), now, now)
    .first<{ id: number }>();
  await applyColumns(c.env, inserted!.id, cols, emails, photo);
  const user = (await getUserByExternalId(c.env, externalId))!;
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_created", upn, undefined, c.req.raw);
  downstream(c, () => pushUserAndRules(c.env, null, user), "create", upn);
  return c.json(await userResource(c.env, user), 201, { Location: `${base(c.env)}/Users/${externalId}` });
});

async function guardedUser(c: Context<{ Bindings: Env }>): Promise<UserRow> {
  const user = await loadUser(c);
  if (await holdsAdminRole(c.env, user.id)) requireAdminFor(c, "Changing an account that holds an admin role");
  return user;
}

/**
 * An attribute write must not move the user into a dynamic group linked to an
 * admin role either: department = "OnCall" can be an admin grant when a rule
 * says so. `before` is null on the create path; `cols` are the columns about
 * to be applied, merged onto the row to get the post-write state.
 */
async function assertNoAdminRoleGrant(c: Context<{ Bindings: Env }>, user: UserRow | null, cols: Record<string, string | null>) {
  if (hasScope(c.get("apiActor").scopes, "admin")) return;
  const granted = await grantsAdminRoleGroup(c.env, user, { ...(user ?? {}), ...cols } as UserRow);
  if (granted) throw new ScimError(403, `This change moves the user into ${granted}, an admin role group, which requires an admin-scoped key.`);
}

scimServer.put("/scim/v2/Users/:id", requireScope("directory:write"), async (c) => {
  const user = await guardedUser(c);
  const body = await c.req.json<ScimUserBody>();
  const { cols, emails, custom, photo } = await columnsFrom(c.env, body);
  const merged = mergedCustomAttributes(user.custom_attributes, custom);
  if (merged !== undefined) cols.custom_attributes = merged;
  await assertNoAdminRoleGrant(c, user, { ...cols, ...(emails ? { email: emails.find((e) => e.primary)?.value ?? emails[0]?.value ?? null } : {}) });
  await applyColumns(c.env, user.id, cols, emails, photo);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_replaced", user.upn, undefined, c.req.raw);
  const fresh = (await getUserByExternalId(c.env, user.external_id))!;
  downstream(c, () => pushUserAndRules(c.env, user, fresh), "update", fresh.upn);
  return c.json(await userResource(c.env, fresh));
});

/** PATCH operations as clients send them: path-less replace objects, or paths like "active" and "name.givenName". */
function patchToBody(ops: { op?: string; path?: string; value?: unknown }[]): ScimUserBody {
  const body: Record<string, unknown> = {};
  for (const op of ops) {
    const kind = String(op.op ?? "").toLowerCase();
    if (kind !== "replace" && kind !== "add") throw new ScimError(400, `Unsupported PATCH op "${op.op}" for users.`, "invalidSyntax");
    if (!op.path) {
      Object.assign(body, op.value as object);
      continue;
    }
    const path = op.path.replace(`${ENTERPRISE}:`, `${ENTERPRISE}.`);
    if (path.startsWith(`${ENTERPRISE}.`)) {
      const key = path.slice(ENTERPRISE.length + 1);
      body[ENTERPRISE] = { ...((body[ENTERPRISE] as object) ?? {}), [key]: op.value };
    } else if (path.startsWith("name.")) {
      body.name = { ...((body.name as object) ?? {}), [path.slice(5)]: op.value };
    } else if (path.startsWith("emails")) {
      const v = op.value;
      body.emails = Array.isArray(v) ? v : [{ value: typeof v === "object" && v ? (v as { value?: string }).value : v, primary: true }];
    } else {
      body[path] = path === "active" && typeof op.value === "string" ? op.value.toLowerCase() === "true" : op.value;
    }
  }
  return body as ScimUserBody;
}

scimServer.patch("/scim/v2/Users/:id", requireScope("directory:write"), async (c) => {
  const user = await guardedUser(c);
  const body = await c.req.json<{ schemas?: string[]; Operations?: { op?: string; path?: string; value?: unknown }[] }>();
  if (!body.schemas?.includes(PATCH_OP) || !Array.isArray(body.Operations)) throw new ScimError(400, "Expected a PatchOp message.", "invalidSyntax");
  const patchBody = patchToBody(body.Operations);
  // Mappings see the patch applied to the current resource, so an expression
  // can combine the changed attribute with untouched ones. `partial` keeps an
  // expression that yields nothing from clearing its field.
  const doc = mergeScimBody(await userResource(c.env, user), patchBody);
  const { cols, emails, custom, photo } = await columnsFrom(c.env, patchBody, { doc, partial: true });
  const merged = mergedCustomAttributes(user.custom_attributes, custom);
  if (merged !== undefined) cols.custom_attributes = merged;
  await assertNoAdminRoleGrant(c, user, { ...cols, ...(emails ? { email: emails.find((e) => e.primary)?.value ?? emails[0]?.value ?? null } : {}) });
  await applyColumns(c.env, user.id, cols, emails, photo);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_patched", user.upn, { ops: body.Operations.length }, c.req.raw);
  const fresh = (await getUserByExternalId(c.env, user.external_id))!;
  downstream(c, () => pushUserAndRules(c.env, user, fresh), "update", fresh.upn);
  return c.json(await userResource(c.env, fresh));
});

scimServer.delete("/scim/v2/Users/:id", requireScope("directory:write"), async (c) => {
  const user = await guardedUser(c);
  await c.env.DB.batch([...(await scimDeprovisionStatements(c.env, "user", user.id, user.upn)), ...deleteUserStatements(c.env, user.id)]);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_deleted", user.upn, undefined, c.req.raw);
  // The row (and its links) is gone now; the queue still names the remote objects.
  downstream(c, async () => { const r = await drainScimDeprovisionQueue(c.env); return r.failed ? { ok: false, error: `${r.remaining} queued` } : { ok: true }; }, "delete", user.upn);
  return c.body(null, 204);
});

// ------------------------------------------------------------------ Groups

async function loadGroup(c: Context<{ Bindings: Env }>, write = false): Promise<GroupRow> {
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(Number(c.req.param("id"))).first<GroupRow>();
  if (!group) throw new ScimError(404, "No such group.");
  if (write && group.system) throw new ScimError(400, `"${group.name}" is a system group; it cannot be changed via SCIM.`);
  if (write && (group.name === SUPER_ADMINS_GROUP || (await adminRoleGroupIds(c.env)).has(group.id))) requireAdminFor(c, `Changing ${group.name}, an admin role group`);
  return group;
}

scimServer.get("/scim/v2/Groups", requireScope("directory:read"), async (c) => {
  const f = parseFilter(c.req.query("filter"), { displayname: "name" });
  const { startIndex, count } = paging(c);
  const where = f ? "WHERE name = ?" : "";
  const args = f ? [f.value] : [];
  const total = (await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM groups ${where}`).bind(...args).first<{ n: number }>())?.n ?? 0;
  const order = sorting(c, { displayname: "name" });
  const { results } = await c.env.DB.prepare(`SELECT * FROM groups ${where}${order} LIMIT ? OFFSET ?`).bind(...args, count, startIndex - 1).all<GroupRow>();
  // The page's members in one pass (one directory read for all its dynamic
  // groups, one lookup for every member), and none at all when not asked for.
  let resources;
  if (wantsMembers(c)) {
    const members = await resolveManyGroupMemberUserIds(c.env, results);
    const refs = await memberRefs(c.env, [...new Set([...members.values()].flat())]);
    resources = results.map((g) => groupResourceFrom(c.env, g, (members.get(g.id) ?? []).map((id) => refs.get(id)).filter((m): m is MemberRef => Boolean(m))));
  } else {
    resources = results.map((g) => groupResourceFrom(c.env, g, null));
  }
  return c.json({ schemas: [LIST], totalResults: total, startIndex, itemsPerPage: results.length, Resources: resources });
});

scimServer.get("/scim/v2/Groups/:id", requireScope("directory:read"), async (c) => c.json(await groupResource(c.env, await loadGroup(c))));

/** Resolves SCIM member references (user ids = external_id) to FlareID user ids, refusing administrators for non-admin keys. */
async function memberIds(c: Context<{ Bindings: Env }>, members: { value?: string }[]): Promise<number[]> {
  const ids: number[] = [];
  for (const m of members) {
    const user = m.value ? await getUserByExternalId(c.env, String(m.value)) : null;
    if (!user) throw new ScimError(400, `Unknown member "${m.value}".`, "invalidValue");
    if (await holdsAdminRole(c.env, user.id)) requireAdminFor(c, "Changing an administrator's group memberships");
    ids.push(user.id);
  }
  return ids;
}

/** A rename may not take an admin role group's name either (it is free only if an admin removed the link first). */
async function guardNewName(c: Context<{ Bindings: Env }>, name: string | undefined) {
  if (name === undefined) return;
  const trimmed = name.trim();
  if ((await adminRoleGroupNames(c.env)).includes(trimmed)) requireAdminFor(c, `Naming a group ${trimmed}`);
}

/** Whether any explicit member of the group holds an admin role - statically, or by matching a role-linked group's rule. */
async function groupHasAdminMember(env: Env, groupId: number, roleGroups: Set<number>): Promise<boolean> {
  if (!roleGroups.size) return false;
  const ids = JSON.stringify([...roleGroups]);
  const hit = await env.DB.prepare(
    "SELECT 1 FROM group_members gm JOIN group_members rg ON rg.user_id = gm.user_id WHERE gm.group_id = ? AND rg.group_id IN (SELECT value FROM json_each(?)) LIMIT 1"
  ).bind(groupId, ids).first();
  if (hit) return true;
  const { results: dyn } = await env.DB.prepare("SELECT id, rule FROM groups WHERE rule != '' AND id IN (SELECT value FROM json_each(?))").bind(ids).all<{ id: number; rule: string }>();
  if (!dyn.length) return false;
  const { results: members } = await env.DB.prepare("SELECT u.* FROM users u JOIN group_members gm ON gm.user_id = u.id WHERE gm.group_id = ?").bind(groupId).all<UserRow>();
  for (const d of dyn) {
    const rule = parseRule(d.rule);
    if (rule && members.some((u) => userMatchesRule(u, rule))) return true;
  }
  return false;
}

/**
 * The statements for one membership change, not yet run: a request commits all
 * of its operations in one batch, so a later failing operation leaves nothing
 * half-applied (RFC 7644 3.5.2 - PATCH is all or nothing).
 */
async function memberStatements(env: Env, group: GroupRow, add: number[], remove: number[] | "all", c?: Context<{ Bindings: Env }>): Promise<D1PreparedStatement[]> {
  if (group.rule) throw new ScimError(400, "This is a dynamic group: its membership is its rule.", "mutability");
  // Replacing or clearing the member list acts on every member - including any administrator.
  if (remove === "all" && c && !hasScope(c.get("apiActor").scopes, "admin")) {
    if (await groupHasAdminMember(env, group.id, await adminRoleGroupIds(env)))
      throw new ScimError(403, "Replacing the members of a group that contains an administrator requires an admin-scoped key.");
  }
  const stmts: D1PreparedStatement[] = [];
  if (remove === "all") stmts.push(env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(group.id));
  else for (const id of remove) stmts.push(env.DB.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").bind(group.id, id));
  for (const id of add) stmts.push(env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(group.id, id));
  return stmts;
}

async function setMembers(env: Env, group: GroupRow, add: number[], remove: number[] | "all", c?: Context<{ Bindings: Env }>) {
  const stmts = await memberStatements(env, group, add, remove, c);
  if (stmts.length) await env.DB.batch(stmts);
}

scimServer.post("/scim/v2/Groups", requireScope("directory:write"), async (c) => {
  const body = await c.req.json<{ displayName?: string; members?: { value?: string }[] }>();
  const name = String(body.displayName ?? "").trim();
  if (!name) throw new ScimError(400, "displayName is required.", "invalidSyntax");
  if ((await adminRoleGroupNames(c.env)).includes(name)) requireAdminFor(c, `Creating an admin role group`);
  if (await c.env.DB.prepare("SELECT 1 FROM groups WHERE name = ?").bind(name).first()) throw new ScimError(409, "A group with that displayName already exists.", "uniqueness");
  const row = await c.env.DB.prepare("INSERT INTO groups (name, description, rule) VALUES (?, NULL, '') RETURNING *").bind(name).first<GroupRow>();
  await setMembers(c.env, row!, await memberIds(c, body.members ?? []), []);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.group_created", name, undefined, c.req.raw);
  downstream(c, () => pushGroupCurrent(c.env, row!), "create", name);
  return c.json(await groupResource(c.env, row!), 201, { Location: `${base(c.env)}/Groups/${row!.id}` });
});

scimServer.put("/scim/v2/Groups/:id", requireScope("directory:write"), async (c) => {
  const group = await loadGroup(c, true);
  const body = await c.req.json<{ displayName?: string; members?: { value?: string }[] }>();
  await guardNewName(c, body.displayName);
  const membersBefore = await explicitMembers(c.env, group.id);
  // Everything is resolved and checked before anything is written.
  const stmts: D1PreparedStatement[] = [];
  if (body.displayName && body.displayName !== group.name) stmts.push(c.env.DB.prepare("UPDATE groups SET name = ? WHERE id = ?").bind(body.displayName.trim(), group.id));
  if (body.members !== undefined) stmts.push(...(await memberStatements(c.env, group, await memberIds(c, body.members), "all", c)));
  if (stmts.length) await c.env.DB.batch(stmts);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.group_replaced", group.name, undefined, c.req.raw);
  const replaced = await loadGroup(c);
  downstream(c, () => pushGroupAndRemoved(c.env, replaced, membersBefore), "update", replaced.name);
  return c.json(await groupResource(c.env, (await loadGroup(c))!));
});

scimServer.patch("/scim/v2/Groups/:id", requireScope("directory:write"), async (c) => {
  const group = await loadGroup(c, true);
  const body = await c.req.json<{ schemas?: string[]; Operations?: { op?: string; path?: string; value?: unknown }[] }>();
  if (!body.schemas?.includes(PATCH_OP) || !Array.isArray(body.Operations)) throw new ScimError(400, "Expected a PatchOp message.", "invalidSyntax");
  const membersBefore = await explicitMembers(c.env, group.id);
  const stmts: D1PreparedStatement[] = [];
  for (const op of body.Operations) {
    const kind = String(op.op ?? "").toLowerCase();
    const path = op.path ?? "";
    const value = op.value as { value?: string }[] | { displayName?: string; members?: { value?: string }[] } | string | undefined;
    if ((path === "displayName" || (!path && typeof value === "object" && value && "displayName" in value)) && kind === "replace") {
      const name = typeof value === "string" ? value : (value as { displayName?: string }).displayName;
      await guardNewName(c, name);
      if (name) stmts.push(c.env.DB.prepare("UPDATE groups SET name = ? WHERE id = ?").bind(name.trim(), group.id));
      continue;
    }
    if (path === "members" || (!path && typeof value === "object" && value && "members" in value)) {
      const list = Array.isArray(value) ? value : ((value as { members?: { value?: string }[] })?.members ?? []);
      if (kind === "add") stmts.push(...(await memberStatements(c.env, group, await memberIds(c, list), [])));
      else if (kind === "replace") stmts.push(...(await memberStatements(c.env, group, await memberIds(c, list), "all", c)));
      else if (kind === "remove") stmts.push(...(await memberStatements(c.env, group, [], list.length ? await memberIds(c, list) : "all", c)));
      else throw new ScimError(400, `Unsupported PATCH op "${op.op}".`, "invalidSyntax");
      continue;
    }
    // members[value eq "<id>"] - the form Azure AD and others use for removal.
    const one = /^members\[value eq "([^"]+)"\]$/.exec(path);
    if (one && kind === "remove") {
      stmts.push(...(await memberStatements(c.env, group, [], await memberIds(c, [{ value: one[1] }]))));
      continue;
    }
    throw new ScimError(400, `Unsupported PATCH path "${path}".`, "invalidPath");
  }
  if (stmts.length) await c.env.DB.batch(stmts);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.group_patched", group.name, { ops: body.Operations.length }, c.req.raw);
  const patched = await loadGroup(c);
  downstream(c, () => pushGroupAndRemoved(c.env, patched, membersBefore), "update", patched.name);
  return c.json(await groupResource(c.env, await loadGroup(c)));
});

scimServer.delete("/scim/v2/Groups/:id", requireScope("directory:write"), async (c) => {
  const group = await loadGroup(c, true);
  if (group.name === SUPER_ADMINS_GROUP) throw new ScimError(400, `${SUPER_ADMINS_GROUP} cannot be deleted.`, "mutability");
  const membersBefore = await explicitMembers(c.env, group.id);
  // Queued with the deletion, like users: the remote id must survive a failed DELETE.
  await c.env.DB.batch([
    ...(await scimDeprovisionStatements(c.env, "group", group.id, group.name)),
    c.env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(group.id),
    c.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(group.id),
  ]);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.group_deleted", group.name, undefined, c.req.raw);
  downstream(c, async () => {
    const d = await drainScimDeprovisionQueue(c.env);
    const u = await pushUsersById(c.env, membersBefore);
    return d.failed ? { ok: false, error: `${d.remaining} queued` } : u;
  }, "delete", group.name);
  return c.body(null, 204);
});

import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { auditActor, requireApiAuth, requireScope } from "../lib/api-auth.js";
import { hasScope } from "../lib/api-keys.js";
import { logAudit } from "../lib/audit.js";
import { getUserByExternalId } from "../lib/db.js";
import { listDomains, getDefaultDomain } from "../lib/domains.js";
import { resolveGroupMemberUserIds } from "../lib/groups.js";
import { defaultSchemaId } from "../lib/schemas.js";
import { deleteUserStatements, revokeAllSessionsForUser, revokeTokensForUser } from "../lib/sessions.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { revokeAccountTokens } from "../lib/account-tokens.js";
import { deactivateUserScim, deleteGroupScim, drainScimDeprovisionQueue, isScimConfigured, pushDynamicGroups, pushGroupCurrent, pushUser, queueScimDeprovision, type ScimResult } from "../lib/scim-client.js";

/**
 * SCIM 2.0 server (RFC 7643/7644) for inbound provisioning: an HR system or
 * upstream directory creates, updates and deprovisions FlareID users and
 * groups. Mounted at /scim/v2, authenticated with a FlareID API key
 * (directory:read to read, directory:write to change).
 *
 * Mapping: a User's id is its external_id (a stable UUID), userName its UPN;
 * a Group's id is its numeric id as a string. The same boundaries as the
 * import API apply: Super Admins - the group and its members - are out of a
 * non-admin key's reach, and dynamic groups take no members (their membership
 * is their rule).
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
async function pushUserAndRules(env: Env, user: UserRow): Promise<ScimResult> {
  const r = user.status === "active" ? await pushUser(env, user) : await deactivateUserScim(env, user);
  return r.ok ? pushDynamicGroups(env) : r;
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

async function isSuperAdmin(env: Env, userId: number): Promise<boolean> {
  return Boolean(
    await env.DB.prepare("SELECT 1 FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.name = ?").bind(userId, SUPER_ADMINS_GROUP).first()
  );
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

scimServer.get("/scim/v2/Schemas", requireScope("directory:read"), (c) =>
  c.json({ schemas: [LIST], totalResults: 3, Resources: [USER, ENTERPRISE, GROUP].map((id) => ({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"], id })) })
);

// ----------------------------------------------------------------- mapping

async function userResource(env: Env, u: UserRow) {
  const manager = u.manager_external_id ? await getUserByExternalId(env, u.manager_external_id) : null;
  const { results: groups } = await env.DB.prepare("SELECT g.id, g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id WHERE gm.user_id = ?")
    .bind(u.id)
    .all<{ id: number; name: string }>();
  return {
    schemas: [USER, ENTERPRISE],
    id: u.external_id,
    userName: u.upn,
    name: { givenName: u.given_name, familyName: u.family_name, formatted: u.display_name },
    displayName: u.display_name,
    title: u.job_title || undefined,
    active: u.status === "active",
    emails: [{ value: u.email || u.upn, primary: true, type: "work" }],
    groups: groups.map((g) => ({ value: String(g.id), display: g.name, $ref: `${base(env)}/Groups/${g.id}` })),
    [ENTERPRISE]: {
      department: u.department || undefined,
      employeeNumber: u.employee_number || undefined,
      ...(manager ? { manager: { value: manager.external_id, displayName: manager.display_name } } : {}),
    },
    meta: { resourceType: "User", created: u.created_at, lastModified: u.updated_at, location: `${base(env)}/Users/${u.external_id}` },
  };
}

async function groupResource(env: Env, g: GroupRow) {
  const ids = await resolveGroupMemberUserIds(env, g);
  const { results } = ids.length
    ? await env.DB.prepare(`SELECT external_id, display_name FROM users WHERE id IN (SELECT value FROM json_each(?))`).bind(JSON.stringify(ids)).all<{ external_id: string; display_name: string }>()
    : { results: [] as { external_id: string; display_name: string }[] };
  return {
    schemas: [GROUP],
    id: String(g.id),
    displayName: g.name,
    members: results.map((m) => ({ value: m.external_id, display: m.display_name, $ref: `${base(env)}/Users/${m.external_id}` })),
    meta: { resourceType: "Group", location: `${base(env)}/Groups/${g.id}` },
  };
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

scimServer.get("/scim/v2/Users", requireScope("directory:read"), async (c) => {
  const f = parseFilter(c.req.query("filter"), { username: "upn", externalid: "external_id", "emails.value": "email" });
  const { startIndex, count } = paging(c);
  const where = f ? `WHERE ${f.column} = ?` : "";
  const args = f ? [f.column === "upn" || f.column === "email" ? f.value.toLowerCase() : f.value] : [];
  const total = (await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM users ${where}`).bind(...args).first<{ n: number }>())?.n ?? 0;
  const { results } = await c.env.DB.prepare(`SELECT * FROM users ${where} ORDER BY id LIMIT ? OFFSET ?`).bind(...args, count, startIndex - 1).all<UserRow>();
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
  name?: { givenName?: string; familyName?: string; formatted?: string };
  displayName?: string;
  title?: string;
  active?: boolean;
  emails?: { value?: string; primary?: boolean }[];
  [ENTERPRISE]?: { department?: string; employeeNumber?: string; manager?: { value?: string } | string };
}

/** Columns a SCIM user body sets. Only what is present is changed (PUT callers send everything anyway). */
async function columnsFrom(env: Env, body: ScimUserBody): Promise<Record<string, string | null>> {
  const cols: Record<string, string | null> = {};
  if (body.name?.givenName !== undefined) cols.given_name = String(body.name.givenName);
  if (body.name?.familyName !== undefined) cols.family_name = String(body.name.familyName);
  if (body.displayName !== undefined || body.name?.formatted !== undefined) cols.display_name = String(body.displayName ?? body.name?.formatted);
  if (body.title !== undefined) cols.job_title = String(body.title);
  if (body.active !== undefined) {
    const active = typeof body.active === "string" ? (body.active as string).trim().toLowerCase() === "true" : body.active === true;
    cols.status = active ? "active" : "disabled";
  }
  if (body.emails) {
    const primary = body.emails.find((e) => e.primary) ?? body.emails[0];
    if (primary?.value) cols.email = String(primary.value).toLowerCase();
  }
  const ent = body[ENTERPRISE];
  if (ent?.department !== undefined) cols.department = String(ent.department);
  if (ent?.employeeNumber !== undefined) cols.employee_number = String(ent.employeeNumber);
  if (ent?.manager !== undefined) {
    const ref = typeof ent.manager === "string" ? ent.manager : ent.manager?.value;
    cols.manager_external_id = ref ? ((await getUserByExternalId(env, ref))?.external_id ?? null) : null;
  }
  return cols;
}

async function applyColumns(env: Env, userId: number, cols: Record<string, string | null>) {
  const keys = Object.keys(cols);
  if (keys.length === 0) return;
  await env.DB.prepare(`UPDATE users SET ${keys.map((k) => `${k} = ?`).join(", ")}, updated_at = ? WHERE id = ?`)
    .bind(...keys.map((k) => cols[k]), new Date().toISOString(), userId)
    .run();
  // Deactivation over SCIM takes effect now, the same as in the console.
  if (cols.status === "disabled") {
    await revokeAllSessionsForUser(env, userId);
    await revokeTokensForUser(env, userId);
  } else if ("email" in cols) {
    // A link already sent to the previous address must not outlive the correction.
    await revokeAccountTokens(env, userId);
  }
}

scimServer.post("/scim/v2/Users", requireScope("directory:write"), async (c) => {
  const body = await c.req.json<ScimUserBody>();
  const userName = String(body.userName ?? "").trim().toLowerCase();
  if (!userName) throw new ScimError(400, "userName is required.", "invalidValue");
  const [local, domainPart] = userName.includes("@") ? userName.split("@") : [userName, await getDefaultDomain(c.env)];
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(local!)) throw new ScimError(400, `"${local}" is not a valid username.`, "invalidValue");
  if (!(await listDomains(c.env)).some((d) => d.domain === domainPart)) throw new ScimError(400, `The domain "${domainPart}" is not configured in FlareID.`, "invalidValue");
  const upn = `${local}@${domainPart}`;
  if (await c.env.DB.prepare("SELECT 1 FROM users WHERE upn = ? OR username = ?").bind(upn, local).first()) throw new ScimError(409, "A user with that userName already exists.", "uniqueness");

  const now = new Date().toISOString();
  const externalId = crypto.randomUUID();
  // No usable password ("!"): an inbound-provisioned account activates by invitation or reset.
  const inserted = await c.env.DB.prepare(
    `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department, employee_number, hire_date, employment_status, employment_type, location, password_hash, password_salt, password_iterations, is_admin, status, schema_id, custom_attributes, created_at, updated_at)
     VALUES (?, ?, ?, '', '', ?, '', '', '', '', '', '', '', '!', '', 0, 0, 'disabled', ?, '{}', ?, ?) RETURNING id`
  )
    .bind(upn, local, local, externalId, await defaultSchemaId(c.env, "user"), now, now)
    .first<{ id: number }>();
  await applyColumns(c.env, inserted!.id, await columnsFrom(c.env, body));
  const user = (await getUserByExternalId(c.env, externalId))!;
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_created", upn, undefined, c.req.raw);
  downstream(c, () => pushUserAndRules(c.env, user), "create", upn);
  return c.json(await userResource(c.env, user), 201, { Location: `${base(c.env)}/Users/${externalId}` });
});

async function guardedUser(c: Context<{ Bindings: Env }>): Promise<UserRow> {
  const user = await loadUser(c);
  if (await isSuperAdmin(c.env, user.id)) requireAdminFor(c, "Changing a Super Admin");
  return user;
}

scimServer.put("/scim/v2/Users/:id", requireScope("directory:write"), async (c) => {
  const user = await guardedUser(c);
  const body = await c.req.json<ScimUserBody>();
  await applyColumns(c.env, user.id, await columnsFrom(c.env, body));
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_replaced", user.upn, undefined, c.req.raw);
  const fresh = (await getUserByExternalId(c.env, user.external_id))!;
  downstream(c, () => pushUserAndRules(c.env, fresh), "update", fresh.upn);
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
  await applyColumns(c.env, user.id, await columnsFrom(c.env, patchToBody(body.Operations)));
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_patched", user.upn, { ops: body.Operations.length }, c.req.raw);
  const fresh = (await getUserByExternalId(c.env, user.external_id))!;
  downstream(c, () => pushUserAndRules(c.env, fresh), "update", fresh.upn);
  return c.json(await userResource(c.env, fresh));
});

scimServer.delete("/scim/v2/Users/:id", requireScope("directory:write"), async (c) => {
  const user = await guardedUser(c);
  await c.env.DB.batch([...(user.scim_id ? [queueScimDeprovision(c.env, "user", user.scim_id, user.upn)] : []), ...deleteUserStatements(c.env, user.id)]);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.user_deleted", user.upn, undefined, c.req.raw);
  // The row (and its scim_id) is gone now; the captured copy still names the remote user.
  downstream(c, async () => { const r = await drainScimDeprovisionQueue(c.env); return r.failed ? { ok: false, error: `${r.remaining} queued` } : { ok: true }; }, "delete", user.upn);
  return c.body(null, 204);
});

// ------------------------------------------------------------------ Groups

async function loadGroup(c: Context<{ Bindings: Env }>, write = false): Promise<GroupRow> {
  const group = await c.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(Number(c.req.param("id"))).first<GroupRow>();
  if (!group) throw new ScimError(404, "No such group.");
  if (write && group.name === SUPER_ADMINS_GROUP) requireAdminFor(c, `Changing ${SUPER_ADMINS_GROUP}`);
  return group;
}

scimServer.get("/scim/v2/Groups", requireScope("directory:read"), async (c) => {
  const f = parseFilter(c.req.query("filter"), { displayname: "name" });
  const { startIndex, count } = paging(c);
  const where = f ? "WHERE name = ?" : "";
  const args = f ? [f.value] : [];
  const total = (await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM groups ${where}`).bind(...args).first<{ n: number }>())?.n ?? 0;
  const { results } = await c.env.DB.prepare(`SELECT * FROM groups ${where} ORDER BY id LIMIT ? OFFSET ?`).bind(...args, count, startIndex - 1).all<GroupRow>();
  const excluded = (c.req.query("excludedAttributes") ?? "").includes("members");
  const resources = await Promise.all(results.map(async (g) => (excluded ? { ...(await groupResource(c.env, g)), members: undefined } : groupResource(c.env, g))));
  return c.json({ schemas: [LIST], totalResults: total, startIndex, itemsPerPage: results.length, Resources: resources });
});

scimServer.get("/scim/v2/Groups/:id", requireScope("directory:read"), async (c) => c.json(await groupResource(c.env, await loadGroup(c))));

/** Resolves SCIM member references (user ids = external_id) to FlareID user ids, refusing Super Admins for non-admin keys. */
async function memberIds(c: Context<{ Bindings: Env }>, members: { value?: string }[]): Promise<number[]> {
  const ids: number[] = [];
  for (const m of members) {
    const user = m.value ? await getUserByExternalId(c.env, String(m.value)) : null;
    if (!user) throw new ScimError(400, `Unknown member "${m.value}".`, "invalidValue");
    if (await isSuperAdmin(c.env, user.id)) requireAdminFor(c, "Changing a Super Admin's group memberships");
    ids.push(user.id);
  }
  return ids;
}

/** A rename may not take the reserved name either (it is free only if an admin removed the built-in group). */
function guardNewName(c: Context<{ Bindings: Env }>, name: string | undefined) {
  if (name !== undefined && name.trim() === SUPER_ADMINS_GROUP) requireAdminFor(c, `Naming a group ${SUPER_ADMINS_GROUP}`);
}

/**
 * The statements for one membership change, not yet run: a request commits all
 * of its operations in one batch, so a later failing operation leaves nothing
 * half-applied (RFC 7644 3.5.2 - PATCH is all or nothing).
 */
async function memberStatements(env: Env, group: GroupRow, add: number[], remove: number[] | "all", c?: Context<{ Bindings: Env }>): Promise<D1PreparedStatement[]> {
  if (group.rule) throw new ScimError(400, "This is a dynamic group: its membership is its rule.", "mutability");
  // Replacing or clearing the member list removes Super Admins too.
  if (remove === "all" && c && !hasScope(c.get("apiActor").scopes, "admin")) {
    const admins = await env.DB.prepare(
      "SELECT 1 FROM group_members gm JOIN group_members sa ON sa.user_id = gm.user_id JOIN groups g ON g.id = sa.group_id WHERE gm.group_id = ? AND g.name = ? LIMIT 1"
    ).bind(group.id, SUPER_ADMINS_GROUP).first();
    if (admins) throw new ScimError(403, "Replacing the members of a group that contains a Super Admin requires an admin-scoped key.");
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
  if (!name) throw new ScimError(400, "displayName is required.", "invalidValue");
  if (name === SUPER_ADMINS_GROUP) requireAdminFor(c, `Changing ${SUPER_ADMINS_GROUP}`);
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
  guardNewName(c, body.displayName);
  // Everything is resolved and checked before anything is written.
  const stmts: D1PreparedStatement[] = [];
  if (body.displayName && body.displayName !== group.name) stmts.push(c.env.DB.prepare("UPDATE groups SET name = ? WHERE id = ?").bind(body.displayName.trim(), group.id));
  if (body.members !== undefined) stmts.push(...(await memberStatements(c.env, group, await memberIds(c, body.members), "all", c)));
  if (stmts.length) await c.env.DB.batch(stmts);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.group_replaced", group.name, undefined, c.req.raw);
  const replaced = await loadGroup(c);
  downstream(c, () => pushGroupCurrent(c.env, replaced), "update", replaced.name);
  return c.json(await groupResource(c.env, (await loadGroup(c))!));
});

scimServer.patch("/scim/v2/Groups/:id", requireScope("directory:write"), async (c) => {
  const group = await loadGroup(c, true);
  const body = await c.req.json<{ schemas?: string[]; Operations?: { op?: string; path?: string; value?: unknown }[] }>();
  if (!body.schemas?.includes(PATCH_OP) || !Array.isArray(body.Operations)) throw new ScimError(400, "Expected a PatchOp message.", "invalidSyntax");
  const stmts: D1PreparedStatement[] = [];
  for (const op of body.Operations) {
    const kind = String(op.op ?? "").toLowerCase();
    const path = op.path ?? "";
    const value = op.value as { value?: string }[] | { displayName?: string; members?: { value?: string }[] } | string | undefined;
    if ((path === "displayName" || (!path && typeof value === "object" && value && "displayName" in value)) && kind === "replace") {
      const name = typeof value === "string" ? value : (value as { displayName?: string }).displayName;
      guardNewName(c, name);
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
  downstream(c, () => pushGroupCurrent(c.env, patched), "update", patched.name);
  return c.json(await groupResource(c.env, await loadGroup(c)));
});

scimServer.delete("/scim/v2/Groups/:id", requireScope("directory:write"), async (c) => {
  const group = await loadGroup(c, true);
  if (group.name === SUPER_ADMINS_GROUP) throw new ScimError(400, `${SUPER_ADMINS_GROUP} cannot be deleted.`, "mutability");
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM group_members WHERE group_id = ?").bind(group.id),
    c.env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(group.id),
  ]);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.group_deleted", group.name, undefined, c.req.raw);
  downstream(c, () => deleteGroupScim(c.env, group), "delete", group.name);
  return c.body(null, 204);
});

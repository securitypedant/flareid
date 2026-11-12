import { z } from "@hono/zod-openapi";
import type { Env } from "../env.js";
import { getDefaultDomain } from "../lib/domains.js";
import { parseRule, userMatchesRule } from "../lib/groups.js";
import { listPasskeys } from "../lib/passkeys.js";
import { defaultSchemaId, findSchema, getSchemaAttributes, parseCustomAttributes, userAttributeValue } from "../lib/schemas.js";
import { listActiveSessionsForUser } from "../lib/sessions.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { apiCtx, ServiceError } from "../services/context.js";
import {
  connectedApps,
  createUser,
  deleteUser,
  removeUserPasskey,
  resetUserMfa,
  resetUserPassword,
  revokeUserAppAccess,
  revokeUserSessions,
  setUserStatus,
  updateUserProfile,
} from "../services/users.js";
import { defineRoute, notFound, param, readJson, readOptionalJson, type ApiContext } from "./openapi.js";
import { StringMap, UserSchema } from "./schemas.js";

/**
 * Users, one at a time - the console's user page as API calls. Bulk work
 * stays POST /api/v1/directory/import. Users are addressed by username, which
 * is unique across every domain.
 */

/**
 * The user rows the API returns, with an explicit column list (password_hash,
 * password_salt and totp_secret live in this table and must never leave it),
 * their groups - dynamic ones resolved against the same page - and attributes.
 */
export async function selectUsers(env: Env, opts: { username?: string; limit: number; offset: number }) {
  const where = opts.username !== undefined ? "WHERE u.username = ?" : "";
  const binds = opts.username !== undefined ? [opts.username] : [];
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.upn, u.username, u.email, u.display_name, u.given_name, u.family_name, u.external_id, u.status,
            u.mfa_enabled, u.job_title, u.department, u.employee_number, u.hire_date, u.employment_status,
            u.employment_type, u.location, u.manager_external_id, u.schema_id, u.custom_attributes, u.created_at, u.updated_at,
            (SELECT upn FROM users m WHERE m.external_id = u.manager_external_id) AS manager_upn,
            (SELECT name FROM schemas s WHERE s.id = u.schema_id) AS schema_name,
            (SELECT GROUP_CONCAT(g.name, char(10)) FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = u.id) AS group_names
       FROM users u ${where} ORDER BY u.id LIMIT ? OFFSET ?`
  )
    .bind(...binds, opts.limit, opts.offset)
    .all<Record<string, unknown> & { group_names: string | null; mfa_enabled: number; custom_attributes: string }>();

  // Dynamic groups don't live in group_members, so resolve them once per
  // request and fold them into each user's groups.
  const { results: ruleGroups } = await env.DB.prepare("SELECT * FROM groups WHERE rule != ''").all<GroupRow>();
  const { results: pageUsers } = await env.DB.prepare(`SELECT * FROM users u ${where} ORDER BY id LIMIT ? OFFSET ?`).bind(...binds, opts.limit, opts.offset).all<UserRow>();
  const dynamicById = new Map(pageUsers.map((u) => [u.id, ruleGroups.filter((g) => { const r = parseRule(g.rule); return r !== null && userMatchesRule(u, r); }).map((g) => g.name)]));

  return results.map(({ group_names, mfa_enabled, custom_attributes, id, ...user }) => ({
    ...user,
    mfa_enabled: mfa_enabled === 1,
    attributes: parseCustomAttributes(custom_attributes),
    groups: [...new Set([...(group_names ? group_names.split("\n") : []), ...(dynamicById.get(Number(id)) ?? [])])],
  }));
}

async function userByUsername(c: ApiContext): Promise<UserRow | null> {
  return c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(param(c, "username").toLowerCase()).first<UserRow>();
}

const noUser = (c: ApiContext) => notFound(c, `No user "${param(c, "username").toLowerCase()}".`);

/** Static group names to ids; an unknown or dynamic group is an error, not a silent skip. */
async function staticGroupIds(env: Env, names: string[]): Promise<number[]> {
  if (names.length === 0) return [];
  const { results } = await env.DB.prepare("SELECT id, name, rule FROM groups WHERE name IN (SELECT value FROM json_each(?))").bind(JSON.stringify(names)).all<{ id: number; name: string; rule: string }>();
  for (const name of names) {
    const g = results.find((r) => r.name === name);
    if (!g) throw new ServiceError(400, `No group named "${name}".`);
    if (g.rule) throw new ServiceError(400, `"${name}" is a dynamic group; its members follow its rule.`);
  }
  return results.map((r) => r.id);
}

async function schemaIdFor(env: Env, body: { schema_id?: number; schema?: string }): Promise<number | undefined> {
  if (body.schema_id !== undefined) return body.schema_id;
  if (body.schema === undefined) return undefined;
  const s = await findSchema(env, "user", body.schema);
  if (!s) throw new ServiceError(400, `No user schema named "${body.schema}".`);
  return s.id;
}

/** An attribute the target schema does not define would be silently dropped by conforming; say so instead. */
async function assertAttributesInSchema(env: Env, schemaId: number | undefined, attributes: Record<string, string> | undefined): Promise<void> {
  if (!attributes || Object.keys(attributes).length === 0) return;
  const id = schemaId ?? (await defaultSchemaId(env, "user"));
  const names = new Set((id ? await getSchemaAttributes(env, id) : []).map((a) => a.name));
  const unknown = Object.keys(attributes).filter((n) => !names.has(n));
  if (unknown.length) throw new ServiceError(400, `Not attributes of the user's schema: ${unknown.join(", ")}. Choose a schema that defines them (schema or schema_id).`);
}

const UserWrite = {
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  email: z.string().nullable().optional().openapi({ description: "Where email for the account goes, when not the UPN; null or empty clears it." }),
  schema_id: z.number().int().optional(),
  schema: z.string().optional().openapi({ description: "The user schema, by name (alternative to schema_id)." }),
  attributes: StringMap.optional().openapi({ description: "Schema attribute values by name. On PATCH, merged into the current values." }),
  groups: z.array(z.string()).optional().openapi({ description: "Static groups, by name. On PATCH, the complete set." }),
  status: z.enum(["active", "disabled"]).optional(),
};

defineRoute(
  {
    method: "post",
    path: "/api/v1/users",
    tag: "Users",
    permission: "users:write",
    summary: "Create a user",
    description:
      "New accounts are inactive unless `status` is `active`. Without `password`, the new-account password setting applies and the generated password is returned once. Giving someone an admin role group needs `*`.",
    body: z.object({ ...UserWrite, username: z.string(), domain: z.string().optional().openapi({ description: "Defaults to the default domain." }), given_name: z.string(), password: z.string().optional() }),
    status: 201,
    errors: [409],
    response: z.object({ ok: z.literal(true), upn: z.string(), username: z.string(), password: z.string().optional() }),
  },
  async (c) => {
    const body = await readJson<{ username: string; domain?: string; given_name: string; family_name?: string; email?: string | null; schema_id?: number; schema?: string; attributes?: Record<string, string>; groups?: string[]; password?: string; status?: "active" | "disabled" }>(c);
    const schemaId = await schemaIdFor(c.env, body);
    await assertAttributesInSchema(c.env, schemaId, body.attributes);
    const created = await createUser(apiCtx(c), {
      username: body.username,
      domain: body.domain ?? (await getDefaultDomain(c.env)),
      givenName: body.given_name,
      familyName: body.family_name ?? "",
      schemaId,
      attributes: body.attributes ?? {},
      groupIds: await staticGroupIds(c.env, body.groups ?? []),
      password: body.password,
      status: body.status,
      email: body.email ?? undefined,
    });
    // Returned once, and only when generated - a caller that chose one has it.
    return c.json({ ok: true, upn: created.upn, username: created.upn.split("@")[0], ...(created.chosen ? {} : { password: created.password }) }, 201);
  }
);

defineRoute(
  { method: "get", path: "/api/v1/users/{username}", tag: "Users", permission: "users:read", summary: "Get a user", errors: [404], response: UserSchema },
  async (c) => {
    const [user] = await selectUsers(c.env, { username: param(c, "username").toLowerCase(), limit: 1, offset: 0 });
    return user ? c.json(user) : noUser(c);
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/users/{username}",
    tag: "Users",
    permission: "users:write",
    summary: "Update a user",
    description:
      "Fields not supplied keep their values. Moving to another schema keeps attributes with the same name and clears the rest. `status: disabled` signs them out everywhere and ends their tokens. An administrator's account needs `*`.",
    body: z.object({ username: z.string().optional(), domain: z.string().optional(), ...UserWrite }),
    errors: [404, 409],
    response: UserSchema,
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    const body = await readJson<{ username?: string; domain?: string; given_name?: string; family_name?: string; email?: string | null; schema_id?: number; schema?: string; attributes?: Record<string, string>; groups?: string[]; status?: "active" | "disabled" }>(c);
    const ctx = apiCtx(c);
    const { status, ...profileFields } = body;
    let username = user.username;
    if (Object.values(profileFields).some((v) => v !== undefined)) {
      // A full desired state for the shared update: the current values, with
      // what was supplied laid over them.
      const at = user.upn.lastIndexOf("@");
      const schemaId = (await schemaIdFor(c.env, body)) ?? user.schema_id ?? (await defaultSchemaId(c.env, "user")) ?? undefined;
      await assertAttributesInSchema(c.env, schemaId, body.attributes);
      const current = Object.fromEntries((await getSchemaAttributes(c.env, Number(schemaId))).map((a) => [a.name, userAttributeValue(user, a)]));
      const { results: memberships } = await c.env.DB.prepare("SELECT gm.group_id FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.rule = ''").bind(user.id).all<{ group_id: number }>();
      const saved = await updateUserProfile(ctx, user.id, {
        username: body.username ?? user.username,
        domain: body.domain ?? user.upn.slice(at + 1),
        givenName: body.given_name ?? user.given_name,
        familyName: body.family_name ?? user.family_name,
        schemaId,
        attributes: { ...current, ...(body.attributes ?? {}) },
        groupIds: body.groups !== undefined ? await staticGroupIds(c.env, body.groups) : memberships.map((m) => m.group_id),
        email: body.email,
      });
      username = saved.upn.slice(0, saved.upn.lastIndexOf("@"));
    }
    if (status !== undefined && status !== user.status) await setUserStatus(ctx, user.id, status);
    const [updated] = await selectUsers(c.env, { username, limit: 1, offset: 0 });
    return c.json(updated);
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/users/{username}",
    tag: "Users",
    permission: "users:write",
    summary: "Delete a user",
    description: "Removes the account, its memberships, sessions and tokens, and deprovisions it over SCIM. An administrator's account needs `*`.",
    errors: [404],
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    await deleteUser(apiCtx(c), user.id);
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/users/{username}/reset-password",
    tag: "Users",
    permission: "users:write",
    summary: "Set or generate a password",
    description: "A supplied password must meet the policy; without one, a password is generated and returned once. Every session and token ends.",
    body: z.object({ password: z.string().optional() }),
    errors: [404],
    response: z.object({ ok: z.literal(true), password: z.string().optional() }),
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    const body = await readOptionalJson<{ password?: string }>(c);
    const chosen = String(body.password ?? "");
    const { password } = await resetUserPassword(apiCtx(c), user.id, chosen);
    return c.json({ ok: true, ...(chosen ? {} : { password }) });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/users/{username}/reset-mfa",
    tag: "Users",
    permission: "users:write",
    summary: "Reset multi-factor authentication",
    description: "Clears the authenticator, backup codes and remembered devices; they enrol again at next sign-in.",
    errors: [404],
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    await resetUserMfa(apiCtx(c), user.id);
    return c.json({ ok: true });
  }
);

const SessionSchema = z.object({ created_at: z.string(), last_seen_at: z.string(), ip: z.string().nullable(), user_agent: z.string().nullable() }).openapi("Session");

defineRoute(
  { method: "get", path: "/api/v1/users/{username}/sessions", tag: "Users", permission: "users:read", summary: "List active sessions", errors: [404], response: z.object({ sessions: z.array(SessionSchema) }) },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    // Never the session id: it is what the cookie carries.
    const sessions = (await listActiveSessionsForUser(c.env, user.id)).map((s) => ({ created_at: s.created_at, last_seen_at: s.last_seen_at, ip: s.ip, user_agent: s.user_agent }));
    return c.json({ sessions });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/users/{username}/sessions", tag: "Users", permission: "users:write", summary: "Sign out everywhere", errors: [404], response: z.object({ ok: z.literal(true), revoked: z.number() }) },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    return c.json({ ok: true, revoked: await revokeUserSessions(apiCtx(c), user.id) });
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/users/{username}/passkeys",
    tag: "Users",
    permission: "users:read",
    summary: "List passkeys",
    errors: [404],
    response: z.object({ passkeys: z.array(z.object({ credential_id: z.string(), name: z.string(), backed_up: z.boolean(), created_at: z.string(), last_used_at: z.string().nullable() })) }),
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    // Public keys stay in the database: nothing a caller needs, and nothing to leak.
    const passkeys = (await listPasskeys(c.env, user.id)).map((p) => ({ credential_id: p.id, name: p.name, backed_up: p.backed_up === 1, created_at: p.created_at, last_used_at: p.last_used_at }));
    return c.json({ passkeys });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/users/{username}/passkeys/{credential_id}", tag: "Users", permission: "users:write", summary: "Remove a passkey", errors: [404] },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    if (!(await removeUserPasskey(apiCtx(c), user, param(c, "credential_id")))) return notFound(c, "No such passkey for this user.");
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/users/{username}/apps",
    tag: "Users",
    permission: "users:read",
    summary: "List the OIDC apps holding tokens for a user",
    errors: [404],
    response: z.object({ apps: z.array(z.object({ client_id: z.string(), name: z.string() })) }),
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    return c.json({ apps: (await connectedApps(c.env, user.id)).map((a) => ({ client_id: a.client_id, name: a.name })) });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/users/{username}/apps/{client_id}", tag: "Users", permission: "users:write", summary: "Revoke an app's access", description: "Its access tokens are deleted and refresh tokens revoked; they sign in to it again.", errors: [404] },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    const client = await c.env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(param(c, "client_id")).first<{ id: number }>();
    if (!client) return notFound(c, `No OIDC client "${param(c, "client_id")}".`);
    await revokeUserAppAccess(apiCtx(c), user.id, client.id);
    return c.json({ ok: true });
  }
);

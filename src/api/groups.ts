import { z } from "@hono/zod-openapi";
import type { Env } from "../env.js";
import { resolveGroupMemberUserIds } from "../lib/groups.js";
import { defaultSchemaId, findSchema, getSchemaAttributes, parseCustomAttributes } from "../lib/schemas.js";
import type { GroupRow } from "../lib/types.js";
import { apiCtx, ServiceError } from "../services/context.js";
import { addGroupMembers, createGroup, deleteGroup, freezeGroup, getGroupById, groupMembers, removeGroupMember, updateGroup } from "../services/groups.js";
import { defineRoute, notFound, param, readJson, type ApiContext } from "./openapi.js";
import { GroupSchema, IdParam, MemberSchema, RuleSchema, StringMap } from "./schemas.js";

/**
 * Groups, one at a time. Static groups take explicit members; a dynamic
 * group's members are whoever its rule matches, so it takes none. The type is
 * fixed at creation, except that a dynamic group can be frozen into a static
 * one with its current members.
 */

export async function groupJson(env: Env, g: GroupRow) {
  const schemaName = g.schema_id ? (await env.DB.prepare("SELECT name FROM schemas WHERE id = ?").bind(g.schema_id).first<{ name: string }>())?.name ?? null : null;
  const explicit = (await env.DB.prepare("SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?").bind(g.id).first<{ n: number }>())?.n ?? 0;
  const { custom_attributes, scim_id: _scim, ...rest } = g;
  return { ...rest, schema_name: schemaName, attributes: parseCustomAttributes(custom_attributes), member_count: (await resolveGroupMemberUserIds(env, g)).length, explicit_member_count: explicit };
}

async function groupFor(c: ApiContext): Promise<GroupRow | null> {
  return getGroupById(c.env, Number(param(c, "id")));
}

const noGroup = (c: ApiContext) => notFound(c, `No group with id ${param(c, "id")}.`);

/** Usernames to user ids; an unknown username is an error. */
async function userIds(env: Env, usernames: string[]): Promise<number[]> {
  const names = [...new Set(usernames.map((u) => u.trim().toLowerCase()))];
  if (names.length === 0) return [];
  const { results } = await env.DB.prepare("SELECT id, username FROM users WHERE username IN (SELECT value FROM json_each(?))").bind(JSON.stringify(names)).all<{ id: number; username: string }>();
  const missing = names.filter((n) => !results.some((r) => r.username === n));
  if (missing.length) throw new ServiceError(400, `No such user(s): ${missing.join(", ")}.`);
  return results.map((r) => r.id);
}

/** The group schema (by id or name, else the current or default one) and the values it keeps. */
async function schemaAndCustom(env: Env, body: { schema_id?: number; schema?: string; attributes?: Record<string, string> }, current: GroupRow | null) {
  let schemaId: number | null = body.schema_id ?? null;
  if (schemaId === null && body.schema !== undefined) {
    const s = await findSchema(env, "group", body.schema);
    if (!s) throw new ServiceError(400, `No group schema named "${body.schema}".`);
    schemaId = s.id;
  }
  schemaId ??= current?.schema_id ?? (await defaultSchemaId(env, "group"));
  const attrs = schemaId ? await getSchemaAttributes(env, schemaId) : [];
  const values = { ...parseCustomAttributes(current?.custom_attributes), ...(body.attributes ?? {}) };
  // Conform: only the schema's attributes are kept.
  const custom = Object.fromEntries(attrs.map((a) => [a.name, String(values[a.name] ?? "").trim()]).filter(([, v]) => v));
  return { schemaId, custom };
}

const GroupWrite = {
  description: z.string().optional(),
  schema_id: z.number().int().optional(),
  schema: z.string().optional().openapi({ description: "The group schema, by name (alternative to schema_id)." }),
  attributes: StringMap.optional().openapi({ description: "Group schema attribute values; on PATCH, merged into the current ones." }),
};

defineRoute(
  {
    method: "post",
    path: "/api/v1/groups",
    tag: "Groups",
    permission: "groups:write",
    summary: "Create a group",
    description: "With `rule`, a dynamic group (no explicit members); otherwise static, optionally with `members`. A name that grants an admin role needs `*`.",
    body: z.object({ name: z.string(), rule: RuleSchema.nullable().optional(), members: z.array(z.string()).optional().openapi({ description: "Usernames, for a static group." }), ...GroupWrite }),
    status: 201,
    errors: [409],
    response: z.object({ ok: z.literal(true), id: z.number(), name: z.string() }),
  },
  async (c) => {
    const body = await readJson<{ name: string; description?: string; rule?: unknown; members?: string[]; schema_id?: number; schema?: string; attributes?: Record<string, string> }>(c);
    const { schemaId, custom } = await schemaAndCustom(c.env, body, null);
    const name = String(body.name).trim();
    const id = await createGroup(apiCtx(c), { name, description: String(body.description ?? "").trim(), rule: body.rule ? JSON.stringify(body.rule) : "", schemaId, custom }, await userIds(c.env, body.members ?? []));
    return c.json({ ok: true, id, name }, 201);
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/groups/{id}",
    tag: "Groups",
    permission: "groups:read",
    summary: "Get a group and a page of its members",
    description: "Members are the assigned ones for a static group and the rule's matches for a dynamic one; `search` filters them by name, UPN or username.",
    params: IdParam,
    query: z.object({ search: z.string().optional(), limit: z.string().optional().openapi({ description: "Default 100, at most 500." }), offset: z.string().optional() }),
    errors: [404],
    response: GroupSchema.extend({ members: z.object({ total: z.number(), limit: z.number(), offset: z.number(), users: z.array(MemberSchema) }) }),
  },
  async (c) => {
    const group = await groupFor(c);
    if (!group) return noGroup(c);
    const limit = Math.min(Number(c.req.query("limit") ?? 100) || 100, 500);
    const offset = Math.max(Number(c.req.query("offset") ?? 0) || 0, 0);
    const { total, rows } = await groupMembers(c.env, group, (c.req.query("search") ?? "").slice(0, 100), limit, offset);
    return c.json({
      ...(await groupJson(c.env, group)),
      members: { total, limit, offset, users: rows.map((u) => ({ upn: u.upn, username: u.username, display_name: u.display_name, status: u.status })) },
    });
  }
);

defineRoute(
  {
    method: "patch",
    path: "/api/v1/groups/{id}",
    tag: "Groups",
    permission: "groups:write",
    summary: "Update a group",
    description:
      "Fields not supplied keep their values. A dynamic group's `rule` can be replaced, but the type cannot change: a static group never becomes dynamic, and a dynamic one becomes static only through POST /api/v1/groups/{id}/freeze. Members are managed with the members endpoints. An admin role group needs `*`.",
    params: IdParam,
    body: z.object({ name: z.string().optional(), rule: RuleSchema.nullable().optional(), ...GroupWrite }),
    errors: [404, 409],
    response: GroupSchema,
  },
  async (c) => {
    const group = await groupFor(c);
    if (!group) return noGroup(c);
    const body = await readJson<{ name?: string; description?: string; rule?: unknown; schema_id?: number; schema?: string; attributes?: Record<string, string> }>(c);
    if (body.rule !== undefined) {
      if (group.rule && !body.rule) throw new ServiceError(400, `A dynamic group becomes static only through POST /api/v1/groups/${group.id}/freeze, which keeps its current members.`);
      if (!group.rule && body.rule) throw new ServiceError(400, "A static group cannot become dynamic; create a dynamic group instead.");
    }
    const { schemaId, custom } = await schemaAndCustom(c.env, body, group);
    await updateGroup(apiCtx(c), group.id, {
      name: body.name !== undefined ? String(body.name).trim() : group.name,
      description: body.description !== undefined ? String(body.description).trim() : (group.description ?? ""),
      rule: body.rule ? JSON.stringify(body.rule) : group.rule,
      schemaId,
      custom,
    });
    return c.json(await groupJson(c.env, (await getGroupById(c.env, group.id))!));
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/groups/{id}", tag: "Groups", permission: "groups:write", summary: "Delete a group", description: "Super Admins cannot be deleted; an admin role group needs `*`.", params: IdParam, errors: [404] },
  async (c) => {
    const group = await groupFor(c);
    if (!group) return noGroup(c);
    await deleteGroup(apiCtx(c), group.id);
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/groups/{id}/freeze",
    tag: "Groups",
    permission: "groups:write",
    summary: "Convert a dynamic group to static",
    description: "The rule's current matches become assigned members and the rule is removed.",
    params: IdParam,
    errors: [404],
    response: z.object({ ok: z.literal(true), members: z.number() }),
  },
  async (c) => {
    const group = await groupFor(c);
    if (!group) return noGroup(c);
    return c.json({ ok: true, members: await freezeGroup(apiCtx(c), group.id) });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/groups/{id}/members",
    tag: "Groups",
    permission: "groups:write",
    summary: "Add members to a static group",
    description: "People already in the group are left as they are.",
    params: IdParam,
    body: z.object({ usernames: z.array(z.string()) }),
    errors: [404],
    response: z.object({ ok: z.literal(true), added: z.number() }),
  },
  async (c) => {
    const group = await groupFor(c);
    if (!group) return noGroup(c);
    const body = await readJson<{ usernames: string[] }>(c);
    return c.json({ ok: true, added: await addGroupMembers(apiCtx(c), group.id, await userIds(c.env, body.usernames ?? [])) });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/groups/{id}/members/{username}", tag: "Groups", permission: "groups:write", summary: "Remove a member from a static group", params: IdParam.extend({ username: z.string() }), errors: [404] },
  async (c) => {
    const group = await groupFor(c);
    if (!group) return noGroup(c);
    const user = await c.env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(param(c, "username").toLowerCase()).first<{ id: number }>();
    if (!user) return notFound(c, `No user "${param(c, "username").toLowerCase()}".`);
    await removeGroupMember(apiCtx(c), group.id, user.id);
    return c.json({ ok: true });
  }
);

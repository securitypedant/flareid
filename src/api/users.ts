import { z } from "@hono/zod-openapi";
import type { Env } from "../env.js";
import { enrolledFactors, hasBackupCodesSql, hasPasskeySql } from "../lib/auth-policy.js";
import { getDefaultDomain } from "../lib/domains.js";
import { parseRule, userMatchesRule } from "../lib/groups.js";
import { listPasskeys } from "../lib/passkeys.js";
import { defaultSchemaId, findSchema, getSchemaAttributes, parseCustomAttributes, userAttributeValue } from "../lib/schemas.js";
import { getMasteredFields, masteredFieldsInBody } from "../lib/scim-mapping.js";
import { listActiveSessionsForUser } from "../lib/sessions.js";
import { listTrustedDevices, revokeTrustedDevice } from "../lib/trusted-devices.js";
import { deleteUserPhoto, getUserPhoto, MAX_PHOTO_BYTES, setUserPhoto, sniffImageType } from "../lib/photos.js";
import { auditActor } from "../lib/api-auth.js";
import { getReport, listOpenReports, resolveReport } from "../lib/account-reports.js";
import { logAudit } from "../lib/audit.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { listUserEmailsFor, type UserEmailInput } from "../lib/user-emails.js";
import { type UserPhoneInput } from "../lib/user-phones.js";
import { parseIdentifier, resolveLoginIdentifier } from "../lib/identifier.js";
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
import { badRequest, defineRoute, notFound, param, readJson, readOptionalJson, type ApiContext } from "./openapi.js";
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
export async function selectUsers(env: Env, opts: { id?: number; username?: string; q?: string; limit: number; offset: number }) {
  const conds: string[] = [];
  const binds: (string | number)[] = [];
  if (opts.id !== undefined) { conds.push("u.id = ?"); binds.push(opts.id); }
  if (opts.username !== undefined) { conds.push("u.username = ?"); binds.push(opts.username); }
  if (opts.q) {
    conds.push("(lower(u.display_name) LIKE ? ESCAPE '\\' OR lower(u.upn) LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\' OR lower(u.email) LIKE ? ESCAPE '\\')");
    const like = `%${opts.q.replace(/[%_\\]/g, (m) => `\\${m}`)}%`;
    binds.push(like, like, like, like);
  }
  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.upn, u.username, u.email, u.display_name, u.given_name, u.family_name, u.external_id, u.status,
            u.mfa_enabled, u.email_otp_enabled, u.security_questions_enabled, u.job_title, u.department, u.employee_number, u.hire_date, u.employment_status,
            u.employment_type, u.location, u.manager_external_id, u.schema_id, u.custom_attributes, u.created_at, u.updated_at,
            (SELECT upn FROM users m WHERE m.external_id = u.manager_external_id) AS manager_upn,
            (SELECT name FROM schemas s WHERE s.id = u.schema_id) AS schema_name,
            ${hasPasskeySql("u")} AS has_passkey,
            ${hasBackupCodesSql("u")} AS has_backup_codes,
            (SELECT GROUP_CONCAT(g.name, char(10)) FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = u.id) AS group_names
       FROM users u ${where} ORDER BY u.id LIMIT ? OFFSET ?`
  )
    .bind(...binds, opts.limit, opts.offset)
    .all<Record<string, unknown> & { group_names: string | null; mfa_enabled: number; email_otp_enabled: number; security_questions_enabled: number; has_passkey: number; has_backup_codes: number; custom_attributes: string }>();

  // Dynamic groups don't live in group_members, so resolve them once per
  // request and fold them into each user's groups.
  const { results: ruleGroups } = await env.DB.prepare("SELECT * FROM groups WHERE rule != ''").all<GroupRow>();
  const { results: pageUsers } = await env.DB.prepare(`SELECT * FROM users u ${where} ORDER BY id LIMIT ? OFFSET ?`).bind(...binds, opts.limit, opts.offset).all<UserRow>();
  const dynamicById = new Map(pageUsers.map((u) => [u.id, ruleGroups.filter((g) => { const r = parseRule(g.rule); return r !== null && userMatchesRule(u, r); }).map((g) => g.name)]));

  const emailsById = await listUserEmailsFor(env, results.map((u) => Number(u.id)));

  return results.map(({ group_names, mfa_enabled, email_otp_enabled, security_questions_enabled, has_passkey, has_backup_codes, custom_attributes, id, ...user }) => ({
    ...user,
    mfa_enabled: mfa_enabled === 1,
    email_otp_enabled: email_otp_enabled === 1,
    security_questions_enabled: security_questions_enabled === 1,
    second_factors: enrolledFactors({ mfa_enabled, email_otp_enabled, security_questions_enabled, has_passkey, has_backup_codes }),
    attributes: parseCustomAttributes(custom_attributes),
    emails: (emailsById.get(Number(id)) ?? []).map((e) => ({ value: e.email, type: e.type, primary: e.is_primary === 1 })),
    groups: [...new Set([...(group_names ? group_names.split("\n") : []), ...(dynamicById.get(Number(id)) ?? [])])],
  }));
}

/**
 * The {username} path parameter takes any sign-in name: an exact upn (a UPN,
 * a handle, or a phone) wins, else a bare local part only when it names
 * exactly one account - the login resolver's own rule, so an ambiguous bare
 * name is a 404, never the wrong user.
 */
async function userByUsername(c: ApiContext): Promise<UserRow | null> {
  // deliveryOnly: an admin-scoped lookup is not a credential prompt - it may
  // find an account by a verified alias even when alias sign-in is off.
  return (await resolveLoginIdentifier(c.env, param(c, "username"), { deliveryOnly: true })).user;
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

/** Mastered fields belong to the upstream provisioner: sending one over the admin API is a mistake, not a no-op. */
async function assertNoMasteredFields(env: Env, body: { username?: unknown; domain?: unknown; given_name?: unknown; family_name?: unknown; email?: unknown; emails?: unknown; attributes?: Record<string, unknown> }): Promise<void> {
  const mastered = new Set(await getMasteredFields(env));
  if (!mastered.size) return;
  const bad = masteredFieldsInBody(mastered, body);
  if (bad.length) throw new ServiceError(400, `${bad.map((f) => `"${f}"`).join(", ")} ${bad.length === 1 ? "is" : "are"} mastered by inbound provisioning - change ${bad.length === 1 ? "it" : "them"} over SCIM instead.`);
}

const UserWrite = {
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  email: z.string().nullable().optional().openapi({ description: "Where email for the account goes, when not the UPN; null or empty clears it." }),
  emails: z
    .array(z.object({ value: z.string(), type: z.string().optional(), primary: z.boolean().optional() }))
    .optional()
    .openapi({ description: "The complete contact-address list (work/home/aliases), replacing what is there; the marked or first entry is the primary that `email` claims and mail goes to. Takes precedence over `email`." }),
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
    body: z.object({ ...UserWrite, username: z.string().optional(), domain: z.string().optional().openapi({ description: "Defaults to the default domain." }), identifier: z.string().optional().openapi({ description: "The sign-in name verbatim - a user@domain UPN, a bare handle, or +E.164 phone. Wins over username+domain." }), given_name: z.string(), password: z.string().optional() }),
    status: 201,
    errors: [409],
    response: z.object({ ok: z.literal(true), upn: z.string(), username: z.string(), password: z.string().optional() }),
  },
  async (c) => {
    const body = await readJson<{ username?: string; domain?: string; identifier?: string; given_name: string; family_name?: string; email?: string | null; emails?: UserEmailInput[]; phones?: UserPhoneInput[]; schema_id?: number; schema?: string; attributes?: Record<string, string>; groups?: string[]; password?: string; status?: "active" | "disabled" }>(c);
    if (!body.identifier && !body.username) return c.json(badRequest("Give `identifier` (any sign-in name) or `username` (+`domain` for a UPN)."), 400);
    const schemaId = await schemaIdFor(c.env, body);
    await assertAttributesInSchema(c.env, schemaId, body.attributes);
    await assertNoMasteredFields(c.env, body);
    const created = await createUser(apiCtx(c), {
      username: body.username ?? "",
      domain: body.domain ?? (await getDefaultDomain(c.env)),
      identifier: body.identifier,
      givenName: body.given_name,
      familyName: body.family_name ?? "",
      schemaId,
      attributes: body.attributes ?? {},
      groupIds: await staticGroupIds(c.env, body.groups ?? []),
      password: body.password,
      status: body.status,
      email: body.email ?? undefined,
      emails: body.emails,
      phones: body.phones,
    });
    // Returned once, and only when generated - a caller that chose one has it.
    return c.json({ ok: true, upn: created.upn, username: parseIdentifier(created.upn)?.username ?? created.upn, ...(created.chosen ? {} : { password: created.password }) }, 201);
  }
);

defineRoute(
  { method: "get", path: "/api/v1/users/{username}", tag: "Users", permission: "users:read", summary: "Get a user", errors: [404], response: UserSchema },
  async (c) => {
    const found = await userByUsername(c);
    if (!found) return noUser(c);
    const [user] = await selectUsers(c.env, { id: found.id, limit: 1, offset: 0 });
    return c.json(user);
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
    body: z.object({ username: z.string().optional(), domain: z.string().optional(), identifier: z.string().optional(), ...UserWrite }),
    errors: [404, 409],
    response: UserSchema,
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    const body = await readJson<{ username?: string; domain?: string; identifier?: string; given_name?: string; family_name?: string; email?: string | null; emails?: UserEmailInput[]; phones?: UserPhoneInput[]; schema_id?: number; schema?: string; attributes?: Record<string, string>; groups?: string[]; status?: "active" | "disabled" }>(c);
    const ctx = apiCtx(c);
    const { status, ...profileFields } = body;
    if (Object.values(profileFields).some((v) => v !== undefined)) {
      // A full desired state for the shared update: the current values, with
      // what was supplied laid over them.
      const at = user.upn.lastIndexOf("@");
      const schemaId = (await schemaIdFor(c.env, body)) ?? user.schema_id ?? (await defaultSchemaId(c.env, "user")) ?? undefined;
      await assertAttributesInSchema(c.env, schemaId, body.attributes);
      await assertNoMasteredFields(c.env, body);
      const current = Object.fromEntries((await getSchemaAttributes(c.env, Number(schemaId))).map((a) => [a.name, userAttributeValue(user, a)]));
      const { results: memberships } = await c.env.DB.prepare("SELECT gm.group_id FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.rule = ''").bind(user.id).all<{ group_id: number }>();
      await updateUserProfile(ctx, user.id, {
        username: body.username ?? user.username,
        domain: body.domain ?? (at >= 0 ? user.upn.slice(at + 1) : ""),
        identifier: body.identifier,
        givenName: body.given_name ?? user.given_name,
        familyName: body.family_name ?? user.family_name,
        schemaId,
        attributes: { ...current, ...(body.attributes ?? {}) },
        groupIds: body.groups !== undefined ? await staticGroupIds(c.env, body.groups) : memberships.map((m) => m.group_id),
        email: body.email,
        emails: body.emails,
        phones: body.phones,
      });
    }
    if (status !== undefined && status !== user.status) await setUserStatus(ctx, user.id, status);
    const [updated] = await selectUsers(c.env, { id: user.id, limit: 1, offset: 0 });
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
    description: "Clears the authenticator, backup codes, email one-time codes, security questions and remembered devices; they enrol again at next sign-in. Passkeys are kept (remove them with the passkeys operations).",
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

// ---------------------------------------------------------------------------
// Profile photo
// ---------------------------------------------------------------------------

const photoToB64 = (buf: Uint8Array) => {
  let s = "";
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(s);
};

defineRoute(
  {
    method: "get",
    path: "/api/v1/users/{username}/devices",
    tag: "Users",
    permission: "users:read",
    summary: "List remembered (trusted) devices",
    description: "`id` is the hash of the device cookie - enough to revoke one, useless for signing in.",
    errors: [404],
    response: z.object({ devices: z.array(z.object({ id: z.string(), user_agent: z.string().nullable(), ip: z.string().nullable(), created_at: z.string(), last_used_at: z.string(), expires_at: z.string() })) }),
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    const devices = (await listTrustedDevices(c.env, user.id)).map((d) => ({ id: d.id, user_agent: d.user_agent, ip: d.ip, created_at: d.created_at, last_used_at: d.last_used_at, expires_at: d.expires_at }));
    return c.json({ devices });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/users/{username}/devices/{id}", tag: "Users", permission: "users:write", summary: "Forget a remembered device", errors: [404] },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    await revokeTrustedDevice(c.env, user.id, param(c, "id"));
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "get",
    path: "/api/v1/users/{username}/photo",
    tag: "Users",
    permission: "users:read",
    summary: "Get the profile photo",
    description: "The stored image as base64 - the same bytes the console's /account/photo route serves browsers.",
    errors: [404],
    response: z.object({ content_type: z.string(), photo: z.string().openapi({ description: "Base64 image data." }) }),
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    const photo = await getUserPhoto(c.env, user.id);
    if (!photo) return notFound(c, `"${user.username}" has no photo.`);
    return c.json({ content_type: photo.content_type, photo: photoToB64(photo.data) });
  }
);

defineRoute(
  {
    method: "put",
    path: "/api/v1/users/{username}/photo",
    tag: "Users",
    permission: "users:write",
    summary: "Set the profile photo",
    description: "Base64 PNG, JPEG, WebP or GIF, at most 1 MB decoded. Refused while `photo` is mastered by inbound provisioning.",
    body: z.object({ photo: z.string() }),
    errors: [404],
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    if ((await getMasteredFields(c.env)).includes("photo")) throw new ServiceError(400, '"photo" is mastered by inbound provisioning - change it over SCIM instead.');
    const body = await readJson<{ photo?: string }>(c);
    let buf: Uint8Array;
    try {
      buf = Uint8Array.from(atob(String(body.photo ?? "")), (ch) => ch.charCodeAt(0));
    } catch {
      throw new ServiceError(400, "photo must be base64 image data.");
    }
    if (buf.byteLength === 0) throw new ServiceError(400, "photo must be base64 image data.");
    if (buf.byteLength > MAX_PHOTO_BYTES) throw new ServiceError(400, "Photos are limited to 1 MB.");
    const type = sniffImageType(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer);
    if (!type) throw new ServiceError(400, "That doesn't look like a PNG, JPG, WebP or GIF image.");
    await setUserPhoto(c.env, user.id, buf, type);
    await logAudit(c.env, auditActor(c.get("apiActor")), "user.photo_updated", user.upn, undefined, c.req.raw);
    return c.json({ ok: true });
  }
);

defineRoute(
  {
    method: "delete",
    path: "/api/v1/users/{username}/photo",
    tag: "Users",
    permission: "users:write",
    summary: "Remove the profile photo",
    description: "Refused while `photo` is mastered by inbound provisioning.",
    errors: [404],
  },
  async (c) => {
    const user = await userByUsername(c);
    if (!user) return noUser(c);
    if ((await getMasteredFields(c.env)).includes("photo")) throw new ServiceError(400, '"photo" is mastered by inbound provisioning - change it over SCIM instead.');
    await deleteUserPhoto(c.env, user.id);
    await logAudit(c.env, auditActor(c.get("apiActor")), "user.photo_removed", user.upn, undefined, c.req.raw);
    return c.json({ ok: true });
  }
);

// ---------- "This wasn't me" reports (account-reports.ts) ----------

const AccountReportSchema = z
  .object({
    id: z.number(),
    username: z.string(),
    display_name: z.string(),
    kind: z.enum(["session", "device"]).openapi({ description: "What the person reported: a signed-in session or a remembered device. It was revoked when reported." }),
    ip: z.string().nullable(),
    user_agent: z.string().nullable(),
    reported_at: z.string(),
  })
  .openapi("AccountReport");

defineRoute(
  {
    method: "get",
    path: "/api/v1/account-reports",
    tag: "Users",
    permission: "users:read",
    summary: "List open account reports",
    description: "Sessions and remembered devices people flagged as not theirs on their Security page, still waiting for an administrator to review.",
    response: z.object({ reports: z.array(AccountReportSchema) }),
  },
  async (c) =>
    c.json({
      reports: (await listOpenReports(c.env, 500)).map((r) => ({ id: r.id, username: r.upn, display_name: r.display_name, kind: r.kind, ip: r.ip, user_agent: r.user_agent, reported_at: r.created_at })),
    })
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/account-reports/{id}/resolve",
    tag: "Users",
    permission: "users:write",
    summary: "Mark an account report reviewed",
    params: z.object({ id: z.string() }),
    errors: [404],
    response: z.object({ ok: z.literal(true) }),
  },
  async (c) => {
    const report = await getReport(c.env, Number(param(c, "id")));
    // API keys aren't people: resolved_by stays empty, the audit row names the key.
    if (!report || !(await resolveReport(c.env, report.id, null))) return notFound(c, "No open report with that id.");
    const target = await c.env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(report.user_id).first<{ upn: string }>();
    await logAudit(c.env, auditActor(c.get("apiActor")), "user.report_resolved", target?.upn, { kind: report.kind }, c.req.raw);
    return c.json({ ok: true as const });
  }
);

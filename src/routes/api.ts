import { z } from "@hono/zod-openapi";
import { ID_TOKEN_ALGS, isIdTokenAlg, validFrontchannelUri } from "../services/clients.js";
import { api, apiErrorHandler, AnyObject, badRequest, defineRoute, readJson } from "../api/openapi.js";
import { GroupSchema, IdParam, Paging, PasswordPolicySchema, SchemaAttributeInput, ServiceProviderSchema, StringMap, UserSchema } from "../api/schemas.js";
// Each module registers its routes on `api` when imported (users.ts also
// shares the user query with the list below).
import { selectUsers } from "../api/users.js";
import "../api/groups.js";
import "../api/applications.js";
import "../api/settings.js";
import "../api/monitoring.js";
import { auditActor, bootstrapTokenValid } from "../lib/api-auth.js";
import { createApiKey, hasScope, isApiScope, type ApiScope } from "../lib/api-keys.js";
import { importDirectory, type DirectoryBundle } from "../lib/directory-import.js";
import { isEmailConfigured, recipientFor } from "../lib/email.js";
import { CLAIM_GROUPS, isValidPostLogoutUri } from "../lib/oidc.js";
import { apiCtx } from "../services/context.js";
import { applyScimScope } from "../services/scim-sync.js";
import { sendUserLink } from "../services/users.js";
import { assignDomainBrand } from "../services/branding.js";
import { runSetup, SetupAdminError, type SetupInput } from "../services/setup.js";
import { resolveManyGroupMemberUserIds } from "../lib/groups.js";
import {
  listSchemas,
  getSchema,
  findSchema,
  getSchemaAttributes,
  parseCustomAttributes,
  createSchema,
  saveSchemaAttributes,
  applySchemaToAll,
  countConforming,
  defaultSchemaId,
} from "../lib/schemas.js";
import { addDomain, applyDomainToAllUsers, getDefaultDomain, listDomains, setDefaultDomain } from "../lib/domains.js";
import { logAudit } from "../lib/audit.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { syncAll, testScimConnection } from "../lib/scim-client.js";
import { getAppName, isSetupCompleted, setScimConfig } from "../lib/settings.js";
import type { GroupRow, OAuthClientRow, SamlServiceProviderRow, UserRow } from "../lib/types.js";
import { normalizeCertPem } from "../lib/saml/x509.js";
import { fetchSpMetadata, parseSpMetadata, SpMetadataError, upsertSpFromMetadata, type ParsedSpMetadata } from "../lib/saml/sp-metadata.js";
import { nameIdFormatUri } from "../lib/saml/messages.js";
import { USER_ATTRIBUTE_FIELDS } from "../lib/saml/attributes.js";

/**
 * The machine-facing provisioning API.
 *
 * Everything here exists because the alternative was a deploy script holding a
 * cookie jar, regexing a `flow_id` out of the login page and parsing a client
 * secret out of a <code> block. That worked, until a heading moved.
 *
 * Two things shape the design:
 *
 *   - It is idempotent. Provisioning runs more than once - a lab re-applies,
 *     a deploy is retried - so every mutation here either converges on the
 *     requested state or reports why it cannot, rather than failing because
 *     something already exists.
 *
 *   - Nothing needs a browser. A fresh deployment has no users at all, so the
 *     first call has to be authenticated by something other than a password;
 *     see BOOTSTRAP_TOKEN in api-auth.ts.
 */
export { api };

// The app, its authentication middleware, the OpenAPI document and
// defineRoute() live in src/api/openapi.ts; the routes added since v3.5 are in
// src/api/*.ts. These are the original ones, now with schemas.

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

defineRoute({
  method: "get", path: "/api/v1/status", tag: "Status", permission: "directory:read",
  summary: "Instance status and directory counts",
  response: z.object({
    service: z.string(), api_version: z.number(), issuer: z.string(), app_name: z.string(), setup_completed: z.boolean(), default_domain: z.string().nullable(),
    counts: z.object({ users: z.number(), groups: z.number(), oidc_clients: z.number(), domains: z.number() }),
  }),
}, async (c) => {
  const [users, groups, clients, domains, setupCompleted, appName] = await Promise.all([
    c.env.DB.prepare("SELECT COUNT(*) as n FROM users").first<{ n: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as n FROM groups").first<{ n: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as n FROM oauth_clients").first<{ n: number }>(),
    listDomains(c.env),
    isSetupCompleted(c.env),
    getAppName(c.env),
  ]);

  return c.json({
    service: "flareid-idp",
    api_version: 1,
    issuer: c.env.ISSUER_URL,
    app_name: appName,
    setup_completed: setupCompleted,
    default_domain: domains.find((d) => d.is_default)?.domain ?? null,
    counts: {
      users: users?.n ?? 0,
      groups: groups?.n ?? 0,
      oidc_clients: clients?.n ?? 0,
      domains: domains.length,
    },
  });
});

// ---------------------------------------------------------------------------
// First-run setup
// ---------------------------------------------------------------------------

/** The body: the same fields runSetup (services/setup.ts) takes, applied in its order. */
const SetupBody = z.object({
  domain: z.string().optional(),
  admin: z.object({ username: z.string().optional(), password: z.string().optional(), display_name: z.string().optional(), given_name: z.string().optional(), family_name: z.string().optional() }).optional(),
  default_password: z.string().optional(),
  app_name: z.string().optional(),
  login_subtitle: z.string().optional(),
  login_gradient: z.object({ from: z.string().optional(), to: z.string().optional() }).optional(),
  require_mfa: z.boolean().optional().openapi({ description: "Make the default policy (everyone no other policy matches) require a second factor, or not." }),
  admin_mfa: z.boolean().optional().openapi({
    description:
      "Require a second factor for administrators (default: a fresh install does). true keeps Super Admins in the \"Password and a second factor\" policy; false takes them out of every policy that requires one and makes \"Password only\" the default, so the first administrator signs in with the password alone. Omitted leaves the policies as they are. false needs the `admin` scope; false with require_mfa: true is a 400.",
  }),
  new_user_password_mode: z.enum(["default", "random"]).optional(),
  password_policy: PasswordPolicySchema.optional(),
  rate_limit: z.object({ max_attempts: z.number().optional(), window_minutes: z.number().optional() }).optional(),
  cursor_trail: z.object({ enabled: z.boolean().optional(), characters: z.string().optional() }).optional(),
  session_limits: z.object({ max_hours: z.number().optional(), idle_minutes: z.number().optional() }).optional(),
  complete: z.boolean().optional(),
});

defineRoute({
  method: "post", path: "/api/v1/setup", tag: "Status", permission: "settings:write",
  summary: "Configure the instance (first run, or re-run to converge)",
  description: "Applies settings, then creates or resets the administrator (needs `*`), then marks setup complete when `complete` is true - which retires the bootstrap token, so send it last.",
  body: SetupBody,
  response: z.object({ ok: z.literal(true), applied: z.array(z.string()), setup_completed: z.boolean(), admin: z.object({ upn: z.string(), password: z.string().optional() }).optional() }),
}, async (c) => {
  try {
    const result = await runSetup(apiCtx(c), await readJson<SetupInput>(c), "api");
    return c.json({ ok: true as const, ...result });
  } catch (err) {
    if (err instanceof SetupAdminError) return c.json({ error: "setup_failed", message: err.message, details: err.details }, 400);
    throw err;
  }
});

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

defineRoute({
  method: "get", path: "/api/v1/domains", tag: "Domains", permission: "domains:read", summary: "List domains",
  response: z.object({ domains: z.array(z.object({ domain: z.string(), is_default: z.boolean(), brand_id: z.number().nullable().openapi({ description: "The brand its people see (`/api/v1/branding/brands/{id}`); null for the default brand." }), created_at: z.string() })) }),
}, async (c) => {
  const domains = await listDomains(c.env);
  return c.json({
    domains: domains.map((d) => ({ domain: d.domain, is_default: d.is_default === 1, brand_id: d.brand_id ?? null, created_at: d.created_at })),
  });
});

defineRoute({
  method: "put", path: "/api/v1/domains/{domain}/brand", tag: "Domains", permission: "domains:write",
  summary: "Choose the brand a domain's people see",
  description: "`brand_id` null is the default brand. The sign-in pages, My account and emails follow the person's UPN domain (see Branding).",
  body: z.object({ brand_id: z.number().int().nullable() }),
  errors: [404], response: z.object({ ok: z.literal(true), domain: z.string(), brand_id: z.number().nullable() }),
}, async (c) => {
  const domain = (c.req.param("domain") ?? "").toLowerCase();
  const body = await readJson<{ brand_id?: number | null }>(c);
  const brandId = body.brand_id === null || body.brand_id === undefined ? null : Number(body.brand_id);
  await assignDomainBrand(apiCtx(c), domain, brandId);
  return c.json({ ok: true as const, domain, brand_id: brandId });
});

defineRoute({
  method: "post", path: "/api/v1/domains", tag: "Domains", permission: "domains:write", summary: "Add a domain (idempotent)",
  body: z.object({ domain: z.string(), set_default: z.boolean().optional() }),
  response: z.object({ ok: z.literal(true), domain: z.string(), is_default: z.boolean() }),
}, async (c) => {
  const body = await readJson<{ domain?: string; set_default?: boolean }>(c);
  const domain = String(body.domain ?? "").trim().toLowerCase();
  if (!domain) return c.json(badRequest("domain is required."), 400);

  const existing = await listDomains(c.env);
  if (!existing.some((d) => d.domain === domain)) await addDomain(c.env, domain);

  if (body.set_default) {
    const row = (await listDomains(c.env)).find((d) => d.domain === domain);
    if (row) await setDefaultDomain(c.env, row.id);
  }

  await logAudit(c.env, auditActor(c.get("apiActor")), "domain.added", domain, undefined, c.req.raw);
  return c.json({ ok: true, domain, is_default: Boolean(body.set_default) });
});

defineRoute({
  method: "post", path: "/api/v1/domains/{domain}/default", tag: "Domains", permission: "domains:write", summary: "Make a domain the default",
  errors: [404], response: z.object({ ok: z.literal(true), default_domain: z.string() }),
}, async (c) => {
  const domain = (c.req.param("domain") ?? "").toLowerCase();
  const row = (await listDomains(c.env)).find((d) => d.domain === domain);
  if (!row) return c.json({ error: "not_found", message: `No such domain "${domain}".` }, 404);

  await setDefaultDomain(c.env, row.id);
  await logAudit(c.env, auditActor(c.get("apiActor")), "domain.set_default", domain, undefined, c.req.raw);
  return c.json({ ok: true, default_domain: domain });
});

/**
 * Rewrites every user's UPN onto this domain, keeping the local part.
 *
 * Kept because an already-provisioned instance sometimes has to move zone, but
 * note it is no longer how the demo suite gets its addresses right: a bundle
 * carries usernames and the domain is a parameter of the import, so there is
 * nothing to rewrite afterwards.
 */
defineRoute({
  method: "post", path: "/api/v1/domains/{domain}/apply-to-all", tag: "Domains", permission: "domains:write",
  summary: "Move every user onto this domain", description: "Also needs `*`: it rewrites Super Admin UPNs, and recovery mail follows the UPN.",
  errors: [404], response: z.object({ ok: z.literal(true), updated: z.number(), conflicts: z.array(z.string()) }),
}, async (c) => {
  const domain = (c.req.param("domain") ?? "").toLowerCase();
  const row = (await listDomains(c.env)).find((d) => d.domain === domain);
  if (!row) return c.json({ error: "not_found", message: `No such domain "${domain}".` }, 404);

  // Rewriting every UPN includes Super Admins, and recovery mail follows the
  // UPN: moving an admin onto a domain the caller registered would hand it
  // their reset link. Admin authority only, as in the console.
  if (!hasScope(c.get("apiActor").scopes, "admin")) {
    return c.json({ error: "forbidden", message: 'Applying a domain to every user (Super Admins included) requires the "admin" scope.' }, 403);
  }
  const { updated, conflicts } = await applyDomainToAllUsers(c.env, domain);
  await logAudit(c.env, auditActor(c.get("apiActor")), "domain.applied_to_all", domain, { updated, conflicts }, c.req.raw);
  return c.json({ ok: true, updated, conflicts });
});

// ---------------------------------------------------------------------------
// Directory
// ---------------------------------------------------------------------------

const BundleSchema = z
  .object({
    version: z.number().optional(),
    mode: z.enum(["merge", "replace"]).optional(),
    passwords: z.enum(["default", "none"]).optional(),
    domain: z.string().optional(),
    groups: z.array(z.object({ name: z.string(), description: z.string().optional(), rule: z.string().optional() }).passthrough()).optional(),
    users: z.array(z.object({ username: z.string() }).passthrough()).optional(),
  })
  .passthrough()
  .openapi("DirectoryBundle", { description: "Users and groups to merge into (or replace) the directory; see docs/api.md for every user field." });

const ImportResultSchema = z
  .object({
    domain: z.string(),
    mode: z.enum(["merge", "replace"]),
    users: z.object({ created: z.number(), updated: z.number(), skipped: z.number() }),
    groups: z.object({ created: z.number(), updated: z.number() }),
    generated_passwords: StringMap,
    managers_resolved: z.number(),
    errors: z.array(z.object({ username: z.string().optional(), group: z.string().optional(), message: z.string() })),
    scim: AnyObject.optional(),
  })
  .openapi("ImportResult");

defineRoute({
  method: "post", path: "/api/v1/directory/import", tag: "Directory", permission: "import:write",
  summary: "Import users and groups", description: "Idempotent. `super_admin`, admin role group membership and overwriting an administrator need `*`.",
  body: BundleSchema, response: ImportResultSchema,
}, async (c) => {
  const bundle = await readJson<DirectoryBundle>(c);
  // super_admin grants, "Super Admins" membership and overwriting an existing
  // admin are admin authority, not directory authority.
  const result = await importDirectory(c.env, bundle, { allowPrivileged: hasScope(c.get("apiActor").scopes, "admin") });

  await logAudit(
    c.env,
    auditActor(c.get("apiActor")),
    "directory.imported",
    result.domain,
    { mode: result.mode, users: result.users, groups: result.groups, errors: result.errors.length },
    c.req.raw
  );

  return c.json(result);
});

/**
 * Emails a user a single-use link: an invitation (choosing a password
 * activates the account) or, for an active account, a password reset link.
 * Needs email configured (Admin -> Integrations -> Email).
 */
defineRoute({
  method: "post", path: "/api/v1/users/{username}/invite", tag: "Users", permission: "users:write",
  summary: "Email an invitation or a password reset link",
  description: "An inactive account gets an invitation (choosing a password activates it); an active one a reset link. Needs email configured. An administrator's account needs `*`.",
  errors: [404, 409, 502], response: z.object({ ok: z.literal(true), kind: z.enum(["invite", "reset"]), to: z.string() }),
}, async (c) => {
  if (!(await isEmailConfigured(c.env))) return c.json({ error: "email_not_configured", message: "Set a From address in Admin -> Integrations -> Email first." }, 409);
  const username = (c.req.param("username") ?? "").toLowerCase();
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first<UserRow>();
  if (!user) return c.json({ error: "not_found", message: `No user "${username}".` }, 404);
  // Same rule as /directory/import: Super Admin accounts are admin authority.
  if (!hasScope(c.get("apiActor").scopes, "admin") && (await c.env.DB.prepare(
    "SELECT 1 FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.name = ?"
  ).bind(user.id, SUPER_ADMINS_GROUP).first())) {
    return c.json({ error: "forbidden", message: "Emailing a Super Admin a credential link requires the \"admin\" scope." }, 403);
  }
  const kind = user.status === "active" ? "reset" : "invite";
  // Shared with the console's invite and send-reset buttons; refuses any other
  // admin role holder below "*" too.
  const result = await sendUserLink(apiCtx(c), user, kind);
  if (!result.ok) return c.json({ error: "send_failed", message: result.error }, 502);
  return c.json({ ok: true, kind, to: recipientFor(user) });
});

/** The "remove the sample directory" wipe, as an API call. Keeps the built-in groups and the administrators. */
defineRoute({
  method: "post", path: "/api/v1/directory/reset", tag: "Directory", permission: "import:write",
  summary: "Remove every user and group except the administrators and their groups",
  response: z.object({ ok: z.literal(true), domain: z.string(), scim: AnyObject.optional() }),
}, async (c) => {
  const result = await importDirectory(c.env, { version: 1, mode: "replace", users: [], groups: [] }, { allowPrivileged: hasScope(c.get("apiActor").scopes, "admin") });
  await logAudit(c.env, auditActor(c.get("apiActor")), "directory.reset", undefined, undefined, c.req.raw);
  return c.json({ ok: true, domain: result.domain, ...(result.scim ? { scim: result.scim } : {}) });
});

defineRoute({
  method: "get", path: "/api/v1/users", tag: "Users", permission: "users:read", summary: "List users",
  query: z.object(Paging),
  response: z.object({ total: z.number(), limit: z.number(), offset: z.number(), users: z.array(UserSchema) }),
}, async (c) => {
  const limit = Math.min(Number(c.req.query("limit") ?? 100) || 100, 500);
  const offset = Math.max(Number(c.req.query("offset") ?? 0) || 0, 0);

  // Explicit column list and dynamic groups resolved: see selectUsers.
  const users = await selectUsers(c.env, { limit, offset });
  const total = await c.env.DB.prepare("SELECT COUNT(*) as n FROM users").first<{ n: number }>();

  return c.json({
    total: total?.n ?? 0,
    limit,
    offset,
    users,
  });
});

defineRoute({
  method: "get", path: "/api/v1/groups", tag: "Groups", permission: "groups:read", summary: "List groups",
  response: z.object({ groups: z.array(GroupSchema) }),
}, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT g.*, (SELECT name FROM schemas s WHERE s.id = g.schema_id) AS schema_name,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) AS explicit_member_count
       FROM groups g ORDER BY g.name`
  ).all<GroupRow & { member_count: number; explicit_member_count: number; schema_name: string | null }>();

  // Every group's members in one pass: one read of the directory for all the
  // dynamic groups, not one per group.
  const members = await resolveManyGroupMemberUserIds(c.env, results);
  const groups = results.map(({ explicit_member_count, custom_attributes, ...g }) => ({
    ...g,
    attributes: parseCustomAttributes(custom_attributes),
    member_count: members.get(g.id)?.length ?? 0,
    explicit_member_count,
  }));

  return c.json({ groups });
});

// ---------------------------------------------------------------------------
// Directory schemas
// ---------------------------------------------------------------------------

const SchemaSchema = z
  .object({
    id: z.number(), object_type: z.enum(["user", "group"]), name: z.string(), description: z.string().nullable(), builtin: z.boolean(), default: z.boolean(), conforming: z.number(),
    attributes: z.array(z.object({ name: z.string(), label: z.string(), type: z.string(), required: z.boolean(), ref_object: z.string().nullable() })),
  })
  .openapi("Schema");

defineRoute({
  method: "get", path: "/api/v1/schemas", tag: "Schemas", permission: "schemas:read", summary: "List schemas",
  query: z.object({ object_type: z.enum(["user", "group"]).optional() }),
  response: z.object({ schemas: z.array(SchemaSchema) }),
}, async (c) => {
  const objectType = c.req.query("object_type");
  const schemas = await listSchemas(c.env, objectType === "group" ? "group" : objectType === "user" ? "user" : undefined);
  const result = await Promise.all(
    schemas.map(async (s) => ({
      id: s.id,
      object_type: s.object_type,
      name: s.name,
      description: s.description,
      builtin: s.builtin === 1,
      default: s.is_default === 1,
      conforming: await countConforming(c.env, s.id, s.object_type),
      attributes: (await getSchemaAttributes(c.env, s.id)).map((a) => ({
        name: a.name,
        label: a.label,
        type: a.type,
        required: a.required === 1,
        ref_object: a.ref_object,
      })),
    }))
  );
  return c.json({ schemas: result });
});

defineRoute({
  method: "post", path: "/api/v1/schemas", tag: "Schemas", permission: "schemas:write", summary: "Create a schema",
  body: z.object({ object_type: z.enum(["user", "group"]).optional(), name: z.string(), description: z.string().optional(), attributes: z.array(SchemaAttributeInput).optional() }),
  status: 201, errors: [409], response: z.object({ id: z.number() }),
}, async (c) => {
  const body = await readJson<{
    object_type?: string;
    name?: string;
    description?: string;
    attributes?: { name: string; label?: string; type?: string; required?: boolean; ref_object?: string; user_editable?: boolean }[];
  }>(c);
  const objectType = body.object_type === "group" ? "group" : "user";
  const name = String(body.name ?? "").trim();
  if (!name) return c.json(badRequest("name is required."), 400);
  if (await findSchema(c.env, objectType, name)) return c.json({ error: "conflict", message: `A ${objectType} schema named "${name}" already exists.` }, 409);

  const id = await createSchema(c.env, objectType, name, String(body.description ?? "").trim());
  if (body.attributes) await saveSchemaAttributes(c.env, id, body.attributes.map((a) => ({ name: a.name, label: a.label ?? a.name, type: a.type ?? "string", required: a.required, ref_object: a.ref_object, user_editable: a.user_editable })));
  await logAudit(c.env, auditActor(c.get("apiActor")), "schema.created", `${objectType}:${name}`, undefined, c.req.raw);
  return c.json({ id }, 201);
});

defineRoute({
  method: "patch", path: "/api/v1/schemas/{id}", tag: "Schemas", permission: "schemas:write", summary: "Update a schema",
  description: "`attributes`, when given, replaces the attribute list.",
  params: IdParam, body: z.object({ name: z.string().optional(), description: z.string().optional(), attributes: z.array(SchemaAttributeInput).optional() }),
  errors: [404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return c.json({ error: "not_found" }, 404);
  const body = await readJson<{
    name?: string;
    description?: string;
    attributes?: { name: string; label?: string; type?: string; required?: boolean; ref_object?: string; user_editable?: boolean }[];
  }>(c);
  const name = String(body.name ?? schema.name).trim();
  const description = body.description === undefined ? schema.description : String(body.description).trim() || null;

  await c.env.DB.prepare("UPDATE schemas SET name = ?, description = ? WHERE id = ?").bind(name, description, id).run();
  if (body.attributes) {
    await saveSchemaAttributes(c.env, id, body.attributes.map((a) => ({ name: a.name, label: a.label ?? a.name, type: a.type ?? "string", required: a.required, ref_object: a.ref_object, user_editable: a.user_editable })));
  }
  await logAudit(c.env, auditActor(c.get("apiActor")), "schema.updated", `${schema.object_type}:${name}`, undefined, c.req.raw);
  return c.json({ ok: true });
});

defineRoute({
  method: "post", path: "/api/v1/schemas/{id}/apply", tag: "Schemas", permission: "schemas:write", summary: "Move every user (or group) onto this schema",
  params: IdParam, errors: [404], response: z.object({ applied: z.number() }),
}, async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return c.json({ error: "not_found" }, 404);
  const count = await applySchemaToAll(c.env, schema);
  await logAudit(c.env, auditActor(c.get("apiActor")), "schema.applied", `${schema.object_type}:${schema.name}`, { count }, c.req.raw);
  return c.json({ applied: count });
});

defineRoute({
  method: "delete", path: "/api/v1/schemas/{id}", tag: "Schemas", permission: "schemas:write", summary: "Delete a schema",
  description: "Objects on it move to the default schema. Provided schemas cannot be deleted.",
  params: IdParam, errors: [404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const schema = await getSchema(c.env, id);
  if (!schema) return c.json({ error: "not_found" }, 404);
  if (schema.builtin) return c.json({ error: "forbidden", message: "Provided schemas cannot be deleted." }, 403);

  // Objects on it move to the default schema, conforming as they go.
  const fallback = await getSchema(c.env, Number(await defaultSchemaId(c.env, schema.object_type)));
  if (fallback) await applySchemaToAll(c.env, fallback, id);
  await c.env.DB.prepare("DELETE FROM schemas WHERE id = ?").bind(id).run();
  await logAudit(c.env, auditActor(c.get("apiActor")), "schema.deleted", `${schema.object_type}:${schema.name}`, undefined, c.req.raw);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// OIDC clients
// ---------------------------------------------------------------------------

defineRoute({
  method: "get", path: "/api/v1/clients", tag: "OIDC clients", permission: "oidc:read", summary: "List OIDC clients",
  response: z.object({ clients: z.array(z.object({ id: z.number(), client_id: z.string(), name: z.string(), redirect_uris: z.array(z.string()), id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS), created_at: z.string() })) }),
}, async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, client_id, name, redirect_uris, id_token_signed_response_alg, created_at FROM oauth_clients ORDER BY name"
  ).all<Omit<OAuthClientRow, "client_secret_hash">>();

  return c.json({
    clients: results.map((cl) => ({
      id: cl.id,
      client_id: cl.client_id,
      name: cl.name,
      redirect_uris: JSON.parse(cl.redirect_uris) as string[],
      id_token_signed_response_alg: isIdTokenAlg(cl.id_token_signed_response_alg) ? cl.id_token_signed_response_alg : "RS256",
      created_at: cl.created_at,
    })),
  });
});

/**
 * Registers a relying party, optionally with credentials the caller chose.
 *
 * The seeded-credential path is what makes a single-pass Terraform apply
 * possible: Terraform needs this client's id and secret to create the Access
 * identity provider, and it cannot read a value out of an application it has
 * not deployed yet. So it generates the pair, passes it in here, and nothing
 * has to flow back. The 24-character floor exists because a short secret used
 * to be silently replaced with a generated one, which left Access holding a
 * credential FlareID had never heard of and every login failing with nothing
 * to explain why - so now it is a 400.
 */
defineRoute({
  method: "post", path: "/api/v1/clients", tag: "OIDC clients", permission: "oidc:write",
  summary: "Register an OIDC client (idempotent on a supplied client_id)",
  description: "Supply `client_id` and `client_secret` (24+ characters) together to seed known credentials; omit both to have them generated (the secret is returned once).",
  body: z.object({
    name: z.string(),
    redirect_uris: z.array(z.string()),
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
    client_type: z.enum(["confidential", "public"]).optional(),
    trusted: z.boolean().optional(),
    allowed_claims: z.array(z.string()).nullable().optional(),
    post_logout_redirect_uris: z.array(z.string()).optional(),
    frontchannel_logout_uri: z.string().optional(),
    id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS).optional().openapi({ description: "How this client's id_tokens are signed (default RS256)." }),
  }),
  response: z.object({ ok: z.literal(true), created: z.boolean(), id: z.number(), client_id: z.string(), client_secret: z.string().optional(), client_type: z.string().optional(), redirect_uris: z.array(z.string()), id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS) }),
}, async (c) => {
  const body = await readJson<{
    name?: string;
    redirect_uris?: string[];
    client_id?: string;
    client_secret?: string;
    client_type?: "confidential" | "public";
    trusted?: boolean;
    allowed_claims?: string[] | null;
    post_logout_redirect_uris?: string[];
    frontchannel_logout_uri?: string;
    id_token_signed_response_alg?: string;
  }>(c);
  const isPublic = body.client_type === "public";
  if (body.client_type !== undefined && body.client_type !== "public" && body.client_type !== "confidential") {
    return c.json(badRequest('client_type must be "confidential" or "public".'), 400);
  }
  if (isPublic && body.client_secret) return c.json(badRequest("A public client has no secret; omit client_secret."), 400);
  const badClaim = (body.allowed_claims ?? []).find((g) => !(CLAIM_GROUPS as readonly string[]).includes(g));
  if (badClaim) return c.json(badRequest(`Unknown claim group "${badClaim}". Valid: ${CLAIM_GROUPS.join(", ")}.`), 400);
  const trusted = body.trusted === false ? 0 : 1;
  // null/omitted = every group (the pre-v3 behaviour); a list = exactly those.
  const allowedClaims = Array.isArray(body.allowed_claims) ? JSON.stringify(CLAIM_GROUPS.filter((g) => body.allowed_claims!.includes(g))) : null;
  const postLogoutList = (body.post_logout_redirect_uris ?? []).map((u) => String(u).trim()).filter(Boolean);
  const badLogout = postLogoutList.find((u) => !isValidPostLogoutUri(u));
  if (badLogout) return c.json(badRequest(`post_logout_redirect_uri "${badLogout}" must be https (or http on a loopback host).`), 400);
  const postLogout = JSON.stringify(postLogoutList);
  const fcl = body.frontchannel_logout_uri === undefined ? undefined : validFrontchannelUri(String(body.frontchannel_logout_uri).trim());
  if (body.frontchannel_logout_uri && !fcl) return c.json(badRequest("frontchannel_logout_uri must be an https URL."), 400);
  if (body.id_token_signed_response_alg !== undefined && !isIdTokenAlg(body.id_token_signed_response_alg)) {
    return c.json(badRequest(`id_token_signed_response_alg must be one of ${ID_TOKEN_ALGS.join(", ")}.`), 400);
  }
  const idTokenAlg = body.id_token_signed_response_alg as "RS256" | "ES256" | undefined;
  const name = String(body.name ?? "").trim();
  if (!name) return c.json(badRequest("name is required."), 400);

  const redirectUris = (Array.isArray(body.redirect_uris) ? body.redirect_uris : [])
    .map((u) => String(u).trim())
    .filter(Boolean);
  if (redirectUris.length === 0) return c.json(badRequest("At least one redirect_uri is required."), 400);

  const seededId = String(body.client_id ?? "").trim();
  const seededSecret = String(body.client_secret ?? "").trim();
  if (!isPublic && (seededId === "") !== (seededSecret === "")) {
    return c.json(badRequest("client_id and client_secret must be supplied together, or neither."), 400);
  }
  if (seededSecret !== "" && seededSecret.length < 24) {
    return c.json(badRequest(`client_secret is ${seededSecret.length} characters; at least 24 are required.`), 400);
  }

  const existing = seededId
    ? await c.env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(seededId).first<{ id: number }>()
    : null;

  const clientId = seededId || `flareid_${randomToken(8)}`;
  const clientSecret = isPublic ? "" : seededSecret || randomToken(24);
  const clientSecretHash = isPublic ? "" : await sha256Hex(clientSecret);

  // Idempotent on the seeded id: re-running provisioning should converge, not
  // collide on the unique index.
  if (existing) {
    await c.env.DB.prepare(
      "UPDATE oauth_clients SET name = ?, redirect_uris = ?, client_secret_hash = ?, client_type = ?, trusted = ?, allowed_claims = ?, post_logout_redirect_uris = ? WHERE id = ?"
    )
      .bind(name, JSON.stringify(redirectUris), clientSecretHash, isPublic ? "public" : "confidential", trusted, allowedClaims, postLogout, existing.id)
      .run();
    if (fcl !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ? WHERE client_id = ?").bind(fcl, clientId).run();
    if (idTokenAlg) await c.env.DB.prepare("UPDATE oauth_clients SET id_token_signed_response_alg = ? WHERE id = ?").bind(idTokenAlg, existing.id).run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "oidc_client.updated", name, { client_id: clientId }, c.req.raw);
    const alg = (await c.env.DB.prepare("SELECT id_token_signed_response_alg AS alg FROM oauth_clients WHERE id = ?").bind(existing.id).first<{ alg: string }>())?.alg;
    return c.json({ ok: true, created: false, id: existing.id, client_id: clientId, redirect_uris: redirectUris, id_token_signed_response_alg: isIdTokenAlg(alg) ? alg : "RS256" });
  }

  const result = await c.env.DB.prepare(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, client_type, trusted, allowed_claims, post_logout_redirect_uris)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(clientId, clientSecretHash, name, JSON.stringify(redirectUris), new Date().toISOString(), isPublic ? "public" : "confidential", trusted, allowedClaims, postLogout)
    .run();

  if (fcl !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ? WHERE client_id = ?").bind(fcl, clientId).run();
  if (idTokenAlg) await c.env.DB.prepare("UPDATE oauth_clients SET id_token_signed_response_alg = ? WHERE client_id = ?").bind(idTokenAlg, clientId).run();
  await logAudit(c.env, auditActor(c.get("apiActor")), "oidc_client.created", name, { client_id: clientId }, c.req.raw);

  return c.json({
    ok: true,
    created: true,
    id: result.meta.last_row_id,
    client_id: clientId,
    // Returned once, and only when we generated it - a caller that supplied its
    // own already has it.
    ...(seededSecret || isPublic ? {} : { client_secret: clientSecret }),
    client_type: isPublic ? "public" : "confidential",
    redirect_uris: redirectUris,
    id_token_signed_response_alg: idTokenAlg ?? "RS256",
  });
});

// ---------------------------------------------------------------------------
// SCIM (FlareID as a SCIM client, pushing to e.g. Cloudflare Access)
// ---------------------------------------------------------------------------

defineRoute({
  method: "post", path: "/api/v1/scim/config", tag: "SCIM", permission: "scim:write", summary: "Set the SCIM endpoint, secret and scope",
  description: "A changed scope re-evaluates everything already pushed, after the response.",
  body: z.object({ endpoint: z.string().optional(), secret: z.string().optional(), scope: z.object({ mode: z.enum(["all", "selected"]).optional(), group_ids: z.array(z.number()).optional() }).optional() }),
}, async (c) => {
  const body = await readJson<{ endpoint?: string; secret?: string; scope?: { mode?: string; group_ids?: number[] } }>(c);

  if (body.endpoint !== undefined || body.secret !== undefined) {
    await setScimConfig(c.env, { endpoint: String(body.endpoint ?? ""), secret: String(body.secret ?? "") });
  }
  if (body.scope) {
    // As in the console: what was already pushed is re-evaluated against the new scope.
    await applyScimScope(apiCtx(c), {
      mode: body.scope.mode === "selected" ? "selected" : "all",
      groupIds: Array.isArray(body.scope.group_ids) ? body.scope.group_ids.map(Number) : [],
    }, (p) => c.executionCtx.waitUntil(p));
  }

  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_config_changed", undefined, undefined, c.req.raw);
  return c.json({ ok: true });
});

defineRoute({
  method: "post", path: "/api/v1/scim/test", tag: "SCIM", permission: "scim:write", summary: "Test the SCIM connection",
  response: z.object({ ok: z.boolean(), status: z.number().optional(), error: z.string().optional() }).passthrough(),
}, async (c) => {
  const result = await testScimConnection(c.env);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.connection_tested", undefined, { ok: result.ok }, c.req.raw);
  return c.json(result);
});

defineRoute({
  method: "post", path: "/api/v1/scim/sync", tag: "SCIM", permission: "scim:write", summary: "Push the next batch of users, then the groups",
  description: "Call again until `complete` is true.",
  response: z.object({ ok: z.boolean(), complete: z.boolean() }).passthrough(),
}, async (c) => {
  const summary = await syncAll(c.env);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.sync_all", undefined, { ...summary }, c.req.raw);
  return c.json({ ok: summary.userErrors === 0 && summary.groupErrors === 0, ...summary });
});

// ---------------------------------------------------------------------------
// SAML service providers
// ---------------------------------------------------------------------------

function spJson(sp: SamlServiceProviderRow) {
  return {
    id: sp.id,
    entity_id: sp.entity_id,
    name: sp.name,
    acs_urls: JSON.parse(sp.acs_urls) as string[],
    default_acs_url: sp.default_acs_url,
    nameid_format: sp.nameid_format,
    attribute_map: JSON.parse(sp.attribute_map) as Record<string, string>,
    sign_response: sp.sign_response === 1,
    sign_assertion: sp.sign_assertion === 1,
    want_authn_requests_signed: sp.want_authn_requests_signed === 1,
    signing_certs: JSON.parse(sp.signing_certs) as string[],
    slo_url: sp.slo_url,
    encryption_cert: sp.encryption_cert,
    encrypt_assertions: sp.encrypt_assertions === 1,
    created_at: sp.created_at,
    updated_at: sp.updated_at,
  };
}

defineRoute({
  method: "get", path: "/api/v1/saml/service-providers", tag: "SAML", permission: "saml:read", summary: "List SAML service providers",
  response: z.object({ service_providers: z.array(ServiceProviderSchema) }),
}, async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM saml_service_providers ORDER BY name").all<SamlServiceProviderRow>();
  return c.json({ service_providers: results.map(spJson) });
});

interface SpUpsertBody {
  subject_id?: "" | "subject-id" | "pairwise-id";
  entity_id?: string;
  name?: string;
  acs_urls?: string[];
  default_acs_url?: string;
  nameid_format?: string;
  attribute_map?: Record<string, string>;
  sign_response?: boolean;
  sign_assertion?: boolean;
  want_authn_requests_signed?: boolean;
  signing_certs?: string[];
  slo_url?: string | null;
  encryption_cert?: string | null;
  encrypt_assertions?: boolean;
}

/**
 * Registers a service provider, keyed on entity_id so re-running provisioning
 * converges rather than colliding on the unique index - the same idempotence
 * rule as POST /api/v1/clients. On update, fields not supplied keep their
 * existing values; on create, the documented defaults apply.
 */
defineRoute({
  method: "post", path: "/api/v1/saml/service-providers", tag: "SAML", permission: "saml:write",
  summary: "Register or update a service provider (keyed on entity_id)",
  description: "On update, fields not supplied keep their values; on create, the documented defaults apply.",
  body: z.object({
    entity_id: z.string(),
    name: z.string().optional(),
    acs_urls: z.array(z.string()).optional(),
    default_acs_url: z.string().optional(),
    nameid_format: z.string().optional(),
    attribute_map: StringMap.optional(),
    sign_response: z.boolean().optional(),
    sign_assertion: z.boolean().optional(),
    want_authn_requests_signed: z.boolean().optional(),
    signing_certs: z.array(z.string()).optional(),
    slo_url: z.string().nullable().optional(),
    encryption_cert: z.string().nullable().optional(),
    encrypt_assertions: z.boolean().optional(),
    subject_id: z.enum(["", "subject-id", "pairwise-id"]).optional(),
  }),
  response: z.object({ ok: z.literal(true), created: z.boolean(), id: z.number(), entity_id: z.string() }),
}, async (c) => {
  const body = await readJson<SpUpsertBody>(c);
  const entityId = String(body.entity_id ?? "").trim();
  if (!entityId) return c.json(badRequest("entity_id is required."), 400);

  const existing = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE entity_id = ?")
    .bind(entityId)
    .first<SamlServiceProviderRow>();

  const acsUrls = body.acs_urls !== undefined ? body.acs_urls.map((u) => String(u).trim()).filter(Boolean) : existing ? (JSON.parse(existing.acs_urls) as string[]) : [];
  if (acsUrls.length === 0) return c.json(badRequest("At least one acs_url is required."), 400);

  const nameidFormat = body.nameid_format ?? existing?.nameid_format ?? "transient";
  if (!nameIdFormatUri(nameidFormat)) return c.json(badRequest(`Unsupported nameid_format "${nameidFormat}".`), 400);

  const attributeMap = body.attribute_map ?? (existing ? (JSON.parse(existing.attribute_map) as Record<string, string>) : {});
  for (const field of Object.values(attributeMap)) {
    if (!USER_ATTRIBUTE_FIELDS.includes(field as (typeof USER_ATTRIBUTE_FIELDS)[number])) {
      return c.json(badRequest(`"${field}" is not a user attribute field. Valid fields: ${USER_ATTRIBUTE_FIELDS.join(", ")}.`), 400);
    }
  }

  const wantSigned = body.want_authn_requests_signed ?? existing?.want_authn_requests_signed === 1;
  const signingCerts = (body.signing_certs ?? (existing ? (JSON.parse(existing.signing_certs) as string[]) : []))
    .map((cert) => normalizeCertPem(cert))
    .filter((pem): pem is string => pem !== null);
  if (wantSigned && signingCerts.length === 0) {
    return c.json(badRequest("want_authn_requests_signed needs at least one signing certificate."), 400);
  }

  const sloUrl = body.slo_url !== undefined ? (body.slo_url ? String(body.slo_url).trim() : null) : (existing?.slo_url ?? null);
  if (sloUrl && !sloUrl.startsWith("https://")) return c.json(badRequest("slo_url must be https."), 400);
  const encryptionCert = body.encryption_cert !== undefined ? (body.encryption_cert ? normalizeCertPem(body.encryption_cert) : null) : (existing?.encryption_cert ?? null);
  if (body.encryption_cert && !encryptionCert) return c.json(badRequest("encryption_cert could not be parsed."), 400);
  const encrypt = body.encrypt_assertions ?? existing?.encrypt_assertions === 1;
  if (encrypt && !encryptionCert) return c.json(badRequest("encrypt_assertions needs an encryption_cert."), 400);

  const name = String(body.name ?? existing?.name ?? entityId).trim();
  const now = new Date().toISOString();
  const values = [
    entityId,
    name,
    JSON.stringify(acsUrls),
    body.default_acs_url ?? existing?.default_acs_url ?? null,
    nameidFormat,
    JSON.stringify(attributeMap),
    (body.sign_response ?? (existing ? existing.sign_response === 1 : true)) ? 1 : 0,
    (body.sign_assertion ?? (existing ? existing.sign_assertion === 1 : true)) ? 1 : 0,
    wantSigned ? 1 : 0,
    JSON.stringify(signingCerts),
    sloUrl,
    encryptionCert,
    encrypt ? 1 : 0,
  ];

  if (existing) {
    await c.env.DB.prepare(
      `UPDATE saml_service_providers SET entity_id = ?, name = ?, acs_urls = ?, default_acs_url = ?, nameid_format = ?, attribute_map = ?, sign_response = ?, sign_assertion = ?, want_authn_requests_signed = ?, signing_certs = ?, slo_url = ?, encryption_cert = ?, encrypt_assertions = ?, updated_at = ? WHERE id = ?`
    )
      .bind(...values, now, existing.id)
      .run();
    if (body.subject_id !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE entity_id = ?").bind(["subject-id", "pairwise-id"].includes(String(body.subject_id)) ? String(body.subject_id) : "", entityId).run();
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml_sp.updated", name, { entity_id: entityId }, c.req.raw);
    return c.json({ ok: true, created: false, id: existing.id, entity_id: entityId });
  }

  const result = await c.env.DB.prepare(
    `INSERT INTO saml_service_providers (entity_id, name, acs_urls, default_acs_url, nameid_format, attribute_map, sign_response, sign_assertion, want_authn_requests_signed, signing_certs, slo_url, encryption_cert, encrypt_assertions, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(...values, now, now)
    .run();

  if (body.subject_id !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE entity_id = ?").bind(["subject-id", "pairwise-id"].includes(String(body.subject_id)) ? String(body.subject_id) : "", entityId).run();
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml_sp.created", name, { entity_id: entityId }, c.req.raw);
  return c.json({ ok: true, created: true, id: result.meta.last_row_id, entity_id: entityId });
});

// Keyed on the numeric row id, not entity_id: entity IDs are URLs, and a
// URL full of slashes cannot ride inside a path segment.
/**
 * Registers (or updates, keyed on entityID) a service provider from its SAML
 * metadata XML: ACS URLs, signing and encryption certificates, the Single
 * Logout URL and the NameID format. Body: { "xml": "<md:EntityDescriptor ...>" }.
 */
defineRoute({
  method: "post", path: "/api/v1/saml/service-providers/import-metadata", tag: "SAML", permission: "saml:write",
  summary: "Register or update a service provider from its metadata",
  description: "Pasted `xml`, or a `url` that is fetched now and re-read daily.",
  body: z.object({ xml: z.string().optional(), url: z.string().optional(), name: z.string().optional() }),
  response: z.object({ ok: z.literal(true), id: z.number(), entity_id: z.string(), acs_urls: z.array(z.string()), slo_url: z.string().nullable(), encryption: z.boolean(), subject_id: z.string().nullable(), refresh: z.boolean() }).passthrough(),
}, async (c) => {
  const body = await readJson<{ xml?: string; url?: string; name?: string }>(c);
  let meta: ParsedSpMetadata;
  try {
    // A URL is fetched now and re-read daily by the cron; pasted XML is a one-off.
    meta = body.url ? await fetchSpMetadata(String(body.url)) : parseSpMetadata(String(body.xml ?? ""));
  } catch (e) {
    if (e instanceof SpMetadataError) return c.json(badRequest(e.message), 400);
    throw e;
  }
  const id = await upsertSpFromMetadata(c.env, meta, body.name, body.url ? String(body.url) : undefined);
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml_sp.metadata_imported", meta.entityId, { acs_urls: meta.acsUrls.length }, c.req.raw);
  return c.json({ ok: true, id, entity_id: meta.entityId, acs_urls: meta.acsUrls, slo_url: meta.sloUrl, encryption: Boolean(meta.encryptionCert), subject_id: meta.subjectId, refresh: Boolean(body.url) });
});

defineRoute({
  method: "delete", path: "/api/v1/saml/service-providers/{id}", tag: "SAML", permission: "saml:write", summary: "Delete a service provider",
  params: IdParam, errors: [404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const existing = await c.env.DB.prepare("SELECT id, name, entity_id FROM saml_service_providers WHERE id = ?").bind(id).first<{ id: number; name: string; entity_id: string }>();
  if (!existing) return c.json({ error: "not_found", message: `No service provider with id ${id}.` }, 404);

  await c.env.DB.prepare("DELETE FROM saml_service_providers WHERE id = ?").bind(id).run();
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml_sp.deleted", existing.name, { entity_id: existing.entity_id }, c.req.raw);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

defineRoute({
  method: "post", path: "/api/v1/api-keys", tag: "API keys", permission: "admin", summary: "Mint an API key",
  description: "`scopes` are permissions (`users:read`, `oidc:write`, `*`) or the legacy scopes; omit for an admin key. The token is returned once.",
  body: z.object({ name: z.string(), scopes: z.array(z.string()).optional(), expires_at: z.string().nullable().optional() }),
  response: z.object({ ok: z.literal(true), id: z.number(), name: z.string(), scopes: z.array(z.string()), token: z.string() }),
}, async (c) => {
  const body = await readJson<{ name?: string; scopes?: string[]; expires_at?: string }>(c);
  const name = String(body.name ?? "").trim();
  if (!name) return c.json(badRequest("name is required."), 400);

  const requested = Array.isArray(body.scopes) ? body.scopes.map(String) : ["admin"];
  const invalid = requested.filter((s) => !isApiScope(s));
  if (invalid.length > 0) return c.json(badRequest(`Unknown scope(s): ${invalid.join(", ")}.`), 400);
  // An explicit empty list used to be stored as admin while the response and
  // the audit entry said "no scopes". Omit `scopes` to mean admin; [] is an error.
  if (requested.length === 0) return c.json(badRequest("scopes cannot be empty. Omit it for an admin key, or list the scopes the key needs."), 400);

  // An unparseable expiry used to be stored as-is, and NaN never compares as
  // expired - so a typo produced a key that lives forever.
  let expiresAt: string | null = null;
  if (body.expires_at !== undefined && body.expires_at !== null) {
    const when = Date.parse(String(body.expires_at));
    if (!Number.isFinite(when)) return c.json(badRequest("expires_at must be an ISO 8601 date-time."), 400);
    if (when <= Date.now()) return c.json(badRequest("expires_at must be in the future."), 400);
    expiresAt = new Date(when).toISOString();
  }

  const created = await createApiKey(c.env, {
    name,
    scopes: requested as ApiScope[],
    createdBy: c.get("apiActor").label,
    expiresAt,
  });

  await logAudit(c.env, auditActor(c.get("apiActor")), "api_key.created", name, { scopes: requested }, c.req.raw);

  // The only time the token is ever returned.
  return c.json({ ok: true, id: created.id, name, scopes: requested, token: created.token });
});

// ---------------------------------------------------------------------------
// Break-glass
// ---------------------------------------------------------------------------

/**
 * The one route the bootstrap token still answers after setup is complete.
 *
 * It exists because the alternative is a locked-out deployment whose only
 * recovery is hand-editing D1. It re-mints (or re-enables, and resets the
 * password of) a Super Admin, and it shouts about it in the audit log. An
 * operator who does not want this door to exist deletes the secret:
 * `wrangler secret delete BOOTSTRAP_TOKEN`.
 */
defineRoute({
  method: "post", path: "/api/v1/recovery/admin-reset", tag: "Recovery", permission: null,
  summary: "Re-mint a Super Admin (break-glass)", description: "Only the BOOTSTRAP_TOKEN secret is accepted, before or after setup. Loudly audited.",
  body: z.object({ username: z.string(), password: z.string().optional() }),
  response: z.object({ ok: z.literal(true), upn: z.string(), password: z.string() }),
}, async (c) => {
  const header = c.req.header("Authorization") ?? "";
  const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
  if (!token || !(await bootstrapTokenValid(c.env, token))) {
    return c.json({ error: "forbidden", message: "This route is only reachable with the BOOTSTRAP_TOKEN secret." }, 403);
  }

  const body = await readJson<{ username?: string; password?: string }>(c);
  const username = String(body.username ?? "").trim().toLowerCase();
  if (!username) return c.json(badRequest("username is required."), 400);

  const password = String(body.password ?? "") || randomToken(12);
  const domain = await getDefaultDomain(c.env);

  const result = await importDirectory(
    c.env,
    {
      version: 1,
      domain,
      groups: [{ name: SUPER_ADMINS_GROUP, description: "Members can administer this directory" }],
      users: [{ username, display_name: "Administrator", given_name: "Administrator", password, status: "active", super_admin: true }],
    },
    // The bootstrap token is the highest-trust caller there is.
    { allowPrivileged: true }
  );

  if (result.errors.length > 0) {
    return c.json({ error: "recovery_failed", message: "Could not reset the administrator.", details: result.errors }, 400);
  }

  await logAudit(
    c.env,
    { id: null, upn: "bootstrap-token" },
    "idp.admin_recovery",
    `${username}@${domain}`,
    { warning: "Super Admin reset using the bootstrap secret" },
    c.req.raw
  );

  return c.json({ ok: true, upn: `${username}@${domain}`, password });
});

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

api.onError(apiErrorHandler);

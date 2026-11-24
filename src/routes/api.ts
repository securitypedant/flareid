import { z } from "@hono/zod-openapi";
import { ID_TOKEN_ALGS, isIdTokenAlg, validFrontchannelUri } from "../services/clients.js";
import { api, apiErrorHandler, AnyObject, badRequest, defineRoute, notFound, readJson } from "../api/openapi.js";
import { GroupSchema, IdParam, Paging, PasswordPolicySchema, SchemaAttributeInput, ServiceProviderSchema, StringMap, UserSchema } from "../api/schemas.js";
// Each module registers its routes on `api` when imported (users.ts also
// shares the user query with the list below).
import { selectUsers } from "../api/users.js";
import "../api/groups.js";
import "../api/access.js";
import "../api/applications.js";
import "../api/settings.js";
import "../api/monitoring.js";
import "../api/ldap.js";
import "../api/cfone.js";
import "../api/backup.js";
import "../api/ssf.js";
import { auditActor, bootstrapTokenValid } from "../lib/api-auth.js";
import { createApiKey, hasScope, isApiScope, type ApiScope } from "../lib/api-keys.js";
import { importDirectory, type DirectoryBundle } from "../lib/directory-import.js";
import { isEmailConfigured, recipientFor } from "../lib/email.js";
import { assertPolicyExists } from "../lib/auth-policy.js";
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
import { isValidDomain, addDomain, applyDomainToAllUsers, getDefaultDomain, listDomains, setDefaultDomain } from "../lib/domains.js";
import { createUpstreamIdp, deleteUpstreamIdp, getUpstreamIdp, idpConfig, MAX_JIT_GROUPS, updateUpstreamIdp, upstreamJitGroups, type UpstreamIdpInput, type UpstreamIdpRow } from "../lib/federation.js";
import { logAudit } from "../lib/audit.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { syncAll, testScimConnection } from "../lib/scim-client.js";
import { getAppName, getDisabledAlgorithms, isSetupCompleted, normalizeDisabledAlgorithms, setDisabledAlgorithms } from "../lib/settings.js";
import { getCollisionPolicy, listMappings, replaceMappings, setCollisionPolicy, validateJitTarget, validateOidcClaimTarget, validateScimOutTarget } from "../lib/mappings.js";
import { CORRELATION_KEYS, getCorrelationKeys, getMasteredFields, isValidMappingTarget, listScimMappings, MASTERING_FIELDS, replaceScimMappings, setCorrelationKeys, setMasteredFields } from "../lib/scim-mapping.js";
import { createScimTarget, deleteScimTarget, getScimTarget, listScimTargets, updateScimTarget } from "../lib/scim-targets.js";
import type { GroupRow, OAuthClientRow, SamlServiceProviderRow, UserRow } from "../lib/types.js";
import { normalizeCertPem } from "../lib/saml/x509.js";
import { fetchSpMetadata, parseSpMetadata, SpMetadataError, upsertSpFromMetadata, type ParsedSpMetadata } from "../lib/saml/sp-metadata.js";
import { CONTENT_ALGORITHMS, TRANSPORT_ALGORITHMS } from "../lib/saml/encrypt.js";
import { disabledAlgorithmInPolicy, normalizeAttributeDefinitions, parseAssignedGroupIds, parseAssignedUserIds, spAttributeDefinitions, spEncryptionPolicy } from "../lib/saml/service-providers.js";
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
  if (!isValidDomain(domain)) return c.json(badRequest(`"${domain}" is not a valid DNS domain name.`), 400);

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
  // The bundle's domain is ensured into the domains table, whose consumers
  // assume DNS names - the same gate as POST /api/v1/domains.
  const domain = String(bundle.domain ?? "").trim().toLowerCase();
  if (domain && !isValidDomain(domain)) return c.json(badRequest(`"${domain}" is not a valid DNS domain name.`), 400);
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
  query: z.object({ ...Paging, q: z.string().optional().openapi({ description: "Filter by name, UPN, username or email (substring, case-insensitive)." }) }),
  response: z.object({ total: z.number(), limit: z.number(), offset: z.number(), users: z.array(UserSchema) }),
}, async (c) => {
  const limit = Math.min(Number(c.req.query("limit") ?? 100) || 100, 500);
  const offset = Math.max(Number(c.req.query("offset") ?? 0) || 0, 0);
  const q = (c.req.query("q") ?? "").trim().toLowerCase().slice(0, 100) || undefined;

  // Explicit column list and dynamic groups resolved: see selectUsers.
  const users = await selectUsers(c.env, { q, limit, offset });
  const conds = q ? "WHERE (lower(display_name) LIKE ? ESCAPE '\\' OR lower(upn) LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR lower(email) LIKE ? ESCAPE '\\')" : "";
  const like = `%${(q ?? "").replace(/[%_\\]/g, (m) => `\\${m}`)}%`;
  const total = await c.env.DB.prepare(`SELECT COUNT(*) as n FROM users ${conds}`).bind(...(q ? [like, like, like, like] : [])).first<{ n: number }>();

  return c.json({
    total: total?.n ?? 0,
    limit,
    offset,
    users,
  });
});

defineRoute({
  method: "get", path: "/api/v1/groups", tag: "Groups", permission: "groups:read", summary: "List groups",
  query: z.object({ q: z.string().optional().openapi({ description: "Filter by name or description (substring, case-insensitive)." }) }),
  response: z.object({ groups: z.array(GroupSchema) }),
}, async (c) => {
  const q = (c.req.query("q") ?? "").trim().toLowerCase().slice(0, 100);
  const like = `%${q.replace(/[%_\\]/g, (m) => `\\${m}`)}%`;
  const { results } = await c.env.DB.prepare(
    `SELECT g.*, (SELECT name FROM schemas s WHERE s.id = g.schema_id) AS schema_name,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) AS explicit_member_count
       FROM groups g ${q ? "WHERE (lower(g.name) LIKE ? ESCAPE '\\' OR lower(g.description) LIKE ? ESCAPE '\\')" : ""} ORDER BY g.name`
  ).bind(...(q ? [like, like] : [])).all<GroupRow & { member_count: number; explicit_member_count: number; schema_name: string | null }>();

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
  const count = await applySchemaToAll(apiCtx(c), schema);
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
  if (fallback) await applySchemaToAll(apiCtx(c), fallback, id);
  await c.env.DB.prepare("DELETE FROM schemas WHERE id = ?").bind(id).run();
  await logAudit(c.env, auditActor(c.get("apiActor")), "schema.deleted", `${schema.object_type}:${schema.name}`, undefined, c.req.raw);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// OIDC clients
// ---------------------------------------------------------------------------

defineRoute({
  method: "get", path: "/api/v1/clients", tag: "OIDC clients", permission: "oidc:read", summary: "List OIDC clients",
  response: z.object({ clients: z.array(z.object({ id: z.number(), client_id: z.string(), name: z.string(), redirect_uris: z.array(z.string()), id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS), assigned_groups: z.array(z.number()), created_at: z.string() })) }),
}, async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, client_id, name, redirect_uris, id_token_signed_response_alg, access_mode, assigned_groups, assigned_users, require_mfa, requestable, policy_id, created_at FROM oauth_clients ORDER BY name"
  ).all<Omit<OAuthClientRow, "client_secret_hash">>();

  return c.json({
    clients: results.map((cl) => ({
      id: cl.id,
      client_id: cl.client_id,
      name: cl.name,
      redirect_uris: JSON.parse(cl.redirect_uris) as string[],
      id_token_signed_response_alg: isIdTokenAlg(cl.id_token_signed_response_alg) ? cl.id_token_signed_response_alg : "RS256",
      access_mode: cl.access_mode,
      assigned_groups: parseAssignedGroupIds(cl.assigned_groups),
      assigned_users: parseAssignedUserIds(cl.assigned_users),
      require_mfa: cl.require_mfa === 1,
      requestable: cl.requestable === 1,
      policy_id: cl.policy_id,
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
    backchannel_logout_uri: z.string().optional(),
    initiate_login_uri: z.string().optional(),
    id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS).optional().openapi({ description: "How this client's id_tokens are signed (default RS256)." }),
    assigned_groups: z.array(z.number()).nullable().optional().openapi({ description: "Group ids (static or dynamic) assigned to this app. On update, omitted keeps the current assignment." }),
    access_mode: z.enum(["everyone", "restricted"]).optional().openapi({ description: "restricted = only assigned users/groups reach the app; default for new apps." }),
    assigned_users: z.array(z.number()).nullable().optional().openapi({ description: "User ids assigned to this app. On update, omitted keeps the current assignment." }),
    require_mfa: z.boolean().optional().openapi({ description: "The session must carry a second factor to SSO into this app." }),
    requestable: z.boolean().optional().openapi({ description: "People without access may request it under My account -> Access." }),
    policy_id: z.number().nullable().optional().openapi({ description: "Authentication policy the sign-in must satisfy to use this app. null/0 clears the binding; omitted keeps the current one." }),
  }),
  response: z.object({ ok: z.literal(true), created: z.boolean(), id: z.number(), client_id: z.string(), client_secret: z.string().optional(), client_type: z.string().optional(), redirect_uris: z.array(z.string()), id_token_signed_response_alg: z.enum(ID_TOKEN_ALGS), assigned_groups: z.array(z.number()) }),
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
    backchannel_logout_uri?: string;
    initiate_login_uri?: string;
    id_token_signed_response_alg?: string;
    assigned_groups?: number[] | null;
    access_mode?: "everyone" | "restricted";
    assigned_users?: number[] | null;
    require_mfa?: boolean;
    requestable?: boolean;
    policy_id?: number | null;
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
  const bcl = body.backchannel_logout_uri === undefined ? undefined : validFrontchannelUri(String(body.backchannel_logout_uri).trim());
  if (body.backchannel_logout_uri && !bcl) return c.json(badRequest("backchannel_logout_uri must be an https URL."), 400);
  const init = body.initiate_login_uri === undefined ? undefined : validFrontchannelUri(String(body.initiate_login_uri).trim());
  if (body.initiate_login_uri && !init) return c.json(badRequest("initiate_login_uri must be an https URL."), 400);
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

  // undefined keeps the stored restriction.
  const assigned = body.assigned_groups === undefined ? undefined : Array.isArray(body.assigned_groups) ? JSON.stringify(body.assigned_groups.filter((n) => Number.isInteger(n))) : null;
  const assignedUsers = body.assigned_users === undefined ? undefined : Array.isArray(body.assigned_users) ? JSON.stringify(body.assigned_users.filter((n) => Number.isInteger(n))) : null;
  if (body.access_mode !== undefined && body.access_mode !== "everyone" && body.access_mode !== "restricted") return c.json(badRequest('access_mode must be "everyone" or "restricted".'), 400);

  const existing = seededId
    ? await c.env.DB.prepare("SELECT id, assigned_groups FROM oauth_clients WHERE client_id = ?").bind(seededId).first<{ id: number; assigned_groups: string | null }>()
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
    if (bcl !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET backchannel_logout_uri = ? WHERE client_id = ?").bind(bcl, clientId).run();
    if (init !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET initiate_login_uri = ? WHERE client_id = ?").bind(init, clientId).run();
    if (idTokenAlg) await c.env.DB.prepare("UPDATE oauth_clients SET id_token_signed_response_alg = ? WHERE id = ?").bind(idTokenAlg, existing.id).run();
    if (assigned !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET assigned_groups = ? WHERE id = ?").bind(assigned, existing.id).run();
    if (assignedUsers !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET assigned_users = ? WHERE id = ?").bind(assignedUsers, existing.id).run();
    if (body.access_mode !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET access_mode = ? WHERE id = ?").bind(body.access_mode, existing.id).run();
    if (body.require_mfa !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET require_mfa = ? WHERE id = ?").bind(body.require_mfa ? 1 : 0, existing.id).run();
    if (body.requestable !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET requestable = ? WHERE id = ?").bind(body.requestable ? 1 : 0, existing.id).run();
    if (body.policy_id !== undefined) {
      const pid = Number(body.policy_id) > 0 ? Number(body.policy_id) : null;
      await assertPolicyExists(c.env, pid);
      await c.env.DB.prepare("UPDATE oauth_clients SET policy_id = ? WHERE id = ?").bind(pid, existing.id).run();
    }
    await logAudit(c.env, auditActor(c.get("apiActor")), "oidc_client.updated", name, { client_id: clientId }, c.req.raw);
    const alg = (await c.env.DB.prepare("SELECT id_token_signed_response_alg AS alg FROM oauth_clients WHERE id = ?").bind(existing.id).first<{ alg: string }>())?.alg;
    return c.json({ ok: true, created: false, id: existing.id, client_id: clientId, redirect_uris: redirectUris, id_token_signed_response_alg: isIdTokenAlg(alg) ? alg : "RS256", assigned_groups: parseAssignedGroupIds(assigned === undefined ? existing.assigned_groups : assigned) });
  }

  const result = await c.env.DB.prepare(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, client_type, trusted, allowed_claims, post_logout_redirect_uris)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(clientId, clientSecretHash, name, JSON.stringify(redirectUris), new Date().toISOString(), isPublic ? "public" : "confidential", trusted, allowedClaims, postLogout)
    .run();

  if (fcl !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ? WHERE client_id = ?").bind(fcl, clientId).run();
  if (bcl !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET backchannel_logout_uri = ? WHERE client_id = ?").bind(bcl, clientId).run();
  if (init !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET initiate_login_uri = ? WHERE client_id = ?").bind(init, clientId).run();
  if (idTokenAlg) await c.env.DB.prepare("UPDATE oauth_clients SET id_token_signed_response_alg = ? WHERE client_id = ?").bind(idTokenAlg, clientId).run();
  if (assigned !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET assigned_groups = ? WHERE client_id = ?").bind(assigned, clientId).run();
  if (assignedUsers !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET assigned_users = ? WHERE client_id = ?").bind(assignedUsers, clientId).run();
  if (body.access_mode !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET access_mode = ? WHERE client_id = ?").bind(body.access_mode, clientId).run();
  if (body.require_mfa !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET require_mfa = ? WHERE client_id = ?").bind(body.require_mfa ? 1 : 0, clientId).run();
  if (body.requestable !== undefined) await c.env.DB.prepare("UPDATE oauth_clients SET requestable = ? WHERE client_id = ?").bind(body.requestable ? 1 : 0, clientId).run();
  if (body.policy_id !== undefined) {
    const pid = Number(body.policy_id) > 0 ? Number(body.policy_id) : null;
    await assertPolicyExists(c.env, pid);
    await c.env.DB.prepare("UPDATE oauth_clients SET policy_id = ? WHERE client_id = ?").bind(pid, clientId).run();
  }
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
    assigned_groups: parseAssignedGroupIds(assigned ?? null),
  });
});

// ---------------------------------------------------------------------------
// SCIM (FlareID as a SCIM client, pushing to e.g. Cloudflare Access)
// ---------------------------------------------------------------------------

defineRoute({
  method: "post", path: "/api/v1/scim/config", tag: "SCIM", permission: "admin", summary: "Set the first SCIM target's endpoint, secret, scope and tuning",
  description:
    "The legacy single-target view: updates the first target (creating one named Default when none exists). `POST /api/v1/scim/targets` and `/api/v1/scim/targets/{id}` manage them all. A changed scope re-evaluates everything already pushed, after the response. `tuning` controls how hard the client pushes: pace_ms between requests, members_per_request per group PATCH, and sync_batch users per sync call.",
  body: z.object({
    endpoint: z.string().optional(),
    secret: z.string().optional(),
    scope: z.object({ mode: z.enum(["all", "selected"]).optional(), group_ids: z.array(z.number()).optional() }).optional(),
    tuning: z.object({ pace_ms: z.number().int().min(0).max(10_000), members_per_request: z.number().int().min(1).max(500), sync_batch: z.number().int().min(10).max(500) }).optional(),
  }),
}, async (c) => {
  const body = await readJson<{ endpoint?: string; secret?: string; scope?: { mode?: string; group_ids?: number[] }; tuning?: { pace_ms?: number; members_per_request?: number; sync_batch?: number } }>(c);

  const existing = (await listScimTargets(c.env)).sort((a, b) => a.id - b.id)[0];
  if (!existing) {
    const endpoint = String(body.endpoint ?? "").trim();
    const secret = String(body.secret ?? "").trim();
    if (!endpoint || !secret) return c.json(badRequest("endpoint and secret are required to create the first target."), 400);
    try {
      await createScimTarget(c.env, {
        name: "Default",
        endpoint,
        secret,
        scope: { mode: body.scope?.mode === "selected" ? "selected" : "all", groupIds: Array.isArray(body.scope?.group_ids) ? body.scope.group_ids.map(Number) : [] },
        paceMs: body.tuning?.pace_ms ?? 200,
        membersPerRequest: body.tuning?.members_per_request ?? 50,
        syncBatchSize: body.tuning?.sync_batch ?? 50,
        enabled: true,
      });
    } catch (e) {
      return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
    }
  } else {
    const updates: Parameters<typeof updateScimTarget>[2] = {};
    if (body.endpoint !== undefined || body.secret !== undefined) {
      updates.endpoint = String(body.endpoint ?? existing.endpoint).trim();
      // A blank secret keeps the stored one; clearing the endpoint removes the credential with it.
      updates.secret = updates.endpoint === "" ? "" : String(body.secret ?? "").trim();
    }
    if (body.tuning) {
      updates.paceMs = body.tuning.pace_ms;
      updates.membersPerRequest = body.tuning.members_per_request;
      updates.syncBatchSize = body.tuning.sync_batch;
    }
    if (Object.keys(updates).length) {
      try {
        await updateScimTarget(c.env, existing.id, updates);
      } catch (e) {
        return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
      }
    }
    if (body.scope) {
      // As in the console: what was already pushed is re-evaluated against the new scope.
      await applyScimScope(apiCtx(c), existing.id, {
        mode: body.scope.mode === "selected" ? "selected" : "all",
        groupIds: Array.isArray(body.scope.group_ids) ? body.scope.group_ids.map(Number) : [],
      }, (p) => c.executionCtx.waitUntil(p));
    }
  }

  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_config_changed", undefined, undefined, c.req.raw);
  return c.json({ ok: true });
});

const ScimTargetBody = z.object({
  name: z.string().min(1).max(80),
  endpoint: z.string(),
  secret: z.string().optional(),
  scope: z.object({ mode: z.enum(["all", "selected"]).optional(), group_ids: z.array(z.number()).optional() }).optional(),
  tuning: z.object({ pace_ms: z.number().int().min(0).max(10_000), members_per_request: z.number().int().min(1).max(500), sync_batch: z.number().int().min(10).max(500) }).optional(),
  enabled: z.boolean().optional(),
});

defineRoute({
  method: "post", path: "/api/v1/scim/targets", tag: "SCIM", permission: "admin", summary: "Add an outbound SCIM target",
  // Choosing where the directory is pushed exports every account's data - the
  // outbound mirror of trusting an IdP, so this is admin scope.
  description: "One target per downstream SCIM server. `name` is unique; `secret` is write-only.",
  body: ScimTargetBody, errors: [400, 409],
}, async (c) => {
  const body = await readJson<{ name?: string; endpoint?: string; secret?: string; scope?: { mode?: string; group_ids?: number[] }; tuning?: { pace_ms?: number; members_per_request?: number; sync_batch?: number }; enabled?: boolean }>(c);
  try {
    const t = await createScimTarget(c.env, {
      name: String(body.name ?? ""),
      endpoint: String(body.endpoint ?? ""),
      secret: String(body.secret ?? ""),
      scope: { mode: body.scope?.mode === "selected" ? "selected" : "all", groupIds: Array.isArray(body.scope?.group_ids) ? body.scope.group_ids.map(Number) : [] },
      paceMs: body.tuning?.pace_ms ?? 200,
      membersPerRequest: body.tuning?.members_per_request ?? 50,
      syncBatchSize: body.tuning?.sync_batch ?? 50,
      enabled: body.enabled ?? true,
    });
    await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_target_created", t.name, undefined, c.req.raw);
    return c.json({ id: t.id, ok: true });
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
});

defineRoute({
  method: "patch", path: "/api/v1/scim/targets/{id}", tag: "SCIM", permission: "admin", summary: "Change a SCIM target",
  description: "Fields not supplied keep their values; a blank secret keeps the stored credential. A changed scope re-evaluates everything already pushed, after the response.",
  body: ScimTargetBody.partial(), errors: [400, 404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const target = await getScimTarget(c.env, id);
  if (!target) return notFound(c, "No such SCIM target.");
  const body = await readJson<{ name?: string; endpoint?: string; secret?: string; scope?: { mode?: string; group_ids?: number[] }; tuning?: { pace_ms?: number; members_per_request?: number; sync_batch?: number }; enabled?: boolean }>(c);
  const scope = body.scope ? { mode: body.scope.mode === "selected" ? ("selected" as const) : ("all" as const), groupIds: Array.isArray(body.scope.group_ids) ? body.scope.group_ids.map(Number) : [] } : undefined;
  try {
    await updateScimTarget(c.env, id, {
      name: body.name,
      endpoint: body.endpoint,
      secret: body.secret,
      paceMs: body.tuning?.pace_ms,
      membersPerRequest: body.tuning?.members_per_request,
      syncBatchSize: body.tuning?.sync_batch,
      enabled: body.enabled,
    });
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
  if (scope) {
    // As in the console: what was already pushed is re-evaluated against the new scope.
    await applyScimScope(apiCtx(c), id, scope, (p) => c.executionCtx.waitUntil(p));
  }
  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_target_changed", target.name, undefined, c.req.raw);
  return c.json({ ok: true });
});

defineRoute({
  method: "delete", path: "/api/v1/scim/targets/{id}", tag: "SCIM", permission: "scim:write", summary: "Remove a SCIM target",
  description: "Links, push state and queued deprovisions go with it; the objects already created downstream are left there.",
  errors: [404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const target = await getScimTarget(c.env, id);
  if (!target) return notFound(c, "No such SCIM target.");
  await deleteScimTarget(c.env, id);
  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_target_deleted", target.name, undefined, c.req.raw);
  return c.json({ ok: true });
});

defineRoute({
  method: "post", path: "/api/v1/scim/test", tag: "SCIM", permission: "scim:write", summary: "Test a SCIM connection",
  description: "`target_id` picks the target; without it the first enabled one.",
  body: z.object({ target_id: z.number().int().optional() }).optional(),
  response: z.object({ ok: z.boolean(), status: z.number().optional(), error: z.string().optional() }).passthrough(),
}, async (c) => {
  const body = await readJson<{ target_id?: number }>(c).catch(() => ({}) as { target_id?: number });
  const result = await testScimConnection(c.env, body?.target_id);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.connection_tested", undefined, { ok: result.ok, target_id: body?.target_id }, c.req.raw);
  return c.json(result);
});

defineRoute({
  method: "post", path: "/api/v1/scim/sync", tag: "SCIM", permission: "admin", summary: "Push the next batch of users, then the groups",
  description: "Call again until `complete` is true. `target_id` picks the target; without it the first enabled one.",
  body: z.object({ target_id: z.number().int().optional() }).optional(),
  response: z.object({ ok: z.boolean(), complete: z.boolean() }).passthrough(),
}, async (c) => {
  const body = await readJson<{ target_id?: number }>(c).catch(() => ({}) as { target_id?: number });
  const summary = await syncAll(c.env, { targetId: body?.target_id });
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.sync_all", undefined, { ...summary, target_id: body?.target_id }, c.req.raw);
  return c.json({ ok: summary.userErrors === 0 && summary.groupErrors === 0, ...summary });
});

// ---------------------------------------------------------------------------
// SCIM inbound attribute mappings (FlareID as a SCIM server)
// ---------------------------------------------------------------------------

defineRoute({
  method: "get", path: "/api/v1/scim/mappings", tag: "SCIM", permission: "scim:read", summary: "List inbound attribute mappings",
  description:
    "The expressions that rewrite fields on users an upstream provisioner creates or updates over the SCIM server API. Fields with no mapping keep the standard SCIM attribute mapping.",
  response: z.object({ mappings: z.array(z.object({ target: z.string(), expression: z.string(), enabled: z.boolean() })) }),
}, async (c) => {
  const mappings = await listScimMappings(c.env, "user");
  return c.json({ mappings: mappings.map((m) => ({ target: m.target, expression: m.expression, enabled: m.enabled })) });
});

defineRoute({
  method: "put", path: "/api/v1/scim/mappings", tag: "SCIM", permission: "scim:write", summary: "Replace the inbound attribute mappings",
  description:
    "The whole set at once, in evaluation order. Each `target` is a user field: a column name (display_name, department, ...), `upn`, `active`, `manager`, `emails`, or `custom.<key>`. An expression yielding nothing clears its field on PUT and leaves it alone on PATCH.",
  body: z.object({ mappings: z.array(z.object({ target: z.string(), expression: z.string().min(1), enabled: z.boolean().optional() })) }),
  errors: [400],
}, async (c) => {
  const body = await readJson<{ mappings?: { target: string; expression: string; enabled?: boolean }[] }>(c);
  try {
    await replaceScimMappings(c.env, "user", body.mappings ?? []);
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_mappings_changed", undefined, { count: (body.mappings ?? []).length }, c.req.raw);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Unified attribute mappings: every channel's rules in one surface
// ---------------------------------------------------------------------------

const MappingRow = z.object({ target: z.string(), expression: z.string(), enabled: z.boolean() });
const MAPPING_CHANNELS = ["scim-in", "jit", "scim-out", "oidc"] as const;

function channelValidator(channel: string): (target: string) => string | null {
  switch (channel) {
    case "scim-in": return (t) => (isValidMappingTarget("user", t) ? null : `"${t}" is not a field a user mapping can feed.`);
    case "jit": return validateJitTarget;
    case "scim-out": return validateScimOutTarget;
    case "oidc": return validateOidcClaimTarget;
    default: return () => `Unknown channel "${channel}" - use ${MAPPING_CHANNELS.join(", ")}.`;
  }
}

defineRoute({
  method: "get", path: "/api/v1/mappings", tag: "Mappings", permission: "schemas:read", summary: "List a channel's attribute mappings",
  description:
    `The mapping rows for one flow: \`channel\` is ${MAPPING_CHANNELS.join(", ")}; \`owner\` scopes it (an upstream IdP id for jit, a SCIM target id for scim-out, a client_id for oidc, empty for the channel's defaults and for scim-in). Each row's \`expression\` is evaluated over the source document - the SCIM body, the IdP's claims, or the FlareID user.`,
  query: z.object({ channel: z.string(), owner: z.string().optional() }),
  errors: [400],
  response: z.object({ mappings: z.array(MappingRow.extend({ owner: z.string(), enabled: z.boolean() })) }),
}, async (c) => {
  const channel = c.req.query("channel") ?? "";
  const owner = c.req.query("owner") ?? "";
  if (!MAPPING_CHANNELS.includes(channel as (typeof MAPPING_CHANNELS)[number]))
    return c.json(badRequest(`Unknown channel "${channel}" - use ${MAPPING_CHANNELS.join(", ")}.`), 400);
  const rows = await listMappings(c.env, { channel, owner });
  return c.json({ mappings: rows.map((m) => ({ owner: m.owner, target: m.target, expression: m.expression, enabled: m.enabled })) });
});

defineRoute({
  method: "put", path: "/api/v1/mappings", tag: "Mappings", permission: "admin", summary: "Replace a channel's attribute mappings",
  description:
    "The whole set for (channel, owner) at once - the same surface as the console's Flows editor, which is Super-Admin-gated for the same reason: the rows rewrite what every sign-in and provisioning write carries. `/api/v1/scim/mappings` remains the delegable (scim:write) view of the scim-in channel.",
  body: z.object({ channel: z.string(), owner: z.string().optional(), resource: z.string().optional(), mappings: z.array(z.object({ target: z.string(), expression: z.string().min(1), enabled: z.boolean().optional() })) }),
  errors: [400],
}, async (c) => {
  const body = await readJson<{ channel?: string; owner?: string; resource?: string; mappings?: { target: string; expression: string; enabled?: boolean }[] }>(c);
  const channel = body.channel ?? "";
  const validator = channelValidator(channel);
  if (!MAPPING_CHANNELS.includes(channel as (typeof MAPPING_CHANNELS)[number]))
    return c.json(badRequest(`Unknown channel "${channel}" - use ${MAPPING_CHANNELS.join(", ")}.`), 400);
  try {
    await replaceMappings(c.env, { channel, owner: body.owner ?? "", resource: body.resource ?? "user" }, body.mappings ?? [], validator);
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.mappings_changed", `${channel}${body.owner ? ` (${body.owner})` : ""}`, { count: (body.mappings ?? []).length }, c.req.raw);
  return c.json({ ok: true });
});

defineRoute({
  method: "get", path: "/api/v1/mappings/collisions", tag: "Mappings", permission: "schemas:read", summary: "Read the collision policy",
  description:
    "What inbound writes do when an identity collides: `username` is increment (append a counter), pattern (evaluate `username_pattern` over {local, n, domain, email} until free), or fail; `email` is skip (don't attach) or fail.",
  response: z.object({ username: z.string(), username_pattern: z.string(), email: z.string() }),
}, async (c) => c.json(await getCollisionPolicy(c.env)));

defineRoute({
  method: "put", path: "/api/v1/mappings/collisions", tag: "Mappings", permission: "admin", summary: "Set the collision policy",
  body: z.object({ username: z.string().optional(), username_pattern: z.string().optional(), email: z.string().optional() }),
  errors: [400],
  response: z.object({ username: z.string(), username_pattern: z.string(), email: z.string() }),
}, async (c) => {
  const body = await readJson<{ username?: string; username_pattern?: string; email?: string }>(c);
  try {
    const policy = await setCollisionPolicy(c.env, body);
    await logAudit(c.env, auditActor(c.get("apiActor")), "settings.collision_policy_changed", undefined, { username: policy.username, email: policy.email }, c.req.raw);
    return c.json(policy);
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
});

defineRoute({
  method: "get", path: "/api/v1/scim/correlation", tag: "SCIM", permission: "scim:read", summary: "List the inbound correlation keys",
  description: `Ordered match keys tried when an inbound create's userName is new - the first key matching one existing user adopts the account instead of conflicting. Valid keys: ${CORRELATION_KEYS.join(", ")}.`,
  response: z.object({ keys: z.array(z.string()) }),
}, async (c) => c.json({ keys: await getCorrelationKeys(c.env) }));

defineRoute({
  method: "put", path: "/api/v1/scim/correlation", tag: "SCIM", permission: "scim:write", summary: "Replace the inbound correlation keys",
  description: `The ordered list, empty to refuse every duplicate. Valid keys: ${CORRELATION_KEYS.join(", ")}.`,
  body: z.object({ keys: z.array(z.string()) }),
  errors: [400],
}, async (c) => {
  const body = await readJson<{ keys?: string[] }>(c);
  try {
    await setCorrelationKeys(c.env, body.keys ?? []);
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_correlation_changed", undefined, { keys: body.keys ?? [] }, c.req.raw);
  return c.json({ ok: true });
});

defineRoute({
  method: "get", path: "/api/v1/scim/mastering", tag: "SCIM", permission: "scim:read", summary: "List the fields mastered by inbound provisioning",
  description:
    `Mastered fields belong to the upstream provisioner: inbound SCIM writes change them, the console shows them read-only, and the admin API rejects them. Valid fields: ${MASTERING_FIELDS.join(", ")}, or custom.<key> for a custom attribute.`,
  response: z.object({ fields: z.array(z.string()) }),
}, async (c) => c.json({ fields: await getMasteredFields(c.env) }));

defineRoute({
  method: "put", path: "/api/v1/scim/mastering", tag: "SCIM", permission: "scim:write", summary: "Replace the mastered field list",
  description: `The whole set, empty to unmaster everything. Valid fields: ${MASTERING_FIELDS.join(", ")}, or custom.<key>.`,
  body: z.object({ fields: z.array(z.string()) }),
  errors: [400],
}, async (c) => {
  const body = await readJson<{ fields?: string[] }>(c);
  try {
    await setMasteredFields(c.env, body.fields ?? []);
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_mastering_changed", undefined, { fields: body.fields ?? [] }, c.req.raw);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Federation (upstream identity providers)
// ---------------------------------------------------------------------------

const UpstreamIdpBody = z.object({
  name: z.string().min(1).max(80),
  protocol: z.enum(["oidc", "saml"]),
  enabled: z.boolean().optional(),
  jit: z.boolean().optional(),
  jit_domain: z.string().optional(),
  jit_groups: z.array(z.number().int().positive()).max(MAX_JIT_GROUPS).optional().openapi({
    description: "Group ids every JIT-provisioned account joins at creation. A group may grant a read-only admin role; one granting a write-capable role is refused.",
  }),
  config: z.record(z.string(), z.union([z.string(), z.record(z.string(), z.string())])),
});

function upstreamInput(body: { name?: string; protocol?: string; enabled?: boolean; jit?: boolean; jit_domain?: string; jit_groups?: number[]; config?: Record<string, unknown> }, existing?: UpstreamIdpRow | null): UpstreamIdpInput & { enabled: boolean; keepSecret: boolean } {
  const cfg: Record<string, string | Record<string, string>> = existing ? { ...(idpConfig(existing) as unknown as Record<string, string | Record<string, string>>) } : {};
  for (const [k, v] of Object.entries(body.config ?? {})) {
    if (typeof v === "string") cfg[k] = v;
    else if (v && typeof v === "object" && !Array.isArray(v)) cfg[k] = v as Record<string, string>;
  }
  return {
    name: String(body.name ?? existing?.name ?? ""),
    protocol: (body.protocol ?? existing?.protocol ?? "oidc") === "saml" ? "saml" : "oidc",
    jit: body.jit ?? (existing ? existing.jit === 1 : false),
    jitDomain: body.jit_domain ?? existing?.jit_domain ?? "",
    jitGroups: body.jit_groups ?? (existing ? upstreamJitGroups(existing) : []),
    enabled: body.enabled ?? (existing ? existing.enabled === 1 : true),
    keepSecret: existing != null && cfg.client_secret === undefined,
    config: cfg,
  };
}

defineRoute({
  method: "post", path: "/api/v1/federation/idps", tag: "Federation", permission: "admin", summary: "Add an upstream identity provider",
  description:
    "FlareID as the relying party. OIDC `config`: issuer, client_id, client_secret (write-only), scopes. SAML `config`: sso_url, certificate (PEM or base64), idp_entity_id, nameid_format, attr_map. `jit` creates an account on first sign-in when no local user matches; `jit_groups` lists the groups every such account joins. Registering an IdP trusts its claims for every account here, so this needs an admin-scoped key - not delegated federation write.",
  body: UpstreamIdpBody, errors: [400, 409],
}, async (c) => {
  const body = await readJson<{ name?: string; protocol?: string; enabled?: boolean; jit?: boolean; jit_domain?: string; jit_groups?: number[]; config?: Record<string, unknown> }>(c);
  try {
    const created = await createUpstreamIdp(c.env, upstreamInput(body));
    await logAudit(c.env, auditActor(c.get("apiActor")), "federation.idp_created", created.name, { protocol: created.protocol }, c.req.raw);
    return c.json({ id: created.id, ok: true });
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
});

defineRoute({
  method: "patch", path: "/api/v1/federation/idps/{id}", tag: "Federation", permission: "admin", summary: "Change an upstream identity provider",
  description: "Fields not supplied keep their values; `config` keys merge onto the stored config, and an omitted client_secret keeps the stored credential.",
  body: UpstreamIdpBody.partial(), errors: [400, 404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const existing = await getUpstreamIdp(c.env, id);
  if (!existing) return notFound(c, "No such upstream identity provider.");
  const body = await readJson<{ name?: string; protocol?: string; enabled?: boolean; jit?: boolean; jit_domain?: string; jit_groups?: number[]; config?: Record<string, unknown> }>(c);
  try {
    const updated = await updateUpstreamIdp(c.env, id, upstreamInput(body, existing));
    await logAudit(c.env, auditActor(c.get("apiActor")), "federation.idp_updated", updated.name, { protocol: updated.protocol, enabled: updated.enabled }, c.req.raw);
    return c.json({ ok: true });
  } catch (e) {
    return c.json(badRequest(e instanceof Error ? e.message : String(e)), 400);
  }
});

defineRoute({
  method: "delete", path: "/api/v1/federation/idps/{id}", tag: "Federation", permission: "admin", summary: "Remove an upstream identity provider",
  description: "Its sign-in button and linked identities go with it; the accounts themselves are kept.",
  errors: [404],
}, async (c) => {
  const id = Number(c.req.param("id"));
  const existing = await getUpstreamIdp(c.env, id);
  if (!existing) return notFound(c, "No such upstream identity provider.");
  await deleteUpstreamIdp(c.env, id);
  await logAudit(c.env, auditActor(c.get("apiActor")), "federation.idp_deleted", existing.name, { protocol: existing.protocol }, c.req.raw);
  return c.json({ ok: true });
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
    attribute_definitions: spAttributeDefinitions(sp).map((d) => ({ name: d.name, field: d.field, name_format: d.nameFormat ?? null })),
    sign_response: sp.sign_response === 1,
    sign_assertion: sp.sign_assertion === 1,
    want_authn_requests_signed: sp.want_authn_requests_signed === 1,
    signing_certs: JSON.parse(sp.signing_certs) as string[],
    slo_url: sp.slo_url,
    encryption_cert: sp.encryption_cert,
    encrypt_assertions: sp.encrypt_assertions === 1,
    access_mode: sp.access_mode,
    assigned_groups: parseAssignedGroupIds(sp.assigned_groups),
    assigned_users: parseAssignedUserIds(sp.assigned_users),
    require_mfa: sp.require_mfa === 1,
    requestable: sp.requestable === 1,
    policy_id: sp.policy_id,
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

const SamlSettingsSchema = z.object({
  disabled_algorithms: z.array(z.string()).openapi({
    description: "Instance-wide algorithm deny list (IIP-ALG08): full URIs or short tokens (aes256-cbc, rsa-oaep-mgf1p, sha1). A denied algorithm cannot be selected on a service provider and fails closed at emission.",
  }),
});

defineRoute({
  method: "get", path: "/api/v1/saml/settings", tag: "SAML", permission: "saml:read", summary: "Read the instance SAML settings",
  response: SamlSettingsSchema,
}, async (c) => c.json({ disabled_algorithms: await getDisabledAlgorithms(c.env) }));

defineRoute({
  method: "put", path: "/api/v1/saml/settings", tag: "SAML", permission: "saml:write", summary: "Set the SAML algorithm deny list",
  description:
    "Entries are XML Encryption URIs or short tokens, matched against content, key-transport, OAEP digest and MGF choices alike (a URI's #-fragment counts too). Replaces the whole list. A service provider whose encryption policy resolves to a denied algorithm cannot be saved, and one already stored fails closed at emission.",
  body: SamlSettingsSchema, errors: [400], response: SamlSettingsSchema,
}, async (c) => {
  const body = await readJson<{ disabled_algorithms?: unknown }>(c);
  if (!Array.isArray(body.disabled_algorithms)) return c.json(badRequest("disabled_algorithms must be an array of strings."), 400);
  let saved: string[];
  try {
    saved = normalizeDisabledAlgorithms(body.disabled_algorithms);
  } catch (e) {
    return c.json(badRequest(e instanceof RangeError ? e.message : "Invalid disabled_algorithms."), 400);
  }
  await setDisabledAlgorithms(c.env, saved);
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml.disabled_algorithms_changed", undefined, { count: saved.length }, c.req.raw);
  return c.json({ disabled_algorithms: saved });
});

interface SpUpsertBody {
  subject_id?: "" | "subject-id" | "pairwise-id";
  entity_id?: string;
  name?: string;
  acs_urls?: string[];
  default_acs_url?: string;
  nameid_format?: string;
  attribute_map?: Record<string, string>;
  attribute_definitions?: { name?: string; field?: string; name_format?: string }[] | null;
  sign_response?: boolean;
  sign_assertion?: boolean;
  want_authn_requests_signed?: boolean;
  signing_certs?: string[];
  slo_url?: string | null;
  encryption_cert?: string | null;
  encrypt_assertions?: boolean;
  encryption_policy?: { content?: string; transport?: string; digest?: string; mgf?: string | null } | null;
  assigned_groups?: number[] | null;
  access_mode?: "everyone" | "restricted";
  assigned_users?: number[] | null;
  require_mfa?: boolean;
  requestable?: boolean;
  policy_id?: number | null;
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
    nameid_format: z.string().optional().openapi({ description: 'transient, emailAddress, persistent - or "none" to omit <saml:NameID> from the Subject entirely.' }),
    attribute_map: StringMap.optional(),
    attribute_definitions: z
      .array(z.object({ name: z.string(), field: z.string(), name_format: z.string().optional() }))
      .nullable()
      .optional()
      .openapi({ description: "Released attributes with an arbitrary SAML Name and optional NameFormat per entry; replaces attribute_map when non-empty. null clears it back to the map." }),
    sign_response: z.boolean().optional(),
    sign_assertion: z.boolean().optional(),
    want_authn_requests_signed: z.boolean().optional(),
    signing_certs: z.array(z.string()).optional(),
    slo_url: z.string().nullable().optional(),
    encryption_cert: z.string().nullable().optional(),
    encrypt_assertions: z.boolean().optional(),
    encryption_policy: z.object({
      content: z.string().optional(),
      transport: z.string().optional(),
      digest: z.string().optional(),
      mgf: z.string().nullable().optional(),
    }).nullable().optional(),
    subject_id: z.enum(["", "subject-id", "pairwise-id"]).optional(),
    assigned_groups: z.array(z.number()).nullable().optional().openapi({ description: "Group ids (static or dynamic) assigned to this app. On update, omitted keeps the current assignment." }),
    access_mode: z.enum(["everyone", "restricted"]).optional().openapi({ description: "restricted = only assigned users/groups reach the app; default for new apps." }),
    assigned_users: z.array(z.number()).nullable().optional().openapi({ description: "User ids assigned to this app. On update, omitted keeps the current assignment." }),
    require_mfa: z.boolean().optional().openapi({ description: "The session must carry a second factor to SSO into this app." }),
    requestable: z.boolean().optional().openapi({ description: "People without access may request it under My account -> Access." }),
    policy_id: z.number().nullable().optional().openapi({ description: "Authentication policy the sign-in must satisfy to use this app. null/0 clears the binding; omitted keeps the current one." }),
  }),
  response: z.object({ ok: z.literal(true), created: z.boolean(), id: z.number(), entity_id: z.string(), assigned_groups: z.array(z.number()) }),
}, async (c) => {
  const body = await readJson<SpUpsertBody>(c);
  const entityId = String(body.entity_id ?? "").trim();
  if (!entityId) return c.json(badRequest("entity_id is required."), 400);

  const existing = await c.env.DB.prepare("SELECT * FROM saml_service_providers WHERE entity_id = ?")
    .bind(entityId)
    .first<SamlServiceProviderRow>();

  const acsUrls = body.acs_urls !== undefined ? body.acs_urls.map((u) => String(u).trim()).filter(Boolean) : existing ? (JSON.parse(existing.acs_urls) as string[]) : [];
  if (acsUrls.length === 0) return c.json(badRequest("At least one acs_url is required."), 400);
  // Assertions are bearer credentials: only https endpoints are registrable.
  for (const u of acsUrls) if (!u.startsWith("https://")) return c.json(badRequest(`acs_url "${u}" must be https.`), 400);
  const defaultAcs = body.default_acs_url !== undefined ? String(body.default_acs_url).trim() : (existing?.default_acs_url ?? "");
  if (defaultAcs && !acsUrls.includes(defaultAcs)) return c.json(badRequest("default_acs_url must be one of the acs_urls."), 400);

  const nameidFormat = body.nameid_format ?? existing?.nameid_format ?? "transient";
  // "none" (IIP-IDP11) is a stored format too: the Subject then carries no NameID.
  if (nameidFormat !== "none" && !nameIdFormatUri(nameidFormat)) return c.json(badRequest(`Unsupported nameid_format "${nameidFormat}".`), 400);

  const attributeMap = body.attribute_map ?? (existing ? (JSON.parse(existing.attribute_map) as Record<string, string>) : {});
  const validField = (field: string) => USER_ATTRIBUTE_FIELDS.includes(field as (typeof USER_ATTRIBUTE_FIELDS)[number]);
  for (const field of Object.values(attributeMap)) {
    if (!validField(field)) {
      return c.json(badRequest(`"${field}" is not a user attribute field. Valid fields: ${USER_ATTRIBUTE_FIELDS.join(", ")}.`), 400);
    }
  }

  // Attribute definitions: null clears back to the plain map; undefined keeps the stored value.
  let attributeDefinitions: string | null | undefined;
  if (body.attribute_definitions !== undefined) {
    if (body.attribute_definitions === null) attributeDefinitions = null;
    else {
      const norm = normalizeAttributeDefinitions(body.attribute_definitions);
      if ("error" in norm) return c.json(badRequest(norm.error), 400);
      for (const def of norm.defs) {
        if (!validField(def.field)) return c.json(badRequest(`"${def.field}" is not a user attribute field. Valid fields: ${USER_ATTRIBUTE_FIELDS.join(", ")}.`), 400);
      }
      attributeDefinitions = JSON.stringify(norm.defs);
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

  // Token shorthand or full XML Encryption URIs; stored canonical as URIs.
  const encToken = (kind: "content" | "transport", v: string): string | null => {
    const table = kind === "content" ? CONTENT_ALGORITHMS : TRANSPORT_ALGORITHMS;
    if (v in table) return v;
    const match = Object.keys(table).find((uri) => uri.endsWith(`#${v}`) || uri.endsWith(`#${v.replace(/_/g, "-")}`));
    return match ?? null;
  };
  let encryptionPolicy: string | null | undefined;
  if (body.encryption_policy === null) encryptionPolicy = null;
  else if (body.encryption_policy !== undefined) {
    const ep = body.encryption_policy;
    const prev = existing ? spEncryptionPolicy(existing) : {};
    const content = ep.content !== undefined ? encToken("content", ep.content) : (prev.content ?? null);
    const transport = ep.transport !== undefined ? encToken("transport", ep.transport) : (prev.transport ?? null);
    if (ep.content !== undefined && !content) return c.json(badRequest(`Unsupported encryption content algorithm "${ep.content}".`), 400);
    if (ep.transport !== undefined && !transport) return c.json(badRequest(`Unsupported key transport algorithm "${ep.transport}".`), 400);
    const digest = ep.digest ?? prev.digest ?? "sha1";
    const mgf = ep.mgf === undefined ? (prev.mgf ?? null) : ep.mgf;
    if (!["sha1", "sha256", "sha384", "sha512"].includes(digest)) return c.json(badRequest(`Unsupported OAEP digest "${digest}".`), 400);
    if (mgf !== null && !["sha1", "sha256", "sha384", "sha512"].includes(mgf)) return c.json(badRequest(`Unsupported MGF1 hash "${mgf}".`), 400);
    // rsa-oaep-mgf1p fixes the mask to MGF1-SHA1 (XML Enc 1.0 §5.4.1); an
    // explicit MGF is only declarable under the 1.1 parameterized URI.
    if (transport !== "http://www.w3.org/2009/xmlenc11#rsa-oaep" && mgf !== null && mgf !== "sha1")
      return c.json(badRequest("rsa-oaep-mgf1p fixes the MGF to MGF1-SHA1; select transport rsa-oaep to set an MGF."), 400);
    const resolved = { content: content ?? "http://www.w3.org/2009/xmlenc11#aes256-gcm", transport: transport ?? "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", digest, mgf };
    // IIP-ALG08.a: selecting a deny-listed algorithm fails at write time.
    const denied = disabledAlgorithmInPolicy(resolved, await getDisabledAlgorithms(c.env));
    if (denied) return c.json(badRequest(`Encryption ${denied.field} algorithm "${denied.value}" is disabled for this instance.`), 400);
    encryptionPolicy = JSON.stringify(resolved);
  } else encryptionPolicy = undefined;

  const name = String(body.name ?? existing?.name ?? entityId).trim();
  // undefined keeps the stored assignment.
  const assigned = body.assigned_groups === undefined ? undefined : Array.isArray(body.assigned_groups) ? JSON.stringify(body.assigned_groups.filter((n) => Number.isInteger(n))) : null;
  const assignedUsers = body.assigned_users === undefined ? undefined : Array.isArray(body.assigned_users) ? JSON.stringify(body.assigned_users.filter((n) => Number.isInteger(n))) : null;
  const writeAccess = async (id: number) => {
    if (assigned !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET assigned_groups = ? WHERE id = ?").bind(assigned, id).run();
    if (assignedUsers !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET assigned_users = ? WHERE id = ?").bind(assignedUsers, id).run();
    if (body.access_mode !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET access_mode = ? WHERE id = ?").bind(body.access_mode, id).run();
    if (body.require_mfa !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET require_mfa = ? WHERE id = ?").bind(body.require_mfa ? 1 : 0, id).run();
    if (body.requestable !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET requestable = ? WHERE id = ?").bind(body.requestable ? 1 : 0, id).run();
    if (body.policy_id !== undefined) {
      const pid = Number(body.policy_id) > 0 ? Number(body.policy_id) : null;
      await assertPolicyExists(c.env, pid);
      await c.env.DB.prepare("UPDATE saml_service_providers SET policy_id = ? WHERE id = ?").bind(pid, id).run();
    }
  };
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
      `UPDATE saml_service_providers SET entity_id = ?, name = ?, acs_urls = ?, default_acs_url = ?, nameid_format = ?, attribute_map = ?, sign_response = ?, sign_assertion = ?, want_authn_requests_signed = ?, signing_certs = ?, slo_url = ?, encryption_cert = ?, encrypt_assertions = ?, encryption_policy = ?, attribute_definitions = ?, updated_at = ? WHERE id = ?`
    )
      .bind(...values, encryptionPolicy === undefined ? (existing.encryption_policy ?? null) : encryptionPolicy, attributeDefinitions === undefined ? (existing.attribute_definitions ?? null) : attributeDefinitions, now, existing.id)
      .run();
    if (body.subject_id !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE entity_id = ?").bind(["subject-id", "pairwise-id"].includes(String(body.subject_id)) ? String(body.subject_id) : "", entityId).run();
    await writeAccess(existing.id);
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml_sp.updated", name, { entity_id: entityId }, c.req.raw);
    return c.json({ ok: true, created: false, id: existing.id, entity_id: entityId, assigned_groups: parseAssignedGroupIds(assigned === undefined ? existing.assigned_groups : assigned) });
  }

  const result = await c.env.DB.prepare(
    `INSERT INTO saml_service_providers (entity_id, name, acs_urls, default_acs_url, nameid_format, attribute_map, sign_response, sign_assertion, want_authn_requests_signed, signing_certs, slo_url, encryption_cert, encrypt_assertions, encryption_policy, attribute_definitions, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(...values, encryptionPolicy ?? null, attributeDefinitions ?? null, now, now)
    .run();

  if (body.subject_id !== undefined) await c.env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE entity_id = ?").bind(["subject-id", "pairwise-id"].includes(String(body.subject_id)) ? String(body.subject_id) : "", entityId).run();
  await writeAccess(Number(result.meta.last_row_id));
  await logAudit(c.env, auditActor(c.get("apiActor")), "saml_sp.created", name, { entity_id: entityId }, c.req.raw);
  return c.json({ ok: true, created: true, id: result.meta.last_row_id, entity_id: entityId, assigned_groups: parseAssignedGroupIds(assigned ?? null) });
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
  // A key can only carry scopes the caller holds (the console's rule): admin
  // callers pass this trivially, and it keeps minting safe if the route's
  // permission ever widens.
  const mintActor = c.get("apiActor");
  const beyond = requested.filter((s) => !hasScope(mintActor.scopes, s));
  if (beyond.length) return c.json({ error: "forbidden", message: `This token cannot grant scopes it does not hold: ${beyond.join(", ")}.` }, 403);

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

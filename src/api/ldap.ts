import { z } from "@hono/zod-openapi";
import type { Env } from "../env.js";
import { logAudit } from "../lib/audit.js";
import { auditActor } from "../lib/api-auth.js";
import { getDefaultDomain } from "../lib/domains.js";
import { setSetting } from "../lib/settings.js";
import type { LdapAppRow } from "../lib/types.js";
import { getLdapAppBySlug, isLdapSlug, listLdapApps, revokeLdapApp, revealLdapSecret, rotateLdapSecret, writeLdapApp, appGroupIds, type LdapAppInput } from "../ldap/apps.js";
import { disableLdap, domainToBaseDn, enableLdap, getLdapSettings } from "../ldap/settings.js";
import { badRequest, defineRoute, notFound, param, readJson } from "./openapi.js";
import { ServiceError } from "../services/context.js";

/**
 * The LDAP interface's provisioning surface (LDAP.md section 15): app
 * registrations, secret rotation, revocation, and the directory settings.
 * Secrets are only ever returned at create/rotate time.
 */

/** Group names to ids; an unknown name is an error (same rule as the settings API). */
async function groupIdsByName(env: Env, names: string[]): Promise<number[]> {
  if (!names.length) return [];
  const { results } = await env.DB.prepare("SELECT id, name FROM groups WHERE name IN (SELECT value FROM json_each(?))").bind(JSON.stringify(names)).all<{ id: number; name: string }>();
  const missing = names.filter((n) => !results.some((r) => r.name === n));
  if (missing.length) throw new ServiceError(400, `No such group(s): ${missing.join(", ")}.`);
  return results.map((r) => r.id);
}

async function groupNamesById(env: Env, ids: number[]): Promise<string[]> {
  if (!ids.length) return [];
  const { results } = await env.DB.prepare("SELECT id, name FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(ids)).all<{ id: number; name: string }>();
  return ids.map((id) => results.find((r) => r.id === id)?.name ?? `#${id}`);
}

async function appJson(env: Env, app: LdapAppRow) {
  const { userGroups, exposedGroups } = appGroupIds(app);
  return {
    slug: app.slug,
    name: app.name,
    secret_prefix: app.secret_prefix,
    user_groups: userGroups === null ? null : await groupNamesById(env, userGroups),
    exposed_groups: exposedGroups === null ? null : await groupNamesById(env, exposedGroups),
    mfa_mode: app.mfa_mode,
    include_disabled: Boolean(app.include_disabled),
    revoked: app.revoked_at !== null,
    created_at: app.created_at,
    updated_at: app.updated_at,
  };
}

const MfaMode = z.enum(["password", "otp_if_enrolled", "otp_required"]);
const AppBody = z.object({
  slug: z.string().min(1).max(64).describe("Lowercase letters, digits and dashes; also the DN branch: ou=<slug>,<base>."),
  name: z.string().min(1).max(128),
  user_groups: z.array(z.string()).optional().describe("Group names whose members may bind; omit/empty = all users."),
  exposed_groups: z.array(z.string()).optional().describe("Group names visible to this app; omit/empty = all groups."),
  mfa_mode: MfaMode.optional().describe("password | otp_if_enrolled (default) | otp_required"),
  include_disabled: z.boolean().optional(),
});
const AppSchema = z
  .object({
    slug: z.string(),
    name: z.string(),
    secret_prefix: z.string(),
    user_groups: z.array(z.string()).nullable(),
    exposed_groups: z.array(z.string()).nullable(),
    mfa_mode: MfaMode,
    include_disabled: z.boolean(),
    revoked: z.boolean(),
    created_at: z.string(),
    updated_at: z.string(),
  })
  .openapi("LdapApp");

const SettingsSchema = z
  .object({
    enabled: z.boolean(),
    hostname: z.string(),
    base_dn: z.string(),
    netbios_name: z.string(),
    unscoped_bind_app: z.string(),
    posix_uid_base: z.number(),
    posix_gid_base: z.number(),
    posix_default_gid: z.number(),
    posix_shell: z.string(),
    posix_home: z.string(),
    idle_timeout_minutes: z.number(),
    otp_rebind_seconds: z.number(),
  })
  .openapi("LdapSettings");

async function settingsJson(env: Env) {
  const s = await getLdapSettings(env);
  return {
    enabled: s.enabled,
    hostname: s.hostname,
    base_dn: s.baseDn,
    netbios_name: s.netbios,
    unscoped_bind_app: s.unscopedBindApp,
    posix_uid_base: s.posixUidBase,
    posix_gid_base: s.posixGidBase,
    posix_default_gid: s.posixDefaultGid,
    posix_shell: s.posixShell,
    posix_home: s.posixHome,
    idle_timeout_minutes: s.idleTimeoutMinutes,
    otp_rebind_seconds: s.otpRebindSeconds,
  };
}

defineRoute(
  { method: "get", path: "/api/v1/ldap/apps", tag: "LDAP", permission: "directory:read", summary: "List LDAP apps", description: "Secrets are never returned - only the prefix for identification.", response: z.array(AppSchema) },
  async (c) => {
    const apps = await listLdapApps(c.env);
    return c.json(await Promise.all(apps.map((a) => appJson(c.env, a))));
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/ldap/apps",
    tag: "LDAP",
    permission: "clients:write",
    summary: "Create or update an LDAP app (upsert by slug)",
    description: "Idempotent: the same body re-applied updates the app. The `secret` field appears only on create; rotate to get a new one.",
    body: AppBody,
    response: AppSchema.extend({ secret: z.string().nullable() }),
    errors: [400],
  },
  async (c) => {
    const body = await readJson<z.infer<typeof AppBody>>(c);
    const slug = String(body.slug ?? "").toLowerCase();
    if (!isLdapSlug(slug)) throw new ServiceError(400, `'${slug}' is not a usable app name (lowercase letters, digits, dashes; not services/people/groups).`);
    const existing = await getLdapAppBySlug(c.env, slug);
    const input: LdapAppInput = {
      slug,
      name: String(body.name ?? ""),
      ...(body.user_groups !== undefined ? { user_group_ids: await groupIdsByName(c.env, body.user_groups) } : existing ? {} : { user_group_ids: [] }),
      ...(body.exposed_groups !== undefined ? { exposed_group_ids: await groupIdsByName(c.env, body.exposed_groups) } : existing ? {} : { exposed_group_ids: [] }),
      ...(body.mfa_mode !== undefined ? { mfa_mode: body.mfa_mode } : {}),
      ...(body.include_disabled !== undefined ? { include_disabled: body.include_disabled } : {}),
    };
    const { app, secret } = await writeLdapApp(c.env, input);
    await logAudit(c.env, auditActor(c.get("apiActor")), existing ? "ldap.app.updated" : "ldap.app.created", slug, {}, c.req.raw);
    return c.json({ ...(await appJson(c.env, app)), secret }, existing ? 200 : 201);
  }
);

defineRoute(
  { method: "post", path: "/api/v1/ldap/apps/{slug}/rotate", tag: "LDAP", permission: "clients:write", summary: "Rotate an app's bind secret", response: z.object({ slug: z.string(), secret: z.string() }), errors: [404] },
  async (c) => {
    const app = await getLdapAppBySlug(c.env, param(c, "slug").toLowerCase());
    if (!app) throw new ServiceError(404, "No such LDAP app.");
    const secret = await rotateLdapSecret(c.env, app);
    await logAudit(c.env, auditActor(c.get("apiActor")), "ldap.app.secret_rotated", app.slug, {}, c.req.raw);
    return c.json({ slug: app.slug, secret });
  }
);

defineRoute(
  { method: "post", path: "/api/v1/ldap/apps/{slug}/reveal", tag: "LDAP", permission: "clients:write", summary: "Reveal an app's current bind secret", description: "Returns the KEK-sealed secret. 409 when the app predates secret sealing - rotate once to enable reveal.", errors: [404, 409] },
  async (c) => {
    const app = await getLdapAppBySlug(c.env, param(c, "slug").toLowerCase());
    if (!app) throw new ServiceError(404, "No such LDAP app.");
    const secret = await revealLdapSecret(c.env, app);
    if (!secret) throw new ServiceError(409, "This app's secret predates reveal - rotate it once to enable.");
    await logAudit(c.env, auditActor(c.get("apiActor")), "ldap.app.secret_revealed", app.slug, {}, c.req.raw);
    return c.json({ slug: app.slug, secret });
  }
);

defineRoute(
  { method: "delete", path: "/api/v1/ldap/apps/{slug}", tag: "LDAP", permission: "clients:write", summary: "Revoke an LDAP app", description: "Sets revoked_at; binds and searches fail immediately. Idempotent.", errors: [404] },
  async (c) => {
    const app = await getLdapAppBySlug(c.env, param(c, "slug").toLowerCase());
    if (!app) throw new ServiceError(404, "No such LDAP app.");
    if (!app.revoked_at) {
      await revokeLdapApp(c.env, app);
      await logAudit(c.env, auditActor(c.get("apiActor")), "ldap.app.revoked", app.slug, {}, c.req.raw);
    }
    return c.json({ ok: true });
  }
);

const SettingsBody = z.object({
  enabled: z.boolean().optional(),
  hostname: z.string().max(253).optional(),
  base_dn: z.string().max(512).optional().describe("'' = derive dc=… from the default domain."),
  netbios_name: z.string().max(15).optional().describe("'' = uppercased first label of the default domain."),
  unscoped_bind_app: z.string().max(64).optional().describe("Slug that unattributed user binds land on; '' = deny them."),
  posix_uid_base: z.number().int().min(0).optional(),
  posix_gid_base: z.number().int().min(0).optional(),
  posix_default_gid: z.number().int().min(0).optional(),
  posix_shell: z.string().max(128).optional(),
  posix_home: z.string().max(256).optional().describe("Template; {username} is substituted."),
  idle_timeout_minutes: z.number().int().min(1).max(1440).optional(),
  otp_rebind_seconds: z.number().int().min(0).max(3600).optional(),
});

defineRoute(
  { method: "get", path: "/api/v1/ldap/settings", tag: "LDAP", permission: "directory:read", summary: "Read the LDAP settings", response: SettingsSchema },
  async (c) => c.json(await settingsJson(c.env))
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/ldap/settings",
    tag: "LDAP",
    permission: "settings:write",
    summary: "Update the LDAP settings",
    description: "Only the fields sent change. `enabled: true` also generates the domain SID and GUID namespace on first use.",
    body: SettingsBody,
    response: SettingsSchema,
    errors: [400],
  },
  async (c) => {
    const body = await readJson<z.infer<typeof SettingsBody>>(c);
    if (body.enabled === true) await enableLdap(c.env);
    else if (body.enabled === false) await disableLdap(c.env);
    const put = async (key: string, value: string | number | undefined) => {
      if (value !== undefined) await setSetting(c.env, key, String(value));
    };
    if (body.base_dn !== undefined) {
      const trimmed = body.base_dn.trim();
      await put("ldap_base_dn", trimmed === "" ? "" : trimmed);
    }
    await put("ldap_hostname", body.hostname?.trim());
    await put("ldap_netbios_name", body.netbios_name?.trim());
    if (body.unscoped_bind_app !== undefined) {
      const slug = body.unscoped_bind_app.trim().toLowerCase();
      if (slug && !(await getLdapAppBySlug(c.env, slug))) throw new ServiceError(400, `No LDAP app named '${slug}'.`);
      await put("ldap_unscoped_bind_app", slug);
    }
    await put("ldap_posix_uid_base", body.posix_uid_base);
    await put("ldap_posix_gid_base", body.posix_gid_base);
    await put("ldap_posix_default_gid", body.posix_default_gid);
    await put("ldap_posix_shell", body.posix_shell?.trim());
    await put("ldap_posix_home", body.posix_home?.trim());
    await put("ldap_idle_timeout_minutes", body.idle_timeout_minutes);
    await put("ldap_otp_rebind_seconds", body.otp_rebind_seconds);
    await logAudit(c.env, auditActor(c.get("apiActor")), "ldap.settings.updated", "ldap", { fields: Object.keys(body).filter((k) => (body as Record<string, unknown>)[k] !== undefined) }, c.req.raw);
    return c.json(await settingsJson(c.env));
  }
);

import { Hono } from "hono";
import type { Env } from "../env.js";
import { auditActor, bootstrapTokenValid, requireApiAuth, requireScope } from "../lib/api-auth.js";
import { createApiKey, isApiScope, type ApiScope } from "../lib/api-keys.js";
import { importDirectory, ImportValidationError, type DirectoryBundle } from "../lib/directory-import.js";
import { addDomain, applyDomainToAllUsers, getDefaultDomain, listDomains, setDefaultDomain } from "../lib/domains.js";
import { logAudit } from "../lib/audit.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { syncAll, testScimConnection } from "../lib/scim-client.js";
import {
  getAppName,
  isSetupCompleted,
  markSetupCompleted,
  setAppName,
  setDefaultPassword,
  setLoginGradient,
  setLoginSubtitle,
  setMfaRequired,
  setNewUserPasswordMode,
  setPasswordPolicy,
  setScimConfig,
  setScimScope,
  type PasswordPolicy,
} from "../lib/settings.js";
import { setRateLimitPolicy } from "../lib/rate-limit.js";
import type { GroupRow, OAuthClientRow } from "../lib/types.js";

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
export const api = new Hono<{ Bindings: Env }>();

api.use("/api/v1/*", requireApiAuth);

async function readJson<T>(c: { req: { json: () => Promise<unknown> } }): Promise<T> {
  try {
    return (await c.req.json()) as T;
  } catch {
    throw new ImportValidationError("Request body must be valid JSON.");
  }
}

function badRequest(message: string) {
  return { error: "invalid_request", message };
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

api.get("/api/v1/status", requireScope("directory:read"), async (c) => {
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

interface SetupBody {
  domain?: string;
  admin?: { username?: string; password?: string; display_name?: string; given_name?: string; family_name?: string };
  default_password?: string;
  app_name?: string;
  login_subtitle?: string;
  login_gradient?: { from?: string; to?: string };
  require_mfa?: boolean;
  new_user_password_mode?: "default" | "random";
  password_policy?: Partial<PasswordPolicy>;
  rate_limit?: { max_attempts?: number; window_minutes?: number };
  complete?: boolean;
}

/**
 * Settings first, then the administrator, then the completion flag - and that
 * order matters. The account is created with whatever `new_user_password_mode`
 * and `default_password` say, so applying those afterwards would mint an
 * administrator with the wrong credential; and `complete` is last because it is
 * what stops the bootstrap token working, so anything after it would be locked
 * out of its own setup call.
 */
api.post("/api/v1/setup", requireScope("settings:write"), async (c) => {
  const body = await readJson<SetupBody>(c);
  const actor = c.get("apiActor");
  const applied: string[] = [];

  if (body.domain !== undefined) {
    const domain = String(body.domain).trim().toLowerCase();
    if (!domain) return c.json(badRequest("domain cannot be empty."), 400);
    const existing = await listDomains(c.env);
    if (!existing.some((d) => d.domain === domain)) await addDomain(c.env, domain);
    const row = (await listDomains(c.env)).find((d) => d.domain === domain);
    if (row) await setDefaultDomain(c.env, row.id);
    applied.push(`domain=${domain}`);
  }

  if (body.default_password !== undefined) {
    await setDefaultPassword(c.env, String(body.default_password));
    applied.push("default_password");
  }
  if (body.new_user_password_mode !== undefined) {
    await setNewUserPasswordMode(c.env, body.new_user_password_mode === "default" ? "default" : "random");
    applied.push(`new_user_password_mode=${body.new_user_password_mode}`);
  }
  if (body.app_name !== undefined) {
    await setAppName(c.env, String(body.app_name));
    applied.push("app_name");
  }
  if (body.login_subtitle !== undefined) {
    await setLoginSubtitle(c.env, String(body.login_subtitle));
    applied.push("login_subtitle");
  }
  if (body.login_gradient?.from && body.login_gradient?.to) {
    await setLoginGradient(c.env, { from: body.login_gradient.from, to: body.login_gradient.to });
    applied.push("login_gradient");
  }
  if (body.require_mfa !== undefined) {
    await setMfaRequired(c.env, Boolean(body.require_mfa));
    applied.push(`require_mfa=${Boolean(body.require_mfa)}`);
  }
  if (body.password_policy !== undefined) {
    const p = body.password_policy;
    await setPasswordPolicy(c.env, {
      minLength: Number(p.minLength ?? 8),
      requireUppercase: Boolean(p.requireUppercase),
      requireLowercase: Boolean(p.requireLowercase),
      requireNumber: Boolean(p.requireNumber),
      requireSymbol: Boolean(p.requireSymbol),
    });
    applied.push("password_policy");
  }
  if (body.rate_limit !== undefined) {
    await setRateLimitPolicy(c.env, {
      maxAttempts: Number(body.rate_limit.max_attempts ?? 5),
      windowMinutes: Number(body.rate_limit.window_minutes ?? 15),
    });
    applied.push("rate_limit");
  }

  // The administrator, routed through the ordinary import so there is exactly
  // one code path that creates a user.
  let admin: { upn: string; password?: string } | undefined;
  if (body.admin?.username) {
    const username = String(body.admin.username).trim().toLowerCase();
    const result = await importDirectory(c.env, {
      version: 1,
      domain: body.domain,
      groups: [{ name: SUPER_ADMINS_GROUP, description: "Members can administer this directory" }],
      users: [
        {
          username,
          display_name: body.admin.display_name ?? "Administrator",
          given_name: body.admin.given_name ?? "Administrator",
          family_name: body.admin.family_name ?? "",
          password: body.admin.password ?? null,
          super_admin: true,
        },
      ],
    });

    if (result.errors.length > 0) {
      return c.json({ error: "setup_failed", message: "Could not create the administrator.", details: result.errors }, 400);
    }
    const upn = `${username}@${result.domain}`;
    admin = { upn, ...(result.generated_passwords[upn] ? { password: result.generated_passwords[upn] } : {}) };
    applied.push(`admin=${upn}`);
  }

  if (body.complete) {
    await markSetupCompleted(c.env);
    applied.push("setup_completed");
  }

  await logAudit(c.env, auditActor(actor), "idp.setup_completed", body.domain, { applied, via: "api" }, c.req.raw);

  return c.json({
    ok: true,
    applied,
    setup_completed: await isSetupCompleted(c.env),
    ...(admin ? { admin } : {}),
  });
});

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

api.get("/api/v1/domains", requireScope("directory:read"), async (c) => {
  const domains = await listDomains(c.env);
  return c.json({
    domains: domains.map((d) => ({ domain: d.domain, is_default: d.is_default === 1, created_at: d.created_at })),
  });
});

api.post("/api/v1/domains", requireScope("directory:write"), async (c) => {
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

api.post("/api/v1/domains/:domain/default", requireScope("directory:write"), async (c) => {
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
api.post("/api/v1/domains/:domain/apply-to-all", requireScope("directory:write"), async (c) => {
  const domain = (c.req.param("domain") ?? "").toLowerCase();
  const row = (await listDomains(c.env)).find((d) => d.domain === domain);
  if (!row) return c.json({ error: "not_found", message: `No such domain "${domain}".` }, 404);

  const { updated, conflicts } = await applyDomainToAllUsers(c.env, domain);
  await logAudit(c.env, auditActor(c.get("apiActor")), "domain.applied_to_all", domain, { updated, conflicts }, c.req.raw);
  return c.json({ ok: true, updated, conflicts });
});

// ---------------------------------------------------------------------------
// Directory
// ---------------------------------------------------------------------------

api.post("/api/v1/directory/import", requireScope("directory:write"), async (c) => {
  const bundle = await readJson<DirectoryBundle>(c);
  const result = await importDirectory(c.env, bundle);

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

/** The "remove the sample directory" wipe, as an API call. Keeps the built-in groups and the administrators. */
api.post("/api/v1/directory/reset", requireScope("directory:write"), async (c) => {
  const result = await importDirectory(c.env, { version: 1, mode: "replace", users: [], groups: [] });
  await logAudit(c.env, auditActor(c.get("apiActor")), "directory.reset", undefined, undefined, c.req.raw);
  return c.json({ ok: true, domain: result.domain });
});

api.get("/api/v1/users", requireScope("directory:read"), async (c) => {
  const limit = Math.min(Number(c.req.query("limit") ?? 100) || 100, 500);
  const offset = Math.max(Number(c.req.query("offset") ?? 0) || 0, 0);

  // Explicit column list, not SELECT *: password_hash, password_salt and
  // totp_secret live in this table and must never leave it.
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.upn, u.username, u.display_name, u.given_name, u.family_name, u.external_id, u.status,
            u.mfa_enabled, u.job_title, u.department, u.employee_number, u.hire_date, u.employment_status,
            u.employment_type, u.location, u.manager_external_id, u.created_at, u.updated_at,
            (SELECT upn FROM users m WHERE m.external_id = u.manager_external_id) AS manager_upn,
            (SELECT GROUP_CONCAT(g.name, char(10)) FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = u.id) AS group_names
       FROM users u ORDER BY u.id LIMIT ? OFFSET ?`
  )
    .bind(limit, offset)
    .all<Record<string, unknown> & { group_names: string | null; mfa_enabled: number }>();

  const total = await c.env.DB.prepare("SELECT COUNT(*) as n FROM users").first<{ n: number }>();

  return c.json({
    total: total?.n ?? 0,
    limit,
    offset,
    users: results.map(({ group_names, mfa_enabled, ...user }) => ({
      ...user,
      mfa_enabled: mfa_enabled === 1,
      groups: group_names ? group_names.split("\n") : [],
    })),
  });
});

api.get("/api/v1/groups", requireScope("directory:read"), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT g.id, g.name, g.description, g.scim_id,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) AS member_count
       FROM groups g ORDER BY g.name`
  ).all<GroupRow & { member_count: number }>();

  return c.json({ groups: results });
});

// ---------------------------------------------------------------------------
// OIDC clients
// ---------------------------------------------------------------------------

api.get("/api/v1/clients", requireScope("directory:read"), async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, client_id, name, redirect_uris, created_at FROM oauth_clients ORDER BY name"
  ).all<Omit<OAuthClientRow, "client_secret_hash">>();

  return c.json({
    clients: results.map((cl) => ({
      id: cl.id,
      client_id: cl.client_id,
      name: cl.name,
      redirect_uris: JSON.parse(cl.redirect_uris) as string[],
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
api.post("/api/v1/clients", requireScope("clients:write"), async (c) => {
  const body = await readJson<{ name?: string; redirect_uris?: string[]; client_id?: string; client_secret?: string }>(c);
  const name = String(body.name ?? "").trim();
  if (!name) return c.json(badRequest("name is required."), 400);

  const redirectUris = (Array.isArray(body.redirect_uris) ? body.redirect_uris : [])
    .map((u) => String(u).trim())
    .filter(Boolean);
  if (redirectUris.length === 0) return c.json(badRequest("At least one redirect_uri is required."), 400);

  const seededId = String(body.client_id ?? "").trim();
  const seededSecret = String(body.client_secret ?? "").trim();
  if ((seededId === "") !== (seededSecret === "")) {
    return c.json(badRequest("client_id and client_secret must be supplied together, or neither."), 400);
  }
  if (seededSecret !== "" && seededSecret.length < 24) {
    return c.json(badRequest(`client_secret is ${seededSecret.length} characters; at least 24 are required.`), 400);
  }

  const existing = seededId
    ? await c.env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(seededId).first<{ id: number }>()
    : null;

  const clientId = seededId || `flareid_${randomToken(8)}`;
  const clientSecret = seededSecret || randomToken(24);
  const clientSecretHash = await sha256Hex(clientSecret);

  // Idempotent on the seeded id: re-running provisioning should converge, not
  // collide on the unique index.
  if (existing) {
    await c.env.DB.prepare("UPDATE oauth_clients SET name = ?, redirect_uris = ?, client_secret_hash = ? WHERE id = ?")
      .bind(name, JSON.stringify(redirectUris), clientSecretHash, existing.id)
      .run();
    await logAudit(c.env, auditActor(c.get("apiActor")), "oidc_client.updated", name, { client_id: clientId }, c.req.raw);
    return c.json({ ok: true, created: false, id: existing.id, client_id: clientId, redirect_uris: redirectUris });
  }

  const result = await c.env.DB.prepare(
    "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(clientId, clientSecretHash, name, JSON.stringify(redirectUris), new Date().toISOString())
    .run();

  await logAudit(c.env, auditActor(c.get("apiActor")), "oidc_client.created", name, { client_id: clientId }, c.req.raw);

  return c.json({
    ok: true,
    created: true,
    id: result.meta.last_row_id,
    client_id: clientId,
    // Returned once, and only when we generated it - a caller that supplied its
    // own already has it.
    ...(seededSecret ? {} : { client_secret: clientSecret }),
    redirect_uris: redirectUris,
  });
});

// ---------------------------------------------------------------------------
// SCIM (FlareID as a SCIM client, pushing to e.g. Cloudflare Access)
// ---------------------------------------------------------------------------

api.post("/api/v1/scim/config", requireScope("settings:write"), async (c) => {
  const body = await readJson<{ endpoint?: string; secret?: string; scope?: { mode?: string; group_ids?: number[] } }>(c);

  if (body.endpoint !== undefined || body.secret !== undefined) {
    await setScimConfig(c.env, { endpoint: String(body.endpoint ?? ""), secret: String(body.secret ?? "") });
  }
  if (body.scope) {
    await setScimScope(c.env, {
      mode: body.scope.mode === "selected" ? "selected" : "all",
      groupIds: Array.isArray(body.scope.group_ids) ? body.scope.group_ids.map(Number) : [],
    });
  }

  await logAudit(c.env, auditActor(c.get("apiActor")), "settings.scim_config_changed", undefined, undefined, c.req.raw);
  return c.json({ ok: true });
});

api.post("/api/v1/scim/test", requireScope("settings:write"), async (c) => {
  const result = await testScimConnection(c.env);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.connection_tested", undefined, { ok: result.ok }, c.req.raw);
  return c.json(result);
});

api.post("/api/v1/scim/sync", requireScope("settings:write"), async (c) => {
  const summary = await syncAll(c.env);
  await logAudit(c.env, auditActor(c.get("apiActor")), "scim.sync_all", undefined, summary, c.req.raw);
  return c.json({ ok: summary.userErrors === 0 && summary.groupErrors === 0, ...summary });
});

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

api.post("/api/v1/api-keys", requireScope("admin"), async (c) => {
  const body = await readJson<{ name?: string; scopes?: string[]; expires_at?: string }>(c);
  const name = String(body.name ?? "").trim();
  if (!name) return c.json(badRequest("name is required."), 400);

  const requested = Array.isArray(body.scopes) ? body.scopes.map(String) : ["admin"];
  const invalid = requested.filter((s) => !isApiScope(s));
  if (invalid.length > 0) return c.json(badRequest(`Unknown scope(s): ${invalid.join(", ")}.`), 400);

  const created = await createApiKey(c.env, {
    name,
    scopes: requested as ApiScope[],
    createdBy: c.get("apiActor").label,
    expiresAt: body.expires_at ?? null,
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
api.post("/api/v1/recovery/admin-reset", async (c) => {
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

  const result = await importDirectory(c.env, {
    version: 1,
    domain,
    groups: [{ name: SUPER_ADMINS_GROUP, description: "Members can administer this directory" }],
    users: [{ username, display_name: "Administrator", given_name: "Administrator", password, status: "active", super_admin: true }],
  });

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

api.onError((err, c) => {
  if (err instanceof ImportValidationError) return c.json(badRequest(err.message), 400);
  console.error(err);
  return c.json({ error: "server_error", message: "Unexpected error." }, 500);
});

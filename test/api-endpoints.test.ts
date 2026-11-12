// The API endpoints that make it complete with the admin console: each area's
// happy path, and at least one refusal per area (a token without the
// permission, or an action that needs "*").
import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(resetDatabase);

async function keyWith(adminKey: string, ...scopes: string[]): Promise<string> {
  const res = await apiCall("/api/v1/api-keys", { token: adminKey, body: { name: `k-${scopes.join("-")}-${Math.random()}`, scopes } });
  expect(res.status).toBe(200);
  return res.body.token as string;
}

const call = (token: string, method: string, path: string, body?: unknown) => apiCall(path, { token, method, ...(body !== undefined ? { body } : {}) });

describe("users", () => {
  it("creates, reads, updates, resets and deletes a user", async () => {
    const { apiKey } = await bootstrapInstance();
    await call(apiKey, "POST", "/api/v1/groups", { name: "Crew" });

    expect((await call(apiKey, "POST", "/api/v1/users", { username: "Jane", given_name: "Jane", attributes: { shoe_size: "9" } })).status).toBe(400);
    const created = await call(apiKey, "POST", "/api/v1/users", { username: "Jane", given_name: "Jane", family_name: "Doe", groups: ["Crew"], schema: "FlareID HR", attributes: { department: "Ops" } });
    expect(created.status).toBe(201);
    expect(created.body.upn).toBe("jane@example.com");
    expect(typeof created.body.password).toBe("string");

    const got = await call(apiKey, "GET", "/api/v1/users/jane");
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ upn: "jane@example.com", status: "disabled", groups: ["Crew"] });
    expect(got.body.password_hash).toBeUndefined();

    const patched = await call(apiKey, "PATCH", "/api/v1/users/jane", { family_name: "Smith", email: "jane@personal.test", status: "active", attributes: { job_title: "Lead" } });
    expect(patched.status).toBe(200);
    expect(patched.body).toMatchObject({ display_name: "Jane Smith", email: "jane@personal.test", status: "active", job_title: "Lead", department: "Ops", schema_name: "FlareID HR", groups: ["Crew"] });

    // Disabling ends sessions now.
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'jane'").first<{ id: number }>())!.id;
    await createSession(env, id, ["pwd"], new Request(BASE));
    expect((await call(apiKey, "GET", "/api/v1/users/jane/sessions")).body.sessions).toHaveLength(1);
    expect((await call(apiKey, "PATCH", "/api/v1/users/jane", { status: "disabled" })).status).toBe(200);
    expect((await call(apiKey, "GET", "/api/v1/users/jane/sessions")).body.sessions).toHaveLength(0);

    await createSession(env, id, ["pwd"], new Request(BASE));
    expect((await call(apiKey, "DELETE", "/api/v1/users/jane/sessions")).body).toEqual({ ok: true, revoked: 1 });

    // No body at all: generate one.
    const generated = await call(apiKey, "POST", "/api/v1/users/jane/reset-password");
    expect(generated.status).toBe(200);
    expect(typeof generated.body.password).toBe("string");
    const chosen = await call(apiKey, "POST", "/api/v1/users/jane/reset-password", { password: "a-chosen-password-1" });
    expect(chosen.body).toEqual({ ok: true });

    expect((await call(apiKey, "POST", "/api/v1/users/jane/reset-mfa", {})).status).toBe(200);
    expect((await call(apiKey, "GET", "/api/v1/users/jane/passkeys")).body).toEqual({ passkeys: [] });
    expect((await call(apiKey, "GET", "/api/v1/users/jane/apps")).body).toEqual({ apps: [] });

    expect((await call(apiKey, "DELETE", "/api/v1/users/jane")).status).toBe(200);
    expect((await call(apiKey, "GET", "/api/v1/users/jane")).status).toBe(404);
  });

  it("refuses a read-only key, a duplicate, and a non-admin acting on an administrator", async () => {
    const { apiKey } = await bootstrapInstance();
    const reader = await keyWith(apiKey, "users:read");
    expect((await call(reader, "POST", "/api/v1/users", { username: "x", given_name: "X" })).status).toBe(403);

    expect((await call(apiKey, "POST", "/api/v1/users", { username: "dup", given_name: "D" })).status).toBe(201);
    expect((await call(apiKey, "POST", "/api/v1/users", { username: "dup", given_name: "D" })).status).toBe(409);

    const writer = await keyWith(apiKey, "users:write", "groups:read");
    const reset = await call(writer, "POST", "/api/v1/users/admin/reset-password", {});
    expect(reset.status).toBe(403);
    expect(reset.body.error).toBe("forbidden");
    expect((await call(writer, "DELETE", "/api/v1/users/admin")).status).toBe(403);
    // Nor give anyone an admin role through their groups.
    expect((await call(writer, "PATCH", "/api/v1/users/dup", { groups: ["Super Admins"] })).status).toBe(403);
    expect((await call(writer, "PATCH", "/api/v1/users/dup", { given_name: "Dee" })).status).toBe(200);
  });

  it("validates a body against the schema with the API's error shape", async () => {
    const { apiKey } = await bootstrapInstance();
    const bad = await call(apiKey, "POST", "/api/v1/users", { username: 5, given_name: "X" });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe("invalid_request");
    expect(bad.body.message).toMatch(/username/);
  });
});

describe("groups", () => {
  it("creates, reads, updates, freezes and deletes groups and their members", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, passwords: "none", users: [{ username: "ann", given_name: "Ann", department: "Sales" }, { username: "bob", given_name: "Bob", department: "Ops" }] },
    });

    const created = await call(apiKey, "POST", "/api/v1/groups", { name: "Team", description: "t", members: ["ann"] });
    expect(created.status).toBe(201);
    const id = created.body.id as number;

    expect((await call(apiKey, "POST", `/api/v1/groups/${id}/members`, { usernames: ["bob", "ann"] })).body).toEqual({ ok: true, added: 1 });
    const got = await call(apiKey, "GET", `/api/v1/groups/${id}?search=bo`);
    expect(got.body).toMatchObject({ name: "Team", member_count: 2, members: { total: 1, users: [{ username: "bob" }] } });

    expect((await call(apiKey, "PATCH", `/api/v1/groups/${id}`, { name: "Team A" })).body.name).toBe("Team A");
    const toDynamic = await call(apiKey, "PATCH", `/api/v1/groups/${id}`, { rule: { all: [{ field: "department", op: "eq", value: "Sales" }] } });
    expect(toDynamic.status).toBe(400);

    expect((await call(apiKey, "DELETE", `/api/v1/groups/${id}/members/ann`)).status).toBe(200);
    expect((await call(apiKey, "GET", `/api/v1/groups/${id}`)).body.member_count).toBe(1);

    const dyn = await call(apiKey, "POST", "/api/v1/groups", { name: "Sales", rule: { all: [{ field: "department", op: "eq", value: "Sales" }] } });
    expect(dyn.status).toBe(201);
    expect((await call(apiKey, "GET", `/api/v1/groups/${dyn.body.id}`)).body.members.users.map((u: { username: string }) => u.username)).toEqual(["ann"]);
    expect((await call(apiKey, "POST", `/api/v1/groups/${dyn.body.id}/members`, { usernames: ["bob"] })).status).toBe(400);
    expect((await call(apiKey, "PATCH", `/api/v1/groups/${dyn.body.id}`, { rule: null })).status).toBe(400);
    expect((await call(apiKey, "POST", `/api/v1/groups/${dyn.body.id}/freeze`, {})).body).toEqual({ ok: true, members: 1 });
    expect((await call(apiKey, "GET", `/api/v1/groups/${dyn.body.id}`)).body.rule).toBe("");

    expect((await call(apiKey, "DELETE", `/api/v1/groups/${id}`)).status).toBe(200);
    expect((await call(apiKey, "GET", `/api/v1/groups/${id}`)).status).toBe(404);
  });

  it("keeps admin role groups and Super Admins for admin keys", async () => {
    const { apiKey } = await bootstrapInstance();
    const writer = await keyWith(apiKey, "groups:write", "users:read");
    const superAdmins = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Super Admins'").first<{ id: number }>())!.id;
    expect((await call(writer, "POST", `/api/v1/groups/${superAdmins}/members`, { usernames: ["admin"] })).status).toBe(403);
    expect((await call(writer, "POST", "/api/v1/groups", { name: "Directory Admins" })).status).toBe(403);
    expect((await call(apiKey, "DELETE", `/api/v1/groups/${superAdmins}`)).status).toBe(400);
    const reader = await keyWith(apiKey, "groups:read");
    expect((await call(reader, "POST", "/api/v1/groups", { name: "Nope" })).status).toBe(403);
  });
});

describe("applications", () => {
  it("reads, updates, rotates and deletes an OIDC client", async () => {
    const { apiKey } = await bootstrapInstance();
    const made = await call(apiKey, "POST", "/api/v1/clients", { name: "App", redirect_uris: ["https://app.test/cb"] });
    const clientId = made.body.client_id as string;

    const got = await call(apiKey, "GET", `/api/v1/clients/${clientId}`);
    expect(got.body).toMatchObject({ client_id: clientId, name: "App", client_type: "confidential", trusted: true, allowed_claims: null });
    expect(JSON.stringify(got.body)).not.toMatch(/secret/);

    const patched = await call(apiKey, "PATCH", `/api/v1/clients/${clientId}`, { name: "App 2", allowed_claims: ["email"], trusted: false });
    expect(patched.body).toMatchObject({ name: "App 2", allowed_claims: ["email"], trusted: false, redirect_uris: ["https://app.test/cb"] });
    expect((await call(apiKey, "PATCH", `/api/v1/clients/${clientId}`, { allowed_claims: ["nope"] })).status).toBe(400);

    const reader = await keyWith(apiKey, "oidc:read");
    expect((await call(reader, "POST", `/api/v1/clients/${clientId}/rotate-secret`)).status).toBe(403);
    const rotated = await call(apiKey, "POST", `/api/v1/clients/${clientId}/rotate-secret`);
    expect(rotated.status).toBe(200);
    expect(rotated.body.client_secret).not.toBe(made.body.client_secret);

    expect((await call(apiKey, "DELETE", `/api/v1/clients/${clientId}`)).status).toBe(200);
    expect((await call(apiKey, "GET", `/api/v1/clients/${clientId}`)).status).toBe(404);
  });

  it("reads one SAML service provider", async () => {
    const { apiKey } = await bootstrapInstance();
    const sp = await call(apiKey, "POST", "/api/v1/saml/service-providers", { entity_id: "https://sp.test", acs_urls: ["https://sp.test/acs"] });
    const got = await call(apiKey, "GET", `/api/v1/saml/service-providers/${sp.body.id}`);
    expect(got.body).toMatchObject({ entity_id: "https://sp.test", acs_urls: ["https://sp.test/acs"], sign_response: true });
    expect((await call(await keyWith(apiKey, "oidc:read"), "GET", `/api/v1/saml/service-providers/${sp.body.id}`)).status).toBe(403);
  });

  it("lists API keys without secrets, and revokes one", async () => {
    const { apiKey } = await bootstrapInstance();
    const other = await keyWith(apiKey, "users:read");
    const list = await call(apiKey, "GET", "/api/v1/api-keys");
    expect(list.status).toBe(200);
    expect(list.body.api_keys.length).toBe(2);
    expect(JSON.stringify(list.body)).not.toMatch(/key_hash|flareid_sk_[A-Za-z0-9_-]{20}/);
    expect((await call(other, "GET", "/api/v1/api-keys")).status).toBe(403);

    const target = list.body.api_keys.find((k: { scopes: string[] }) => k.scopes.includes("users:read"));
    expect((await call(apiKey, "DELETE", `/api/v1/api-keys/${target.id}`)).status).toBe(200);
    expect((await call(other, "GET", "/api/v1/users")).status).toBe(401);
  });

  it("removes an unused domain and refuses one in use", async () => {
    const { apiKey } = await bootstrapInstance();
    await call(apiKey, "POST", "/api/v1/domains", { domain: "spare.test" });
    expect((await call(apiKey, "DELETE", "/api/v1/domains/example.com")).status).toBe(409);
    expect((await call(await keyWith(apiKey, "domains:read"), "DELETE", "/api/v1/domains/spare.test")).status).toBe(403);
    expect((await call(apiKey, "DELETE", "/api/v1/domains/spare.test")).status).toBe(200);
    expect((await call(apiKey, "DELETE", "/api/v1/domains/spare.test")).status).toBe(404);
  });

  it("reads the SCIM configuration without the secret", async () => {
    const { apiKey } = await bootstrapInstance();
    await call(apiKey, "POST", "/api/v1/scim/config", { endpoint: "https://scim.test/v2", secret: "s".repeat(30) });
    const got = await call(apiKey, "GET", "/api/v1/scim/config");
    expect(got.body).toEqual({ endpoint: "https://scim.test/v2", secret_set: true, scope: { mode: "all", group_ids: [] } });
  });
});

describe("email and branding", () => {
  it("reads and changes email settings, the switch and templates", async () => {
    const { apiKey } = await bootstrapInstance();
    const saved = await call(apiKey, "PUT", "/api/v1/email", { from_address: "No-Reply@Example.com", from_name: "IdP" });
    expect(saved.body).toMatchObject({ from_address: "no-reply@example.com", from_name: "IdP", enabled: true });
    expect((await call(apiKey, "PUT", "/api/v1/email", { from_address: "nope" })).status).toBe(400);
    expect((await call(apiKey, "POST", "/api/v1/email/enabled", { enabled: false })).body.enabled).toBe(false);
    // No EMAIL binding in the test Worker: the send fails, and says so.
    expect((await call(apiKey, "POST", "/api/v1/email/test", { to: "ops@example.com" })).status).toBe(502);

    const templates = await call(apiKey, "GET", "/api/v1/branding/email-templates");
    expect(templates.body.templates.map((t: { key: string }) => t.key)).toEqual(["invitation", "password_reset", "email_otp"]);
    const put = await call(apiKey, "PUT", "/api/v1/branding/email-templates/invitation", { subject: "Join {{app_name}}", heading: "Hi {{name}}" });
    expect(put.body).toMatchObject({ subject: "Join {{app_name}}", customised: true });
    expect((await call(apiKey, "PUT", "/api/v1/branding/email-templates/invitation", { subject: " ", heading: "x" })).status).toBe(400);
    expect((await call(apiKey, "DELETE", "/api/v1/branding/email-templates/invitation")).body.customised).toBe(false);

    const reader = await keyWith(apiKey, "email:read");
    expect((await call(reader, "GET", "/api/v1/email")).status).toBe(200);
    expect((await call(reader, "PUT", "/api/v1/email", { from_address: "a@b.co" })).status).toBe(403);
  });

  it("reads and patches the branding", async () => {
    const { apiKey } = await bootstrapInstance();
    const patched = await call(apiKey, "PATCH", "/api/v1/branding", { app_name: "Acme ID", login_gradient: { from: "#000000", to: "#ffffff" }, cursor_trail: { enabled: false }, email_accent: "#123456" });
    expect(patched.body).toMatchObject({ app_name: "Acme ID", login_gradient: { from: "#000000", to: "#ffffff" }, cursor_trail: { enabled: false }, email_accent: "#123456" });
    expect((await call(apiKey, "PATCH", "/api/v1/branding", { login_gradient: { from: "red", to: "#ffffff" } })).status).toBe(400);
    expect((await call(apiKey, "GET", "/api/v1/branding")).body.app_name).toBe("Acme ID");
    expect((await call(await keyWith(apiKey, "branding:read"), "PATCH", "/api/v1/branding", { app_name: "x" })).status).toBe(403);
  });
});

describe("security", () => {
  it("reads and changes the security settings", async () => {
    const { apiKey } = await bootstrapInstance();
    expect((await call(apiKey, "PUT", "/api/v1/security/password-policy", { minLength: 12, requireNumber: true })).body.password_policy).toMatchObject({ minLength: 12, requireNumber: true, requireSymbol: false });
    expect((await call(apiKey, "PUT", "/api/v1/security/rate-limit", { max_attempts: 7, window_minutes: 30 })).body.rate_limit).toEqual({ max_attempts: 7, window_minutes: 30 });
    expect((await call(apiKey, "PUT", "/api/v1/security/session-limits", { max_hours: 9999, idle_minutes: 30 })).body.session_limits).toEqual({ max_hours: 720, idle_minutes: 30 });
    expect((await call(apiKey, "PUT", "/api/v1/security/audit-retention", { days: 90 })).body.audit_retention_days).toBe(90);
    const pw = await call(apiKey, "PUT", "/api/v1/security/new-user-password", { mode: "default", default_password: "shared-password-1" });
    expect(pw.body.new_user_password).toEqual({ mode: "default", default_password_set: true });
    expect(JSON.stringify(pw.body)).not.toMatch(/shared-password-1/);
    expect((await call(apiKey, "PUT", "/api/v1/security/require-mfa", { required: true })).body.require_mfa).toBe(true);

    // Resetting every password includes administrators: "*" only.
    const sec = await keyWith(apiKey, "security:write");
    expect((await call(sec, "POST", "/api/v1/security/new-user-password/apply-to-all", {})).status).toBe(403);
    expect((await call(apiKey, "POST", "/api/v1/security/new-user-password/apply-to-all", {})).body).toEqual({ ok: true, updated: 1 });
    expect((await call(await keyWith(apiKey, "security:read"), "PUT", "/api/v1/security/audit-retention", { days: 90 })).status).toBe(403);
  });

  it("manages authentication policies and factors", async () => {
    const { apiKey } = await bootstrapInstance();
    await call(apiKey, "POST", "/api/v1/groups", { name: "Contractors" });
    const made = await call(apiKey, "POST", "/api/v1/security/policies", { name: "Strict", requirement: "mfa", priority: 5, groups: ["Contractors"] });
    expect(made.status).toBe(201);
    expect(made.body).toMatchObject({ name: "Strict", requirement: "mfa", priority: 5, groups: ["Contractors"], is_default: false });
    expect((await call(apiKey, "POST", "/api/v1/security/policies", { name: "Strict" })).status).toBe(400);
    expect((await call(apiKey, "PATCH", `/api/v1/security/policies/${made.body.id}`, { priority: 2 })).body).toMatchObject({ priority: 2, groups: ["Contractors"] });

    const factors = await call(apiKey, "GET", "/api/v1/security/factors");
    expect(factors.body.factors.filter((f: { available: boolean }) => f.available).map((f: { key: string; enabled: boolean }) => [f.key, f.enabled])).toEqual([["totp", true], ["passkey", true], ["email_otp", false], ["security_questions", false]]);
    // Email codes stay off until email is configured.
    expect((await call(apiKey, "PUT", "/api/v1/security/factors/email_otp", { enabled: true })).status).toBe(400);
    expect((await call(apiKey, "PUT", "/api/v1/security/factors/totp", { enabled: false })).status).toBe(200);
    // The last factor stays on while a policy requires one.
    expect((await call(apiKey, "PUT", "/api/v1/security/factors/passkey", { enabled: false })).status).toBe(400);

    expect((await call(apiKey, "DELETE", `/api/v1/security/policies/${made.body.id}`)).status).toBe(200);
    const def = (await call(apiKey, "GET", "/api/v1/security/policies")).body.policies.find((p: { is_default: boolean }) => p.is_default);
    expect((await call(apiKey, "DELETE", `/api/v1/security/policies/${def.id}`)).status).toBe(400);
  });

  it("manages roles without letting a caller grant more than it holds", async () => {
    const { apiKey } = await bootstrapInstance();
    await call(apiKey, "POST", "/api/v1/groups", { name: "Helpdesk" });
    const made = await call(apiKey, "POST", "/api/v1/security/roles", { name: "Helpdesk", permissions: ["users:write"], groups: ["Helpdesk"] });
    expect(made.status).toBe(201);
    expect(made.body).toMatchObject({ name: "Helpdesk", permissions: ["users:write"], groups: ["Helpdesk"], builtin: false });
    expect((await call(apiKey, "PATCH", `/api/v1/security/roles/${made.body.id}`, { permissions: ["users:read", "audit:read"] })).body.permissions).toEqual(["users:read", "audit:read"]);
    expect((await call(apiKey, "POST", "/api/v1/security/roles", { name: "Bad", permissions: ["users:destroy"] })).status).toBe(400);

    const limited = await keyWith(apiKey, "roles:write", "users:read");
    expect((await call(limited, "POST", "/api/v1/security/roles", { name: "Up", permissions: ["users:write"] })).status).toBe(403);
    expect((await call(limited, "POST", "/api/v1/security/roles", { name: "All", permissions: ["*"] })).status).toBe(403);
    expect((await call(limited, "POST", "/api/v1/security/roles", { name: "Read", permissions: ["users:read"] })).status).toBe(201);

    const roles = (await call(apiKey, "GET", "/api/v1/security/roles")).body.roles as { id: number; name: string }[];
    const superRole = roles.find((r) => r.name === "Super Admin")!;
    const auditor = roles.find((r) => r.name === "Auditor")!;
    expect((await call(apiKey, "PATCH", `/api/v1/security/roles/${superRole.id}`, { description: "x" })).status).toBe(400);
    expect((await call(apiKey, "DELETE", `/api/v1/security/roles/${auditor.id}`)).status).toBe(400);
    expect((await call(apiKey, "DELETE", `/api/v1/security/roles/${made.body.id}`)).status).toBe(200);
  });

  it("lists signing keys (public parts only) and rotates one", async () => {
    const { apiKey } = await bootstrapInstance();
    const before = await call(apiKey, "GET", "/api/v1/security/signing-keys");
    expect(before.status).toBe(200);
    expect(JSON.stringify(before.body)).not.toMatch(/private|"d":/);
    const es = before.body.keys.find((k: { alg: string; status: string }) => k.alg === "ES256" && k.status === "active");
    const rotated = await call(apiKey, "POST", "/api/v1/security/signing-keys/ES256/rotate");
    expect(rotated.body.kid).not.toBe(es.kid);
    const after = (await call(apiKey, "GET", "/api/v1/security/signing-keys")).body.keys as { kid: string; status: string }[];
    expect(after.find((k) => k.kid === es.kid)?.status).toBe("retired");
    expect((await call(apiKey, "POST", "/api/v1/security/signing-keys/HS256/rotate")).status).toBe(400);
    expect((await call(await keyWith(apiKey, "signing_keys:read"), "POST", "/api/v1/security/signing-keys/ES256/rotate")).status).toBe(403);
  });
});

describe("monitoring", () => {
  it("reads the audit log with the console's filters, the overview and performance", async () => {
    const { apiKey } = await bootstrapInstance();
    await keyWith(apiKey, "users:read");
    const log = await call(apiKey, "GET", "/api/v1/audit?category=api_key&limit=5");
    expect(log.status).toBe(200);
    expect(log.body.entries.length).toBeGreaterThan(0);
    expect(log.body.entries.every((e: { action: string }) => e.action.startsWith("api_key."))).toBe(true);
    expect(log.body.entries[0].details).toMatchObject({ scopes: ["users:read"] });

    const stats = await call(apiKey, "GET", "/api/v1/stats");
    expect(stats.body.counts).toMatchObject({ users: 1, active_api_keys: 2 });
    expect(stats.body.last_30d.sign_ins_by_day).toHaveLength(30);

    // No CF_ACCOUNT_ID / CF_ANALYTICS_TOKEN in tests: a clear answer, not an error.
    const perf = await call(apiKey, "GET", "/api/v1/performance?range=1h");
    expect(perf.body).toMatchObject({ configured: false, range: "1h" });

    const reader = await keyWith(apiKey, "users:read");
    expect((await call(reader, "GET", "/api/v1/audit")).status).toBe(403);
    expect((await call(reader, "GET", "/api/v1/stats")).status).toBe(403);
  });
});

import { describe, it, expect, beforeEach } from "vitest";
import { env, SELF } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { stashPendingAction } from "../src/lib/step-up.js";
import { createScimTarget, updateScimTarget, getScimTarget } from "../src/lib/scim-targets.js";
import { configureAccessApp } from "../src/lib/cfone.js";
import { adminRoleGroupIds } from "../src/lib/admin-roles.js";

beforeEach(resetDatabase);

const USER_PASSWORD = "user-password-123";
const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";

function b64decode(input: string): string {
  return new TextDecoder().decode(Uint8Array.from(atob(input), (c) => c.charCodeAt(0)));
}

function authnRequestXml(opts: { isPassive?: boolean } = {}): string {
  const id = `_req-${Math.random().toString(16).slice(2)}`;
  return (
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${id}" Version="2.0" IssueInstant="2026-10-31T00:00:00Z"` +
    ` AssertionConsumerServiceURL="${SP_ACS}" Destination="${BASE}/saml/sso"` +
    (opts.isPassive ? ` IsPassive="true"` : "") +
    `><saml:Issuer>${SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>`
  );
}

async function deflateB64(xml: string): Promise<string> {
  const stream = new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  const buf = await new Response(stream).arrayBuffer();
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function postSso(opts: { isPassive?: boolean; cookie?: string } = {}): Promise<Response> {
  return SELF.fetch(`${BASE}/saml/sso`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(opts.cookie ? { Cookie: opts.cookie } : {}) },
    body: new URLSearchParams({ SAMLRequest: btoa(authnRequestXml(opts)) }).toString(),
    redirect: "manual",
  });
}

async function seedSp(apiKey: string, extra: Record<string, unknown> = {}): Promise<void> {
  const r = await apiCall("/api/v1/saml/service-providers", {
    token: apiKey,
    body: { entity_id: SP_ENTITY_ID, name: "sp", acs_urls: [SP_ACS], access_mode: "everyone", ...extra },
  });
  if (r.status !== 200) throw new Error(`sp seed: ${JSON.stringify(r.body)}`);
}

async function seedUser(apiKey: string, username: string): Promise<void> {
  const r = await apiCall("/api/v1/users", { token: apiKey, body: { username, given_name: username, password: USER_PASSWORD, status: "active" } });
  if (r.status >= 300) throw new Error(`user seed: ${JSON.stringify(r.body)}`);
}

describe("app require_mfa on a fresh password login", () => {
  it("withholds the SAML assertion (RequestDenied) when the session has no factor", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedSp(apiKey, { require_mfa: true });
    await seedUser(apiKey, "ned");

    const sso = await postSso();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(await sso.text())?.[1] ?? "";
    expect(flowId).toBeTruthy();

    const login = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow_id: flowId, upn: "ned@example.com", password: USER_PASSWORD }).toString(),
      redirect: "manual",
    });
    const html = await login.text();
    const samlResponse = /name="SAMLResponse" value="([^"]+)"/.exec(html)?.[1] ?? "";
    expect(samlResponse, "the flow must answer the SP, not park or redirect").toBeTruthy();
    const xml = b64decode(samlResponse);
    expect(xml).toContain("RequestDenied");
    expect(xml).not.toContain("<saml:Assertion");
  });
});

describe("IsPassive with an unsatisfied factor gate", () => {
  it("answers NoPassive instead of dropping to the enrolment UI", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
    await seedSp(apiKey);
    await seedUser(apiKey, "pat");

    // Signed in (password only): session exists, the gate wants enrolment.
    const loginPage = await SELF.fetch(`${BASE}/login`, { redirect: "manual" });
    const flowId = /name="flow_id" value="([^"]+)"/.exec(await loginPage.text())?.[1] ?? "";
    const login = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow_id: flowId, upn: "pat@example.com", password: USER_PASSWORD }).toString(),
      redirect: "manual",
    });
    const cookie = login.headers.get("Set-Cookie")?.split(";")[0] ?? "";
    expect(cookie).toBeTruthy();

    const res = await postSso({ isPassive: true, cookie });
    const html = await res.text();
    const samlResponse = /name="SAMLResponse" value="([^"]+)"/.exec(html)?.[1] ?? "";
    expect(samlResponse).toBeTruthy();
    const xml = b64decode(samlResponse);
    expect(xml).toContain("NoPassive");
    expect(xml).not.toContain("<saml:Assertion");
  });
});

describe("access-request decisions charge the target's own write scope", () => {
  it("groups:write alone cannot approve an oidc_app request; oidc:write can", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, "pat");
    const app = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: { name: "rp", redirect_uris: ["https://rp.test/cb"], access_mode: "restricted", requestable: true },
    });
    const clientId = app.body.client_id as string;
    const appRow = await env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(clientId).first<{ id: number }>();

    const filed = await apiCall("/api/v1/access/requests", {
      token: apiKey,
      body: { username: "pat", target_type: "oidc_app", target_id: appRow!.id },
    });
    expect(filed.status).toBe(201);
    const reqId = filed.body.request.id as number;

    const narrow = (await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "n", scopes: ["groups:write"] } })).body.token as string;
    const denied = await apiCall(`/api/v1/access/requests/${reqId}`, { token: narrow, body: { decision: "approved" } });
    expect(denied.status).toBe(403);

    const apps = (await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "a", scopes: ["groups:write", "oidc:write"] } })).body.token as string;
    const ok = await apiCall(`/api/v1/access/requests/${reqId}`, { token: apps, body: { decision: "approved" } });
    expect(ok.status).toBe(200);
  });
});

describe("dangling policy_id writes", () => {
  it("PATCH a client with a non-existent policy_id -> 400", async () => {
    const { apiKey } = await bootstrapInstance();
    const app = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "rp", redirect_uris: ["https://rp.test/cb"], access_mode: "everyone" } });
    const res = await apiCall(`/api/v1/clients/${app.body.client_id}`, { token: apiKey, method: "PATCH", body: { policy_id: 999999 } });
    expect(res.status).toBe(400);
  });
});

describe("SCIM target credential on repoint", () => {
  const input = {
    name: "t",
    endpoint: "https://scim.example.com/v2",
    secret: "s3cret-token",
    scope: { mode: "all" as const, groupIds: [] },
    paceMs: 100,
    membersPerRequest: 100,
    syncBatchSize: 100,
    enabled: true,
  };

  it("changing the endpoint without a new secret drops the stored credential", async () => {
    await bootstrapInstance();
    const target = await createScimTarget(env, input);
    const moved = await updateScimTarget(env, target.id, { endpoint: "https://evil.example.com/v2" });
    expect(moved!.secret).toBe("");
  });

  it("a metadata-only update keeps the credential", async () => {
    await bootstrapInstance();
    const target = await createScimTarget(env, input);
    const renamed = await updateScimTarget(env, target.id, { name: "t2" });
    expect(renamed!.secret).not.toBe("");
    const row = await getScimTarget(env, target.id);
    expect(row!.endpoint).toBe(input.endpoint);
  });
});

describe("pending-action stash refuses credential fields", () => {
  it("returns null when the form carries a password/secret/token/key field", async () => {
    await bootstrapInstance();
    const req = new Request(`${BASE}/admin/users`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: "x", password: "hunter2" }).toString(),
    });
    expect(await stashPendingAction(env, "sess-1", req, "/admin/users")).toBeNull();
  });

  it("stashes a benign form", async () => {
    await bootstrapInstance();
    const req = new Request(`${BASE}/admin/users`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: "x", display_name: "X" }).toString(),
    });
    expect(await stashPendingAction(env, "sess-1", req, "/admin/users")).toBeTruthy();
  });
});

describe("Access-app granting group cannot confer an admin role", () => {
  it("configureAccessApp refuses a role-linked group", async () => {
    const { apiKey } = await bootstrapInstance();
    await env.DB.prepare(
      "INSERT INTO cf_access_apps (cf_app_id, name, type, hostname, granting_group_id, grant_hint, requestable, synced_at, updated_at) VALUES ('cf-1', 'App', 'self_hosted', 'app.test', NULL, '[]', 1, '', 'now')"
    ).run();
    const row = await env.DB.prepare("SELECT id FROM cf_access_apps WHERE cf_app_id = 'cf-1'").first<{ id: number }>();
    const roleGroups = await adminRoleGroupIds(env);
    expect(roleGroups.size).toBeGreaterThan(0);
    const roleGroupId = [...roleGroups][0]!;
    await expect(configureAccessApp(env, row!.id, roleGroupId, true)).rejects.toThrow();
    const still = await env.DB.prepare("SELECT granting_group_id FROM cf_access_apps WHERE id = ?").bind(row!.id).first<{ granting_group_id: number | null }>();
    expect(still!.granting_group_id).toBeNull();
  });
});

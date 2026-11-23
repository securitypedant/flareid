import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { b64decode, b64encode } from "../src/lib/saml/xml.js";

beforeEach(resetDatabase);

const REDIRECT_URI = "https://rp.test/callback";
const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";
const USER_PASSWORD = "a-test-user-password-1";

/**
 * A bootstrapped instance with two groups and two users: Ada (Executives +
 * the dynamic All Employees) and a contractor (no groups).
 */
async function seedDirectory(): Promise<{ apiKey: string; execGroupId: number; otherGroupId: number }> {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      groups: [
        { name: "Executives" },
        { name: "Other Team" },
        { name: "All Employees", rule: JSON.stringify({ all: [{ field: "employment_type", op: "eq", value: "full_time" }] }) },
      ],
      users: [
        {
          username: "ada.kowalski",
          given_name: "Ada",
          family_name: "Kowalski",
          employment_type: "full_time",
          password: USER_PASSWORD,
          status: "active",
          groups: ["Executives"],
        },
        {
          username: "con.tractor",
          given_name: "Con",
          family_name: "Tractor",
          employment_type: "contractor",
          password: USER_PASSWORD,
          status: "active",
          groups: [],
        },
      ],
    },
  });
  const execGroupId = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Executives'").first<{ id: number }>())!.id;
  const otherGroupId = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Other Team'").first<{ id: number }>())!.id;
  return { apiKey, execGroupId, otherGroupId };
}

async function userId(username: string): Promise<number> {
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

/** A live session cookie without driving the login form. */
async function sessionFor(id: number): Promise<string> {
  const { setCookie } = await createSession(env, id, ["pwd"], new Request(BASE));
  return setCookie.split(";")[0]!;
}

function authorizeQuery(clientId: string): URLSearchParams {
  return new URLSearchParams({ client_id: clientId, redirect_uri: REDIRECT_URI, response_type: "code", scope: "openid", state: "s1" });
}

/** GET /authorize -> login form -> POST /login; returns the browser's redirect. */
async function authorizeAndLogin(clientId: string, upn: string): Promise<string | null> {
  const page = await SELF.fetch(`${BASE}/authorize?${authorizeQuery(clientId)}`, { redirect: "manual" });
  const html = await page.text();
  if (page.headers.get("Location")) return page.headers.get("Location");
  const flowId = /name="flow_id" value="([^"]*)"/.exec(html)?.[1];
  if (!flowId) throw new Error(`no login form at /authorize (HTTP ${page.status}): ${html.slice(0, 300)}`);
  const submitted = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password: USER_PASSWORD }).toString(),
    redirect: "manual",
  });
  return submitted.headers.get("Location");
}

async function createClient(apiKey: string, name: string, assignedGroups?: number[], extra: Record<string, unknown> = {}): Promise<string> {
  const res = await apiCall("/api/v1/clients", {
    token: apiKey,
    body: { name, redirect_uris: [REDIRECT_URI], ...(assignedGroups !== undefined ? { assigned_groups: assignedGroups } : {}), ...extra },
  });
  if (res.status !== 200) throw new Error(`client seed failed: ${JSON.stringify(res.body)}`);
  return res.body.client_id as string;
}

function authnRequestXml(id = `_req-${Math.random().toString(16).slice(2)}`): string {
  return (
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${id}" Version="2.0" IssueInstant="2026-10-31T00:00:00Z" AssertionConsumerServiceURL="${SP_ACS}" Destination="${BASE}/saml/sso">` +
    `<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>`
  );
}

/** raw-DEFLATE + base64, the HTTP-Redirect binding's encoding. */
async function ssoQuery(xml: string): Promise<string> {
  const stream = new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  const buf = await new Response(stream).arrayBuffer();
  return `SAMLRequest=${encodeURIComponent(b64encode(buf))}`;
}

async function createSp(apiKey: string, entityId: string, assignedGroups?: number[], extra: Record<string, unknown> = {}): Promise<void> {
  const res = await apiCall("/api/v1/saml/service-providers", {
    token: apiKey,
    body: { entity_id: entityId, name: entityId, acs_urls: [SP_ACS], ...(assignedGroups !== undefined ? { assigned_groups: assignedGroups } : {}), ...extra },
  });
  if (res.status !== 200) throw new Error(`SP seed failed: ${JSON.stringify(res.body)}`);
}

/** GET /saml/sso -> login form -> POST /login; returns the resulting page. */
async function ssoViaLogin(query: string, upn: string): Promise<{ status: number; html: string }> {
  const first = await SELF.fetch(`${BASE}/saml/sso?${query}`, { redirect: "manual" });
  const firstHtml = await first.text();
  const flowId = /name="flow_id" value="([^"]*)"/.exec(firstHtml)?.[1];
  if (!flowId) return { status: first.status, html: firstHtml };
  const submitted = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password: USER_PASSWORD }).toString(),
    redirect: "manual",
  });
  return { status: submitted.status, html: await submitted.text() };
}

function samlResponseOf(html: string): string {
  const b64 = /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1];
  expect(b64, "a SAMLResponse field in the auto-POST page").toBeTruthy();
  return new TextDecoder().decode(b64decode(b64!));
}

describe("OIDC app assignment", () => {
  it("denies sign-in for a user outside the assigned groups (access_denied to the redirect_uri)", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    const clientId = await createClient(apiKey, "Exec App", [execGroupId]);

    const location = await authorizeAndLogin(clientId, "con.tractor@horizon.test");
    expect(location).toBeTruthy();
    const url = new URL(location!);
    expect(`${url.origin}${url.pathname}`).toBe(REDIRECT_URI);
    expect(url.searchParams.get("error")).toBe("access_denied");
    expect(url.searchParams.get("state")).toBe("s1");
    expect(url.searchParams.get("code")).toBeNull();
  });

  it("denies the reused-session path the same way", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    const clientId = await createClient(apiKey, "Exec App", [execGroupId]);
    const cookie = await sessionFor(await userId("con.tractor"));

    const res = await SELF.fetch(`${BASE}/authorize?${authorizeQuery(clientId)}`, { redirect: "manual", headers: { Cookie: cookie } });
    const location = res.headers.get("Location");
    expect(res.status).toBe(302);
    expect(new URL(location!).searchParams.get("error")).toBe("access_denied");
  });

  it("lets an assigned group member through - including a dynamic-rule group", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    const clientId = await createClient(apiKey, "Exec App", [execGroupId]);

    const location = await authorizeAndLogin(clientId, "ada.kowalski@horizon.test");
    expect(new URL(location!).searchParams.get("code")).toBeTruthy();

    // A dynamic group works for assignment too: All Employees matches on
    // employment_type, which excludes the contractor.
    const allEmployees = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'All Employees'").first<{ id: number }>())!.id;
    const dynClient = await createClient(apiKey, "All Employees App", [allEmployees]);
    expect(new URL((await authorizeAndLogin(dynClient, "ada.kowalski@horizon.test"))!).searchParams.get("code")).toBeTruthy();
    const denied = await authorizeAndLogin(dynClient, "con.tractor@horizon.test");
    expect(new URL(denied!).searchParams.get("error")).toBe("access_denied");
  });

  it("denies an app with no assignees by default - 'everyone' must be explicit", async () => {
    const { apiKey } = await seedDirectory();
    const closed = await createClient(apiKey, "Unassigned App");
    const denied = await authorizeAndLogin(closed, "con.tractor@horizon.test");
    expect(new URL(denied!).searchParams.get("error")).toBe("access_denied");

    const open = await createClient(apiKey, "Open App", undefined, { access_mode: "everyone" });
    const location = await authorizeAndLogin(open, "con.tractor@horizon.test");
    expect(new URL(location!).searchParams.get("code")).toBeTruthy();
  });
});

describe("SAML app assignment", () => {
  it("posts a signed RequestDenied to the ACS for a user outside the assigned groups", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    await createSp(apiKey, SP_ENTITY_ID, [execGroupId]);

    const result = await ssoViaLogin(await ssoQuery(authnRequestXml()), "con.tractor@horizon.test");
    const xml = samlResponseOf(result.html);
    expect(xml).toContain("status:RequestDenied");
    expect(xml).toContain("status:Responder");
    expect(xml).not.toContain("status:Success");
  });

  it("denies an existing session the same way", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    await createSp(apiKey, SP_ENTITY_ID, [execGroupId]);
    const cookie = await sessionFor(await userId("con.tractor"));

    const res = await SELF.fetch(`${BASE}/saml/sso?${await ssoQuery(authnRequestXml())}`, { redirect: "manual", headers: { Cookie: cookie } });
    const xml = samlResponseOf(await res.text());
    expect(xml).toContain("status:RequestDenied");
  });

  it("issues a normal assertion for an assigned member", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    await createSp(apiKey, SP_ENTITY_ID, [execGroupId]);

    const result = await ssoViaLogin(await ssoQuery(authnRequestXml()), "ada.kowalski@horizon.test");
    const xml = samlResponseOf(result.html);
    expect(xml).toContain("status:Success");
    expect(xml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
  });

  it("gates IdP-initiated SSO by assignment", async () => {
    const { apiKey, execGroupId, otherGroupId } = await seedDirectory();
    await createSp(apiKey, SP_ENTITY_ID, [execGroupId]);
    await createSp(apiKey, "https://other.test/saml", [otherGroupId]);

    const ada = await SELF.fetch(`${BASE}/saml/idp-initiated?sp=${encodeURIComponent(SP_ENTITY_ID)}`, {
      redirect: "manual",
      headers: { Cookie: await sessionFor(await userId("ada.kowalski")) },
    });
    expect(samlResponseOf(await ada.text())).toContain("status:Success");

    const con = await SELF.fetch(`${BASE}/saml/idp-initiated?sp=${encodeURIComponent(SP_ENTITY_ID)}`, {
      redirect: "manual",
      headers: { Cookie: await sessionFor(await userId("con.tractor")) },
    });
    expect(con.status).toBe(403);
    expect(await con.text()).toMatch(/not allowed/);
  });
});

describe("launchpad", () => {
  it("lists only the apps visible to the signed-in user", async () => {
    const { apiKey, execGroupId, otherGroupId } = await seedDirectory();
    await createClient(apiKey, "Exec OIDC App", [execGroupId]);
    await createClient(apiKey, "Other OIDC App", [otherGroupId]);
    await createClient(apiKey, "Everyone OIDC App", undefined, { access_mode: "everyone" });
    await createSp(apiKey, SP_ENTITY_ID, [execGroupId]);
    await createSp(apiKey, "https://other.test/saml", [otherGroupId]);

    const adaPage = await (await SELF.fetch(`${BASE}/account/applications`, { headers: { Cookie: await sessionFor(await userId("ada.kowalski")) } })).text();
    expect(adaPage).toContain("Exec OIDC App");
    expect(adaPage).toContain("Everyone OIDC App");
    expect(adaPage).toContain("/saml/idp-initiated?sp=");
    expect(adaPage).toContain(`client_id=`);
    expect(adaPage).not.toContain("Other OIDC App");
    expect(adaPage).not.toContain("https://other.test/saml");

    const conPage = await (await SELF.fetch(`${BASE}/account/applications`, { headers: { Cookie: await sessionFor(await userId("con.tractor")) } })).text();
    expect(conPage).toContain("Everyone OIDC App");
    expect(conPage).not.toContain("Exec OIDC App");
    expect(conPage).not.toContain(SP_ENTITY_ID);
  });

  it("shows the empty state when nothing is visible", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    await createClient(apiKey, "Exec OIDC App", [execGroupId]);
    const conPage = await (await SELF.fetch(`${BASE}/account/applications`, { headers: { Cookie: await sessionFor(await userId("con.tractor")) } })).text();
    expect(conPage).toContain("No apps assigned yet.");
    expect(conPage).not.toContain("Exec OIDC App");
  });
});

describe("assigned users", () => {
  it("lets a directly assigned person in without any group membership", async () => {
    const { apiKey } = await seedDirectory();
    const conId = await userId("con.tractor");
    const clientId = await createClient(apiKey, "Named People App", undefined, { assigned_users: [conId] });

    const location = await authorizeAndLogin(clientId, "con.tractor@horizon.test");
    expect(new URL(location!).searchParams.get("code")).toBeTruthy();

    // A group member who is NOT named is still out.
    const denied = await authorizeAndLogin(clientId, "ada.kowalski@horizon.test");
    expect(new URL(denied!).searchParams.get("error")).toBe("access_denied");
  });

  it("combines users and groups: either path opens the app", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    const conId = await userId("con.tractor");
    const clientId = await createClient(apiKey, "Exec Plus Named", [execGroupId], { assigned_users: [conId] });

    expect(new URL((await authorizeAndLogin(clientId, "ada.kowalski@horizon.test"))!).searchParams.get("code")).toBeTruthy();
    expect(new URL((await authorizeAndLogin(clientId, "con.tractor@horizon.test"))!).searchParams.get("code")).toBeTruthy();
  });
});

describe("require_mfa", () => {
  it("steps a password-only sign-in up to a second factor before issuing a code", async () => {
    const { apiKey } = await seedDirectory();
    const clientId = await createClient(apiKey, "MFA App", undefined, { access_mode: "everyone", require_mfa: true });

    // Ada has TOTP: after the password step she must land on the MFA challenge,
    // not on a code redirect.
    const page = await SELF.fetch(`${BASE}/authorize?${authorizeQuery(clientId)}`, { redirect: "manual" });
    const html = await page.text();
    const flowId = /name="flow_id" value="([^"]*)"/.exec(html)?.[1];
    expect(flowId).toBeTruthy();

    // Give Ada a TOTP factor.
    const adaId = await userId("ada.kowalski");
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE id = ?").bind(adaId).run();

    const submitted = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow_id: flowId!, upn: "ada.kowalski@horizon.test", password: USER_PASSWORD }).toString(),
      redirect: "manual",
    });
    const body = await submitted.text();
    // An MFA challenge form - not a code redirect.
    expect(submitted.headers.get("Location")).toBeNull();
    expect(body).toMatch(/code|authenticator|factor/i);
    expect(new URL(submitted.headers.get("Location") ?? "https://x.test/").searchParams.get("code")).toBeNull();
  });
});

describe("app access requests", () => {
  const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

  it("runs ask -> approve -> assigned-user for a requestable app", async () => {
    const { apiKey } = await seedDirectory();
    const clientId = await createClient(apiKey, "Requestable App", undefined, { requestable: true });
    const appRow = await env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(clientId).first<{ id: number }>();
    const conId = await userId("con.tractor");
    const cookie = await sessionFor(conId);

    // The app shows in the targets picker for someone outside it.
    const targets = (await (await SELF.fetch(`${BASE}/account/access/targets?q=Requestable`, { headers: { Cookie: cookie } })).json()) as { id: string; label: string }[];
    expect(targets.some((t) => t.id === `oidc_app:${appRow!.id}`)).toBe(true);

    // Ask -> approve through the API -> the user lands in assigned_users.
    const ask = await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: `target=oidc_app%3A${appRow!.id}&reason=need+it`,
      redirect: "manual",
    });
    expect(ask.headers.get("Location")).toContain("saved=access-requested");
    const req = await env.DB.prepare("SELECT id FROM access_requests WHERE user_id = ? AND target_type = 'oidc_app'").bind(conId).first<{ id: number }>();
    expect(req).toBeTruthy();
    const decide = await apiCall(`/api/v1/access/requests/${req!.id}`, { token: apiKey, body: { decision: "approved" } });
    expect(decide.status).toBe(200);
    const assigned = await env.DB.prepare("SELECT assigned_users FROM oauth_clients WHERE id = ?").bind(appRow!.id).first<{ assigned_users: string }>();
    expect(JSON.parse(assigned!.assigned_users)).toContain(conId);

    // And sign-in works now.
    const location = await authorizeAndLogin(clientId, "con.tractor@horizon.test");
    expect(new URL(location!).searchParams.get("code")).toBeTruthy();
  });

  it("refuses a request for a non-requestable app", async () => {
    const { apiKey } = await seedDirectory();
    const clientId = await createClient(apiKey, "Closed App");
    const appRow = await env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(clientId).first<{ id: number }>();
    const conId = await userId("con.tractor");
    const cookie = await sessionFor(conId);

    const res = await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: `target=oidc_app%3A${appRow!.id}`,
    });
    expect(res.status).toBe(200); // the friendly error page
    expect(await env.DB.prepare("SELECT 1 FROM access_requests WHERE user_id = ? AND target_type = 'oidc_app'").bind(conId).first()).toBeNull();
  });
});

describe("bound authentication policy", () => {
  async function makePolicy(apiKey: string, body: Record<string, unknown>): Promise<number> {
    const res = await apiCall("/api/v1/security/policies", { token: apiKey, body });
    if (res.status !== 201 && res.status !== 200) throw new Error(`policy seed failed: ${JSON.stringify(res.body)}`);
    return res.body.id as number;
  }

  it("steps a password-only sign-in up when the app binds an MFA policy (no require_mfa switch)", async () => {
    const { apiKey } = await seedDirectory();
    const policyId = await makePolicy(apiKey, { name: "Strict", requirement: "mfa", groups: [] });
    const clientId = await createClient(apiKey, "Policy App", undefined, { access_mode: "everyone", policy_id: policyId });

    const adaId = await userId("ada.kowalski");
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE id = ?").bind(adaId).run();

    const page = await SELF.fetch(`${BASE}/authorize?${authorizeQuery(clientId)}`, { redirect: "manual" });
    const html = await page.text();
    const flowId = /name="flow_id" value="([^"]*)"/.exec(html)?.[1];
    expect(flowId).toBeTruthy();

    const submitted = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow_id: flowId!, upn: "ada.kowalski@horizon.test", password: USER_PASSWORD }).toString(),
      redirect: "manual",
    });
    const body = await submitted.text();
    // An MFA challenge form - the bound policy, not a code redirect.
    expect(submitted.headers.get("Location")).toBeNull();
    expect(body).toMatch(/code|authenticator|factor/i);
  });

  it("denies sign-in when the bound policy requires a device certificate the request lacks", async () => {
    const { apiKey } = await seedDirectory();
    const policyId = await makePolicy(apiKey, { name: "Managed devices", requirement: "password", device_cert: true, groups: [] });
    const clientId = await createClient(apiKey, "Device Policy App", undefined, { access_mode: "everyone", policy_id: policyId });

    const location = await authorizeAndLogin(clientId, "ada.kowalski@horizon.test");
    expect(location).toBeTruthy();
    expect(location).toContain("error=access_denied");
  });

  it("lets the sign-in through when no certificate is required by the bound policy", async () => {
    const { apiKey } = await seedDirectory();
    const policyId = await makePolicy(apiKey, { name: "Password is fine", requirement: "password", groups: [] });
    const clientId = await createClient(apiKey, "Relaxed Policy App", undefined, { access_mode: "everyone", policy_id: policyId });

    const location = await authorizeAndLogin(clientId, "ada.kowalski@horizon.test");
    expect(location).toBeTruthy();
    expect(location).toContain("code=");
  });

  it("keeps the console Policies tab and the policies list in sync with the binding", async () => {
    const { apiKey } = await seedDirectory();
    const policyId = await makePolicy(apiKey, { name: "Strict", requirement: "mfa", groups: [] });
    const clientId = await createClient(apiKey, "Console App", undefined, { access_mode: "everyone" });
    const appRow = await env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(clientId).first<{ id: number }>();
    const adminId = await userId("admin");
    const cookie = await sessionFor(adminId);

    // The Policies tab offers every policy.
    const tab = await (await SELF.fetch(`${BASE}/admin/clients/${appRow!.id}?tab=policies`, { headers: { Cookie: cookie } })).text();
    expect(tab).toContain('name="policy_id"');
    expect(tab).toContain("Strict");

    // Binding through the console writes policy_id.
    const save = await SELF.fetch(`${BASE}/admin/clients/${appRow!.id}/policies`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: BASE },
      body: `policy_id=${policyId}`,
      redirect: "manual",
    });
    expect(save.headers.get("Location")).toContain("tab=policies");
    const bound = await env.DB.prepare("SELECT policy_id FROM oauth_clients WHERE id = ?").bind(appRow!.id).first<{ policy_id: number | null }>();
    expect(bound!.policy_id).toBe(policyId);

    // And the policies list shows the app under "Applies to".
    const list = await (await SELF.fetch(`${BASE}/admin/security/policies`, { headers: { Cookie: cookie } })).text();
    expect(list).toContain(`href="/admin/clients/${appRow!.id}?tab=policies"`);
  });

  it("round-trips bind, read and clear through the API on both app kinds", async () => {
    const { apiKey } = await seedDirectory();
    const policyId = await makePolicy(apiKey, { name: "Strict", requirement: "mfa", groups: [] });

    const cl = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "API App", redirect_uris: [REDIRECT_URI], policy_id: policyId } });
    expect(cl.status).toBe(200);
    expect((await apiCall(`/api/v1/clients/${cl.body.client_id}`, { token: apiKey })).body.policy_id).toBe(policyId);

    const patch = await apiCall(`/api/v1/clients/${cl.body.client_id}`, { token: apiKey, method: "PATCH", body: { policy_id: null } });
    expect(patch.body.policy_id).toBeNull();

    const sp = await apiCall("/api/v1/saml/service-providers", { token: apiKey, body: { entity_id: "https://pol-sp.test", name: "SP", acs_urls: [SP_ACS], policy_id: policyId } });
    expect(sp.body.created).toBe(true);
    const spRow = await env.DB.prepare("SELECT id, policy_id FROM saml_service_providers WHERE entity_id = 'https://pol-sp.test'").first<{ id: number; policy_id: number | null }>();
    expect(spRow!.policy_id).toBe(policyId);

    await apiCall("/api/v1/saml/service-providers", { token: apiKey, body: { entity_id: "https://pol-sp.test", policy_id: null } });
    expect((await env.DB.prepare("SELECT policy_id FROM saml_service_providers WHERE id = ?").bind(spRow!.id).first<{ policy_id: number | null }>())!.policy_id).toBeNull();

    // The policy read endpoint reports the bound apps (cleared ones are gone).
    const policies = (await apiCall("/api/v1/security/policies", { token: apiKey })).body.policies as { id: number; apps: { kind: string; name: string }[] }[];
    const cleared = policies.find((p) => p.id === policyId)!;
    expect(cleared.apps).toEqual([]);
  });

  it("does not wipe access fields when the Settings tab saves", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    const policyId = await makePolicy(apiKey, { name: "Strict", requirement: "mfa", groups: [] });
    const clientId = await createClient(apiKey, "Settings App", [execGroupId], { require_mfa: true, policy_id: policyId });
    const appRow = await env.DB.prepare("SELECT id FROM oauth_clients WHERE client_id = ?").bind(clientId).first<{ id: number }>();
    const cookie = await sessionFor(await userId("admin"));

    const save = await SELF.fetch(`${BASE}/admin/clients/${appRow!.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: BASE },
      body: new URLSearchParams({ name: "Settings App", redirect_uris: REDIRECT_URI, trusted: "1", allowed_claims: "sub" }).toString(),
      redirect: "manual",
    });
    expect(save.headers.get("Location")).toContain("saved=1");
    const row = await env.DB.prepare("SELECT access_mode, assigned_groups, require_mfa, policy_id FROM oauth_clients WHERE id = ?").bind(appRow!.id).first<{ access_mode: string; assigned_groups: string; require_mfa: number; policy_id: number | null }>();
    expect(row!.access_mode).toBe("restricted");
    expect(JSON.parse(row!.assigned_groups)).toEqual([execGroupId]);
    expect(row!.require_mfa).toBe(1);
    expect(row!.policy_id).toBe(policyId);
  });
});

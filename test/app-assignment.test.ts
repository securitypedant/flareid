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

async function createClient(apiKey: string, name: string, assignedGroups?: number[]): Promise<string> {
  const res = await apiCall("/api/v1/clients", {
    token: apiKey,
    body: { name, redirect_uris: [REDIRECT_URI], ...(assignedGroups !== undefined ? { assigned_groups: assignedGroups } : {}) },
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

async function createSp(apiKey: string, entityId: string, assignedGroups?: number[]): Promise<void> {
  const res = await apiCall("/api/v1/saml/service-providers", {
    token: apiKey,
    body: { entity_id: entityId, name: entityId, acs_urls: [SP_ACS], ...(assignedGroups !== undefined ? { assigned_groups: assignedGroups } : {}) },
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

  it("leaves unassigned apps open to everyone", async () => {
    const { apiKey } = await seedDirectory();
    const clientId = await createClient(apiKey, "Open App");
    const location = await authorizeAndLogin(clientId, "con.tractor@horizon.test");
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
    await createClient(apiKey, "Everyone OIDC App");
    await createSp(apiKey, SP_ENTITY_ID, [execGroupId]);
    await createSp(apiKey, "https://other.test/saml", [otherGroupId]);

    const adaPage = await (await SELF.fetch(`${BASE}/account`, { headers: { Cookie: await sessionFor(await userId("ada.kowalski")) } })).text();
    expect(adaPage).toContain("Exec OIDC App");
    expect(adaPage).toContain("Everyone OIDC App");
    expect(adaPage).toContain("/saml/idp-initiated?sp=");
    expect(adaPage).toContain(`client_id=`);
    expect(adaPage).not.toContain("Other OIDC App");
    expect(adaPage).not.toContain("https://other.test/saml");

    const conPage = await (await SELF.fetch(`${BASE}/account`, { headers: { Cookie: await sessionFor(await userId("con.tractor")) } })).text();
    expect(conPage).toContain("Everyone OIDC App");
    expect(conPage).not.toContain("Exec OIDC App");
    expect(conPage).not.toContain(SP_ENTITY_ID);
  });

  it("shows the empty state when nothing is visible", async () => {
    const { apiKey, execGroupId } = await seedDirectory();
    await createClient(apiKey, "Exec OIDC App", [execGroupId]);
    const conPage = await (await SELF.fetch(`${BASE}/account`, { headers: { Cookie: await sessionFor(await userId("con.tractor")) } })).text();
    expect(conPage).toContain("No apps assigned yet.");
    expect(conPage).not.toContain("Exec OIDC App");
  });
});

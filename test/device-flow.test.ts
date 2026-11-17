import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { decodeJwt } from "jose";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const PASSWORD = "user-password-123";
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

async function setup(client: Record<string, unknown> = {}) {
  const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, users: [{ username: "ola", given_name: "Ola", family_name: "Berg", password: PASSWORD, status: "active" }] },
  });
  const created = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Device App", redirect_uris: ["https://app.test/cb"], ...client } });
  if (created.status !== 200) throw new Error(JSON.stringify(created.body));
  return { apiKey, upn: `ola@${domain}`, clientId: created.body.client_id as string, clientSecret: created.body.client_secret as string | undefined };
}

async function deviceAuthorize(clientId: string, extra: Record<string, string> = {}) {
  const res = await SELF.fetch(`${BASE}/device_authorization`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, scope: "openid email", ...extra }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

async function poll(clientId: string, deviceCode: string, extra: Record<string, string> = {}) {
  const res = await SELF.fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: clientId, ...extra }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** Signs in through the login form for a `next` target; returns the session cookie. */
async function signIn(upn: string, next: string) {
  const page = await SELF.fetch(`${BASE}/login?next=${encodeURIComponent(next)}`, { redirect: "manual" });
  const flowId = /name="flow_id" value="([^"]+)"/.exec(await page.text())![1]!;
  const res = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: FORM,
    body: new URLSearchParams({ flow_id: flowId, upn, password: PASSWORD }).toString(),
    redirect: "manual",
  });
  return res.headers.get("Set-Cookie")?.split(";")[0] ?? "";
}

/** Runs the user's half of the flow at /device: entry -> approval page -> decision. */
async function decide(cookie: string, userCode: string, decision: "approve" | "deny") {
  const page = await SELF.fetch(`${BASE}/device?user_code=${encodeURIComponent(userCode)}`, { headers: { Cookie: cookie } });
  const html = await page.text();
  expect(html).toContain('action="/device/approve"');
  const res = await SELF.fetch(`${BASE}/device/approve`, {
    method: "POST",
    headers: { ...FORM, Cookie: cookie },
    body: new URLSearchParams({ user_code: userCode, decision }).toString(),
  });
  return { status: res.status, body: await res.text() };
}

describe("device authorization grant (RFC 8628)", () => {
  it("issues codes, paces polling, and delivers tokens once approved", async () => {
    const { upn, clientId } = await setup({ client_type: "public" });
    const auth = await deviceAuthorize(clientId);
    expect(auth.status).toBe(200);
    expect(auth.body.device_code).toBeTruthy();
    expect(String(auth.body.user_code)).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(auth.body.verification_uri).toBe(`${BASE}/device`);
    expect(String(auth.body.verification_uri_complete)).toContain("user_code=");

    const deviceCode = String(auth.body.device_code);
    const userCode = String(auth.body.user_code);

    // First poll: pending. A too-fast second poll earns slow_down.
    expect((await poll(clientId, deviceCode)).body.error).toBe("authorization_pending");
    expect((await poll(clientId, deviceCode)).body.error).toBe("slow_down");

    // Approving needs a signed-in browser; the code entry redirects to login.
    const anon = await SELF.fetch(`${BASE}/device?user_code=${userCode}`, { redirect: "manual" });
    expect(anon.status).toBe(302);
    expect(anon.headers.get("Location")).toContain("/login?next=");

    const cookie = await signIn(upn, `/device?user_code=${userCode}`);
    expect(cookie).toContain("__Host-flareid_session");
    const approved = await decide(cookie, userCode, "approve");
    expect(approved.status).toBe(200);
    expect(approved.body).toContain("Device connected");

    const tokens = await poll(clientId, deviceCode);
    expect(tokens.status).toBe(200);
    expect(tokens.body.access_token).toBeTruthy();
    const idClaims = decodeJwt(tokens.body.id_token!);
    expect(idClaims.aud).toBe(clientId);
    expect(idClaims.email).toBe(upn);

    // Approved codes are single-use.
    expect((await poll(clientId, deviceCode)).body.error).toBe("invalid_grant");
  });

  it("denied codes answer access_denied once, then are gone", async () => {
    const { upn, clientId } = await setup({ client_type: "public" });
    const auth = await deviceAuthorize(clientId);
    const cookie = await signIn(upn, `/device?user_code=${auth.body.user_code}`);

    const denied = await decide(cookie, String(auth.body.user_code), "deny");
    expect(denied.body).toContain("Access denied");

    expect((await poll(clientId, String(auth.body.device_code))).body.error).toBe("access_denied");
    expect((await poll(clientId, String(auth.body.device_code))).body.error).toBe("invalid_grant");
  });

  it("expired codes answer expired_token", async () => {
    const { clientId } = await setup({ client_type: "public" });
    const auth = await deviceAuthorize(clientId);
    const deviceCode = String(auth.body.device_code);
    const past = new Date(Date.now() - 60_000).toISOString();
    await env.DB.prepare("UPDATE device_codes SET expires_at = ?").bind(past).run();
    expect((await poll(clientId, deviceCode)).body.error).toBe("expired_token");
  });

  it("rejects unknown codes, wrong clients, and unknown user_codes", async () => {
    const { apiKey, clientId } = await setup({ client_type: "public" });
    const other = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Other", client_type: "public", redirect_uris: ["https://app.test/cb"] } });
    const auth = await deviceAuthorize(clientId);

    expect((await poll(String(other.body.client_id), String(auth.body.device_code))).body.error).toBe("invalid_grant");
    expect((await poll(clientId, "not-a-code")).body.error).toBe("invalid_grant");

    const page = await SELF.fetch(`${BASE}/device?user_code=ZZZZ-ZZZZ`);
    expect((await page.text()).toLowerCase()).toContain("valid");
  });
});

describe("client_credentials grant", () => {
  it("mints a service JWT for a confidential client, verifiable via JWKS", async () => {
    const { apiKey, clientId, clientSecret } = await setup();
    const res = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret!,
        scope: "report:read report:write",
        audience: "https://api.internal",
      }).toString(),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("report:read report:write");

    const claims = decodeJwt(String(body.access_token));
    expect(claims.iss).toBe(BASE);
    expect(claims.sub).toBe(clientId);
    expect(claims.aud).toBe("https://api.internal");
    expect((claims as Record<string, unknown>).client_id).toBe(clientId);

    // Introspection answers from the signature - no server-side record exists.
    const introspect = await SELF.fetch(`${BASE}/introspect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: String(body.access_token), client_id: clientId, client_secret: clientSecret! }).toString(),
    });
    const info = (await introspect.json()) as Record<string, unknown>;
    expect(info.active).toBe(true);
    expect(info.scope).toBe("report:read report:write");

    // Another client cannot introspect a token that is not theirs.
    const other = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Other", redirect_uris: ["https://app.test/cb"] } });
    const foreign = await SELF.fetch(`${BASE}/introspect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: String(body.access_token), client_id: String(other.body.client_id), client_secret: String(other.body.client_secret) }).toString(),
    });
    expect(((await foreign.json()) as { active: boolean }).active).toBe(false);
  });

  it("refuses public clients and bad secrets", async () => {
    const { apiKey, clientId, clientSecret } = await setup();
    const pub = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "CLI", client_type: "public", redirect_uris: ["https://app.test/cb"] } });

    const publicClient = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: String(pub.body.client_id) }).toString(),
    });
    expect(((await publicClient.json()) as { error: string }).error).toBe("unauthorized_client");

    const badSecret = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: "wrong" }).toString(),
    });
    expect(badSecret.status).toBe(401);
  });
});

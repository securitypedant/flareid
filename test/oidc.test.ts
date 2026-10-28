import { SELF } from "cloudflare:test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const REDIRECT_URI = "https://rp.test/callback";
const USER_PASSWORD = "a-test-user-password-1";

/** A client, a user who can sign in, and the credentials to drive both. */
async function seedRelyingParty(): Promise<{ clientId: string; clientSecret: string; upn: string }> {
  const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });

  const client = await apiCall("/api/v1/clients", {
    token: apiKey,
    body: { name: "Test RP", redirect_uris: [REDIRECT_URI] },
  });

  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      users: [
        {
          username: "ada.kowalski",
          given_name: "Ada",
          family_name: "Kowalski",
          job_title: "Chief Executive Officer",
          department: "Executive",
          password: USER_PASSWORD,
          groups: ["All Employees", "Executives"],
        },
      ],
    },
  });

  return {
    clientId: client.body.client_id as string,
    clientSecret: client.body.client_secret as string,
    upn: `ada.kowalski@${domain}`,
  };
}

/** base64url of a SHA-256 digest - the S256 PKCE challenge. */
async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Drives the browser half of the flow and returns the authorization code.
 *
 * The login form carries a flow_id identifying the pending OIDC request, which
 * is why this has to scrape it: there is no other way for the POST to say which
 * authorization it is completing.
 */
async function authorizeAndLogin(params: {
  clientId: string;
  upn: string;
  password?: string;
  codeChallenge?: string;
  state?: string;
  nonce?: string;
}): Promise<{ code: string | null; location: string | null; state: string | null }> {
  const query = new URLSearchParams({
    client_id: params.clientId,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile groups",
    ...(params.state ? { state: params.state } : {}),
    ...(params.nonce ? { nonce: params.nonce } : {}),
    ...(params.codeChallenge ? { code_challenge: params.codeChallenge, code_challenge_method: "S256" } : {}),
  });

  const page = await SELF.fetch(`${BASE}/authorize?${query}`, { redirect: "manual" });
  const html = await page.text();
  const flowId = /name="flow_id" value="([^"]*)"/.exec(html)?.[1];
  if (!flowId) throw new Error(`no login form at /authorize (HTTP ${page.status}): ${html.slice(0, 300)}`);

  const form = new URLSearchParams({
    flow_id: flowId,
    upn: params.upn,
    password: params.password ?? USER_PASSWORD,
  });

  const submitted = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
    redirect: "manual",
  });

  const location = submitted.headers.get("Location");
  if (!location) return { code: null, location: null, state: null };
  const url = new URL(location, BASE);
  return { code: url.searchParams.get("code"), location, state: url.searchParams.get("state") };
}

async function exchangeCode(params: {
  code: string;
  clientId: string;
  clientSecret: string;
  codeVerifier?: string;
  scope?: string;
}): Promise<{ status: number; body: any }> {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: REDIRECT_URI,
    client_id: params.clientId,
    client_secret: params.clientSecret,
    ...(params.codeVerifier ? { code_verifier: params.codeVerifier } : {}),
  });

  const response = await SELF.fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  return { status: response.status, body: await response.json() };
}

describe("discovery", () => {
  it("publishes a discovery document whose endpoints all share the issuer", async () => {
    const response = await SELF.fetch(`${BASE}/.well-known/openid-configuration`);
    const doc = (await response.json()) as Record<string, string>;

    expect(response.status).toBe(200);
    expect(doc.issuer).toBe("https://idp.test");
    for (const key of [
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri",
      "introspection_endpoint",
      "revocation_endpoint",
    ]) {
      expect(doc[key], key).toMatch(/^https:\/\/idp\.test\//);
    }
  });

  it("publishes a usable key set", async () => {
    const response = await SELF.fetch(`${BASE}/jwks.json`);
    const jwks = (await response.json()) as { keys: Record<string, unknown>[] };

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: "RSA", use: "sig", alg: "RS256", kid: "flareid-test-key" });
    // Never the private half.
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });
});

describe("authorization code flow", () => {
  it("issues a code, exchanges it, and the id_token verifies against the published keys", async () => {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const verifier = "a-code-verifier-long-enough-to-be-realistic";

    const { code, state } = await authorizeAndLogin({
      clientId,
      upn,
      codeChallenge: await s256(verifier),
      state: "opaque-state",
      nonce: "a-nonce",
    });
    expect(code).toBeTruthy();
    expect(state).toBe("opaque-state");

    const { status, body } = await exchangeCode({ code: code!, clientId, clientSecret, codeVerifier: verifier });
    expect(status).toBe(200);
    expect(body.token_type).toBe("Bearer");
    expect(body.id_token).toBeTypeOf("string");

    const jwksResponse = await SELF.fetch(`${BASE}/jwks.json`);
    const jwks = createLocalJWKSet((await jwksResponse.json()) as any);
    const { payload, protectedHeader } = await jwtVerify(body.id_token, jwks, {
      issuer: "https://idp.test",
      audience: clientId,
    });

    expect(protectedHeader.alg).toBe("RS256");
    expect(payload.email).toBe(upn);
    expect(payload.name).toBe("Ada Kowalski");
    expect(payload.given_name).toBe("Ada");
    expect(payload.groups).toEqual(expect.arrayContaining(["All Employees", "Executives"]));
    expect(payload.job_title).toBe("Chief Executive Officer");
    expect(payload.amr).toEqual(["pwd"]);
    expect(payload.nonce).toBe("a-nonce");
  });

  it("rejects an authorization code the second time it is presented", async () => {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn });

    const first = await exchangeCode({ code: code!, clientId, clientSecret });
    expect(first.status).toBe(200);

    const second = await exchangeCode({ code: code!, clientId, clientSecret });
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("invalid_grant");
  });

  it("rejects a bad PKCE verifier", async () => {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn, codeChallenge: await s256("the-real-verifier") });

    const { status, body } = await exchangeCode({
      code: code!,
      clientId,
      clientSecret,
      codeVerifier: "not-the-real-verifier",
    });

    expect(status).toBe(400);
    expect(body.error_description).toMatch(/PKCE/);
  });

  it("rejects a missing PKCE verifier when the code carried a challenge", async () => {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn, codeChallenge: await s256("the-real-verifier") });

    const { status, body } = await exchangeCode({ code: code!, clientId, clientSecret });
    expect(status).toBe(400);
    expect(body.error_description).toMatch(/code_verifier/);
  });

  it("rejects the wrong client secret", async () => {
    const { clientId, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn });

    const { status, body } = await exchangeCode({ code: code!, clientId, clientSecret: "wrong-secret" });
    expect(status).toBe(401);
    expect(body.error).toBe("invalid_client");
  });

  it("refuses an unregistered redirect_uri", async () => {
    const { clientId } = await seedRelyingParty();
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: "https://attacker.test/callback",
      response_type: "code",
      scope: "openid",
    });

    const response = await SELF.fetch(`${BASE}/authorize?${query}`, { redirect: "manual" });
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/not registered/);
  });

  it("refuses an unknown client", async () => {
    await seedRelyingParty();
    const query = new URLSearchParams({
      client_id: "flareid_nosuchclient",
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
    });

    const response = await SELF.fetch(`${BASE}/authorize?${query}`, { redirect: "manual" });
    expect(response.status).toBe(400);
  });

  it("does not issue a code for the wrong password", async () => {
    const { clientId, upn } = await seedRelyingParty();
    const { code, location } = await authorizeAndLogin({ clientId, upn, password: "wrong" });

    expect(code).toBeNull();
    expect(location).toBeNull();
  });

  it("does not issue a code for a disabled account", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const client = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: { name: "Test RP", redirect_uris: [REDIRECT_URI] },
    });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: {
        version: 1,
        users: [{ username: "gone", given_name: "Gone", password: USER_PASSWORD, status: "disabled" }],
      },
    });

    const { code } = await authorizeAndLogin({ clientId: client.body.client_id, upn: "gone@horizon.test" });
    expect(code).toBeNull();
  });
});

describe("userinfo", () => {
  it("returns the same claims as the id_token for a valid access token", async () => {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn });
    const { body } = await exchangeCode({ code: code!, clientId, clientSecret });

    const response = await SELF.fetch(`${BASE}/userinfo`, {
      headers: { Authorization: `Bearer ${body.access_token}` },
    });
    const claims = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(claims.email).toBe(upn);
    expect(claims.groups).toEqual(expect.arrayContaining(["All Employees"]));
  });

  it("refuses an unknown access token", async () => {
    const response = await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: "Bearer nope" } });
    expect(response.status).toBe(401);
  });

  it("refuses a request with no token at all", async () => {
    const response = await SELF.fetch(`${BASE}/userinfo`);
    expect(response.status).toBe(401);
  });
});

describe("introspection and revocation", () => {
  async function tokens() {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn });
    const { body } = await exchangeCode({ code: code!, clientId, clientSecret });
    return { clientId, clientSecret, upn, ...body };
  }

  async function introspect(token: string, clientId: string, clientSecret: string) {
    const response = await SELF.fetch(`${BASE}/introspect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token, client_id: clientId, client_secret: clientSecret }).toString(),
    });
    return (await response.json()) as { active: boolean; sub?: string };
  }

  it("reports a live access token as active", async () => {
    const { access_token, clientId, clientSecret } = await tokens();
    const result = await introspect(access_token, clientId, clientSecret);
    expect(result.active).toBe(true);
  });

  it("reports an unknown token as inactive rather than erroring", async () => {
    const { clientId, clientSecret } = await tokens();
    const result = await introspect("not-a-token", clientId, clientSecret);
    expect(result.active).toBe(false);
  });

  it("stops honouring a revoked access token", async () => {
    const { access_token, clientId, clientSecret } = await tokens();

    const revoked = await SELF.fetch(`${BASE}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: access_token, client_id: clientId, client_secret: clientSecret }).toString(),
    });
    expect(revoked.status).toBe(200);

    const after = await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${access_token}` } });
    expect(after.status).toBe(401);
  });
});

describe("refresh grant", () => {
  it("issues a refresh token only when offline_access is asked for", async () => {
    const { clientId, clientSecret, upn } = await seedRelyingParty();
    const { code } = await authorizeAndLogin({ clientId, upn });
    const { body } = await exchangeCode({ code: code!, clientId, clientSecret });

    // The seeded scope does not include offline_access, so there should be no
    // refresh token to hand out.
    expect(body.refresh_token).toBeUndefined();
  });
});

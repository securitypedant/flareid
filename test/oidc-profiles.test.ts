import { beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { sha256Hex } from "../src/lib/tokens.js";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

beforeEach(async () => {
  await resetDatabase();
});

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const REDIRECT = "https://rp.example/cb";

async function sessionFor(userId: number): Promise<string> {
  const { setCookie } = await createSession(env, userId, ["pwd", "mfa"], new Request(BASE));
  return setCookie.split(";")[0]!;
}

async function seedUser(apiKey: string, username = "ada"): Promise<number> {
  const res = await apiCall("/api/v1/users", { token: apiKey, body: { username, given_name: "Ada", family_name: "Chen", password: "user-password-123", status: "active" } });
  if (res.status !== 201) throw new Error(`user create failed: ${JSON.stringify(res.body)}`);
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

async function seedClient(apiKey: string, extra: Record<string, unknown> = {}): Promise<{ client_id: string; client_secret: string }> {
  const res = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "rp", redirect_uris: [REDIRECT], trusted: true, ...extra } });
  if (res.status !== 200) throw new Error(`client create failed: ${JSON.stringify(res.body)}`);
  return res.body as { client_id: string; client_secret: string };
}

async function authorize(cookie: string, clientId: string, extra: Record<string, string> = {}): Promise<Response> {
  const params = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, scope: "openid", state: "s1", ...extra });
  return SELF.fetch(`${BASE}/authorize?${params}`, { headers: { Cookie: cookie }, redirect: "manual" });
}

describe("OIDC claims: address and phone", () => {
  it("releases address and phone_number from schema attributes when the scope asks", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    await env.DB.prepare("UPDATE users SET custom_attributes = ? WHERE id = ?")
      .bind(JSON.stringify({ street_address: "12 Normandy Ave", locality: "Cambridge", postal_code: "CB3", country: "GB", phone_number: "+44 1223 000000" }), userId)
      .run();
    const client = await seedClient(apiKey);

    const token = `at-${crypto.randomUUID()}`;
    await env.DB.prepare("INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at, amr) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(await sha256Hex(token), client.client_id, userId, "openid address phone", new Date(Date.now() + 600_000).toISOString(), '["pwd"]')
      .run();

    const res = await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${token}` } });
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(body.address).toMatchObject({ street_address: "12 Normandy Ave", locality: "Cambridge", postal_code: "CB3", country: "GB" });
    expect(body.phone_number).toBe("+44 1223 000000");
  });

  it("omits the claims when the scope doesn't ask, but lets the raw attributes through custom", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    await env.DB.prepare("UPDATE users SET custom_attributes = ? WHERE id = ?")
      .bind(JSON.stringify({ phone_number: "+1 555 0100", favorite_color: "blue" }), userId)
      .run();
    const client = await seedClient(apiKey);

    const token = `at-${crypto.randomUUID()}`;
    await env.DB.prepare("INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at, amr) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(await sha256Hex(token), client.client_id, userId, "openid profile", new Date(Date.now() + 600_000).toISOString(), '["pwd"]')
      .run();

    const body = (await (await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${token}` } })).json()) as Record<string, unknown>;
    expect(body.phone_number).toBeUndefined();
    expect(body.address).toBeUndefined();
    // The component names are ordinary user attributes: custom passes them
    // through untouched; only the assembled claim names are withheld.
    expect((body.custom as Record<string, unknown>)?.phone_number).toBe("+1 555 0100");
    expect((body.custom as Record<string, unknown>)?.favorite_color).toBe("blue");
  });

  it("advertises the new scopes in the discovery document", async () => {
    await bootstrapInstance();
    const disco = (await (await SELF.fetch(`${BASE}/.well-known/openid-configuration`)).json()) as { scopes_supported: string[]; response_modes_supported: string[]; claims_supported: string[] };
    expect(disco.scopes_supported).toEqual(expect.arrayContaining(["address", "phone"]));
    expect(disco.response_modes_supported).toContain("form_post");
    expect(disco.claims_supported).toEqual(expect.arrayContaining(["address", "phone_number"]));
  });
});

describe("response_mode=form_post", () => {
  it("answers authorization with an auto-submitting POST form", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const client = await seedClient(apiKey);

    const res = await authorize(cookie, client.client_id, { response_mode: "form_post", scope: "openid email" });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`method="POST"`);
    expect(html).toContain(`action="${REDIRECT}"`);
    expect(html).toMatch(/name="code" value="[^"]+"/);
    expect(html).toContain('name="state" value="s1"');
    expect(html).toContain('name="session_state"');
  });

  it("delivers errors by POST too, and rejects unknown modes", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const client = await seedClient(apiKey);

    // prompt=none with a fresh session is fine, so provoke an error instead:
    // a made-up scope check won't fail, but an unsigned request object does.
    const res = await authorize(cookie, client.client_id, { response_mode: "form_post", request: "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ." });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`action="${REDIRECT}"`);
    expect(html).toContain('name="error" value="request_not_supported"');

    const bad = await authorize(cookie, client.client_id, { response_mode: "fragment" });
    expect(bad.status).toBe(302);
    expect(new URL(bad.headers.get("location")!).searchParams.get("error")).toBe("invalid_request");
  });
});

describe("session management", () => {
  it("puts session_state on the authorization response", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const client = await seedClient(apiKey);

    const res = await authorize(cookie, client.client_id);
    const state = new URL(res.headers.get("location")!).searchParams.get("session_state");
    expect(state).toMatch(/^[0-9a-f]{64}\..+/);
  });

  it("serves a frameable check_session endpoint", async () => {
    await bootstrapInstance();
    const res = await SELF.fetch(`${BASE}/check_session`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("postMessage");
    expect(res.headers.get("x-frame-options")).toBeNull();
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors *");
  });
});

describe("third-party initiated login", () => {
  it("starts an authorization for a client that opted in", async () => {
    const { apiKey } = await bootstrapInstance();
    const client = await seedClient(apiKey);
    await env.DB.prepare("UPDATE oauth_clients SET initiate_login_uri = ? WHERE client_id = ?").bind("https://op.example/init", client.client_id).run();

    const res = await SELF.fetch(`${BASE}/oidc/init-login?iss=${client.client_id}&login_hint=ada%40example.com`, { redirect: "manual" });
    expect(res.status).toBe(302);
    const dest = new URL(res.headers.get("location")!, BASE);
    expect(dest.pathname).toBe("/authorize");
    expect(dest.searchParams.get("client_id")).toBe(client.client_id);
    expect(dest.searchParams.get("redirect_uri")).toBe(REDIRECT);
    expect(dest.searchParams.get("login_hint")).toBe("ada@example.com");
  });

  it("refuses clients that did not opt in", async () => {
    const { apiKey } = await bootstrapInstance();
    const client = await seedClient(apiKey);
    const res = await SELF.fetch(`${BASE}/oidc/init-login?iss=${client.client_id}`);
    expect(res.status).toBe(400);
  });
});

describe("back-channel logout", () => {
  it("posts a logout_token to registered URIs when the session is revoked", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const client = await seedClient(apiKey, { frontchannel_logout_uri: "https://rp.example/fcl" });
    await env.DB.prepare("UPDATE oauth_clients SET backchannel_logout_uri = ? WHERE client_id = ?").bind("https://rp.example/bcl", client.client_id).run();

    const { sessionId } = await createSession(env, userId, ["pwd"], new Request(BASE));
    await env.DB.prepare("INSERT INTO session_clients (session_id, client_id, created_at) VALUES (?, ?, ?)").bind(sessionId, client.client_id, new Date().toISOString()).run();

    const posts: { uri: string; body: string }[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      posts.push({ uri: String(input), body: String(init?.body ?? "") });
      return new Response(null, { status: 200 });
    });
    try {
      const { revokeSession } = await import("../src/lib/sessions.js");
      await revokeSession(env, sessionId);
    } finally {
      vi.unstubAllGlobals();
    }

    expect(posts).toHaveLength(1);
    expect(posts[0]!.uri).toBe("https://rp.example/bcl");
    const token = new URLSearchParams(posts[0]!.body).get("logout_token")!;
    const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
    expect(payload.iss).toBe(BASE);
    expect(payload.aud).toBe(client.client_id);
    expect(payload.events["http://schemas.openid.net/event/backchannel-logout"]).toBeDefined();
    expect(payload.sid).toBeTruthy();
    expect(payload.nonce).toBeUndefined();
  });
});

describe("dynamic client registration (RFC 7591/7592)", () => {
  it("registers, reads, updates and deletes a client", async () => {
    await bootstrapInstance();
    const created = (await (
      await SELF.fetch(`${BASE}/connect/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_name: "dyn", redirect_uris: [REDIRECT], backchannel_logout_uri: "https://rp.example/bcl" }),
      })
    ).json()) as Record<string, unknown>;

    expect(created.client_id).toMatch(/^flareid_/);
    expect(created.client_secret).toBeTruthy();
    expect(created.registration_access_token).toBeTruthy();
    expect(created.token_endpoint_auth_method).toBe("client_secret_basic");
    expect(created.backchannel_logout_uri).toBe("https://rp.example/bcl");

    const read = await SELF.fetch(`${BASE}/connect/register/${created.client_id}`, { headers: { Authorization: `Bearer ${created.registration_access_token}` } });
    expect(read.status).toBe(200);
    expect(((await read.json()) as Record<string, unknown>).client_secret).toBeUndefined();

    const noAuth = await SELF.fetch(`${BASE}/connect/register/${created.client_id}`);
    expect(noAuth.status).toBe(401);

    const updated = await SELF.fetch(`${BASE}/connect/register/${created.client_id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${created.registration_access_token}` },
      body: JSON.stringify({ client_name: "renamed" }),
    });
    expect(((await updated.json()) as Record<string, unknown>).client_name).toBe("renamed");

    const del = await SELF.fetch(`${BASE}/connect/register/${created.client_id}`, { method: "DELETE", headers: { Authorization: `Bearer ${created.registration_access_token}` } });
    expect(del.status).toBe(204);
    expect(await env.DB.prepare("SELECT 1 FROM oauth_clients WHERE client_id = ?").bind(created.client_id).first()).toBeNull();
  });

  it("rejects bad metadata and registers untrusted so consent shows", async () => {
    await bootstrapInstance();
    const bad = await SELF.fetch(`${BASE}/connect/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "x" }),
    });
    expect(bad.status).toBe(400);

    const ok = await SELF.fetch(`${BASE}/connect/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT] }),
    });
    expect(ok.status).toBe(201);
    const { client_id } = (await ok.json()) as { client_id: string };
    const row = await env.DB.prepare("SELECT trusted FROM oauth_clients WHERE client_id = ?").bind(client_id).first<{ trusted: number }>();
    expect(row!.trusted).toBe(0);
  });
});

describe("private_key_jwt client authentication", () => {
  it("accepts a valid client assertion at /token", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);

    const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1" };
    const client = await seedClient(apiKey);
    await env.DB.prepare("UPDATE oauth_clients SET jwks = ? WHERE client_id = ?").bind(JSON.stringify({ keys: [jwk] }), client.client_id).run();

    const code = new URL((await authorize(cookie, client.client_id)).headers.get("location")!, BASE).searchParams.get("code")!;
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: jwk.kid ?? "k1" })
      .setIssuer(client.client_id)
      .setSubject(client.client_id)
      .setAudience(`${BASE}/token`)
      .setIssuedAt()
      .setExpirationTime("5m")
      .setJti(crypto.randomUUID())
      .sign(privateKey);

    const res = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: client.client_id,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      }).toString(),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.id_token).toBeTruthy();
  });

  it("rejects an assertion signed by an unknown key", async () => {
    const { apiKey } = await bootstrapInstance();
    const client = await seedClient(apiKey);
    const { publicKey } = await generateKeyPair("RS256", { extractable: true });
    await env.DB.prepare("UPDATE oauth_clients SET jwks = ? WHERE client_id = ?").bind(JSON.stringify({ keys: [await exportJWK(publicKey)] }), client.client_id).run();

    const wrongKey = (await generateKeyPair("RS256", { extractable: true })).privateKey;
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(client.client_id)
      .setSubject(client.client_id)
      .setAudience(`${BASE}/token`)
      .setIssuedAt()
      .setExpirationTime("5m")
      .setJti(crypto.randomUUID())
      .sign(wrongKey);

    const res = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "anything",
        client_id: client.client_id,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      }).toString(),
    });
    expect(res.status).toBe(401);
  });
});

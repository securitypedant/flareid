import { beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession, revokeSession } from "../src/lib/sessions.js";
import { CHECK_SESSION_SHA256_JS } from "../src/routes/oidc-session.js";
import { sha256Hex } from "../src/lib/tokens.js";
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";

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
    // an unsigned request object is refused (RFC 9101: we only take signed ones).
    const res = await authorize(cookie, client.client_id, { response_mode: "form_post", request: "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ." });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`action="${REDIRECT}"`);
    expect(html).toContain('name="error" value="invalid_request_object"');

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

  it("marks the session via a SameSite=None cookie so the iframe can see it cross-origin", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const { setCookies } = await createSession(env, userId, ["pwd", "mfa"], new Request(BASE));
    const sessionCookie = setCookies[0].split(";")[0]!;
    const marker = setCookies[1].split(";")[0]!;
    expect(setCookies[0]).toContain("SameSite=Lax");
    expect(setCookies[1]).toContain("SameSite=None");

    const client = await seedClient(apiKey);
    const res = await authorize(sessionCookie, client.client_id);
    const state = new URL(res.headers.get("location")!).searchParams.get("session_state")!;

    // Inside the iframe on the RP's origin, the Lax session cookie is withheld
    // and only the marker arrives - /check_session must still answer "unchanged".
    const cs = await SELF.fetch(`${BASE}/check_session`, { headers: { Cookie: marker } });
    const sid = (await cs.text()).match(/data-sid="([^"]*)"/)?.[1];
    expect(sid).toBeTruthy();

    // Recompute the comparison the iframe JS performs (OIDC Session Mgmt 1.0 §4.2).
    const [hash, salt] = state.split(".");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${client.client_id} ${new URL(REDIRECT).origin} ${sid} ${salt}`));
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(hash);
  });

  it("answers changed once the session behind the marker is gone server-side", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const { sessionId, setCookies } = await createSession(env, userId, ["pwd"], new Request(BASE));
    const marker = setCookies[1].split(";")[0]!;

    // A live session still answers through the marker.
    const live = await SELF.fetch(`${BASE}/check_session`, { headers: { Cookie: marker } });
    expect((await live.text()).match(/data-sid="([^"]*)"/)?.[1]).toBeTruthy();

    // Revocation the browser cannot observe (admin sign-out, password change,
    // SSF) leaves the cookie in place - the iframe must answer "changed"
    // anyway, which an empty data-sid produces.
    await revokeSession(env, sessionId);
    const dead = await SELF.fetch(`${BASE}/check_session`, { headers: { Cookie: marker } });
    expect((await dead.text()).match(/data-sid="([^"]*)"/)?.[1]).toBe("");

    // A row minted before the oidc_sid column (NULL) cannot be verified either.
    await env.DB.prepare("UPDATE sessions SET oidc_sid = NULL, revoked_at = NULL WHERE id = ?").bind(sessionId).run();
    const legacy = await SELF.fetch(`${BASE}/check_session`, { headers: { Cookie: marker } });
    expect((await legacy.text()).match(/data-sid="([^"]*)"/)?.[1]).toBe("");
  });

  it("ships a self-contained sha256 in the check_session page", async () => {
    // The iframe JS can't rely on WebCrypto - conformance clients run in
    // headless browsers whose crypto.subtle rejects digest calls - so the
    // page carries a synchronous implementation.
    await bootstrapInstance();
    const html = await (await SELF.fetch(`${BASE}/check_session`)).text();
    expect(html).toContain("function sha256");
    expect(html).not.toContain("crypto.subtle");
    expect(CHECK_SESSION_SHA256_JS).toContain("function sha256");
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

  it("delivers the back-channel POST on the console sign-out path too (POST /logout)", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const client = await seedClient(apiKey, { frontchannel_logout_uri: "https://rp.example/fcl" });
    await env.DB.prepare("UPDATE oauth_clients SET backchannel_logout_uri = ? WHERE client_id = ?").bind("https://rp.example/bcl", client.client_id).run();

    const { sessionId, setCookie } = await createSession(env, userId, ["pwd"], new Request(BASE));
    await env.DB.prepare("INSERT INTO session_clients (session_id, client_id, created_at) VALUES (?, ?, ?)").bind(sessionId, client.client_id, new Date().toISOString()).run();

    const posts: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      posts.push(String(input));
      return new Response(null, { status: 200 });
    });
    try {
      const out = await SELF.fetch(`${BASE}/logout`, { method: "POST", headers: { ...FORM, Cookie: setCookie.split(";")[0]! } });
      expect(out.status).toBe(200); // the front-channel iframe page
    } finally {
      vi.unstubAllGlobals();
    }

    // Ordering regression: frontchannelTargets used to run first and delete
    // the session_clients rows, so revokeSession's fan-out found nothing.
    expect(posts).toEqual(["https://rp.example/bcl"]);
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

  it("rejects a redirect_uri with a fragment (OIDC Core 3.1.2.1)", async () => {
    await bootstrapInstance();
    const res = await SELF.fetch(`${BASE}/connect/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [`${REDIRECT}#frag`] }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as Record<string, unknown>).error).toBe("invalid_client_metadata");
  });

  it("keeps and echoes display metadata, and shows it on the sign-in page", async () => {
    await bootstrapInstance();
    const meta = {
      logo_uri: "https://rp.example/logo.png",
      policy_uri: "https://rp.example/privacy",
      tos_uri: "https://rp.example/terms",
      client_uri: "https://rp.example/",
    };
    const created = (await (
      await SELF.fetch(`${BASE}/connect/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_name: "display rp", redirect_uris: [REDIRECT], ...meta }),
      })
    ).json()) as Record<string, unknown>;
    for (const [k, v] of Object.entries(meta)) expect(created[k]).toBe(v);

    const read = (await (
      await SELF.fetch(`${BASE}/connect/register/${created.client_id}`, { headers: { Authorization: `Bearer ${created.registration_access_token}` } })
    ).json()) as Record<string, unknown>;
    for (const [k, v] of Object.entries(meta)) expect(read[k]).toBe(v);

    const updated = (await (
      await SELF.fetch(`${BASE}/connect/register/${created.client_id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${created.registration_access_token}` },
        body: JSON.stringify({ redirect_uris: [REDIRECT], tos_uri: "https://rp.example/terms-v2", logo_uri: "" }),
      })
    ).json()) as Record<string, unknown>;
    expect(updated.tos_uri).toBe("https://rp.example/terms-v2");
    expect(updated.logo_uri).toBeUndefined();
    expect(updated.policy_uri).toBe(meta.policy_uri);

    const bad = await SELF.fetch(`${BASE}/connect/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT], logo_uri: "javascript:alert(1)" }),
    });
    expect(bad.status).toBe(400);

    // The sign-in page names the app, shows its logo and links its documents.
    const page = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: updated.client_id as string, redirect_uri: REDIRECT, response_type: "code", scope: "openid" })}`, { redirect: "manual" });
    const html = await page.text();
    expect(page.status).toBe(200);
    expect(html).toContain("display rp");
    expect(html).toContain(`href="${meta.policy_uri}"`);
    expect(html).toContain(`href="https://rp.example/terms-v2"`);
    expect(html).toContain(`href="${meta.client_uri}"`);
    expect(html).not.toContain('class="auth-client-logo"');

    const withLogo = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: created.client_id as string, redirect_uri: REDIRECT, response_type: "code", scope: "openid" })}`, { redirect: "manual" });
    // The PUT cleared the logo; re-set it to see the img and its CSP allowance.
    await env.DB.prepare("UPDATE oauth_clients SET logo_uri = ? WHERE client_id = ?").bind(meta.logo_uri, created.client_id as string).run();
    const withLogo2 = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: created.client_id as string, redirect_uri: REDIRECT, response_type: "code", scope: "openid" })}`, { redirect: "manual" });
    const html2 = await withLogo2.text();
    expect(html2).toContain(`src="${meta.logo_uri}"`);
    expect(withLogo2.headers.get("Content-Security-Policy")).toContain(`img-src 'self' data: ${meta.logo_uri}`);
    expect(withLogo.headers.get("Content-Security-Policy")).toContain("img-src 'self' data:");
    expect(withLogo.headers.get("Content-Security-Policy")).not.toContain(meta.logo_uri);
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

  it("requires exp/iat/jti and refuses a replayed jti (RFC 7523)", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1" };
    const client = await seedClient(apiKey);
    await env.DB.prepare("UPDATE oauth_clients SET jwks = ? WHERE client_id = ?").bind(JSON.stringify({ keys: [jwk] }), client.client_id).run();

    const token = (assertion: string, code: string) =>
      SELF.fetch(`${BASE}/token`, {
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
    const code = async () => new URL((await authorize(cookie, client.client_id)).headers.get("location")!, BASE).searchParams.get("code")!;

    // No exp: an assertion that never expires is refused outright.
    const timeless = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(client.client_id).setSubject(client.client_id)
      .setAudience(`${BASE}/token`).setIssuedAt().setJti(crypto.randomUUID())
      .sign(privateKey);
    expect((await token(timeless, await code())).status).toBe(401);

    // A valid assertion redeems once; the same jti a second time is a replay.
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(client.client_id).setSubject(client.client_id)
      .setAudience(`${BASE}/token`).setIssuedAt().setExpirationTime("5m").setJti(crypto.randomUUID())
      .sign(privateKey);
    expect((await token(assertion, await code())).status).toBe(200);
    expect((await token(assertion, await code())).status).toBe(401);
  });

  it("identifies the client from the assertion iss when client_id is omitted (RFC 7523)", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1" };
    const client = await seedClient(apiKey);
    await env.DB.prepare("UPDATE oauth_clients SET jwks = ? WHERE client_id = ?").bind(JSON.stringify({ keys: [jwk] }), client.client_id).run();

    const code = new URL((await authorize(cookie, client.client_id)).headers.get("location")!, BASE).searchParams.get("code")!;
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(client.client_id).setSubject(client.client_id)
      .setAudience(`${BASE}/token`).setIssuedAt().setExpirationTime("5m").setJti(crypto.randomUUID())
      .sign(privateKey);

    // No client_id in the body: the OIDF suite sends assertions this way.
    const res = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      }).toString(),
    });
    expect(res.status, JSON.stringify(await res.json())).toBe(200);

    // An iss that does not name a registered client still fails closed.
    const stranger = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer("no-such-client").setSubject("no-such-client")
      .setAudience(`${BASE}/token`).setIssuedAt().setExpirationTime("5m").setJti(crypto.randomUUID())
      .sign(privateKey);
    const bad = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "anything",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: stranger,
      }).toString(),
    });
    expect(bad.status).toBe(401);
  });
});

async function registerDynamic(body: Record<string, unknown>): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await SELF.fetch(`${BASE}/connect/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

describe("signed userinfo (OIDC Core 5.3.2.4)", () => {
  it("answers application/jwt when the client registered userinfo_signed_response_alg", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const { json: client } = await registerDynamic({ redirect_uris: [REDIRECT], userinfo_signed_response_alg: "RS256" });
    expect(client.userinfo_signed_response_alg).toBe("RS256");

    const token = `at-${crypto.randomUUID()}`;
    await env.DB.prepare("INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at, amr) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(await sha256Hex(token), client.client_id, userId, "openid profile", new Date(Date.now() + 600_000).toISOString(), '["pwd"]')
      .run();

    const res = await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/jwt");
    const jwt = await res.text();

    const { keys } = (await (await SELF.fetch(`${BASE}/jwks.json`)).json()) as { keys: object[] };
    const { payload } = await jwtVerify(jwt, createLocalJWKSet({ keys: keys as never[] }));
    expect(payload.iss).toBe(BASE);
    expect(payload.aud).toBe(client.client_id);
    expect(payload.sub).toBe(String(userId));
  });

  it("still answers JSON when the client registered none, and validates the field at DCR", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const client = await seedClient(apiKey);

    const token = `at-${crypto.randomUUID()}`;
    await env.DB.prepare("INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at, amr) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(await sha256Hex(token), client.client_id, userId, "openid", new Date(Date.now() + 600_000).toISOString(), '["pwd"]')
      .run();
    const res = await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.headers.get("content-type")).toContain("application/json");

    const bad = await registerDynamic({ redirect_uris: [REDIRECT], userinfo_signed_response_alg: "HS256" });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toBe("invalid_client_metadata");
  });
});

describe("pairwise subjects (OIDC Core 8)", () => {
  async function issueIdToken(cookie: string, client: { client_id: string; client_secret: string }, redirectUri: string) {
    const res = await authorize(cookie, client.client_id, { redirect_uri: redirectUri });
    const code = new URL(res.headers.get("location")!, BASE).searchParams.get("code")!;
    const tok = (await (
      await SELF.fetch(`${BASE}/token`, {
        method: "POST",
        headers: FORM,
        body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: client.client_id, client_secret: client.client_secret }).toString(),
      })
    ).json()) as { id_token: string; access_token: string };
    return tok;
  }

  // DCR clients register untrusted; mark them trusted so the flow does not
  // stop at the consent screen.
  const trust = async (clientId: string) => env.DB.prepare("UPDATE oauth_clients SET trusted = 1 WHERE client_id = ?").bind(clientId).run();

  it("derives a stable sector-scoped sub across id_token and userinfo, per sector", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);

    const a = (await registerDynamic({ redirect_uris: ["https://a.example/cb"], subject_type: "pairwise" })).json as { client_id: string; client_secret: string };
    const b = (await registerDynamic({ redirect_uris: ["https://b.example/cb"], subject_type: "pairwise" })).json as { client_id: string; client_secret: string };
    await trust(a.client_id);
    await trust(b.client_id);
    const pub = await seedClient(apiKey);

    const subA = JSON.parse(Buffer.from((await issueIdToken(cookie, a, "https://a.example/cb")).id_token.split(".")[1]!, "base64url").toString()).sub as string;
    const subB = JSON.parse(Buffer.from((await issueIdToken(cookie, b, "https://b.example/cb")).id_token.split(".")[1]!, "base64url").toString()).sub as string;
    const subPub = JSON.parse(Buffer.from((await issueIdToken(cookie, pub, REDIRECT)).id_token.split(".")[1]!, "base64url").toString()).sub as string;

    expect(subA).toMatch(/^_[0-9a-f]{64}$/);
    expect(subB).toMatch(/^_[0-9a-f]{64}$/);
    expect(subA).not.toBe(subB); // different sectors must not correlate
    expect(subPub).toBe(String(userId));

    // userinfo returns the same pairwise sub the id_token carried.
    const tok = await issueIdToken(cookie, a, "https://a.example/cb");
    const info = (await (await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${tok.access_token}` } })).json()) as { sub: string };
    expect(info.sub).toBe(subA);
  });

  it("validates the sector document against the registered redirect_uris", async () => {
    const { apiKey } = await bootstrapInstance();
    const sectorUri = "https://sector.example/list.json";

    vi.stubGlobal("fetch", async () => new Response(JSON.stringify(["https://a.example/cb", "https://a.example/alt"]), { headers: { "Content-Type": "application/json" } }));
    try {
      const ok = await registerDynamic({ redirect_uris: ["https://a.example/cb", "https://a.example/alt"], subject_type: "pairwise", sector_identifier_uri: sectorUri });
      expect(ok.status, JSON.stringify(ok.json)).toBe(201);
      expect(ok.json.sector_identifier_uri).toBe(sectorUri);
      // The sector is the document's host, not the redirect host.
      const userId = await seedUser(apiKey);
      const cookie = await sessionFor(userId);
      await trust(ok.json.client_id as string);
      const sub = JSON.parse(
        Buffer.from((await issueIdToken(cookie, ok.json as { client_id: string; client_secret: string }, "https://a.example/cb")).id_token.split(".")[1]!, "base64url").toString()
      ).sub as string;
      expect(sub).toMatch(/^_[0-9a-f]{64}$/);

      const missing = await registerDynamic({ redirect_uris: ["https://other.example/cb"], subject_type: "pairwise", sector_identifier_uri: sectorUri });
      expect(missing.status).toBe(400);
      expect(missing.json.error).toBe("invalid_client_metadata");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("requires a shared redirect host when no sector_identifier_uri is given", async () => {
    await bootstrapInstance();
    const res = await registerDynamic({ redirect_uris: ["https://a.example/cb", "https://b.example/cb"], subject_type: "pairwise" });
    expect(res.status).toBe(400);
    expect(res.json.error).toBe("invalid_client_metadata");
  });
});

describe("JAR request objects (RFC 9101)", () => {
  async function jarClient() {
    const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
    const jwk = { ...(await exportJWK(publicKey)), kid: "jar-k1" };
    const { json } = await registerDynamic({ redirect_uris: [REDIRECT], jwks: { keys: [jwk] } });
    await env.DB.prepare("UPDATE oauth_clients SET trusted = 1 WHERE client_id = ?").bind(json.client_id as string).run();
    return { client: json as { client_id: string }, privateKey };
  }

  async function requestObject(clientId: string, privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"], claims: Record<string, unknown> = {}) {
    return new SignJWT({
      client_id: clientId,
      response_type: "code",
      redirect_uri: REDIRECT,
      scope: "openid",
      state: "jar-state",
      ...claims,
    })
      .setProtectedHeader({ alg: "RS256", kid: "jar-k1" })
      .setIssuer(clientId)
      .setAudience(BASE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  }

  it("accepts a signed request object and uses the claims inside it", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const { client, privateKey } = await jarClient();

    const request = await requestObject(client.client_id, privateKey);
    // client_id only inside the object: the endpoint has to find it there.
    const res = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ request })}`, { headers: { Cookie: cookie }, redirect: "manual" });
    expect(res.status).toBe(302);
    const dest = new URL(res.headers.get("location")!);
    expect(dest.origin + dest.pathname).toBe(REDIRECT);
    expect(dest.searchParams.get("code")).toBeTruthy();
    expect(dest.searchParams.get("state")).toBe("jar-state");
  });

  it("rejects unsigned objects and objects signed with an unknown key", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const { client, privateKey } = await jarClient();

    const unsigned = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: client.client_id, redirect_uri: REDIRECT, request: "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ." })}`, {
      headers: { Cookie: cookie },
      redirect: "manual",
    });
    expect(unsigned.status).toBe(302);
    expect(new URL(unsigned.headers.get("location")!).searchParams.get("error")).toBe("invalid_request_object");

    const stranger = (await generateKeyPair("RS256", { extractable: true })).privateKey;
    const forged = await new SignJWT({ client_id: client.client_id, response_type: "code", redirect_uri: REDIRECT, scope: "openid" })
      .setProtectedHeader({ alg: "RS256", kid: "jar-k1" })
      .setIssuer(client.client_id)
      .setAudience(BASE)
      .setExpirationTime("5m")
      .sign(stranger);
    const bad = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: client.client_id, redirect_uri: REDIRECT, request: forged })}`, { headers: { Cookie: cookie }, redirect: "manual" });
    expect(new URL(bad.headers.get("location")!).searchParams.get("error")).toBe("invalid_request_object");
  });

  it("fetches request_uri only when it is registered on the client", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey);
    const cookie = await sessionFor(userId);
    const { client, privateKey } = await jarClient();
    const requestUri = "https://rp.example/object.jwt";
    await env.DB.prepare("UPDATE oauth_clients SET request_uris = ? WHERE client_id = ?").bind(JSON.stringify([requestUri]), client.client_id).run();

    const object = await requestObject(client.client_id, privateKey);
    const fetched: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      fetched.push(String(input));
      return new Response(object, { headers: { "Content-Type": "application/jwt" } });
    });
    try {
      const res = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: client.client_id, request_uri: requestUri })}`, { headers: { Cookie: cookie }, redirect: "manual" });
      expect(res.status).toBe(302);
      expect(new URL(res.headers.get("location")!).searchParams.get("code")).toBeTruthy();
      expect(fetched).toEqual([requestUri]);

      const other = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ client_id: client.client_id, redirect_uri: REDIRECT, request_uri: "https://evil.example/x.jwt" })}`, {
        headers: { Cookie: cookie },
        redirect: "manual",
      });
      expect(new URL(other.headers.get("location")!).searchParams.get("error")).toBe("invalid_request_uri");
      expect(fetched).toEqual([requestUri]); // never fetched the unregistered one
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("bounds the remote JWKS cache like the token path does", async () => {
    const { clientKeyResolver, remoteJwks, MAX_REMOTE_JWKS } = await import("../src/lib/request-object.js");
    remoteJwks.clear();
    for (let i = 0; i < MAX_REMOTE_JWKS + 1; i++) {
      expect(clientKeyResolver({ jwks: null, jwks_uri: `https://keys-${i}.example/jwks` })).toBeTruthy();
    }
    // Each entry is an endpoint this isolate will fetch on an anonymous
    // request; the cache must stay capped, not grow per registered URI.
    expect(remoteJwks.size).toBeLessThanOrEqual(MAX_REMOTE_JWKS);
    remoteJwks.clear();
  });
});

describe("JWKS rotation probe", () => {
  it("adds a new RS256 kid while keeping the old key published", async () => {
    await bootstrapInstance();
    (env as Record<string, unknown>).JWKS_ROTATION_PROBE = "true";
    try {
      const before = (await (await SELF.fetch(`${BASE}/jwks.json`)).json()) as { keys: { kid: string }[] };
      const after = (await (await SELF.fetch(`${BASE}/jwks.json`)).json()) as { keys: { kid: string }[] };
      const beforeKids = new Set(before.keys.map((k) => k.kid));
      const afterKids = after.keys.map((k) => k.kid);
      expect(afterKids.some((kid) => !beforeKids.has(kid))).toBe(true);
      for (const kid of beforeKids) expect(afterKids).toContain(kid);
    } finally {
      (env as Record<string, unknown>).JWKS_ROTATION_PROBE = "";
    }
  });
});

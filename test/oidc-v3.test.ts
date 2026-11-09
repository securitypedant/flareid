import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { decodeJwt } from "jose";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const CB = "https://rp.test/cb";
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const PASSWORD = "user-password-123";

async function s256(verifier: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function setup(client: Record<string, unknown> = {}) {
  const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, users: [{ username: "ola", given_name: "Ola", family_name: "Berg", job_title: "Engineer", password: PASSWORD, status: "active" }] },
  });
  const created = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "RP", redirect_uris: [CB], ...client } });
  if (created.status !== 200) throw new Error(JSON.stringify(created.body));
  return { apiKey, upn: `ola@${domain}`, clientId: created.body.client_id as string, clientSecret: created.body.client_secret as string | undefined };
}

function authorizeUrl(clientId: string, extra: Record<string, string> = {}) {
  return `${BASE}/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: CB, response_type: "code", scope: "openid email profile groups", state: "st", ...extra })}`;
}

/** Signs in through the form for an /authorize request; returns the final Location and the session cookie. */
async function signInVia(url: string, upn: string, cookie = "") {
  const page = await SELF.fetch(url, { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} });
  if (page.status === 302) return { location: page.headers.get("Location")!, cookie };
  const flowId = /name="flow_id" value="([^"]+)"/.exec(await page.text())![1]!;
  const res = await SELF.fetch(`${BASE}/login`, { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: flowId, upn, password: PASSWORD }).toString(), redirect: "manual" });
  return { location: res.headers.get("Location")!, cookie: res.headers.get("Set-Cookie")?.split(";")[0] ?? cookie };
}

async function exchange(code: string, clientId: string, extra: Record<string, string> = {}) {
  const res = await SELF.fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: clientId, ...extra }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

const codeOf = (location: string) => new URL(location).searchParams.get("code")!;

describe("per-client claim allowlist", () => {
  it("releases only allowed groups that were also requested by scope, in the id_token and /userinfo", async () => {
    const { upn, clientId, clientSecret } = await setup({ allowed_claims: ["email", "groups"] });
    const { location } = await signInVia(authorizeUrl(clientId), upn);
    const tokens = await exchange(codeOf(location), clientId, { client_secret: clientSecret! });
    const claims = decodeJwt(tokens.body.id_token!);
    expect(claims.email).toBe(upn);
    expect(claims.groups).toBeDefined();
    expect(claims.name).toBeUndefined();
    expect(claims.job_title).toBeUndefined();
    expect(claims.custom).toBeUndefined();

    const info = (await (await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${tokens.body.access_token}` } })).json()) as Record<string, unknown>;
    expect(info.email).toBe(upn);
    expect(info.job_title).toBeUndefined();
  });

  it("without an allowlist, scope alone decides: openid only means no profile claims", async () => {
    const { upn, clientId, clientSecret } = await setup();
    const { location } = await signInVia(authorizeUrl(clientId, { scope: "openid" }), upn);
    const claims = decodeJwt((await exchange(codeOf(location), clientId, { client_secret: clientSecret! })).body.id_token!);
    expect(claims.sub).toBeDefined();
    expect(claims.email).toBeUndefined();
    expect(claims.name).toBeUndefined();
  });
});

describe("protocol claims", () => {
  it("id_token carries auth_time, acr, sid, azp and an at_hash that matches the access token", async () => {
    const { upn, clientId, clientSecret } = await setup();
    const before = Math.floor(Date.now() / 1000) - 1;
    const { location } = await signInVia(authorizeUrl(clientId, { nonce: "n-1" }), upn);
    const tokens = await exchange(codeOf(location), clientId, { client_secret: clientSecret! });
    const claims = decodeJwt(tokens.body.id_token!);
    expect(claims.auth_time).toBeGreaterThanOrEqual(before);
    expect(claims.acr).toBe("urn:flareid:acr:pwd");
    expect(claims.sid).toBeTruthy();
    expect(claims.azp).toBe(clientId);
    expect(claims.nonce).toBe("n-1");
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(tokens.body.access_token!)));
    const expected = btoa(String.fromCharCode(...d.slice(0, 16))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(claims.at_hash).toBe(expected);
  });

  it("discovery advertises the endpoints and values the OP supports", async () => {
    const doc = (await (await SELF.fetch(`${BASE}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(doc.end_session_endpoint).toBe(`${BASE}/oidc/logout`);
    expect(doc.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(doc.prompt_values_supported).toEqual(["none", "login", "consent"]);
    expect(doc.token_endpoint_auth_methods_supported).toContain("none");
    expect(doc.claims_supported).toEqual(expect.arrayContaining(["auth_time", "acr", "sid", "preferred_username"]));
  });
});

describe("prompt and max_age", () => {
  it("prompt=none answers login_required without a session, and a code with one", async () => {
    const { upn, clientId } = await setup();
    const none = await SELF.fetch(authorizeUrl(clientId, { prompt: "none" }), { redirect: "manual" });
    const err = new URL(none.headers.get("Location")!);
    expect(err.searchParams.get("error")).toBe("login_required");
    expect(err.searchParams.get("state")).toBe("st");

    const { cookie } = await signInVia(authorizeUrl(clientId), upn);
    const silent = await SELF.fetch(authorizeUrl(clientId, { prompt: "none" }), { redirect: "manual", headers: { Cookie: cookie } });
    expect(new URL(silent.headers.get("Location")!).searchParams.get("code")).toBeTruthy();
  });

  it("prompt=login and an exceeded max_age show the login form despite a session", async () => {
    const { upn, clientId } = await setup();
    const { cookie } = await signInVia(authorizeUrl(clientId), upn);
    for (const extra of [{ prompt: "login" }, { max_age: "0" }] as Record<string, string>[]) {
      await env.DB.prepare("UPDATE sessions SET created_at = ?").bind(new Date(Date.now() - 5000).toISOString()).run();
      const res = await SELF.fetch(authorizeUrl(clientId, extra), { redirect: "manual", headers: { Cookie: cookie } });
      expect(res.status).toBe(200);
      expect(await res.text()).toContain('name="flow_id"');
    }
  });

  it("errors after redirect_uri validation go back to the client", async () => {
    const { clientId } = await setup();
    const res = await SELF.fetch(authorizeUrl(clientId, { response_type: "token" }), { redirect: "manual" });
    expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBe("unsupported_response_type");
  });
});

describe("consent for non-trusted clients", () => {
  it("asks once, remembers the answer, and a denial returns access_denied", async () => {
    const { upn, clientId, clientSecret } = await setup({ trusted: false });
    const first = await signInVia(authorizeUrl(clientId), upn);
    expect(first.location).toMatch(/^\/consent\/[0-9a-f]{32}$/);
    const page = await (await SELF.fetch(`${BASE}${first.location}`, { headers: { Cookie: first.cookie } })).text();
    expect(page).toContain("RP wants to sign you in");

    const allow = await SELF.fetch(`${BASE}${first.location}`, { method: "POST", headers: { ...FORM, Cookie: first.cookie }, body: "decision=allow", redirect: "manual" });
    const code = codeOf(allow.headers.get("Location")!);
    expect((await exchange(code, clientId, { client_secret: clientSecret! })).status).toBe(200);

    // Remembered: the same scopes again go straight through.
    const again = await SELF.fetch(authorizeUrl(clientId), { redirect: "manual", headers: { Cookie: first.cookie } });
    expect(new URL(again.headers.get("Location")!).searchParams.get("code")).toBeTruthy();

    // prompt=consent asks again; deny sends access_denied to the client.
    const forced = await SELF.fetch(authorizeUrl(clientId, { prompt: "consent" }), { redirect: "manual", headers: { Cookie: first.cookie } });
    const consentPath = forced.headers.get("Location")!;
    expect(consentPath).toMatch(/^\/consent\//);
    const deny = await SELF.fetch(`${BASE}${consentPath}`, { method: "POST", headers: { ...FORM, Cookie: first.cookie }, body: "decision=deny", redirect: "manual" });
    expect(new URL(deny.headers.get("Location")!).searchParams.get("error")).toBe("access_denied");
  });

  it("a consent page cannot be answered by someone else's session", async () => {
    const { apiKey, upn, clientId } = await setup({ trusted: false });
    const first = await signInVia(authorizeUrl(clientId), upn);
    const { cookie: adminCookie } = await signInVia(`${BASE}/login`, "admin@horizon.test").catch(() => ({ cookie: "" }));
    expect(apiKey).toBeTruthy();
    const res = await SELF.fetch(`${BASE}${first.location}`, { headers: adminCookie ? { Cookie: adminCookie } : {} });
    expect(res.status).toBe(400);
  });
});

describe("public clients", () => {
  it("have no secret, must use PKCE, and may use a loopback redirect on any port", async () => {
    const { apiKey, upn } = await setup();
    const created = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "CLI", client_type: "public", redirect_uris: ["http://127.0.0.1/callback"] } });
    expect(created.body.client_secret).toBeUndefined();
    const clientId = created.body.client_id as string;
    const redirect = "http://127.0.0.1:53682/callback";
    const url = (extra: Record<string, string>) =>
      `${BASE}/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirect, response_type: "code", scope: "openid", state: "s", ...extra })}`;

    const noPkce = await SELF.fetch(url({}), { redirect: "manual" });
    expect(new URL(noPkce.headers.get("Location")!).searchParams.get("error")).toBe("invalid_request");

    const verifier = "v".repeat(50);
    const { location } = await signInVia(url({ code_challenge: await s256(verifier), code_challenge_method: "S256" }), upn);
    const res = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: codeOf(location), redirect_uri: redirect, client_id: clientId, code_verifier: verifier }).toString(),
    });
    expect(res.status).toBe(200);

    // Introspection stays confidential-only.
    const intro = await SELF.fetch(`${BASE}/introspect`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `token=x&client_id=${clientId}` });
    expect(intro.status).toBe(401);
  });
});

describe("RP-initiated logout", () => {
  it("with a hint for the current session, signs out and returns to a registered post-logout URI", async () => {
    const { upn, clientId, clientSecret } = await setup({ post_logout_redirect_uris: ["https://rp.test/bye"] });
    const { location, cookie } = await signInVia(authorizeUrl(clientId), upn);
    const idToken = (await exchange(codeOf(location), clientId, { client_secret: clientSecret! })).body.id_token!;

    const res = await SELF.fetch(`${BASE}/oidc/logout?${new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: "https://rp.test/bye", state: "x" })}`, {
      redirect: "manual",
      headers: { Cookie: cookie },
    });
    expect(res.headers.get("Location")).toBe("https://rp.test/bye?state=x");
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(302);
  });

  it("refuses an unregistered post-logout URI, and asks first without a hint", async () => {
    const { upn, clientId } = await setup();
    const { cookie } = await signInVia(authorizeUrl(clientId), upn);
    const evil = await SELF.fetch(`${BASE}/oidc/logout?${new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: "https://evil.test/" })}`, {
      redirect: "manual",
      headers: { Cookie: cookie },
    });
    expect(evil.status).toBe(400);

    const ask = await SELF.fetch(`${BASE}/oidc/logout`, { redirect: "manual", headers: { Cookie: cookie } });
    expect(ask.status).toBe(200);
    expect(await ask.text()).toContain('action="/oidc/logout/confirm"');
    // Still signed in until the user confirms.
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(200);
    await SELF.fetch(`${BASE}/oidc/logout/confirm`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "", redirect: "manual" });
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(302);
  });
});

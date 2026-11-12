// Security > Signing keys: rotation from the console (step-up protected), the
// per-client id_token algorithm, what /jwks.json publishes around a rotation,
// and the hourly purge of keys past their publication window.
import { SELF, env } from "cloudflare:test";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { purgeRetiredKeys, RETIRED_PUBLISH_HOURS } from "../src/lib/signing-keys.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const REDIRECT_URI = "https://rp.test/callback";
const USER_PASSWORD = "a-test-user-password-1";

async function adminCookie(opts: { stale?: boolean } = {}): Promise<string> {
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
  const { setCookie, sessionId } = await createSession(env, id, ["pwd", "mfa"], new Request(BASE));
  if (opts.stale) await env.DB.prepare("UPDATE sessions SET created_at = ? WHERE id = ?").bind(new Date(Date.now() - 30 * 60 * 1000).toISOString(), sessionId).run();
  return setCookie.split(";")[0]!;
}

const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, cookie: string, body: Record<string, string> = {}, headers: Record<string, string> = {}) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie, ...headers }, body: new URLSearchParams(body).toString(), redirect: "manual" });

async function activeKid(alg: string): Promise<string> {
  await SELF.fetch(`${BASE}/jwks.json`); // keys are created on first use
  return (await env.DB.prepare("SELECT kid FROM signing_keys WHERE alg = ? AND status = 'active'").bind(alg).first<{ kid: string }>())!.kid;
}

async function jwks(): Promise<{ keys: { kid: string; alg: string }[] }> {
  return (await (await SELF.fetch(`${BASE}/jwks.json`)).json()) as { keys: { kid: string; alg: string }[] };
}

async function seedUser(apiKey: string): Promise<string> {
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, users: [{ username: "ada", given_name: "Ada", family_name: "K", password: USER_PASSWORD, status: "active", groups: [] }] },
  });
  return "ada@horizon.test";
}

/** The authorization code flow for a confidential client, returning the id_token. */
async function idTokenFor(clientId: string, clientSecret: string, upn: string): Promise<string> {
  const query = new URLSearchParams({ client_id: clientId, redirect_uri: REDIRECT_URI, response_type: "code", scope: "openid email", nonce: "n" });
  const html = await (await SELF.fetch(`${BASE}/authorize?${query}`, { redirect: "manual" })).text();
  const flowId = /name="flow_id" value="([^"]*)"/.exec(html)?.[1];
  if (!flowId) throw new Error(`no login form: ${html.slice(0, 300)}`);
  const login = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password: USER_PASSWORD }).toString(),
    redirect: "manual",
  });
  const code = new URL(login.headers.get("Location")!, BASE).searchParams.get("code");
  if (!code) throw new Error(`no code: ${login.headers.get("Location")}`);
  const res = await SELF.fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, client_secret: clientSecret }).toString(),
  });
  const body = (await res.json()) as { id_token?: string };
  expect(res.status).toBe(200);
  return body.id_token!;
}

describe("Security > Signing keys (console)", () => {
  it("lists the keys with the active one per algorithm and links it from the Security sub-nav", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    const res = await get("/admin/security/signing-keys", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('href="/admin/security/signing-keys" class="sub active"');
    expect(html).toContain(await activeKid("RS256"));
    expect(html).toContain(await activeKid("ES256"));
    expect(html).toContain('action="/admin/security/signing-keys/RS256/rotate"');
    expect(html).toContain('action="/admin/security/signing-keys/ES256/rotate"');
    expect(html).toContain("data-confirm=");
    expect(html).toContain(`stays published for ${RETIRED_PUBLISH_HOURS} hours`);
    expect(html.match(/class="key-active"/g)).toHaveLength(2);
  });

  it("sends a stale session to step-up, then rotates with a fresh one; the old key stays published", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const before = await activeKid("RS256");

    const stale = await adminCookie({ stale: true });
    const blocked = await post("/admin/security/signing-keys/RS256/rotate", stale, {}, { Referer: `${BASE}/admin/security/signing-keys` });
    expect(blocked.status).toBe(303);
    expect(blocked.headers.get("Location")).toBe(`/admin/reauth?next=${encodeURIComponent("/admin/security/signing-keys")}`);
    expect(await activeKid("RS256")).toBe(before);

    const fresh = await adminCookie();
    const ok = await post("/admin/security/signing-keys/RS256/rotate", fresh);
    expect(ok.status).toBe(302);
    const after = await activeKid("RS256");
    expect(after).not.toBe(before);
    expect(ok.headers.get("Location")).toBe(`/admin/security/signing-keys?rotated=${encodeURIComponent(after)}`);

    const retired = await env.DB.prepare("SELECT status, retired_at FROM signing_keys WHERE kid = ?").bind(before).first<{ status: string; retired_at: string }>();
    expect(retired?.status).toBe("retired");
    const audit = await env.DB.prepare("SELECT target, details FROM audit_log WHERE action = 'signing_key.rotated'").first<{ target: string; details: string }>();
    expect(audit?.target).toBe(after);
    expect(JSON.parse(audit!.details)).toMatchObject({ alg: "RS256" });

    const kids = (await jwks()).keys.map((k) => k.kid);
    expect(kids).toEqual(expect.arrayContaining([before, after, await activeKid("ES256")]));
    const page = await (await get(ok.headers.get("Location")!, fresh)).text();
    expect(page).toContain("Rotated. New key:");
    expect(page).toContain("Retired");

    // Unknown algorithms are refused.
    expect((await post("/admin/security/signing-keys/HS256/rotate", fresh)).status).toBe(400);
    const disco = (await (await SELF.fetch(`${BASE}/.well-known/openid-configuration`)).json()) as { id_token_signing_alg_values_supported: string[]; jwks_uri: string };
    expect(disco.id_token_signing_alg_values_supported).toEqual(["RS256", "ES256"]);
    expect(disco.jwks_uri).toBe(`${BASE}/jwks.json`);
  });

  it("signs with the new key after a rotation, and tokens from the old key still verify", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = await seedUser(apiKey);
    const client = (await apiCall("/api/v1/clients", { token: apiKey, body: { name: "RP", redirect_uris: [REDIRECT_URI] } })).body;
    const oldToken = await idTokenFor(client.client_id, client.client_secret, upn);
    const oldKid = decodeProtectedHeader(oldToken).kid;

    expect((await post("/admin/security/signing-keys/RS256/rotate", await adminCookie())).status).toBe(302);
    const newToken = await idTokenFor(client.client_id, client.client_secret, upn);
    expect(decodeProtectedHeader(newToken).kid).toBe(await activeKid("RS256"));
    expect(decodeProtectedHeader(newToken).kid).not.toBe(oldKid);

    const set = createLocalJWKSet((await jwks()) as never);
    await jwtVerify(oldToken, set, { issuer: BASE, audience: client.client_id });
    await jwtVerify(newToken, set, { issuer: BASE, audience: client.client_id });
  });
});

describe("per-client id_token signing algorithm", () => {
  it("issues ES256 id_tokens to a client that asks for them, verifiable against the JWKS", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = await seedUser(apiKey);
    const created = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "EC RP", redirect_uris: [REDIRECT_URI], id_token_signed_response_alg: "ES256" } });
    expect(created.status).toBe(200);
    expect(created.body.id_token_signed_response_alg).toBe("ES256");
    expect((await apiCall(`/api/v1/clients/${created.body.client_id}`, { token: apiKey })).body.id_token_signed_response_alg).toBe("ES256");

    const idToken = await idTokenFor(created.body.client_id, created.body.client_secret, upn);
    const { protectedHeader, payload } = await jwtVerify(idToken, createLocalJWKSet((await jwks()) as never), { issuer: BASE, audience: created.body.client_id });
    expect(protectedHeader.alg).toBe("ES256");
    expect(protectedHeader.kid).toBe(await activeKid("ES256"));
    expect(payload.email).toBe(upn);
  });

  it("accepts and validates the algorithm on API create and PATCH", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    expect((await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Bad", redirect_uris: [REDIRECT_URI], id_token_signed_response_alg: "HS256" } })).status).toBe(400);
    const made = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "RP", redirect_uris: [REDIRECT_URI] } });
    expect(made.body.id_token_signed_response_alg).toBe("RS256");
    const path = `/api/v1/clients/${made.body.client_id}`;
    expect((await apiCall(path, { token: apiKey, method: "PATCH", body: { id_token_signed_response_alg: "none" } })).status).toBe(400);
    const patched = await apiCall(path, { token: apiKey, method: "PATCH", body: { id_token_signed_response_alg: "ES256" } });
    expect(patched.status).toBe(200);
    expect(patched.body.id_token_signed_response_alg).toBe("ES256");
    // Not supplied: kept.
    expect((await apiCall(path, { token: apiKey, method: "PATCH", body: { name: "Renamed" } })).body.id_token_signed_response_alg).toBe("ES256");
    const listed = (await apiCall("/api/v1/clients", { token: apiKey })).body.clients as { client_id: string; id_token_signed_response_alg: string }[];
    expect(listed.find((c) => c.client_id === made.body.client_id)?.id_token_signed_response_alg).toBe("ES256");
  });

  it("is set from the console's client create and edit forms", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    const newForm = await (await get("/admin/clients/new", cookie)).text();
    expect(newForm).toContain('name="id_token_signed_response_alg"');

    expect((await post("/admin/clients", cookie, { name: "Console RP", redirect_uris: REDIRECT_URI, id_token_signed_response_alg: "ES256" })).status).toBe(200);
    const row = (await env.DB.prepare("SELECT id, id_token_signed_response_alg AS alg FROM oauth_clients WHERE name = 'Console RP'").first<{ id: number; alg: string }>())!;
    expect(row.alg).toBe("ES256");
    const edit = await (await get(`/admin/clients/${row.id}`, cookie)).text();
    expect(edit).toMatch(/<option value="ES256" selected>/);

    expect((await post(`/admin/clients/${row.id}`, cookie, { name: "Console RP", redirect_uris: REDIRECT_URI, id_token_signed_response_alg: "RS256" })).status).toBe(302);
    expect((await env.DB.prepare("SELECT id_token_signed_response_alg AS alg FROM oauth_clients WHERE id = ?").bind(row.id).first<{ alg: string }>())!.alg).toBe("RS256");
    // Anything else falls back to the default.
    await post(`/admin/clients/${row.id}`, cookie, { name: "Console RP", redirect_uris: REDIRECT_URI, id_token_signed_response_alg: "HS256" });
    expect((await env.DB.prepare("SELECT id_token_signed_response_alg AS alg FROM oauth_clients WHERE id = ?").bind(row.id).first<{ alg: string }>())!.alg).toBe("RS256");
  });
});

describe("retired key cleanup", () => {
  it("keeps a retired key published inside the window and purges it once past", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const first = await activeKid("ES256");
    await apiCall("/api/v1/security/signing-keys/ES256/rotate", { token: apiKey, method: "POST" });
    const second = await activeKid("ES256");
    await apiCall("/api/v1/security/signing-keys/ES256/rotate", { token: apiKey, method: "POST" });

    // `first` retired long ago; `second` just now.
    const longAgo = new Date(Date.now() - (RETIRED_PUBLISH_HOURS + 1) * 3600 * 1000).toISOString();
    await env.DB.prepare("UPDATE signing_keys SET retired_at = ? WHERE kid = ?").bind(longAgo, first).run();

    const published = (await jwks()).keys.map((k) => k.kid);
    expect(published).not.toContain(first);
    expect(published).toContain(second);
    const page = await (await get("/admin/security/signing-keys", await adminCookie())).text();
    expect(page).toContain("Expired &mdash; removed by the hourly cleanup");

    expect(await purgeRetiredKeys(env)).toBe(1);
    const left = (await env.DB.prepare("SELECT kid FROM signing_keys WHERE alg = 'ES256'").all<{ kid: string }>()).results.map((r) => r.kid);
    expect(left).not.toContain(first);
    expect(left).toContain(second);
    expect(left).toContain(await activeKid("ES256"));
    // Nothing else is due.
    expect(await purgeRetiredKeys(env)).toBe(0);
  });
});

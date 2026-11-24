// Social sign-in: the provider catalog, the console pages under
// Integrations, the OAuth2-userinfo adapter end to end (GitHub), Apple's
// generated client secret, and the API surface.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { sealLoginFlow } from "../src/lib/authorize-state.js";
import { requiredPermission } from "../src/lib/admin-roles.js";
import { SOCIAL_PROVIDERS, appleClientSecret, socialProvider } from "../src/lib/social.js";
import { idpConfig, type OidcIdpConfig, type UpstreamIdpRow } from "../src/lib/federation.js";
import { generateKeyPair, exportPKCS8, jwtVerify } from "jose";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
  const adminCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { apiKey, adminCookie };
}

const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, cookie: string, body: Record<string, string>) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(body).toString(), redirect: "manual" });
const socialRow = (key: string) => env.DB.prepare("SELECT * FROM upstream_idps WHERE json_extract(config, '$.social') = ?").bind(key).first<UpstreamIdpRow>();

describe("the catalog pages", () => {
  it("lists every provider and marks configured ones", async () => {
    const { adminCookie } = await setup();
    const html = await (await get("/admin/integrations/social", adminCookie)).text();
    for (const p of SOCIAL_PROVIDERS) expect(html).toContain(p.name);
    expect(html).toContain("Not set up");
    await post("/admin/social/github", adminCookie, { name: "GitHub", client_id: "gh-cid", client_secret: "gh-secret" });
    const after = await (await get("/admin/integrations/social", adminCookie)).text();
    expect(after).toContain("Enabled");
  });

  it("creates an upstream row marked social, hidden from the federation list and offered on the login page", async () => {
    const { adminCookie } = await setup();
    const res = await post("/admin/social/github", adminCookie, { name: "GitHub", client_id: "gh-cid", client_secret: "gh-secret", jit: "1", jit_domain: "horizon.test" });
    expect(res.headers.get("Location")).toContain("/admin/integrations/social/github?saved=1");
    const row = (await socialRow("github"))!;
    expect(row.jit).toBe(1);
    const cfg = idpConfig<OidcIdpConfig>(row);
    expect(cfg.social).toBe("github");
    expect(cfg.issuer).toBe("social:github");

    // The login page offers the button; the federation list does not duplicate it.
    const login = await (await SELF.fetch(`${BASE}/login`)).text();
    expect(login).toContain(`/login/federated/${row.id}`);
    expect(login).toContain("GitHub");
    const fed = await (await get("/admin/integrations/federation", adminCookie)).text();
    expect(fed).not.toContain(`/admin/integrations/federation/${row.id}`);
    expect(fed).toContain("/admin/integrations/social");
    // The generic detail page hands social rows to their own editor.
    expect((await get(`/admin/integrations/federation/${row.id}`, adminCookie)).headers.get("Location")).toBe("/admin/integrations/social/github");
    // The integrations overview counts it.
    const overview = await (await get("/admin/integrations", adminCookie)).text();
    expect(overview).toContain("Social sign-in");
  });

  it("resolves Microsoft's tenant into the stored issuer", async () => {
    const { adminCookie } = await setup();
    await post("/admin/social/microsoft", adminCookie, { name: "Microsoft", tenant: "contoso.onmicrosoft.com", client_id: "ms-cid", client_secret: "ms-secret" });
    const cfg = idpConfig<OidcIdpConfig>((await socialRow("microsoft"))!);
    expect(cfg.issuer).toBe("https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0");
  });

  it("keeps the stored secret and apple key on update when the fields come back blank", async () => {
    const { adminCookie } = await setup();
    await post("/admin/social/google", adminCookie, { name: "Google", client_id: "g-cid", client_secret: "g-secret" });
    const before = idpConfig<OidcIdpConfig>((await socialRow("google"))!);
    expect(before.client_secret).toBeTruthy();
    // Update with an empty secret field: stored secret survives, name changes.
    await post("/admin/social/google", adminCookie, { name: "Google Workspace", client_id: "g-cid2", client_secret: "", enabled: "1" });
    const after = idpConfig<OidcIdpConfig>((await socialRow("google"))!);
    expect(after.client_secret).toBe(before.client_secret);
    expect(after.client_id).toBe("g-cid2");
  });

  it("refuses an unknown provider key and a missing client id", async () => {
    const { adminCookie } = await setup();
    expect((await get("/admin/integrations/social/myspace", adminCookie)).status).toBe(404);
    const res = await post("/admin/social/google", adminCookie, { name: "Google", client_id: "", client_secret: "x" });
    expect(res.headers.get("Location")).toContain("error=");
  });
});

describe("the OAuth2 adapter", () => {
  it("sends the browser to GitHub with PKCE and no nonce, then completes sign-in from /user", async () => {
    const { apiKey, adminCookie } = await setup();
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "ada", email: "ada@horizon.test", status: "active" }] } });
    await post("/admin/social/github", adminCookie, { name: "GitHub", client_id: "gh-cid", client_secret: "gh-secret" });
    const row = (await socialRow("github"))!;

    let exchangedBody = "";
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === "https://github.com/login/oauth/access_token") {
        exchangedBody = String(init?.body ?? "");
        return Response.json({ access_token: "gho_tok" });
      }
      if (url === "https://api.github.com/user") return Response.json({ id: 4242, login: "ada-dev", name: "Ada Dev", email: "ada@horizon.test", avatar_url: "https://avatars.test/4242" });
      return new Response("unexpected fetch " + url, { status: 500 });
    });

    const flowId = await sealLoginFlow(env, { kind: "direct", next: "/account" });
    const start = await SELF.fetch(`${BASE}/login/federated/${row.id}?flow=${encodeURIComponent(flowId)}`, { redirect: "manual" });
    expect(start.status).toBe(302);
    const authUrl = new URL(start.headers.get("Location")!);
    expect(authUrl.origin + authUrl.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(authUrl.searchParams.get("client_id")).toBe("gh-cid");
    expect(authUrl.searchParams.get("code_challenge")).toBeTruthy();
    expect(authUrl.searchParams.get("nonce")).toBeNull();
    expect(authUrl.searchParams.get("scope")).toBe("read:user user:email");
    const state = authUrl.searchParams.get("state")!;

    const cb = await SELF.fetch(`${BASE}/federation/oidc/callback?code=gh-code&state=${encodeURIComponent(state)}`, { redirect: "manual" });
    spy.mockRestore();
    expect(cb.status).toBe(302);
    expect(cb.headers.get("Location")).toBe("/account");
    expect(cb.headers.get("Set-Cookie")).toContain("__Host-flareid_session=");
    // The exchange sent the secret and the PKCE verifier in the form.
    expect(exchangedBody).toContain("client_secret=gh-secret");
    expect(exchangedBody).toContain("code_verifier=");
    // The identity is linked to ada for the next sign-in.
    const link = await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND subject = '4242'").bind(row.id).first();
    expect(link).toBeTruthy();
  });

  it("normalizes Discord's @me profile into claims", async () => {
    const { apiKey, adminCookie } = await setup();
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "ada", email: "ada@horizon.test", status: "active" }] } });
    await post("/admin/social/discord", adminCookie, { name: "Discord", client_id: "dc-cid", client_secret: "dc-secret" });
    const row = (await socialRow("discord"))!;

    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === "https://discord.com/api/v10/oauth2/token") return Response.json({ access_token: "dc_tok" });
      if (url === "https://discord.com/api/v10/users/@me") return Response.json({ id: "999888", username: "ada.d", global_name: "Ada D", email: "ada@horizon.test", verified: true, avatar: "abc123" });
      return new Response("unexpected fetch " + url, { status: 500 });
    });

    const flowId = await sealLoginFlow(env, { kind: "direct", next: "/account" });
    const start = await SELF.fetch(`${BASE}/login/federated/${row.id}?flow=${encodeURIComponent(flowId)}`, { redirect: "manual" });
    expect(new URL(start.headers.get("Location")!).origin + new URL(start.headers.get("Location")!).pathname).toBe("https://discord.com/oauth2/authorize");
    const state = new URL(start.headers.get("Location")!).searchParams.get("state")!;
    const cb = await SELF.fetch(`${BASE}/federation/oidc/callback?code=dc-code&state=${encodeURIComponent(state)}`, { redirect: "manual" });
    spy.mockRestore();
    expect(cb.status).toBe(302);
    expect(await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND subject = '999888'").bind(row.id).first()).toBeTruthy();
  });

  it("JIT-provisions a GitHub sign-in, pulling the primary verified email when the profile hides it", async () => {
    const { adminCookie } = await setup();
    await post("/admin/social/github", adminCookie, { name: "GitHub", client_id: "gh-cid", client_secret: "gh-secret", jit: "1", jit_domain: "horizon.test" });
    const row = (await socialRow("github"))!;

    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === "https://github.com/login/oauth/access_token") return Response.json({ access_token: "gho_tok" });
      if (url === "https://api.github.com/user") return Response.json({ id: 777, login: "rookie-gh", name: "Rookie Gh", email: null, avatar_url: "" });
      if (url === "https://api.github.com/user/emails")
        return Response.json([
          { email: "rookie@public.test", primary: false, verified: true },
          { email: "rookie@horizon.test", primary: true, verified: true },
        ]);
      return new Response("unexpected fetch " + url, { status: 500 });
    });

    const flowId = await sealLoginFlow(env, { kind: "direct", next: "/account" });
    const start = await SELF.fetch(`${BASE}/login/federated/${row.id}?flow=${encodeURIComponent(flowId)}`, { redirect: "manual" });
    const state = new URL(start.headers.get("Location")!).searchParams.get("state")!;
    const cb = await SELF.fetch(`${BASE}/federation/oidc/callback?code=gh-code&state=${encodeURIComponent(state)}`, { redirect: "manual" });
    spy.mockRestore();
    expect(cb.status).toBe(302);
    expect(cb.headers.get("Set-Cookie")).toContain("__Host-flareid_session=");
    const user = await env.DB.prepare("SELECT id, email FROM users WHERE upn = 'rookie-gh-github'").first<{ id: number; email: string }>();
    expect(user).toBeTruthy();
    expect(user!.email).toBe("rookie@horizon.test");
  });
});

describe("Apple", () => {
  it("stores the key material sealed and mints a verifiable ES256 client secret", async () => {
    const { adminCookie } = await setup();
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const pkcs8 = await exportPKCS8(privateKey);
    const res = await post("/admin/social/apple", adminCookie, { name: "Apple", client_id: "com.example.service", apple_team_id: "TEAM123456", apple_key_id: "KEY1234567", apple_private_key: pkcs8 });
    expect(res.headers.get("Location")).toContain("saved=1");
    const cfg = idpConfig<OidcIdpConfig>((await socialRow("apple"))!);
    expect(cfg.apple?.team_id).toBe("TEAM123456");
    expect(cfg.apple?.private_key).toBeTruthy();
    expect(cfg.apple?.private_key).not.toBe(pkcs8); // sealed at rest

    const secret = await appleClientSecret(env, cfg.apple!, cfg.client_id);
    const { payload, protectedHeader } = await jwtVerify(secret, publicKey, { issuer: "TEAM123456", audience: "https://appleid.apple.com" });
    expect(protectedHeader.kid).toBe("KEY1234567");
    expect(payload.sub).toBe("com.example.service");
  });

  it("keeps the stored key when the .p8 field comes back blank", async () => {
    const { adminCookie } = await setup();
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const pkcs8 = await exportPKCS8(privateKey);
    await post("/admin/social/apple", adminCookie, { name: "Apple", client_id: "com.example.service", apple_team_id: "TEAM123456", apple_key_id: "KEY1234567", apple_private_key: pkcs8 });
    const before = idpConfig<OidcIdpConfig>((await socialRow("apple"))!);
    await post("/admin/social/apple", adminCookie, { name: "Apple", client_id: "com.example.service", apple_team_id: "TEAM123456", apple_key_id: "KEY1234567", apple_private_key: "" });
    expect(idpConfig<OidcIdpConfig>((await socialRow("apple"))!).apple?.private_key).toBe(before.apple?.private_key);
  });
});

describe("the API surface", () => {
  it("GET /api/v1/social/providers returns the catalog with configured state", async () => {
    const { apiKey, adminCookie } = await setup();
    await post("/admin/social/gitlab", adminCookie, { name: "GitLab", client_id: "gl-cid", client_secret: "gl-secret" });
    const res = await apiCall("/api/v1/social/providers", { token: apiKey });
    expect(res.status).toBe(200);
    const providers = res.body.providers as { key: string; idp: { id: number; enabled: boolean } | null }[];
    expect(providers.length).toBe(SOCIAL_PROVIDERS.length);
    const gitlab = providers.find((p) => p.key === "gitlab")!;
    expect(gitlab.idp?.enabled).toBe(true);
    expect(providers.find((p) => p.key === "google")!.idp).toBeNull();
  });

  it("federation reads stay delegated; social writes need a Super Admin", () => {
    expect(requiredPermission("GET", "/admin/integrations/social")).toBe("federation:read");
    expect(requiredPermission("GET", "/admin/integrations/social/github")).toBe("federation:read");
    expect(requiredPermission("POST", "/admin/social/github")).toBe("super");
    expect(requiredPermission("POST", "/admin/social/github/delete")).toBe("super");
  });
});

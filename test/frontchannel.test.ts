// OIDC Front-Channel Logout 1.0: sessions remember the clients they signed in to;
// signing out frames each client's frontchannel_logout_uri with iss and sid.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession, oidcSid } from "../src/lib/sessions.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

describe("front-channel logout", () => {
  it("records the client at /authorize and frames its logout URI on sign-out", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const reg = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: { name: "App", client_id: "app", client_secret: "s".repeat(32), redirect_uris: ["https://app.test/cb"], frontchannel_logout_uri: "https://app.test/fcl?x=1" },
    });
    expect(reg.status).toBe(200);
    const bad = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Bad", redirect_uris: ["https://b.test/cb"], frontchannel_logout_uri: "http://b.test/fcl" } });
    expect(bad.status).toBe(400);

    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const { setCookie, sessionId } = await createSession(env, uid, ["pwd", "mfa"], new Request(BASE));
    const cookie = setCookie.split(";")[0]!;
    const auth = await SELF.fetch(`${BASE}/authorize?response_type=code&client_id=app&redirect_uri=${encodeURIComponent("https://app.test/cb")}&scope=openid&state=s&nonce=n`, { headers: { Cookie: cookie }, redirect: "manual" });
    expect(auth.headers.get("Location")).toContain("https://app.test/cb?code=");
    expect(await env.DB.prepare("SELECT client_id FROM session_clients WHERE session_id = ?").bind(sessionId).first<{ client_id: string }>()).toEqual({ client_id: "app" });

    const out = await SELF.fetch(`${BASE}/logout`, { method: "POST", headers: { ...FORM, Cookie: cookie }, redirect: "manual" });
    expect(out.status).toBe(200);
    const html = await out.text();
    const src = new URL(/<iframe src="([^"]+)"/.exec(html)![1]!.replace(/&amp;/g, "&"));
    expect(src.origin + src.pathname).toBe("https://app.test/fcl");
    expect(src.searchParams.get("x")).toBe("1");
    expect(src.searchParams.get("iss")).toBe(BASE);
    expect(src.searchParams.get("sid")).toBe(await oidcSid(sessionId));
    expect(out.headers.get("Content-Security-Policy")).toContain("frame-src https://app.test");
    expect(out.headers.get("X-FlareID-Frame-Src")).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM session_clients WHERE session_id = ?").bind(sessionId).first()).toBeNull();

    const disc = (await (await SELF.fetch(`${BASE}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(disc.frontchannel_logout_supported).toBe(true);
  });

  it("signs out with a plain redirect when no client registered a front-channel URI", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, uid, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const out = await SELF.fetch(`${BASE}/logout`, { method: "POST", headers: { ...FORM, Cookie: cookie }, redirect: "manual" });
    expect(out.status).toBe(302);
  });
});

describe("conformance fixes", () => {
  it("accepts POST at /authorize and /userinfo, and refuses request objects", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/clients", { token: apiKey, body: { name: "App", client_id: "app", client_secret: "s".repeat(32), redirect_uris: ["https://app.test/cb"] } });
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, uid, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const params = { response_type: "code", client_id: "app", redirect_uri: "https://app.test/cb", scope: "openid email", state: "s1", nonce: "n1" };

    const post = await SELF.fetch(`${BASE}/authorize`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://app.test", Cookie: cookie }, body: new URLSearchParams(params).toString(), redirect: "manual" });
    const loc = new URL(post.headers.get("Location")!);
    expect(loc.origin + loc.pathname).toBe("https://app.test/cb");
    expect(loc.searchParams.get("state")).toBe("s1");
    const code = loc.searchParams.get("code")!;

    const tok = (await (await SELF.fetch(`${BASE}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${btoa(`app:${"s".repeat(32)}`)}` }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "https://app.test/cb" }).toString() })).json()) as { access_token: string };
    const viaHeader = await SELF.fetch(`${BASE}/userinfo`, { method: "POST", headers: { Authorization: `Bearer ${tok.access_token}` } });
    expect(viaHeader.status).toBe(200);
    const viaBody = await SELF.fetch(`${BASE}/userinfo`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `access_token=${encodeURIComponent(tok.access_token)}` });
    expect(((await viaBody.json()) as { sub: string }).sub).toBeTruthy();

    const withRequest = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ ...params, request: "eyJhbGciOiJub25lIn0.e30." })}`, { headers: { Cookie: cookie }, redirect: "manual" });
    const err = new URL(withRequest.headers.get("Location")!);
    expect(err.searchParams.get("error")).toBe("request_not_supported");
    expect(err.searchParams.get("state")).toBe("s1");
  });
});

describe("conformance fixes 2", () => {
  async function codeFor(cookie: string, extra: Record<string, string> = {}) {
    const params = { response_type: "code", client_id: "app", redirect_uri: "https://app.test/cb", scope: "openid", state: "s", nonce: "n", ...extra };
    const r = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams(params)}`, { headers: { Cookie: cookie }, redirect: "manual" });
    return new URL(r.headers.get("Location")!).searchParams.get("code")!;
  }
  const redeem = (code: string) =>
    SELF.fetch(`${BASE}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${btoa(`app:${"s".repeat(32)}`)}` }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "https://app.test/cb" }).toString() });

  it("revokes the tokens a reused code issued, and honours the claims parameter", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/clients", { token: apiKey, body: { name: "App", client_id: "app", client_secret: "s".repeat(32), redirect_uris: ["https://app.test/cb"] } });
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, uid, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;

    const code = await codeFor(cookie);
    const first = (await (await redeem(code)).json()) as { access_token: string };
    expect((await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${first.access_token}` } })).status).toBe(200);
    const again = await redeem(code);
    expect(again.status).toBe(400);
    expect((await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${first.access_token}` } })).status).toBe(401);

    // scope=openid alone releases no profile; asking for name with `claims` does.
    const plain = (await (await redeem(await codeFor(cookie))).json()) as { access_token: string };
    expect(((await (await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${plain.access_token}` } })).json()) as Record<string, unknown>).name).toBeUndefined();
    const asked = (await (await redeem(await codeFor(cookie, { claims: JSON.stringify({ userinfo: { name: { essential: true } } }) }))).json()) as { access_token: string };
    expect(((await (await SELF.fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${asked.access_token}` } })).json()) as Record<string, unknown>).name).toBeTruthy();

    const bad = await SELF.fetch(`${BASE}/authorize?${new URLSearchParams({ response_type: "code", client_id: "app", redirect_uri: "https://app.test/cb", scope: "openid", state: "s", claims: "{nope" })}`, { headers: { Cookie: cookie }, redirect: "manual" });
    expect(new URL(bad.headers.get("Location")!).searchParams.get("error")).toBe("invalid_request");
  });
});

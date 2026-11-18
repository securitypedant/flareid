import { beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { cfOneClearCaches, deviceCertVerified, flagUser, getCfOne, riskAtMost, saveCfOne, sweepWatchlist, syncLists, unflagUser, watchlist, watchlistGroup, watchedUser } from "../src/lib/cfone.js";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

beforeEach(async () => {
  await resetDatabase();
  cfOneClearCaches();
});

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function sessionFor(userId: number): Promise<string> {
  const { setCookie } = await createSession(env, userId, ["pwd", "mfa"], new Request(BASE));
  return setCookie.split(";")[0]!;
}

async function adminCookie(): Promise<string> {
  const admin = await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>();
  return sessionFor(admin!.id);
}

async function seedUser(apiKey: string, username: string): Promise<number> {
  const res = await apiCall("/api/v1/users", { token: apiKey, body: { username, given_name: username[0]!.toUpperCase() + username.slice(1), password: "user-password-123", status: "active" } });
  if (res.status !== 201) throw new Error(`user create failed: ${JSON.stringify(res.body)}`);
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

async function flowId(): Promise<string> {
  return /name="flow_id" value="([^"]+)"/.exec(await (await SELF.fetch(`${BASE}/login`)).text())![1]!;
}

async function postLogin(upn: string, init?: RequestInit): Promise<Response> {
  return SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { ...FORM, "CF-Connecting-IP": "198.51.100.9" },
    body: new URLSearchParams({ flow_id: await flowId(), upn, password: "user-password-123" }).toString(),
    redirect: "manual",
    ...init,
  });
}

/** Stubs outbound fetch for the CF API and Access JWKS hosts; returns what they saw. */
function stubCfApi(handler?: (url: URL, method: string, body?: any) => Response) {
  const calls: { method: string; url: string; body: any }[] = [];
  const real = globalThis.fetch.bind(globalThis);
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const host = new URL(url).hostname;
    if (host !== "api.cloudflare.com" && !host.endsWith(".cloudflareaccess.com")) return real(input as RequestInfo, init);
    let body: unknown;
    try {
      body = init?.body ? JSON.parse(String(init.body)) : undefined;
    } catch {
      body = undefined;
    }
    calls.push({ method: init?.method ?? "GET", url, body });
    if (handler) return handler(new URL(url), init?.method ?? "GET", body);
    return Response.json({ success: true, errors: [], result: { id: "cf-list-1" } });
  });
  return calls;
}

const CONFIG = { accountId: "acct-1", apiToken: "tok-1", team: "", accessAud: "" };

describe("device-cert posture", () => {
  it("deviceCertVerified reads request.cf.tlsClientAuth", () => {
    const req = (cf: unknown) => new Request(BASE, { cf } as RequestInit);
    expect(deviceCertVerified(req({ tlsClientAuth: { certPresented: "1", certVerified: "SUCCESS" } }))).toBe(true);
    expect(deviceCertVerified(req({ tlsClientAuth: { certPresented: "1", certVerified: "FAILED" } }))).toBe(false);
    expect(deviceCertVerified(req({ tlsClientAuth: { certPresented: "0" } }))).toBe(false);
    expect(deviceCertVerified(new Request(BASE))).toBe(false);
  });

  it("a policy with device_cert denies a sign-in that lacks the cert", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUser(apiKey, "ada");
    await env.DB.prepare("UPDATE auth_policies SET device_cert = 1 WHERE is_default = 1").run();

    const res = await postLogin("ada@horizon.test");
    expect(res.headers.get("Location")).toBe("/login?denied=device");
    expect(await (await SELF.fetch(`${BASE}/login?denied=device`)).text()).toContain("managed device");
    expect((await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'login.denied_device_cert'").first())).toBeTruthy();
  });
});

describe("risk-score cap", () => {
  it("riskAtMost orders the levels", () => {
    expect(riskAtMost("high", "medium")).toBe(false);
    expect(riskAtMost("medium", "medium")).toBe(true);
    expect(riskAtMost("low", "medium")).toBe(true);
    expect(riskAtMost(undefined, "low")).toBe(true);
    expect(riskAtMost("high", "")).toBe(true);
  });

  it("denies sign-in when the ZT risk is above the policy cap, passes when the API fails", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUser(apiKey, "ada");
    await saveCfOne(env, CONFIG);
    await env.DB.prepare("UPDATE auth_policies SET max_risk = 'low' WHERE is_default = 1").run();

    stubCfApi((url) => {
      if (url.pathname.endsWith("/access/users")) return Response.json({ success: true, result: [{ id: "zt-user-1" }] });
      if (url.pathname.includes("zt_risk_scoring")) return Response.json({ success: true, result: { risk_level: "high", events: [] } });
      return Response.json({ success: true, result: {} });
    });
    const denied = await postLogin("ada@horizon.test");
    expect(denied.headers.get("Location")).toBe("/login?denied=risk");

    // An API outage must not become a sign-in outage (a second user, so the
    // 5-minute risk cache for ada's email does not answer for this leg).
    await seedUser(apiKey, "bob");
    stubCfApi(() => new Response("down", { status: 500 }));
    const passed = await postLogin("bob@horizon.test");
    expect(passed.headers.get("Location")).not.toBe("/login?denied=risk");
  });
});

describe("risk watchlist", () => {
  it("flags create the system group, follow TTLs, and sweep on expiry", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "ada");

    await flagUser(env, uid, "Suspicious travel", "manual");
    const group = await watchlistGroup(env);
    expect(group).toBeTruthy();
    expect(group!.system).toBe("watchlist");
    expect(await memberOf(group!.id, uid)).toBeTruthy();
    expect((await watchlist(env)).map((w) => w.user_id)).toEqual([uid]);

    // Manual member edits on the system group are refused.
    const { addGroupMembers } = await import("../src/services/groups.js");
    await expect(addGroupMembers({ env, actor: { id: null, upn: "test" }, privileged: true, selfId: null }, group!.id, [uid])).rejects.toThrow(/maintained automatically/);

    // An expired flag drops the member on sweep.
    await env.DB.prepare("UPDATE user_watch SET expires_at = ? WHERE user_id = ?").bind(new Date(Date.now() - 1000).toISOString(), uid).run();
    expect(await sweepWatchlist(env)).toBe(1);
    expect(await watchedUser(env, uid)).toBeNull();
    expect(await memberOf(group!.id, uid)).toBeNull();

    // Clearing a live flag removes the member too.
    await flagUser(env, uid, "again", "auto:fails", 24);
    expect(await memberOf(group!.id, uid)).toBeTruthy();
    await unflagUser(env, uid);
    expect(await memberOf(group!.id, uid)).toBeNull();
  });
});

const memberOf = (groupId: number, userId: number) => env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(groupId, userId).first();

describe("list sync", () => {
  it("creates remote lists and full-replaces their items; a deleted list self-heals", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUser(apiKey, "ada");
    await saveCfOne(env, { ...CONFIG, apiToken: "tok-1" });
    const config = (await getCfOne(env))!;

    // Enable the domain + watchlist syncs; flag someone so the watchlist has an item.
    await apiCall("/api/v1/integrations/cloudflare-one", { token: apiKey, method: "PUT", body: { account_id: "acct-1", lists: ["managed-domains", "watchlist"] } });
    await flagUser(env, (await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id, "test", "manual");

    let next = 0;
    const calls = stubCfApi((url, method) => {
      if (method === "POST" && url.pathname.endsWith("/gateway/lists")) return Response.json({ success: true, result: { id: `list-${++next}` } });
      return Response.json({ success: true, result: {} });
    });
    const r1 = await syncLists(env, config);
    expect(r1.failed).toEqual({});
    expect(new Set(r1.synced)).toEqual(new Set(["watchlist", "managed-domains"]));

    const puts = calls.filter((c) => c.method === "PUT");
    const watchlistPut = puts.find((p) => p.body.items.some((i: { value: string }) => i.value === "ada@horizon.test"));
    expect(watchlistPut).toBeTruthy();
    const domainPut = puts.find((p) => p.body.items.some((i: { value: string }) => i.value === "horizon.test"));
    expect(domainPut).toBeTruthy();

    // Remote list deleted out from under us: the PUT 404s, the row is dropped and recreated.
    const firstRow = (await env.DB.prepare("SELECT cf_list_id FROM cf_lists WHERE key = 'watchlist'").first<{ cf_list_id: string }>())!;
    stubCfApi((url, method) => {
      if (method === "PUT" && url.pathname.includes(firstRow.cf_list_id)) return Response.json({ success: false, errors: [{ message: "not found" }] }, { status: 404 });
      if (method === "POST" && url.pathname.endsWith("/gateway/lists")) return Response.json({ success: true, result: { id: "list-healed" } });
      return Response.json({ success: true, result: {} });
    });
    const r2 = await syncLists(env, config);
    expect(r2.failed).toEqual({});
    expect((await env.DB.prepare("SELECT cf_list_id FROM cf_lists WHERE key = 'watchlist'").first<{ cf_list_id: string }>())!.cf_list_id).toBe("list-healed");
  });

  it("a group with cf_list_sync gets its own email list", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "ada");
    const g = await apiCall("/api/v1/groups", { token: apiKey, body: { name: "Field staff", cf_list_sync: true } });
    expect(g.status).toBe(201);
    await apiCall(`/api/v1/groups/${g.body.id}/members`, { token: apiKey, body: { usernames: ["ada"] } });
    await saveCfOne(env, CONFIG);

    const calls = stubCfApi((url, method) => {
      if (method === "POST" && url.pathname.endsWith("/gateway/lists")) return Response.json({ success: true, result: { id: "grp-list-1" } });
      return Response.json({ success: true, result: {} });
    });
    const r = await syncLists(env, (await getCfOne(env))!);
    expect(r.synced).toContain(`group:${g.body.id}`);
    const created = calls.find((c) => c.method === "POST" && c.body.name === "FlareID: Field staff");
    expect(created).toBeTruthy();
    expect(calls.some((c) => c.method === "PUT" && c.url.includes("grp-list-1") && c.body.items.some((i: { value: string }) => i.value === "ada@horizon.test"))).toBe(true);
    expect(uid).toBeGreaterThan(0);
  });
});

describe("Access JWT on the admin plane", () => {
  it("refuses console requests with no valid JWT once team + AUD are set", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUser(apiKey, "ada");

    // Not configured: the console answers as usual (302 to login).
    expect((await SELF.fetch(`${BASE}/admin`, { redirect: "manual" })).status).toBe(302);

    await saveCfOne(env, { ...CONFIG, team: "testteam", accessAud: "aud-tag-1" });
    const blocked = await SELF.fetch(`${BASE}/admin`, { redirect: "manual" });
    expect(blocked.status).toBe(403);
    expect(await blocked.text()).toContain("Cloudflare Access");

    // A valid JWT for the configured app passes the gate (to the login redirect).
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1" };
    stubCfApi((url) => {
      if (url.hostname === "testteam.cloudflareaccess.com") return Response.json({ keys: [jwk] });
      return Response.json({ success: true, result: {} });
    });
    const jwt = await new SignJWT({ email: "ada@horizon.test" })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer("https://testteam.cloudflareaccess.com")
      .setAudience("aud-tag-1")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);
    const passed = await SELF.fetch(`${BASE}/admin`, { headers: { "Cf-Access-Jwt-Assertion": jwt }, redirect: "manual" });
    expect(passed.status).toBe(302);

    // A JWT for a different application is refused.
    const wrongAud = await new SignJWT({ email: "ada@horizon.test" })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer("https://testteam.cloudflareaccess.com")
      .setAudience("another-app")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);
    expect((await SELF.fetch(`${BASE}/admin`, { headers: { "Cf-Access-Jwt-Assertion": wrongAud }, redirect: "manual" })).status).toBe(403);
  });
});

describe("console and API", () => {
  it("the Cloudflare One page renders and stores settings without returning the token", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();

    const res = await SELF.fetch(`${BASE}/admin/integrations/cf-one`, { headers: { Cookie: cookie } });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Account ID");

    const saved = await SELF.fetch(`${BASE}/admin/integrations/cf-one`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ account_id: "acct-1", api_token: "tok-1", team: "team", access_aud: "", list_watchlist: "1" }).toString(),
      redirect: "manual",
    });
    expect(saved.headers.get("Location")).toContain("saved=1");
    const config = await getCfOne(env);
    expect(config?.accountId).toBe("acct-1");
    expect(config?.apiToken).toBe("tok-1");

    const read = await apiCall("/api/v1/integrations/cloudflare-one", { token: apiKey });
    expect(read.status).toBe(200);
    expect(read.body.account_id).toBe("acct-1");
    expect(read.body.api_token_set).toBe(true);
    expect(JSON.stringify(read.body)).not.toContain("tok-1");
    expect(read.body.lists).toContain("watchlist");
  });

  it("flags and clears users through the API", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUser(apiKey, "ada");

    const flag = await apiCall("/api/v1/users/ada/watch", { token: apiKey, method: "PUT", body: { reason: "Impossible travel" } });
    expect(flag.status).toBe(200);
    expect(await watchedUser(env, (await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id)).toBeTruthy();

    const userPage = await SELF.fetch(`${BASE}/admin/users/${(await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id}`, { headers: { Cookie: await adminCookie() } });
    expect(await userPage.text()).toContain("On watchlist");

    const clear = await apiCall("/api/v1/users/ada/watch", { token: apiKey, method: "DELETE" });
    expect(clear.status).toBe(200);
    const group = await watchlistGroup(env);
    expect(await memberOf(group!.id, (await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id)).toBeNull();
  });
});

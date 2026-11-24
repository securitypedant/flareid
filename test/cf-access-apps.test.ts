import { beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { cfOneClearCaches, configureAccessApp, getCfOne, grantHints, listAccessApps, saveCfOne, syncAccessApps } from "../src/lib/cfone.js";

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

async function makeGroup(apiKey: string, name: string, extra: Record<string, unknown> = {}): Promise<number> {
  const res = await apiCall("/api/v1/groups", { token: apiKey, body: { name, ...extra } });
  if (res.status !== 201) throw new Error(`group create failed: ${JSON.stringify(res.body)}`);
  return res.body.id;
}

const realFetch = globalThis.fetch.bind(globalThis);

/** Stubs outbound fetch for api.cloudflare.com, like cfone.test.ts's. */
function stubCfApi(handler?: (url: URL, method: string, body?: any) => Response) {
  const calls: { method: string; url: string; body: any }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (new URL(url).hostname !== "api.cloudflare.com") return realFetch(input as RequestInfo, init);
    let body: unknown;
    try {
      body = init?.body ? JSON.parse(String(init.body)) : undefined;
    } catch {
      body = undefined;
    }
    calls.push({ method: init?.method ?? "GET", url, body });
    if (handler) return handler(new URL(url), init?.method ?? "GET", body);
    return Response.json({ success: true, errors: [], result: {} });
  });
  return calls;
}

/** A two-app Access account: app-1 policies name a group claim, app-2 selects a reusable Access group. */
function stubAccessApps() {
  return stubCfApi((url) => {
    if (url.pathname.endsWith("/access/apps")) {
      return Response.json({
        success: true,
        result: [
          { id: "cf-app-1", name: "Salesforce", type: "saas", self_hosted_domains: ["salesforce.example.test"], domain: "salesforce.example.test" },
          { id: "cf-app-2", name: "Internal Wiki", type: "self_hosted", self_hosted_domains: ["wiki.internal.test"], domain: "wiki.internal.test" },
        ],
      });
    }
    if (url.pathname.endsWith("/access/apps/cf-app-1/policies")) {
      return Response.json({
        success: true,
        result: [
          { id: "p1", decision: "allow", include: [{ oidc: { group_id: "Salesforce users", identity_provider_id: "idp-1" } }, { saml: { attribute_name: "department", attribute_value: "Denied group", identity_provider_id: "idp-1" } }, { emails: ["vip@example.test"] }] },
          { id: "p2", decision: "deny", include: [{ oidc: { group_id: "Denied group" } }] },
        ],
      });
    }
    if (url.pathname.endsWith("/access/apps/cf-app-2/policies")) {
      return Response.json({ success: true, result: [{ id: "p3", decision: "allow", include: [{ group: { id: "ag-1" } }] }] });
    }
    if (url.pathname.endsWith("/access/groups/ag-1")) {
      return Response.json({ success: true, result: { id: "ag-1", include: [{ oidc: { group_id: "Wiki editors" } }] } });
    }
    return Response.json({ success: true, result: {} });
  });
}

async function configure(apiKey: string) {
  const res = await apiCall("/api/v1/integrations/cloudflare-one", {
    token: apiKey,
    method: "PUT",
    body: { account_id: "acct-1", api_token: "tok-1", team: "tme", access_aud: "" },
  });
  expect(res.status).toBe(200);
}

describe("Access app sync", () => {
  it("pulls apps, infers grant hints from policy group claims and reusable groups", async () => {
    const { apiKey } = await bootstrapInstance();
    await makeGroup(apiKey, "Salesforce users");
    await makeGroup(apiKey, "Wiki editors");
    await makeGroup(apiKey, "Denied group");
    await configure(apiKey);
    stubAccessApps();

    const config = (await getCfOne(env))!;
    const result = await syncAccessApps(env, config);
    expect(result).toEqual({ synced: 2, removed: 0 });

    const apps = await listAccessApps(env);
    expect(apps.map((a) => a.name)).toEqual(["Internal Wiki", "Salesforce"]);
    const sf = apps.find((a) => a.name === "Salesforce")!;
    // Only Allow policies count, and only names that match a FlareID group.
    expect(grantHints(sf)).toEqual(["Salesforce users"]);
    expect(sf.hostname).toBe("salesforce.example.test");
    expect(sf.type).toBe("saas");
    const wiki = apps.find((a) => a.name === "Internal Wiki")!;
    // The reusable Access group's own selectors resolved to the group claim.
    expect(grantHints(wiki)).toEqual(["Wiki editors"]);
  });

  it("keeps the mapping across re-syncs and drops apps that vanished with their pending requests", async () => {
    const { apiKey } = await bootstrapInstance();
    const groupId = await makeGroup(apiKey, "Salesforce users");
    const uid = await seedUser(apiKey, "pat");
    await configure(apiKey);
    stubAccessApps();
    const config = (await getCfOne(env))!;

    await syncAccessApps(env, config);
    const sf = (await listAccessApps(env)).find((a) => a.name === "Salesforce")!;
    await configureAccessApp(env, sf.id, groupId, true);

    // A pending ask for the app before it disappears.
    const cookie = await sessionFor(uid);
    await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ target: `cfapp:${sf.id}`, reason: "please" }).toString(),
      redirect: "manual",
    });

    // Re-sync without Salesforce: the row and its pending request go together.
    stubCfApi((url) => {
      if (url.pathname.endsWith("/access/apps")) {
        return Response.json({ success: true, result: [{ id: "cf-app-2", name: "Internal Wiki", type: "self_hosted", self_hosted_domains: ["wiki.internal.test"] }] });
      }
      if (url.pathname.includes("/policies")) return Response.json({ success: true, result: [] });
      return Response.json({ success: true, result: {} });
    });
    const result = await syncAccessApps(env, config);
    expect(result.removed).toBe(1);
    expect((await listAccessApps(env)).map((a) => a.name)).toEqual(["Internal Wiki"]);
    expect(await env.DB.prepare("SELECT 1 FROM access_requests WHERE target_type = 'cfapp'").first()).toBeNull();
  });
});

describe("Access app mapping", () => {
  it("refuses a dynamic granting group and requestable-without-a-group", async () => {
    const { apiKey } = await bootstrapInstance();
    await makeGroup(apiKey, "Salesforce users");
    const dynId = await makeGroup(apiKey, "Everyone dynamic", { rule: { all: [{ field: "username", op: "eq", value: "nobody" }] } });
    await configure(apiKey);
    stubAccessApps();
    const config = (await getCfOne(env))!;
    await syncAccessApps(env, config);
    const sf = (await listAccessApps(env)).find((a) => a.name === "Salesforce")!;

    await expect(configureAccessApp(env, sf.id, dynId, false)).rejects.toThrow("rule");
    // Requestable without a granting group is refused outright.
    await expect(configureAccessApp(env, sf.id, null, true)).rejects.toThrow("grants this app");
  });
});

describe("Access apps on the launchpad and in requests", () => {
  async function syncedApp(apiKey: string, groupName: string): Promise<{ appId: number; groupId: number }> {
    const groupId = await makeGroup(apiKey, groupName);
    await configure(apiKey);
    stubAccessApps();
    const config = (await getCfOne(env))!;
    await syncAccessApps(env, config);
    const app = (await listAccessApps(env)).find((a) => a.name === "Salesforce")!;
    return { appId: app.id, groupId };
  }

  it("shows the app to granting-group members and hides it from others", async () => {
    const { apiKey } = await bootstrapInstance();
    const { appId, groupId } = await syncedApp(apiKey, "Salesforce users");
    await configureAccessApp(env, appId, groupId, false);
    const member = await seedUser(apiKey, "pat");
    const outsider = await seedUser(apiKey, "sam");
    await apiCall(`/api/v1/groups/${groupId}/members`, { token: apiKey, method: "POST", body: { usernames: ["pat"] } });

    const memberPage = await (await SELF.fetch(`${BASE}/account/applications`, { headers: { Cookie: await sessionFor(member) } })).text();
    expect(memberPage).toContain("Salesforce");
    expect(memberPage).toContain("https://salesforce.example.test");
    const outsiderPage = await (await SELF.fetch(`${BASE}/account/applications`, { headers: { Cookie: await sessionFor(outsider) } })).text();
    expect(outsiderPage).not.toContain("Salesforce");
  });

  it("runs ask -> approve -> granting-group membership, then the card appears", async () => {
    const { apiKey } = await bootstrapInstance();
    const { appId, groupId } = await syncedApp(apiKey, "Salesforce users");
    await configureAccessApp(env, appId, groupId, true);
    const uid = await seedUser(apiKey, "pat");
    const cookie = await sessionFor(uid);

    // The requestable app shows up in the self-service picker.
    const found = (await (await SELF.fetch(`${BASE}/account/access/targets?q=Sales`, { headers: { Cookie: cookie } })).json()) as { id: string; label: string }[];
    expect(found).toEqual([{ id: `cfapp:${appId}`, label: "Salesforce", badges: [{ label: "Access", title: "Access application" }], desc: "Cloudflare Access application - an approved request joins you to the group that grants it" }]);

    const ask = await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ target: `cfapp:${appId}`, reason: "need it" }).toString(),
      redirect: "manual",
    });
    expect(ask.headers.get("Location")).toContain("saved=access-requested");
    const req = await env.DB.prepare("SELECT id FROM access_requests WHERE user_id = ? AND target_type = 'cfapp'").bind(uid).first<{ id: number }>();
    expect(req).toBeTruthy();

    const admin = await adminCookie();
    const queue = await (await SELF.fetch(`${BASE}/admin/access`, { headers: { Cookie: admin } })).text();
    expect(queue).toContain("Salesforce");
    expect(queue).toContain("Access app");

    const approve = await SELF.fetch(`${BASE}/admin/access/requests/${req!.id}`, {
      method: "POST",
      headers: { ...FORM, Cookie: admin },
      body: new URLSearchParams({ decision: "approved" }).toString(),
      redirect: "manual",
    });
    expect(approve.headers.get("Location")).toContain("saved=1");
    expect(await env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(groupId, uid).first()).toBeTruthy();

    const launchpad = await (await SELF.fetch(`${BASE}/account/applications`, { headers: { Cookie: cookie } })).text();
    expect(launchpad).toContain("Salesforce");
  });

  it("refuses requests for unmapped or non-requestable apps", async () => {
    const { apiKey } = await bootstrapInstance();
    const { appId } = await syncedApp(apiKey, "Salesforce users");
    const uid = await seedUser(apiKey, "pat");
    const cookie = await sessionFor(uid);

    // Not requestable (and not mapped): the ask is rejected.
    const ask = await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ target: `cfapp:${appId}`, reason: "need it" }).toString(),
    });
    expect(await ask.text()).toContain("not open to requests");
  });
});

describe("Access apps API", () => {
  it("lists, maps and syncs via the integration API", async () => {
    const { apiKey } = await bootstrapInstance();
    const groupId = await makeGroup(apiKey, "Salesforce users");
    await configure(apiKey);
    stubAccessApps();

    const sync = await apiCall("/api/v1/integrations/cloudflare-one/access-apps/sync", { token: apiKey, method: "POST" });
    expect(sync.status).toBe(200);
    expect(sync.body.synced).toBe(2);

    const list = await apiCall("/api/v1/integrations/cloudflare-one/access-apps", { token: apiKey, method: "GET" });
    expect(list.status).toBe(200);
    const sf = list.body.access_apps.find((a: any) => a.name === "Salesforce");
    expect(sf.grant_hint).toEqual(["Salesforce users"]);
    expect(sf.granting_group_id).toBeNull();

    const patch = await apiCall(`/api/v1/integrations/cloudflare-one/access-apps/${sf.id}`, {
      token: apiKey,
      method: "PATCH",
      body: { granting_group_id: groupId, requestable: true },
    });
    expect(patch.status).toBe(200);
    expect(patch.body.granting_group_id).toBe(groupId);
    expect(patch.body.requestable).toBe(true);
  });
});

describe("disconnect and stale mirrors", () => {
  it("re-pointing or disconnecting drops the mirror and its pending requests", async () => {
    const { apiKey } = await bootstrapInstance();
    const groupId = await makeGroup(apiKey, "Salesforce users");
    const uid = await seedUser(apiKey, "pat");
    await configure(apiKey);
    stubAccessApps();
    const config = (await getCfOne(env))!;
    await syncAccessApps(env, config);
    const sf = (await listAccessApps(env)).find((a) => a.name === "Salesforce")!;
    await configureAccessApp(env, sf.id, groupId, true);

    const cookie = await sessionFor(uid);
    await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ target: `cfapp:${sf.id}` }).toString(),
      redirect: "manual",
    });

    // Pointing at a different account clears the mirror; so does disconnecting.
    const res = await apiCall("/api/v1/integrations/cloudflare-one", {
      token: apiKey,
      method: "PUT",
      body: { account_id: "acct-2", api_token: "tok-2" },
    });
    expect(res.status).toBe(200);
    expect(await listAccessApps(env)).toEqual([]);
    expect(await env.DB.prepare("SELECT 1 FROM access_requests WHERE target_type = 'cfapp'").first()).toBeNull();
  });

  it("a manager of the granting group adds themselves instead of requesting", async () => {
    const { apiKey } = await bootstrapInstance();
    const groupId = await makeGroup(apiKey, "Salesforce users");
    const uid = await seedUser(apiKey, "pat");
    await env.DB.prepare("INSERT INTO group_managers (group_id, user_id, created_at) VALUES (?, ?, ?)").bind(groupId, uid, new Date().toISOString()).run();
    await configure(apiKey);
    stubAccessApps();
    const config = (await getCfOne(env))!;
    await syncAccessApps(env, config);
    const sf = (await listAccessApps(env)).find((a) => a.name === "Salesforce")!;
    await configureAccessApp(env, sf.id, groupId, true);

    const cookie = await sessionFor(uid);
    const ask = await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ target: `cfapp:${sf.id}` }).toString(),
    });
    expect(await ask.text()).toContain("add yourself on its Manage page");
  });
});

describe("sync cadence", () => {
  it("gates the scheduled pull on the configured interval", async () => {
    const { accessAppsSyncDue, accessAppsSyncHours } = await import("../src/lib/cfone.js");
    const { setSetting } = await import("../src/lib/settings.js");
    const { apiKey } = await bootstrapInstance();

    // Never synced -> due immediately; default cadence is 6h.
    expect(await accessAppsSyncHours(env)).toBe(6);
    expect(await accessAppsSyncDue(env)).toBe(true);

    // Fresh stamp -> not due at 6h; is due when the interval shrinks.
    await setSetting(env, "cfone.apps_synced_at", new Date().toISOString());
    expect(await accessAppsSyncDue(env)).toBe(false);
    await setSetting(env, "cfone.apps_synced_at", new Date(Date.now() - 2 * 3600_000).toISOString());
    expect(await accessAppsSyncDue(env)).toBe(false);
    await setSetting(env, "cfone.apps_synced_at", new Date(Date.now() - 7 * 3600_000).toISOString());
    expect(await accessAppsSyncDue(env)).toBe(true);

    // Setting a 1h cadence makes a 2h-old stamp due again.
    await setSetting(env, "cfone.apps_sync_hours", "1");
    await setSetting(env, "cfone.apps_synced_at", new Date(Date.now() - 2 * 3600_000).toISOString());
    expect(await accessAppsSyncHours(env)).toBe(1);
    expect(await accessAppsSyncDue(env)).toBe(true);
    void apiKey;
  });

  it("reads and validates apps_sync_hours on the integration API", async () => {
    const { apiKey } = await bootstrapInstance();
    const put = await apiCall("/api/v1/integrations/cloudflare-one", {
      token: apiKey,
      method: "PUT",
      body: { account_id: "acct-1", api_token: "tok-1", apps_sync_hours: 12 },
    });
    expect(put.status).toBe(200);
    expect(put.body.apps_sync_hours).toBe(12);

    const bad = await apiCall("/api/v1/integrations/cloudflare-one", {
      token: apiKey,
      method: "PUT",
      body: { account_id: "acct-1", apps_sync_hours: 5 },
    });
    expect(bad.status).toBe(400);
  });
});

import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { trustDevice } from "../src/lib/trusted-devices.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const ADMIN_PASSWORD = "test-admin-password-1";

async function kvKeys(prefix: string): Promise<string[]> {
  return (await env.SESSIONS_KV.list({ prefix })).keys.map((k) => k.name);
}

async function flowIdFrom(res: Response): Promise<string> {
  return /name="flow_id" value="([^"]+)"/.exec(await res.text())![1]!;
}

describe("anonymous entry points write nothing", () => {
  it("GET /login and /authorize hand out sealed flows instead of KV entries", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const client = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "rp", redirect_uris: ["https://rp.test/cb"] } });
    const before = await kvKeys("flow:");

    for (let i = 0; i < 5; i++) await SELF.fetch(`${BASE}/login`);
    const authorize = await SELF.fetch(
      `${BASE}/authorize?client_id=${client.body.client_id}&redirect_uri=${encodeURIComponent("https://rp.test/cb")}&response_type=code&scope=openid`
    );
    expect(await flowIdFrom(authorize)).toMatch(/^s\./);
    expect(await kvKeys("flow:")).toEqual(before);
  });

  it("a sealed flow cannot be altered", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const flowId = await flowIdFrom(await SELF.fetch(`${BASE}/login`));
    const [prefix, payload, mac] = flowId.split(".");
    const forged = `${prefix}.${payload!.slice(0, -2)}AA.${mac}`;
    const res = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({ flow_id: forged, upn: "admin@horizon.test", password: ADMIN_PASSWORD }).toString(),
      redirect: "manual",
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("This sign-in has expired");
  });
});

describe("edge flood control", () => {
  it("refuses with 429 once the edge limiter says no, before any handler runs", async () => {
    const no = { limit: async () => ({ success: false }) };
    const ctx = createExecutionContext();
    const page = await worker.fetch(new Request(`${BASE}/login`), { ...env, AUTH_LIMITER: no } as typeof env, ctx);
    const api = await worker.fetch(new Request(`${BASE}/api/v1/status`, { headers: { Authorization: "Bearer flareid_sk_x" } }), { ...env, API_LIMITER: no } as typeof env, ctx);
    await waitOnExecutionContext(ctx);
    expect(page.status).toBe(429);
    expect(page.headers.get("Retry-After")).toBe("60");
    expect(api.status).toBe(429);
    // Refused before the API handler could log a failed key.
    const failed = await env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'api.auth_failed'").first<{ n: number }>();
    expect(failed?.n).toBe(0);
  });

  it("leaves routes outside its groups alone", async () => {
    const no = { limit: async () => ({ success: false }) };
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`${BASE}/.well-known/openid-configuration`), { ...env, AUTH_LIMITER: no, API_LIMITER: no } as typeof env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
  });
});

describe("open redirect", () => {
  it("/login?next= only ever leads to a path on this origin", async () => {
    const { domain } = await bootstrapInstance({ domain: "horizon.test" });
    for (const next of ["https://evil.test/x", "//evil.test/x", "/\\evil.test", "javascript:alert(1)"]) {
      const flowId = await flowIdFrom(await SELF.fetch(`${BASE}/login?next=${encodeURIComponent(next)}`));
      const res = await SELF.fetch(`${BASE}/login`, {
        method: "POST",
        headers: FORM,
        body: new URLSearchParams({ flow_id: flowId, upn: `admin@${domain}`, password: ADMIN_PASSWORD }).toString(),
        redirect: "manual",
      });
      expect(res.headers.get("Location")).toBe("/account");
    }
    const flowId = await flowIdFrom(await SELF.fetch(`${BASE}/login?next=${encodeURIComponent("/admin/users")}`));
    const ok = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({ flow_id: flowId, upn: `admin@${domain}`, password: ADMIN_PASSWORD }).toString(),
      redirect: "manual",
    });
    expect(ok.headers.get("Location")).toBe("/admin/users");
  });
});

describe("API key validation", () => {
  it("rejects an empty scope list and an expiry that is not a future date", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    expect((await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "a", scopes: [] } })).status).toBe(400);
    expect((await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "b", expires_at: "next tuesday" } })).status).toBe(400);
    expect((await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "c", expires_at: "2001-01-01T00:00:00Z" } })).status).toBe(400);
    const ok = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "d", scopes: ["directory:read"], expires_at: "2999-01-01T00:00:00Z" } });
    expect(ok.status).toBe(200);
  });

  it("a key whose stored expiry does not parse is refused rather than immortal", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const minted = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "legacy", scopes: ["directory:read"] } });
    await env.DB.prepare("UPDATE api_keys SET expires_at = 'garbage' WHERE name = 'legacy'").run();
    expect((await apiCall("/api/v1/status", { token: minted.body.token })).status).toBe(401);
  });
});

describe("login gradient", () => {
  it("is validated by the API before anything is applied, and never rendered unvalidated", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const res = await apiCall("/api/v1/setup", {
      token: apiKey,
      body: { app_name: "NOT APPLIED", login_gradient: { from: "red;}</style><script>alert(1)</script>", to: "#000000" } },
    });
    expect(res.status).toBe(400);
    expect((await apiCall("/api/v1/status", { token: apiKey })).body.app_name).not.toBe("NOT APPLIED");

    // A bad value stored directly (e.g. before validation existed) falls back to the default.
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('login_gradient_from', 'red;}</style>', '')").run();
    const page = await (await SELF.fetch(`${BASE}/login`)).text();
    expect(page).not.toContain("red;}</style>");
  });
});

describe("caching", () => {
  it("dynamic responses are no-store; public documents are not", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    expect((await SELF.fetch(`${BASE}/login`)).headers.get("Cache-Control")).toBe("no-store");
    expect((await SELF.fetch(`${BASE}/jwks.json`)).headers.get("Cache-Control")).not.toBe("no-store");
    const logout = await SELF.fetch(`${BASE}/logout`, { method: "POST", headers: FORM, redirect: "manual" });
    // Sign-out redirects straight away: no Clear-Site-Data (it stalled the navigation in Chrome).
    expect(logout.status).toBe(302);
    expect(logout.headers.get("Clear-Site-Data")).toBeNull();
  });
});

describe("user deletion", () => {
  it("succeeds for a user with a remembered device", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "sam", password: "pw-sam-12345", status: "active" }] } });
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'sam'").first<{ id: number }>())!.id;
    await trustDevice(env, new Request(BASE), uid);

    const { setCookie } = await createSession(env, (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id, ["pwd"], new Request(BASE));
    const res = await SELF.fetch(`${BASE}/admin/users/${uid}/delete`, { method: "POST", headers: { ...FORM, Cookie: setCookie.split(";")[0]! }, redirect: "manual" });
    expect(res.status).toBe(302);
    expect(await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(uid).first()).toBeNull();
    expect(domain).toBe("horizon.test");
  });
});

describe("directory import and SCIM", () => {
  it("pushes imported users (disabled ones as inactive) and removes what replace mode deletes", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/scim/config", { token: apiKey, body: { endpoint: "https://scim.test/scim/v2", secret: "x" } });

    const first = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, groups: [{ name: "Staff" }], users: [{ username: "una", password: "pw-una-12345", status: "active", groups: ["Staff"] }] },
    });
    expect(first.status).toBe(200);
    expect(first.body.scim).toMatchObject({ users_pushed: 1, errors: 0 });
    expect((await env.DB.prepare("SELECT scim_id FROM users WHERE username = 'una'").first<{ scim_id: string | null }>())?.scim_id).toBeTruthy();

    const replaced = await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, mode: "replace", users: [], groups: [] } });
    expect(replaced.status).toBe(200);
    expect(replaced.body.scim.users_removed).toBe(1);
    expect(replaced.body.scim.groups_removed).toBe(1);
  });
});

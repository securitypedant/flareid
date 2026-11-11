import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { generateBackupCodes } from "../src/lib/backup-codes.js";
import { createSession } from "../src/lib/sessions.js";
import { purgeExpiredState } from "../src/lib/cleanup.js";

beforeEach(resetDatabase);

const ADMIN_PASSWORD = "test-admin-password-1";
const USER_PASSWORD = "user-password-123";
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function flowId(path = "/login"): Promise<string> {
  const html = await (await SELF.fetch(`${BASE}${path}`)).text();
  return /name="flow_id" value="([^"]+)"/.exec(html)![1]!;
}

async function signIn(upn: string, password: string): Promise<{ cookie: string; res: Response }> {
  const res = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: FORM,
    body: new URLSearchParams({ flow_id: await flowId(), upn, password }).toString(),
    redirect: "manual",
  });
  return { cookie: res.headers.get("Set-Cookie")?.split(";")[0] ?? "", res };
}

async function adminSession(): Promise<{ apiKey: string; cookie: string }> {
  const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
  const { cookie } = await signIn(`admin@${domain}`, ADMIN_PASSWORD);
  return { apiKey, cookie };
}

/** A session for a user straight from the library - for tests about what happens after sign-in. */
async function sessionFor(userId: number): Promise<string> {
  const { setCookie } = await createSession(env, userId, ["pwd", "mfa"], new Request(BASE));
  return setCookie.split(";")[0]!;
}

async function seedUser(apiKey: string, username: string): Promise<number> {
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username, password: USER_PASSWORD, status: "active" }] } });
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

describe("disabling MFA with a backup code", () => {
  it("accepts an unused backup code, so a lost authenticator can be replaced", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "pat");
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE id = ?").bind(uid).run();
    const [code] = await generateBackupCodes(env, uid);
    const cookie = await sessionFor(uid);

    const wrong = await SELF.fetch(`${BASE}/account/mfa/disable`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "code=AAAA-BBBB", redirect: "manual" });
    expect(wrong.headers.get("Location")).toContain("error=mfa-code");

    const res = await SELF.fetch(`${BASE}/account/mfa/disable`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `code=${code}`, redirect: "manual" });
    expect(res.headers.get("Location")).toContain("saved=mfa-disabled");
    const row = await env.DB.prepare("SELECT mfa_enabled, totp_secret FROM users WHERE id = ?").bind(uid).first<{ mfa_enabled: number; totp_secret: string | null }>();
    expect(row).toEqual({ mfa_enabled: 0, totp_secret: null });
  });
});

describe("sign-in error pages", () => {
  it("an expired sign-in shows the branded page, not plain text", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const res = await SELF.fetch(`${BASE}/login/mfa`, { method: "POST", headers: FORM, body: "mfa_id=gone&code=123456" });
    expect(res.status).toBe(400);
    expect(res.headers.get("Content-Type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("This sign-in has expired");
    expect(html).toContain('class="auth-brand"');
    expect(html).toContain('href="/login"');
  });

  it("an app misconfiguration is explained without a pointless retry button", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const res = await SELF.fetch(`${BASE}/authorize?client_id=nope&redirect_uri=https://x.test/cb&response_type=code`);
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("This app can&#039;t sign you in");
    expect(html).not.toContain("Sign in again");
  });
});

describe("cursor trail", () => {
  it("is on by default, can be switched off, and cycles custom characters", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    expect(await (await SELF.fetch(`${BASE}/login`)).text()).toContain('id="cursor-fx"');

    await apiCall("/api/v1/setup", { token: apiKey, body: { cursor_trail: { characters: 'Horizon <Inc>' } } });
    const custom = await (await SELF.fetch(`${BASE}/login`)).text();
    // Split into characters, spaces dropped, and escaped into the attribute.
    expect(custom).toContain(`data-symbols="${'["H","o","r","i","z","o","n","<","I","n","c",">"]'.replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}"`);

    await apiCall("/api/v1/setup", { token: apiKey, body: { cursor_trail: { enabled: false } } });
    expect(await (await SELF.fetch(`${BASE}/login`)).text()).not.toContain('id="cursor-fx"');
  });
});

describe("session limits", () => {
  it("the maximum length applies to existing sessions and sets the cookie lifetime", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "quinn");
    await apiCall("/api/v1/setup", { token: apiKey, body: { session_limits: { max_hours: 2 } } });

    const { setCookie } = await createSession(env, uid, ["pwd"], new Request(BASE));
    expect(setCookie).toContain("Max-Age=7200");
    const cookie = setCookie.split(";")[0]!;
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(200);

    const threeHoursAgo = new Date(Date.now() - 3 * 3600_000).toISOString();
    await env.DB.prepare("UPDATE sessions SET created_at = ? WHERE user_id = ?").bind(threeHoursAgo, uid).run();
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(302);
  });

  it("the inactivity limit ends an unused session, and 0 turns it off", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "riley");
    const cookie = await sessionFor(uid);
    const idleSince = new Date(Date.now() - 20 * 60_000).toISOString();
    await env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE user_id = ?").bind(idleSince, uid).run();

    // No idle limit by default: 20 minutes unused is fine.
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(200);

    await apiCall("/api/v1/setup", { token: apiKey, body: { session_limits: { idle_minutes: 15 } } });
    await env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE user_id = ?").bind(idleSince, uid).run();
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(302);
  });
});

describe("scheduled cleanup of rate-limit counters", () => {
  it("removes only counters older than a week", async () => {
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO rate_limits (key, count, window_start) VALUES ('login:upn:fresh', 3, ?)").bind(now - 60_000),
      env.DB.prepare("INSERT INTO rate_limits (key, count, window_start) VALUES ('login:upn:stale', 3, ?)").bind(now - 8 * 86_400_000),
    ]);
    await purgeExpiredState(env, now);
    const { results } = await env.DB.prepare("SELECT key FROM rate_limits ORDER BY key").all<{ key: string }>();
    expect(results.map((r) => r.key)).toEqual(["login:upn:fresh"]);
  });
});

describe("API key activity in the log", () => {
  it("records every call with its status, and failed keys by prefix only", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const minted = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "reader", scopes: ["directory:read"] } });
    const reader = minted.body.token as string;

    await apiCall("/api/v1/users", { token: reader });
    await apiCall("/api/v1/clients", { token: reader, body: { name: "x", redirect_uris: ["https://x.test"] } }); // 403: no clients:write
    const bogus = "flareid_sk_doesnotexist0000000000000000";
    await apiCall("/api/v1/users", { token: bogus });

    const { results } = await env.DB.prepare(
      "SELECT actor_upn, action, target, details FROM audit_log WHERE action LIKE 'api.%' ORDER BY id"
    ).all<{ actor_upn: string | null; action: string; target: string; details: string }>();
    const reads = results.filter((r) => r.actor_upn === "api-key:reader");
    expect(reads.map((r) => [r.target, JSON.parse(r.details).status])).toEqual([
      ["GET /api/v1/users", 200],
      ["POST /api/v1/clients", 403],
    ]);
    const failed = results.find((r) => r.action === "api.auth_failed")!;
    expect(JSON.parse(failed.details).key_prefix).toBe(bogus.slice(0, 19));
    expect(failed.details).not.toContain(bogus);
  });
});

describe("admin console navigation and pages", () => {
  it("has an Overview link, an Integrations summary and a page per integration, with the old paths redirecting", async () => {
    const { apiKey, cookie } = await adminSession();
    const get = (path: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });

    const overview = await (await get("/admin")).text();
    expect(overview).toMatch(/<a href="\/admin" class="active">Overview<\/a>/);
    // Integrations' own pages are listed only inside Integrations; Overview lists its own.
    expect(overview).not.toContain('href="/admin/integrations/oidc" class="sub');
    expect(overview).toContain('href="/admin/performance" class="sub">Performance');

    await apiCall("/api/v1/clients", { token: apiKey, body: { name: "Cloudflare Access", redirect_uris: ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"] } });
    const summary = await get("/admin/integrations");
    expect(summary.status).toBe(200);
    const summaryHtml = await summary.text();
    expect(summaryHtml).toContain('href="/admin/integrations" class="sub active">Overview');
    expect(summaryHtml).toContain("Cloudflare Access");
    expect(summaryHtml).toContain("1 registered");
    expect(summaryHtml).toContain("test-suite"); // the bootstrap helper's admin key
    expect(summaryHtml).toContain("Not configured"); // SCIM

    for (const [path, title] of [
      ["/admin/integrations/oidc", "OIDC clients"],
      ["/admin/integrations/saml", "SAML apps"],
      ["/admin/integrations/api-keys", "API keys"],
      ["/admin/integrations/scim", "SCIM provisioning"],
    ] as const) {
      const res = await get(path);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain(`<h1>${title}</h1>`);
      expect(html).toContain(`href="${path}" class="sub active"`);
    }

    expect((await get("/admin/scim?x=1")).headers.get("Location")).toBe("/admin/integrations/scim?x=1");
    expect((await get("/admin/clients")).headers.get("Location")).toBe("/admin/integrations/oidc");
  });

  it("filters the log by actor type, action family and date", async () => {
    const { apiKey, cookie } = await adminSession();
    await apiCall("/api/v1/status", { token: apiKey });
    const get = async (query: string) =>
      (await SELF.fetch(`${BASE}/admin/audit?${query}`, { headers: { Cookie: cookie } })).text();

    await apiCall("/api/v1/status", { token: "flareid_sk_revoked000000000000000000" });
    const api = await get("actor=api");
    expect(api).toContain("api.request");
    expect(api).toContain("api.auth_failed");
    expect(api).not.toContain("login.success");

    const people = await get("actor=people&category=login");
    expect(people).toContain("login.success");
    expect(people).not.toContain("api.request");

    const future = await get("from=2999-01-01");
    expect(future).toContain("0 entries match");
  });
});

describe("CSV import endpoint", () => {
  it("imports a chunk with passwords=none: active accounts that cannot sign in until a reset", async () => {
    const { cookie } = await adminSession();
    const res = await SELF.fetch(`${BASE}/admin/users/import`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: BASE, Cookie: cookie },
      body: JSON.stringify({ version: 1, passwords: "none", groups: [{ name: "Ops" }], users: [{ username: "csv.one", status: "active", groups: ["Ops"] }] }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { users: { created: number }; generated_passwords: Record<string, string> };
    expect(body.users.created).toBe(1);
    expect(body.generated_passwords).toEqual({});
    expect((await env.DB.prepare("SELECT password_hash FROM users WHERE username = 'csv.one'").first<{ password_hash: string }>())?.password_hash).toBe("!");
    const attempt = await signIn("csv.one@horizon.test", "");
    expect(attempt.res.headers.get("Set-Cookie")).toBeNull();
  });
});

// Breached-password check (Have I Been Pwned, k-anonymity) and Cloudflare
// Turnstile on the sign-in and recovery forms. Neither test touches the
// network: globalThis.fetch is stubbed here, and vitest.config.ts stands in for
// both services when it is not.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { breachCount, newPasswordError } from "../src/lib/breached-passwords.js";
import { createSession } from "../src/lib/sessions.js";
import { issueAccountToken } from "../src/lib/account-tokens.js";

beforeEach(resetDatabase);
afterEach(() => vi.restoreAllMocks());

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const ADMIN_PASSWORD = "test-admin-password-1";
const BREACHED = "Summer2024!breached";
const SITE_KEY = "1x00000000000000000000AA";
const SECRET = "0x4AAAAAAAsecret-never-shown";

async function sha1(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

const urlOf = (input: RequestInfo | URL) => String(input instanceof Request ? input.url : input);

interface Calls {
  pwned: { url: string; headers: Headers }[];
  siteverify: URLSearchParams[];
}

/**
 * Stubs fetch: the range API answers with padding plus BREACHED (42 times)
 * under its prefix; Siteverify answers with `verify(params)`. Anything else
 * goes to the real fetch (the config's stand-ins).
 */
function stubFetch(verify: (p: URLSearchParams) => Record<string, unknown> | Error = () => ({ success: false, "error-codes": ["invalid-input-response"] })): Calls {
  const calls: Calls = { pwned: [], siteverify: [] };
  const real = globalThis.fetch.bind(globalThis);
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = urlOf(input);
    if (url.startsWith("https://api.pwnedpasswords.com/range/")) {
      calls.pwned.push({ url, headers: new Headers(init?.headers) });
      const prefix = url.slice(-5);
      const hash = await sha1(BREACHED);
      const lines = ["0000000000000000000000000000000000A:0", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3"];
      if (hash.startsWith(prefix)) lines.push(`${hash.slice(5)}:42`);
      return new Response(lines.join("\r\n"));
    }
    if (url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
      const params = new URLSearchParams(String(init?.body ?? ""));
      calls.siteverify.push(params);
      const out = verify(params);
      if (out instanceof Error) throw out;
      return Response.json(out);
    }
    return real(input as RequestInfo, init);
  });
  return calls;
}

const goodToken = (action: string, hostname = "idp.test") => (p: URLSearchParams) =>
  p.get("response") === "good-token" ? { success: true, hostname, action, "error-codes": [] } : { success: false, "error-codes": ["invalid-input-response"] };

async function adminCookie(): Promise<string> {
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
  return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
}

async function flowId(): Promise<string> {
  return /name="flow_id" value="([^"]+)"/.exec(await (await SELF.fetch(`${BASE}/login`)).text())![1]!;
}

async function postLogin(fields: Record<string, string>, ip = "198.51.100.7"): Promise<Response> {
  return SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { ...FORM, "CF-Connecting-IP": ip },
    body: new URLSearchParams({ flow_id: await flowId(), upn: "admin@horizon.test", password: ADMIN_PASSWORD, ...fields }).toString(),
    redirect: "manual",
  });
}

async function auditActions(): Promise<string[]> {
  return (await env.DB.prepare("SELECT action FROM audit_log ORDER BY id").all<{ action: string }>()).results.map((r) => r.action);
}

describe("breached-password check", () => {
  it("sends only the 5-character hash prefix, with padding, and reads the count locally", async () => {
    const calls = stubFetch();
    expect(await breachCount(BREACHED)).toBe(42);
    expect(await breachCount("a-password-nobody-has-used-7f3k")).toBe(0);
    const hash = await sha1(BREACHED);
    expect(calls.pwned[0]!.url).toBe(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`);
    expect(calls.pwned[0]!.headers.get("Add-Padding")).toBe("true");
    expect(calls.pwned[0]!.url).not.toContain(hash.slice(5));
  });

  it("fails open, logging no password, when the service is unreachable or slow", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new DOMException("timed out", "TimeoutError"));
    expect(await breachCount(BREACHED)).toBeNull();
    expect(await newPasswordError(env, BREACHED)).toBeNull();
    const logged = JSON.stringify(warn.mock.calls);
    expect(logged).toContain("breached_password_check_unavailable");
    expect(logged).not.toContain(BREACHED);
    expect(logged).not.toContain((await sha1(BREACHED)).slice(0, 5));
  });

  it("is on by default on a fresh install, and can be switched off (audited)", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    expect((await apiCall("/api/v1/security", { token: apiKey })).body.breached_password_check).toBe(true);
    const off = await apiCall("/api/v1/security/breached-passwords", { token: apiKey, method: "PUT", body: { enabled: false } });
    expect(off.status).toBe(200);
    expect(off.body.breached_password_check).toBe(false);
    expect(await auditActions()).toContain("settings.breached_password_check_changed");
    stubFetch();
    const users = await apiCall("/api/v1/users", { token: apiKey, body: { username: "pat", given_name: "Pat", password: BREACHED } });
    expect(users.status).toBe(201);
  });

  it("refuses breached passwords an administrator sets, through the API and the console", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const calls = stubFetch();
    const create = await apiCall("/api/v1/users", { token: apiKey, body: { username: "pat", given_name: "Pat", password: BREACHED } });
    expect(create.status).toBe(400);
    expect(create.body.message).toBe("This password has appeared in a data breach 42 times; choose another.");
    expect(await env.DB.prepare("SELECT id FROM users WHERE username = 'pat'").first()).toBeNull();

    const ok = await apiCall("/api/v1/users", { token: apiKey, body: { username: "pat", given_name: "Pat", status: "active" } });
    expect(ok.status).toBe(201);
    const asked = calls.pwned.length;
    // A generated password is not checked.
    expect((await apiCall("/api/v1/users/pat/reset-password", { token: apiKey, body: {} })).status).toBe(200);
    expect(calls.pwned.length).toBe(asked);
    const reset = await apiCall("/api/v1/users/pat/reset-password", { token: apiKey, body: { password: BREACHED } });
    expect(reset.status).toBe(400);
    expect(reset.body.message).toContain("data breach 42 times");

    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'pat'").first<{ id: number }>())!.id;
    const res = await SELF.fetch(`${BASE}/admin/users/${id}/reset-password`, {
      method: "POST",
      headers: { ...FORM, Cookie: await adminCookie() },
      body: new URLSearchParams({ password: BREACHED, require_chosen: "1" }).toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("This password has appeared in a data breach 42 times; choose another.");
  });

  it("refuses breached imported passwords", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    stubFetch();
    const r = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "leaky", password: BREACHED, status: "active" }, { username: "fine", password: "a-fine-password-x9", status: "active" }] },
    });
    expect(r.body.errors).toEqual([{ username: "leaky", message: "Password rejected: This password has appeared in a data breach 42 times; choose another." }]);
    expect(await env.DB.prepare("SELECT id FROM users WHERE username = 'leaky'").first()).toBeNull();
    expect(await env.DB.prepare("SELECT id FROM users WHERE username = 'fine'").first()).not.toBeNull();
  });

  it("refuses breached passwords people choose: self-service change and invitation", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "rita", password: "old-password-1", status: "active" }, { username: "nina", status: "disabled" }] } });
    stubFetch();
    const rita = (await env.DB.prepare("SELECT id FROM users WHERE username = 'rita'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, rita, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const change = await SELF.fetch(`${BASE}/account/password`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ current_password: "old-password-1", new_password: BREACHED, confirm_password: BREACHED }).toString(),
      redirect: "manual",
    });
    expect(await change.text()).toContain("appeared in a data breach 42 times");

    const nina = (await env.DB.prepare("SELECT id FROM users WHERE username = 'nina'").first<{ id: number }>())!.id;
    const token = await issueAccountToken(env, nina, "invite");
    const accept = await SELF.fetch(`${BASE}/invite/${token}`, { method: "POST", headers: FORM, body: new URLSearchParams({ password: BREACHED, confirm: BREACHED }).toString() });
    expect(accept.status).toBe(400);
    expect(await accept.text()).toContain("appeared in a data breach 42 times");
    // The link was not used up by the refusal.
    const retry = await SELF.fetch(`${BASE}/invite/${token}`, { method: "POST", headers: FORM, body: new URLSearchParams({ password: "a-fine-password-x9", confirm: "a-fine-password-x9" }).toString() });
    expect(retry.status).toBe(200);
  });

  it("is answered by the test stand-in, not the network, when fetch is not stubbed", async () => {
    // Without the stand-in this would reach Have I Been Pwned, where it is breached.
    expect(await breachCount("password")).toBe(0);
  });
});

describe("Turnstile", () => {
  async function enable(apiKey: string) {
    const r = await apiCall("/api/v1/security/turnstile", { token: apiKey, method: "PUT", body: { mode: "on", site_key: SITE_KEY, secret: SECRET } });
    expect(r.status).toBe(200);
    return r;
  }

  it("is off by default: no widget, no CSP allowance, no check", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    expect((await apiCall("/api/v1/security", { token: apiKey })).body.turnstile).toEqual({ mode: "off", active: false, site_key: "", secret_set: false, secret_from_env: false });
    const page = await SELF.fetch(`${BASE}/login`);
    expect(page.headers.get("Content-Security-Policy")).not.toContain("challenges.cloudflare.com");
    expect(page.headers.get("X-FlareID-Turnstile")).toBeNull();
    expect(await page.text()).not.toContain("challenges.cloudflare.com");
    const calls = stubFetch();
    const res = await postLogin({});
    expect(res.status).toBe(302);
    expect(calls.siteverify).toHaveLength(0);
  });

  it("needs both keys to switch on, and never returns or renders the secret", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const refused = await apiCall("/api/v1/security/turnstile", { token: apiKey, method: "PUT", body: { mode: "on", site_key: SITE_KEY } });
    expect(refused.status).toBe(400);
    const on = await enable(apiKey);
    expect(on.body.turnstile).toEqual({ mode: "on", active: true, site_key: SITE_KEY, secret_set: true, secret_from_env: false });
    expect(JSON.stringify(on.body)).not.toContain(SECRET);
    expect(JSON.stringify((await apiCall("/api/v1/security", { token: apiKey })).body)).not.toContain(SECRET);
    // Changing the mode alone keeps the secret.
    await apiCall("/api/v1/security/turnstile", { token: apiKey, method: "PUT", body: { mode: "off" } });
    expect((await apiCall("/api/v1/security", { token: apiKey })).body.turnstile.secret_set).toBe(true);
    const audit = await env.DB.prepare("SELECT details FROM audit_log WHERE action = 'settings.turnstile_changed'").all<{ details: string }>();
    expect(audit.results.length).toBe(2); // the refused call is not audited
    expect(JSON.stringify(audit.results)).not.toContain(SECRET);
    const consolePage = await (await SELF.fetch(`${BASE}/admin/security`, { headers: { Cookie: await adminCookie() } })).text();
    expect(consolePage).toContain("Bot protection (Turnstile)");
    expect(consolePage).toContain(SITE_KEY);
    expect(consolePage).not.toContain(SECRET);
    expect((await SELF.fetch(`${BASE}/login`)).headers.get("Content-Security-Policy")).not.toContain("challenges.cloudflare.com");
  });

  it("the console saves the keys and refuses switching on without them", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cookie = await adminCookie();
    const post = (fields: Record<string, string>) =>
      SELF.fetch(`${BASE}/admin/security/turnstile`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(fields).toString(), redirect: "manual" });
    expect((await post({ mode: "on", site_key: "", secret: "" })).headers.get("Location")).toContain("error=");
    expect((await post({ mode: "on", site_key: SITE_KEY, secret: SECRET })).headers.get("Location")).toBe("/admin/security?saved=1");
    expect(await (await SELF.fetch(`${BASE}/login`)).text()).toContain(`data-sitekey="${SITE_KEY}"`);
  });

  it("renders the widget, and allows Turnstile in the CSP, only on the pages that show it", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    const page = await SELF.fetch(`${BASE}/login`);
    const csp = page.headers.get("Content-Security-Policy")!;
    expect(csp).toMatch(/script-src [^;]*https:\/\/challenges\.cloudflare\.com/);
    expect(csp).toMatch(/frame-src [^;]*https:\/\/challenges\.cloudflare\.com/);
    expect(csp).not.toContain("cloudflareinsights");
    expect(page.headers.get("X-FlareID-Turnstile")).toBeNull();
    const html = await page.text();
    expect(html).toContain(`data-sitekey="${SITE_KEY}"`);
    expect(html).toContain('data-action="login"');
    expect(html).toContain('data-theme="light"');
    expect(html).toContain('<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=flareidTurnstileReady" async defer></script>');
    expect(html).not.toContain(SECRET);
    // Elsewhere, nothing changes.
    const account = await SELF.fetch(`${BASE}/admin/security`, { headers: { Cookie: await adminCookie() } });
    expect(account.headers.get("Content-Security-Policy")).not.toContain("challenges.cloudflare.com");
    expect((await SELF.fetch(`${BASE}/.well-known/openid-configuration`)).headers.get("Content-Security-Policy")).not.toContain("challenges.cloudflare.com");
  });

  it("refuses a missing or invalid token before the password is checked or counted", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    const calls = stubFetch();
    const before = await auditActions();

    const missing = await postLogin({});
    expect(missing.status).toBe(200);
    expect(missing.headers.get("Set-Cookie")).toBeNull();
    expect(await missing.text()).toContain("Please complete the check and try again.");
    expect(calls.siteverify).toHaveLength(0); // nothing to verify

    const invalid = await postLogin({ "cf-turnstile-response": "forged", password: "wrong-password" });
    expect(await invalid.text()).toContain("Please complete the check and try again.");
    expect(calls.siteverify).toHaveLength(1);

    // No failed sign-in recorded, and the account's failure budget untouched.
    expect((await auditActions()).slice(before.length)).not.toContain("login.failed");
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM rate_limits WHERE key LIKE 'login:%'").first<{ n: number }>())!.n).toBe(0);
  });

  it("a valid token signs in as usual, and Siteverify gets the secret, token, address and an idempotency key", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    const calls = stubFetch(goodToken("login"));
    const res = await postLogin({ "cf-turnstile-response": "good-token" }, "203.0.113.44");
    expect(res.status).toBe(302);
    expect(res.headers.get("Set-Cookie")).toContain("=");
    const p = calls.siteverify[0]!;
    expect(p.get("secret")).toBe(SECRET);
    expect(p.get("response")).toBe("good-token");
    expect(p.get("remoteip")).toBe("203.0.113.44");
    expect(p.get("idempotency_key")).toMatch(/^[0-9a-f-]{36}$/);
    // A wrong password with a valid token is an ordinary failure.
    const wrong = await postLogin({ "cf-turnstile-response": "good-token", password: "wrong-password" });
    expect(await wrong.text()).toContain("Incorrect username/UPN or password.");
    expect(await auditActions()).toContain("login.failed");
  });

  it("refuses a token solved for another hostname or another form", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    stubFetch(goodToken("login", "evil.test"));
    expect(await (await postLogin({ "cf-turnstile-response": "good-token" })).text()).toContain("Please complete the check and try again.");
    vi.restoreAllMocks();
    stubFetch(goodToken("recovery"));
    expect(await (await postLogin({ "cf-turnstile-response": "good-token" })).text()).toContain("Please complete the check and try again.");
  });

  it("fails closed when Siteverify cannot be reached, retrying once with the same key", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const calls = stubFetch(() => new TypeError("network down"));
    expect(await (await postLogin({ "cf-turnstile-response": "good-token" })).text()).toContain("Please complete the check and try again.");
    expect(calls.siteverify).toHaveLength(2);
    expect(calls.siteverify[0]!.get("idempotency_key")).toBe(calls.siteverify[1]!.get("idempotency_key"));
  });

  it("does not challenge passkey sign-in", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    const res = await SELF.fetch(`${BASE}/login/passkey`, { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: await flowId(), attempt: "x", response: "{}" }).toString() });
    const text = await res.text();
    expect(text).toContain("That passkey could not sign you in.");
    expect(text).not.toContain("Please complete the check");
  });

  it("uses the TURNSTILE_SECRET_KEY Worker secret over the stored one", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await enable(apiKey);
    const calls = stubFetch(goodToken("login"));
    const withSecret = { ...env, TURNSTILE_SECRET_KEY: "env-secret-key" } as typeof env;
    const ctx = createExecutionContext();
    const html = await (await worker.fetch(new Request(`${BASE}/login`), withSecret, ctx)).text();
    const flow = /name="flow_id" value="([^"]+)"/.exec(html)![1]!;
    const res = await worker.fetch(
      new Request(`${BASE}/login`, { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: flow, upn: "admin@horizon.test", password: ADMIN_PASSWORD, "cf-turnstile-response": "good-token" }).toString(), redirect: "manual" }),
      withSecret,
      ctx
    );
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(302);
    expect(calls.siteverify[0]!.get("secret")).toBe("env-secret-key");
  });

  describe("password recovery", () => {
    function fakeEmail() {
      const sent: unknown[] = [];
      return { sent, binding: { async send(m: unknown) { sent.push(m); return { messageId: "m" }; } } };
    }
    async function call(email: ReturnType<typeof fakeEmail>, path: string, init: RequestInit = {}) {
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request(`${BASE}${path}`, init), { ...env, EMAIL: email.binding } as unknown as typeof env, ctx);
      await waitOnExecutionContext(ctx);
      return res;
    }

    it("checks the recovery request before anything is looked up or sent", async () => {
      const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
      await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "rita", password: "old-password-1", status: "active", email: "rita@personal.test" }] } });
      await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@horizon.test', '')").run();
      await enable(apiKey);
      const email = fakeEmail();

      const form = await call(email, "/forgot-password");
      expect(form.headers.get("Content-Security-Policy")).toContain("https://challenges.cloudflare.com");
      expect(await form.text()).toContain('data-action="recovery"');

      stubFetch(goodToken("recovery"));
      const refused = await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=rita" });
      expect(refused.status).toBe(400);
      expect(await refused.text()).toContain("Please complete the check and try again.");
      expect(email.sent).toHaveLength(0);
      expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM rate_limits WHERE key LIKE 'recovery:%'").first<{ n: number }>())!.n).toBe(0);

      const ok = await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=rita&cf-turnstile-response=good-token" });
      expect(ok.status).toBe(200);
      expect(await ok.text()).toContain("Check your email");
      expect(email.sent).toHaveLength(1);
    });
  });
});

import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const ADMIN_PASSWORD = "test-admin-password-1";

/** Signs the bootstrap administrator in through the real login form and returns the session cookie. */
async function adminSession(): Promise<string> {
  await bootstrapInstance({ domain: "horizon.test" });
  const page = await (await SELF.fetch(`${BASE}/login`)).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
  const res = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE },
    body: new URLSearchParams({ flow_id: flowId, upn: "admin@horizon.test", password: ADMIN_PASSWORD }).toString(),
    redirect: "manual",
  });
  const cookie = res.headers.get("Set-Cookie")?.split(";")[0];
  if (!cookie) throw new Error(`login failed: HTTP ${res.status}`);
  return cookie;
}

/** A state-changing admin POST that is harmless to repeat. */
function postRetention(cookie: string | null, headers: Record<string, string>) {
  return SELF.fetch(`${BASE}/admin/security/audit-retention`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(cookie ? { Cookie: cookie } : {}), ...headers },
    body: "days=400",
    redirect: "manual",
  });
}

describe("CSRF protection", () => {
  it("accepts a same-origin POST", async () => {
    const cookie = await adminSession();
    expect((await postRetention(cookie, { Origin: BASE })).status).toBe(302);
    expect((await postRetention(cookie, { "Sec-Fetch-Site": "same-origin" })).status).toBe(302);
  });

  it("refuses a cross-site POST, including from a sibling subdomain that SameSite=Lax would let through", async () => {
    const cookie = await adminSession();
    for (const origin of ["https://evil.example", "https://app.idp.test", "http://idp.test", "null"]) {
      expect((await postRetention(cookie, { Origin: origin })).status, origin).toBe(403);
    }
    expect((await postRetention(cookie, { "Sec-Fetch-Site": "same-site" })).status).toBe(403);
    expect((await postRetention(cookie, { "Sec-Fetch-Site": "cross-site" })).status).toBe(403);
    expect((await postRetention(cookie, { Referer: "https://evil.example/page" })).status).toBe(403);
  });

  it("refuses a cookie-bearing POST that says nothing about where it came from", async () => {
    const cookie = await adminSession();
    expect((await postRetention(cookie, {})).status).toBe(403);
  });

  it("refuses login CSRF - a cross-site form posting credentials to /login", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const res = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://evil.example" },
      body: "flow_id=x&upn=admin@horizon.test&password=x",
    });
    expect(res.status).toBe(403);
  });

  it("leaves the machine endpoints alone", async () => {
    const res = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://evil.example" },
      body: "grant_type=authorization_code&code=x&client_id=nope&client_secret=nope",
    });
    // Rejected for its credentials, not by the CSRF check.
    expect(res.status).toBe(401);
  });
});

async function sha256b64(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

/** Asserts a page's CSP allows exactly the inline scripts it contains, and that it has no inline handlers. */
async function expectCspCoversPage(res: Response, label: string) {
  const csp = res.headers.get("Content-Security-Policy") ?? "";
  const html = await res.text();
  expect(csp, label).toContain("frame-ancestors 'none'");
  expect(csp, label).not.toContain("'unsafe-inline' 'sha256");
  const scriptSrc = /script-src ([^;]*)/.exec(csp)?.[1] ?? "";
  expect(scriptSrc, label).not.toContain("unsafe-inline");

  const scripts = [...html.matchAll(/<script(?![^>]*type="application\/json")[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]!);
  expect(scripts.length, label).toBeGreaterThan(0);
  for (const body of scripts) {
    expect(scriptSrc, `${label}: script starting ${JSON.stringify(body.slice(0, 40))}`).toContain(`'sha256-${await sha256b64(body)}'`);
  }
  expect(html, label).not.toMatch(/\son[a-z]+="/);
}

describe("content security policy", () => {
  it("allows exactly the inline scripts on the login page and the admin console", async () => {
    const cookie = await adminSession();
    await expectCspCoversPage(await SELF.fetch(`${BASE}/login?next=/x`), "/login");
    for (const path of ["/admin", "/admin/users", "/admin/groups/new", "/admin/integrations", "/admin/schemas"]) {
      await expectCspCoversPage(await SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie } }), path);
    }
  });

  it("locks non-HTML responses down completely", async () => {
    const res = await SELF.fetch(`${BASE}/api/v1/status`);
    expect(res.headers.get("Content-Security-Policy")).toBe("default-src 'none'; frame-ancestors 'none'");
  });
});

describe("security headers", () => {
  it("sets the standard headers on pages and API responses", async () => {
    for (const path of ["/login", "/api/v1/status", "/.well-known/openid-configuration"]) {
      const res = await SELF.fetch(`${BASE}${path}`);
      expect(res.headers.get("Strict-Transport-Security"), path).toContain("max-age=");
      expect(res.headers.get("X-Content-Type-Options"), path).toBe("nosniff");
      expect(res.headers.get("X-Frame-Options"), path).toBe("DENY");
      expect(res.headers.get("Referrer-Policy"), path).toBe("same-origin");
    }
  });
});

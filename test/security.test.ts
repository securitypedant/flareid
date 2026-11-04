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

// The SCIM endpoint is where the whole directory is pushed under a Bearer
// credential: it must be a validated https URL, never a private address.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { validateScimEndpoint, setScimConfig } from "../src/lib/settings.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

describe("validateScimEndpoint", () => {
  it("accepts an ordinary https endpoint", () => {
    expect(validateScimEndpoint("https://api.cloudflare.com/client/v4/accounts/abc/access/scim")).toBeNull();
  });

  it("refuses cleartext and non-URL schemes", () => {
    for (const u of ["http://scim.example.com", "ftp://scim.example.com", "scim.example.com", "not a url", "https://"])
      expect(validateScimEndpoint(u), u).not.toBeNull();
  });

  it("refuses embedded credentials, query and fragment", () => {
    for (const u of [
      "https://user:pass@scim.example.com",
      "https://scim.example.com/?token=x",
      "https://scim.example.com/#frag",
      "https://user@scim.example.com",
    ])
      expect(validateScimEndpoint(u), u).not.toBeNull();
  });

  it("refuses loopback, private, link-local and mapped literals - in every spelling the URL parser normalizes", () => {
    for (const u of [
      "https://localhost",
      "https://x.localhost",
      "https://127.0.0.1",
      "https://0x7f.0.0.1", // hex loopback
      "https://2130706433", // integer loopback
      "https://[::1]",
      "https://[::ffff:127.0.0.1]",
      "https://[fe80::1]",
      "https://[fd00::1]",
      "https://10.0.0.4",
      "https://172.16.0.9",
      "https://172.15.0.9".replace("172.15", "172.20"), // inside 172.16-31
      "https://192.168.1.1",
      "https://169.254.169.254", // metadata service
      "https://100.64.0.1",
      "https://[::]",
      "https://0.0.0.0",
      "https://224.0.0.1",
    ])
      expect(validateScimEndpoint(u), u).not.toBeNull();
  });

  it("does not false-positive on public names and addresses", () => {
    for (const u of ["https://scim.example.com", "https://8.8.8.8", "https://172.15.0.9", "https://fda.gov", "https://fcuk.example.com", "https://172.32.0.1"])
      expect(validateScimEndpoint(u), u).toBeNull();
  });
});

describe("storing the SCIM endpoint", () => {
  it("setScimConfig refuses an invalid endpoint", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    void apiKey;
    await expect(setScimConfig(env, { endpoint: "http://scim.example.com", secret: "x" })).rejects.toThrow(/https/);
    await expect(setScimConfig(env, { endpoint: "https://169.254.169.254/scim", secret: "x" })).rejects.toThrow(/private|loopback/i);
    // The refused write stores nothing.
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_endpoint'").first<{ value: string }>())?.value ?? "").toBe("");
  });

  it("the API validates the endpoint and keeps the secret on a blank field", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const scim = (await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "scim-mgr", scopes: ["scim:write"] } })).body.token as string;

    const bad = await apiCall("/api/v1/scim/config", { token: scim, body: { endpoint: "http://attacker.example.com", secret: "leak" } });
    expect(bad.status).toBe(400);
    expect(bad.body.message).toMatch(/https/);

    const good = await apiCall("/api/v1/scim/config", { token: scim, body: { endpoint: "https://scim.example.com/v2", secret: "tok-1" } });
    expect(good.status).toBe(200);
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_secret'").first<{ value: string }>())!.value).toBe("tok-1");

    // A blank secret keeps the stored one; clearing the endpoint removes it.
    await apiCall("/api/v1/scim/config", { token: scim, body: { endpoint: "https://scim.example.com/v2", secret: "" } });
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_secret'").first<{ value: string }>())!.value).toBe("tok-1");
    await apiCall("/api/v1/scim/config", { token: scim, body: { endpoint: "" } });
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_secret'").first<{ value: string }>())!.value).toBe("");
  });

  it("the console refuses an invalid endpoint with an inline error", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const res = await SELF.fetch(`${BASE}/admin/scim`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ endpoint: "https://10.0.0.5/scim", secret: "x" }).toString(),
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/admin/integrations/scim?error=");
    // The refused write stores nothing, and the error is shown on the page.
    const page = await (await SELF.fetch(`${BASE}${location}`, { headers: { Cookie: cookie } })).text();
    expect(page).toContain("private");
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_endpoint'").first<{ value: string }>())!.value).toBe("");
  });
});

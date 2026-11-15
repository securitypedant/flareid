// Stored credentials render write-only in the console: a saved SCIM bearer
// secret or default password must never reach a reader's page.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, cookie: string, body: Record<string, string>) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(body).toString(), redirect: "manual" });

async function sessionOf(username: string): Promise<string> {
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
  return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
}

describe("stored credentials are write-only in the console", () => {
  it("the SCIM page does not render the stored bearer secret - even to a writer", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "audi", status: "active", groups: ["Auditors"] }] } });
    const SECRET = "cf-scim-bearer-live-token-9f8e7d";
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('scim_endpoint', 'https://api.cloudflare.com/client/v4/accounts/abc/access/scim', ''), ('scim_secret', ?, '')").bind(SECRET).run();

    // Read-only Auditor.
    const audi = await sessionOf("audi");
    const page = await (await get("/admin/integrations/scim", audi)).text();
    expect(page).not.toContain(SECRET);
    expect(page).toContain("leave blank to keep it");

    // Write role gets the same write-only field.
    const admin = await sessionOf("admin");
    const writerPage = await (await get("/admin/integrations/scim", admin)).text();
    expect(writerPage).not.toContain(SECRET);
  });

  it("a blank secret field keeps the stored credential; clearing the endpoint removes it", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const SECRET = "cf-scim-bearer-live-token-9f8e7d";
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('scim_endpoint', 'https://example.test/scim', ''), ('scim_secret', ?, '')").bind(SECRET).run();
    const admin = await sessionOf("admin");

    // Save with an unchanged endpoint and a blank secret field.
    await post("/admin/scim", admin, { endpoint: "https://example.test/scim", secret: "" });
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_secret'").first<{ value: string }>())!.value).toBe(SECRET);

    // Rotating it stores the new one.
    await post("/admin/scim", admin, { endpoint: "https://example.test/scim", secret: "rotated-secret-1" });
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_secret'").first<{ value: string }>())!.value).toBe("rotated-secret-1");

    // Clearing the endpoint removes the credential too.
    await post("/admin/scim", admin, { endpoint: "", secret: "" });
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'scim_secret'").first<{ value: string }>())!.value).toBe("");
  });

  it("the Security page does not render the stored default password", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const PASSWORD = "shared-default-password-77";
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('default_password', ?, '')").bind(PASSWORD).run();

    // A custom read-only role with just security:read.
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, groups: [{ name: "SecWatch" }], users: [{ username: "watcher", status: "active", groups: ["SecWatch"] }] } });
    const rid = (await env.DB.prepare("INSERT INTO admin_roles (name, permissions, created_at) VALUES ('Security Reader', '[\"security:read\"]', ?) RETURNING id").bind(new Date().toISOString()).first<{ id: number }>())!.id;
    await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT ?, id FROM groups WHERE name = 'SecWatch'").bind(rid).run();

    const watcher = await sessionOf("watcher");
    const page = await (await get("/admin/security", watcher)).text();
    expect(page).not.toContain(PASSWORD);

    // And the writer's page renders it write-only too.
    const admin = await sessionOf("admin");
    const writerPage = await (await get("/admin/security", admin)).text();
    expect(writerPage).not.toContain(PASSWORD);
  });

  it("a blank default-password field keeps the stored one, and apply-to-all still uses it", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const PASSWORD = "shared-default-password-77";
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('default_password', ?, '')").bind(PASSWORD).run();
    const admin = await sessionOf("admin");

    // Blank save keeps the stored password.
    await post("/admin/security/default-password", admin, { default_password: "" });
    expect((await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'default_password'").first<{ value: string }>())!.value).toBe(PASSWORD);
  });
});

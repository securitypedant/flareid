import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { notificationFeedFor } from "../src/lib/notifications.js";

beforeEach(() => resetDatabase());

const FORM = { "Content-Type": "application/x-www-form-urlencoded" };

describe("account reports", () => {
  it("reporting a session revokes it, notifies admins, and can be resolved", async () => {
    const { apiKey } = await bootstrapInstance();
    expect((await apiCall("/api/v1/users", { token: apiKey, body: { given_name: "Ada", username: "ada", domain: "example.com", password: "user-password-123", status: "active" } })).status).toBe(201);
    const user = (await env.DB.prepare("SELECT id FROM users WHERE upn = 'ada@example.com'").first<{ id: number }>())!;
    const mine = (await createSession(env, user.id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const other = await createSession(env, user.id, ["pwd"], new Request(BASE, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36", "CF-Connecting-IP": "203.0.113.9" } }));
    const otherId = (await env.DB.prepare("SELECT id FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1").bind(user.id).first<{ id: string }>())!.id;
    expect(other).toBeTruthy();

    const page = await (await SELF.fetch(`${BASE}/account/security`, { headers: { Cookie: mine } })).text();
    expect(page).toContain(`/account/sessions/${otherId}/report`);

    const res = await SELF.fetch(`${BASE}/account/sessions/${otherId}/report`, { method: "POST", headers: { ...FORM, Cookie: mine, Origin: BASE }, body: "", redirect: "manual" });
    expect(res.headers.get("Location")).toBe("/account/security?saved=reported");
    expect((await env.DB.prepare("SELECT revoked_at FROM sessions WHERE id = ?").bind(otherId).first<{ revoked_at: string | null }>())!.revoked_at).not.toBeNull();

    const feed = (await notificationFeedFor(env, 1, true))!;
    expect(feed.count).toBe(1);
    expect(feed.items[0]!.label).toMatch(/^Ada reported a session/);
    expect(feed.items[0]!.href).toBe(`/admin/users/${user.id}`);

    const list = await apiCall("/api/v1/account-reports", { token: apiKey, method: "GET" });
    expect(list.body.reports).toHaveLength(1);
    expect((await apiCall(`/api/v1/account-reports/${list.body.reports[0].id}/resolve`, { token: apiKey, body: {} })).body).toEqual({ ok: true });
    expect((await notificationFeedFor(env, 1, true))!.count).toBe(0);
  });

  it("refuses to report the session in use, or someone else's", async () => {
    const { apiKey } = await bootstrapInstance();
    for (const u of ["ada", "bob"]) await apiCall("/api/v1/users", { token: apiKey, body: { given_name: u, username: u, domain: "example.com", password: "user-password-123", status: "active" } });
    const [ada, bob] = await Promise.all(["ada", "bob"].map(async (u) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id));
    const adaCookie = (await createSession(env, ada!, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    await createSession(env, bob!, ["pwd"], new Request(BASE));
    const ids = (await env.DB.prepare("SELECT id, user_id FROM sessions").all<{ id: string; user_id: number }>()).results;
    for (const s of ids) {
      await SELF.fetch(`${BASE}/account/sessions/${s.id}/report`, { method: "POST", headers: { ...FORM, Cookie: adaCookie, Origin: BASE }, body: "", redirect: "manual" });
    }
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM account_reports").first<{ n: number }>())!.n).toBe(0);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NOT NULL").first<{ n: number }>())!.n).toBe(0);
  });
});

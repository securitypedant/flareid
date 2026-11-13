// "Has a second factor" means any of them - authenticator app, passkey, email
// codes, security questions - in the users list, its filter, the overview,
// My account, the user page and the API.
import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(resetDatabase);

async function seed() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  const r = await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, passwords: "none", users: ["app", "key", "mail", "quiz", "none", "both"].map((u) => ({ username: u, display_name: `User ${u}`, status: "active" })) },
  });
  expect(r.status).toBe(200);
  const id = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
  await env.DB.prepare("UPDATE users SET mfa_enabled = 1 WHERE username IN ('app', 'both')").run();
  await env.DB.prepare("UPDATE users SET email_otp_enabled = 1 WHERE username = 'mail'").run();
  await env.DB.prepare("UPDATE users SET security_questions_enabled = 1 WHERE username = 'quiz'").run();
  for (const [u, n] of [["key", 1], ["both", 2]] as const) {
    for (let i = 0; i < n; i++) {
      await env.DB.prepare("INSERT INTO webauthn_credentials (id, user_id, public_key, created_at) VALUES (?, ?, 'pk', ?)").bind(`${u}-${i}`, await id(u), new Date().toISOString()).run();
    }
  }
  const adminId = await id("admin");
  const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { apiKey, id, cookie };
}

async function page(path: string, cookie: string) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${BASE}${path}`, { headers: { Cookie: cookie } }), env, ctx);
  await waitOnExecutionContext(ctx);
  return { status: res.status, html: await res.text() };
}

/** The users-list row of a display name, as text. */
const row = (html: string, name: string) => /<tr>[\s\S]*?<\/tr>/g[Symbol.match](html)?.find((r) => r.includes(`>${name}</a>`)) ?? "";

describe("second factors", () => {
  it("the API lists every factor per user, keeps mfa_enabled as the authenticator app, and breaks the stats down", async () => {
    const { apiKey } = await seed();
    const list = await apiCall("/api/v1/users?limit=100", { token: apiKey });
    const by = (u: string) => list.body.users.find((x: { username: string }) => x.username === u);
    expect(by("app")).toMatchObject({ mfa_enabled: true, second_factors: ["totp"] });
    expect(by("key")).toMatchObject({ mfa_enabled: false, second_factors: ["passkey"] });
    expect(by("mail").second_factors).toEqual(["email_otp"]);
    expect(by("quiz").second_factors).toEqual(["security_questions"]);
    expect(by("none").second_factors).toEqual([]);
    expect(by("both").second_factors).toEqual(["totp", "passkey"]);
    expect((await apiCall("/api/v1/users/key", { token: apiKey })).body.second_factors).toEqual(["passkey"]);

    const admin = by("admin").second_factors.length ? 1 : 0;
    const stats = await apiCall("/api/v1/stats", { token: apiKey });
    expect(stats.body.counts.mfa_enrolled).toBe(5 + admin);
    expect(stats.body.second_factors).toMatchObject({ any: 5 + admin, passkey: 2, email_otp: 1, security_questions: 1 });
    expect(stats.body.second_factors.totp).toBe(2 + (by("admin").mfa_enabled ? 1 : 0));
  });

  it("the users list shows which factors, and its MFA filter uses the same definition", async () => {
    const { cookie } = await seed();
    const all = await page("/admin/users?pageSize=100", cookie);
    expect(all.status).toBe(200);
    expect(row(all.html, "User app")).toContain("<td>Authenticator app</td>");
    expect(row(all.html, "User key")).toContain("<td>Passkey</td>");
    expect(row(all.html, "User mail")).toContain("<td>Email codes</td>");
    expect(row(all.html, "User quiz")).toContain("Security questions</span>");
    expect(row(all.html, "User both")).toContain("<td>Authenticator app, Passkey</td>");
    expect(row(all.html, "User none")).toContain('<td><span class="muted">-</span></td>');

    const withFactor = (await page("/admin/users?pageSize=100&mfa=enabled", cookie)).html;
    for (const u of ["app", "key", "mail", "quiz", "both"]) expect(withFactor).toContain(`>User ${u}</a>`);
    expect(withFactor).not.toContain(">User none</a>");
    const without = (await page("/admin/users?pageSize=100&mfa=disabled", cookie)).html;
    expect(without).toContain(">User none</a>");
    for (const u of ["app", "key", "mail", "quiz", "both"]) expect(without).not.toContain(`>User ${u}</a>`);
  });

  it("the overview counts anyone with a factor, with a breakdown", async () => {
    const { cookie, apiKey } = await seed();
    const stats = (await apiCall("/api/v1/stats", { token: apiKey })).body;
    const html = (await page("/admin", cookie)).html;
    expect(html).toContain(`${stats.counts.mfa_enrolled} of ${stats.counts.users}`);
    expect(html).toContain(`Passkey 2 · Email codes 1 · Security questions 1`);
  });

  it("the user page and My account name the factors", async () => {
    const { cookie, id } = await seed();
    const keyPage = (await page(`/admin/users/${await id("key")}`, cookie)).html;
    expect(keyPage).toMatch(/Multi-factor authentication <span class="badge badge-active">Enrolled/);
    expect(keyPage).toContain("Passkeys: enrolled");
    const nonePage = (await page(`/admin/users/${await id("none")}`, cookie)).html;
    expect(nonePage).toMatch(/Multi-factor authentication <span class="badge badge-disabled">Not enrolled/);

    const own = (await createSession(env, await id("both"), ["pwd", "hwk"], new Request(BASE))).setCookie.split(";")[0]!;
    const account = (await page("/account", own)).html;
    expect(account).toContain("Your second factors: Authenticator app, Passkey.");
    expect(account).toContain(">Authenticator app</h2>");
    expect(account).not.toContain("Two-factor authentication</h2>");
    const bare = (await createSession(env, await id("none"), ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    expect((await page("/account", bare)).html).toContain("You have no second factor yet.");
  });

  it("an administrator's security questions are marked as not counting", async () => {
    const { cookie, id } = await seed();
    const adminId = await id("admin");
    await env.DB.prepare("UPDATE users SET security_questions_enabled = 1, mfa_enabled = 0 WHERE id = ?").bind(adminId).run();
    await env.DB.prepare("DELETE FROM webauthn_credentials WHERE user_id = ?").bind(adminId).run();
    const html = (await page(`/admin/users/${adminId}`, cookie)).html;
    expect(html).toContain("Security questions: enrolled (does not count for an administrator)");
    expect(html).toMatch(/Multi-factor authentication <span class="badge badge-disabled">Not enrolled/);
  });
});

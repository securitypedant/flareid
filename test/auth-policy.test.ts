// Authentication policies and factors: per-group requirements, a passkey as
// the second factor after a password, enrolment with a passkey, factor toggles.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { mfaRequiredFor, policyForUser } from "../src/lib/auth-policy.js";
import { SoftAuthenticator } from "./fixtures/soft-authenticator.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const PASSWORD = "Policy-test-pass-1";

async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, groups: [{ name: "Finance" }], users: [{ username: "fin", status: "active", password: PASSWORD, groups: ["Finance"] }, { username: "eng", status: "active", password: PASSWORD }] },
  });
  const id = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
  const adminId = await id("admin");
  const adminCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { apiKey, adminCookie, fin: await id("fin"), eng: await id("eng") };
}

async function passwordLogin(upn: string) {
  const page = await (await SELF.fetch(`${BASE}/login`)).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
  return SELF.fetch(`${BASE}/login`, { method: "POST", headers: FORM, redirect: "manual", body: new URLSearchParams({ flow_id: flowId, upn, password: PASSWORD }).toString() });
}

describe("authentication policies", () => {
  it("applies a group's policy and otherwise the default", async () => {
    const { adminCookie, fin, eng } = await setup();
    const mfa = (await env.DB.prepare("SELECT id FROM auth_policies WHERE requirement = 'mfa'").first<{ id: number }>())!.id;
    const gid = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Finance'").first<{ id: number }>())!.id;
    const save = await SELF.fetch(`${BASE}/admin/security/policies/${mfa}`, {
      method: "POST", headers: { ...FORM, Cookie: adminCookie }, redirect: "manual",
      body: new URLSearchParams({ name: "Password and a second factor", requirement: "mfa", priority: "10", group_ids: String(gid) }).toString(),
    });
    expect(save.status).toBe(302);
    expect(await mfaRequiredFor(env, fin)).toBe(true);
    expect(await mfaRequiredFor(env, eng)).toBe(false);
    expect((await policyForUser(env, eng))!.name).toBe("Password only");

    const finLogin = await passwordLogin("fin@horizon.test");
    expect(finLogin.headers.get("Location")).toMatch(/^\/account\/mfa\/setup\?resume=/);
    const engLogin = await passwordLogin("eng@horizon.test");
    expect(engLogin.headers.get("Location")).not.toContain("/account/mfa/setup");

    const page = await (await SELF.fetch(`${BASE}/admin/security/policies`, { headers: { Cookie: adminCookie } })).text();
    expect(page).toContain("Finance");
  });

  it("asks a passkey-only user for the passkey after the password, and counts it as multi-factor", async () => {
    const { apiKey, fin } = await setup();
    await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
    expect(await mfaRequiredFor(env, fin)).toBe(true);
    const auth = await new SoftAuthenticator().init();
    const cookie = (await createSession(env, fin, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    const reg = await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { "Content-Type": "application/json", Origin: BASE, Cookie: cookie }, body: JSON.stringify({ response: await auth.register(opts.challenge) }) });
    expect(reg.status).toBe(200);

    const step = await passwordLogin("fin@horizon.test");
    expect(step.status).toBe(200);
    const html = await step.text();
    expect(html).toContain("Use a passkey");
    expect(html).not.toContain('name="code"');
    const mfaId = /data-flow="([^"]+)"/.exec(html)![1]!;
    const o = (await (await SELF.fetch(`${BASE}/login/mfa/passkey/options?mfa_id=${encodeURIComponent(mfaId)}`)).json()) as { attempt: string; options: { challenge: string; allowCredentials?: unknown[] } };
    expect(o.options.allowCredentials?.length).toBe(1);
    const done = await SELF.fetch(`${BASE}/login/mfa/passkey`, {
      method: "POST", headers: FORM, redirect: "manual",
      body: new URLSearchParams({ mfa_id: mfaId, attempt: o.attempt, response: JSON.stringify(await auth.assert(o.options.challenge)) }).toString(),
    });
    expect(done.status).toBe(302);
    expect(done.headers.get("Location")).not.toContain("/account/mfa/setup");
    const sid = /__Host-flareid_session=([^;]+)/.exec(done.headers.get("Set-Cookie") ?? "")![1]!;
    expect(JSON.parse((await env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sid).first<{ amr: string }>())!.amr)).toEqual(["pwd", "hwk", "mfa"]);
  });

  it("lets a forced enrolment finish with a passkey, and keeps one factor on while a policy needs it", async () => {
    const { apiKey, adminCookie, fin } = await setup();
    await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
    const cookie = (await createSession(env, fin, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const setupPage = await (await SELF.fetch(`${BASE}/account/mfa/setup`, { headers: { Cookie: cookie } })).text();
    expect(setupPage).toContain('data-done="/account/mfa/passkey-enrolled"');
    const auth = await new SoftAuthenticator().init();
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { "Content-Type": "application/json", Origin: BASE, Cookie: cookie }, body: JSON.stringify({ response: await auth.register(opts.challenge) }) });
    const enrolled = await SELF.fetch(`${BASE}/account/mfa/passkey-enrolled`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "resume=", redirect: "manual" });
    expect(enrolled.status).toBe(302);
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(200);

    const off = (k: string) => SELF.fetch(`${BASE}/admin/security/factors/${k}`, { method: "POST", headers: { ...FORM, Cookie: adminCookie }, body: "enabled=0", redirect: "manual" });
    expect((await off("totp")).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    expect((await off("passkey")).headers.get("Location")).toContain("error=");
    expect(await (await SELF.fetch(`${BASE}/admin/security/factors`, { headers: { Cookie: adminCookie } })).text()).toContain("Security questions");
  });
});

describe("secure defaults", () => {
  it("a fresh install requires a second factor by default, and always for Super Admins", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test", secureDefaults: true });
    const def = await env.DB.prepare("SELECT name, requirement FROM auth_policies WHERE is_default = 1").first<{ name: string; requirement: string }>();
    expect(def).toEqual({ name: "Password and a second factor", requirement: "mfa" });
    const admin = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    expect((await policyForUser(env, admin))!.name).toBe("Password and a second factor");

    // The administrator's first sign-in goes straight to enrolment.
    const page = await (await SELF.fetch(`${BASE}/login`)).text();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
    const login = await SELF.fetch(`${BASE}/login`, { method: "POST", headers: FORM, redirect: "manual", body: new URLSearchParams({ flow_id: flowId, upn: "admin@horizon.test", password: "test-admin-password-1" }).toString() });
    expect(login.headers.get("Location")).toMatch(/^\/account\/mfa\/setup/);

    // Relaxing the default for everyone leaves Super Admins on the MFA policy.
    await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: false } });
    expect((await env.DB.prepare("SELECT requirement FROM auth_policies WHERE is_default = 1").first<{ requirement: string }>())!.requirement).toBe("password");
    expect(await mfaRequiredFor(env, admin)).toBe(true);
  });
});

describe("administrators always need a strong second factor", () => {
  const ADMIN_PASSWORD = "test-admin-password-1";
  const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
  const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
  const sessionOf = async (userId: number, amr: string[]) => (await createSession(env, userId, amr, new Request(BASE))).setCookie.split(";")[0]!;

  /** The default "Password only" policy, a Super Admin ("admin"), a Directory Admin ("dora") and an ordinary user ("eng"). */
  async function adminSetup() {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "dora", status: "active", password: PASSWORD, groups: ["Directory Admins"] }, { username: "eng", status: "active", password: PASSWORD }] },
    });
    const id = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
    return { apiKey, admin: await id("admin"), dora: await id("dora"), eng: await id("eng") };
  }

  async function login(upn: string, password: string, path = "/login") {
    const page = await (await SELF.fetch(`${BASE}${path}`)).text();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
    return SELF.fetch(`${BASE}/login`, { method: "POST", headers: FORM, redirect: "manual", body: new URLSearchParams({ flow_id: flowId, upn, password }).toString() });
  }

  it("sends an administrator's password-only session to enrolment whatever the policy, but not an ordinary user's", async () => {
    const { admin, dora, eng } = await adminSetup();
    for (const uid of [admin, dora, eng]) expect((await policyForUser(env, uid))!.requirement).toBe("password");
    expect(await mfaRequiredFor(env, admin)).toBe(true);
    expect(await mfaRequiredFor(env, dora)).toBe(true);
    expect(await mfaRequiredFor(env, eng)).toBe(false);

    for (const [uid, path] of [[admin, "/admin"], [dora, "/admin/users"], [admin, "/account"], [dora, "/account"]] as const) {
      const res = await get(path, await sessionOf(uid, ["pwd"]));
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/account/mfa/setup");
    }
    expect((await get("/account", await sessionOf(eng, ["pwd"]))).status).toBe(200);

    // Signing in with the password alone parks the administrator at enrolment; the ordinary user goes straight through.
    expect((await login("admin@horizon.test", ADMIN_PASSWORD)).headers.get("Location")).toMatch(/^\/account\/mfa\/setup\?resume=/);
    expect((await login("dora@horizon.test", PASSWORD)).headers.get("Location")).toMatch(/^\/account\/mfa\/setup\?resume=/);
    expect((await login("eng@horizon.test", PASSWORD)).headers.get("Location")).toBe("/account");

    // A multi-factor session opens the console.
    expect((await get("/admin", await sessionOf(admin, ["pwd", "mfa"]))).status).toBe(200);
    expect((await get("/admin/users", await sessionOf(dora, ["pwd", "hwk", "mfa"]))).status).toBe(200);
  });

  it("sends an administrator who has an authenticator but signed in without it back to sign in", async () => {
    const { admin } = await adminSetup();
    await env.DB.prepare("UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?").bind(TOTP_SECRET, admin).run();
    const res = await get("/admin", await sessionOf(admin, ["pwd"]));
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/login?next=%2Fadmin");
    // The sign-in asks for the code.
    const step = await login("admin@horizon.test", ADMIN_PASSWORD);
    expect(step.status).toBe(200);
    const html = await step.text();
    expect(html).toContain('action="/login/mfa"');
    expect(html).toContain('name="mfa_id"');
  });

  it("does not let security questions stand in for an administrator's second factor", async () => {
    const { apiKey, dora, eng } = await adminSetup();
    expect((await apiCall("/api/v1/security/factors/security_questions", { token: apiKey, method: "PUT", body: { enabled: true } })).status).toBe(200);
    const { saveAnswers } = await import("../src/lib/security-questions.js");
    const { results } = await env.DB.prepare("SELECT id FROM security_questions ORDER BY id LIMIT 3").all<{ id: number }>();
    const answers = ["Rex the Dog", "Springfield", "Hill Valley High"].map((answer, i) => ({ questionId: results[i]!.id, answer }));
    await saveAnswers(env, dora, answers);
    await saveAnswers(env, eng, answers);

    // Dora's only factor is security questions: still sent to enrol a stronger one.
    expect((await get("/admin/users", await sessionOf(dora, ["pwd"]))).headers.get("Location")).toBe("/account/mfa/setup");
    expect((await get("/admin/users", await sessionOf(dora, ["pwd", "kba", "mfa"]))).headers.get("Location")).toBe("/account/mfa/setup");
    // The sign-in has no questions step for her...
    const doraLogin = await login("dora@horizon.test", PASSWORD);
    expect(doraLogin.status).toBe(302);
    expect(doraLogin.headers.get("Location")).toMatch(/^\/account\/mfa\/setup\?resume=/);
    // ...while an ordinary user with the same questions is asked them.
    const engLogin = await login("eng@horizon.test", PASSWORD);
    expect(engLogin.status).toBe(200);
    expect(await engLogin.text()).toContain('action="/login/mfa/questions"');
  });

  it("does not let an administrator finish a forced enrolment by posting security questions", async () => {
    const { apiKey, dora } = await adminSetup();
    expect((await apiCall("/api/v1/security/factors/security_questions", { token: apiKey, method: "PUT", body: { enabled: true } })).status).toBe(200);
    const redirectUri = "https://rp.test/callback";
    const client = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "rp", redirect_uris: [redirectUri] } });
    const authorize = `/authorize?${new URLSearchParams({ client_id: client.body.client_id, redirect_uri: redirectUri, response_type: "code", scope: "openid" })}`;

    // Signing in to the app with the password parks her at enrolment, which offers no questions.
    const res = await login("dora@horizon.test", PASSWORD, authorize);
    const location = res.headers.get("Location")!;
    expect(location).toMatch(/^\/account\/mfa\/setup\?resume=/);
    const resume = new URL(location, BASE).searchParams.get("resume")!;
    const cookie = res.headers.get("Set-Cookie")!.split(";")[0]!;
    expect(await (await get(location, cookie)).text()).not.toContain('action="/account/mfa/questions"');

    // Posting questions anyway must not complete the app's sign-in.
    const { results } = await env.DB.prepare("SELECT id FROM security_questions ORDER BY id LIMIT 3").all<{ id: number }>();
    const form = Object.fromEntries(["Rex the Dog", "Springfield", "Hill Valley High"].flatMap((a, i) => [[`question_${i + 1}`, String(results[i]!.id)], [`answer_${i + 1}`, a]]));
    const posted = await SELF.fetch(`${BASE}/account/mfa/questions`, { method: "POST", headers: { ...FORM, Cookie: cookie }, redirect: "manual", body: new URLSearchParams({ ...form, from: "setup", resume }).toString() });
    // Refused outright: an administrator may not set them at all.
    expect(posted.status).toBe(403);
    expect(posted.headers.get("Location")).toBeNull();
    expect(await posted.text()).toContain("available to administrators");
    expect(await env.DB.prepare("SELECT 1 FROM auth_codes").first()).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM user_security_answers").first()).toBeNull();
  });

  it("refuses to turn off the last of the administrators' factors, even with no policy requiring one", async () => {
    const { apiKey, admin } = await adminSetup();
    await env.DB.prepare("UPDATE auth_policies SET requirement = 'password'").run();
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM auth_policies WHERE requirement = 'mfa'").first<{ n: number }>())!.n).toBe(0);
    // Security questions on: they would satisfy the policy guard, but not the administrators' rule.
    expect((await apiCall("/api/v1/security/factors/security_questions", { token: apiKey, method: "PUT", body: { enabled: true } })).status).toBe(200);
    const cookie = await sessionOf(admin, ["pwd", "mfa"]);
    const toggle = (k: string, on: boolean) => SELF.fetch(`${BASE}/admin/security/factors/${k}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `enabled=${on ? 1 : 0}`, redirect: "manual" });

    expect((await toggle("passkey", false)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    expect((await toggle("email_otp", false)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    const refused = await toggle("totp", false);
    expect(refused.headers.get("Location")).toContain("error=Administrators%20always%20need%20a%20second%20factor");
    expect((await apiCall("/api/v1/security/factors/totp", { token: apiKey, method: "PUT", body: { enabled: false } })).status).toBe(400);
    const { isFactorEnabled } = await import("../src/lib/auth-policy.js");
    expect(await isFactorEnabled(env, "totp")).toBe(true);
    // With passkeys back on, the authenticator app can go.
    expect((await toggle("passkey", true)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    expect((await toggle("totp", false)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
  });

  it("shows each administrator's second factor on the Roles page", async () => {
    const { admin, dora } = await adminSetup();
    await env.DB.prepare("UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?").bind(TOTP_SECRET, dora).run();
    const html = await (await get("/admin/security/roles", await sessionOf(admin, ["pwd", "mfa"]))).text();
    expect(html).toContain("<th>Second factor</th>");
    const rowOf = (uid: number) => {
      const start = html.indexOf(`<tr><td><a href="/admin/users/${uid}">`);
      expect(start).toBeGreaterThan(-1);
      return html.slice(start, html.indexOf("</tr>", start));
    };
    expect(rowOf(admin)).toContain('<span class="badge badge-disabled">None</span>');
    expect(rowOf(admin)).toContain("Must set one up at their next sign-in");
    expect(rowOf(dora)).toContain("Authenticator app");
    expect(rowOf(dora)).not.toContain(">None<");
  });
});

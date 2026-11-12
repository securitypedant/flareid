// Email one-time codes as a second factor: enrolment from My account and the
// forced-enrolment page, the sign-in step, the code's limits, the factor
// switch, policies, the administrator's reset and user deletion.
import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { secondFactorGate } from "../src/lib/auth-policy.js";
import { storePendingMfa } from "../src/lib/authorize-state.js";
import { accountScope, sendEmailOtp, verifyEmailOtp } from "../src/lib/email-otp.js";
import type { UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const PASSWORD = "Email-otp-pass-1";

type Sent = { to: string; subject: string; text: string; html: string; from: unknown };

/** A stand-in for the send_email binding that keeps what it was asked to send. */
function fakeEmail() {
  const sent: Sent[] = [];
  return {
    sent,
    binding: {
      async send(message: Sent) {
        sent.push(message);
        return { messageId: `msg-${sent.length}` };
      },
    },
    /** The code in the latest email (on a line of its own in the text part). */
    lastCode(): string {
      return /^(\d{6})$/m.exec(sent[sent.length - 1]!.text)![1]!;
    },
  };
}

type Email = ReturnType<typeof fakeEmail>;

/** Calls the Worker with the fake email binding (or with none, for "email not configured"). */
async function call(email: Email | null, path: string, init: RequestInit = {}) {
  const ctx = createExecutionContext();
  const bindings = email ? { ...env, EMAIL: email.binding } : env;
  const res = await worker.fetch(new Request(`${BASE}${path}`, { redirect: "manual", ...init }), bindings as unknown as typeof env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

const post = (email: Email | null, path: string, form: Record<string, string>, cookie?: string) =>
  call(email, path, { method: "POST", headers: { ...FORM, ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(form).toString() });

const wrongCode = (code: string) => (code === "123456" ? "654321" : "123456");

async function setup(opts: { requireMfa?: boolean } = {}) {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, users: [{ username: "rita", password: PASSWORD, status: "active", email: "rita@personal.test" }] },
  });
  if (opts.requireMfa) await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
  await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@horizon.test', '')").run();
  const id = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
  const adminId = await id("admin");
  const rita = await id("rita");
  const adminCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { apiKey, adminCookie, rita };
}

async function factor(email: Email | null, adminCookie: string, key: string, on: boolean) {
  return post(email, `/admin/security/factors/${key}`, { enabled: on ? "1" : "0" }, adminCookie);
}

async function enrolDirectly(userId: number) {
  await env.DB.prepare("UPDATE users SET email_otp_enabled = 1 WHERE id = ?").bind(userId).run();
}

async function userRow(id: number): Promise<UserRow> {
  return (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>())!;
}

/** Password step; returns the response and, when a second step is shown, its mfa id. */
async function passwordStep(email: Email | null) {
  const page = await (await call(email, "/login")).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
  const res = await post(email, "/login", { flow_id: flowId, upn: "rita", password: PASSWORD });
  const html = res.status === 200 ? await res.text() : "";
  return { res, html, mfaId: /name="mfa_id" value="([^"]+)"/.exec(html)?.[1] };
}

const sessionIdOf = (res: Response) => /__Host-flareid_session=([^;]+)/.exec(res.headers.get("Set-Cookie") ?? "")?.[1];
const amrOf = async (sid: string) => JSON.parse((await env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sid).first<{ amr: string }>())!.amr) as string[];

describe("email one-time codes", () => {
  it("enrols from My account and signs in with the password and an emailed code", async () => {
    const { adminCookie, rita } = await setup();
    const email = fakeEmail();
    expect((await factor(email, adminCookie, "email_otp", true)).headers.get("Location")).toBe("/admin/security/factors?saved=1");

    const cookie = (await createSession(env, rita, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const accountPage = await (await call(email, "/account", { headers: { Cookie: cookie } })).text();
    expect(accountPage).toContain("Email codes");
    expect(accountPage).toContain("Send a code to rita@personal.test");

    const send = await post(email, "/account/mfa/email/send", { purpose: "enrol" }, cookie);
    expect(send.headers.get("Location")).toContain("email_code=enrol");
    expect(email.sent).toHaveLength(1);
    expect(email.sent[0]!.to).toBe("rita@personal.test");
    const code = email.lastCode();
    expect(email.sent[0]!.subject).toContain(code); // the Sign-in code template
    expect(email.sent[0]!.text).toContain("10 minutes");
    expect(await (await call(email, "/account?email_code=enrol", { headers: { Cookie: cookie } })).text()).toContain('action="/account/mfa/email/enable"');

    const wrong = await post(email, "/account/mfa/email/enable", { code: wrongCode(code) }, cookie);
    expect(wrong.headers.get("Location")).toContain("error=email-code");
    expect((await userRow(rita)).email_otp_enabled).toBe(0);
    const ok = await post(email, "/account/mfa/email/enable", { code }, cookie);
    expect(ok.headers.get("Location")).toBe("/account?saved=email-otp-enabled");
    expect((await userRow(rita)).email_otp_enabled).toBe(1);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.email_otp_enabled'").first()).not.toBeNull();

    // Sign-in: email codes are the only factor, so the step is email-only.
    const step = await passwordStep(email);
    expect(step.res.status).toBe(200);
    expect(step.html).toContain("Email me a code");
    expect(step.html).toContain('action="/login/mfa/email/send"');
    expect(step.html).not.toContain('name="code"');
    const sent = await post(email, "/login/mfa/email/send", { mfa_id: step.mfaId! });
    const sentHtml = await sent.text();
    expect(sentHtml).toContain("Check your email");
    expect(sentHtml).toContain("r***@personal.test"); // masked: a password alone must not reveal the address
    expect(sentHtml).not.toContain("rita@personal.test");
    const loginCode = email.lastCode();

    const done = await post(email, "/login/mfa/email", { mfa_id: step.mfaId!, code: loginCode });
    expect(done.status).toBe(302);
    expect(done.headers.get("Location")).toBe("/account");
    expect(await amrOf(sessionIdOf(done)!)).toEqual(["pwd", "otp", "mfa"]);
    // Single use: the pending step is gone with it.
    expect((await post(email, "/login/mfa/email", { mfa_id: step.mfaId!, code: loginCode })).status).toBe(400);

    // Sends are audited; the code itself is never written anywhere in the log.
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'login.email_otp_sent'").first()).not.toBeNull();
    for (const c of [code, loginCode]) {
      expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE instr(COALESCE(details, ''), ?) > 0 OR instr(COALESCE(target, ''), ?) > 0").bind(c, c).first()).toBeNull();
    }
  });

  it("invalidates a code after five wrong guesses, and refuses expired and used codes", async () => {
    const { adminCookie, rita } = await setup();
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);
    await enrolDirectly(rita);
    // A generous per-user MFA budget, so the per-code limit is what is tested.
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('rate_limit_max_attempts', '50', '')").run();

    const { mfaId } = await passwordStep(email);
    await post(email, "/login/mfa/email/send", { mfa_id: mfaId! });
    const code = email.lastCode();
    for (let i = 1; i <= 5; i++) {
      const html = await (await post(email, "/login/mfa/email", { mfa_id: mfaId!, code: wrongCode(code) })).text();
      expect(html).toContain(i < 5 ? "Incorrect code" : "Too many incorrect codes");
    }
    expect(await (await post(email, "/login/mfa/email", { mfa_id: mfaId!, code })).text()).toContain("expired or was already used");
    const failures = await env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'login.mfa_failed' AND details LIKE '%email_otp%'").first<{ n: number }>();
    expect(failures!.n).toBe(6);

    // A new code works again - until it expires.
    await post(email, "/login/mfa/email/send", { mfa_id: mfaId! });
    const fresh = email.lastCode();
    const key = `emailotp:login:${mfaId}`;
    const record = JSON.parse((await env.SESSIONS_KV.get(key))!) as { expiresAt: number };
    await env.SESSIONS_KV.put(key, JSON.stringify({ ...record, expiresAt: Date.now() - 1000 }));
    expect(await (await post(email, "/login/mfa/email", { mfa_id: mfaId!, code: fresh })).text()).toContain("expired or was already used");

    // Used once, never again (checked at the code store directly).
    const withEmail = { ...env, EMAIL: email.binding } as unknown as typeof env;
    const scope = accountScope("test-session");
    expect((await sendEmailOtp(withEmail, await userRow(rita), scope, "enrol", "FlareID")).ok).toBe(true);
    const once = email.lastCode();
    expect(await verifyEmailOtp(withEmail, scope, rita, "disable", once)).toBe("expired"); // wrong purpose
    expect(await verifyEmailOtp(withEmail, scope, rita, "enrol", once)).toBe("ok");
    expect(await verifyEmailOtp(withEmail, scope, rita, "enrol", once)).toBe("expired");
  });

  it("limits how many codes are sent", async () => {
    const { adminCookie, rita } = await setup();
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);
    await enrolDirectly(rita);
    const { mfaId } = await passwordStep(email);
    for (let i = 0; i < 5; i++) expect(await (await post(email, "/login/mfa/email/send", { mfa_id: mfaId! })).text()).toContain("Check your email");
    expect(await (await post(email, "/login/mfa/email/send", { mfa_id: mfaId! })).text()).toContain("Too many codes requested");
    expect(email.sent).toHaveLength(5);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'login.email_otp_rate_limited'").first()).not.toBeNull();

    // Both email-code endpoints are sign-in steps for the edge limiter, too.
    const no = { limit: async () => ({ success: false }) };
    for (const path of ["/login/mfa/email/send", "/login/mfa/email"]) {
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request(`${BASE}${path}`, { method: "POST", headers: FORM, body: `mfa_id=${mfaId}` }), { ...env, EMAIL: email.binding, AUTH_LIMITER: no } as unknown as typeof env, ctx);
      expect(res.status).toBe(429);
    }
  });

  it("is not offered while the factor is off or email is not configured", async () => {
    const { adminCookie, rita } = await setup();
    const email = fakeEmail();
    await enrolDirectly(rita);

    // Off by default, even with email configured.
    const factors = await (await call(email, "/admin/security/factors", { headers: { Cookie: adminCookie } })).text();
    expect(factors).toContain("Email one-time code");
    let step = await passwordStep(email);
    expect(step.res.status).toBe(302); // no second step: the password policy is enough and no factor is in use
    const cookie = (await createSession(env, rita, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    expect(await (await call(email, "/account", { headers: { Cookie: cookie } })).text()).not.toContain("Email codes");
    const mfaId = await storePendingMfa(env, rita, "s.unused");
    expect((await post(email, "/login/mfa/email/send", { mfa_id: mfaId })).status).toBe(400);
    expect(email.sent).toHaveLength(0);

    // Without email it cannot be switched on, and the page says why.
    expect((await factor(null, adminCookie, "email_otp", true)).headers.get("Location")).toContain("error=");
    expect(await (await call(null, "/admin/security/factors", { headers: { Cookie: adminCookie } })).text()).toContain("Needs email to be configured first");

    // On, but email went away: not offered either.
    await factor(email, adminCookie, "email_otp", true);
    step = await passwordStep(null);
    expect(step.res.status).toBe(302);
    step = await passwordStep(email);
    expect(step.html).toContain("Email me a code");
  });

  it("counts as a second factor for a policy that requires one", async () => {
    const { adminCookie, rita } = await setup({ requireMfa: true });
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);

    const withEmail = { ...env, EMAIL: email.binding } as unknown as typeof env;
    expect(await secondFactorGate(withEmail, await userRow(rita), ["pwd"])).toBe("enrol");
    await enrolDirectly(rita);
    expect(await secondFactorGate(withEmail, await userRow(rita), ["pwd"])).toBe("login");
    expect(await secondFactorGate(withEmail, await userRow(rita), ["pwd", "otp", "mfa"])).toBe("ok");

    const { mfaId } = await passwordStep(email);
    await post(email, "/login/mfa/email/send", { mfa_id: mfaId! });
    const done = await post(email, "/login/mfa/email", { mfa_id: mfaId!, code: email.lastCode() });
    expect(done.headers.get("Location")).toBe("/account");

    // The last-factor guard counts email codes: TOTP and passkeys can go while they are on...
    expect((await factor(email, adminCookie, "totp", false)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    expect((await factor(email, adminCookie, "passkey", false)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    // ...but they cannot be the last one switched off.
    expect((await factor(email, adminCookie, "email_otp", false)).headers.get("Location")).toContain("error=");
    // And once switched off, they no longer count: enrolment is needed again.
    await factor(email, adminCookie, "totp", true);
    await factor(email, adminCookie, "email_otp", false);
    expect(await secondFactorGate(withEmail, await userRow(rita), ["pwd"])).toBe("enrol");
  });

  it("finishes a forced enrolment with email codes and resumes the sign-in", async () => {
    const { adminCookie, rita } = await setup({ requireMfa: true });
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);
    const other = await createSession(env, rita, ["pwd"], new Request(BASE));

    const { res } = await passwordStep(email);
    const location = res.headers.get("Location")!;
    expect(location).toMatch(/^\/account\/mfa\/setup\?resume=/);
    const resume = new URL(location, BASE).searchParams.get("resume")!;
    const cookie = `__Host-flareid_session=${sessionIdOf(res)}`;

    const setupPage = await (await call(email, location, { headers: { Cookie: cookie } })).text();
    expect(setupPage).toContain("Or use email codes");
    expect(setupPage).toContain('name="from" value="setup"');

    const send = await post(email, "/account/mfa/email/send", { purpose: "enrol", from: "setup", resume }, cookie);
    expect(send.headers.get("Location")).toBe(`/account/mfa/setup?resume=${resume}&email_code=enrol`);
    expect(await (await call(email, send.headers.get("Location")!, { headers: { Cookie: cookie } })).text()).toContain('action="/account/mfa/email/enable"');

    const done = await post(email, "/account/mfa/email/enable", { code: email.lastCode(), from: "setup", resume }, cookie);
    expect(done.headers.get("Location")).toBe("/account");
    expect(await amrOf(sessionIdOf(res)!)).toEqual(["pwd", "otp", "mfa"]);
    expect((await env.DB.prepare("SELECT revoked_at FROM sessions WHERE id = ?").bind(other.sessionId).first<{ revoked_at: string | null }>())!.revoked_at).not.toBeNull();
    expect((await call(email, "/account", { headers: { Cookie: cookie } })).status).toBe(200);
  });

  it("turning email codes off needs a fresh code", async () => {
    const { adminCookie, rita } = await setup();
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);
    await enrolDirectly(rita);
    const cookie = (await createSession(env, rita, ["pwd", "otp", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    expect(await (await call(email, "/account", { headers: { Cookie: cookie } })).text()).toContain("Turn off");

    // No code sent: refused, and counted as a failed step-up.
    expect((await post(email, "/account/mfa/email/disable", { code: "123456" }, cookie)).headers.get("Location")).toContain("error=email-code");
    expect((await userRow(rita)).email_otp_enabled).toBe(1);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.step_up_failed' AND details LIKE '%email_otp_disable%'").first()).not.toBeNull();

    expect((await post(email, "/account/mfa/email/send", { purpose: "disable" }, cookie)).headers.get("Location")).toContain("email_code=disable");
    const off = await post(email, "/account/mfa/email/disable", { code: email.lastCode() }, cookie);
    expect(off.headers.get("Location")).toBe("/account?saved=email-otp-disabled");
    expect((await userRow(rita)).email_otp_enabled).toBe(0);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.email_otp_disabled'").first()).not.toBeNull();
  });

  it("an administrator's MFA reset clears it, in the console and the API", async () => {
    const { apiKey, adminCookie, rita } = await setup();
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);
    await enrolDirectly(rita);

    expect(await (await call(email, `/admin/users/${rita}`, { headers: { Cookie: adminCookie } })).text()).toContain("Email codes: enrolled");
    expect((await apiCall("/api/v1/users/rita", { token: apiKey })).body.email_otp_enabled).toBe(true);
    expect((await post(email, `/admin/users/${rita}/reset-mfa`, {}, adminCookie)).status).toBe(302);
    expect((await userRow(rita)).email_otp_enabled).toBe(0);

    await enrolDirectly(rita);
    expect((await apiCall("/api/v1/users/rita/reset-mfa", { token: apiKey, method: "POST" })).status).toBe(200);
    expect((await userRow(rita)).email_otp_enabled).toBe(0);
    expect((await apiCall("/api/v1/users/rita", { token: apiKey })).body.email_otp_enabled).toBe(false);
  });

  it("deleting the user removes their email-code state", async () => {
    const { apiKey, adminCookie, rita } = await setup();
    const email = fakeEmail();
    await factor(email, adminCookie, "email_otp", true);
    await enrolDirectly(rita);
    const { mfaId } = await passwordStep(email);
    await post(email, "/login/mfa/email/send", { mfa_id: mfaId! });
    const code = email.lastCode();
    expect(await env.DB.prepare("SELECT 1 FROM rate_limits WHERE key = ?").bind(`email_otp:send:${rita}`).first()).not.toBeNull();

    expect((await apiCall("/api/v1/users/rita", { token: apiKey, method: "DELETE" })).status).toBe(200);
    expect(await env.DB.prepare("SELECT 1 FROM rate_limits WHERE key = ?").bind(`email_otp:send:${rita}`).first()).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE id = ?").bind(rita).first()).toBeNull();
    // The outstanding code cannot finish a sign-in for the deleted account.
    expect((await post(email, "/login/mfa/email", { mfa_id: mfaId!, code })).status).toBe(400);
  });
});

describe("admin step-up with email codes", () => {
  it("asks an administrator whose only factor is email codes for one, not just the password", async () => {
    const { adminCookie: _fresh } = await setup();
    const email = fakeEmail();
    await factor(email, _fresh, "email_otp", true);
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    await env.DB.prepare("UPDATE users SET email_otp_enabled = 1, email = 'admin@personal.test' WHERE id = ?").bind(adminId).run();
    const { setCookie, sessionId } = await createSession(env, adminId, ["pwd", "otp", "mfa"], new Request(BASE));
    const cookie = setCookie.split(";")[0]!;
    await env.DB.prepare("UPDATE sessions SET created_at = ? WHERE id = ?").bind(new Date(Date.now() - 30 * 60 * 1000).toISOString(), sessionId).run();
    const next = "/admin/integrations/api-keys";

    const page = await (await call(email, `/admin/reauth?next=${encodeURIComponent(next)}`, { headers: { Cookie: cookie } })).text();
    expect(page).toContain('name="email_code"');
    expect(page).toContain("Email me a code");

    // The password alone no longer confirms.
    const pwOnly = await post(email, "/admin/reauth", { password: "test-admin-password-1", next }, cookie);
    expect(pwOnly.headers.get("Location")).toContain("error=");
    expect((await env.DB.prepare("SELECT stepped_up_at FROM sessions WHERE id = ?").bind(sessionId).first<{ stepped_up_at: string | null }>())!.stepped_up_at).toBeNull();

    const sent = await post(email, "/admin/reauth/email/send", { next }, cookie);
    expect(sent.headers.get("Location")).toContain("sent=");
    expect(sent.headers.get("Location")).not.toContain("admin%40personal.test");
    const code = email.lastCode();
    expect((await post(email, "/admin/reauth", { password: "test-admin-password-1", email_code: wrongCode(code), next }, cookie)).headers.get("Location")).toContain("error=");
    const ok = await post(email, "/admin/reauth", { password: "test-admin-password-1", email_code: code, next }, cookie);
    expect(ok.headers.get("Location")).toBe(next);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'admin.step_up' AND details LIKE '%email_otp%'").first()).not.toBeNull();
  });
});

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
    expect(await (await SELF.fetch(`${BASE}/admin/security/factors`, { headers: { Cookie: adminCookie } })).text()).toContain("Planned");
  });
});

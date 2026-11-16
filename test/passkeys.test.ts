// Passkeys end to end with a software authenticator: register from /account,
// sign in with no username, counter replay refused, removal.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { b64u, SoftAuthenticator } from "./fixtures/soft-authenticator.js";

beforeEach(resetDatabase);

/** An ordinary user with a password-only session (an administrator would be sent to set up a second factor first). */
async function signedIn() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "pat", password: "user-password-123", status: "active" }] } });
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'pat'").first<{ id: number }>())!.id;
  return { id, cookie: (await createSession(env, id, ["pwd"], new Request(BASE))).setCookie.split(";")[0]! };
}
const JSON_POST = { "Content-Type": "application/json", Origin: BASE };

async function passkeyLogin(auth: SoftAuthenticator, counter?: number) {
  const page = await (await SELF.fetch(`${BASE}/login`)).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
  const opts = (await (await SELF.fetch(`${BASE}/login/passkey/options?flow_id=${encodeURIComponent(flowId)}`)).json()) as { attempt: string; options: { challenge: string } };
  const response = await auth.assert(opts.options.challenge, counter);
  return SELF.fetch(`${BASE}/login/passkey`, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE },
    body: new URLSearchParams({ flow_id: flowId, attempt: opts.attempt, response: JSON.stringify(response) }).toString(),
  });
}

describe("passkeys", () => {
  it("registers from /account, signs in without a username as multi-factor, and refuses a replayed counter", async () => {
    const { id, cookie } = await signedIn();
    const auth = await new SoftAuthenticator().init();
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    const reg = await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ name: "Laptop", response: await auth.register(opts.challenge) }) });
    expect(await reg.json()).toEqual({ ok: true });
    expect((await env.DB.prepare("SELECT name FROM webauthn_credentials WHERE user_id = ?").bind(id).first<{ name: string }>())!.name).toBe("Laptop");
    expect(await (await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie } })).text()).toContain("Laptop");

    const ok = await passkeyLogin(auth);
    expect(ok.status).toBe(302);
    const sid = /__Host-flareid_session=([^;]+)/.exec(ok.headers.get("Set-Cookie") ?? "")![1]!;
    const row = await env.DB.prepare("SELECT user_id, amr FROM sessions WHERE id = ?").bind(sid).first<{ user_id: number; amr: string }>();
    expect(row!.user_id).toBe(id);
    expect(JSON.parse(row!.amr)).toEqual(["hwk", "mfa"]);

    const replay = await passkeyLogin(auth, 1);
    expect(replay.status).toBe(200);
    expect(await replay.text()).toContain("That passkey could not sign you in.");
  });

  it("rejects a registration whose challenge was not issued, and removes a passkey", async () => {
    const { id, cookie } = await signedIn();
    const auth = await new SoftAuthenticator().init();
    const forged = await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ response: await auth.register("bm90LWlzc3VlZA") }) });
    expect(forged.status).toBe(400);
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ response: await auth.register(opts.challenge) }) });
    const cred = b64u(auth.credId);
    const rm = await SELF.fetch(`${BASE}/account/passkeys/${encodeURIComponent(cred)}/remove`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: cookie }, redirect: "manual" });
    expect(rm.status).toBe(302);
    expect(await env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ?").bind(id).first()).toBeNull();
    expect((await passkeyLogin(auth)).status).toBe(200);
  });
});

describe("passkey step-up", () => {
  // A session older than the step-up window must prove the password before it
  // can mint or destroy a sign-in credential; a fresh one does not.
  async function staleCookie() {
    const { id, cookie } = await signedIn();
    const sessionId = cookie.split("=")[1]!;
    await env.DB.prepare("UPDATE sessions SET created_at = ? WHERE id = ?").bind(new Date(Date.now() - 30 * 60 * 1000).toISOString(), sessionId).run();
    return { id, cookie };
  }

  it("a stale session must give the current password to register a passkey", async () => {
    const { id, cookie } = await staleCookie();
    const auth = await new SoftAuthenticator().init();

    // Without the password: refused, and the JS learns to ask for it.
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    const denied = await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ response: await auth.register(opts.challenge) }) });
    expect(denied.status).toBe(403);
    expect((await denied.json() as { needsPassword?: boolean }).needsPassword).toBe(true);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?").bind(id).first<{ n: number }>()).toEqual({ n: 0 });
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.step_up_failed'").first()).toBeTruthy();

    // With it: registered, and the account page now lists it.
    const opts2 = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    const reg = await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ name: "Laptop", password: "user-password-123", response: await auth.register(opts2.challenge) }) });
    expect(await reg.json()).toEqual({ ok: true });
    expect((await env.DB.prepare("SELECT name FROM webauthn_credentials WHERE user_id = ?").bind(id).first<{ name: string }>())!.name).toBe("Laptop");
  });

  it("a stale session is sent to the confirm page and must give the password to remove a passkey", async () => {
    const { id, cookie } = await staleCookie();
    // Register while... stale too: supply the password inline.
    const auth = await new SoftAuthenticator().init();
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ password: "user-password-123", response: await auth.register(opts.challenge) }) });
    const cred = b64u(auth.credId);
    const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: cookie };

    // The row form posts no password: bounced to the confirm page, credential intact.
    const bounced = await SELF.fetch(`${BASE}/account/passkeys/${encodeURIComponent(cred)}/remove`, { method: "POST", headers: FORM, redirect: "manual" });
    expect(bounced.status).toBe(303);
    expect(bounced.headers.get("Location")).toBe(`/account/passkeys/${encodeURIComponent(cred)}/remove`);
    expect(await env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ?").bind(id).first()).toBeTruthy();

    // The confirm page asks for the password.
    const page = await (await SELF.fetch(`${BASE}/account/passkeys/${encodeURIComponent(cred)}/remove`, { headers: { Cookie: cookie } })).text();
    expect(page).toContain('name="current_password"');
    expect(page).toContain("Remove this passkey?");

    // Wrong password: audited, nothing removed.
    const wrong = await SELF.fetch(`${BASE}/account/passkeys/${encodeURIComponent(cred)}/remove`, { method: "POST", headers: FORM, body: "current_password=wrong-password", redirect: "manual" });
    expect(new URL(wrong.headers.get("Location")!, BASE).searchParams.get("error")).toBe("That password is not right.");
    expect(await env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ?").bind(id).first()).toBeTruthy();

    // Right password: removed.
    const ok = await SELF.fetch(`${BASE}/account/passkeys/${encodeURIComponent(cred)}/remove`, { method: "POST", headers: FORM, body: "current_password=user-password-123", redirect: "manual" });
    expect(new URL(ok.headers.get("Location")!, BASE).search).toContain("saved=passkey-removed");
    expect(await env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ?").bind(id).first()).toBeNull();
  });

  it("a fresh session removes a passkey without the extra proof", async () => {
    const { id, cookie } = await signedIn();
    const auth = await new SoftAuthenticator().init();
    const opts = (await (await SELF.fetch(`${BASE}/account/passkeys/options`, { headers: { Cookie: cookie } })).json()) as { challenge: string };
    await SELF.fetch(`${BASE}/account/passkeys`, { method: "POST", headers: { ...JSON_POST, Cookie: cookie }, body: JSON.stringify({ response: await auth.register(opts.challenge) }) });
    const cred = b64u(auth.credId);
    const rm = await SELF.fetch(`${BASE}/account/passkeys/${encodeURIComponent(cred)}/remove`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: cookie }, redirect: "manual" });
    expect(rm.status).toBe(302);
    expect(new URL(rm.headers.get("Location")!, BASE).search).toContain("saved=passkey-removed");
    expect(await env.DB.prepare("SELECT 1 FROM webauthn_credentials WHERE user_id = ?").bind(id).first()).toBeNull();
  });
});

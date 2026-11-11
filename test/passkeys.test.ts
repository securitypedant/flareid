// Passkeys end to end with a software authenticator: register from /account,
// sign in with no username, counter replay refused, removal.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { b64u, SoftAuthenticator } from "./fixtures/soft-authenticator.js";

beforeEach(resetDatabase);

async function signedIn() {
  await bootstrapInstance({ domain: "horizon.test" });
  const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
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

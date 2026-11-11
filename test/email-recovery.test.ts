import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

/** A stand-in for the send_email binding that keeps what it was asked to send. */
function fakeEmail() {
  const sent: { to: string; subject: string; text: string; html: string; from: unknown }[] = [];
  return {
    sent,
    binding: {
      async send(message: { to: string; subject: string; text: string; html: string; from: unknown }) {
        sent.push(message);
        return { messageId: `msg-${sent.length}` };
      },
    },
  };
}

/** Calls the Worker with the fake email binding and waits for waitUntil work (the recovery send). */
async function call(email: ReturnType<typeof fakeEmail>, path: string, init: RequestInit = {}) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${BASE}${path}`, { redirect: "manual", ...init }), { ...env, EMAIL: email.binding } as unknown as typeof env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

function linkIn(text: string, kind: "reset-password" | "invite"): string {
  return new URL(new RegExp(`https://idp\\.test/${kind}/[0-9a-f]{64}`).exec(text)![0]).pathname;
}

async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      users: [
        { username: "rita", password: "old-password-1", status: "active", email: "rita@personal.test" },
        { username: "nina", status: "disabled" },
      ],
    },
  });
  await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@horizon.test', '')").run();
  return apiKey;
}

describe("password recovery", () => {
  it("emails a single-use link to the contact address, and the link sets the password", async () => {
    await setup();
    const email = fakeEmail();

    const login = await (await call(email, "/login")).text();
    expect(login).toContain('href="/forgot-password"');

    const ask = await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=rita" });
    expect(ask.status).toBe(200);
    expect(email.sent).toHaveLength(1);
    expect(email.sent[0]!.to).toBe("rita@personal.test");
    const link = linkIn(email.sent[0]!.text, "reset-password");

    expect((await call(email, link)).status).toBe(200);
    const weak = await call(email, link, { method: "POST", headers: FORM, body: "password=x&confirm=x" });
    expect(weak.status).toBe(400); // policy refused - and the link still works afterwards
    const done = await call(email, link, { method: "POST", headers: FORM, body: "password=brand-new-pass-9&confirm=brand-new-pass-9" });
    expect(done.status).toBe(200);
    expect(await done.text()).toContain("Password changed");

    // Single-use.
    expect((await call(email, link, { method: "POST", headers: FORM, body: "password=again-pass-99&confirm=again-pass-99" })).status).toBe(400);
  });

  it("answers identically for unknown and disabled accounts, and sends nothing", async () => {
    await setup();
    const email = fakeEmail();
    const known = await (await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=rita" })).text();
    email.sent.length = 0;
    const unknown = await (await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=nobody" })).text();
    const disabled = await (await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=nina" })).text();
    expect(unknown).toBe(known);
    expect(disabled).toBe(known);
    expect(email.sent).toHaveLength(0);
  });

  it("limits requests per account", async () => {
    await setup();
    const email = fakeEmail();
    for (let i = 0; i < 6; i++) await call(email, "/forgot-password", { method: "POST", headers: FORM, body: "identifier=rita" });
    expect(email.sent).toHaveLength(3);
  });

  it("is not offered when email is not configured", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const email = fakeEmail();
    expect(await (await call(email, "/login")).text()).not.toContain("/forgot-password");
    expect((await call(email, "/forgot-password")).status).toBe(400);
  });
});

describe("invitations", () => {
  it("an invitation activates the account when accepted", async () => {
    const apiKey = await setup();
    const email = fakeEmail();
    const res = await call(email, "/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { kind: string }).kind).toBe("invite");
    expect(email.sent[0]!.to).toBe("nina@horizon.test"); // no contact email: the UPN

    const link = linkIn(email.sent[0]!.text, "invite");
    const accepted = await call(email, link, { method: "POST", headers: FORM, body: "password=nina-chosen-12&confirm=nina-chosen-12" });
    expect(accepted.status).toBe(200);
    expect((await env.DB.prepare("SELECT status FROM users WHERE username = 'nina'").first<{ status: string }>())?.status).toBe("active");

    // And she can now sign in with the password she chose.
    const page = await (await call(email, "/login")).text();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
    const signIn = await call(email, "/login", { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: flowId, upn: "nina", password: "nina-chosen-12" }).toString() });
    expect(signIn.headers.get("Set-Cookie")).toContain("flareid_session");
  });

  it("a newer invitation replaces the old one", async () => {
    const apiKey = await setup();
    const email = fakeEmail();
    await call(email, "/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } });
    await call(email, "/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } });
    const [first, second] = email.sent.map((m) => linkIn(m.text, "invite"));
    expect((await call(email, first!)).status).toBe(400);
    expect((await call(email, second!)).status).toBe(200);
  });
});

describe("email switch", () => {
  it("switches sending off and on without losing the From address", async () => {
    const { setEmailSettings, setEmailEnabled, isEmailConfigured, getEmailSettings } = await import("../src/lib/email.js");
    const { env: e } = await import("cloudflare:test");
    const withBinding = { ...e, EMAIL: { send: async () => ({ messageId: "x" }) } } as unknown as typeof e;
    await setEmailSettings(withBinding, { fromAddress: "no-reply@horizon.test", fromName: "FlareID" });
    expect(await isEmailConfigured(withBinding)).toBe(true);
    await setEmailEnabled(withBinding, false);
    expect(await isEmailConfigured(withBinding)).toBe(false);
    expect((await getEmailSettings(withBinding)).fromAddress).toBe("no-reply@horizon.test");
    await setEmailEnabled(withBinding, true);
    expect(await isEmailConfigured(withBinding)).toBe(true);
  });
});

import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { resolveLoginIdentifier } from "../src/lib/identifier.js";
import { createUpstreamIdp, NoLocalAccount, resolveFederatedUser } from "../src/lib/federation.js";
import { setUserEmails } from "../src/lib/user-emails.js";
import { deleteAlias, startAliasVerification, verifyAliasCode } from "../src/lib/alias-verify.js";
import { getSmsConfig, saveSmsConfig, smsConfigured } from "../src/lib/sms.js";
import type { UserRow } from "../src/lib/types.js";

const PASSWORD = "user-password-123";
const IDP = { name: "Partner", protocol: "oidc" as const, config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "" };

const sent: { to: string; text: string }[] = [];
const EMAIL = { async send(m: { to: string; text: string }) { sent.push(m); return { messageId: "m" }; } };
const envE = () => ({ ...env, EMAIL }) as typeof env;

beforeEach(() => {
  sent.length = 0;
  return resetDatabase();
});

async function seedUser(apiKey: string, body: Record<string, unknown>) {
  const r = await apiCall("/api/v1/users", { token: apiKey, body: { given_name: "U", password: PASSWORD, status: "active", ...body } });
  if (r.status !== 201) throw new Error(`seed: ${JSON.stringify(r.body)}`);
  return r.body;
}

async function userRow(upn: string): Promise<UserRow> {
  return (await env.DB.prepare("SELECT * FROM users WHERE upn = ?").bind(upn).first<UserRow>())!;
}

async function signIn(upn: string): Promise<boolean> {
  const loginPage = await SELF.fetch(`${BASE}/login`, { redirect: "manual" });
  const flowId = /name="flow_id" value="([^"]+)"/.exec(await loginPage.text())?.[1] ?? "";
  const res = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password: PASSWORD }).toString(),
    redirect: "manual",
  });
  await res.text();
  return Boolean(res.headers.get("Set-Cookie")?.includes("flareid_session"));
}

describe("allow_linking", () => {
  const profile = { subject: "sub-1", username: "newbie", email: "victim@x.com", givenName: "N", familyName: "U" };

  it("off: a matching claim never adopts - JIT mints a separate account", async () => {
    const { apiKey } = await bootstrapInstance();
    const victim = await seedUser(apiKey, { username: "victim", domain: "example.com", emails: [{ value: "victim@x.com" }] });
    const victimId = (await userRow(victim.upn)).id;
    const idp = await createUpstreamIdp(env, { ...IDP, allowLinking: false });
    const user = await resolveFederatedUser(env, idp, profile);
    expect(user.upn).not.toBe(victim.upn);
    expect(await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND user_id = ?").bind(idp.id, victimId).first()).toBeNull();
    expect(await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND user_id = ?").bind(idp.id, user.id).first()).not.toBeNull();
  });

  it("off with no JIT: an exact match is still refused outright", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { username: "victim", domain: "example.com", emails: [{ value: "victim@x.com" }] });
    const idp = await createUpstreamIdp(env, { ...IDP, jit: false, allowLinking: false });
    await expect(resolveFederatedUser(env, idp, profile)).rejects.toBeInstanceOf(NoLocalAccount);
  });

  it("on: a matching verified claim adopts, as before", async () => {
    const { apiKey } = await bootstrapInstance();
    const victim = await seedUser(apiKey, { username: "victim", domain: "example.com", emails: [{ value: "victim@x.com" }] });
    const idp = await createUpstreamIdp(env, IDP);
    const user = await resolveFederatedUser(env, idp, { ...profile, username: "" });
    expect(user.upn).toBe(victim.upn);
  });
});

describe("alias_signin", () => {
  it("off: aliases stop resolving at the sign-in prompt but still resolve for delivery", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { username: "ada", domain: "example.com", emails: [{ value: "ada@partner.com" }] });
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user?.upn).toBe("ada@example.com");

    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('alias_signin', 'false', '')").run();
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user).toBeNull();
    expect((await resolveLoginIdentifier(env, "ada@partner.com", { deliveryOnly: true })).user?.upn).toBe("ada@example.com");
    expect(await signIn("ada@partner.com")).toBe(false);
    expect(await signIn("ada@example.com")).toBe(true);
  });
});

describe("verified aliases", () => {
  it("an unverified alias row resolves nothing until verified", async () => {
    const { apiKey } = await bootstrapInstance();
    const u = await seedUser(apiKey, { username: "ada", domain: "example.com" });
    await env.DB.prepare("INSERT INTO user_emails (user_id, email, type, is_primary, verified, created_at) VALUES (?, 'ada@partner.com', 'work', 0, 0, '')").bind((await userRow(u.upn)).id).run();
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user).toBeNull();
    await env.DB.prepare("UPDATE user_emails SET verified = 1 WHERE email = 'ada@partner.com'").run();
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user?.upn).toBe("ada@example.com");
  });

  it("self-service: add -> code emailed -> verify -> resolves", async () => {
    const { apiKey } = await bootstrapInstance();
    await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@example.com', '')").run();
    const u = await seedUser(apiKey, { username: "ada", domain: "example.com" });
    const user = await userRow(u.upn);

    const outcome = await startAliasVerification(envE(), user, "email", "Ada@Partner.com");
    expect(outcome).toMatchObject({ ok: true });
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user).toBeNull(); // unverified yet
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("ada@partner.com");
    const code = /\b(\d{6})\b/.exec(sent[0]!.text)![1]!;

    expect(await verifyAliasCode(env, user, "email", "ada@partner.com", "000000")).toBe(code === "000000" ? "ok" : "wrong");
    if (code === "000000") return;
    expect(await verifyAliasCode(env, user, "email", "ada@partner.com", code)).toBe("ok");
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user?.upn).toBe("ada@example.com");

    await deleteAlias(env, user, "email", "ada@partner.com");
    expect((await resolveLoginIdentifier(env, "ada@partner.com")).user).toBeNull();
  });

  it("a phone add without an SMS provider fails clearly", async () => {
    const { apiKey } = await bootstrapInstance();
    const u = await seedUser(apiKey, { username: "ada", domain: "example.com" });
    const outcome = await startAliasVerification(envE(), await userRow(u.upn), "phone", "+15551239999");
    expect(outcome).toMatchObject({ ok: false });
    expect((outcome as { error: string }).error).toMatch(/SMS/i);
  });

  it("an admin-written alias (setUserEmails) arrives verified", async () => {
    const { apiKey } = await bootstrapInstance();
    const u = await seedUser(apiKey, { username: "ada", domain: "example.com" });
    await setUserEmails(env, (await userRow(u.upn)).id, [{ value: "ada@partner.com" }]);
    expect((await env.DB.prepare("SELECT verified FROM user_emails WHERE email = 'ada@partner.com'").first<{ verified: number }>())?.verified).toBe(1);
  });
});

describe("sms config", () => {
  it("round-trips provider settings and reports configured per provider", async () => {
    await bootstrapInstance();
    let config = await getSmsConfig(env);
    expect(smsConfigured(config)).toBe(false);

    await saveSmsConfig(env, { provider: "telnyx", telnyxKey: "KEY", from: "+15551230000" });
    config = await getSmsConfig(env);
    expect(config.provider).toBe("telnyx");
    expect(config.telnyxKey).toBe("KEY");
    expect(smsConfigured(config)).toBe(true);

    // A blank secret keeps the stored one.
    await saveSmsConfig(env, { provider: "telnyx", telnyxKey: "", from: "+15551230001" });
    config = await getSmsConfig(env);
    expect(config.telnyxKey).toBe("KEY");
    expect(config.from).toBe("+15551230001");
  });
});

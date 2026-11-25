import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { saveSmsConfig } from "../src/lib/sms.js";
import { setFactorEnabled } from "../src/lib/auth-policy.js";
import { maskPhone, otpSmsText, routablePhone, sendSmsOtp, userHasSmsOtp, verifySmsOtp } from "../src/lib/sms-otp.js";
import { accountScope, verifyEmailOtp } from "../src/lib/email-otp.js";
import { secondStepFactors } from "../src/lib/second-step.js";
import type { UserRow } from "../src/lib/types.js";

const texts: { to: string; body: string }[] = [];
beforeEach(async () => {
  texts.length = 0;
  await resetDatabase();
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://api.twilio.com/")) {
      const p = new URLSearchParams(String(init?.body ?? ""));
      texts.push({ to: p.get("To") ?? "", body: p.get("Body") ?? "" });
      return new Response(JSON.stringify({ sid: "SM1" }), { status: 201 });
    }
    return new Response("not mocked", { status: 599 });
  });
});
afterEach(() => vi.restoreAllMocks());

async function seed(): Promise<UserRow> {
  const { apiKey } = await bootstrapInstance();
  expect((await apiCall("/api/v1/users", { token: apiKey, body: { given_name: "Ada", username: "ada", domain: "example.com", password: "user-password-123", status: "active" } })).status).toBe(201);
  await saveSmsConfig(env, { provider: "twilio", accountSid: "AC123", authToken: "tok", from: "+15550001111" });
  await setFactorEnabled(env, "sms_otp", true);
  return (await env.DB.prepare("SELECT * FROM users WHERE upn = 'ada@example.com'").first<UserRow>())!;
}

describe("SMS one-time codes", () => {
  it("text varies across sends, always carries the code, the app and the WebOTP line", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 6; i++) {
      const t = otpSmsText({ app: "Acme", code: "123456", minutes: 10, host: "idp.example.com", purpose: "signin", pick: () => i });
      expect(t).toContain("123456");
      expect(t).toContain("Acme");
      expect(t.endsWith("@idp.example.com #123456")).toBe(true);
      seen.add(t.split("\n")[0]!);
    }
    expect(seen.size).toBe(6);
    expect(maskPhone("+15551234567")).toBe("+1••••••4567");
  });

  it("only a verified phone receives codes; unverified rows are ignored", async () => {
    const user = await seed();
    expect(await routablePhone(env, user)).toBeNull();
    await env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, verified, created_at) VALUES (?, '+15559990000', 'mobile', 1, 0, '')").bind(user.id).run();
    expect(await routablePhone(env, user)).toBeNull();
    await env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, verified, created_at) VALUES (?, '+15551234567', 'mobile', 0, 1, '')").bind(user.id).run();
    expect(await routablePhone(env, user)).toBe("+15551234567");
    expect(await userHasSmsOtp(env, { ...user, sms_otp_enabled: 1 })).toBe(true);
  });

  it("sends, verifies once, and a texted code can't satisfy an email step", async () => {
    const user = await seed();
    await env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, verified, created_at) VALUES (?, '+15551234567', 'mobile', 1, 1, '')").bind(user.id).run();
    const scope = accountScope("s1");
    expect(await sendSmsOtp(env, user, scope, "enrol")).toEqual({ ok: true, to: "+15551234567" });
    expect(texts).toHaveLength(1);
    const code = /\b(\d{6})\b/.exec(texts[0]!.body)![1]!;
    expect(await verifyEmailOtp(env, scope, user.id, "enrol", code)).toBe("expired");
    expect(await verifySmsOtp(env, scope, user.id, "enrol", code)).toBe("ok");
    expect(await verifySmsOtp(env, scope, user.id, "enrol", code)).toBe("expired");
  });

  it("is offered at sign-in to users, never to administrators", async () => {
    const user = await seed();
    await env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, verified, created_at) VALUES (?, '+15551234567', 'mobile', 1, 1, '')").bind(user.id).run();
    await env.DB.prepare("UPDATE users SET sms_otp_enabled = 1 WHERE id = ?").bind(user.id).run();
    const ada = (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first<UserRow>())!;
    expect((await secondStepFactors(env, ada)).smsOtp).toBe(true);
    const admin = (await env.DB.prepare("SELECT * FROM users WHERE upn = 'admin@example.com'").first<UserRow>())!;
    await env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, verified, created_at) VALUES (?, '+15557654321', 'mobile', 1, 1, '')").bind(admin.id).run();
    await env.DB.prepare("UPDATE users SET sms_otp_enabled = 1 WHERE id = ?").bind(admin.id).run();
    expect((await secondStepFactors(env, { ...admin, sms_otp_enabled: 1 })).smsOtp).toBe(false);
  });

  it("the sign-in page offers 'Text me a code' when SMS is the person's factor", async () => {
    const user = await seed();
    await env.DB.prepare("INSERT INTO user_phones (user_id, phone, type, is_primary, verified, created_at) VALUES (?, '+15551234567', 'mobile', 1, 1, '')").bind(user.id).run();
    await env.DB.prepare("UPDATE users SET sms_otp_enabled = 1 WHERE id = ?").bind(user.id).run();
    const page = await SELF.fetch(`${BASE}/login`, { redirect: "manual" });
    const flowId = /name="flow_id" value="([^"]+)"/.exec(await page.text())?.[1] ?? "";
    const res = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow_id: flowId, upn: "ada@example.com", password: "user-password-123" }).toString(),
      redirect: "manual",
    });
    const html = await res.text();
    expect(html).toContain('action="/login/mfa/sms/send"');
    expect(html).toContain("Text me a code");
  });
});

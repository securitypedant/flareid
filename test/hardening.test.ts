// Hardening after the run-2 audit: hashed trusted devices, no X-Forwarded-For,
// import password policy, per-client back-channel rate limits, batched SCIM sync.
import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { getClientIp } from "../src/lib/rate-limit.js";
import { trustDevice } from "../src/lib/trusted-devices.js";
import { sha256Hex } from "../src/lib/tokens.js";

beforeEach(resetDatabase);

describe("hardening", () => {
  it("stores only a hash of the trusted-device cookie", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = await trustDevice(env, new Request(BASE), id);
    const value = /=([^;]+)/.exec(cookie)![1]!;
    const row = await env.DB.prepare("SELECT id FROM trusted_devices WHERE user_id = ?").bind(id).first<{ id: string }>();
    expect(row!.id).toBe(await sha256Hex(value));
    expect(row!.id).not.toBe(value);
  });

  it("ignores X-Forwarded-For when deriving the client address", () => {
    expect(getClientIp(new Request(BASE, { headers: { "X-Forwarded-For": "1.2.3.4" } }))).toBe("unknown");
    expect(getClientIp(new Request(BASE, { headers: { "CF-Connecting-IP": "5.6.7.8", "X-Forwarded-For": "1.2.3.4" } }))).toBe("5.6.7.8");
  });

  it("rejects an imported password that fails the policy", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const r = await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "weak", password: "a", status: "active" }] } });
    expect(r.body.errors[0].message).toContain("Password rejected");
    expect(await env.DB.prepare("SELECT id FROM users WHERE username = 'weak'").first()).toBeNull();
  });

  it("keys /token limits per client as well as per address", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const keys: string[] = [];
    const limiter = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: true }) };
    const ctx = createExecutionContext();
    const form = (id: string) => new Request(`${BASE}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "203.0.113.9" }, body: `grant_type=x&client_id=${id}` });
    await worker.fetch(form("rp-a"), { ...env, API_LIMITER: limiter } as typeof env, ctx);
    await worker.fetch(form("rp-b"), { ...env, API_LIMITER: limiter } as typeof env, ctx);
    await waitOnExecutionContext(ctx);
    expect(keys).toEqual(["api:203.0.113.9:client:rp-a", "api:203.0.113.9:client:rp-b"]);
  });
});

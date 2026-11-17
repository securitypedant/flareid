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

  it("keys /token limits per client as well as per address - but only for a client that exists", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const a = (await apiCall("/api/v1/clients", { token: apiKey, body: { name: "A", redirect_uris: ["https://a.test/cb"] } })).body.client_id as string;
    const b = (await apiCall("/api/v1/clients", { token: apiKey, body: { name: "B", redirect_uris: ["https://b.test/cb"] } })).body.client_id as string;
    const keys: string[] = [];
    const limiter = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: true }) };
    const ctx = createExecutionContext();
    const form = (id: string) => new Request(`${BASE}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "203.0.113.9" }, body: `grant_type=x&client_id=${id}` });
    await worker.fetch(form(a), { ...env, API_LIMITER: limiter } as typeof env, ctx);
    await worker.fetch(form(b), { ...env, API_LIMITER: limiter } as typeof env, ctx);
    // A made-up client_id does not mint its own budget: it shares the address's.
    await worker.fetch(form("attacker-invented-id"), { ...env, API_LIMITER: limiter } as typeof env, ctx);
    await waitOnExecutionContext(ctx);
    expect(keys).toEqual([`api:203.0.113.9:client:${a}`, `api:203.0.113.9:client:${b}`, "api:203.0.113.9"]);
  });

  it("IPv6 sources are charged at /64 and /48 so rotating prefixes cannot escape the budget", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const keys: string[] = [];
    const limiter = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: true }) };
    const ctx = createExecutionContext();
    for (const addr of ["2001:db8:aa:1::1", "2001:db8:aa:2::1", "2001:db8:bb:1::1"]) {
      await worker.fetch(new Request(`${BASE}/api/v1/status`, { headers: { Authorization: "Bearer x", "CF-Connecting-IP": addr } }), { ...env, API_LIMITER: limiter } as typeof env, ctx);
    }
    await waitOnExecutionContext(ctx);
    // Two /64s under the same /48 plus one outside it.
    expect(keys).toEqual([
      "api:2001:db8:aa:1::/64", "api:48:2001:db8:aa::/48",
      "api:2001:db8:aa:2::/64", "api:48:2001:db8:aa::/48",
      "api:2001:db8:bb:1::/64", "api:48:2001:db8:bb::/48",
    ]);
  });
});

describe("SCIM full sync in steps", () => {
  it("runs user batches, then the groups, and reports each step for the sync log", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", groups: [{ name: "Crew" }], users: [{ username: "a1", status: "active", groups: ["Crew"] }, { username: "a2", status: "active" }] } });
    await apiCall("/api/v1/scim/config", { token: apiKey, body: { endpoint: "https://scim.test/scim/v2", secret: "x".repeat(24), scope: { mode: "all", group_ids: [] }, tuning: { pace_ms: 0, members_per_request: 500, sync_batch: 500 } } });
    let n = 0;
    const { vi } = await import("vitest");
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (!url.startsWith("https://scim.test/")) return new Response("unexpected", { status: 500 });
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
      if (method === "GET") return Response.json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: 0, Resources: [] });
      return Response.json({ id: `remote-${++n}` }, { status: method === "POST" ? 201 : 200 });
    });
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const { createSession } = await import("../src/lib/sessions.js");
    const cookie = (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const step = async (restart: boolean) =>
      (await (await worker.fetch(new Request(`${BASE}/admin/scim/sync${restart ? "?restart=1" : ""}`, { method: "POST", headers: { Origin: BASE, Cookie: cookie } }), env, createExecutionContext())).json()) as Record<string, unknown>;
    const first = await step(true);
    expect(first).toMatchObject({ phase: "users", complete: false, remainingUsers: 0, userErrors: 0 });
    expect(first.users).toBeGreaterThanOrEqual(3);
    const second = await step(false);
    expect(second).toMatchObject({ phase: "groups", complete: true, groupErrors: 0 });
    expect(second.groups).toBeGreaterThanOrEqual(1);
    spy.mockRestore();
    const page = await (await worker.fetch(new Request(`${BASE}/admin/integrations/scim`, { headers: { Cookie: cookie } }), env, createExecutionContext())).text();
    expect(page).toContain('id="scim-log"');
    expect(page).toContain("full sync:");
  });
});

describe("inline scripts", () => {
  it("the SCIM page script keeps its newline escape (a raw newline in a string broke the whole script)", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const { setScimConfig } = await import("../src/lib/settings.js");
    await setScimConfig(env, { endpoint: "https://scim.test/scim/v2", secret: "x".repeat(24) });
    const targetId = (await env.DB.prepare("SELECT id FROM scim_targets ORDER BY id").first<{ id: number }>())!.id;
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const { createSession } = await import("../src/lib/sessions.js");
    const cookie = (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const html = await (await worker.fetch(new Request(`${BASE}/admin/integrations/scim/${targetId}`, { headers: { Cookie: cookie } }), env, createExecutionContext())).text();
    expect(html).toContain('text + "\\n";');
    // No double-quoted string in any inline script runs across a line break.
    for (const m of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) {
      for (const line of m[1]!.split("\n")) expect((line.replace(/\\./g, "").match(/"/g) ?? []).length % 2, line).toBe(0);
    }
  });
});

describe("import SCIM push", () => {
  it("pushes only the groups an import could have changed", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", groups: [{ name: "A" }, { name: "B" }, { name: "C" }], users: [{ username: "u1", status: "active", groups: ["A"] }, { username: "u2", status: "active", groups: ["B"] }] } });
    await apiCall("/api/v1/scim/config", { token: apiKey, body: { endpoint: "https://scim.test/scim/v2", secret: "x".repeat(24), scope: { mode: "all", group_ids: [] }, tuning: { pace_ms: 0, members_per_request: 500, sync_batch: 500 } } });
    const { vi } = await import("vitest");
    const groupWrites: string[] = [];
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/Groups") && method !== "GET") groupWrites.push(url);
      if (method === "GET") return Response.json({ Resources: [] });
      return Response.json({ id: `r-${Math.random()}` }, { status: method === "POST" ? 201 : 200 });
    });
    // The config call re-pushes everything in the background; let it finish,
    // then a full sync pushes the users and the groups with their members.
    await new Promise((r) => setTimeout(r, 300));
    const { syncAll } = await import("../src/lib/scim-client.js");
    while (!(await syncAll(env)).complete) { /* next step */ }
    groupWrites.length = 0;
    const byScimId = new Map((await env.DB.prepare("SELECT g.name, l.scim_id FROM groups g JOIN scim_group_links l ON l.group_id = g.id").all<{ name: string; scim_id: string }>()).results.map((g) => [g.scim_id, g.name]));
    // u1 moves from A to C: A and C change, B does not. The push runs after the
    // import's response, so give it a moment to land its writes.
    const res = await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "u1", status: "active", groups: ["C"] }] } });
    expect(res.status).toBe(200);
    let names: (string | undefined)[] = [];
    for (let i = 0; i < 50; i++) {
      names = groupWrites.map((url) => byScimId.get(url.split("/Groups/")[1] ?? ""));
      if (names.includes("A") && names.includes("C")) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    spy.mockRestore();
    expect(names).toContain("A");
    expect(names).toContain("C");
    expect(names).not.toContain("B");
  });
});

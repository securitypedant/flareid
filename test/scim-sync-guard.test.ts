// Outbound SCIM full sync: the single-flight lock keeps concurrent syncAll
// invocations (console poller, API, cron) from pushing the same batch twice,
// and the guarded scim_id link write sends the losing remote object to the
// deprovision queue instead of leaving an untracked duplicate.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { pushUser, syncAll } from "../src/lib/scim-client.js";
import { setScimConfig } from "../src/lib/settings.js";
import type { UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);
afterEach(() => vi.restoreAllMocks());

const LOCK_KEY = "scim_sync_lock";
const scim = () => setScimConfig(env, { endpoint: "https://scim.test/scim/v2", secret: "x".repeat(24) });

async function provisioned(username = "admin"): Promise<UserRow> {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  if (username !== "admin") {
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", users: [{ username, status: "active" }] } });
  }
  await scim();
  return (await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first<UserRow>())!;
}

describe("SCIM sync single-flight", () => {
  it("a held lock coalesces a second sync; a stale lock expires", async () => {
    await provisioned();
    const held = new Date().toISOString();
    await env.DB.prepare("INSERT INTO idp_settings (key, value, updated_at) VALUES (?, ?, ?)").bind(LOCK_KEY, `${held}:other-runner`, held).run();
    const busy = await syncAll(env);
    expect(busy.busy).toBe(true);
    expect(busy.complete).toBe(false);
    expect(busy.users).toBe(0);

    // Fifteen minutes on, the dead runner's lock expires and the sync runs.
    const stale = new Date(Date.now() - 16 * 60 * 1000).toISOString();
    await env.DB.prepare("UPDATE idp_settings SET value = ? WHERE key = ?").bind(`${stale}:other-runner`, LOCK_KEY).run();
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => Response.json({ id: "r-1", Resources: [] }, { status: 201 }));
    const step = await syncAll(env);
    expect(step.busy).toBeUndefined();
    // The lock row itself was released, not left behind.
    expect(await env.DB.prepare("SELECT value FROM idp_settings WHERE key = ?").bind(LOCK_KEY).first()).toBeNull();
  });
});

describe("SCIM create race-safety", () => {
  it("a remote id that loses the link race is queued for deprovision, not orphaned", async () => {
    const user = await provisioned("racer");
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "POST") {
        // A concurrent push links its own remote id while our POST is in flight.
        await env.DB.prepare("UPDATE users SET scim_id = 'u-other' WHERE id = ?").bind(user.id).run();
        return Response.json({ id: "u-ours" }, { status: 201 });
      }
      return Response.json({ Resources: [] });
    });
    const result = await pushUser(env, user);
    expect(result.ok).toBe(true);
    // The first link wins; ours is a duplicate queued for removal.
    expect((await env.DB.prepare("SELECT scim_id FROM users WHERE id = ?").bind(user.id).first<{ scim_id: string }>())!.scim_id).toBe("u-other");
    const queued = await env.DB.prepare("SELECT scim_id FROM scim_deprovision_queue WHERE kind = 'user'").first<{ scim_id: string }>();
    expect(queued!.scim_id).toBe("u-ours");
  });

  it("a 409 from the remote resolves the existing object by externalId and links it", async () => {
    const user = await provisioned("already-there");
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push(`${method} ${url}`);
      if (method === "POST") return new Response("conflict", { status: 409 });
      if (method === "GET" && url.includes("externalId")) return Response.json({ Resources: [{ id: "u-existing" }] });
      return Response.json({ Resources: [] });
    });
    const result = await pushUser(env, user);
    expect(result.ok).toBe(true);
    expect((await env.DB.prepare("SELECT scim_id FROM users WHERE id = ?").bind(user.id).first<{ scim_id: string }>())!.scim_id).toBe("u-existing");
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_deprovision_queue").first<{ n: number }>()).toEqual({ n: 0 });
  });
});

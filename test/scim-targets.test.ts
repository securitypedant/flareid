// Multi-target outbound SCIM: one scim_targets row per downstream server,
// per-target links and queue, pushes fan out to every enabled target, and the
// legacy single-target helpers/API act on the first target.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env, SELF } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { createScimTarget, listScimTargets, getScimTarget, updateScimTarget, deleteScimTarget } from "../src/lib/scim-targets.js";
import { getScimConfig, setScimConfig, getScimTuning, setScimTuning } from "../src/lib/settings.js";
import { pushUser } from "../src/lib/scim-client.js";
import type { UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);
afterEach(() => vi.restoreAllMocks());

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const ENDPOINT_A = "https://a.scim.test/scim/v2";
const ENDPOINT_B = "https://b.scim.test/scim/v2";

/** Records the requests each fake receiver gets, keyed by origin. */
function fakeReceivers() {
  const seen = new Map<string, string[]>();
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    const host = url.startsWith(ENDPOINT_A) ? "a" : url.startsWith(ENDPOINT_B) ? "b" : null;
    if (!host) return new Response("unexpected", { status: 500 });
    const method = (init?.method ?? "GET").toUpperCase();
    if (method !== "GET") seen.set(host, [...(seen.get(host) ?? []), `${method} ${url.slice(host === "a" ? ENDPOINT_A.length : ENDPOINT_B.length)}`]);
    if (method === "GET") return Response.json({ Resources: [], totalResults: 0 });
    if (method === "POST") return Response.json({ id: `${host}-u-1` }, { status: 201 });
    return Response.json({}, { status: 200 });
  });
  return { hits: (host: "a" | "b") => seen.get(host) ?? [] };
}

async function makeTarget(name: string, endpoint: string, opts: Partial<Parameters<typeof createScimTarget>[1]> = {}) {
  return await createScimTarget(env, {
    name,
    endpoint,
    secret: "x".repeat(24),
    scope: { mode: "all", groupIds: [] },
    paceMs: 0,
    membersPerRequest: 50,
    syncBatchSize: 50,
    enabled: true,
    ...opts,
  });
}

describe("multi-target SCIM", () => {
  it("a user push fans out to every enabled target, each with its own remote id", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "mia", status: "active" }] } });
    const a = await makeTarget("Access", ENDPOINT_A);
    const b = await makeTarget("Workspace", ENDPOINT_B);
    const rx = fakeReceivers();

    const mia = (await env.DB.prepare("SELECT * FROM users WHERE username = 'mia'").first<UserRow>())!;
    expect((await pushUser(env, mia)).ok).toBe(true);
    expect(rx.hits("a")).toEqual(["POST /Users"]);
    expect(rx.hits("b")).toEqual(["POST /Users"]);

    const links = (await env.DB.prepare("SELECT target_id, scim_id FROM scim_user_links WHERE user_id = ? ORDER BY target_id").bind(mia.id).all<{ target_id: number; scim_id: string }>()).results;
    expect(links).toEqual([
      { target_id: a.id, scim_id: "a-u-1" },
      { target_id: b.id, scim_id: "b-u-1" },
    ]);
  });

  it("a disabled target is skipped entirely, and scope narrows per target", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, groups: [{ name: "Staff" }], users: [{ username: "nia", status: "active", groups: ["Staff"] }] } });
    const a = await makeTarget("Access", ENDPOINT_A, { scope: { mode: "selected", groupIds: [(await env.DB.prepare("SELECT id FROM groups WHERE name = 'Staff'").first<{ id: number }>())!.id] } });
    const b = await makeTarget("Workspace", ENDPOINT_B, { scope: { mode: "selected", groupIds: [] }, enabled: false });
    const rx = fakeReceivers();

    const nia = (await env.DB.prepare("SELECT * FROM users WHERE username = 'nia'").first<UserRow>())!;
    expect((await pushUser(env, nia)).ok).toBe(true);
    // A is in scope (Staff member); B is disabled, and out of scope besides.
    expect(rx.hits("a")).toEqual(["POST /Users"]);
    expect(rx.hits("b")).toEqual([]);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_user_links WHERE target_id = ?").bind(b.id).first<{ n: number }>())).toEqual({ n: 0 });
  });

  it("deleting a user queues a deprovision per linked target", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "ria", status: "active" }] } });
    const a = await makeTarget("Access", ENDPOINT_A, { enabled: false });
    const b = await makeTarget("Workspace", ENDPOINT_B, { enabled: false });
    const ria = (await env.DB.prepare("SELECT * FROM users WHERE username = 'ria'").first<{ id: number; upn: string }>())!;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO scim_user_links (target_id, user_id, scim_id) VALUES (?, ?, 'a-ria')").bind(a.id, ria.id),
      env.DB.prepare("INSERT INTO scim_user_links (target_id, user_id, scim_id) VALUES (?, ?, 'b-ria')").bind(b.id, ria.id),
    ]);
    expect((await apiCall("/api/v1/users/ria", { token: apiKey, method: "DELETE" })).status).toBe(200);
    const queued = (await env.DB.prepare("SELECT target_id, scim_id FROM scim_deprovision_queue WHERE kind = 'user' ORDER BY target_id").all<{ target_id: number; scim_id: string }>()).results;
    expect(queued).toEqual([
      { target_id: a.id, scim_id: "a-ria" },
      { target_id: b.id, scim_id: "b-ria" },
    ]);
  });

  it("the legacy helpers read and write the first target", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    expect((await getScimConfig(env)).endpoint).toBe("");
    await setScimConfig(env, { endpoint: "https://first.scim.test/v2", secret: "tok-1" });
    const first = (await listScimTargets(env)).sort((x, y) => x.id - y.id)[0]!;
    expect(first.name).toBe("Default");
    expect(first.endpoint).toBe("https://first.scim.test/v2");

    // A second, later target does not change the legacy view.
    await makeTarget("Second", ENDPOINT_B);
    expect((await getScimConfig(env)).endpoint).toBe("https://first.scim.test/v2");

    await setScimTuning(env, { paceMs: 30, membersPerRequest: 20, syncBatchSize: 100 });
    expect(await getScimTuning(env)).toEqual({ paceMs: 30, membersPerRequest: 20, syncBatchSize: 100 });
    expect((await getScimTarget(env, first.id))!.paceMs).toBe(30);
    // ... while the second target keeps its own values.
    const second = (await listScimTargets(env)).find((t) => t.name === "Second")!;
    expect(second.paceMs).toBe(0);
  });

  it("target CRUD enforces the endpoint rules and the write-only secret", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const fails = async (p: Promise<unknown>, re: RegExp) => {
      try {
        await p;
      } catch (e) {
        expect(String(e)).toMatch(re);
        return;
      }
      throw new Error("expected a rejection");
    };
    await fails(makeTarget("Bad", "http://scim.example.com"), /https/);
    await fails(makeTarget("Bad", "https://10.1.2.3/scim"), /private|loopback/i);

    const t = await makeTarget("Access", ENDPOINT_A);
    // Blank secret keeps the stored one; clearing the endpoint drops it.
    await updateScimTarget(env, t.id, { secret: "" });
    expect((await getScimTarget(env, t.id))!.secret).toBe("x".repeat(24));
    await updateScimTarget(env, t.id, { endpoint: "" });
    const cleared = (await getScimTarget(env, t.id))!;
    expect(cleared.endpoint).toBe("");
    expect(cleared.secret).toBe("");

    // Names are unique; deleting removes the row and its links.
    await fails(createScimTarget(env, { name: "Access", endpoint: ENDPOINT_B, secret: "x", scope: { mode: "all", groupIds: [] }, paceMs: 0, membersPerRequest: 50, syncBatchSize: 50, enabled: true }), /./);
    expect(await deleteScimTarget(env, t.id)).toBe(true);
    expect(await getScimTarget(env, t.id)).toBeNull();
  });

  it("the console lists targets and the detail page edits one", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;

    // Create through the console form.
    const created = await SELF.fetch(`${BASE}/admin/scim/targets`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ name: "Access", endpoint: ENDPOINT_A, secret: "tok-abc", enabled: "1", mode: "all" }).toString(),
      redirect: "manual",
    });
    expect(created.status).toBe(302);
    const targetId = Number(created.headers.get("Location")!.match(/scim\/(\d+)/)![1]);

    const list = await (await SELF.fetch(`${BASE}/admin/integrations/scim`, { headers: { Cookie: cookie } })).text();
    expect(list).toContain("Access");
    expect(list).toContain("a.scim.test");
    expect(list).not.toContain("tok-abc");

    const detail = await (await SELF.fetch(`${BASE}/admin/integrations/scim/${targetId}`, { headers: { Cookie: cookie } })).text();
    expect(detail).toContain("Sync tuning");
    expect(detail).toContain("leave blank to keep it");

    // Per-target tuning save.
    const saved = await SELF.fetch(`${BASE}/admin/scim/targets/${targetId}/tuning`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ pace_ms: "400", members_per_request: "25", sync_batch: "100" }).toString(),
      redirect: "manual",
    });
    expect(saved.status).toBe(302);
    expect((await getScimTarget(env, targetId))!.paceMs).toBe(400);
  });

  it("the API manages targets and keeps /scim/config pointed at the first", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });

    const made = await apiCall("/api/v1/scim/targets", { token: apiKey, body: { name: "Access", endpoint: ENDPOINT_A, secret: "tok-1", tuning: { pace_ms: 10, members_per_request: 25, sync_batch: 100 } } });
    expect(made.status).toBe(200);
    const id = made.body.id as number;

    const list = await apiCall("/api/v1/scim/targets", { token: apiKey });
    expect(list.body.targets).toEqual([{ id, name: "Access", endpoint: ENDPOINT_A, secret_set: true, scope: { mode: "all", group_ids: [] }, tuning: { pace_ms: 10, members_per_request: 25, sync_batch: 100 }, enabled: true }]);
    expect(JSON.stringify(list.body)).not.toContain("tok-1");

    // The legacy view sees the first target.
    const config = await apiCall("/api/v1/scim/config", { token: apiKey });
    expect(config.body).toEqual({ endpoint: ENDPOINT_A, secret_set: true, scope: { mode: "all", group_ids: [] } });

    // PATCH keeps the secret on a blank field; a second target joins the list.
    expect((await apiCall(`/api/v1/scim/targets/${id}`, { token: apiKey, method: "PATCH", body: { name: "Access EU" } })).status).toBe(200);
    await apiCall("/api/v1/scim/targets", { token: apiKey, body: { name: "Workspace", endpoint: ENDPOINT_B, secret: "tok-2" } });
    expect((await apiCall("/api/v1/scim/targets", { token: apiKey })).body.targets).toHaveLength(2);
    expect((await getScimTarget(env, id))!.name).toBe("Access EU");
    expect((await getScimTarget(env, id))!.secret).toBe("tok-1");

    expect((await apiCall(`/api/v1/scim/targets/${id}`, { token: apiKey, method: "DELETE" })).status).toBe(200);
    expect(await getScimTarget(env, id)).toBeNull();
  });
});

// Outbound SCIM group updates are proportional to the change: PATCH add/remove
// against the last accepted push, a full PUT only when there is nothing to
// compare with, the change is large, or the server refuses the PATCH.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { groupPatchBodies, syncAll, syncGroups } from "../src/lib/scim-client.js";
import { setScimConfig, setScimTuning } from "../src/lib/settings.js";
import { listScimTargets, type ScimTarget } from "../src/lib/scim-targets.js";

beforeEach(resetDatabase);
afterEach(() => vi.restoreAllMocks());

interface Sent {
  method: string;
  path: string;
  body: any;
  bytes: number;
}

/** A stand-in SCIM server recording every write; `patchStatus` refuses group PATCHes that carry a remove op (the delta shape a fussy server rejects). */
function fakeScim(opts: { patchStatus?: number } = {}) {
  const sent: Sent[] = [];
  let n = 0;
  let delayMs = 0;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    const url = String(input instanceof Request ? input.url : input);
    if (!url.startsWith("https://scim.test/")) return new Response("unexpected", { status: 500 });
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.slice("https://scim.test/scim/v2".length);
    const raw = String(init?.body ?? "");
    if (method !== "GET") sent.push({ method, path, body: raw ? JSON.parse(raw) : null, bytes: raw.length });
    if (method === "GET") return Response.json({ Resources: [], totalResults: 0 });
    if (method === "POST") return Response.json({ id: `${path.includes("/Groups") ? "g" : "u"}-${++n}` }, { status: 201 });
    if (method === "PATCH" && path.startsWith("/Groups/") && opts.patchStatus && raw.includes('"remove"')) return new Response("refused", { status: opts.patchStatus });
    return Response.json({}, { status: 200 });
  });
  return { sent, groupWrites: () => sent.filter((s) => s.path.startsWith("/Groups")), reset: () => (sent.length = 0), setDelay: (ms: number) => (delayMs = ms) };
}

async function call(path: string, token: string, method: string, body?: unknown) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(
    new Request(`${BASE}${path}`, { method, headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) }),
    env,
    ctx
  );
  await waitOnExecutionContext(ctx);
  return { status: res.status, body: (await res.json().catch(() => null)) as any };
}

const SIZE = 120;

/** Two static groups of SIZE people each, everyone pushed by a full sync. */
async function directory() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  const people = Array.from({ length: SIZE * 2 }, (_, i) => ({ username: `p${i}`, status: "active" as const, groups: [i < SIZE ? "Big A" : "Big B"] }));
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", groups: [{ name: "Big A" }, { name: "Big B" }, { name: "Small" }], users: [] } });
  for (let i = 0; i < people.length; i += 100) {
    const r = await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", users: people.slice(i, i + 100) } });
    expect(r.status).toBe(200);
  }
  await setScimConfig(env, { endpoint: "https://scim.test/scim/v2", secret: "x".repeat(24) });
  // No pacing in tests, and batch sizes kept the sync loops small.
  await setScimTuning(env, { paceMs: 0, membersPerRequest: 50, syncBatchSize: 200 });
  const scim = fakeScim();
  const target = (await listScimTargets(env))[0]!;
  // A full sync: user batches until the groups step.
  for (let step = await syncAll(env, { restart: true }); !step.complete; step = await syncAll(env)) {
    /* next batch */
  }
  const ids = async (name: string) =>
    (await env.DB.prepare("SELECT g.id, l.scim_id FROM groups g JOIN scim_group_links l ON l.group_id = g.id AND l.target_id = ? WHERE g.name = ?").bind(target.id, name).first<{ id: number; scim_id: string }>())!;
  const userScimId = async (username: string) =>
    (await env.DB.prepare("SELECT l.scim_id FROM scim_user_links l JOIN users u ON u.id = l.user_id WHERE l.target_id = ? AND u.username = ?").bind(target.id, username).first<{ scim_id: string }>())!.scim_id;
  return { apiKey, scim, target, a: await ids("Big A"), b: await ids("Big B"), userScimId };
}

const stored = async (target: ScimTarget, groupId: number) =>
  (await env.DB.prepare("SELECT u.username FROM scim_group_members s JOIN users u ON u.id = s.user_id WHERE s.target_id = ? AND s.group_id = ? ORDER BY u.username").bind(target.id, groupId).all<{ username: string }>()).results.map((r) => r.username);

describe("SCIM group pushes", () => {
  it("creates groups in full the first time, then moves one person with two small PATCHes", async () => {
    const { apiKey, scim, target, a, b, userScimId } = await directory();
    const first = scim.groupWrites();
    const postA = first.find((w) => w.method === "POST" && w.body.displayName === "Big A")!;
    // The create carries identity only - no single body is allowed to dwarf
    // the receiver's limits; members arrive as PATCH adds of 50 at a time.
    expect(postA.body.members).toHaveLength(0);
    const addsA = first.filter((w) => w.method === "PATCH" && w.path.endsWith(a.scim_id));
    expect(addsA.map((w) => w.body.Operations[0].value.length)).toEqual([50, 50, 20]);
    expect(await stored(target, a.id)).toHaveLength(SIZE);

    scim.reset();
    const moved = await call("/api/v1/directory/import", apiKey, "POST", { version: 1, users: [{ username: "p0", status: "active", groups: ["Big B"] }] });
    expect(moved.status).toBe(200);
    const writes = scim.groupWrites();
    expect(writes.map((w) => `${w.method} ${w.path}`).sort()).toEqual([`PATCH /Groups/${a.scim_id}`, `PATCH /Groups/${b.scim_id}`].sort());
    const p0 = await userScimId("p0");
    const toA = writes.find((w) => w.path.endsWith(a.scim_id))!;
    const toB = writes.find((w) => w.path.endsWith(b.scim_id))!;
    expect(toA.body).toEqual({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "remove", path: `members[value eq "${p0}"]` }] });
    expect(toB.body.Operations).toEqual([{ op: "add", path: "members", value: [{ value: p0 }] }]);
    for (const w of writes) expect(w.bytes).toBeLessThan(300);
    expect(postA.bytes).toBeLessThan(300);
    // The stored state follows.
    expect(await stored(target, a.id)).not.toContain("p0");
    expect(await stored(target, b.id)).toContain("p0");
  });

  it("removes a member's previous remote id when it rotates, alongside adding the new one", async () => {
    const { scim, target, a, userScimId } = await directory();
    const oldId = await userScimId("p0");

    // The remote user was deleted and recreated downstream: same account,
    // new remote id. The last push recorded the old one.
    await env.DB.prepare("UPDATE scim_user_links SET scim_id = ? WHERE target_id = ? AND user_id = (SELECT id FROM users WHERE username = 'p0')").bind("u-rotated", target.id).run();

    scim.reset();
    await syncGroups(env, target, [a.id]);
    const patch = scim.groupWrites().find((w) => w.method === "PATCH" && w.path === `/Groups/${a.scim_id}`)!;
    expect(patch).toBeTruthy();
    expect(patch.body.Operations).toContainEqual({ op: "remove", path: `members[value eq "${oldId}"]` });
    expect(patch.body.Operations).toContainEqual({ op: "add", path: "members", value: [{ value: "u-rotated" }] });
  });

  it("sends nothing for a group whose membership did not change (the conformance user's re-import)", async () => {
    const { apiKey, scim, target } = await directory();
    scim.reset();
    const r = await call("/api/v1/directory/import", apiKey, "POST", { version: 1, users: [{ username: "p5", given_name: "P", family_name: "Five", status: "active" }] });
    expect(r.status).toBe(200);
    expect(r.body.scim.errors).toBe(0);
    expect(scim.groupWrites()).toEqual([]);
    expect(scim.sent.filter((s) => s.path.startsWith("/Users"))).toHaveLength(1);
  });

  it("a rename alone is a displayName PATCH; a full sync re-sends groups whole and refreshes the state", async () => {
    const { apiKey, scim, target, a } = await directory();
    scim.reset();
    await call(`/api/v1/groups/${a.id}`, apiKey, "PATCH", { name: "Big A renamed" });
    expect(scim.groupWrites()).toEqual([{ method: "PATCH", path: `/Groups/${a.scim_id}`, bytes: expect.any(Number), body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "displayName", value: "Big A renamed" }] } }]);

    // Drift the stored state; a full sync puts it right with a full PUT
    // followed by the member-set PATCHes.
    await env.DB.prepare("DELETE FROM scim_group_members WHERE target_id = ? AND group_id = ?").bind(target.id, a.id).run();
    scim.reset();
    await syncGroups(env, target);
    const writes = scim.groupWrites().filter((w) => w.path === `/Groups/${a.scim_id}`);
    expect(writes[0]!.method).toBe("PUT");
    expect(writes[0]!.body.members).toHaveLength(0);
    const added = writes.filter((w) => w.method === "PATCH").reduce((n, w) => n + w.body.Operations[0].value.length, 0);
    expect(added).toBe(SIZE);
    expect(await stored(target, a.id)).toHaveLength(SIZE);
  });

  it("falls back to a full PUT when the PATCH is refused, and recreates on 404", async () => {
    const { apiKey, target, a } = await directory();
    vi.restoreAllMocks();
    const refused = fakeScim({ patchStatus: 400 });
    await call(`/api/v1/groups/${a.id}/members/p1`, apiKey, "DELETE");
    // PATCH refused → full PUT (empty members) → member PATCHes.
    expect(refused.groupWrites().map((w) => w.method)).toEqual(["PATCH", "PUT", "PATCH", "PATCH", "PATCH"]);
    expect(refused.groupWrites()[1]!.body.members).toHaveLength(0);
    const readded = refused.groupWrites().filter((w) => w.method === "PATCH" && w.body.Operations[0].op === "add").reduce((n, w) => n + w.body.Operations[0].value.length, 0);
    expect(readded).toBe(SIZE - 1);
    expect(await stored(target, a.id)).toHaveLength(SIZE - 1);

    vi.restoreAllMocks();
    const gone = fakeScim({ patchStatus: 404 });
    await call(`/api/v1/groups/${a.id}/members/p2`, apiKey, "DELETE");
    expect(gone.groupWrites().map((w) => w.method)).toEqual(["PATCH", "POST", "PATCH", "PATCH", "PATCH"]);
    expect(gone.groupWrites()[1]!.body.members).toHaveLength(0);
    const relinked = (await env.DB.prepare("SELECT scim_id FROM scim_group_links WHERE target_id = ? AND group_id = ?").bind(target.id, a.id).first<{ scim_id: string }>())!.scim_id;
    expect(relinked).not.toBe(a.scim_id);
    expect(await env.DB.prepare("SELECT scim_id FROM scim_group_state WHERE target_id = ? AND group_id = ?").bind(target.id, a.id).first()).toEqual({ scim_id: relinked });
  });

  it("sends a large change as a full PUT", async () => {
    const { apiKey, scim, target } = await directory();
    await call("/api/v1/directory/import", apiKey, "POST", { version: 1, users: ["p0", "p1", "p2"].map((username) => ({ username, status: "active", groups: ["Small", "Big A"] })) });
    const small = (await env.DB.prepare("SELECT g.id, l.scim_id FROM groups g JOIN scim_group_links l ON l.group_id = g.id AND l.target_id = ? WHERE g.name = 'Small'").bind(target.id).first<{ id: number; scim_id: string }>())!;
    expect(await stored(target, small.id)).toEqual(["p0", "p1", "p2"]);
    scim.reset();
    // Two of Small's three leave: more than half the group.
    await call("/api/v1/directory/import", apiKey, "POST", { version: 1, users: ["p0", "p1"].map((username) => ({ username, status: "active", groups: ["Big A"] })) });
    const writes = scim.groupWrites();
    expect(writes.map((w) => `${w.method} ${w.path}`)).toEqual([`PUT /Groups/${small.scim_id}`, `PATCH /Groups/${small.scim_id}`]);
    expect(writes[0]!.body.members).toHaveLength(0);
    expect(writes[1]!.body.Operations).toEqual([{ op: "add", path: "members", value: [{ value: expect.any(String) }] }]);
    expect(await stored(target, small.id)).toEqual(["p2"]);
  });

  it("answers the write before a slow remote finishes - pushes are post-response work", async () => {
    const { apiKey, scim, target } = await directory();
    scim.reset();
    scim.setDelay(300);
    const ctx = createExecutionContext();
    const res = await worker.fetch(
      new Request(`${BASE}/api/v1/users/p0`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ given_name: "Renamed" }),
      }),
      env,
      ctx
    );
    expect(res.status).toBe(200);
    // The remote call is still sleeping, but the write has already answered.
    expect(scim.sent).toHaveLength(0);
    // Flushing the context shows the push ran after the response.
    await waitOnExecutionContext(ctx);
    expect(scim.sent.some((s) => s.path.startsWith("/Users"))).toBe(true);
  });

  it("forgets a deleted group's state, and a deleted user's rows", async () => {
    const { apiKey, target, a, b } = await directory();
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_group_state WHERE target_id = ? AND group_id = ?").bind(target.id, a.id).first()).toEqual({ n: 1 });
    expect((await call(`/api/v1/groups/${a.id}`, apiKey, "DELETE")).status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_group_state WHERE target_id = ? AND group_id = ?").bind(target.id, a.id).first()).toEqual({ n: 0 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_group_members WHERE target_id = ? AND group_id = ?").bind(target.id, a.id).first()).toEqual({ n: 0 });

    const before = (await stored(target, b.id)).length;
    expect((await call(`/api/v1/users/p${SIZE}`, apiKey, "DELETE")).status).toBe(200);
    expect(await stored(target, b.id)).toHaveLength(before - 1);
    expect(await stored(target, b.id)).not.toContain(`p${SIZE}`);
  });

  it("batches PATCH operations at the configured member references per request", () => {
    const add = Array.from({ length: 2500 }, (_, i) => `a${i}`);
    const remove = Array.from({ length: 700 }, (_, i) => `r${i}`);
    const bodies = groupPatchBodies(add, remove, "New name", 1000).map((b) => JSON.parse(b) as { Operations: { op: string; path: string; value?: unknown[] }[] });
    expect(bodies).toHaveLength(4);
    const refs = bodies.map((b) => b.Operations.reduce((n, op) => n + (op.path === "members" ? op.value!.length : op.op === "remove" ? 1 : 0), 0));
    expect(refs).toEqual([1000, 1000, 1000, 200]);
    expect(bodies[0]!.Operations[0]).toEqual({ op: "replace", path: "displayName", value: "New name" });
    expect(bodies.slice(1).every((b) => b.Operations.every((op) => op.path !== "displayName"))).toBe(true);
    expect(groupPatchBodies([], ['x"y'], null)).toEqual([JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "remove", path: 'members[value eq "x\\"y"]' }] })]);
  });
});

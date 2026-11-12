// Group lists resolve every group's members with one read of the directory,
// not one per dynamic group (and SCIM resolves none when members are not asked for).
import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

/** env with a D1 binding that records every statement prepared through it. */
function countingEnv() {
  const sql: string[] = [];
  const db = new Proxy(env.DB, {
    get(target, prop) {
      if (prop === "prepare") return (query: string) => (sql.push(query), target.prepare(query));
      const value = Reflect.get(target, prop);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { env: { ...env, DB: db } as typeof env, sql };
}

const fullUserReads = (sql: string[]) => sql.filter((q) => /^\s*SELECT \* FROM users\s*$/i.test(q)).length;

async function seed(apiKey: string) {
  const rule = (value: string) => JSON.stringify({ all: [{ field: "department", op: "eq", value }] });
  const r = await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      passwords: "none",
      groups: [{ name: "Sales (dynamic)", rule: rule("Sales") }, { name: "Ops (dynamic)", rule: rule("Ops") }, { name: "Legal (dynamic)", rule: rule("Legal") }, { name: "Not Sales", rule: JSON.stringify({ all: [{ field: "department", op: "ne", value: "Sales" }] }) }, { name: "Static" }],
      users: [
        { username: "s1", department: "Sales", status: "active", groups: ["Static"] },
        { username: "s2", department: "Sales", status: "active" },
        { username: "o1", department: "Ops", status: "active", groups: ["Static"] },
        { username: "l1", department: "Legal", status: "active" },
      ],
    },
  });
  expect(r.status).toBe(200);
}

async function get(e: typeof env, path: string, token: string) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } }), e, ctx);
  await waitOnExecutionContext(ctx);
  return { status: res.status, body: (await res.json()) as any };
}

describe("group lists", () => {
  it("GET /api/v1/groups reads the users table once for all dynamic groups", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seed(apiKey);
    const { env: e, sql } = countingEnv();
    const res = await get(e, "/api/v1/groups", apiKey);
    expect(res.status).toBe(200);
    const count = (name: string) => res.body.groups.find((g: { name: string }) => g.name === name).member_count;
    expect(count("Sales (dynamic)")).toBe(2);
    expect(count("Ops (dynamic)")).toBe(1);
    expect(count("Not Sales")).toBe(3); // o1, l1 and the administrator
    expect(count("Static")).toBe(2);
    expect(fullUserReads(sql)).toBe(1);
  });

  it("GET /api/v1/groups/{id} stays correct for a dynamic group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seed(apiKey);
    const id = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Sales (dynamic)'").first<{ id: number }>())!.id;
    const res = await get(env, `/api/v1/groups/${id}`, apiKey);
    expect(res.body.member_count).toBe(2);
    expect(res.body.members.users.map((u: { username: string }) => u.username).sort()).toEqual(["s1", "s2"]);
  });

  it("GET /scim/v2/Groups reads the users table at most once per page, and not at all without members", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seed(apiKey);

    const full = countingEnv();
    const listed = await get(full.env, "/scim/v2/Groups", apiKey);
    expect(listed.status).toBe(200);
    const sales = listed.body.Resources.find((g: { displayName: string }) => g.displayName === "Sales (dynamic)");
    expect(sales.members).toHaveLength(2);
    expect(listed.body.Resources.find((g: { displayName: string }) => g.displayName === "Static").members).toHaveLength(2);
    expect(fullUserReads(full.sql)).toBe(1);

    const bare = countingEnv();
    const without = await get(bare.env, "/scim/v2/Groups?excludedAttributes=members", apiKey);
    expect(without.body.Resources.length).toBe(listed.body.Resources.length);
    expect(without.body.Resources.every((g: Record<string, unknown>) => !("members" in g))).toBe(true);
    expect(fullUserReads(bare.sql)).toBe(0);
    expect(bare.sql.some((q) => /group_members/.test(q))).toBe(false);

    const named = countingEnv();
    const onlyName = await get(named.env, "/scim/v2/Groups?attributes=displayName", apiKey);
    expect(onlyName.body.Resources.every((g: Record<string, unknown>) => !("members" in g))).toBe(true);
    expect(fullUserReads(named.sql)).toBe(0);

    // The single-group read still resolves the rule.
    const one = await get(env, `/scim/v2/Groups/${sales.id}`, apiKey);
    expect(one.body.members).toHaveLength(2);
  });
});

import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

async function scim(token: string, path: string, method = "GET", body?: unknown) {
  const res = await SELF.fetch(`${BASE}/scim/v2${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/scim+json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, type: res.headers.get("Content-Type") ?? "", body: text ? JSON.parse(text) : null };
}

const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

describe("SCIM 2.0 server", () => {
  it("creates, finds, patches, deactivates and deletes a user", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const created = await scim(apiKey, "/Users", "POST", {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "kim.lee@horizon.test",
      name: { givenName: "Kim", familyName: "Lee" },
      displayName: "Kim Lee",
      active: true,
      emails: [{ value: "kim@personal.test", primary: true }],
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { department: "Sales" },
    });
    expect(created.status).toBe(201);
    expect(created.type).toContain("application/scim+json");
    const id = created.body.id as string;

    const found = await scim(apiKey, `/Users?filter=${encodeURIComponent('userName eq "kim.lee@horizon.test"')}`);
    expect(found.body.totalResults).toBe(1);
    expect(found.body.Resources[0].id).toBe(id);

    expect((await scim(apiKey, "/Users", "POST", { userName: "kim.lee@horizon.test" })).status).toBe(409);

    const patched = await scim(apiKey, `/Users/${id}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "replace", path: "title", value: "Account Executive" }, { op: "replace", path: "active", value: false }] });
    expect(patched.body.title).toBe("Account Executive");
    expect(patched.body.active).toBe(false);

    expect((await scim(apiKey, `/Users/${id}`, "DELETE")).status).toBe(204);
    expect((await scim(apiKey, `/Users/${id}`)).status).toBe(404);
  });

  it("manages static group membership, and refuses members for dynamic groups", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const user = await scim(apiKey, "/Users", "POST", { userName: "jo@horizon.test", active: true });
    const group = await scim(apiKey, "/Groups", "POST", { displayName: "Field Sales", members: [{ value: user.body.id }] });
    expect(group.status).toBe(201);
    expect(group.body.members).toHaveLength(1);

    const removed = await scim(apiKey, `/Groups/${group.body.id}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "remove", path: `members[value eq "${user.body.id}"]` }] });
    expect(removed.body.members).toHaveLength(0);

    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, groups: [{ name: "Everyone", rule: JSON.stringify({ all: [{ field: "status", op: "eq", value: "active" }] }) }], users: [] } });
    const dyn = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Everyone'").first<{ id: number }>())!.id;
    const refused = await scim(apiKey, `/Groups/${dyn}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "add", path: "members", value: [{ value: user.body.id }] }] });
    expect(refused.status).toBe(400);
    expect(refused.body.scimType).toBe("mutability");
  });

  it("keeps Super Admins out of a non-admin key's reach, and needs a key at all", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = (await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "hr", scopes: ["directory:read", "directory:write"] } })).body.token as string;
    const admin = (await scim(dw, `/Users?filter=${encodeURIComponent('userName eq "admin@horizon.test"')}`)).body.Resources[0];
    expect((await scim(dw, `/Users/${admin.id}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "replace", path: "active", value: false }] })).status).toBe(403);
    const sa = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Super Admins'").first<{ id: number }>())!.id;
    const self = await scim(dw, "/Users", "POST", { userName: "mallory@horizon.test", active: true });
    expect((await scim(dw, `/Groups/${sa}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "add", path: "members", value: [{ value: self.body.id }] }] })).status).toBe(403);
    expect((await scim("flareid_sk_nope", "/Users")).status).toBe(401);
  });
});

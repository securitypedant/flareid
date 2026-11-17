// The contact-address list (user_emails): SCIM writes it whole, the API and
// console go through the same service, the primary is mirrored to users.email,
// and any address names the account for sign-in and recovery.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function scim(token: string, path: string, method = "GET", body?: unknown) {
  const res = await SELF.fetch(`${BASE}/scim/v2${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/scim+json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const storedEmails = async (username: string) =>
  (
    await env.DB.prepare("SELECT e.email, e.type, e.is_primary FROM user_emails e JOIN users u ON u.id = e.user_id WHERE u.username = ? ORDER BY e.is_primary DESC, e.id")
      .bind(username)
      .all<{ email: string; type: string; is_primary: number }>()
  ).results;

describe("user email addresses", () => {
  it("stores the whole SCIM emails list, mirrors the primary, and serves it back", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const created = await scim(apiKey, "/Users", "POST", {
      userName: "kim.lee@horizon.test",
      name: { givenName: "Kim", familyName: "Lee" },
      active: true,
      emails: [
        { value: "kim@work.test", type: "work", primary: true },
        { value: "kim@personal.test", type: "home" },
      ],
    });
    expect(created.status).toBe(201);
    expect(created.body.emails).toEqual([
      { value: "kim@work.test", type: "work", primary: true },
      { value: "kim@personal.test", type: "home", primary: false },
    ]);
    expect(await storedEmails("kim.lee")).toEqual([
      { email: "kim@work.test", type: "work", is_primary: 1 },
      { email: "kim@personal.test", type: "home", is_primary: 0 },
    ]);
    expect((await env.DB.prepare("SELECT email FROM users WHERE username = 'kim.lee'").first<{ email: string }>())!.email).toBe("kim@work.test");

    // Replacing the list promotes a different primary - users.email follows.
    const patched = await scim(apiKey, `/Users/${created.body.id}`, "PATCH", {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "emails", value: [{ value: "kim@personal.test", type: "home", primary: true }] }],
    });
    expect(patched.status).toBe(200);
    expect(patched.body.emails).toEqual([{ value: "kim@personal.test", type: "home", primary: true }]);
    expect((await env.DB.prepare("SELECT email FROM users WHERE username = 'kim.lee'").first<{ email: string }>())!.email).toBe("kim@personal.test");
  });

  it("refuses an address another account already holds, on create and on update", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await scim(apiKey, "/Users", "POST", { userName: "a@horizon.test", active: true, emails: [{ value: "shared@test.dev" }] });
    expect((await scim(apiKey, "/Users", "POST", { userName: "b@horizon.test", active: true, emails: [{ value: "shared@test.dev" }] })).status).toBe(409);

    const c = await scim(apiKey, "/Users", "POST", { userName: "c@horizon.test", active: true });
    const conflict = await scim(apiKey, `/Users/${c.body.id}`, "PATCH", {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "emails", value: [{ value: "shared@test.dev" }] }],
    });
    expect(conflict.status).toBe(409);
    // Malformed is a plain bad request, not a 500.
    const bad = await scim(apiKey, `/Users/${c.body.id}`, "PATCH", {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "emails", value: [{ value: "not-an-address" }] }],
    });
    expect(bad.status).toBe(400);
  });

  it("keeps the list in sync when the API writes it, and signs in by alias", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/users", {
      token: apiKey,
      body: { username: "rita", given_name: "Rita", password: "rita-password-9", status: "active", emails: [{ value: "rita@work.test", primary: true }, { value: "rita@home.test", type: "home" }] },
    });
    expect(await storedEmails("rita")).toEqual([
      { email: "rita@work.test", type: "work", is_primary: 1 },
      { email: "rita@home.test", type: "home", is_primary: 0 },
    ]);

    // PATCH replaces the list; GET returns it.
    const patched = await apiCall("/api/v1/users/rita", { token: apiKey, method: "PATCH", body: { emails: [{ value: "rita@new.test" }] } });
    expect(patched.status).toBe(200);
    expect(patched.body.emails).toEqual([{ value: "rita@new.test", type: "work", primary: true }]);
    expect((await env.DB.prepare("SELECT email FROM users WHERE username = 'rita'").first<{ email: string }>())!.email).toBe("rita@new.test");

    // Signing in with the alias identifies the same account.
    const page = await (await SELF.fetch(`${BASE}/login`)).text();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
    const signIn = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: FORM,
      body: new URLSearchParams({ flow_id: flowId, upn: "rita@new.test", password: "rita-password-9" }).toString(),
      redirect: "manual",
    });
    expect(signIn.headers.get("Set-Cookie")).toContain("flareid_session");
  });
});

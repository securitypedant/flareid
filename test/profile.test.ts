import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function setup(attributes: Record<string, unknown>[]) {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  const schema = await apiCall("/api/v1/schemas", { token: apiKey, body: { object_type: "user", name: "Staff", attributes } });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: { version: 1, users: [{ username: "pia", password: "pia-password-1", status: "active", schema: "Staff", attributes: { location: "Oslo", pronouns: "she/her" } }] },
  });
  const user = (await env.DB.prepare("SELECT id FROM users WHERE username = 'pia'").first<{ id: number }>())!;
  const { setCookie } = await createSession(env, user.id, ["pwd"], new Request(BASE));
  return { apiKey, schemaId: schema.body.id as number, userId: user.id, cookie: setCookie.split(";")[0]! };
}

describe("self-service profile editing", () => {
  it("lets a user change exactly the attributes their schema marks editable", async () => {
    const { userId, cookie } = await setup([
      { name: "location", label: "Location", user_editable: true },
      { name: "pronouns", label: "Pronouns", user_editable: true },
      { name: "department", label: "Department" },
    ]);
    const page = await (await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie } })).text();
    expect(page).toContain("Edit your details");
    expect(page).toContain('name="attr_location"');
    expect(page).not.toContain('name="attr_department"');

    // department is posted too, and must be ignored.
    const res = await SELF.fetch(`${BASE}/account/profile`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ attr_location: "Bergen", attr_pronouns: "", attr_department: "Finance" }).toString(),
      redirect: "manual",
    });
    expect(res.headers.get("Location")).toBe("/account?saved=profile");
    const row = (await env.DB.prepare("SELECT location, department, custom_attributes FROM users WHERE id = ?").bind(userId).first<{ location: string; department: string; custom_attributes: string }>())!;
    expect(row.location).toBe("Bergen");
    expect(row.department).not.toBe("Finance");
    expect(JSON.parse(row.custom_attributes).pronouns).toBeUndefined();
  });

  it("refuses to make an attribute editable while a dynamic group's rule uses it, and the reverse", async () => {
    const { apiKey, schemaId } = await setup([{ name: "location", label: "Location" }]);
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, groups: [{ name: "Oslo office", rule: JSON.stringify({ all: [{ field: "location", op: "eq", value: "Oslo" }] }) }], users: [] },
    });
    const refused = await apiCall(`/api/v1/schemas/${schemaId}`, { token: apiKey, method: "PATCH", body: { attributes: [{ name: "location", label: "Location", user_editable: true }] } });
    expect(refused.status).toBe(400);

    // And with an editable attribute in place, a new rule on it is ignored by the import.
    await apiCall(`/api/v1/schemas/${schemaId}`, { token: apiKey, method: "PATCH", body: { attributes: [{ name: "location", label: "Location" }, { name: "pronouns", label: "Pronouns", user_editable: true }] } });
    const imported = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, groups: [{ name: "She/her", rule: JSON.stringify({ all: [{ field: "pronouns", op: "eq", value: "she/her" }] }) }], users: [] },
    });
    expect(imported.body.errors.some((e: { group?: string }) => e.group === "She/her")).toBe(true);
  });
});

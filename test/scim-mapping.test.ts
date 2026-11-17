import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { evalExpression, parseExpression, ScimMappingError } from "../src/lib/scim-mapping.js";

beforeEach(resetDatabase);

const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

async function scim(token: string, path: string, method = "GET", body?: unknown) {
  const res = await SELF.fetch(`${BASE}/scim/v2${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/scim+json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const doc = {
  userName: "JDoe@corp.example",
  name: { givenName: "John", familyName: "Doe" },
  emails: [
    { value: "john@work.example", type: "work", primary: true },
    { value: "jd@home.example", type: "home" },
  ],
  [ENT]: { department: "Sales", employeeNumber: "E-42", manager: { value: "ext-9" } },
};

describe("mapping expressions", () => {
  const ev = (src: string) => evalExpression(parseExpression(src), doc);

  it("resolves paths, filters and URN attributes", () => {
    expect(ev("name.givenName")).toBe("John");
    expect(ev('emails[type eq "work"].value')).toEqual(["john@work.example"]);
    expect(ev("emails[primary eq true].value")).toEqual(["john@work.example"]);
    expect(ev(`${ENT}:department`)).toBe("Sales");
    expect(ev(`${ENT}:manager.value`)).toBe("ext-9");
    expect(ev("missing.path")).toBeNull();
  });

  it("applies functions and concatenation", () => {
    expect(ev('lower(name.givenName + "." + name.familyName)')).toBe("john.doe");
    expect(ev('join(" ", name.givenName, name.familyName)')).toBe("John Doe");
    expect(ev('coalesce(missing, name.givenName, "x")')).toBe("John");
    expect(ev("first(emails.value)")).toBe("john@work.example");
    expect(ev('split(userName, "@")')).toEqual(["JDoe", "corp.example"]);
    expect(ev('upper(trim("  a  "))')).toBe("A");
    expect(ev('if(eq(name.givenName, "John"), "yes", "no")')).toBe("yes");
  });

  it("rejects bad syntax and unknown functions", () => {
    expect(() => parseExpression("name.")).toThrow(ScimMappingError);
    expect(() => parseExpression("(")).toThrow(ScimMappingError);
    expect(() => parseExpression("emails[type zz")).toThrow(ScimMappingError);
    expect(() => ev("bogus(1)")).toThrow(ScimMappingError);
  });
});

describe("inbound attribute mappings", () => {
  async function setMappings(mappings: { target: string; expression: string; enabled?: boolean }[]) {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const res = await apiCall("/api/v1/scim/mappings", { token: apiKey, method: "PUT", body: { mappings } });
    return { apiKey, res };
  }

  it("derives the UPN and fields on create", async () => {
    const { apiKey } = await setMappings([
      { target: "upn", expression: 'lower(name.givenName + "." + name.familyName) + "@horizon.test"' },
      { target: "display_name", expression: 'join(" ", name.givenName, name.familyName)' },
      { target: "department", expression: `${ENT}:costCenter` },
      { target: "custom.pronouns", expression: '"she/her"' },
    ]);
    const created = await scim(apiKey, "/Users", "POST", {
      userName: "ignored-but-present@horizon.test",
      name: { givenName: "Ada", familyName: "Wong" },
      [ENT]: { costCenter: "R&D" },
      active: true,
    });
    expect(created.status).toBe(201);
    expect(created.body.userName).toBe("ada.wong@horizon.test");
    expect(created.body.displayName).toBe("Ada Wong");

    const row = (await env.DB.prepare("SELECT department, custom_attributes FROM users WHERE upn = ?").bind("ada.wong@horizon.test").first<{ department: string; custom_attributes: string }>())!;
    expect(row.department).toBe("R&D");
    expect(JSON.parse(row.custom_attributes).pronouns).toBe("she/her");
  });

  it("maps emails and active through expressions", async () => {
    const { apiKey } = await setMappings([
      { target: "emails", expression: 'lower(name.givenName + "." + name.familyName + "@horizon.test")' },
      { target: "active", expression: 'if(eq(urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employmentStatus, "Contractor"), false, true)' },
    ]);
    const contractor = await scim(apiKey, "/Users", "POST", { userName: "con@horizon.test", name: { givenName: "Bo", familyName: "Kim" }, [ENT]: { employmentStatus: "Contractor" } });
    expect(contractor.body.active).toBe(false);
    expect(contractor.body.emails).toEqual([{ value: "bo.kim@horizon.test", type: "work", primary: true }]);
  });

  it("PATCH evaluates over the merged resource and leaves untouched fields alone", async () => {
    const { apiKey } = await setMappings([{ target: "display_name", expression: 'join(" ", name.givenName, name.familyName)' }]);
    const created = await scim(apiKey, "/Users", "POST", { userName: "sam@horizon.test", name: { givenName: "Sam", familyName: "Old" }, title: "Engineer", active: true });
    const id = created.body.id;

    const patched = await scim(apiKey, `/Users/${id}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "replace", path: "name.familyName", value: "New" }] });
    expect(patched.body.displayName).toBe("Sam New");
    expect(patched.body.title).toBe("Engineer");
  });

  it("a mapping yielding nothing clears the field on PUT only", async () => {
    const { apiKey } = await setMappings([{ target: "job_title", expression: 'coalesce(urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:role, "")' }]);
    const created = await scim(apiKey, "/Users", "POST", { userName: "t@horizon.test", title: "Engineer", [ENT]: { role: "Lead" }, active: true });
    const id = created.body.id;
    expect(created.body.title).toBe("Lead");

    // PATCH of an unrelated field: the expression yields "" - field stays.
    await scim(apiKey, `/Users/${id}`, "PATCH", { schemas: [PATCH], Operations: [{ op: "replace", path: "name.givenName", value: "T" }] });
    expect((await scim(apiKey, `/Users/${id}`)).body.title).toBe("Lead");

    // PUT without the source attribute: the field clears.
    const put = await scim(apiKey, `/Users/${id}`, "PUT", { userName: "t@horizon.test", title: "Ignored" });
    expect(put.body.title).toBeUndefined();
  });

  it("rejects invalid mappings and duplicate targets", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    expect((await apiCall("/api/v1/scim/mappings", { token: apiKey, method: "PUT", body: { mappings: [{ target: "upn", expression: "bad(" }] } })).status).toBe(400);
    expect((await apiCall("/api/v1/scim/mappings", { token: apiKey, method: "PUT", body: { mappings: [{ target: "not_a_field", expression: "name.givenName" }] } })).status).toBe(400);
    expect((await apiCall("/api/v1/scim/mappings", { token: apiKey, method: "PUT", body: { mappings: [{ target: "upn", expression: "a" }, { target: "upn", expression: "b" }] } })).status).toBe(400);
    const ok = await apiCall("/api/v1/scim/mappings", { token: apiKey, method: "PUT", body: { mappings: [{ target: "display_name", expression: "name.givenName", enabled: false }] } });
    expect(ok.status).toBe(200);
    const list = await apiCall("/api/v1/scim/mappings", { token: apiKey });
    expect(list.body.mappings).toEqual([{ target: "display_name", expression: "name.givenName", enabled: false }]);
    // Disabled: the standard mapping still applies.
    const created = await scim(apiKey, "/Users", "POST", { userName: "x@horizon.test", displayName: "Given Name" });
    expect(created.body.displayName).toBe("Given Name");
  });

  it("stores externalId as source_id and resolves managers through it", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const mgr = await scim(apiKey, "/Users", "POST", { userName: "boss@horizon.test", externalId: "hr-100", displayName: "Boss", active: true });
    expect(mgr.body.externalId).toBe("hr-100");

    const sub = await scim(apiKey, "/Users", "POST", {
      userName: "sub@horizon.test",
      [ENT]: { manager: { value: "hr-100" } },
    });
    expect(sub.body[ENT].manager.value).toBe(mgr.body.id);
    expect(sub.body[ENT].manager.displayName).toBe("Boss");
  });

  it("correlation adopts an existing account instead of 409ing", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    // No keys configured: duplicates still conflict.
    const first = await scim(apiKey, "/Users", "POST", { userName: "rehired@horizon.test", emails: [{ value: "re@home.test", primary: true }], [ENT]: { employeeNumber: "E-7" }, active: true });
    expect((await scim(apiKey, "/Users", "POST", { userName: "rehired@horizon.test" })).status).toBe(409);

    await apiCall("/api/v1/scim/correlation", { token: apiKey, method: "PUT", body: { keys: ["emails", "upn"] } });
    expect((await apiCall("/api/v1/scim/correlation", { token: apiKey })).body.keys).toEqual(["emails", "upn"]);

    // A create under a different userName but with the same address adopts.
    const adopted = await scim(apiKey, "/Users", "POST", { userName: "rehired2@horizon.test", emails: [{ value: "re@home.test", primary: true }], displayName: "Re Hired", active: true });
    expect(adopted.status).toBe(200);
    expect(adopted.body.id).toBe(first.body.id);
    expect(adopted.body.userName).toBe("rehired@horizon.test");
    expect(adopted.body.displayName).toBe("Re Hired");

    // And upn correlation turns a same-userName create into an update.
    const again = await scim(apiKey, "/Users", "POST", { userName: "rehired@horizon.test", title: "Rehired Title" });
    expect(again.status).toBe(200);
    expect(again.body.title).toBe("Rehired Title");

    const { n } = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE employee_number = 'E-7'").first<{ n: number }>())!;
    expect(n).toBe(1);
  });

  it("correlation refuses an ambiguous match and bad keys", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    // Two users sharing an employee number, created before correlation is on.
    expect((await scim(apiKey, "/Users", "POST", { userName: "a@horizon.test", [ENT]: { employeeNumber: "DUP" } })).status).toBe(201);
    expect((await scim(apiKey, "/Users", "POST", { userName: "b@horizon.test", [ENT]: { employeeNumber: "DUP" } })).status).toBe(201);
    await apiCall("/api/v1/scim/correlation", { token: apiKey, method: "PUT", body: { keys: ["employee_number"] } });

    const res = await scim(apiKey, "/Users", "POST", { userName: "c@horizon.test", [ENT]: { employeeNumber: "DUP" } });
    expect(res.status).toBe(409);
    expect(res.body.detail).toContain("ambiguous");

    expect((await apiCall("/api/v1/scim/correlation", { token: apiKey, method: "PUT", body: { keys: ["bogus"] } })).status).toBe(400);
  });

  it("the console form saves the same set the API reads", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const res = await SELF.fetch(`${BASE}/admin/scim/mappings`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: cookie },
      body: "map_target=display_name&map_expr=name.givenName&map_enabled=1&map_target=department&map_expr=urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Aextension%3Aenterprise%3A2.0%3AUser%3Adepartment&map_enabled=0",
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const list = await apiCall("/api/v1/scim/mappings", { token: apiKey });
    expect(list.body.mappings).toEqual([
      { target: "display_name", expression: "name.givenName", enabled: true },
      { target: "department", expression: `${ENT}:department`, enabled: false },
    ]);
  });
});

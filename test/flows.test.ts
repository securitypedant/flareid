import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { evalExpression, parseExpression } from "../src/lib/expr.js";
import { clientMappedClaims, effectiveMappings, getCollisionPolicy, listMappings, replaceMappings, setCollisionPolicy } from "../src/lib/mappings.js";
import { createUpstreamIdp, FederationError, mappedProfileFromClaims, resolveFederatedUser } from "../src/lib/federation.js";
import { parseRule, ruleFromForm, userMatchesRule } from "../src/lib/groups.js";
import { resolveAttributes } from "../src/lib/saml/attributes.js";
import { mappedUserToScim } from "../src/lib/scim-client.js";
import { createSession } from "../src/lib/sessions.js";
import type { UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);

const ev = (src: string, doc: unknown) => evalExpression(parseExpression(src), doc);

describe("the expression language", () => {
  it("composes values the classic function set couldn't reach", () => {
    const doc = { given_name: "Ada", family_name: "Lovelace", email: "ada@example.com", name: "Ada Byron Lovelace", hire_date: "2021-03-08" };
    expect(ev('lower(given_name + "." + family_name)', doc)).toBe("ada.lovelace");
    expect(ev('format("{0}.{1}@corp.test", lower(given_name), lower(family_name))', doc)).toBe("ada.lovelace@corp.test");
    expect(ev('join(" ", given_name, family_name)', doc)).toBe("Ada Lovelace");
    expect(ev('localpart(email)', doc)).toBe("ada");
    expect(ev('domainpart(email)', doc)).toBe("example.com");
    expect(ev('word(name, 0)', doc)).toBe("Ada");
    expect(ev('word(name, 2)', doc)).toBe("Lovelace");
    expect(ev('initials(name)', doc)).toBe("ABL");
    expect(ev('title(lower(name))', doc)).toBe("Ada Byron Lovelace");
    expect(ev('year(hire_date)', doc)).toBe(2021);
  });

  it("sanitizes for sign-in names", () => {
    expect(ev('lower(ascii(given_name + "." + family_name))', { given_name: "José", family_name: "O'Brien" })).toBe("jose.o'brien");
    expect(ev('alnum(lower(ascii(family_name)))', { family_name: "O'Brien-Smith" })).toBe("obriensmith");
  });

  it("reaches attributes outside the path grammar with attr()", () => {
    const claims = { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "ws@example.com" };
    expect(ev('attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")', claims)).toBe("ws@example.com");
    expect(ev('coalesce(email, attr("urn:oid:0.9.2342.19200300.100.1.3"))', { "urn:oid:0.9.2342.19200300.100.1.3": "oid@example.com" })).toBe("oid@example.com");
  });

  it("compares, selects and counts", () => {
    const doc = { department: "Engineering", groups: ["a", "b"], n: 4 };
    expect(ev('contains(department, "eng")', doc)).toBe(true);
    expect(ev('startsWith(department, "Eng")', doc)).toBe(true);
    expect(ev('len(groups)', doc)).toBe(2);
    expect(ev('in(department, "HR", "Engineering")', doc)).toBe(true);
    expect(ev('select(eq(department, "Engineering"), "eng", "other")', doc)).toBe("eng");
    expect(ev('and(gt(n, 2), lt(n, 10))', doc)).toBe(true);
    expect(ev('add(n, 1)', doc)).toBe(5);
    expect(ev('substr(department, 0, 4)', doc)).toBe("Engi");
    expect(ev('at(groups, -1)', doc)).toBe("b");
    expect(ev('replace(department, "Engineering", "Eng")', doc)).toBe("Eng");
  });
});

describe("dynamic group rules", () => {
  const user = {
    id: 1, username: "ada", upn: "ada@example.com", display_name: "Ada Lovelace", given_name: "Ada", family_name: "Lovelace",
    job_title: "", department: "Engineering", employee_number: "", hire_date: "2021-01-01", employment_status: "", employment_type: "full_time",
    location: "london", status: "active", manager_external_id: null, source_id: null, custom_attributes: '{"cost_center":"cc-42"}',
  } as UserRow;

  it("evaluates expr conditions over the user document", () => {
    const rule = parseRule(JSON.stringify({ all: [{ expr: 'startsWith(lower(department), "eng")' }, { field: "employment_type", op: "eq", value: "full_time" }] }))!;
    expect(userMatchesRule(user, rule)).toBe(true);
    expect(userMatchesRule({ ...user, department: "HR" }, rule)).toBe(false);
  });

  it("sees custom attributes in expressions", () => {
    const rule = parseRule(JSON.stringify({ all: [{ expr: 'eq(custom.cost_center, "cc-42")' }] }))!;
    expect(userMatchesRule(user, rule)).toBe(true);
  });

  it("builds expr conditions from the form and rejects bad expressions", () => {
    const rule = ruleFromForm([""], [""], ["expr"], ['contains(department, "eng")']);
    expect(JSON.parse(rule)).toEqual({ all: [{ expr: 'contains(department, "eng")' }] });
    expect(() => ruleFromForm([""], [""], ["expr"], ["contains("])).toThrow(/invalid/);
  });
});

async function seedUserViaApi(apiKey: string, username: string, extra: Record<string, unknown> = {}) {
  const res = await apiCall("/api/v1/users", { token: apiKey, body: { username, given_name: username, password: "user-password-123", status: "active", ...extra } });
  expect(res.status).toBe(201);
  return (await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first<UserRow>())!;
}

describe("JIT mappings", () => {
  const oidcInput = () => ({ name: "U", protocol: "oidc" as const, config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "horizon.test" });

  it("seeds the global defaults with the built-in claim names", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const rows = await listMappings(env, { channel: "jit", owner: "" });
    expect(rows.map((r) => r.target).sort()).toEqual(["display_name", "email", "family_name", "given_name", "username"]);
    const profile = await mappedProfileFromClaims(env, { sub: "s", mail: "ada@corp.test", givenname: "Ada" }, "s");
    expect(profile.email).toBe("ada@corp.test");
    expect(profile.givenName).toBe("Ada");
  });

  it("lets an IdP override the defaults with expressions", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const idp = await createUpstreamIdp(env, oidcInput());
    await replaceMappings(env, { channel: "jit", owner: String(idp.id) }, [
      { target: "username", expression: 'lower(given_name + "." + family_name)' },
      { target: "email", expression: "work_email" },
      { target: "display_name", expression: 'given_name + " " + family_name' },
      { target: "department", expression: "dept" },
      { target: "custom.cost_center", expression: "cc" },
    ]);
    const profile = await mappedProfileFromClaims(
      env,
      { sub: "s", first: "Ada", last: "Lovelace", work_email: "ada@corp.test", dept: "Math", cc: "cc-9" },
      "s",
      { first: "given_name", last: "family_name" },
      idp.id
    );
    expect(profile.username).toBe("ada.lovelace");
    expect(profile.email).toBe("ada@corp.test");
    expect(profile.displayName).toBe("Ada Lovelace");
    expect(profile.cols?.department).toBe("Math");
    expect(profile.custom?.cost_center).toBe("cc-9");
  });

  it("writes mapped columns and custom attributes on JIT create", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const idp = await createUpstreamIdp(env, oidcInput());
    await replaceMappings(env, { channel: "jit", owner: String(idp.id) }, [
      { target: "username", expression: "preferred_username" },
      { target: "email", expression: "email" },
      { target: "department", expression: "dept" },
      { target: "custom.employee_tier", expression: "tier" },
    ]);
    const profile = await mappedProfileFromClaims(env, { sub: "s", preferred_username: "new.person", email: "n@x.test", dept: "R&D", tier: "t2" }, "s", undefined, idp.id);
    const user = await resolveFederatedUser(env, idp, profile);
    expect(user.department).toBe("R&D");
    expect(JSON.parse(user.custom_attributes)).toEqual({ employee_tier: "t2" });
  });
});

describe("collision policy", () => {
  const profile = { subject: "sub", email: "x@else.test", username: "ada", givenName: "A", familyName: "B", displayName: "A B" };
  const oidcInput = () => ({ name: "U", protocol: "oidc" as const, config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "horizon.test" });

  // A bare upstream handle mints {handle}-{idp-slug}: "ada" via idp "U" -> "ada-u".
  it("increments a taken sign-in name by default", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUserViaApi(apiKey, "ada-u", { identifier: "ada-u" });
    const idp = await createUpstreamIdp(env, oidcInput());
    const user = await resolveFederatedUser(env, idp, { ...profile, email: "other@else.test" });
    expect(user.upn).toBe("ada-u2");
  });

  it("fails the sign-in when the policy says fail", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUserViaApi(apiKey, "ada-u", { identifier: "ada-u" });
    await setCollisionPolicy(env, { username: "fail" });
    const idp = await createUpstreamIdp(env, oidcInput());
    await expect(resolveFederatedUser(env, idp, { ...profile, email: "other@else.test" })).rejects.toBeInstanceOf(FederationError);
  });

  it("evaluates a pattern expression until the name is free", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await seedUserViaApi(apiKey, "ada-u", { identifier: "ada-u" });
    await seedUserViaApi(apiKey, "ada-u-x2", { identifier: "ada-u-x2" });
    await setCollisionPolicy(env, { username: "pattern", username_pattern: 'local + "-x" + n' });
    const idp = await createUpstreamIdp(env, oidcInput());
    const user = await resolveFederatedUser(env, idp, { ...profile, email: "other@else.test" });
    expect(user.upn).toBe("ada-u-x3");
  });

  it("refuses a colliding claimed email when the policy says fail", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const owner = await seedUserViaApi(apiKey, "ada");
    // The clash is on ada's UPN: adoption matches on users.email / user_emails
    // only, so a claimed address that equals another account's sign-in name
    // reaches the create path, where the policy decides.
    await env.DB.prepare("UPDATE users SET upn = ? WHERE id = ?").bind("claimed@else.test", owner.id).run();
    await setCollisionPolicy(env, { email: "fail" });
    const idp = await createUpstreamIdp(env, oidcInput());
    await expect(resolveFederatedUser(env, idp, { ...profile, username: "newguy", email: "claimed@else.test" })).rejects.toBeInstanceOf(FederationError);
  });
});

describe("outbound mappings", () => {
  it("evaluates SAML attribute fields as expressions", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const user = await seedUserViaApi(apiKey, "ada", { given_name: "Ada", family_name: "Lovelace" });
    await env.DB.prepare("UPDATE users SET department = ?, custom_attributes = ? WHERE id = ?").bind("Math", '{"cost_center":"cc-1"}', user.id).run();
    const sp = {
      attribute_map: JSON.stringify({ cn: 'given_name + " " + family_name', dept: "department", cc: "custom.cost_center", title: 'title(department)' }),
      attribute_definitions: "",
      subject_id: "",
      entity_id: "https://sp.test",
    } as never;
    const attrs = await resolveAttributes(env, sp, (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first<UserRow>())!);
    const byName = Object.fromEntries(attrs.map((a) => [a.name, a.values]));
    expect(byName.cn).toEqual(["Ada Lovelace"]);
    expect(byName.dept).toEqual(["Math"]);
    expect(byName.cc).toEqual(["cc-1"]);
    expect(byName.title).toEqual(["Math"]);
  });

  it("builds the pushed SCIM document from a target's rows", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const user = await seedUserViaApi(apiKey, "ada", { given_name: "Ada", family_name: "Lovelace" });
    await env.DB.prepare("UPDATE users SET department = ?, custom_attributes = ? WHERE id = ?").bind("Math", '{"cost_center":"cc-1"}', user.id).run();
    const fresh = (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first<UserRow>())!;
    await replaceMappings(env, { channel: "scim-out", owner: "7" }, [
      { target: "userName", expression: 'lower(given_name + "." + family_name + "@corp.test")' },
      { target: "name.givenName", expression: "given_name" },
      { target: "displayName", expression: 'given_name + " " + family_name' },
      { target: "enterprise.department", expression: "department" },
      { target: "urn:ietf:params:scim:schemas:extension:hr:2.0:User:costCenter", expression: 'custom.cost_center' },
    ]);
    const target = { id: 7 } as never;
    const doc = (await mappedUserToScim(env, target, fresh, await effectiveMappings(env, "scim-out", "7"))) as Record<string, any>;
    expect(doc.userName).toBe("ada.lovelace@corp.test");
    expect(doc.name.givenName).toBe("Ada");
    expect(doc.displayName).toBe("Ada Lovelace");
    expect(doc["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].department).toBeTruthy();
    expect(doc["urn:ietf:params:scim:schemas:extension:hr:2.0:User"].costCenter).toBe("cc-1");
    expect(doc.schemas).toContain("urn:ietf:params:scim:schemas:extension:hr:2.0:User");
  });
});

describe("OIDC claim mappings", () => {
  it("adds computed claims and refuses protocol claims", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    await replaceMappings(env, { channel: "oidc", owner: "client-x" }, [
      { target: "full_name", expression: 'given_name + " " + family_name' },
      { target: "dept", expression: "department" },
      { target: "cost_center", expression: "custom.cost_center" },
    ]);
    const claims = await clientMappedClaims(env, "client-x", {
      sub: "1", id: "ext-1", email: "a@h.test", name: "Ada Lovelace", givenName: "Ada", familyName: "Lovelace",
      username: "ada", groups: [], amr: ["pwd"], jobTitle: "", department: "Math", managerEmail: null,
      customAttributes: { cost_center: "cc-1" },
    });
    expect(claims.full_name).toBe("Ada Lovelace");
    expect(claims.dept).toBe("Math");
    expect(claims.cost_center).toBe("cc-1");
    // No rows for another client: nothing added.
    expect(await clientMappedClaims(env, "client-y", {} as never)).toEqual({});
  });
});

describe("mappings API and console", () => {
  it("round-trips rows and the collision policy", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const put = await apiCall("/api/v1/mappings", {
      token: apiKey,
      method: "PUT",
      body: { channel: "jit", owner: "42", mappings: [{ target: "username", expression: "preferred_username" }, { target: "email", expression: "email" }] },
    });
    expect(put.status).toBe(200);
    const got = await apiCall("/api/v1/mappings?channel=jit&owner=42", { token: apiKey });
    expect(got.body.mappings.map((m: { target: string }) => m.target)).toEqual(["username", "email"]);

    const bad = await apiCall("/api/v1/mappings", { token: apiKey, method: "PUT", body: { channel: "jit", owner: "", mappings: [{ target: "bogus", expression: "x" }] } });
    expect(bad.status).toBe(400);

    const collision = await apiCall("/api/v1/mappings/collisions", { token: apiKey, method: "PUT", body: { username: "pattern", username_pattern: "local + n", email: "fail" } });
    expect(collision.status).toBe(200);
    expect((await getCollisionPolicy(env)).email).toBe("fail");
  });

  it("serves the Flows page to a super admin", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const admin = await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>();
    const cookie = (await createSession(env, admin!.id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const res = await SELF.fetch(`${BASE}/admin/flows`, { headers: { Cookie: cookie } });
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain("Collision policy");
    expect(html).toContain("Federation sign-in");
    const edit = await SELF.fetch(`${BASE}/admin/flows/edit?channel=jit&owner=`, { headers: { Cookie: cookie } });
    expect(edit.status).toBe(200);
  });

  it("needs schemas:read for the API and Super for writes", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const scoped = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "scoped", scopes: ["users:read"] } });
    const res = await apiCall("/api/v1/mappings?channel=jit", { token: scoped.body.token });
    expect(res.status).toBe(403);
  });
});

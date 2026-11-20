import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SignedXml } from "xml-crypto";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { TEST_SAML_IDP_CERT_PEM, TEST_SAML_IDP_KEY_PKCS8, TEST_SAML_SP_CERT_PEM, TEST_SAML_SP_KEY_PKCS8 } from "./fixtures/saml-keys.js";
import { createUpstreamIdp, FederationError, getUpstreamIdp, profileFromClaims, resolveFederatedUser, updateUpstreamIdp, verifySamlResponse, NoLocalAccount, type SamlIdpConfig } from "../src/lib/federation.js";
import { accessFor } from "../src/lib/admin-roles.js";
import { createSession } from "../src/lib/sessions.js";
import { sealLoginFlow } from "../src/lib/authorize-state.js";
import { b64encode } from "../src/lib/saml/xml.js";
import { unsealMaybe } from "../src/lib/sealed.js";

beforeEach(resetDatabase);

const SP_ENTITY = "https://idp.test/federation/saml/1";
const ACS = "https://idp.test/federation/saml/acs/1";
const REQ_ID = "_req-test-1";

function samlCfg(overrides: Partial<SamlIdpConfig> = {}): SamlIdpConfig {
  return { idp_entity_id: "https://upstream-idp.test/entity", sso_url: "https://upstream-idp.test/sso", certificate: TEST_SAML_IDP_CERT_PEM, ...overrides };
}

/** A Response carrying one Assertion, signed (assertion or response) with `key`. */
function samlResponse(opts: { key?: string; cert?: string; signResponse?: boolean; audience?: string; recipient?: string; inResponseTo?: string; notOnOrAfter?: string; issuer?: string; subject?: string; attrs?: Record<string, string[]> } = {}): string {
  const key = opts.key ?? TEST_SAML_IDP_KEY_PKCS8;
  const cert = opts.cert ?? TEST_SAML_IDP_CERT_PEM;
  const assertionId = "_assert-1";
  const responseId = "_resp-1";
  const attrs = Object.entries(opts.attrs ?? { email: ["ada@horizon.test"], given_name: ["Ada"], family_name: ["Kowalski"] })
    .map(([n, vs]) => `<saml:Attribute Name="${n}">${vs.map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`).join("")}</saml:Attribute>`)
    .join("");
  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${new Date().toISOString()}">` +
    `<saml:Issuer>${opts.issuer ?? "https://upstream-idp.test/entity"}</saml:Issuer>` +
    `<saml:Subject><saml:NameID>${opts.subject ?? "ada@horizon.test"}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:bearer"><saml:SubjectConfirmationData Recipient="${opts.recipient ?? ACS}"${opts.inResponseTo === null ? "" : ` InResponseTo="${opts.inResponseTo ?? REQ_ID}"`} NotOnOrAfter="${opts.notOnOrAfter ?? new Date(Date.now() + 300_000).toISOString()}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${new Date(Date.now() - 60_000).toISOString()}" NotOnOrAfter="${opts.notOnOrAfter ?? new Date(Date.now() + 300_000).toISOString()}"><saml:AudienceRestriction><saml:Audience>${opts.audience ?? SP_ENTITY}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${new Date().toISOString()}"/>` +
    `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>` +
    `</saml:Assertion>`;
  const doc =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${ACS}">` +
    `<saml:Issuer>${opts.issuer ?? "https://upstream-idp.test/entity"}</saml:Issuer>` +
    assertion +
    `</samlp:Response>`;
  const sig = new SignedXml({
    privateKey: key,
    publicCert: cert,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  const signedElement = opts.signResponse ? "Response" : "Assertion";
  sig.addReference({
    xpath: `//*[local-name(.)='${signedElement}']`,
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(doc, { location: { reference: `//*[local-name(.)='${signedElement}']/*[local-name(.)='Issuer']`, action: "after" } });
  return b64encode(sig.getSignedXml());
}

async function seedIdp(over: Record<string, unknown> = {}): Promise<{ apiKey: string; idpId: number }> {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  const res = await apiCall("/api/v1/federation/idps", { token: apiKey, body: over });
  return { apiKey, idpId: res.body.id as number };
}

describe("verifySamlResponse", () => {
  it("accepts a correctly signed assertion and returns the identity", () => {
    const id = verifySamlResponse(samlCfg(), samlResponse(), ACS, SP_ENTITY, REQ_ID);
    expect(id.subject).toBe("ada@horizon.test");
    expect(id.attributes.email).toEqual(["ada@horizon.test"]);
  });

  it("accepts a signed response wrapping an unsigned assertion", () => {
    const id = verifySamlResponse(samlCfg(), samlResponse({ signResponse: true }), ACS, SP_ENTITY, REQ_ID);
    expect(id.subject).toBe("ada@horizon.test");
  });

  it("rejects an unsigned response", () => {
    const doc =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>x</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`;
    expect(() => verifySamlResponse(samlCfg(), b64encode(doc), ACS, SP_ENTITY)).toThrow(/unsigned/i);
  });

  it("rejects a signature under a key that is not the configured one, even when its cert rides in KeyInfo", () => {
    // Attacker signs with their own key and embeds their own cert - the
    // configured certificate must pin verification regardless.
    const forged = samlResponse({ key: TEST_SAML_SP_KEY_PKCS8, cert: TEST_SAML_SP_CERT_PEM });
    expect(() => verifySamlResponse(samlCfg(), forged, ACS, SP_ENTITY)).toThrow(/signature/i);
  });

  it("rejects an assertion that sits outside the signed element", () => {
    // Tamper with the signed Response's NameID - the digest breaks.
    const doc = atob(samlResponse({ signResponse: true }));
    const tampered = doc.replace("ada@horizon.test", "mallory@evil.test");
    expect(() => verifySamlResponse(samlCfg(), b64encode(tampered), ACS, SP_ENTITY)).toThrow(/signature/i);
  });

  it("rejects the wrong audience, recipient, request id, and an expired assertion", () => {
    expect(() => verifySamlResponse(samlCfg(), samlResponse({ audience: "https://other-sp.test" }), ACS, SP_ENTITY, REQ_ID)).toThrow(/service provider/i);
    expect(() => verifySamlResponse(samlCfg(), samlResponse({ recipient: "https://other.test/acs" }), ACS, SP_ENTITY, REQ_ID)).toThrow(/recipient/i);
    expect(() => verifySamlResponse(samlCfg(), samlResponse({ inResponseTo: "_other" }), ACS, SP_ENTITY, REQ_ID)).toThrow(/different request/i);
    expect(() => verifySamlResponse(samlCfg(), samlResponse({ notOnOrAfter: new Date(Date.now() - 600_000).toISOString() }), ACS, SP_ENTITY, REQ_ID)).toThrow(/expired/i);
  });

  it("rejects a different issuer when one is configured", () => {
    expect(() => verifySamlResponse(samlCfg(), samlResponse({ issuer: "https://rogue.test" }), ACS, SP_ENTITY, REQ_ID)).toThrow(/different IdP/i);
  });
});

describe("profileFromClaims", () => {
  it("maps common OIDC claims", () => {
    const p = profileFromClaims({ sub: "abc", email: "Ada@Test.COM", given_name: "Ada", family_name: "Kowalski", preferred_username: "ADA@HORIZON.TEST" }, "abc");
    expect(p).toMatchObject({ subject: "abc", email: "ada@test.com", username: "ada@horizon.test", givenName: "Ada", familyName: "Kowalski" });
  });
  it("falls back to the email as username and derives names", () => {
    const p = profileFromClaims({ sub: "abc", email: "bob@corp.test" }, "abc");
    expect(p.username).toBe("bob@corp.test");
    expect(p.givenName).toBe("bob");
  });
  it("honours an attribute map", () => {
    const p = profileFromClaims({ sub: "x", EmployeeEmail: "c@d.test", FirstName: "Cid" }, "x", { EmployeeEmail: "email", FirstName: "given_name" });
    expect(p.email).toBe("c@d.test");
    expect(p.givenName).toBe("Cid");
  });
});

describe("resolveFederatedUser", () => {
  const profile = { subject: "sub-1", email: "ada@horizon.test", username: "ada@horizon.test", givenName: "Ada", familyName: "K", displayName: "Ada K" };

  it("adopts a local account by email and links it", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", users: [{ username: "ada", emails: ["ada@horizon.test"], status: "active" }] } });
    const idp = await createUpstreamIdp(env, { name: "U", protocol: "oidc", config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: false, jitDomain: "" });
    const user = await resolveFederatedUser(env, idp, profile);
    expect(user.username).toBe("ada");
    const link = await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND subject = 'sub-1'").bind(idp.id).first();
    expect(link).toBeTruthy();
  });

  it("refuses a disabled account", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", users: [{ username: "ada", emails: ["ada@horizon.test"], status: "disabled" }] } });
    const idp = await createUpstreamIdp(env, { name: "U", protocol: "oidc", config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: false, jitDomain: "" });
    await expect(resolveFederatedUser(env, idp, profile)).rejects.toBeInstanceOf(NoLocalAccount);
  });

  it("refuses an unknown identity when JIT is off", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const idp = await createUpstreamIdp(env, { name: "U", protocol: "oidc", config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: false, jitDomain: "" });
    await expect(resolveFederatedUser(env, idp, { ...profile, email: "new@else.test", username: "new@else.test" })).rejects.toBeInstanceOf(NoLocalAccount);
  });

  it("JIT-provisions an account under the configured domain and links it", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const idp = await createUpstreamIdp(env, { name: "U", protocol: "oidc", config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "horizon.test" });
    const user = await resolveFederatedUser(env, idp, { ...profile, email: "new.person@else.test", username: "new.person" });
    expect(user.upn).toBe("new.person@horizon.test");
    expect(user.display_name).toBe("Ada K");
    const email = await env.DB.prepare("SELECT email FROM user_emails WHERE user_id = ?").bind(user.id).first<{ email: string }>();
    expect(email?.email).toBe("new.person@else.test");
    const link = await env.DB.prepare("SELECT 1 FROM federated_identities WHERE idp_id = ? AND user_id = ?").bind(idp.id, user.id).first();
    expect(link).toBeTruthy();
    // Second sign-in hits the link directly.
    const again = await resolveFederatedUser(env, idp, { ...profile, email: "new.person@else.test", username: "new.person" });
    expect(again.id).toBe(user.id);
  });

  it("refuses a JIT account whose claims would put it in an admin role group", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    // A dynamic rule on a claim-controlled field, linked to a role: the
    // upstream asserts given_name and the account is born an administrator.
    const gid = (await env.DB.prepare("INSERT INTO groups (name, description, rule) VALUES ('Vip Admins', '', ?) RETURNING id")
      .bind(JSON.stringify({ all: [{ field: "given_name", op: "eq", value: "RootOfTrust" }] }))
      .first<{ id: number }>())!.id;
    await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT r.id, ? FROM admin_roles r WHERE r.name = 'Directory Admin'").bind(gid).run();

    const idp = await createUpstreamIdp(env, { name: "U", protocol: "oidc", config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "horizon.test" });
    await expect(resolveFederatedUser(env, idp, { subject: "sub-x", email: "new@else.test", username: "nobody", givenName: "RootOfTrust", familyName: "", displayName: "RootOfTrust" })).rejects.toBeInstanceOf(FederationError);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'nobody'").first()).toBeNull();
  });

  it("refuses a JIT account whose sign-in name collides with another account's alias", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/users", { token: apiKey, body: { username: "ada", given_name: "Ada", password: "user-password-123", status: "active" } });
    const adaId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first<{ id: number }>())!.id;
    // ada's alias is exactly the upn JIT would compose for the new account.
    await env.DB.prepare("INSERT INTO user_emails (user_id, email, type, is_primary, created_at) VALUES (?, 'new.person@horizon.test', 'work', 0, ?)").bind(adaId, new Date().toISOString()).run();

    const idp = await createUpstreamIdp(env, { name: "U", protocol: "oidc", config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "horizon.test" });
    await expect(resolveFederatedUser(env, idp, { ...profile, email: "new.person@else.test", username: "new.person" })).rejects.toBeInstanceOf(FederationError);
    expect(await env.DB.prepare("SELECT 1 FROM users WHERE username = 'new.person'").first()).toBeNull();
  });
});

describe("JIT group assignment", () => {
  const jitProfile = { subject: "sub-jit", email: "new.person@else.test", username: "new.person", givenName: "New", familyName: "Person", displayName: "New Person" };
  const oidcInput = (jitGroups: number[]) => ({ name: "U", protocol: "oidc" as const, config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "horizon.test", jitGroups });

  async function group(name: string): Promise<number> {
    return (await env.DB.prepare("INSERT INTO groups (name) VALUES (?) RETURNING id").bind(name).first<{ id: number }>())!.id;
  }
  async function linkRole(groupId: number, roleName: string): Promise<void> {
    await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT id, ? FROM admin_roles WHERE name = ?").bind(groupId, roleName).run();
  }
  async function memberGroupIds(userId: number): Promise<number[]> {
    const { results } = await env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ? ORDER BY group_id").bind(userId).all<{ group_id: number }>();
    return results.map((r) => r.group_id);
  }

  it("puts a JIT-provisioned account in each configured group", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const gid = await group("Demo Observers");
    const gid2 = await group("Everyone Else");
    const idp = await createUpstreamIdp(env, oidcInput([gid, gid2]));
    const user = await resolveFederatedUser(env, idp, jitProfile);
    expect(user.username).toBe("new.person");
    expect(await memberGroupIds(user.id)).toEqual([gid, gid2]);
  });

  it("accepts a group that grants a read-only admin role, and the account holds it", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const gid = await group("Read-Only Observers");
    await linkRole(gid, "Auditor"); // every permission the Auditor role holds is *:read
    const idp = await createUpstreamIdp(env, oidcInput([gid]));
    const user = await resolveFederatedUser(env, idp, jitProfile);
    expect(await memberGroupIds(user.id)).toEqual([gid]);
    expect((await accessFor(env, user.id)).roles).toContain("Auditor");
  });

  it("refuses a group that grants a write-capable role, on create and on update", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const gid = await group("Directory Crew");
    await linkRole(gid, "Directory Admin");
    await expect(createUpstreamIdp(env, oidcInput([gid]))).rejects.toThrow(/read-only/i);
    const idp = await createUpstreamIdp(env, oidcInput([]));
    await expect(updateUpstreamIdp(env, idp.id, { ...oidcInput([gid]), enabled: true })).rejects.toThrow(/read-only/i);
  });

  it("refuses a group id that does not exist", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    await expect(createUpstreamIdp(env, oidcInput([424242]))).rejects.toThrow(/[Uu]nknown group/);
  });

  it("console: the provider form lists the groups and saves the selection", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const gid = await group("Demo Observers");
    const roGid = await group("Read-Only Observers");
    await linkRole(roGid, "Auditor");
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;

    const page = await SELF.fetch(`${BASE}/admin/integrations/federation/new`, { headers: { Cookie: cookie } });
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Groups JIT accounts join");
    expect(html).toContain("grants Auditor");

    const form = new URLSearchParams({ protocol: "oidc", name: "Corp", issuer: "https://i.test", client_id: "c", client_secret: "s", jit: "1" });
    form.append("jit_groups", String(gid));
    form.append("jit_groups", String(roGid));
    const res = await SELF.fetch(`${BASE}/admin/federation/idps`, {
      method: "POST",
      headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded", Origin: BASE },
      body: form.toString(),
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    const saved = await env.DB.prepare("SELECT jit_groups FROM upstream_idps WHERE name = 'Corp'").first<{ jit_groups: string }>();
    expect(JSON.parse(saved!.jit_groups).sort()).toEqual([gid, roGid].sort());
  });
});

describe("federation API", () => {
  it("creates, reads, changes and removes a provider without exposing the secret", async () => {
    const { apiKey, idpId } = await seedIdp({ name: "Entra", protocol: "oidc", jit: true, config: { issuer: "https://login.test/t", client_id: "cid", client_secret: "shh" } });
    expect(idpId).toBeGreaterThan(0);
    const got = await apiCall(`/api/v1/federation/idps/${idpId}`, { token: apiKey });
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ name: "Entra", protocol: "oidc", jit: true });
    expect(got.body.config.client_secret).toBeUndefined();
    expect(got.body.config.secret_set).toBe(true);
    const patched = await apiCall(`/api/v1/federation/idps/${idpId}`, { token: apiKey, method: "PATCH", body: { enabled: false } });
    expect(patched.status).toBe(200);
    const row = await getUpstreamIdp(env, idpId);
    expect(row?.enabled).toBe(0);
    // Sealed at rest; the kept secret unseals back to the original.
    const mergedSecret = (JSON.parse(row!.config) as { client_secret?: string }).client_secret;
    expect(await unsealMaybe(env, mergedSecret)).toBe("shh");
    const list = await apiCall("/api/v1/federation/idps", { token: apiKey });
    expect(list.body.idps).toHaveLength(1);
    const del = await apiCall(`/api/v1/federation/idps/${idpId}`, { token: apiKey, method: "DELETE" });
    expect(del.status).toBe(200);
    expect(await apiCall(`/api/v1/federation/idps/${idpId}`, { token: apiKey })).toMatchObject({ status: 404 });
  });

  it("refuses delegated federation writes: registering an IdP needs an admin key", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const delegated = (await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "fed-admin", scopes: ["clients:write"] } })).body.token as string;

    // clients:write grants federation:write - which still reads, but can no
    // longer register, change or remove a trust anchor.
    const created = await apiCall("/api/v1/federation/idps", { token: delegated, body: { name: "Rogue", protocol: "oidc", config: { issuer: "https://evil.test", client_id: "c" } } });
    expect(created.status).toBe(403);
    expect((await apiCall("/api/v1/federation/idps", { token: delegated })).status).toBe(200);

    const adminCreated = await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "Entra", protocol: "oidc", config: { issuer: "https://login.test", client_id: "c" } } });
    const idpId = adminCreated.body.id as number;
    expect((await apiCall(`/api/v1/federation/idps/${idpId}`, { token: delegated, method: "PATCH", body: { enabled: false } })).status).toBe(403);
    expect((await apiCall(`/api/v1/federation/idps/${idpId}`, { token: delegated, method: "DELETE" })).status).toBe(403);
    expect((await apiCall(`/api/v1/federation/idps/${idpId}`, { token: delegated })).status).toBe(200);
  });

  it("accepts and returns jit_groups, keeps them on unrelated PATCHes, and refuses a write-role group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const gid = (await env.DB.prepare("INSERT INTO groups (name) VALUES ('Demo Observers') RETURNING id").first<{ id: number }>())!.id;
    const created = await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "Entra", protocol: "oidc", jit: true, jit_groups: [gid], config: { issuer: "https://login.test", client_id: "c" } } });
    expect(created.status).toBe(200);
    const id = created.body.id as number;
    expect((await apiCall(`/api/v1/federation/idps/${id}`, { token: apiKey })).body.jit_groups).toEqual([gid]);
    // An unrelated patch keeps the list; an empty array clears it.
    expect((await apiCall(`/api/v1/federation/idps/${id}`, { token: apiKey, method: "PATCH", body: { enabled: false } })).status).toBe(200);
    expect((await getUpstreamIdp(env, id))?.jit_groups).toBe(`[${gid}]`);
    expect((await apiCall(`/api/v1/federation/idps/${id}`, { token: apiKey, method: "PATCH", body: { jit_groups: [] } })).status).toBe(200);
    expect((await apiCall(`/api/v1/federation/idps/${id}`, { token: apiKey })).body.jit_groups).toEqual([]);
    // A group granting a write-capable role is refused at save.
    const writeGid = (await env.DB.prepare("INSERT INTO groups (name) VALUES ('Directory Crew') RETURNING id").first<{ id: number }>())!.id;
    await env.DB.prepare("INSERT INTO admin_role_groups (role_id, group_id) SELECT id, ? FROM admin_roles WHERE name = 'Directory Admin'").bind(writeGid).run();
    const refused = await apiCall(`/api/v1/federation/idps/${id}`, { token: apiKey, method: "PATCH", body: { jit_groups: [writeGid] } });
    expect(refused.status).toBe(400);
    expect(String(refused.body.message ?? refused.body.error ?? refused.body)).toMatch(/read-only/i);
    // So is an unknown group id.
    expect((await apiCall(`/api/v1/federation/idps/${id}`, { token: apiKey, method: "PATCH", body: { jit_groups: [424242] } })).status).toBe(400);
  });

  it("rejects bad issuer URLs and duplicate names", async () => {
    const { apiKey, idpId } = await seedIdp({ name: "A", protocol: "oidc", config: { issuer: "https://a.test", client_id: "c" } });
    expect(idpId).toBeGreaterThan(0);
    expect((await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "B", protocol: "oidc", config: { issuer: "http://plain.test", client_id: "c" } } })).status).toBe(400);
    expect((await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "A", protocol: "oidc", config: { issuer: "https://a.test", client_id: "c" } } })).status).toBe(400);
  });
});

describe("the sign-in round trip", () => {
  it("shows a federation button on the login form and sends the browser to the IdP", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const res = await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "Corp SAML", protocol: "saml", config: { sso_url: "https://up.test/sso", certificate: TEST_SAML_IDP_CERT_PEM, idp_entity_id: "https://up.test/e" } } });
    expect(res.status).toBe(200);
    const login = await SELF.fetch(`${BASE}/login`);
    const html = await login.text();
    expect(html).toContain("/login/federated/");
    const flowId = html.match(/name="flow" value="([^"]+)"/)?.[1] ?? html.match(/name="flow_id" value="([^"]+)"/)?.[1];
    expect(flowId).toBeTruthy();
    const idpId = res.body.id as number;
    const start = await SELF.fetch(`${BASE}/login/federated/${idpId}?flow=${encodeURIComponent(flowId!)}`, { redirect: "manual" });
    expect(start.status).toBe(302);
    const dest = new URL(start.headers.get("Location")!);
    expect(dest.origin).toBe("https://up.test");
    expect(dest.searchParams.get("SAMLRequest")).toBeTruthy();
    expect(dest.searchParams.get("RelayState")).toBeTruthy();
  });

  it("completes a SAML sign-in: verified assertion -> linked account -> session", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", users: [{ username: "ada", emails: ["ada@horizon.test"], status: "active" }] } });
    const res = await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "Corp SAML", protocol: "saml", config: { sso_url: "https://up.test/sso", certificate: TEST_SAML_IDP_CERT_PEM } } });
    const idpId = res.body.id as number;
    const flowId = await sealLoginFlow(env, { kind: "direct", next: "/account" });
    const start = await SELF.fetch(`${BASE}/login/federated/${idpId}?flow=${encodeURIComponent(flowId)}`, { redirect: "manual" });
    const relay = new URL(start.headers.get("Location")!).searchParams.get("RelayState")!;
    const acsUrl = `${BASE}/federation/saml/acs/${idpId}`;
    const entityId = `https://idp.test/federation/saml/${idpId}`;
    // The ACS URL and entity id depend on the id; rebuild the response for
    // them. No InResponseTo: the request id rides inside the DEFLATEd
    // AuthnRequest and IdP-initiated responses are accepted.
    const responseB64 = samlResponseWithDests(acsUrl, entityId);
    const post = await SELF.fetch(`${BASE}/federation/saml/acs/${idpId}`, {
      redirect: "manual",
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ SAMLResponse: responseB64, RelayState: relay }),
    });
    expect(post.status).toBe(302);
    expect(post.headers.get("Location")).toBe("/account");
    expect(post.headers.get("Set-Cookie")).toContain("__Host-flareid_session=");
  });

  it("completes an OIDC sign-in against a mocked provider", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, passwords: "none", users: [{ username: "ada", emails: ["ada@horizon.test"], status: "active" }] } });
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "test-kid";
    const issuer = "https://upstream.test/t1";
    const res = await apiCall("/api/v1/federation/idps", { token: apiKey, body: { name: "Corp OIDC", protocol: "oidc", config: { issuer, client_id: "flareid", client_secret: "cs" } } });
    const idpId = res.body.id as number;

    let capturedNonce = "";
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `${issuer}/.well-known/openid-configuration`) {
        return Response.json({ issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
      }
      if (url === `${issuer}/jwks`) return Response.json({ keys: [jwk] });
      if (url === `${issuer}/token`) {
        const idToken = await new SignJWT({ email: "ada@horizon.test", nonce: capturedNonce })
          .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
          .setIssuer(issuer)
          .setAudience("flareid")
          .setSubject("oidc-sub-1")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return Response.json({ id_token: idToken });
      }
      return new Response("unexpected fetch " + url, { status: 500 });
    });

    const flowId = await sealLoginFlow(env, { kind: "direct", next: "/account" });
    const start = await SELF.fetch(`${BASE}/login/federated/${idpId}?flow=${encodeURIComponent(flowId)}`, { redirect: "manual" });
    expect(start.status).toBe(302);
    const authUrl = new URL(start.headers.get("Location")!);
    expect(authUrl.origin + authUrl.pathname).toBe(`${issuer}/auth`);
    expect(authUrl.searchParams.get("code_challenge")).toBeTruthy();
    capturedNonce = authUrl.searchParams.get("nonce")!;
    const state = authUrl.searchParams.get("state")!;
    const cb = await SELF.fetch(`${BASE}/federation/oidc/callback?code=abc&state=${encodeURIComponent(state)}`, { redirect: "manual" });
    spy.mockRestore();
    expect(cb.status).toBe(302);
    expect(cb.headers.get("Location")).toBe("/account");
    expect(cb.headers.get("Set-Cookie")).toContain("__Host-flareid_session=");
    // The identity is linked for next time.
    const link = await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND subject = 'oidc-sub-1'").bind(idpId).first();
    expect(link).toBeTruthy();
  });

  it("JIT-provisions an account into the configured groups on sign-in, with a session", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const gid = (await env.DB.prepare("INSERT INTO groups (name) VALUES ('Demo Observers') RETURNING id").first<{ id: number }>())!.id;
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "test-kid";
    const issuer = "https://upstream.test/jit";
    const res = await apiCall("/api/v1/federation/idps", {
      token: apiKey,
      body: { name: "Corp OIDC", protocol: "oidc", jit: true, jit_domain: "horizon.test", jit_groups: [gid], config: { issuer, client_id: "flareid", client_secret: "cs" } },
    });
    expect(res.status).toBe(200);
    const idpId = res.body.id as number;

    let capturedNonce = "";
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `${issuer}/.well-known/openid-configuration`) {
        return Response.json({ issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
      }
      if (url === `${issuer}/jwks`) return Response.json({ keys: [jwk] });
      if (url === `${issuer}/token`) {
        const idToken = await new SignJWT({ email: "rookie@else.test", nonce: capturedNonce })
          .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
          .setIssuer(issuer)
          .setAudience("flareid")
          .setSubject("oidc-jit-1")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return Response.json({ id_token: idToken });
      }
      return new Response("unexpected fetch " + url, { status: 500 });
    });

    const flowId = await sealLoginFlow(env, { kind: "direct", next: "/account" });
    const start = await SELF.fetch(`${BASE}/login/federated/${idpId}?flow=${encodeURIComponent(flowId)}`, { redirect: "manual" });
    expect(start.status).toBe(302);
    const authUrl = new URL(start.headers.get("Location")!);
    capturedNonce = authUrl.searchParams.get("nonce")!;
    const state = authUrl.searchParams.get("state")!;
    const cb = await SELF.fetch(`${BASE}/federation/oidc/callback?code=abc&state=${encodeURIComponent(state)}`, { redirect: "manual" });
    spy.mockRestore();
    expect(cb.status).toBe(302);
    expect(cb.headers.get("Set-Cookie")).toContain("__Host-flareid_session=");
    // The account exists, is linked, and is in the configured group.
    const user = await env.DB.prepare("SELECT id FROM users WHERE upn = 'rookie@horizon.test'").first<{ id: number }>();
    expect(user).toBeTruthy();
    expect(await env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(gid, user!.id).first()).toBeTruthy();
    expect(await env.DB.prepare("SELECT 1 FROM federated_identities WHERE idp_id = ? AND user_id = ?").bind(idpId, user!.id).first()).toBeTruthy();
  });

  it("rejects a callback with an unknown or consumed state", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const cb = await SELF.fetch(`${BASE}/federation/oidc/callback?code=x&state=nonsense`, { redirect: "manual" });
    expect(cb.status).toBe(400);
  });
});

/** Same as samlResponse but parameterising ACS/entity/request-id for the e2e test. */
function samlResponseWithDests(acsUrl: string, entityId: string): string {
  const assertionId = "_a2";
  const attrs = `<saml:Attribute Name="email"><saml:AttributeValue>ada@horizon.test</saml:AttributeValue></saml:Attribute>`;
  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${new Date().toISOString()}">` +
    `<saml:Issuer>https://upstream-idp.test/e</saml:Issuer>` +
    `<saml:Subject><saml:NameID>ada@horizon.test</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:bearer"><saml:SubjectConfirmationData Recipient="${acsUrl}" NotOnOrAfter="${new Date(Date.now() + 300_000).toISOString()}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${new Date(Date.now() - 60_000).toISOString()}" NotOnOrAfter="${new Date(Date.now() + 300_000).toISOString()}"><saml:AudienceRestriction><saml:Audience>${entityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${new Date().toISOString()}"/>` +
    `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>` +
    `</saml:Assertion>`;
  const doc = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r2" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${acsUrl}"><saml:Issuer>https://upstream-idp.test/e</saml:Issuer>${assertion}</samlp:Response>`;
  const sig = new SignedXml({ privateKey: TEST_SAML_IDP_KEY_PKCS8, publicCert: TEST_SAML_IDP_CERT_PEM, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" });
  sig.addReference({ xpath: "//*[local-name(.)='Assertion']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.computeSignature(doc, { location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" } });
  return b64encode(sig.getSignedXml());
}

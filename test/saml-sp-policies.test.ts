// IIP-ALG08 (instance algorithm deny list), IIP-IDP01 (per-attribute Name and
// NameFormat) and IIP-IDP11 (nameid_format "none" omits <saml:NameID>) - the
// policy and write-path halves; emission wiring lives in messages.ts.
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { spEncryptionPolicy, spAttributeDefinitions } from "../src/lib/saml/service-providers.js";
import { resolveAttributes } from "../src/lib/saml/attributes.js";
import type { SamlServiceProviderRow, UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);

const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";

const spRow = (entityId = SP_ENTITY_ID) => env.DB.prepare("SELECT * FROM saml_service_providers WHERE entity_id = ?").bind(entityId).first<SamlServiceProviderRow>();

describe("disabled_algorithms (IIP-ALG08)", () => {
  it("reads empty, saves and reads back through the settings API", async () => {
    const { apiKey } = await bootstrapInstance();
    const empty = await apiCall("/api/v1/saml/settings", { token: apiKey, method: "GET" });
    expect(empty.status).toBe(200);
    expect(empty.body.disabled_algorithms).toEqual([]);

    const saved = await apiCall("/api/v1/saml/settings", {
      token: apiKey,
      method: "PUT",
      body: { disabled_algorithms: [`${XENC}aes256-cbc`, "sha1", `${XENC}aes256-cbc`] },
    });
    expect(saved.status).toBe(200);
    // Deduped, order preserved.
    expect(saved.body.disabled_algorithms).toEqual([`${XENC}aes256-cbc`, "sha1"]);

    const again = await apiCall("/api/v1/saml/settings", { token: apiKey, method: "GET" });
    expect(again.body.disabled_algorithms).toEqual([`${XENC}aes256-cbc`, "sha1"]);
  });

  it("rejects a service provider that selects a disabled algorithm, by URI and by token", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/saml/settings", { token: apiKey, method: "PUT", body: { disabled_algorithms: [`${XENC}aes256-cbc`, "rsa-oaep"] } });

    const byUri = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], encryption_policy: { content: `${XENC}aes256-cbc` } },
    });
    expect(byUri.status).toBe(400);

    // "rsa-oaep" denies both transport spellings: the token and the 1.1 URI.
    const byToken = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], encryption_policy: { transport: "rsa-oaep" } },
    });
    expect(byToken.status).toBe(400);
  });

  it("rejects a policy that resolves a disabled algorithm through the defaults", async () => {
    const { apiKey } = await bootstrapInstance();
    // Deny the default content algorithm: any explicit policy that leaves
    // content unset resolves aes256-gcm and must fail too.
    await apiCall("/api/v1/saml/settings", { token: apiKey, method: "PUT", body: { disabled_algorithms: ["aes256-gcm"] } });
    const res = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], encryption_policy: { digest: "sha256" } },
    });
    expect(res.status).toBe(400);

    // Denying sha1 also denies rsa-oaep-mgf1p: its mask is fixed MGF1-SHA1.
    await apiCall("/api/v1/saml/settings", { token: apiKey, method: "PUT", body: { disabled_algorithms: ["sha1"] } });
    const mgf1p = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], encryption_policy: { digest: "sha256" } },
    });
    expect(mgf1p.status).toBe(400);
  });

  it("throws at resolution when a stored policy picks a disabled algorithm (fail closed)", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], encryption_policy: { content: "aes128-cbc" } },
    });
    const sp = (await spRow())!;
    expect(() => spEncryptionPolicy(sp)).not.toThrow();
    expect(() => spEncryptionPolicy(sp, [`${XENC}aes128-cbc`])).toThrow(/disabled/);
    expect(() => spEncryptionPolicy(sp, ["aes128-cbc"])).toThrow(/disabled/);
    expect(() => spEncryptionPolicy(sp, [`${XENC11}aes256-gcm`])).not.toThrow();
  });
});

describe("attribute_definitions (IIP-IDP01)", () => {
  it("stores arbitrary names and formats and resolves them per user", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const definitions = [
      { name: "http://schemas.example/claims/mail", field: "email", name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" },
      { name: "Department Number", field: "department" },
    ];
    const created = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], attribute_definitions: definitions },
    });
    expect(created.status).toBe(200);

    const fetched = await apiCall(`/api/v1/saml/service-providers/${created.body.id}`, { token: apiKey, method: "GET" });
    expect(fetched.body.attribute_definitions).toEqual([
      { name: "http://schemas.example/claims/mail", field: "email", name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" },
      { name: "Department Number", field: "department", name_format: null },
    ]);

    const sp = (await spRow())!;
    expect(spAttributeDefinitions(sp)).toEqual([
      { name: "http://schemas.example/claims/mail", field: "email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" },
      { name: "Department Number", field: "department" },
    ]);
  });

  it("resolves definitions to name + nameFormat attributes, ignoring the plain map", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const created = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: {
        entity_id: SP_ENTITY_ID,
        acs_urls: [SP_ACS],
        attribute_map: { stale: "email" },
        attribute_definitions: [
          { name: "urn:example:login", field: "username", name_format: "urn:example:format" },
          { name: "urn:example:dept", field: "department" },
        ],
      },
    });
    expect(created.status).toBe(200);
    const sp = (await spRow())!;
    const user = (await env.DB.prepare("SELECT * FROM users LIMIT 1").first<UserRow>())!;
    const attrs = await resolveAttributes(env, sp, user);
    // "stale" from the map is gone - the definitions replaced it entirely;
    // the department definition resolves to nothing on the bootstrap admin.
    expect(attrs.map((a) => a.name)).toEqual(["urn:example:login"]);
    expect(attrs[0]!.nameFormat).toBe("urn:example:format");
    expect(attrs[0]!.values).toEqual([user.username]);
  });

  it("rejects malformed definitions and unknown fields", async () => {
    const { apiKey } = await bootstrapInstance();
    const malformed = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], attribute_definitions: [{ name: "", field: "email" }] },
    });
    expect(malformed.status).toBe(400);
    const unknownField = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], attribute_definitions: [{ name: "x", field: "credit_card" }] },
    });
    expect(unknownField.status).toBe(400);
  });
});

describe('nameid_format "none" (IIP-IDP11)', () => {
  it("is accepted and round-trips through the API", async () => {
    const { apiKey } = await bootstrapInstance();
    const created = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], nameid_format: "none" },
    });
    expect(created.status).toBe(200);

    const fetched = await apiCall(`/api/v1/saml/service-providers/${created.body.id}`, { token: apiKey, method: "GET" });
    expect(fetched.body.nameid_format).toBe("none");

    // An update that doesn't name nameid_format keeps it.
    const updated = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, name: "Renamed" },
    });
    expect(updated.status).toBe(200);
    expect((await spRow())!.nameid_format).toBe("none");
  });
});

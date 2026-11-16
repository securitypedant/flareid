// saml2int items: published IdP metadata (validUntil, scopes, UI info),
// subject-id / pairwise-id, and SP metadata registered from a URL and refreshed.
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { fetchSpMetadata, parseSpMetadata, refreshSpMetadata, upsertSpFromMetadata } from "../src/lib/saml/sp-metadata.js";
import { PAIRWISE_ID, resolveAttributes, SUBJECT_ID } from "../src/lib/saml/attributes.js";
import { TEST_SAML_SP_CERT_PEM } from "./fixtures/saml-keys.js";
import type { SamlServiceProviderRow, UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);
afterEach(() => vi.restoreAllMocks());

const spMetadata = (entityId: string, req?: string, acs = `${entityId}/acs`) =>
  `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}" validUntil="2030-01-01T00:00:00Z">` +
  (req
    ? `<md:Extensions><mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"><saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:oasis:names:tc:SAML:profiles:subject-id:req" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>${req}</saml:AttributeValue></saml:Attribute></mdattr:EntityAttributes></md:Extensions>`
    : "") +
  `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acs}" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>`;

const spRow = (entityId: string) => env.DB.prepare("SELECT * FROM saml_service_providers WHERE entity_id = ?").bind(entityId).first<SamlServiceProviderRow>();

describe("saml2int", () => {
  it("publishes validUntil, cacheDuration, the UPN domains as shibmd:Scope and a display name", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const xml = await (await SELF.fetch(`${BASE}/saml/metadata`)).text();
    expect(xml).toMatch(/validUntil="\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"/);
    expect(xml).toContain('cacheDuration="PT6H"');
    expect(xml).toContain(">horizon.test</shibmd:Scope>");
    expect(xml).toContain("<mdui:DisplayName");
    expect(xml.indexOf("<md:Extensions>")).toBeLessThan(xml.indexOf("<md:KeyDescriptor"));
  });

  it("honours subject-id:req and releases per-SP pairwise-id or a shared subject-id", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    expect(parseSpMetadata(spMetadata("https://a.test", "any")).subjectId).toBe("pairwise-id");
    expect(parseSpMetadata(spMetadata("https://a.test", "none")).subjectId).toBeNull();
    await upsertSpFromMetadata(env, parseSpMetadata(spMetadata("https://a.test", "pairwise-id")));
    await upsertSpFromMetadata(env, parseSpMetadata(spMetadata("https://b.test", "pairwise-id")));
    await upsertSpFromMetadata(env, parseSpMetadata(spMetadata("https://c.test", "subject-id")));
    const [a, b, cc] = [await spRow("https://a.test"), await spRow("https://b.test"), await spRow("https://c.test")];
    expect(a!.subject_id).toBe("pairwise-id");
    expect(a!.metadata_valid_until).toBe("2030-01-01T00:00:00.000Z");
    const user = (await env.DB.prepare("SELECT * FROM users WHERE username = 'admin'").first<UserRow>())!;
    const pick = (attrs: { name: string; values: string[] }[], n: string) => attrs.find((x) => x.name === n)?.values[0];
    const pa = pick(await resolveAttributes(env, a!, user), PAIRWISE_ID)!;
    const pb = pick(await resolveAttributes(env, b!, user), PAIRWISE_ID)!;
    expect(pa).toMatch(/^[0-9a-f]{64}@horizon\.test$/);
    expect(pb).not.toBe(pa);
    expect(pick(await resolveAttributes(env, a!, user), PAIRWISE_ID)).toBe(pa);
    expect(pick(await resolveAttributes(env, cc!, user), SUBJECT_ID)).toBe(`${user.external_id.toLowerCase()}@horizon.test`);
  });

  it("registers SP metadata from an https URL and refreshes it, refusing an entityID change", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await expect(fetchSpMetadata("http://sp.test/metadata")).rejects.toThrow(/https/);
    let served = spMetadata("https://sp.test", undefined, "https://sp.test/acs-1");
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(served, { headers: { "Content-Type": "application/samlmetadata+xml" } }));
    const res = await apiCall("/api/v1/saml/service-providers/import-metadata", { token: apiKey, body: { url: "https://sp.test/metadata" } });
    expect(res.status).toBe(200);
    expect(res.body.refresh).toBe(true);
    expect((await spRow("https://sp.test"))!.metadata_url).toBe("https://sp.test/metadata");

    served = spMetadata("https://sp.test", undefined, "https://sp.test/acs-2");
    await env.DB.prepare("UPDATE saml_service_providers SET metadata_last_refreshed_at = '2000-01-01T00:00:00Z'").run();
    expect(await refreshSpMetadata(env)).toEqual({ refreshed: 1, failed: 0 });
    // A refresh may never add ACS endpoints - the registered set is the
    // administrator's trust decision, so acs-1 stays until an admin re-imports.
    expect(JSON.parse((await spRow("https://sp.test"))!.acs_urls)).toEqual(["https://sp.test/acs-1"]);
    const held = await env.DB.prepare("SELECT details FROM audit_log WHERE action = 'saml.metadata_refresh_held'").first<{ details: string }>();
    expect(held!.details).toContain("acs_added");

    served = spMetadata("https://other.test");
    await env.DB.prepare("UPDATE saml_service_providers SET metadata_last_refreshed_at = '2000-01-01T00:00:00Z'").run();
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await refreshSpMetadata(env)).toEqual({ refreshed: 0, failed: 1 });
    expect(JSON.parse((await spRow("https://sp.test"))!.acs_urls)).toEqual(["https://sp.test/acs-1"]);
  });

  it("a refresh cannot strip signing or encryption requirements, and non-security fields still track the document", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const certBody = TEST_SAML_SP_CERT_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const signedMeta = (acs: string, withKeys: boolean) =>
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.test">` +
      `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"${withKeys ? ' AuthnRequestsSigned="true"' : ""}>` +
      (withKeys
        ? `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${certBody}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
          `<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${certBody}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
        : "") +
      `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://insecure.test/slo"/>` +
      `<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>` +
      `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acs}" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>`;

    let served = signedMeta("https://sp.test/acs", true);
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(served, { headers: { "Content-Type": "application/samlmetadata+xml" } }));
    await upsertSpFromMetadata(env, parseSpMetadata(await (await fetch("https://sp.test/metadata")).text()), undefined, "https://sp.test/metadata");
    const before = (await spRow("https://sp.test"))!;
    expect(before.want_authn_requests_signed).toBe(1);
    expect(before.encrypt_assertions).toBe(1);
    expect(before.slo_url).toBe("http://insecure.test/slo"); // stored as registered (admin's decision)

    // The malicious doc drops every KeyDescriptor, adds an attacker ACS and a
    // different (still http) SLO endpoint.
    served = signedMeta("https://attacker.test/acs", false);
    await env.DB.prepare("UPDATE saml_service_providers SET metadata_last_refreshed_at = '2000-01-01T00:00:00Z'").run();
    expect(await refreshSpMetadata(env)).toEqual({ refreshed: 1, failed: 0 });
    const after = (await spRow("https://sp.test"))!;
    expect(after.want_authn_requests_signed).toBe(1);
    expect(after.encrypt_assertions).toBe(1);
    expect(after.encryption_cert).toBe(before.encryption_cert);
    expect(JSON.parse(after.signing_certs)).toEqual(JSON.parse(before.signing_certs));
    expect(JSON.parse(after.acs_urls)).toEqual(["https://sp.test/acs"]);
    // An http SLO never lands through a refresh.
    expect(after.slo_url).toBeNull();
    // But the harmless fields still track the document.
    expect(after.nameid_format).toBe("persistent");
    const held = await env.DB.prepare("SELECT details FROM audit_log WHERE action = 'saml.metadata_refresh_held'").first<{ details: string }>();
    expect(held!.details).toContain("acs_added");
  });
});

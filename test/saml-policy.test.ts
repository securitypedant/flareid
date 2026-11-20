import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { TEST_SAML_SP_CERT_PEM } from "./fixtures/saml-keys.js";
import { b64decode, b64encode } from "../src/lib/saml/xml.js";

beforeEach(resetDatabase);

const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";
const USER_PASSWORD = "a-test-user-password-1";
const FMT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const FMT_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const AC_PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

async function seedServiceProvider(sp: Record<string, unknown> = {}): Promise<{ upn: string }> {
  const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
  const created = await apiCall("/api/v1/saml/service-providers", {
    token: apiKey,
    body: { entity_id: SP_ENTITY_ID, name: "Test SP", acs_urls: [SP_ACS], ...sp },
  });
  if (created.status !== 200) throw new Error(`SP seed failed: ${JSON.stringify(created.body)}`);
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      users: [{ username: "ada.kowalski", given_name: "Ada", password: USER_PASSWORD, status: "active" }],
    },
  });
  return { upn: `ada.kowalski@${domain}` };
}

/** Same request shape as saml.test.ts, plus raw inner XML for NameIDPolicy / Subject / RequestedAuthnContext. */
function authnRequestXml(opts: { issuer?: string; acsUrl?: string | null; extraInner?: string } = {}): string {
  const id = `_req-${Math.random().toString(16).slice(2)}`;
  const issuer = opts.issuer ?? SP_ENTITY_ID;
  const acs = opts.acsUrl === undefined ? SP_ACS : opts.acsUrl;
  return (
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${id}" Version="2.0" IssueInstant="2026-10-31T00:00:00Z"` +
    (acs ? ` AssertionConsumerServiceURL="${acs}"` : "") +
    ` Destination="${BASE}/saml/sso"` +
    `><saml:Issuer>${issuer}</saml:Issuer>${opts.extraInner ?? ""}</samlp:AuthnRequest>`
  );
}

async function deflateB64(xml: string): Promise<string> {
  const stream = new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  const buf = await new Response(stream).arrayBuffer();
  return b64encode(buf);
}

async function ssoQuery(xml: string): Promise<string> {
  return `SAMLRequest=${encodeURIComponent(await deflateB64(xml))}`;
}

/** GET /saml/sso -> login form -> POST /login, returning the auto-POST page. */
async function ssoViaLogin(query: string, upn: string): Promise<string> {
  const first = await SELF.fetch(`${BASE}/saml/sso?${query}`, { redirect: "manual" });
  const firstHtml = await first.text();
  const flowId = /name="flow_id" value="([^"]*)"/.exec(firstHtml)?.[1];
  if (!flowId) return firstHtml;
  const submitted = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password: USER_PASSWORD }).toString(),
    redirect: "manual",
  });
  return submitted.text();
}

function postFormFields(html: string): { acsUrl: string | null; samlResponse: string | null } {
  return {
    acsUrl: /<form method="POST" action="([^"]*)">/.exec(html)?.[1] ?? null,
    samlResponse: /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1] ?? null,
  };
}

function decodeResponse(samlResponse: string): string {
  return new TextDecoder().decode(b64decode(samlResponse));
}

/** Expectations every protocol error response must meet: non-Success status, posted to the ACS, and no assertion. */
function expectErrorResponse(html: string, secondLevel: string): string {
  const fields = postFormFields(html);
  expect(fields.acsUrl, "error response posts to the registered ACS").toBe(SP_ACS);
  expect(fields.samlResponse).toBeTruthy();
  const xml = decodeResponse(fields.samlResponse!);
  expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:status:Responder");
  expect(xml).toContain(`urn:oasis:names:tc:SAML:2.0:status:${secondLevel}`);
  expect(xml).not.toContain("status:Success");
  expect(xml).not.toContain("<saml:Assertion");
  expect(xml).not.toContain("<saml:EncryptedAssertion");
  return xml;
}

async function ssoRaw(xml: string): Promise<string> {
  const response = await SELF.fetch(`${BASE}/saml/sso?${await ssoQuery(xml)}`, { redirect: "manual" });
  return response.text();
}

describe("error responses carry no assertion", () => {
  it("answers an unrecognized <saml:Subject> with an error Status, no assertion", async () => {
    await seedServiceProvider();
    const xml = authnRequestXml({
      extraInner: `<saml:Subject><saml:NameID Format="${FMT_PERSISTENT}">urn:probe:unknown-subject:1</saml:NameID></saml:Subject>`,
    });
    expectErrorResponse(await ssoRaw(xml), "UnknownPrincipal");
  });
});

describe("NameIDPolicy", () => {
  it("emits a persistent-format NameID when the request asks for one", async () => {
    const { upn } = await seedServiceProvider();
    const xml = authnRequestXml({
      extraInner: `<samlp:NameIDPolicy Format="${FMT_PERSISTENT}" AllowCreate="true"/>`,
    });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(xml), upn)).samlResponse!);
    expect(response).toContain("status:Success");
    expect(response).toContain(`<saml:NameID Format="${FMT_PERSISTENT}"`);
  });

  it("emits a transient-format NameID when the request asks for one on a persistent-configured SP", async () => {
    const { upn } = await seedServiceProvider({ nameid_format: "persistent" });
    const xml = authnRequestXml({
      extraInner: `<samlp:NameIDPolicy Format="${FMT_TRANSIENT}"/>`,
    });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(xml), upn)).samlResponse!);
    expect(response).toContain(`<saml:NameID Format="${FMT_TRANSIENT}"`);
  });

  it("refuses a NameID format the IdP cannot produce", async () => {
    await seedServiceProvider();
    const xml = authnRequestXml({
      extraInner: `<samlp:NameIDPolicy Format="urn:example:unknown-nameid-format" AllowCreate="true"/>`,
    });
    expectErrorResponse(await ssoRaw(xml), "InvalidNameIDPolicy");
  });

  it("echoes SPNameQualifier on the transient NameID", async () => {
    const { upn } = await seedServiceProvider();
    const xml = authnRequestXml({
      extraInner: `<samlp:NameIDPolicy Format="${FMT_TRANSIENT}" SPNameQualifier="https://sp.example/custom-ns"/>`,
    });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(xml), upn)).samlResponse!);
    expect(response).toContain(`Format="${FMT_TRANSIENT}" SPNameQualifier="https://sp.example/custom-ns"`);
  });

  it("uses SPProvidedID as the persistent NameID value", async () => {
    const { upn } = await seedServiceProvider({ nameid_format: "persistent" });
    const xml = authnRequestXml({
      extraInner: `<samlp:NameIDPolicy Format="${FMT_PERSISTENT}" AllowCreate="true" SPProvidedID="sp-chosen-id-7"/>`,
    });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(xml), upn)).samlResponse!);
    expect(response).toContain(">sp-chosen-id-7</saml:NameID>");
  });

  it("refuses SPProvidedID when the resolved format is not persistent", async () => {
    await seedServiceProvider();
    const xml = authnRequestXml({
      extraInner: `<samlp:NameIDPolicy Format="${FMT_TRANSIENT}" SPProvidedID="sp-chosen-id-7"/>`,
    });
    expectErrorResponse(await ssoRaw(xml), "InvalidNameIDPolicy");
  });
});

describe("RequestedAuthnContext", () => {
  const rac = (comparison: string | null, ref: string) =>
    `<samlp:RequestedAuthnContext${comparison ? ` Comparison="${comparison}"` : ""}><saml:AuthnContextClassRef>${ref}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`;

  it("succeeds when an exact request names the asserted class", async () => {
    const { upn } = await seedServiceProvider();
    const xml = authnRequestXml({ extraInner: rac("exact", AC_PPT) });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(xml), upn)).samlResponse!);
    expect(response).toContain("status:Success");
    expect(response).toContain(AC_PPT);
  });

  it("answers an exact request for another class with NoAuthnContext", async () => {
    await seedServiceProvider();
    const xml = authnRequestXml({ extraInner: rac("exact", "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient") });
    expectErrorResponse(await ssoRaw(xml), "NoAuthnContext");
  });

  it("treats a missing Comparison attribute as exact", async () => {
    await seedServiceProvider();
    const xml = authnRequestXml({ extraInner: rac(null, "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient") });
    expectErrorResponse(await ssoRaw(xml), "NoAuthnContext");
  });

  it("answers a better-comparison request with NoAuthnContext - no stronger class exists", async () => {
    await seedServiceProvider();
    const xml = authnRequestXml({ extraInner: rac("better", AC_PPT) });
    expectErrorResponse(await ssoRaw(xml), "NoAuthnContext");
  });

  it("succeeds when a minimum request includes the asserted class", async () => {
    const { upn } = await seedServiceProvider();
    const xml = authnRequestXml({ extraInner: rac("minimum", AC_PPT) });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(xml), upn)).samlResponse!);
    expect(response).toContain("status:Success");
  });
});

describe("EncryptedKey recipient", () => {
  it("names the ACS URL on the wrapped key", async () => {
    const { upn } = await seedServiceProvider({ encrypt_assertions: true, encryption_cert: TEST_SAML_SP_CERT_PEM });
    const response = decodeResponse(postFormFields(await ssoViaLogin(await ssoQuery(authnRequestXml()), upn)).samlResponse!);
    expect(response).toContain("<saml:EncryptedAssertion");
    expect(response).toContain(`<xenc:EncryptedKey Recipient="${SP_ACS}">`);
  });
});

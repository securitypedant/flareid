import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { TEST_SAML_SP_CERT_PEM, TEST_SAML_SP_KEY_PKCS8 } from "./fixtures/saml-keys.js";
import { b64decode } from "../src/lib/saml/xml.js";

beforeEach(resetDatabase);

const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";
const USER_PASSWORD = "a-test-user-password-1";
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";

async function seed(sp: Record<string, unknown> = {}): Promise<{ upn: string; apiKey: string; domain: string }> {
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
  return { upn: `ada.kowalski@${domain}`, apiKey, domain };
}

const deflateB64 = async (xml: string): Promise<string> => {
  const ds = new CompressionStream("deflate-raw");
  const w = ds.writable.getWriter();
  void w.write(new TextEncoder().encode(xml)).then(() => w.close());
  const buf = await new Response(ds.readable).arrayBuffer();
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin);
};

async function ssoResponse(upn: string): Promise<{ xml: string; form: { acsUrl: string | null; samlResponse: string | null } }> {
  const req =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="_req${Math.random().toString(36).slice(2)}" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
    `AssertionConsumerServiceURL="${SP_ACS}"><saml:Issuer>${SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>`;
  const first = await SELF.fetch(`${BASE}/saml/sso?SAMLRequest=${encodeURIComponent(await deflateB64(req))}`, { redirect: "manual" });
  const flowId = /name="flow_id" value="([^"]*)"/.exec(await first.text())?.[1];
  const login = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId!, upn, password: USER_PASSWORD }).toString(),
  });
  const html = await login.text();
  const samlResponse = /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1] ?? null;
  const acsUrl = /<form method="POST" action="([^"]*)"/.exec(html)?.[1] ?? null;
  return { form: { acsUrl, samlResponse }, xml: samlResponse ? new TextDecoder().decode(b64decode(samlResponse)) : "" };
}

/** Decrypts the EncryptedAssertion with the SP's key; returns the plaintext and wrapper shape. */
async function decrypt(xml: string, hash: string, mode: "gcm" | "cbc" = "gcm"): Promise<{ plain: string; xml: string }> {
  const values = [...xml.matchAll(/<xenc:CipherValue>([^<]+)<\/xenc:CipherValue>/g)].map((m) => b64decode(m[1]!));
  const der = b64decode(TEST_SAML_SP_KEY_PKCS8.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const rsa = await crypto.subtle.importKey("pkcs8", der as BufferSource, { name: "RSA-OAEP", hash }, false, ["decrypt"]);
  const cek = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsa, values[0] as BufferSource);
  const data = values[1]!;
  const ivLen = mode === "gcm" ? 12 : 16;
  const algo = mode === "gcm" ? { name: "AES-GCM", iv: data.slice(0, ivLen), tagLength: 128 } : { name: "AES-CBC", iv: data.slice(0, ivLen) };
  const aes = await crypto.subtle.importKey("raw", cek, { name: mode === "gcm" ? "AES-GCM" : "AES-CBC" }, false, ["decrypt"]);
  const plain = new TextDecoder().decode(await crypto.subtle.decrypt(algo, aes, data.slice(ivLen) as BufferSource));
  return { plain, xml };
}

describe("per-SP encryption policy", () => {
  it("emits aes128-gcm when the policy selects it", async () => {
    const { upn } = await seed({
      encrypt_assertions: true,
      encryption_cert: TEST_SAML_SP_CERT_PEM,
      encryption_policy: { content: "aes128-gcm" },
    });
    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC11}aes128-gcm"`);
    const { plain } = await decrypt(xml, "SHA-1");
    expect(plain).toMatch(/^<saml:Assertion /);
  });

  it("emits the parameterized xmlenc11 rsa-oaep with an OAEPParams block", async () => {
    const { upn } = await seed({
      encrypt_assertions: true,
      encryption_cert: TEST_SAML_SP_CERT_PEM,
      encryption_policy: { transport: "rsa-oaep" },
    });
    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC11}rsa-oaep"`);
    expect(xml).toContain("<xenc:OAEPParams>");
    expect(xml).toContain(`<ds:DigestMethod Algorithm="${DS}sha1">`);
    expect(xml).not.toContain("xenc11:MGF"); // omitted MGF = spec default MGF1-SHA1
    const { plain } = await decrypt(xml, "SHA-1");
    expect(plain).toMatch(/^<saml:Assertion /);
  });

  it("emits sha256 OAEP with an explicit MGF element", async () => {
    const { upn } = await seed({
      encrypt_assertions: true,
      encryption_cert: TEST_SAML_SP_CERT_PEM,
      encryption_policy: { digest: "sha256", mgf: "sha256" },
    });
    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC}rsa-oaep-mgf1p"`);
    expect(xml).toContain(`<ds:DigestMethod Algorithm="${DS}sha256">`);
    expect(xml).toContain(`<xenc11:MGF xmlns:xenc11="${XENC11}" Algorithm="${XENC11}mgf1sha256">`);
    const { plain } = await decrypt(xml, "SHA-256");
    expect(plain).toMatch(/^<saml:Assertion /);
  });

  it("honours md:EncryptionMethod advertised in imported metadata", async () => {
    const { apiKey, upn } = await seed({ encrypt_assertions: true, encryption_cert: TEST_SAML_SP_CERT_PEM });
    const certB64 = TEST_SAML_SP_CERT_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const metadata =
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="${DS}" entityID="${SP_ENTITY_ID}">` +
      `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
      `<md:KeyDescriptor use="encryption"><md:EncryptionMethod Algorithm="${XENC11}aes128-gcm"/><md:EncryptionMethod Algorithm="${XENC11}rsa-oaep"/>` +
      `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
      `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${SP_ACS}" index="0" isDefault="true"/>` +
      `</md:SPSSODescriptor></md:EntityDescriptor>`;
    const res = await apiCall("/api/v1/saml/service-providers/import-metadata", { token: apiKey, body: { xml: metadata } });
    expect(res.status).toBe(200);

    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC11}aes128-gcm"`);
    expect(xml).toContain(`Algorithm="${XENC11}rsa-oaep"`);
    const { plain } = await decrypt(xml, "SHA-1");
    expect(plain).toMatch(/^<saml:Assertion /);
  });

  it("rejects an mgf that disagrees with the digest", async () => {
    const { apiKey } = await seed({ encrypt_assertions: true, encryption_cert: TEST_SAML_SP_CERT_PEM });
    const res = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, encryption_policy: { digest: "sha1", mgf: "sha256" } },
    });
    expect(res.status).toBe(400);
  });
});

describe("IdP-initiated SSO", () => {
  async function loginSession(upn: string): Promise<string> {
    const res = await SELF.fetch(`${BASE}/login`, { redirect: "manual" });
    const flowId = /name="flow_id" value="([^"]*)"/.exec(await res.text())?.[1];
    const submitted = await SELF.fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ flow_id: flowId!, upn, password: USER_PASSWORD }).toString(),
      redirect: "manual",
    });
    return submitted.headers.get("Set-Cookie")!.split(";")[0]!;
  }

  it("redirects to login with no session, then issues a response without InResponseTo", async () => {
    const { upn } = await seed();
    const anon = await SELF.fetch(`${BASE}/saml/idp-initiated?sp=${encodeURIComponent(SP_ENTITY_ID)}`, { redirect: "manual" });
    expect(anon.status).toBe(302);
    expect(anon.headers.get("Location")).toContain("/login?next=");

    const cookie = await loginSession(upn);
    const res = await SELF.fetch(`${BASE}/saml/idp-initiated?sp=${encodeURIComponent(SP_ENTITY_ID)}&RelayState=target-page`, {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    const samlResponse = /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1];
    const relayState = /name="RelayState" value="([^"]*)"/.exec(html)?.[1];
    expect(/<form method="POST" action="([^"]*)"/.exec(html)?.[1]).toBe(SP_ACS);
    expect(relayState).toBe("target-page");

    const xml = new TextDecoder().decode(b64decode(samlResponse!));
    expect(xml).not.toContain("InResponseTo");
    expect(xml).toContain('Value="urn:oasis:names:tc:SAML:2.0:status:Success"');
    expect(xml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
    expect(xml).toContain(`Recipient="${SP_ACS}"`);
  });

  it("refuses an unknown service provider", async () => {
    await seed();
    const res = await SELF.fetch(`${BASE}/saml/idp-initiated?sp=${encodeURIComponent("https://unknown.test/x")}`, { redirect: "manual" });
    expect(res.status).toBe(400);
  });
});

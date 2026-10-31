import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { TEST_SAML_IDP_CERT_PEM, TEST_SAML_IDP_KEY_PKCS8, TEST_SAML_SP_CERT_PEM, TEST_SAML_SP_KEY_PKCS8 } from "./fixtures/saml-keys.js";
import { certToVerifyKey } from "../src/lib/saml/x509.js";
import { b64decode, b64encode } from "../src/lib/saml/xml.js";

beforeEach(resetDatabase);

const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";
const USER_PASSWORD = "a-test-user-password-1";
const SIGALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/** Registers an SP and a user who can sign in, the way seedRelyingParty does for OIDC. */
async function seedServiceProvider(sp: Record<string, unknown> = {}): Promise<{ upn: string; apiKey: string }> {
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
      users: [
        {
          username: "ada.kowalski",
          given_name: "Ada",
          family_name: "Kowalski",
          job_title: "Chief Executive Officer",
          department: "Executive",
          password: USER_PASSWORD,
          groups: ["All Employees", "Executives"],
        },
      ],
    },
  });

  return { upn: `ada.kowalski@${domain}`, apiKey };
}

function authnRequestXml(opts: {
  id?: string;
  issuer?: string;
  acsUrl?: string | null;
  destination?: string | null;
  forceAuthn?: boolean;
  version?: string;
} = {}): string {
  const id = opts.id ?? `_req-${Math.random().toString(16).slice(2)}`;
  const issuer = opts.issuer ?? SP_ENTITY_ID;
  const acs = opts.acsUrl === undefined ? SP_ACS : opts.acsUrl;
  const destination = opts.destination === undefined ? `${BASE}/saml/sso` : opts.destination;
  return (
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${id}" Version="${opts.version ?? "2.0"}" IssueInstant="2026-10-31T00:00:00Z"` +
    (acs ? ` AssertionConsumerServiceURL="${acs}"` : "") +
    (destination ? ` Destination="${destination}"` : "") +
    (opts.forceAuthn ? ` ForceAuthn="true"` : "") +
    `><saml:Issuer>${issuer}</saml:Issuer></samlp:AuthnRequest>`
  );
}

/** raw-DEFLATE + base64: the HTTP-Redirect binding's encoding. */
async function deflateB64(xml: string): Promise<string> {
  const stream = new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  const buf = await new Response(stream).arrayBuffer();
  return b64encode(buf);
}

interface SsoUrl {
  query: string;
  requestId: string;
}

async function ssoQuery(xml: string, opts: { relayState?: string; sign?: "sp" | "idp" | "bad" } = {}): Promise<SsoUrl> {
  const requestId = /ID="([^"]*)"/.exec(xml)?.[1] ?? "";
  const reqEnc = encodeURIComponent(await deflateB64(xml));
  const relayEnc = opts.relayState !== undefined ? encodeURIComponent(opts.relayState) : undefined;
  if (!opts.sign) {
    return { query: `SAMLRequest=${reqEnc}` + (relayEnc !== undefined ? `&RelayState=${relayEnc}` : ""), requestId };
  }

  const sigAlgEnc = encodeURIComponent(SIGALG_RSA_SHA256);
  const signedContent = `SAMLRequest=${reqEnc}` + (relayEnc !== undefined ? `&RelayState=${relayEnc}` : "") + `&SigAlg=${sigAlgEnc}`;

  let signature = "";
  if (opts.sign === "bad") {
    signature = b64encode("not-a-real-signature");
  } else {
    const pkcs8 = opts.sign === "sp" ? TEST_SAML_SP_KEY_PKCS8 : TEST_SAML_IDP_KEY_PKCS8;
    const der = b64decode(pkcs8.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
    const key = await crypto.subtle.importKey("pkcs8", der as BufferSource, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    signature = b64encode(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signedContent)));
  }

  return {
    query:
      `SAMLRequest=${reqEnc}` +
      (relayEnc !== undefined ? `&RelayState=${relayEnc}` : "") +
      `&SigAlg=${sigAlgEnc}&Signature=${encodeURIComponent(signature)}`,
    requestId,
  };
}

/** Drives GET /saml/sso -> login form -> POST /login, returning the auto-POST page's fields. */
async function ssoViaLogin(query: string, upn: string, cookie?: string): Promise<{ status: number; html: string; sessionCookie: string | null }> {
  const first = await SELF.fetch(`${BASE}/saml/sso?${query}`, { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} });
  const firstHtml = await first.text();

  const flowId = /name="flow_id" value="([^"]*)"/.exec(firstHtml)?.[1];
  if (!flowId) return { status: first.status, html: firstHtml, sessionCookie: null };

  const submitted = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password: USER_PASSWORD }).toString(),
    redirect: "manual",
  });
  const setCookie = submitted.headers.get("Set-Cookie");
  return { status: submitted.status, html: await submitted.text(), sessionCookie: setCookie?.split(";")[0] ?? null };
}

function postFormFields(html: string): { acsUrl: string | null; samlResponse: string | null; relayState: string | null } {
  return {
    acsUrl: /<form method="POST" action="([^"]*)">/.exec(html)?.[1] ?? null,
    samlResponse: /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1] ?? null,
    relayState: /name="RelayState" value="([^"]*)"/.exec(html)?.[1] ?? null,
  };
}

/**
 * The closest thing to an independent verifier available inside workerd:
 * checks that each SignedInfo actually verifies with the certificate's public
 * key, and that each DigestValue equals SHA-256 of the element minus its
 * Signature - which is precisely what the enveloped-signature transform gives
 * a real verifier, because our emitted form is already canonical.
 */
async function expectSignaturesVerify(xml: string): Promise<void> {
  const key = await certToVerifyKey(TEST_SAML_IDP_CERT_PEM);
  expect(key, "fixture cert should import").not.toBeNull();

  // Every ds:Signature in the document: its SignedInfo bytes are what was
  // signed, so verify them directly.
  const signatures = xml.match(/<ds:Signature xmlns:ds="[^"]*">.*?<\/ds:Signature>/g) ?? [];
  expect(signatures.length).toBeGreaterThan(0);
  for (const sig of signatures) {
    const signedInfo = /<ds:SignedInfo[\s\S]*?<\/ds:SignedInfo>/.exec(sig)?.[0] ?? "";
    const signatureValue = /<ds:SignatureValue>([^<]*)<\/ds:SignatureValue>/.exec(sig)?.[1] ?? "";
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key!,
      b64decode(signatureValue) as BufferSource,
      new TextEncoder().encode(signedInfo)
    );
    expect(ok, "signature over SignedInfo").toBe(true);
  }

  // Response digest: the whole document minus its own (first) Signature.
  const responseDigest = /<ds:DigestValue>([^<]*)<\/ds:DigestValue>/.exec(xml)?.[1] ?? "";
  const unsignedResponse = xml.replace(/<ds:Signature xmlns:ds="[^"]*">.*?<\/ds:Signature>/, "");
  const responseHash = b64encode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(unsignedResponse)));
  expect(responseHash, "Response digest").toBe(responseDigest);

  // Assertion digest: the assertion substring minus its own Signature.
  const assertion = /<saml:Assertion[\s\S]*?<\/saml:Assertion>/.exec(xml)?.[0] ?? "";
  expect(assertion).not.toBe("");
  const assertionDigest = /<ds:DigestValue>([^<]*)<\/ds:DigestValue>/.exec(assertion)?.[1] ?? "";
  const unsignedAssertion = assertion.replace(/<ds:Signature xmlns:ds="[^"]*">.*?<\/ds:Signature>/, "");
  const assertionHash = b64encode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(unsignedAssertion)));
  expect(assertionHash, "Assertion digest").toBe(assertionDigest);
}

function decodeResponse(samlResponse: string): string {
  return new TextDecoder().decode(b64decode(samlResponse));
}

describe("metadata", () => {
  it("publishes an EntityDescriptor with the redirect-binding SSO endpoint and signing certificate", async () => {
    const response = await SELF.fetch(`${BASE}/saml/metadata`);
    const xml = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("samlmetadata");
    expect(xml).toContain(`entityID="${BASE}"`);
    expect(xml).toContain(`Location="${BASE}/saml/sso"`);
    expect(xml).toContain("HTTP-Redirect");
    expect(xml).not.toContain("HTTP-POST");
    expect(xml).toContain("nameid-format:transient");
    expect(xml).toContain(TEST_SAML_IDP_CERT_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  });
});

describe("SSO happy path", () => {
  it("logs in and POSTs a signed response with the right subject, audience and attributes", async () => {
    const { upn } = await seedServiceProvider();
    const { query, requestId } = await ssoQuery(authnRequestXml(), { relayState: "deep-link-state" });

    const result = await ssoViaLogin(query, upn);
    const fields = postFormFields(result.html);

    expect(fields.acsUrl).toBe(SP_ACS);
    expect(fields.relayState).toBe("deep-link-state");
    expect(fields.samlResponse).toBeTruthy();

    const xml = decodeResponse(fields.samlResponse!);
    expect(xml).toContain(`InResponseTo="${requestId}"`);
    expect(xml).toContain(`Destination="${SP_ACS}"`);
    expect(xml).toContain(`<saml:Issuer>${BASE}</saml:Issuer>`);
    expect(xml).toContain(`Recipient="${SP_ACS}"`);
    expect(xml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
    expect(xml).toContain("nameid-format:transient");
    expect(xml).toContain("SessionIndex=");
    expect(xml).toContain("status:Success");
    expect(xml).toContain(`<saml:AttributeValue>${upn}</saml:AttributeValue>`);
    expect(xml).toContain(`<saml:AttributeValue>All Employees</saml:AttributeValue>`);
    expect(xml).toContain(`<saml:AttributeValue>Executives</saml:AttributeValue>`);
    expect(xml).toContain("PasswordProtectedTransport");

    await expectSignaturesVerify(xml);
  });

  it("answers with an existing session and no login form", async () => {
    const { upn } = await seedServiceProvider();
    const login = await ssoViaLogin((await ssoQuery(authnRequestXml())).query, upn);
    expect(login.sessionCookie).toBeTruthy();

    const second = await SELF.fetch(`${BASE}/saml/sso?${(await ssoQuery(authnRequestXml())).query}`, {
      redirect: "manual",
      headers: { Cookie: login.sessionCookie! },
    });
    const html = await second.text();

    expect(second.status).toBe(200);
    expect(html).toContain('name="SAMLResponse"');
    expect(html).not.toContain('name="flow_id"');
  });

  it("honours ForceAuthn by showing the login form even with a live session", async () => {
    const { upn } = await seedServiceProvider();
    const login = await ssoViaLogin((await ssoQuery(authnRequestXml())).query, upn);

    const forced = await SELF.fetch(`${BASE}/saml/sso?${(await ssoQuery(authnRequestXml({ forceAuthn: true }))).query}`, {
      redirect: "manual",
      headers: { Cookie: login.sessionCookie! },
    });
    const html = await forced.text();
    expect(html).toContain('name="flow_id"');
  });

  it("uses the emailAddress NameID format and the configured attribute map", async () => {
    const { upn } = await seedServiceProvider({
      nameid_format: "emailAddress",
      attribute_map: { email: "email", dept: "department" },
    });
    const { query } = await ssoQuery(authnRequestXml());
    const result = await ssoViaLogin(query, upn);
    const xml = decodeResponse(postFormFields(result.html).samlResponse!);

    expect(xml).toContain(`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${upn}</saml:NameID>`);
    expect(xml).toContain(`<saml:Attribute Name="dept"`);
    expect(xml).toContain(`<saml:AttributeValue>Executive</saml:AttributeValue>`);
    // Only the configured attributes are emitted - no groups leak.
    expect(xml).not.toContain("All Employees");
  });

  it("uses the default ACS URL when the request omits one", async () => {
    const { upn } = await seedServiceProvider({ default_acs_url: SP_ACS, acs_urls: [SP_ACS, "https://sp.test/acs2"] });
    const { query } = await ssoQuery(authnRequestXml({ acsUrl: null }));
    const result = await ssoViaLogin(query, upn);
    const xml = decodeResponse(postFormFields(result.html).samlResponse!);
    expect(xml).toContain(`Recipient="${SP_ACS}"`);
  });
});

describe("request validation", () => {
  it("rejects an unknown service provider", async () => {
    await seedServiceProvider();
    const { query } = await ssoQuery(authnRequestXml({ issuer: "https://evil.test" }));
    const response = await SELF.fetch(`${BASE}/saml/sso?${query}`);
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/Unknown service provider/);
  });

  it("rejects an unregistered ACS URL", async () => {
    await seedServiceProvider();
    const { query } = await ssoQuery(authnRequestXml({ acsUrl: "https://attacker.test/acs" }));
    const response = await SELF.fetch(`${BASE}/saml/sso?${query}`);
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/not registered/);
  });

  it("rejects a replayed request ID", async () => {
    const { upn } = await seedServiceProvider();
    const xml = authnRequestXml({ id: "_replay-me" });
    const { query } = await ssoQuery(xml);
    await ssoViaLogin(query, upn);

    const second = await SELF.fetch(`${BASE}/saml/sso?${query}`);
    expect(second.status).toBe(400);
    expect(await second.text()).toMatch(/already been answered/);
  });

  it("rejects a mismatched Destination", async () => {
    await seedServiceProvider();
    const { query } = await ssoQuery(authnRequestXml({ destination: "https://other.test/saml/sso" }));
    const response = await SELF.fetch(`${BASE}/saml/sso?${query}`);
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/Destination/);
  });

  it("rejects the POST binding outright", async () => {
    const response = await SELF.fetch(`${BASE}/saml/sso`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "SAMLRequest=anything",
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/HTTP-POST request binding is not supported/);
  });
});

describe("signed AuthnRequests", () => {
  it("rejects an unsigned request when the SP requires a signature", async () => {
    await seedServiceProvider({ want_authn_requests_signed: true, signing_certs: [TEST_SAML_SP_CERT_PEM] });
    const { query } = await ssoQuery(authnRequestXml());
    const response = await SELF.fetch(`${BASE}/saml/sso?${query}`);
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/requires signed/);
  });

  it("accepts a correctly signed request", async () => {
    const { upn } = await seedServiceProvider({ want_authn_requests_signed: true, signing_certs: [TEST_SAML_SP_CERT_PEM] });
    const { query } = await ssoQuery(authnRequestXml(), { sign: "sp", relayState: "rs" });
    const result = await ssoViaLogin(query, upn);
    const fields = postFormFields(result.html);
    expect(fields.samlResponse).toBeTruthy();
    expect(fields.relayState).toBe("rs");
  });

  it("rejects a signature made with a different key", async () => {
    await seedServiceProvider({ want_authn_requests_signed: true, signing_certs: [TEST_SAML_SP_CERT_PEM] });
    const { query } = await ssoQuery(authnRequestXml(), { sign: "idp" });
    const response = await SELF.fetch(`${BASE}/saml/sso?${query}`);
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/could not be verified/);
  });
});

describe("provisioning API", () => {
  it("creates, lists and deletes a service provider", async () => {
    const { apiKey } = await bootstrapInstance();

    const created = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, name: "Test SP", acs_urls: [SP_ACS], nameid_format: "persistent" },
    });
    expect(created.status).toBe(200);
    expect(created.body.created).toBe(true);

    const listed = await apiCall("/api/v1/saml/service-providers", { token: apiKey });
    expect(listed.body.service_providers).toHaveLength(1);
    expect(listed.body.service_providers[0].entity_id).toBe(SP_ENTITY_ID);
    expect(listed.body.service_providers[0].nameid_format).toBe("persistent");

    // Upsert converges rather than colliding on the unique entity_id.
    const again = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, name: "Renamed SP" },
    });
    expect(again.body.created).toBe(false);

    const deleted = await apiCall(`/api/v1/saml/service-providers/${created.body.id}`, { token: apiKey, method: "DELETE" });
    expect(deleted.status).toBe(200);
  });

  it("rejects an attribute map naming a field that does not exist", async () => {
    const { apiKey } = await bootstrapInstance();
    const response = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, acs_urls: [SP_ACS], attribute_map: { x: "credit_card" } },
    });
    expect(response.status).toBe(400);
  });
});

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

const sha = async (name: string, d: Uint8Array) => new Uint8Array(await crypto.subtle.digest(name, d));

async function mgf1(seed: Uint8Array, outLen: number, hash: string, hLen: number): Promise<Uint8Array> {
  const out = new Uint8Array(outLen);
  const counter = new Uint8Array(seed.length + 4);
  counter.set(seed);
  for (let i = 0, off = 0; off < outLen; i++, off += hLen) {
    counter[seed.length] = i >>> 24;
    counter[seed.length + 1] = (i >>> 16) & 0xff;
    counter[seed.length + 2] = (i >>> 8) & 0xff;
    counter[seed.length + 3] = i & 0xff;
    out.set((await sha(hash, counter)).subarray(0, Math.min(hLen, outLen - off)), off);
  }
  return out;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  for (let b = base % mod, x = exp; x > 0n; x >>= 1n, b = (b * b) % mod) {
    if (x & 1n) result = (result * b) % mod;
  }
  return result;
}

/** RSAES-OAEP-DECRYPT with independent md/MGF hashes - verifies wraps WebCrypto cannot express. */
async function decryptOaep(ciphertext: Uint8Array, pkcs8: Uint8Array, mdHash: string, mdLen: number, mgfHash: string, mgfLen: number): Promise<Uint8Array> {
  let pos = 0;
  const hdr = () => {
    let len = pkcs8[pos + 1]!;
    pos += 2;
    if (len & 0x80) { const nb = len & 0x7f; len = 0; for (let i = 0; i < nb; i++) len = (len << 8) | pkcs8[pos++]!; }
    return { len, start: pos };
  };
  hdr(); // PKCS#8 SEQUENCE
  const ver = hdr();
  pos = ver.start + ver.len; // version INTEGER
  const alg = hdr();
  pos = alg.start + alg.len; // algorithmIdentifier SEQUENCE
  const os = hdr();
  pos = os.start; // privateKey OCTET STRING -> RSAPrivateKey
  hdr(); // RSAPrivateKey SEQUENCE
  const int = () => { const h = hdr(); pos = h.start + h.len; return pkcs8.subarray(h.start, h.start + h.len); };
  int(); // version
  const nB = int();
  int(); // e
  const dB = int();
  let n = 0n;
  let d = 0n;
  for (const b of nB) n = (n << 8n) | BigInt(b);
  for (const b of dB) d = (d << 8n) | BigInt(b);
  const k = ciphertext.length;
  let c = 0n;
  for (const b of ciphertext) c = (c << 8n) | BigInt(b);
  const em = new Uint8Array(k);
  for (let m = modPow(c, d, n), i = k - 1; i >= 0; i--, m >>= 8n) em[i] = Number(m & 0xffn);
  const seedMask = await mgf1(em.subarray(1 + mdLen), mdLen, mgfHash, mgfLen);
  const seed = em.subarray(1, 1 + mdLen).map((b, i) => b ^ seedMask[i]!);
  const dbMask = await mgf1(seed, k - 1 - mdLen, mgfHash, mgfLen);
  const db = em.subarray(1 + mdLen).map((b, i) => b ^ dbMask[i]!);
  const lHash = await sha(mdHash, new Uint8Array(0));
  expect([...db.subarray(0, mdLen)]).toEqual([...lHash]);
  let i = mdLen;
  while (db[i] === 0) i++;
  expect(db[i]).toBe(1);
  return db.subarray(i + 1);
}

/** Decrypts the EncryptedAssertion with the SP's key; returns the plaintext and wrapper shape. */
async function decrypt(xml: string, hash: string, mode: "gcm" | "cbc" = "gcm", mgfHash?: string): Promise<{ plain: string; xml: string }> {
  const values = [...xml.matchAll(/<xenc:CipherValue>([^<]+)<\/xenc:CipherValue>/g)].map((m) => b64decode(m[1]!));
  const der = b64decode(TEST_SAML_SP_KEY_PKCS8.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const lens: Record<string, number> = { "SHA-1": 20, "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };
  const cek = !mgfHash || mgfHash === hash
    ? new Uint8Array(await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        await crypto.subtle.importKey("pkcs8", der as BufferSource, { name: "RSA-OAEP", hash }, false, ["decrypt"]),
        values[0] as BufferSource))
    : await decryptOaep(new Uint8Array(values[0]!), new Uint8Array(der), hash, lens[hash]!, mgfHash, lens[mgfHash]!);
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

  it("emits the parameterized xmlenc11 rsa-oaep with direct parameter children", async () => {
    const { upn } = await seed({
      encrypt_assertions: true,
      encryption_cert: TEST_SAML_SP_CERT_PEM,
      encryption_policy: { transport: "rsa-oaep" },
    });
    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC11}rsa-oaep"`);
    expect(xml).not.toContain("<xenc:OAEPParams>"); // explicit-seed slot; unused
    expect(xml).toContain(`<ds:DigestMethod Algorithm="${DS}sha1">`);
    expect(xml).not.toContain("xenc11:MGF"); // omitted MGF = spec default MGF1-SHA1
    const { plain } = await decrypt(xml, "SHA-1");
    expect(plain).toMatch(/^<saml:Assertion /);
  });

  it("emits mgf1p with a sha256 digest wrapped by the fixed MGF1-SHA1 mask", async () => {
    const { upn } = await seed({
      encrypt_assertions: true,
      encryption_cert: TEST_SAML_SP_CERT_PEM,
      encryption_policy: { digest: "sha256" },
    });
    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC}rsa-oaep-mgf1p"`);
    // RFC 4051 URI (xmlenc#sha256), not xmldsig#sha256 - only the former is
    // registered so peers can map it to a JCE digest.
    expect(xml).toContain(`<ds:DigestMethod Algorithm="${XENC}sha256">`);
    // The 1.0 URI fixes the mask to MGF1-SHA1 - no xenc11:MGF child is
    // emitted, and WebCrypto cannot express the mismatched pair, so the wrap
    // is verified by manual OAEP decode: SHA-256 label hash, MGF1-SHA1 mask.
    expect(xml).not.toContain("xenc11:MGF");
    const { plain } = await decrypt(xml, "SHA-256", "gcm", "SHA-1");
    expect(plain).toMatch(/^<saml:Assertion /);
  });

  it("emits sha256 OAEP with an explicit mgf1sha256 under the 1.1 URI", async () => {
    const { upn } = await seed({
      encrypt_assertions: true,
      encryption_cert: TEST_SAML_SP_CERT_PEM,
      encryption_policy: { transport: "rsa-oaep", digest: "sha256", mgf: "sha256" },
    });
    const { xml } = await ssoResponse(upn);
    expect(xml).toContain(`Algorithm="${XENC11}rsa-oaep"`);
    expect(xml).toContain(`<ds:DigestMethod Algorithm="${XENC}sha256">`);
    expect(xml).toContain(`<xenc11:MGF xmlns:xenc11="${XENC11}" Algorithm="${XENC11}mgf1sha256"></xenc11:MGF>`);
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

  it("rejects a non-sha1 MGF under rsa-oaep-mgf1p", async () => {
    const { apiKey } = await seed({ encrypt_assertions: true, encryption_cert: TEST_SAML_SP_CERT_PEM });
    const res = await apiCall("/api/v1/saml/service-providers", {
      token: apiKey,
      body: { entity_id: SP_ENTITY_ID, encryption_policy: { digest: "sha256", mgf: "sha256" } },
    });
    // The default transport is rsa-oaep-mgf1p, whose MGF is fixed to
    // MGF1-SHA1 - declaring mgf1sha256 under it is a false declaration.
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

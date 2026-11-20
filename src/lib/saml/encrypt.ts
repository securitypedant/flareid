import { b64encode, pemToBase64Der } from "./xml.js";

const NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
const NS_XENC11 = "http://www.w3.org/2009/xmlenc11#";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const NS_DS_MORE = "http://www.w3.org/2001/04/xmldsig-more#";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

/** Assertion content-encryption algorithms FlareID can emit (all WebCrypto-reachable). */
export const CONTENT_ALGORITHMS = {
  [`${NS_XENC11}aes128-gcm`]: { token: "aes128-gcm", keyBytes: 16, mode: "gcm" },
  [`${NS_XENC11}aes192-gcm`]: { token: "aes192-gcm", keyBytes: 24, mode: "gcm" },
  [`${NS_XENC11}aes256-gcm`]: { token: "aes256-gcm", keyBytes: 32, mode: "gcm" },
  [`${NS_XENC}aes128-cbc`]: { token: "aes128-cbc", keyBytes: 16, mode: "cbc" },
  [`${NS_XENC}aes192-cbc`]: { token: "aes192-cbc", keyBytes: 24, mode: "cbc" },
  [`${NS_XENC}aes256-cbc`]: { token: "aes256-cbc", keyBytes: 32, mode: "cbc" },
} as const;

/** Key-transport algorithms: the 2001 mgf1p URI and the XML Enc 1.1 parameterized OAEP. */
export const TRANSPORT_ALGORITHMS = {
  [`${NS_XENC}rsa-oaep-mgf1p`]: { token: "rsa-oaep-mgf1p", parameterized: false },
  [`${NS_XENC11}rsa-oaep`]: { token: "rsa-oaep", parameterized: true },
} as const;

// RFC 4051 digest identifiers: only SHA-1 lives under xmldsig# - 256/512 are
// xmlenc#, 384 is xmldsig-more#. Emitting xmldsig#sha256 is unregistered and
// peers (e.g. Apache Santuario) cannot map it to a JCE digest.
const DIGEST_URIS: Record<string, { uri: string; subtle: string; mgfUri: string }> = {
  sha1: { uri: `${NS_DS}sha1`, subtle: "SHA-1", mgfUri: `${NS_XENC11}mgf1sha1` },
  sha256: { uri: `${NS_XENC}sha256`, subtle: "SHA-256", mgfUri: `${NS_XENC11}mgf1sha256` },
  sha384: { uri: `${NS_DS_MORE}sha384`, subtle: "SHA-384", mgfUri: `${NS_XENC11}mgf1sha384` },
  sha512: { uri: `${NS_XENC}sha512`, subtle: "SHA-512", mgfUri: `${NS_XENC11}mgf1sha512` },
};

/** Resolved per-SP encryption choice. `mgf: null` omits the MGF element (spec default MGF1-SHA1). */
export interface EncryptionPolicy {
  content: keyof typeof CONTENT_ALGORITHMS;
  transport: keyof typeof TRANSPORT_ALGORITHMS;
  digest: keyof typeof DIGEST_URIS;
  mgf: keyof typeof DIGEST_URIS | null;
}

export const DEFAULT_ENCRYPTION_POLICY: EncryptionPolicy = {
  content: `${NS_XENC11}aes256-gcm`,
  transport: `${NS_XENC}rsa-oaep-mgf1p`,
  digest: "sha1",
  mgf: null,
};

/** The SubjectPublicKeyInfo inside an X.509 certificate, found by walking its DER. */
function spkiFromCert(der: Uint8Array): Uint8Array {
  // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version?, serial, sigAlg, issuer, validity, subject, spki, ... } }
  let pos = 0;
  const readHeader = () => {
    const tag = der[pos++]!;
    let len = der[pos++]!;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | der[pos++]!;
    }
    return { tag, len, start: pos };
  };
  readHeader(); // Certificate
  readHeader(); // tbsCertificate
  const skip = () => {
    const h = readHeader();
    pos = h.start + h.len;
    return h;
  };
  if (der[pos] === 0xa0) skip(); // [0] version
  skip(); // serialNumber
  skip(); // signature
  skip(); // issuer
  skip(); // validity
  skip(); // subject
  const start = pos;
  const spki = skip();
  return der.slice(start, spki.start + spki.len);
}

/**
 * Encrypts an assertion for the SP (SAML Core 2.7.3 EncryptedAssertion,
 * XML Encryption 1.1): a fresh content-encryption key seals the assertion and
 * is itself wrapped with RSA-OAEP to the public key in the SP's encryption
 * certificate. The signature, when the assertion is signed, is inside -
 * sign-then-encrypt, as SAML expects.
 *
 * `policy` selects the emitted algorithms; WebCrypto applies one OAEP hash to
 * both the data hash and the MGF1 mask, so the emitted MGF always matches the
 * digest - an omitted MGF element is only emitted when it resolves to the
 * spec default (SHA-1).
 */
export async function encryptAssertion(assertionXml: string, certPem: string, policy?: Partial<EncryptionPolicy>): Promise<string> {
  const p = { ...DEFAULT_ENCRYPTION_POLICY, ...(policy ?? {}) };
  const content = CONTENT_ALGORITHMS[p.content];
  const digest = DIGEST_URIS[p.digest];
  if (!content || !digest || !(p.transport in TRANSPORT_ALGORITHMS)) throw new Error("Unsupported encryption policy");
  // WebCrypto derives the MGF1 mask hash from the key's hash: the emitted MGF
  // must equal the digest, so an explicit MGF different from the digest is
  // rejected rather than emitted falsely. Omitting the element is only honest
  // for the spec default (MGF1-SHA1); any other digest names its MGF.
  const mgfHash = p.mgf ?? p.digest;
  const mgf = DIGEST_URIS[mgfHash];
  if (!mgf || mgf.subtle !== digest.subtle) throw new Error("OAEP MGF must use the same hash as the digest");

  const der = Uint8Array.from(atob(pemToBase64Der(certPem)), (c) => c.charCodeAt(0));
  const publicKey = await crypto.subtle.importKey("spki", spkiFromCert(der) as BufferSource, { name: "RSA-OAEP", hash: digest.subtle }, false, ["encrypt"]);
  const contentKey = crypto.getRandomValues(new Uint8Array(content.keyBytes));
  const input = new TextEncoder().encode(assertionXml);
  let cipher: Uint8Array;
  if (content.mode === "gcm") {
    const aes = await crypto.subtle.importKey("raw", contentKey, { name: "AES-GCM" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // XML Encryption 1.1 GCM: CipherValue is IV || ciphertext || 128-bit tag.
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, aes, input));
    cipher = new Uint8Array(iv.length + sealed.length);
    cipher.set(iv);
    cipher.set(sealed, iv.length);
  } else {
    const aes = await crypto.subtle.importKey("raw", contentKey, { name: "AES-CBC" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    // XML Encryption 1.0 CBC: CipherValue is IV || PKCS#7-padded ciphertext.
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, input));
    cipher = new Uint8Array(iv.length + sealed.length);
    cipher.set(iv);
    cipher.set(sealed, iv.length);
  }
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, contentKey));

  const transport = TRANSPORT_ALGORITHMS[p.transport];
  // XML Encryption 1.1 §5.4.2: under the parameterized xmlenc11 rsa-oaep,
  // ds:DigestMethod and xenc11:MGF are direct children of EncryptionMethod -
  // xenc:OAEPParams instead carries an explicit base64 parameter seed, which we
  // never use, so it is omitted. Under the 2001 rsa-oaep-mgf1p the mask is
  // fixed to MGF1 keyed by the digest's hash, so only DigestMethod is emitted:
  // an xenc11:MGF child there would declare a second, contradictory MGF.
  // xmlns:ds is inherited from ds:KeyInfo and xmlns:xenc from xenc:EncryptedData;
  // xenc11 is a new prefix, so exclusive C14N renders it on the MGF apex itself.
  const mgfElement = p.mgf === null ? "" : `<xenc11:MGF xmlns:xenc11="${NS_XENC11}" Algorithm="${mgf.mgfUri}"></xenc11:MGF>`;
  const transportMethod = transport.parameterized
    ? `<xenc:EncryptionMethod Algorithm="${p.transport}"><ds:DigestMethod Algorithm="${digest.uri}"></ds:DigestMethod>${mgfElement}</xenc:EncryptionMethod>`
    : `<xenc:EncryptionMethod Algorithm="${p.transport}"><ds:DigestMethod Algorithm="${digest.uri}"></ds:DigestMethod></xenc:EncryptionMethod>`;

  // Every element here is canonical-form emission (the whole subtree sits
  // inside the signed Response): xmlns on each usage apex, no self-closing
  // tags - C14N renders <x></x>, never <x/>.
  return (
    `<saml:EncryptedAssertion xmlns:saml="${NS_SAML}">` +
    `<xenc:EncryptedData xmlns:xenc="${NS_XENC}" Type="${NS_XENC}Element">` +
    `<xenc:EncryptionMethod Algorithm="${p.content}"></xenc:EncryptionMethod>` +
    `<ds:KeyInfo xmlns:ds="${NS_DS}">` +
    `<xenc:EncryptedKey>${transportMethod}` +
    `<xenc:CipherData><xenc:CipherValue>${b64encode(wrapped)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>` +
    `</ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${b64encode(cipher)}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedData>` +
    `</saml:EncryptedAssertion>`
  );
}

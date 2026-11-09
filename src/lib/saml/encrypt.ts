import { b64encode, pemToBase64Der } from "./xml.js";

const NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

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
 * XML Encryption 1.1): a fresh AES-256-GCM key encrypts the assertion, and is
 * itself encrypted with RSA-OAEP to the public key in the SP's encryption
 * certificate. The signature, when the assertion is signed, is inside -
 * sign-then-encrypt, as SAML expects.
 */
export async function encryptAssertion(assertionXml: string, certPem: string): Promise<string> {
  const der = Uint8Array.from(atob(pemToBase64Der(certPem)), (c) => c.charCodeAt(0));
  const publicKey = await crypto.subtle.importKey("spki", spkiFromCert(der) as BufferSource, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const aes = await crypto.subtle.importKey("raw", contentKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // XML Encryption 1.1 GCM: CipherValue is IV || ciphertext || 128-bit tag.
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, aes, new TextEncoder().encode(assertionXml)));
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, contentKey));
  const cipher = new Uint8Array(iv.length + sealed.length);
  cipher.set(iv);
  cipher.set(sealed, iv.length);

  return (
    `<saml:EncryptedAssertion>` +
    `<xenc:EncryptedData xmlns:xenc="${NS_XENC}" Type="${NS_XENC}Element">` +
    `<xenc:EncryptionMethod Algorithm="${AES256_GCM}"/>` +
    `<ds:KeyInfo xmlns:ds="${NS_DS}">` +
    `<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="${RSA_OAEP}"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></xenc:EncryptionMethod>` +
    `<xenc:CipherData><xenc:CipherValue>${b64encode(wrapped)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>` +
    `</ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${b64encode(cipher)}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedData>` +
    `</saml:EncryptedAssertion>`
  );
}

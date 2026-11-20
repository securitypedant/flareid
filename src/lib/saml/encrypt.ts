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
const DIGEST_URIS: Record<string, { uri: string; subtle: string; mgfUri: string; len: number }> = {
  sha1: { uri: `${NS_DS}sha1`, subtle: "SHA-1", mgfUri: `${NS_XENC11}mgf1sha1`, len: 20 },
  sha256: { uri: `${NS_XENC}sha256`, subtle: "SHA-256", mgfUri: `${NS_XENC11}mgf1sha256`, len: 32 },
  sha384: { uri: `${NS_DS_MORE}sha384`, subtle: "SHA-384", mgfUri: `${NS_XENC11}mgf1sha384`, len: 48 },
  sha512: { uri: `${NS_XENC}sha512`, subtle: "SHA-512", mgfUri: `${NS_XENC11}mgf1sha512`, len: 64 },
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

/** The RSAPublicKey (n, e) inside a SubjectPublicKeyInfo, found by walking its DER. */
function rsaKeyFromSpki(spki: Uint8Array): { n: bigint; e: bigint; k: number } {
  let pos = 0;
  const readHeader = () => {
    let len = spki[pos + 1]!;
    pos += 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | spki[pos++]!;
    }
    return { len, start: pos };
  };
  readHeader(); // SubjectPublicKeyInfo SEQUENCE
  const alg = readHeader(); // algorithmIdentifier
  pos = alg.start + alg.len;
  const bits = readHeader(); // subjectPublicKey BIT STRING
  pos = bits.start + 1; // the leading unused-bits count byte
  readHeader(); // RSAPublicKey SEQUENCE
  const nH = readHeader();
  const nBytes = spki.subarray(nH.start + (spki[nH.start] === 0 ? 1 : 0), nH.start + nH.len);
  pos = nH.start + nH.len;
  const eH = readHeader();
  const eBytes = spki.subarray(eH.start, eH.start + eH.len);
  let n = 0n;
  let e = 0n;
  for (const b of nBytes) n = (n << 8n) | BigInt(b);
  for (const b of eBytes) e = (e << 8n) | BigInt(b);
  return { n, e, k: nBytes.length };
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  for (let b = base % mod, x = exp; x > 0n; x >>= 1n, b = (b * b) % mod) {
    if (x & 1n) result = (result * b) % mod;
  }
  return result;
}

async function mgf1(seed: Uint8Array, outLen: number, hash: string, hLen: number): Promise<Uint8Array> {
  const out = new Uint8Array(outLen);
  const counter = new Uint8Array(seed.length + 4);
  counter.set(seed);
  for (let i = 0, off = 0; off < outLen; i++, off += hLen) {
    counter[seed.length] = i >>> 24;
    counter[seed.length + 1] = (i >>> 16) & 0xff;
    counter[seed.length + 2] = (i >>> 8) & 0xff;
    counter[seed.length + 3] = i & 0xff;
    out.set(new Uint8Array(await crypto.subtle.digest(hash, counter)).subarray(0, Math.min(hLen, outLen - off)), off);
  }
  return out;
}

/**
 * RSAES-OAEP-ENCRYPT per PKCS#1 v2.1 with the message digest and MGF1 mask
 * hash chosen independently - parameter pairs WebCrypto cannot express, such
 * as mgf1p's fixed MGF1-SHA1 mask beside a SHA-256 digest.
 */
async function rsaOaepWrap(message: Uint8Array, spki: Uint8Array, md: { subtle: string; len: number }, mgf: { subtle: string; len: number }): Promise<Uint8Array> {
  const { n, e, k } = rsaKeyFromSpki(spki);
  if (message.length > k - 2 * md.len - 2) throw new Error("OAEP message too long for key");
  const lHash = new Uint8Array(await crypto.subtle.digest(md.subtle, new Uint8Array(0)));
  const psLen = k - message.length - 2 * md.len - 2;
  const db = new Uint8Array(k - md.len - 1);
  db.set(lHash);
  db[md.len + psLen] = 0x01;
  db.set(message, md.len + psLen + 1);
  const seed = crypto.getRandomValues(new Uint8Array(md.len));
  const dbMask = await mgf1(seed, db.length, mgf.subtle, mgf.len);
  const maskedDB = db.map((b, i) => b ^ dbMask[i]!);
  const seedMask = await mgf1(maskedDB, md.len, mgf.subtle, mgf.len);
  const maskedSeed = seed.map((b, i) => b ^ seedMask[i]!);
  const em = new Uint8Array(k);
  em.set(maskedSeed, 1);
  em.set(maskedDB, 1 + md.len);
  let m = 0n;
  for (const b of em) m = (m << 8n) | BigInt(b);
  const out = new Uint8Array(k);
  for (let c = modPow(m, e, n), i = k - 1; i >= 0; i--, c >>= 8n) out[i] = Number(c & 0xffn);
  return out;
}

/**
 * Encrypts an assertion for the SP (SAML Core 2.7.3 EncryptedAssertion,
 * XML Encryption 1.1): a fresh content-encryption key seals the assertion and
 * is itself wrapped with RSA-OAEP to the public key in the SP's encryption
 * certificate. The signature, when the assertion is signed, is inside -
 * sign-then-encrypt, as SAML expects.
 *
 * `policy` selects the emitted algorithms. Mask generation resolves per the
 * transport URI: `rsa-oaep-mgf1p` fixes the mask to MGF1-SHA1 regardless of
 * the declared digest (XML Enc 1.0 §5.4.1); the 1.1 `rsa-oaep` honors an
 * explicit `xenc11:MGF` and defaults an omitted one to MGF1-SHA1 (§5.4.2).
 * WebCrypto uses one OAEP hash for both the data hash and the MGF1 mask, so
 * mismatched (digest, mgf) pairs are wrapped by rsaOaepWrap instead.
 */
export async function encryptAssertion(assertionXml: string, certPem: string, policy?: Partial<EncryptionPolicy>): Promise<string> {
  const p = { ...DEFAULT_ENCRYPTION_POLICY, ...(policy ?? {}) };
  const content = CONTENT_ALGORITHMS[p.content];
  const digest = DIGEST_URIS[p.digest];
  if (!content || !digest || !(p.transport in TRANSPORT_ALGORITHMS)) throw new Error("Unsupported encryption policy");
  const transport = TRANSPORT_ALGORITHMS[p.transport];
  const mgf = transport.parameterized
    ? DIGEST_URIS[p.mgf ?? "sha1"]
    : p.mgf === null || p.mgf === "sha1" ? DIGEST_URIS.sha1 : null;
  if (!mgf) throw new Error("rsa-oaep-mgf1p fixes the mask generation function to MGF1-SHA1");
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
  const der = Uint8Array.from(atob(pemToBase64Der(certPem)), (c) => c.charCodeAt(0));
  const spki = spkiFromCert(der);
  // WebCrypto ties the OAEP data hash and MGF1 mask hash together; where the
  // resolved pair diverges (e.g. mgf1p's fixed MGF1-SHA1 beside a SHA-256
  // digest) the wrap is built manually to the same PKCS#1 v2.1 structure.
  const wrapped = mgf.subtle === digest.subtle
    ? new Uint8Array(await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        await crypto.subtle.importKey("spki", spki as BufferSource, { name: "RSA-OAEP", hash: digest.subtle }, false, ["encrypt"]),
        contentKey))
    : await rsaOaepWrap(contentKey, spki, digest, mgf);

  // XML Encryption 1.1 §5.4.2: under the parameterized xmlenc11 rsa-oaep,
  // ds:DigestMethod and xenc11:MGF are direct children of EncryptionMethod -
  // xenc:OAEPParams instead carries an explicit base64 parameter seed, which we
  // never use, so it is omitted. Under the 2001 rsa-oaep-mgf1p the mask is
  // fixed to MGF1-SHA1, so only DigestMethod is emitted: an xenc11:MGF child
  // there would declare a second, contradictory MGF.
  // xmlns:ds is inherited from ds:KeyInfo and xmlns:xenc from xenc:EncryptedData;
  // xenc11 is a new prefix, so exclusive C14N renders it on the MGF apex itself.
  const mgfElement = !transport.parameterized || p.mgf === null ? "" : `<xenc11:MGF xmlns:xenc11="${NS_XENC11}" Algorithm="${mgf.mgfUri}"></xenc11:MGF>`;
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

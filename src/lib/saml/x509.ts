/// <reference types="node" />
import { X509Certificate } from "node:crypto";

/**
 * X.509 handling via `node:crypto`, which Workers implements under
 * nodejs_compat (both wrangler configs set the flag).
 *
 * The only things SAML needs out of a certificate are the SubjectPublicKeyInfo
 * - for verifying a service provider's redirect-binding signature - and the
 * notAfter date - for warning about expiry. X509Certificate gives us both
 * without hand-rolling an ASN.1 walk.
 */

/** Normalizes a pasted certificate: PEM with any whitespace, or bare base64 DER. */
export function normalizeCertPem(input: string): string | null {
  const body = input
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  if (!body || !/^[A-Za-z0-9+/=]+$/.test(body)) return null;
  try {
    // Round-trips through the parser, so a malformed blob is rejected here
    // rather than the first time a signature needs verifying.
    return new X509Certificate(`-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`).toString();
  } catch {
    return null;
  }
}

export function certNotAfter(pem: string): Date | null {
  try {
    return new X509Certificate(pem).validToDate;
  } catch {
    return null;
  }
}

/**
 * The RSA public key from an SP's signing certificate, imported ready to
 * verify RSASSA-PKCS1-v1_5/SHA-256. `export({format:"der",type:"spki"})` is
 * exactly the bytes crypto.subtle.importKey("spki") wants.
 */
export async function certToVerifyKey(pem: string): Promise<CryptoKey | null> {
  try {
    const spki = new X509Certificate(pem).publicKey.export({ format: "der", type: "spki" });
    return await crypto.subtle.importKey(
      "spki",
      new Uint8Array(spki),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  } catch {
    return null;
  }
}

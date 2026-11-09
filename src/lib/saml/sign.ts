import { importPKCS8 } from "jose";
import type { Env } from "../../env.js";
import { b64encode, pemToBase64Der } from "./xml.js";

const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ALG_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ALG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

/** SAML endpoints answer 503 rather than half-work when the signing credential was never provisioned. */
export function isSamlConfigured(env: Env): boolean {
  return Boolean(env.SAML_SIGNING_KEY_PKCS8 && env.SAML_SIGNING_CERT);
}

export function idpCertBase64(env: Env): string {
  return pemToBase64Der(env.SAML_SIGNING_CERT ?? "");
}

export async function signingKey(env: Env): Promise<CryptoKey> {
  if (!env.SAML_SIGNING_KEY_PKCS8) {
    throw new Error("SAML_SIGNING_KEY_PKCS8 is not configured - run `npm run saml:keygen` and set the secret");
  }
  return importPKCS8(env.SAML_SIGNING_KEY_PKCS8, "RS256");
}

/**
 * Signs an already-canonical XML subtree, returning a <ds:Signature> element.
 *
 * This is "canonical by construction" (SAML-implementation.md section 5): the
 * caller emits the subtree in canonical form *without* a Signature, we digest
 * exactly that string - which is what the enveloped-signature transform leaves
 * for the verifier - and the verifier's own canonicalization arrives back at
 * the same bytes. No C14N implementation is needed because we never canonicalize
 * XML we didn't write.
 *
 * SignedInfo declares xmlns:ds on itself for the same reason the Assertion
 * declares xmlns:saml: exclusive C14N renders visibly-utilized namespaces at
 * the apex, so this string is what the verifier produces when it extracts and
 * canonicalizes SignedInfo in isolation.
 */
export async function signSubtree(env: Env, canonicalXml: string, referenceId: string): Promise<string> {
  const key = await signingKey(env);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalXml));

  const signedInfo =
    `<ds:SignedInfo xmlns:ds="${NS_DS}">` +
    `<ds:CanonicalizationMethod Algorithm="${ALG_EXC_C14N}"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="${ALG_RSA_SHA256}"></ds:SignatureMethod>` +
    `<ds:Reference URI="#${referenceId}">` +
    `<ds:Transforms>` +
    `<ds:Transform Algorithm="${ALG_ENVELOPED}"></ds:Transform>` +
    `<ds:Transform Algorithm="${ALG_EXC_C14N}"></ds:Transform>` +
    `</ds:Transforms>` +
    `<ds:DigestMethod Algorithm="${ALG_SHA256}"></ds:DigestMethod>` +
    `<ds:DigestValue>${b64encode(digest)}</ds:DigestValue>` +
    `</ds:Reference>` +
    `</ds:SignedInfo>`;

  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signedInfo));

  return (
    `<ds:Signature xmlns:ds="${NS_DS}">${signedInfo}` +
    `<ds:SignatureValue>${b64encode(signature)}</ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${idpCertBase64(env)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>`
  );
}

/**
 * Splices a <ds:Signature> into an element immediately after its
 * <saml:Issuer> - the position both the Assertion and Response schemas
 * require.
 */
export function insertSignatureAfterIssuer(xml: string, signatureXml: string): string {
  const anchor = "</saml:Issuer>";
  const idx = xml.indexOf(anchor);
  if (idx === -1) throw new Error("cannot sign an element with no saml:Issuer");
  return xml.slice(0, idx + anchor.length) + signatureXml + xml.slice(idx + anchor.length);
}

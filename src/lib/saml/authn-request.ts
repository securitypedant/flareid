import { DOMParser } from "@xmldom/xmldom";
import type { SamlServiceProviderRow } from "../types.js";
import { b64decode } from "./xml.js";
import { certToVerifyKey } from "./x509.js";
import { spSigningCerts } from "./service-providers.js";

export const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
export const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const SIGALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

export class AuthnRequestError extends Error {}

export interface ParsedAuthnRequest {
  id: string;
  /** The SP's entityID - the <saml:Issuer> of the request. */
  issuer: string;
  acsUrl: string | null;
  forceAuthn: boolean;
  nameIdFormat: string | null;
  destination: string | null;
}

/**
 * The request parameters with their percent-encoding preserved.
 *
 * Redirect-binding signatures are over the *encoded* query string, so the
 * verification path must not see decoded values - URLSearchParams would give
 * back bytes the signer never signed.
 */
export function rawQueryParams(requestUrl: string): Record<string, string> {
  const query = new URL(requestUrl).search.replace(/^\?/, "");
  const out: Record<string, string> = {};
  for (const pair of query.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const key = eq === -1 ? pair : pair.slice(0, eq);
    if (!(key in out)) out[key] = eq === -1 ? "" : pair.slice(eq + 1);
  }
  return out;
}

/**
 * Real AuthnRequests are a few KB. The inflated size is capped while streaming
 * (a deflate bomb never finishes buffering), and the same cap is enforced at
 * the top of parseAuthnRequestXml before the DOMParser does any superlinear work.
 */
const MAX_INFLATED_BYTES = 64 * 1024;

/** base64 + raw DEFLATE, the HTTP-Redirect binding's encoding. Output is capped. */
export async function inflateAuthnRequest(encoded: string): Promise<string> {
  let bytes: Uint8Array;
  try {
    bytes = b64decode(encoded);
  } catch {
    throw new AuthnRequestError("SAMLRequest is not valid base64.");
  }
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_INFLATED_BYTES) throw new AuthnRequestError("SAMLRequest inflates beyond the size limit.");
      chunks.push(value);
    }
  } catch (err) {
    if (err instanceof AuthnRequestError) throw err;
    throw new AuthnRequestError("SAMLRequest is not a deflated message.");
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(out);
}

/**
 * Reads an AuthnRequest out of a parsed document.
 *
 * Parsing foreign XML is safe; *verifying signatures over* it is not, and we
 * never do - see SAML-implementation.md section 3. The DOCTYPE rejection is
 * belt-and-braces: @xmldom does not resolve external entities, but a document
 * that asks us to has no business being here.
 */
export function parseAuthnRequestXml(xml: string): ParsedAuthnRequest {
  if (xml.length > MAX_INFLATED_BYTES) {
    throw new AuthnRequestError("SAMLRequest exceeds the size limit.");
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    throw new AuthnRequestError("The request contains a DOCTYPE or entity declaration.");
  }

  let doc: ReturnType<DOMParser["parseFromString"]>;
  try {
    doc = new DOMParser().parseFromString(xml, "text/xml");
  } catch {
    throw new AuthnRequestError("SAMLRequest is not well-formed XML.");
  }
  const root = doc.documentElement;
  if (!root || root.localName !== "AuthnRequest" || root.namespaceURI !== NS_SAMLP) {
    throw new AuthnRequestError("The message is not a samlp:AuthnRequest.");
  }
  if (root.getAttribute("Version") !== "2.0") {
    throw new AuthnRequestError("Only SAML 2.0 requests are supported.");
  }

  const binding = root.getAttribute("ProtocolBinding");
  if (binding && binding !== BINDING_HTTP_POST) {
    throw new AuthnRequestError("Only the HTTP-POST response binding is supported.");
  }

  const id = root.getAttribute("ID");
  if (!id) throw new AuthnRequestError("The AuthnRequest has no ID.");

  const issuerEls = root.getElementsByTagNameNS(NS_SAML, "Issuer");
  const issuer = issuerEls.length > 0 ? issuerEls[0]!.textContent?.trim() ?? "" : "";
  if (!issuer) throw new AuthnRequestError("The AuthnRequest has no Issuer.");

  const policyEls = root.getElementsByTagNameNS(NS_SAMLP, "NameIDPolicy");

  return {
    id,
    issuer,
    acsUrl: root.getAttribute("AssertionConsumerServiceURL")?.trim() || null,
    forceAuthn: ["true", "1"].includes((root.getAttribute("ForceAuthn") ?? "").trim()),
    nameIdFormat: policyEls.length > 0 ? policyEls[0]!.getAttribute("Format") : null,
    destination: root.getAttribute("Destination")?.trim() || null,
  };
}

export type SignatureCheck = "unsigned" | "ok" | "bad" | "unsupported-alg" | "no-key";

/**
 * Verifies an HTTP-Redirect-binding signature against every certificate the
 * SP has registered (any may be valid during rollover - [SDP-IDP32]).
 *
 * The signed content is the raw, ordered, still-encoded query string
 * `SAMLRequest=..&RelayState=..&SigAlg=..` - no XML involved. This is the only
 * signature verification FlareID performs; embedded XML signatures in a
 * POSTed AuthnRequest are rejected at the route, not verified.
 */
export async function verifyRedirectSignature(sp: SamlServiceProviderRow, raw: Record<string, string>): Promise<SignatureCheck> {
  if (!raw.Signature) return "unsigned";
  if (!raw.SigAlg) return "bad";

  let sigAlg: string;
  try {
    sigAlg = decodeURIComponent(raw.SigAlg);
  } catch {
    return "bad";
  }
  if (sigAlg !== SIGALG_RSA_SHA256) return "unsupported-alg";

  const certs = spSigningCerts(sp);
  if (certs.length === 0) return "no-key";

  const signedContent =
    `SAMLRequest=${raw.SAMLRequest}` +
    (raw.RelayState !== undefined ? `&RelayState=${raw.RelayState}` : "") +
    `&SigAlg=${raw.SigAlg}`;

  let signature: Uint8Array;
  try {
    signature = b64decode(decodeURIComponent(raw.Signature));
  } catch {
    return "bad";
  }

  const data = new TextEncoder().encode(signedContent);
  for (const pem of certs) {
    const key = await certToVerifyKey(pem);
    if (key && (await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature as BufferSource, data))) {
      return "ok";
    }
  }
  return "bad";
}

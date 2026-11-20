import { X509Certificate } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import type { SamlServiceProviderRow } from "../types.js";
import { b64decode } from "./xml.js";
import { certToVerifyKey } from "./x509.js";
import { spSigningCerts } from "./service-providers.js";

export const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
export const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const SIGALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

export class AuthnRequestError extends Error {}

export interface ParsedAuthnRequest {
  id: string;
  /** The SP's entityID - the <saml:Issuer> of the request. */
  issuer: string;
  acsUrl: string | null;
  forceAuthn: boolean;
  isPassive: boolean;
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
    isPassive: ["true", "1"].includes((root.getAttribute("IsPassive") ?? "").trim()),
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

/** base64 only - the HTTP-POST binding delivers the XML uncompressed in a form field. */
export function decodePostAuthnRequest(encoded: string): string {
  try {
    return new TextDecoder().decode(b64decode(encoded));
  } catch {
    throw new AuthnRequestError("SAMLRequest is not valid base64.");
  }
}

const OK_TRANSFORMS = new Set([
  "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
  "http://www.w3.org/2001/10/xml-exc-c14n#",
  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
]);
const OK_C14N = new Set([
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
  "http://www.w3.org/2001/10/xml-exc-c14n#",
  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
]);
const OK_POST_SIGALGS = new Set([
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
]);
const OK_POST_DIGESTS = new Set([
  "http://www.w3.org/2001/04/xmlenc#sha256",
  "http://www.w3.org/2001/04/xmldsig-more#sha384",
  "http://www.w3.org/2001/04/xmldsig-more#sha512",
]);

/**
 * xml-crypto resolves SignatureMethod, DigestMethod, Transform and friends
 * by local-name under ANY namespace, first in document order - the ds-only
 * getElementsByTagNameNS allowlist reads in verifyPostSignature would never
 * see a decoy like <x:SignatureMethod Algorithm="...rsa-sha1"> that the
 * verifier would honour. So any element inside the Signature subtree named
 * like a security-relevant dsig node but living outside the xmldsig
 * namespace is a decoy, never data: reject it.
 */
const DS_SENSITIVE_LOCALNAMES = new Set([
  "Signature",
  "SignedInfo",
  "CanonicalizationMethod",
  "SignatureMethod",
  "SignatureValue",
  "KeyInfo",
  "Object",
  "Manifest",
  "SignatureProperties",
  "Reference",
  "Transforms",
  "Transform",
  "DigestMethod",
  "DigestValue",
]);

/**
 * xml-crypto ships no ECDSA signature algorithm, so the ecdsa-sha* entries in
 * OK_POST_SIGALGS are verified through this implementation registered on each
 * SignedXml instance. XML-DSig carries the raw r||s signature value - exactly
 * the IEEE-P1363 format crypto.subtle.verify expects - and the pinned
 * certificate supplies the key: KeyInfo in the message is never consulted.
 * Verification only; POST-bound requests are received, never generated.
 */
class EcdsaVerifier {
  constructor(
    private readonly alg: string,
    private readonly namedCurve: string,
    private readonly hash: string,
  ) {}
  getAlgorithmName() {
    return this.alg;
  }
  getSignature(): string {
    throw new Error("ECDSA signing is not supported");
  }
  verifySignature(): boolean {
    throw new Error("ECDSA verification is asynchronous");
  }
  async verifySignatureAsync(material: string, key: unknown, signatureValue: string): Promise<boolean> {
    try {
      const spki = new X509Certificate(String(key)).publicKey.export({ format: "der", type: "spki" });
      const pub = await crypto.subtle.importKey(
        "spki",
        new Uint8Array(spki),
        { name: "ECDSA", namedCurve: this.namedCurve },
        false,
        ["verify"],
      );
      const sig = Uint8Array.from(atob(signatureValue.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
      return await crypto.subtle.verify(
        { name: "ECDSA", hash: this.hash },
        pub,
        sig,
        new TextEncoder().encode(material),
      );
    } catch {
      return false;
    }
  }
}

const ECDSA_SIGALGS: Record<string, { namedCurve: string; hash: string }> = {
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": { namedCurve: "P-256", hash: "SHA-256" },
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": { namedCurve: "P-384", hash: "SHA-384" },
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": { namedCurve: "P-521", hash: "SHA-512" },
};

const ecdsaAlg = (alg: string, namedCurve: string, hash: string) =>
  class extends EcdsaVerifier {
    constructor() {
      super(alg, namedCurve, hash);
    }
  };

/**
 * Verifies the embedded XML-DSig of a POST-binding AuthnRequest.
 *
 * This is the only place FlareID verifies a signature over foreign XML - the
 * XSW hardening from SAML-implementation.md section 4, applied in order:
 *
 * - exactly one <ds:Signature>, a direct child of the signed document element,
 *   containing no dsig-named element in any other namespace (xml-crypto
 *   resolves those by local-name, so one would shadow the checked ds: node)
 * - one <ds:Reference>, an ID-only URI resolving to the document element's ID
 * - no second element anywhere carrying the referenced ID value
 * - no element carrying security meaning outside the signed subtree (with the
 *   root as the signed node, that means no second AuthnRequest and no Assertion)
 * - Transforms limited to enveloped-signature and (exclusive) C14N; anything
 *   else - including a second, unexpected transform - is rejected
 * - verification is pinned to the SP's registered certificates; KeyInfo inside
 *   the message is never consulted for key material
 */
export async function verifyPostSignature(sp: SamlServiceProviderRow, xml: string, request: ParsedAuthnRequest): Promise<SignatureCheck> {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const root = doc.documentElement;
  const sigEls = doc.getElementsByTagNameNS(NS_DS, "Signature");
  if (sigEls.length === 0) return "unsigned";

  if (sigEls.length !== 1 || sigEls[0]!.parentNode !== root) return "bad";
  const sigEl = sigEls[0]!;

  for (const el of Array.from(sigEl.getElementsByTagName("*"))) {
    if (el.namespaceURI !== NS_DS && DS_SENSITIVE_LOCALNAMES.has(el.localName ?? "")) return "bad";
  }

  const sigAlg = sigEl.getElementsByTagNameNS(NS_DS, "SignatureMethod")[0]?.getAttribute("Algorithm") ?? "";
  if (!OK_POST_SIGALGS.has(sigAlg)) return "unsupported-alg";
  const c14nAlg = sigEl.getElementsByTagNameNS(NS_DS, "CanonicalizationMethod")[0]?.getAttribute("Algorithm") ?? "";
  if (!OK_C14N.has(c14nAlg)) return "bad";

  const refs = sigEl.getElementsByTagNameNS(NS_DS, "Reference");
  if (refs.length !== 1) return "bad";
  if ((refs[0]!.getAttribute("URI") ?? "") !== `#${request.id}`) return "bad";
  const digestAlg = refs[0]!.getElementsByTagNameNS(NS_DS, "DigestMethod")[0]?.getAttribute("Algorithm") ?? "";
  if (!OK_POST_DIGESTS.has(digestAlg)) return "unsupported-alg";
  const transforms = Array.from(refs[0]!.getElementsByTagNameNS(NS_DS, "Transform")).map((t) => t.getAttribute("Algorithm") ?? "");
  if (transforms.some((t) => !OK_TRANSFORMS.has(t))) return "bad";

  let idCount = 0;
  for (const node of Array.from(doc.getElementsByTagName("*"))) {
    if (["ID", "Id", "id"].some((attr) => node.getAttribute(attr) === request.id)) idCount++;
  }
  if (idCount !== 1) return "bad";
  if (doc.getElementsByTagNameNS(NS_SAMLP, "AuthnRequest").length !== 1) return "bad";
  if (doc.getElementsByTagNameNS(NS_SAML, "Assertion").length !== 0) return "bad";

  const certs = spSigningCerts(sp);
  if (certs.length === 0) return "no-key";
  for (const pem of certs) {
    const sig = new SignedXml({ publicCert: pem, getCertFromKeyInfo: () => null });
    for (const [alg, params] of Object.entries(ECDSA_SIGALGS)) {
      sig.SignatureAlgorithms[alg] = ecdsaAlg(alg, params.namedCurve, params.hash);
    }
    try {
      sig.loadSignature(sigEl.toString());
      if (await sig.checkSignatureAsync(xml)) return "ok";
    } catch {
      // A cert that cannot even load this signature moves to the next candidate.
    }
  }
  return "bad";
}

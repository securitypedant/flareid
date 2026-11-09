import { DOMParser } from "@xmldom/xmldom";
import { normalizeCertPem } from "./x509.js";

const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const MAX_METADATA_BYTES = 256 * 1024;

export class SpMetadataError extends Error {}

export interface ParsedSpMetadata {
  entityId: string;
  acsUrls: string[];
  defaultAcsUrl: string | null;
  signingCerts: string[];
  encryptionCert: string | null;
  sloUrl: string | null;
  nameIdFormat: "transient" | "persistent" | "emailAddress" | null;
  wantAuthnRequestsSigned: boolean;
}

/**
 * Reads an SP's <md:EntityDescriptor> into the fields FlareID's SP registry
 * stores. Metadata is configuration an administrator pasted in, not a signed
 * message, so it is parsed but not signature-checked - the administrator is
 * the trust decision. DOCTYPE/entities are refused, and the size is capped.
 */
export function parseSpMetadata(xml: string): ParsedSpMetadata {
  if (xml.length > MAX_METADATA_BYTES) throw new SpMetadataError("Metadata is larger than 256 KB.");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new SpMetadataError("Metadata must not contain a DOCTYPE or entity declarations.");
  let doc: ReturnType<DOMParser["parseFromString"]>;
  try {
    doc = new DOMParser().parseFromString(xml, "text/xml");
  } catch {
    throw new SpMetadataError("Metadata is not well-formed XML.");
  }
  const root = doc.documentElement;
  const entity =
    root?.localName === "EntityDescriptor" && root.namespaceURI === NS_MD ? root : (root?.getElementsByTagNameNS(NS_MD, "EntityDescriptor")[0] ?? null);
  if (!entity) throw new SpMetadataError("No md:EntityDescriptor found.");
  const entityId = entity.getAttribute("entityID")?.trim() ?? "";
  if (!entityId) throw new SpMetadataError("The EntityDescriptor has no entityID.");
  const sp = entity.getElementsByTagNameNS(NS_MD, "SPSSODescriptor")[0];
  if (!sp) throw new SpMetadataError("No md:SPSSODescriptor: this is not service provider metadata.");

  const acs = Array.from(sp.getElementsByTagNameNS(NS_MD, "AssertionConsumerService"))
    .filter((e) => e.getAttribute("Binding") === BINDING_POST)
    .sort((a, b) => Number(a.getAttribute("index") ?? 0) - Number(b.getAttribute("index") ?? 0));
  const acsUrls = acs.map((e) => e.getAttribute("Location")?.trim() ?? "").filter((u) => /^https?:\/\//.test(u));
  if (acsUrls.length === 0) throw new SpMetadataError("No AssertionConsumerService with the HTTP-POST binding.");
  const defaultAcs = acs.find((e) => e.getAttribute("isDefault") === "true")?.getAttribute("Location")?.trim() ?? null;

  const certs = (use: string) =>
    Array.from(sp.getElementsByTagNameNS(NS_MD, "KeyDescriptor"))
      .filter((k) => !k.getAttribute("use") || k.getAttribute("use") === use)
      .flatMap((k) => Array.from(k.getElementsByTagNameNS(NS_DS, "X509Certificate")))
      .map((c) => normalizeCertPem(c.textContent ?? ""))
      .filter((p): p is string => p !== null);

  const slo = Array.from(sp.getElementsByTagNameNS(NS_MD, "SingleLogoutService")).find((e) => e.getAttribute("Binding") === BINDING_REDIRECT);
  const formats = Array.from(sp.getElementsByTagNameNS(NS_MD, "NameIDFormat")).map((e) => e.textContent?.trim() ?? "");
  const nameIdFormat = formats.some((f) => f.endsWith(":emailAddress"))
    ? "emailAddress"
    : formats.some((f) => f.endsWith(":persistent"))
      ? "persistent"
      : formats.some((f) => f.endsWith(":transient"))
        ? "transient"
        : null;

  return {
    entityId,
    acsUrls,
    defaultAcsUrl: defaultAcs,
    signingCerts: [...new Set(certs("signing"))],
    encryptionCert: certs("encryption")[0] ?? null,
    sloUrl: slo?.getAttribute("Location")?.trim() || null,
    nameIdFormat,
    wantAuthnRequestsSigned: sp.getAttribute("AuthnRequestsSigned") === "true",
  };
}

import type { Env } from "../../env.js";
import { el, escapeXmlText } from "./xml.js";
import { idpCertBase64 } from "./sign.js";
import { idpEntityId, NS_SAMLP } from "./messages.js";

const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const NS_SHIBMD = "urn:mace:shibboleth:metadata:1.0";
const NS_MDUI = "urn:oasis:names:tc:SAML:metadata:ui";
const BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/**
 * The IdP's EntityDescriptor, served at /saml/metadata.
 *
 * Deliberately not signed: a service provider that fetches it over verified
 * HTTPS has what saml2int [SDP-MD02] requires, and a signature would only add
 * a second trust path to maintain. Only the HTTP-Redirect SSO endpoint is
 * advertised - metadata must not offer the POST binding we reject.
 */
export interface IdpMetadataExtras {
  /** UPN domains, published as shibmd:Scope (the scopes of subject-id/pairwise-id). */
  scopes: string[];
  /** Technical contact address (the configured From address), if any. */
  contactEmail?: string | null;
}

/** How long an SP may rely on a fetched copy (saml2int: metadata carries validUntil). */
const METADATA_VALID_DAYS = 7;

export function idpMetadataXml(env: Env, appName: string, extras: IdpMetadataExtras = { scopes: [] }): string {
  const entityId = idpEntityId(env);

  const extensions = el(
    "md:Extensions",
    {},
    extras.scopes.map((s) => el("shibmd:Scope", { "xmlns:shibmd": NS_SHIBMD, regexp: "false" }, escapeXmlText(s))).join("") +
      el("mdui:UIInfo", { "xmlns:mdui": NS_MDUI }, el("mdui:DisplayName", { "xml:lang": "en" }, escapeXmlText(appName)))
  );

  const descriptor = el(
    "md:IDPSSODescriptor",
    { protocolSupportEnumeration: NS_SAMLP },
    extensions +
    el(
      "md:KeyDescriptor",
      { use: "signing" },
      el(
        "ds:KeyInfo",
        { "xmlns:ds": NS_DS },
        el("ds:X509Data", {}, el("ds:X509Certificate", {}, idpCertBase64(env)))
      )
    ) +
      el("md:SingleLogoutService", { Binding: BINDING_REDIRECT, Location: `${entityId}/saml/slo` }) +
      el("md:NameIDFormat", {}, NAMEID_TRANSIENT) +
      el("md:NameIDFormat", {}, NAMEID_EMAIL) +
      el("md:NameIDFormat", {}, NAMEID_PERSISTENT) +
      el("md:SingleSignOnService", {
        Binding: BINDING_REDIRECT,
        Location: `${entityId}/saml/sso`,
      })
  );

  const org =
    el("md:Organization", {},
      el("md:OrganizationName", { "xml:lang": "en" }, escapeXmlText(appName)) +
      el("md:OrganizationDisplayName", { "xml:lang": "en" }, escapeXmlText(appName)) +
      el("md:OrganizationURL", { "xml:lang": "en" }, escapeXmlText(entityId))
    );

  const contact = extras.contactEmail
    ? el("md:ContactPerson", { contactType: "technical" },
        el("md:GivenName", {}, escapeXmlText(`${appName} administrators`)) + el("md:EmailAddress", {}, escapeXmlText(`mailto:${extras.contactEmail}`)))
    : "";

  const validUntil = new Date(Date.now() + METADATA_VALID_DAYS * 24 * 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  return el("md:EntityDescriptor", { "xmlns:md": NS_MD, entityID: entityId, validUntil, cacheDuration: "PT6H" }, descriptor + org + contact);
}

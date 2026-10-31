import type { Env } from "../../env.js";
import { el, escapeXmlText } from "./xml.js";
import { idpCertBase64 } from "./sign.js";
import { idpEntityId, NS_SAMLP } from "./messages.js";

const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
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
export function idpMetadataXml(env: Env, appName: string): string {
  const entityId = idpEntityId(env);

  const descriptor = el(
    "md:IDPSSODescriptor",
    { protocolSupportEnumeration: NS_SAMLP },
    el(
      "md:KeyDescriptor",
      { use: "signing" },
      el(
        "ds:KeyInfo",
        { "xmlns:ds": NS_DS },
        el("ds:X509Data", {}, el("ds:X509Certificate", {}, idpCertBase64(env)))
      )
    ) +
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

  return el("md:EntityDescriptor", { "xmlns:md": NS_MD, entityID: entityId }, descriptor + org);
}

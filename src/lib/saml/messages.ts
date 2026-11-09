import { encryptAssertion } from "./encrypt.js";
import type { Env } from "../../env.js";
import type { SamlServiceProviderRow, UserRow } from "../types.js";
import { sha256Hex } from "../tokens.js";
import { el, escapeXmlText, samlId, samlInstant } from "./xml.js";
import { insertSignatureAfterIssuer, signSubtree } from "./sign.js";
import { resolveAttributes } from "./attributes.js";

export const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
export const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

const NAMEID_FORMAT_URIS: Record<string, string> = {
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
};

const NAMEID_FORMAT_NAMES = Object.keys(NAMEID_FORMAT_URIS);
const AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const ATTR_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/** The IdP's entityID - the issuer URL, the same thing OIDC already identifies this deployment by. */
export function idpEntityId(env: Env): string {
  return env.ISSUER_URL;
}

export function supportedNameIdFormats(): string[] {
  return NAMEID_FORMAT_NAMES;
}

export function nameIdFormatUri(format: string): string | null {
  return NAMEID_FORMAT_URIS[format] ?? null;
}

export interface IssueParams {
  sp: SamlServiceProviderRow;
  user: UserRow;
  /** The AuthnRequest's ID - echoed as InResponseTo. */
  requestId: string;
  /** The allowlisted AssertionConsumerService URL this response is for. */
  acsUrl: string;
  /** The FlareID session row id - never embedded raw (it is the session cookie). */
  sessionId: string;
  /** When authentication actually happened: session creation for SSO, now for a fresh login. */
  authnInstant: Date;
}

const ASSERTION_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 60 * 1000;

/**
 * The transient NameID and SessionIndex.
 *
 * Both derive from the session id, but *hashed* - the raw id is the session
 * cookie itself, a bearer credential for /account and /admin, and it must
 * never appear in a document handed to a third party. Hashing keeps the value
 * opaque while staying stable across assertions within one session, which is
 * what Single Logout will later match a LogoutRequest against.
 */
async function sessionIdentifiers(sessionId: string): Promise<{ nameId: string; sessionIndex: string }> {
  const hash = await sha256Hex(sessionId);
  return { nameId: `_${hash}`, sessionIndex: `_${hash}` };
}

function attributeStatement(attributes: { name: string; values: string[] }[]): string {
  const inner = attributes
    .map((a) =>
      el(
        "saml:Attribute",
        { Name: a.name, NameFormat: ATTR_NAME_FORMAT },
        a.values.map((v) => el("saml:AttributeValue", {}, escapeXmlText(v))).join("")
      )
    )
    .join("");
  return el("saml:AttributeStatement", {}, inner);
}

async function nameId(env: Env, sp: SamlServiceProviderRow, user: UserRow, sessionId: string): Promise<{ format: string; value: string }> {
  const format = NAMEID_FORMAT_URIS[sp.nameid_format] ? sp.nameid_format : "transient";
  if (format === "emailAddress") return { format: NAMEID_FORMAT_URIS[format]!, value: user.upn };
  if (format === "persistent") return { format: NAMEID_FORMAT_URIS[format]!, value: user.external_id };
  const { nameId } = await sessionIdentifiers(sessionId);
  return { format: NAMEID_FORMAT_URIS[format]!, value: nameId };
}

async function buildAssertion(env: Env, p: IssueParams): Promise<string> {
  const { sp, user, requestId, acsUrl, sessionId, authnInstant } = p;
  const assertionId = samlId();
  const issueInstant = samlInstant(new Date());
  const notBefore = samlInstant(new Date(Date.now() - CLOCK_SKEW_MS));
  const notOnOrAfter = samlInstant(new Date(Date.now() + ASSERTION_TTL_MS));
  const { sessionIndex } = await sessionIdentifiers(sessionId);
  const nid = await nameId(env, sp, user, sessionId);
  const attributes = await resolveAttributes(env, sp, user);

  const inner =
    el("saml:Issuer", {}, escapeXmlText(idpEntityId(env))) +
    el(
      "saml:Subject",
      {},
      el("saml:NameID", { Format: nid.format }, escapeXmlText(nid.value)) +
        el(
          "saml:SubjectConfirmation",
          { Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer" },
          el("saml:SubjectConfirmationData", {
            InResponseTo: requestId,
            NotOnOrAfter: notOnOrAfter,
            Recipient: acsUrl,
          })
        )
    ) +
    el(
      "saml:Conditions",
      { NotBefore: notBefore, NotOnOrAfter: notOnOrAfter },
      el("saml:AudienceRestriction", {}, el("saml:Audience", {}, escapeXmlText(sp.entity_id)))
    ) +
    el(
      "saml:AuthnStatement",
      { AuthnInstant: samlInstant(authnInstant), SessionIndex: sessionIndex },
      el("saml:AuthnContext", {}, el("saml:AuthnContextClassRef", {}, escapeXmlText(AUTHN_CONTEXT)))
    ) +
    (attributes.length > 0 ? attributeStatement(attributes) : "");

  const unsigned = el(
    "saml:Assertion",
    { "xmlns:saml": NS_SAML, ID: assertionId, IssueInstant: issueInstant, Version: "2.0" },
    inner
  );

  const finished = sp.sign_assertion ? insertSignatureAfterIssuer(unsigned, await signSubtree(env, unsigned, assertionId)) : unsigned;
  // Sign, then encrypt: the SP decrypts and then verifies the assertion's own signature.
  if (sp.encrypt_assertions && sp.encryption_cert) return encryptAssertion(finished, sp.encryption_cert);
  return finished;
}

/**
 * Builds the signed <samlp:Response> for a successful authentication.
 *
 * Both the Assertion and the Response are signed when the SP's flags ask for
 * it (the saml2int [SDP-IDP10] posture): each subtree is emitted canonical and
 * unsigned, digested, signed, then the <ds:Signature> is spliced in after the
 * Issuer - see sign.ts.
 */
export async function buildSignedResponse(env: Env, p: IssueParams): Promise<string> {
  const responseId = samlId();
  const assertionXml = await buildAssertion(env, p);

  const inner =
    el("saml:Issuer", {}, escapeXmlText(idpEntityId(env))) +
    el(
      "samlp:Status",
      {},
      el("samlp:StatusCode", { Value: "urn:oasis:names:tc:SAML:2.0:status:Success" })
    ) +
    assertionXml;

  const unsigned = el(
    "samlp:Response",
    {
      "xmlns:saml": NS_SAML,
      "xmlns:samlp": NS_SAMLP,
      Destination: p.acsUrl,
      ID: responseId,
      InResponseTo: p.requestId,
      IssueInstant: samlInstant(new Date()),
      Version: "2.0",
    },
    inner
  );

  if (!p.sp.sign_response) return unsigned;
  return insertSignatureAfterIssuer(unsigned, await signSubtree(env, unsigned, responseId));
}

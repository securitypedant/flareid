import { encryptAssertion } from "./encrypt.js";
import { spEncryptionPolicy, spOmitsNameId } from "./service-providers.js";
import { getDisabledAlgorithms } from "../settings.js";
import type { Env } from "../../env.js";
import type { SamlServiceProviderRow, UserRow } from "../types.js";
import { sha256Hex } from "../tokens.js";
import { el, escapeXmlText, samlId, samlInstant } from "./xml.js";
import { insertSignatureAfterIssuer, signSubtree } from "./sign.js";
import { resolveAttributes, type ResolvedAttribute } from "./attributes.js";

export const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
export const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

export const NAMEID_FORMAT_URIS: Record<string, string> = {
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  emailAddress: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
};

/** URI -> short name, for resolving a NameIDPolicy/@Format into something nameId() can emit. */
export const NAMEID_FORMAT_BY_URI: Record<string, string> = Object.fromEntries(
  Object.entries(NAMEID_FORMAT_URIS).map(([name, uri]) => [uri, name])
);

const NAMEID_FORMAT_NAMES = Object.keys(NAMEID_FORMAT_URIS);
/** The only AuthnContextClassRef this IdP ever asserts - the comparison matrix in saml.ts is built on it. */
export const AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const ATTR_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/** The IdP's entityID - the issuer URL, the same thing OIDC already identifies this deployment by. */
export function idpEntityId(env: Env): string {
  return env.ISSUER_URL;
}

export function supportedNameIdFormats(): string[] {
  return NAMEID_FORMAT_NAMES;
}

/** The Format URIs the responder can actually produce - a NameIDPolicy naming anything else gets InvalidNameIDPolicy. */
export function supportedNameIdFormatUris(): string[] {
  return Object.values(NAMEID_FORMAT_URIS);
}

export function nameIdFormatUri(format: string): string | null {
  return NAMEID_FORMAT_URIS[format] ?? null;
}

export interface IssueParams {
  sp: SamlServiceProviderRow;
  user: UserRow;
  /** The AuthnRequest's ID - echoed as InResponseTo. NULL for IdP-initiated (unsolicited) responses. */
  requestId: string | null;
  /** The allowlisted AssertionConsumerService URL this response is for. */
  acsUrl: string;
  /** The FlareID session row id - never embedded raw (it is the session cookie). */
  sessionId: string;
  /** When authentication actually happened: session creation for SSO, now for a fresh login. */
  authnInstant: Date;
  /** The request's NameIDPolicy (validated in saml.ts): a Format URI we support, the SP namespace, and the SP-chosen persistent value. */
  nameIdFormat?: string | null;
  nameIdSpNameQualifier?: string | null;
  nameIdSpProvidedId?: string | null;
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
 * what Single Logout will later match a LogoutRequest against. The entity id
 * salts the hash so two service providers cannot correlate the pseudonym and
 * link one user's sessions - the pairwise guarantee OIDC's sid already gives.
 */
export async function sessionIdentifiers(sessionId: string, entityId: string): Promise<{ nameId: string; sessionIndex: string }> {
  const hash = await sha256Hex(`${sessionId}|${entityId}`);
  return { nameId: `_${hash}`, sessionIndex: `_${hash}` };
}

function attributeStatement(attributes: ResolvedAttribute[]): string {
  const inner = attributes
    .map((a) =>
      el(
        "saml:Attribute",
        { Name: a.name, NameFormat: a.nameFormat ?? ATTR_NAME_FORMAT },
        a.values.map((v) => el("saml:AttributeValue", {}, escapeXmlText(v))).join("")
      )
    )
    .join("");
  return el("saml:AttributeStatement", {}, inner);
}

async function nameId(
  env: Env,
  sp: SamlServiceProviderRow,
  user: UserRow,
  sessionId: string,
  req?: { format?: string | null; spNameQualifier?: string | null; spProvidedId?: string | null }
): Promise<{ format: string; value: string; spNameQualifier?: string }> {
  // An explicit NameIDPolicy/@Format overrides the SP's configured default:
  // SAML Core 3.4.1.4 requires the returned identifier to conform to the
  // accepted policy (unsupported formats are refused earlier, in saml.ts).
  const requested = req?.format ? NAMEID_FORMAT_BY_URI[req.format] : undefined;
  const format = requested ?? (NAMEID_FORMAT_URIS[sp.nameid_format] ? sp.nameid_format : "transient");
  const out: { format: string; value: string; spNameQualifier?: string } = {
    format: NAMEID_FORMAT_URIS[format]!,
    value: "",
    spNameQualifier: req?.spNameQualifier ?? undefined,
  };
  if (format === "emailAddress") {
    out.value = user.upn;
  } else if (format === "persistent") {
    // SPProvidedID is the SP's own choice of persistent value (Core 3.4.1.1).
    out.value = req?.spProvidedId ?? user.external_id;
  } else {
    out.value = (await sessionIdentifiers(sessionId, sp.entity_id)).nameId;
  }
  return out;
}

async function buildAssertion(env: Env, p: IssueParams): Promise<string> {
  const { sp, user, requestId, acsUrl, sessionId, authnInstant } = p;
  const assertionId = samlId();
  const issueInstant = samlInstant(new Date());
  const notBefore = samlInstant(new Date(Date.now() - CLOCK_SKEW_MS));
  const notOnOrAfter = samlInstant(new Date(Date.now() + ASSERTION_TTL_MS));
  const { sessionIndex } = await sessionIdentifiers(sessionId, sp.entity_id);
  // nameid_format "none" (IIP-IDP11): the Subject carries only
  // SubjectConfirmation - no <saml:NameID> element at all.
  const nid = spOmitsNameId(sp)
    ? null
    : await nameId(env, sp, user, sessionId, {
        format: p.nameIdFormat,
        spNameQualifier: p.nameIdSpNameQualifier,
        spProvidedId: p.nameIdSpProvidedId,
      });
  const attributes = await resolveAttributes(env, sp, user);

  const inner =
    el("saml:Issuer", {}, escapeXmlText(idpEntityId(env))) +
    el(
      "saml:Subject",
      {},
      (nid ? el("saml:NameID", { Format: nid.format, SPNameQualifier: nid.spNameQualifier }, escapeXmlText(nid.value)) : "") +
        el(
          "saml:SubjectConfirmation",
          { Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer" },
          el("saml:SubjectConfirmationData", {
            InResponseTo: requestId ?? undefined,
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
  // The wrapped key names its Recipient - the ACS endpoint the whole response is destined for.
  if (sp.encrypt_assertions && sp.encryption_cert) return encryptAssertion(finished, sp.encryption_cert, spEncryptionPolicy(sp, await getDisabledAlgorithms(env)), acsUrl);
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

  // xmlns:saml belongs on the Issuer, not the Response apex: exclusive C14N
  // renders a namespace on the first element that visibly uses the prefix,
  // so this is where the verifier's canonical form puts it.
  const inner =
    el("saml:Issuer", { "xmlns:saml": NS_SAML }, escapeXmlText(idpEntityId(env))) +
    el(
      "samlp:Status",
      {},
      el("samlp:StatusCode", { Value: "urn:oasis:names:tc:SAML:2.0:status:Success" })
    ) +
    assertionXml;

  const unsigned = el(
    "samlp:Response",
    {
      "xmlns:samlp": NS_SAMLP,
      Destination: p.acsUrl,
      ID: responseId,
      InResponseTo: p.requestId ?? undefined,
      IssueInstant: samlInstant(new Date()),
      Version: "2.0",
    },
    inner
  );

  if (!p.sp.sign_response) return unsigned;
  return insertSignatureAfterIssuer(unsigned, await signSubtree(env, unsigned, responseId));
}

/**
 * A signed <samlp:Response> carrying a SAML error status instead of an
 * assertion - the protocol-level rejection an SP expects when its
 * AuthnRequest itself cannot be honored (bad signature, required signature
 * missing). Top-level Responder (the IdP cannot fulfill the request) with a
 * second-level RequestDenied, the profile-preferred pair for a refused
 * authentication. Always signed: an unsigned error invites downgrade.
 */
export async function buildErrorResponse(env: Env, p: { acsUrl: string; requestId: string | null; statusDetail?: string }): Promise<string> {
  const responseId = samlId();
  const detail = p.statusDetail ?? "RequestDenied";
  const inner =
    el("saml:Issuer", { "xmlns:saml": NS_SAML }, escapeXmlText(idpEntityId(env))) +
    el(
      "samlp:Status",
      {},
      el(
        "samlp:StatusCode",
        { Value: "urn:oasis:names:tc:SAML:2.0:status:Responder" },
        el("samlp:StatusCode", { Value: `urn:oasis:names:tc:SAML:2.0:status:${detail}` })
      )
    );

  const unsigned = el(
    "samlp:Response",
    {
      "xmlns:samlp": NS_SAMLP,
      Destination: p.acsUrl,
      ID: responseId,
      InResponseTo: p.requestId ?? undefined,
      IssueInstant: samlInstant(new Date()),
      Version: "2.0",
    },
    inner
  );
  return insertSignatureAfterIssuer(unsigned, await signSubtree(env, unsigned, responseId));
}

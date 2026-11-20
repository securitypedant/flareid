import { canSignIn } from "../lib/admin-roles.js";
import { isConsumed, markConsumed } from "../lib/one-shot.js";
import { secondFactorGate } from "../lib/auth-policy.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { appConfigError, AUTH_MESSAGES, loginAppearance, msg, renderAuthMessage, sendLoginForm, type AuthMessage } from "../lib/login-views.js";
import { deleteLoginFlow, getFlowBinding, getLoginFlow, sealLoginFlow, storeLoginFlow, type PendingSamlRequest } from "../lib/authorize-state.js";
import { getSession } from "../lib/sessions.js";
import { getUserById } from "../lib/db.js";
import { isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { logAudit } from "../lib/audit.js";
import { b64encode } from "../lib/saml/xml.js";
import { isSamlConfigured } from "../lib/saml/sign.js";
import { idpMetadataXml } from "../lib/saml/metadata.js";
import { samlPostForm } from "../lib/saml/post-form.js";
import { buildErrorResponse, buildSignedResponse, idpEntityId } from "../lib/saml/messages.js";
import {
  AuthnRequestError,
  decodePostAuthnRequest,
  inflateAuthnRequest,
  parseAuthnRequestXml,
  rawQueryParams,
  verifyPostSignature,
  verifyRedirectSignature,
  type ParsedAuthnRequest,
  type SignatureCheck,
} from "../lib/saml/authn-request.js";
import { getSpByEntityId, getSpById, resolveAcsUrl, spAcsUrls } from "../lib/saml/service-providers.js";
import type { SamlServiceProviderRow, UserRow } from "../lib/types.js";

export const saml = new Hono<{ Bindings: Env }>();

const REQUEST_ID_TTL_SECONDS = 600;

const ALREADY_ANSWERED: AuthMessage = {
  title: msg("msg.alreadyAnswered.title"),
  message: msg("msg.alreadyAnswered.message"),
  action: null,
};

/**
 * Issues the signed response and returns the fields for the auto-POST form.
 *
 * Shared by both entry points: the SSO path (existing session answers the
 * AuthnRequest directly) and the end of the login flow (login.ts calls this
 * once authentication completes).
 */
export async function issueSamlResponse(
  env: Env,
  sp: SamlServiceProviderRow,
  request: PendingSamlRequest,
  user: UserRow,
  sessionId: string,
  authnInstant: Date
): Promise<{ acsUrl: string; samlResponse: string; relayState: string | null } | null> {
  // Single-use, enforced here rather than when the request arrives: marking at
  // receipt made every anonymous AuthnRequest a KV write. An ID that has already
  // been answered gets nothing new to post (null), even if it verifies.
  const replayKey = `saml:req:${sp.id}:${request.requestId}`;
  // The marker is an atomic D1 claim - the KV get+put it replaces raced by
  // minutes of propagation time, and its row outlives REQUEST_ID_TTL anyway.
  if (!(await markConsumed(env, replayKey))) return null;
  const xml = await buildSignedResponse(env, {
    sp,
    user,
    requestId: request.requestId,
    acsUrl: request.acsUrl,
    sessionId,
    authnInstant,
  });
  return { acsUrl: request.acsUrl, samlResponse: b64encode(xml), relayState: request.relayState };
}

/** The IdP's EntityDescriptor - what an SP's administrator points at to learn our endpoints and signing certificate. */
saml.get("/saml/metadata", async (c) => {
  if (!isSamlConfigured(c.env)) {
    return c.text("SAML is not configured on this deployment - set SAML_SIGNING_CERT and SAML_SIGNING_KEY_PKCS8.", 503);
  }
  const { results: domains } = await c.env.DB.prepare("SELECT domain FROM domains ORDER BY domain").all<{ domain: string }>();
  const contactEmail = (await c.env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'email_from_address'").first<{ value: string }>())?.value || null;
  return new Response(idpMetadataXml(c.env, c.get("appName"), { scopes: domains.map((d) => d.domain), contactEmail }), {
    headers: { "Content-Type": "application/samlmetadata+xml" },
  });
});

/** The IdP's signing certificate as a PEM download - what Salesforce-style SPs ask to upload. */
saml.get("/saml/cert.pem", (c) => {
  if (!isSamlConfigured(c.env)) {
    return c.text("SAML is not configured on this deployment - set SAML_SIGNING_CERT and SAML_SIGNING_KEY_PKCS8.", 503);
  }
  return new Response(c.env.SAML_SIGNING_CERT, {
    headers: {
      "Content-Type": "application/x-pem-file",
      "Content-Disposition": 'attachment; filename="flareid-saml-signing.pem"',
    },
  });
});

saml.get("/saml/sso", async (c) => {
  if (!isSamlConfigured(c.env)) {
    return renderAuthMessage(c, 503, appConfigError("SAML sign-in is not configured on this deployment."));
  }

  const raw = rawQueryParams(c.req.url);
  if (!raw.SAMLRequest) return renderAuthMessage(c, 400, appConfigError("Missing SAMLRequest parameter."));

  let request;
  try {
    // Decoded here, not in rawQueryParams: the signature check below needs
    // the value exactly as it arrived, but the inflater needs the base64.
    request = parseAuthnRequestXml(await inflateAuthnRequest(decodeURIComponent(raw.SAMLRequest)));
  } catch (err) {
    return renderAuthMessage(c, 400, appConfigError(err instanceof AuthnRequestError ? err.message : "Could not decode the SAML request."));
  }

  if (request.destination && request.destination !== `${idpEntityId(c.env)}/saml/sso`) {
    return renderAuthMessage(c, 400, appConfigError("The request's Destination does not match this endpoint."));
  }

  const sp = await getSpByEntityId(c.env, request.issuer);
  if (!sp) return renderAuthMessage(c, 400, appConfigError("Unknown service provider."));

  // The ACS allowlist is the control that stops an unsigned request
  // redirecting a signed assertion somewhere unregistered - exact match only.
  const acsUrl = resolveAcsUrl(sp, request.acsUrl);
  if (request.acsUrl && !spAcsUrls(sp).includes(request.acsUrl)) {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: "unregistered_acs", acs: request.acsUrl }, c.req.raw);
    return renderAuthMessage(c, 400, appConfigError("AssertionConsumerServiceURL is not registered for this service provider."));
  }
  if (!acsUrl) return renderAuthMessage(c, 400, appConfigError("This service provider has no ACS URL configured."));

  const sig = await verifyRedirectSignature(sp, raw);
  const sigError = await rejectSignature(c, sig, sp, request, acsUrl, raw.RelayState === undefined ? null : raw.RelayState, "query");
  if (sigError) return sigError;

  let relayState: string | null = null;
  if (raw.RelayState !== undefined) {
    try {
      relayState = decodeURIComponent(raw.RelayState).slice(0, 4000);
    } catch {
      return renderAuthMessage(c, 400, appConfigError("RelayState is not valid percent-encoding."));
    }
  }

  return continueSsoRequest(c, request, sp, acsUrl, relayState);
});

/**
 * Where a SAML login flow interrupted by forced MFA enrollment resumes. The
 * backup-codes page links here; the session set at login authenticates it,
 * and the stored flow is consumed issuing the response.
 */
saml.get("/saml/complete", async (c) => {
  if (!isSamlConfigured(c.env)) {
    return renderAuthMessage(c, 503, appConfigError("SAML sign-in is not configured on this deployment."));
  }

  const flowId = c.req.query("flow") ?? "";
  const flow = await getLoginFlow(c.env, flowId);
  if (!flow || flow.kind !== "saml") return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);

  // Only a flow bound by the post-enrolment resume path can redeem here - a
  // flow minted by /saml/sso (e.g. for a ForceAuthn request) has no binding,
  // so a session cookie alone can never answer it without a fresh login.
  const boundUserId = await getFlowBinding(c.env, flowId);
  if (boundUserId === null) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);

  const session = await getSession(c.req.raw, c.env);
  const user = session ? await getUserById(c.env, session.userId) : null;
  // Authorization is re-evaluated at redemption, not parked at binding: a
  // signin permission revoked while the flow sat must stop the assertion.
  if (!session || !user || user.status !== "active" || !(await canSignIn(c.env, user.id))) {
    return c.redirect(`/login?next=${encodeURIComponent(`/saml/complete?flow=${flowId}`)}`, 302);
  }
  if (user.id !== boundUserId) {
    return renderAuthMessage(c, 400, { title: msg("msg.otherAccount.title"), message: msg("msg.otherAccount.message") });
  }

  const sp = await getSpById(c.env, flow.request.spId);
  if (!sp) return renderAuthMessage(c, 400, appConfigError("Unknown service provider."));

  await deleteLoginFlow(c.env, flowId);
  const issued = await issueSamlResponse(c.env, sp, flow.request, user, session.id, new Date(session.createdAt));
  if (!issued) return renderAuthMessage(c, 400, ALREADY_ANSWERED);
  await logAudit(c.env, user, "saml.assertion_issued", sp.entity_id, { request_id: flow.request.requestId, sso: true }, c.req.raw);
  return c.html(samlPostForm(c.get("appName"), issued.acsUrl, issued.samlResponse, issued.relayState));
});

/**
 * Signature-rejection delivery differs by binding. A redirect-binding refusal
 * can only show an error page - the response would have to be GET-encoded and
 * the binding defines no such error channel. A POST-binding request, though,
 * is answered in kind: a signed <samlp:Response> carrying Responder +
 * RequestDenied posted to the registered ACS, which is the protocol error an
 * SP (and a conformance harness) can actually observe. Errors are only ever
 * posted to ACS URLs that passed the registered allowlist.
 */
async function rejectSignature(
  c: Context<{ Bindings: Env }>,
  sig: SignatureCheck,
  sp: SamlServiceProviderRow,
  request: ParsedAuthnRequest,
  acsUrl: string,
  relayState: string | null,
  binding: "query" | "post"
): Promise<Response | null> {
  const required = sig === "unsigned" && sp.want_authn_requests_signed;
  const invalid = sig === "bad" || sig === "unsupported-alg" || sig === "no-key";
  if (!required && !invalid) return null;
  const reason = required ? "unsigned_request" : `signature_${sig}`;
  await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason }, c.req.raw);
  if (binding === "post") {
    const samlResponse = b64encode(await buildErrorResponse(c.env, { acsUrl, requestId: request.id }));
    return c.html(samlPostForm(c.get("appName"), acsUrl, samlResponse, relayState));
  }
  return renderAuthMessage(
    c,
    400,
    appConfigError(required ? "This service provider requires signed authentication requests." : "The request signature could not be verified.")
  );
}

/** The flow both bindings converge on once the request and its signature check out. */
async function continueSsoRequest(
  c: Context<{ Bindings: Env }>,
  request: ParsedAuthnRequest,
  sp: SamlServiceProviderRow,
  acsUrl: string,
  relayState: string | null
): Promise<Response> {
  // Single-use: an AuthnRequest ID may only ever mint one response, so a
  // replayed request - even one that verifies - gets nothing new to post. This
  // is a read; the ID is marked used when the response is issued.
  // Single-use per service provider: one SP's request IDs must not burn
  // another's namespace (SLO keys are namespaced the same way).
  if (await isConsumed(c.env, `saml:req:${sp.id}:${request.id}`)) {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: "replayed_request_id" }, c.req.raw);
    return renderAuthMessage(c, 400, ALREADY_ANSWERED);
  }

  const pending: PendingSamlRequest = { spId: sp.id, requestId: request.id, acsUrl, relayState };

  // SSO: a live session answers the request without a login form, unless the
  // SP asked for a fresh authentication.
  if (!request.forceAuthn) {
    const session = await getSession(c.req.raw, c.env);
    const user = session ? await getUserById(c.env, session.userId) : null;
    const gate = session && user ? await secondFactorGate(c.env, user, session.amr) : "ok";
    // A session that did not use the second factor the user's policy needs is not reused: they sign in again.
    if (session && user && user.status === "active" && gate !== "login" && (await canSignIn(c.env, user.id))) {
      // Same rule as /authorize: a password-only session minted before forced
      // enrolment parks the request and goes through MFA setup first - but
      // IsPassive forbids that UI, so it falls through to the NoPassive error.
      if (gate === "enrol" && !request.isPassive) {
        const resumeFlowId = await storeLoginFlow(c.env, { kind: "saml", request: pending, resumeFor: user.id });
        return c.redirect(`/account/mfa/setup?resume=${resumeFlowId}`, 302);
      }
      const issued = await issueSamlResponse(c.env, sp, pending, user, session.id, new Date(session.createdAt));
      if (!issued) return renderAuthMessage(c, 400, ALREADY_ANSWERED);
      await logAudit(c.env, user, "saml.assertion_issued", sp.entity_id, { request_id: request.id, sso: true }, c.req.raw);
      return c.html(samlPostForm(c.get("appName"), issued.acsUrl, issued.samlResponse, issued.relayState));
    }
  }

  // IsPassive forbids any IdP-driven UI: when the request cannot be answered
  // from the existing session - no session, a required factor missing, or the
  // SP asked for fresh authentication - the SP gets a protocol-level NoPassive
  // response at its ACS, not a login form.
  if (request.isPassive) {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: "is_passive_no_session" }, c.req.raw);
    const samlResponse = b64encode(await buildErrorResponse(c.env, { acsUrl, requestId: request.id, statusDetail: "NoPassive" }));
    return c.html(samlPostForm(c.get("appName"), acsUrl, samlResponse, relayState));
  }

  if (!(await isSetupCompleted(c.env))) {
    return renderAuthMessage(c, 503, AUTH_MESSAGES.notReady);
  }

  // An AuthnRequest carries no hint FlareID reads: the hostname or the default
  // brand, and the request's language.
  const appearance = await loginAppearance(c);
  const flowId = await sealLoginFlow(c.env, { kind: "saml", request: pending, locale: appearance.locale });
  return sendLoginForm(c, flowId, appearance);
}

/**
 * The HTTP-POST binding: the AuthnRequest arrives uncompressed in a form
 * field, its signature embedded as XML-DSig inside the document. Verification
 * follows the XSW hardening checklist in SAML-implementation.md section 4 -
 * which is also what Cloudflare Access's Signed AuthN feature and most
 * enterprise SPs emit.
 */
saml.post("/saml/sso", async (c) => {
  if (!isSamlConfigured(c.env)) {
    return renderAuthMessage(c, 503, appConfigError("SAML sign-in is not configured on this deployment."));
  }

  const form = await c.req.parseBody();
  const samlRequest = typeof form.SAMLRequest === "string" ? form.SAMLRequest : null;
  if (!samlRequest) return renderAuthMessage(c, 400, appConfigError("Missing SAMLRequest parameter."));

  let xml: string;
  let request: ParsedAuthnRequest;
  try {
    xml = decodePostAuthnRequest(samlRequest);
    request = parseAuthnRequestXml(xml);
  } catch (err) {
    return renderAuthMessage(c, 400, appConfigError(err instanceof AuthnRequestError ? err.message : "Could not decode the SAML request."));
  }

  if (request.destination && request.destination !== `${idpEntityId(c.env)}/saml/sso`) {
    return renderAuthMessage(c, 400, appConfigError("The request's Destination does not match this endpoint."));
  }

  const sp = await getSpByEntityId(c.env, request.issuer);
  if (!sp) return renderAuthMessage(c, 400, appConfigError("Unknown service provider."));

  // The ACS allowlist is the control that stops an unsigned request
  // redirecting a signed assertion somewhere unregistered - exact match only.
  const acsUrl = resolveAcsUrl(sp, request.acsUrl);
  if (request.acsUrl && !spAcsUrls(sp).includes(request.acsUrl)) {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: "unregistered_acs", acs: request.acsUrl }, c.req.raw);
    return renderAuthMessage(c, 400, appConfigError("AssertionConsumerServiceURL is not registered for this service provider."));
  }
  if (!acsUrl) return renderAuthMessage(c, 400, appConfigError("This service provider has no ACS URL configured."));

  const relayState = typeof form.RelayState === "string" ? form.RelayState.slice(0, 4000) : null;
  const sig = await verifyPostSignature(sp, xml, request);
  const sigError = await rejectSignature(c, sig, sp, request, acsUrl, relayState, "post");
  if (sigError) return sigError;

  return continueSsoRequest(c, request, sp, acsUrl, relayState);
});

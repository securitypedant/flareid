import { canSignIn } from "../lib/admin-roles.js";
import { isConsumed, markConsumed } from "../lib/one-shot.js";
import { isAdministrator, secondFactorGate } from "../lib/auth-policy.js";
import { hasSecondStep, secondStepFactors } from "../lib/second-step.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { appConfigError, AUTH_MESSAGES, loginAppearance, mfaForm, msg, renderAuthMessage, sendLoginForm, type AuthMessage } from "../lib/login-views.js";
import { deleteLoginFlow, getFlowBinding, getLoginFlow, sealLoginFlow, storeLoginFlow, storePendingMfa, type PendingSamlRequest } from "../lib/authorize-state.js";
import { getSession } from "../lib/sessions.js";
import { getUserById, getUserGroupIds } from "../lib/db.js";
import { isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { logAudit } from "../lib/audit.js";
import { b64encode } from "../lib/saml/xml.js";
import { isSamlConfigured } from "../lib/saml/sign.js";
import { idpMetadataXml } from "../lib/saml/metadata.js";
import { samlPostForm } from "../lib/saml/post-form.js";
import {
  AUTHN_CONTEXT,
  NAMEID_FORMAT_BY_URI,
  NAMEID_FORMAT_URIS,
  buildErrorResponse,
  buildSignedResponse,
  idpEntityId,
  supportedNameIdFormatUris,
} from "../lib/saml/messages.js";
import {
  AuthnRequestError,
  decodePostAuthnRequest,
  inflateAuthnRequest,
  parseAuthnRequestXml,
  rawQueryParams,
  verifyPostSignature,
  verifyRedirectSignature,
  type ParsedAuthnRequest,
  type RequestedAuthnContext,
  type SignatureCheck,
} from "../lib/saml/authn-request.js";
import { amrSatisfiesMfa, appAccessAllowed, appPolicy, appPostureDenied, appRequiresMfa, getSpByEntityId, getSpById, parseAssignedGroupIds, resolveAcsUrl, spAcsUrls } from "../lib/saml/service-providers.js";
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
  // IdP-initiated sign-ons carry no AuthnRequest id - nothing to replay.
  const replayKey = `saml:req:${sp.id}:${request.requestId}`;
  // The marker is an atomic D1 claim - the KV get+put it replaces raced by
  // minutes of propagation time, and its row outlives REQUEST_ID_TTL anyway.
  if (request.requestId !== null && !(await markConsumed(env, replayKey))) return null;
  // The NameIDPolicy the request asked for was validated before the flow was
  // stored and rides along as extra fields (the flow is JSON-serialised, so
  // they survive the login that may happen in between).
  const extra = request as PendingSamlRequest & {
    nameIdFormat?: string | null;
    nameIdSpNameQualifier?: string | null;
    nameIdSpProvidedId?: string | null;
  };
  const xml = await buildSignedResponse(env, {
    sp,
    user,
    requestId: request.requestId,
    acsUrl: request.acsUrl,
    sessionId,
    authnInstant,
    nameIdFormat: extra.nameIdFormat,
    nameIdSpNameQualifier: extra.nameIdSpNameQualifier,
    nameIdSpProvidedId: extra.nameIdSpProvidedId,
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

/**
 * IdP-initiated (unsolicited) SSO: no AuthnRequest, so the response carries no
 * InResponseTo. `?sp=<entity_id>` picks the application; `?RelayState=` passes
 * through verbatim, as the bindings profile defines. The session gate is the
 * same one an SP-initiated request faces - an unsolicited URL is a convenience
 * link, not an authentication bypass.
 */
saml.get("/saml/idp-initiated", async (c) => {
  if (!isSamlConfigured(c.env)) {
    return renderAuthMessage(c, 503, appConfigError("SAML sign-in is not configured on this deployment."));
  }
  const entityId = (c.req.query("sp") ?? "").trim();
  const sp = entityId ? await getSpByEntityId(c.env, entityId) : null;
  if (!sp) return renderAuthMessage(c, 400, appConfigError("Unknown service provider."));
  const acsUrl = resolveAcsUrl(sp, null);
  if (!acsUrl) return renderAuthMessage(c, 400, appConfigError("This service provider has no ACS URL configured."));

  const session = await getSession(c.req.raw, c.env);
  const user = session ? await getUserById(c.env, session.userId) : null;
  const self = new URL(c.req.url);
  if (!session || !user || user.status !== "active" || !(await canSignIn(c.env, user.id))) {
    return c.redirect(`/login?next=${encodeURIComponent(self.pathname + self.search)}`, 302);
  }
  const gate = await secondFactorGate(c.env, user, session.amr);
  // A session missing its required factor cannot mint an assertion either way:
  // 'login' re-authenticates, 'enrol' goes to factor setup and retries the link.
  if (gate === "login") return c.redirect(`/login?next=${encodeURIComponent(self.pathname + self.search)}`, 302);
  if (gate === "enrol") return c.redirect("/account/mfa/setup", 302);

  // App assignment: a restricted SP is not for this user. There is no
  // AuthnRequest to answer, so the denial is a page, not a posted status.
  if (!appAccessAllowed(sp, await getUserGroupIds(c.env, user.id), user.id)) {
    await logAudit(c.env, user, "saml.request_rejected", sp.entity_id, { reason: "app_not_assigned", idp_initiated: true }, c.req.raw);
    return renderAuthMessage(c, 403, appConfigError("Your account is not allowed to use this application."));
  }
  const spPolicy = await appPolicy(c.env, sp.policy_id);
  if (await appPostureDenied(c.env, spPolicy, c.req.raw, user.id)) {
    await logAudit(c.env, user, "saml.request_rejected", sp.entity_id, { reason: "posture_policy", idp_initiated: true }, c.req.raw);
    return renderAuthMessage(c, 403, appConfigError("This application's policy does not allow this sign-in."));
  }
  if (appRequiresMfa(sp, spPolicy) && !amrSatisfiesMfa(session.amr, { admin: await isAdministrator(c.env, user.id) })) {
    if (!(await hasSecondStep(c.env, user))) {
      return renderAuthMessage(c, 403, appConfigError("This application requires a sign-in with a second factor, but your account has none enrolled."));
    }
    return samlStepUp(c, { spId: sp.id, requestId: null, acsUrl, relayState: c.req.query("RelayState") !== undefined ? decodeURIComponent(c.req.query("RelayState") ?? "").slice(0, 4000) : null }, user);
  }

  let relayState: string | null = null;
  if (c.req.query("RelayState") !== undefined) {
    relayState = decodeURIComponent(c.req.query("RelayState") ?? "").slice(0, 4000);
  }
  const xml = await buildSignedResponse(c.env, {
    sp,
    user,
    requestId: null,
    acsUrl,
    sessionId: session.id,
    authnInstant: new Date(session.createdAt),
  });
  await logAudit(c.env, user, "saml.assertion_issued", sp.entity_id, { sso: true, idp_initiated: true }, c.req.raw);
  return c.html(samlPostForm(c.get("appName"), acsUrl, b64encode(xml), relayState));
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

  // Same re-evaluation rule as the signin permission above: assignment is
  // checked at redemption. The denial answers the request in protocol - a
  // signed RequestDenied posted to the registered ACS.
  if (!appAccessAllowed(sp, await getUserGroupIds(c.env, user.id), user.id)) {
    await deleteLoginFlow(c.env, flowId);
    await logAudit(c.env, user, "saml.request_rejected", sp.entity_id, { reason: "app_not_assigned" }, c.req.raw);
    const samlResponse = b64encode(await buildErrorResponse(c.env, { acsUrl: flow.request.acsUrl, requestId: flow.request.requestId, statusDetail: "RequestDenied" }));
    return c.html(samlPostForm(c.get("appName"), flow.request.acsUrl, samlResponse, flow.request.relayState));
  }
  const spPolicy = await appPolicy(c.env, sp.policy_id);
  if (await appPostureDenied(c.env, spPolicy, c.req.raw, user.id)) {
    await deleteLoginFlow(c.env, flowId);
    await logAudit(c.env, user, "saml.request_rejected", sp.entity_id, { reason: "posture_policy" }, c.req.raw);
    const samlResponse = b64encode(await buildErrorResponse(c.env, { acsUrl: flow.request.acsUrl, requestId: flow.request.requestId, statusDetail: "RequestDenied" }));
    return c.html(samlPostForm(c.get("appName"), flow.request.acsUrl, samlResponse, flow.request.relayState));
  }
  if (appRequiresMfa(sp, spPolicy) && !amrSatisfiesMfa(session.amr, { admin: await isAdministrator(c.env, user.id) })) {
    if (!(await hasSecondStep(c.env, user))) {
      await deleteLoginFlow(c.env, flowId);
      await logAudit(c.env, user, "saml.request_rejected", sp.entity_id, { reason: "mfa_required" }, c.req.raw);
      const samlResponse = b64encode(await buildErrorResponse(c.env, { acsUrl: flow.request.acsUrl, requestId: flow.request.requestId, statusDetail: "RequestDenied" }));
      return c.html(samlPostForm(c.get("appName"), flow.request.acsUrl, samlResponse, flow.request.relayState));
    }
    // The parked request becomes a fresh flow behind a second-step challenge.
    await deleteLoginFlow(c.env, flowId);
    return samlStepUp(c, flow.request, user);
  }

  await deleteLoginFlow(c.env, flowId);
  const issued = await issueSamlResponse(c.env, sp, flow.request, user, session.id, new Date(session.createdAt));
  if (!issued) return renderAuthMessage(c, 400, ALREADY_ANSWERED);
  await logAudit(c.env, user, "saml.assertion_issued", sp.entity_id, { request_id: flow.request.requestId, sso: true }, c.req.raw);
  return c.html(samlPostForm(c.get("appName"), issued.acsUrl, issued.samlResponse, issued.relayState));
});

/**
 * An app-level require_mfa against a live session: park the request behind a
 * second-step challenge. Completing it mints an upgraded session and runs the
 * usual completeLoginFlow path, which issues the assertion.
 */
async function samlStepUp(c: Context<{ Bindings: Env }>, request: PendingSamlRequest, user: UserRow): Promise<Response> {
  const appearance = await loginAppearance(c, { userId: user.id });
  const flowId = await sealLoginFlow(c.env, { kind: "saml", request, locale: appearance.locale });
  const mfaId = await storePendingMfa(c.env, user.id, flowId, appearance.locale);
  return c.html(mfaForm(mfaId, appearance, msg("mfa.appRequired"), await secondStepFactors(c.env, user)));
}

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

/**
 * The AuthnContext comparison matrix (SAML Core 3.3.2.2.1). FlareID asserts
 * exactly one class - PasswordProtectedTransport - so comparisons are judged
 * against that single class: "exact" matches only itself; "minimum"/"maximum"
 * are met when it is inside the requested set (it is at least/at most as
 * strong as itself) and undecidable otherwise; "better" can never be met
 * because no stronger class exists to assert. An empty class list or an
 * element without refs places no constraint.
 */
function authnContextSatisfiable(rac: RequestedAuthnContext): boolean {
  if (rac.classRefs.length === 0) return true;
  const inSet = rac.classRefs.includes(AUTHN_CONTEXT);
  switch (rac.comparison) {
    case "exact":
      return inSet;
    case "minimum":
    case "maximum":
      return inSet;
    case "better":
      return false;
    default:
      return false;
  }
}

/** Posts a signed error <samlp:Response> to the registered ACS - the protocol-level refusal for an unsatisfiable request. */
async function postProtocolError(
  c: Context<{ Bindings: Env }>,
  request: ParsedAuthnRequest,
  acsUrl: string,
  relayState: string | null,
  statusDetail: string,
  reason: string
): Promise<Response> {
  await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason }, c.req.raw);
  const samlResponse = b64encode(await buildErrorResponse(c.env, { acsUrl, requestId: request.id, statusDetail }));
  return c.html(samlPostForm(c.get("appName"), acsUrl, samlResponse, relayState));
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

  // SAML Core 3.4.1.4: the responder must answer with assertions meeting the
  // request's specifications, or with a Status describing the error. Every
  // unsatisfiable specification is refused here - a login form cannot change
  // the answer, so the signed error goes straight to the ACS.
  const specifiedFormat = request.nameIdFormat ? NAMEID_FORMAT_BY_URI[request.nameIdFormat] : undefined;
  if (request.nameIdFormat && !specifiedFormat && request.nameIdFormat !== "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified") {
    return postProtocolError(c, request, acsUrl, relayState, "InvalidNameIDPolicy", "unsupported_nameid_format");
  }
  // The format actually emitted: the request's choice when it is one we can
  // produce, otherwise the SP's configured default.
  const resolvedFormatName = specifiedFormat ?? (NAMEID_FORMAT_URIS[sp.nameid_format] ? sp.nameid_format : "transient");
  if (request.nameIdSpProvidedId && resolvedFormatName !== "persistent") {
    return postProtocolError(c, request, acsUrl, relayState, "InvalidNameIDPolicy", "spprovidedid_without_persistent");
  }
  if (request.subjectNameId) {
    // A <saml:Subject> demands an assertion about that specific principal; the
    // IdP authenticates the session user and cannot map an opaque identifier
    // onto a different one - the principal is not recognized.
    return postProtocolError(c, request, acsUrl, relayState, "UnknownPrincipal", "unrecognized_subject");
  }
  if (request.requestedAuthnContext && !authnContextSatisfiable(request.requestedAuthnContext)) {
    return postProtocolError(c, request, acsUrl, relayState, "NoAuthnContext", "unsatisfiable_authn_context");
  }

  const pending: PendingSamlRequest = { spId: sp.id, requestId: request.id, acsUrl, relayState };
  // What issuance must honour from the request: only a format we can actually
  // emit, the SP namespace to echo, and the SP-chosen persistent value.
  Object.assign(pending, {
    nameIdFormat: specifiedFormat ? request.nameIdFormat : null,
    nameIdSpNameQualifier: request.nameIdSpNameQualifier,
    nameIdSpProvidedId: resolvedFormatName === "persistent" ? request.nameIdSpProvidedId : null,
  });

  // SSO: a live session answers the request without a login form, unless the
  // SP asked for a fresh authentication.
  if (!request.forceAuthn) {
    const session = await getSession(c.req.raw, c.env);
    const user = session ? await getUserById(c.env, session.userId) : null;
    const gate = session && user ? await secondFactorGate(c.env, user, session.amr) : "ok";
    // A session that did not use the second factor the user's policy needs is not reused: they sign in again.
    if (session && user && user.status === "active" && gate !== "login" && (await canSignIn(c.env, user.id))) {
      // App assignment: the user is authenticated, but this SP is restricted
      // to groups they are not in - a protocol-level RequestDenied, same
      // delivery as every other refusal here.
      if (!appAccessAllowed(sp, await getUserGroupIds(c.env, user.id), user.id)) {
        return postProtocolError(c, request, acsUrl, relayState, "RequestDenied", "app_not_assigned");
      }
      const spPolicy = await appPolicy(c.env, sp.policy_id);
      if (await appPostureDenied(c.env, spPolicy, c.req.raw, user.id)) {
        return postProtocolError(c, request, acsUrl, relayState, "RequestDenied", "posture_policy");
      }
      // Same rule as /authorize: the app demands a factor this session never
      // presented - park the request behind a second-step challenge, unless
      // IsPassive forbids the UI (then the SP gets NoPassive).
      if (appRequiresMfa(sp, spPolicy) && !amrSatisfiesMfa(session.amr, { admin: await isAdministrator(c.env, user.id) })) {
        if (!request.isPassive && (await hasSecondStep(c.env, user))) return samlStepUp(c, pending, user);
        return postProtocolError(c, request, acsUrl, relayState, "NoPassive", "mfa_required");
      }
      // Same rule as /authorize: a password-only session minted before forced
      // enrolment parks the request and goes through MFA setup first. IsPassive
      // forbids that UI, so the SP gets NoPassive rather than an assertion the
      // policy said to withhold.
      if (gate === "enrol") {
        if (!request.isPassive) {
          const resumeFlowId = await storeLoginFlow(c.env, { kind: "saml", request: pending, resumeFor: user.id });
          return c.redirect(`/account/mfa/setup?resume=${resumeFlowId}`, 302);
        }
        return postProtocolError(c, request, acsUrl, relayState, "NoPassive", "enrol_required");
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

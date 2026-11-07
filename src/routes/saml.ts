import { Hono } from "hono";
import type { Env } from "../env.js";
import { appConfigError, AUTH_MESSAGES, loginForm, renderAuthMessage } from "../lib/login-views.js";
import { deleteLoginFlow, getFlowBinding, getLoginFlow, sealLoginFlow, storeLoginFlow, type PendingSamlRequest } from "../lib/authorize-state.js";
import { getSession } from "../lib/sessions.js";
import { getUserById } from "../lib/db.js";
import { getLoginAppearance, isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { logAudit } from "../lib/audit.js";
import { b64encode } from "../lib/saml/xml.js";
import { isSamlConfigured } from "../lib/saml/sign.js";
import { idpMetadataXml } from "../lib/saml/metadata.js";
import { samlPostForm } from "../lib/saml/post-form.js";
import { buildSignedResponse, idpEntityId } from "../lib/saml/messages.js";
import {
  AuthnRequestError,
  inflateAuthnRequest,
  parseAuthnRequestXml,
  rawQueryParams,
  verifyRedirectSignature,
} from "../lib/saml/authn-request.js";
import { getSpByEntityId, getSpById, resolveAcsUrl, spAcsUrls } from "../lib/saml/service-providers.js";
import type { SamlServiceProviderRow, UserRow } from "../lib/types.js";

export const saml = new Hono<{ Bindings: Env }>();

const REQUEST_ID_TTL_SECONDS = 600;

const ALREADY_ANSWERED = {
  title: "This sign-in was already completed",
  message: "That sign-in request has already been answered. Go back to the app and start again.",
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
  const replayKey = `saml:req:${request.requestId}`;
  if (await env.SESSIONS_KV.get(replayKey)) return null;
  await env.SESSIONS_KV.put(replayKey, "1", { expirationTtl: REQUEST_ID_TTL_SECONDS });
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
  return new Response(idpMetadataXml(c.env, c.get("appName")), {
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
  if (sig === "unsigned" && sp.want_authn_requests_signed) {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: "unsigned_request" }, c.req.raw);
    return renderAuthMessage(c, 400, appConfigError("This service provider requires signed authentication requests."));
  }
  if (sig === "bad" || sig === "unsupported-alg" || sig === "no-key") {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: `signature_${sig}` }, c.req.raw);
    return renderAuthMessage(c, 400, appConfigError("The request signature could not be verified."));
  }

  // Single-use: an AuthnRequest ID may only ever mint one response, so a
  // replayed request - even one that verifies - gets nothing new to post. This
  // is a read; the ID is marked used when the response is issued.
  if (await c.env.SESSIONS_KV.get(`saml:req:${request.id}`)) {
    await logAudit(c.env, null, "saml.request_rejected", request.issuer, { reason: "replayed_request_id" }, c.req.raw);
    return renderAuthMessage(c, 400, ALREADY_ANSWERED);
  }

  let relayState: string | null = null;
  if (raw.RelayState !== undefined) {
    try {
      relayState = decodeURIComponent(raw.RelayState).slice(0, 4000);
    } catch {
      return renderAuthMessage(c, 400, appConfigError("RelayState is not valid percent-encoding."));
    }
  }

  const pending: PendingSamlRequest = { spId: sp.id, requestId: request.id, acsUrl, relayState };

  // SSO: a live session answers the request without a login form, unless the
  // SP asked for a fresh authentication.
  if (!request.forceAuthn) {
    const session = await getSession(c.req.raw, c.env);
    const user = session ? await getUserById(c.env, session.userId) : null;
    if (session && user && user.status === "active") {
      // Same rule as /authorize: a password-only session minted before forced
      // enrolment parks the request and goes through MFA setup first.
      if (!user.mfa_enabled && (await isMfaRequired(c.env))) {
        const resumeFlowId = await storeLoginFlow(c.env, { kind: "saml", request: pending });
        return c.redirect(`/account/mfa/setup?resume=${resumeFlowId}`, 302);
      }
      const issued = await issueSamlResponse(c.env, sp, pending, user, session.id, new Date(session.createdAt));
      if (!issued) return renderAuthMessage(c, 400, ALREADY_ANSWERED);
      await logAudit(c.env, user, "saml.assertion_issued", sp.entity_id, { request_id: request.id, sso: true }, c.req.raw);
      return c.html(samlPostForm(c.get("appName"), issued.acsUrl, issued.samlResponse, issued.relayState));
    }
  }

  if (!(await isSetupCompleted(c.env))) {
    return renderAuthMessage(c, 503, AUTH_MESSAGES.notReady);
  }

  const flowId = await sealLoginFlow(c.env, { kind: "saml", request: pending });
  return c.html(loginForm(c.get("appName"), flowId, await getLoginAppearance(c.env)));
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
  if (!session || !user || user.status !== "active") {
    return c.redirect(`/login?next=${encodeURIComponent(`/saml/complete?flow=${flowId}`)}`, 302);
  }
  if (user.id !== boundUserId) {
    return renderAuthMessage(c, 400, { title: "Signed in as someone else", message: "This sign-in was started by a different account than the one signed in now. Sign out and start again from the app." });
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
 * The POST binding is deliberately unsupported: an embedded XML signature on
 * a foreign document is the XML Signature Wrapping attack surface, and
 * saml2int only requires redirect-binding receipt. Service providers that
 * POST - notably Cloudflare Access with Signed AuthN enabled - get a clear
 * refusal rather than a misverified request. See SAML-implementation.md
 * section 4.
 */
saml.post("/saml/sso", (c) => {
  return renderAuthMessage(
    c,
    400,
    appConfigError(
      "The HTTP-POST request binding is not supported. Send AuthnRequests over HTTP-Redirect, and if this is Cloudflare Access leave 'Sign SAML authentication request' turned off."
    )
  );
});

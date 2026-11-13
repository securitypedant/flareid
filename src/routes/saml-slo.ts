import { Hono } from "hono";
import { DOMParser } from "@xmldom/xmldom";
import type { Env } from "../env.js";
import { inflateAuthnRequest, rawQueryParams, verifyRedirectSignature } from "../lib/saml/authn-request.js";
import { getSpByEntityId } from "../lib/saml/service-providers.js";
import { idpEntityId } from "../lib/saml/messages.js";
import { signingKey } from "../lib/saml/sign.js";
import { b64encode, el, escapeXmlText, samlId, samlInstant } from "../lib/saml/xml.js";
import { msg, renderAuthMessage } from "../lib/login-views.js";
import { clearSessionCookie, getSession, revokeSession } from "../lib/sessions.js";
import { sha256Hex } from "../lib/tokens.js";
import { logAudit } from "../lib/audit.js";

const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SIGALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SLO_MAX_SKEW_MS = 5 * 60 * 1000;

/**
 * SAML Single Logout, SP-initiated, HTTP-Redirect binding (SAML Profiles 4.4).
 * The SP sends the browser here with a signed LogoutRequest; FlareID ends the
 * session the request names - only if it is the browser's own session, found
 * by the SessionIndex FlareID issued - and redirects back to the SP's
 * registered SLO URL with a signed LogoutResponse.
 */
export const samlSlo = new Hono<{ Bindings: Env }>();

async function deflateRaw(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function logoutResponseUrl(env: Env, sloUrl: string, inResponseTo: string, status: string, relayState: string | undefined): Promise<string> {
  const xml = el(
    "samlp:LogoutResponse",
    { "xmlns:samlp": NS_SAMLP, "xmlns:saml": NS_SAML, ID: samlId(), Version: "2.0", IssueInstant: samlInstant(new Date()), Destination: sloUrl, InResponseTo: inResponseTo },
    el("saml:Issuer", {}, escapeXmlText(idpEntityId(env))) + el("samlp:Status", {}, el("samlp:StatusCode", { Value: status }))
  );
  // Redirect-binding signature: over the encoded query string, not the XML.
  let signed = `SAMLResponse=${encodeURIComponent(b64encode(await deflateRaw(xml)))}`;
  if (relayState !== undefined) signed += `&RelayState=${relayState}`;
  signed += `&SigAlg=${encodeURIComponent(SIGALG_RSA_SHA256)}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", await signingKey(env), new TextEncoder().encode(signed));
  return `${sloUrl}${sloUrl.includes("?") ? "&" : "?"}${signed}&Signature=${encodeURIComponent(b64encode(sig))}`;
}

samlSlo.get("/saml/slo", async (c) => {
  const raw = rawQueryParams(c.req.url);
  if (!raw.SAMLRequest) return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "No SAMLRequest was sent.", action: null });

  let xml: string;
  try {
    xml = await inflateAuthnRequest(decodeURIComponent(raw.SAMLRequest));
  } catch (e) {
    return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: e instanceof Error ? e.message : "Unreadable SAMLRequest.", action: null });
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "DOCTYPE is not allowed.", action: null });
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const req = doc.documentElement;
  if (!req || req.localName !== "LogoutRequest" || req.namespaceURI !== NS_SAMLP) {
    return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "Expected a LogoutRequest.", action: null });
  }
  const issuer = req.getElementsByTagNameNS(NS_SAML, "Issuer")[0]?.textContent?.trim() ?? "";
  const requestId = req.getAttribute("ID") ?? "";
  const sessionIndexes = Array.from(req.getElementsByTagNameNS(NS_SAMLP, "SessionIndex")).map((e) => e.textContent?.trim() ?? "");
  const notOnOrAfter = req.getAttribute("NotOnOrAfter");
  const issueInstant = Date.parse(req.getAttribute("IssueInstant") ?? "");
  const destination = req.getAttribute("Destination");

  const sp = issuer ? await getSpByEntityId(c.env, issuer) : null;
  if (!sp || !sp.slo_url) return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "This app is not registered for Single Logout.", action: null });
  // Unsigned logout requests are refused: anyone could otherwise link users into being signed out.
  if ((await verifyRedirectSignature(sp, raw)) !== "ok") {
    return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "The LogoutRequest must be signed with the app's registered certificate.", action: null });
  }
  // A signature proves the SP sent it once - not that it is fresh, meant for
  // this IdP, or unused. Without these a captured request is a reusable
  // sign-out link.
  const fresh = Number.isFinite(issueInstant) && Math.abs(Date.now() - issueInstant) <= SLO_MAX_SKEW_MS;
  if (
    !/^[A-Za-z_][\w.-]{0,255}$/.test(requestId) ||
    !fresh ||
    (notOnOrAfter && Date.parse(notOnOrAfter) < Date.now() - 60_000) ||
    (destination !== null && destination !== `${c.env.ISSUER_URL}/saml/slo`)
  ) {
    return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "The LogoutRequest is malformed, expired or addressed elsewhere.", action: null });
  }
  const replayKey = `saml:slo:${await sha256Hex(`${sp.id}\n${requestId}`)}`;
  if (await c.env.SESSIONS_KV.get(replayKey)) {
    return renderAuthMessage(c, 400, { title: msg("msg.signOutFailed.title"), message: "This LogoutRequest was already used.", action: null });
  }
  await c.env.SESSIONS_KV.put(replayKey, "1", { expirationTtl: Math.ceil((2 * SLO_MAX_SKEW_MS) / 1000) + 60 });

  const session = await getSession(c.req.raw, c.env);
  let status = "urn:oasis:names:tc:SAML:2.0:status:Success";
  if (session) {
    const ours = `_${await sha256Hex(session.id)}`;
    // Only the session the SP names: a request without SessionIndex could be
    // replayed against whoever opens it.
    if (sessionIndexes.includes(ours)) {
      await revokeSession(c.env, session.id);
      c.header("Set-Cookie", clearSessionCookie());
      await logAudit(c.env, { id: session.userId, upn: String(session.userId) }, "logout.saml_slo", sp.name, undefined, c.req.raw);
    } else {
      // The SP names a session this browser does not hold: nothing to end here.
      status = "urn:oasis:names:tc:SAML:2.0:status:Requester";
    }
  }
  return c.redirect(await logoutResponseUrl(c.env, sp.slo_url, requestId, status, raw.RelayState), 302);
});

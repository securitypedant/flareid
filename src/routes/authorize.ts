import { canSignIn } from "../lib/admin-roles.js";
import { claimGroupsFromParameter } from "../lib/oidc.js";
import { secondFactorGate } from "../lib/auth-policy.js";
import { secondStepFactors } from "../lib/second-step.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { appConfigError, AUTH_MESSAGES, loginAppearance, mfaForm, msg, renderAuthMessage, sendLoginForm } from "../lib/login-views.js";
import { domainFromHint } from "../lib/brands.js";
import { uiLocalesPreference } from "../lib/i18n.js";
import { getClientByClientId, getUserById, getUserGroupIds } from "../lib/db.js";
import { randomToken } from "../lib/tokens.js";
import { sealLoginFlow, storeLoginFlow, storePendingMfa, type PendingAuthorizeRequest } from "../lib/authorize-state.js";
import { getSession } from "../lib/sessions.js";
import { isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { authorizeErrorRedirect, effectiveClaimGroups, hasConsent, redirectUriAllowed, sessionState } from "../lib/oidc.js";
import { formPostPage } from "../lib/saml/post-form.js";
import { decodeJwt } from "jose";
import { resolveRequestObject } from "../lib/request-object.js";
import { amrSatisfiesMfa, appAccessAllowed } from "../services/clients.js";
import { logAudit } from "../lib/audit.js";

export const authorize = new Hono<{ Bindings: Env }>();

const CONSENT_TTL_SECONDS = 600;

/**
 * Delivers the authorization response the way the client asked for it
 * (`response_mode`): the default query-string redirect, or an auto-submitting
 * POST form when the mode is form_post (OAuth 2.0 Multiple Response Types).
 */
export function respondAuthorize(c: Context<{ Bindings: Env }>, location: string, responseMode?: string) {
  if (responseMode !== "form_post") return c.redirect(location, 302);
  const url = new URL(location);
  const fields: Record<string, string> = {};
  for (const [k, v] of url.searchParams) fields[k] = v;
  return c.html(formPostPage(c.get("appName"), url.origin + url.pathname, fields));
}

/** A pending consent decision, stored after authentication (so not an anonymous write). */
export interface PendingConsent {
  request: PendingAuthorizeRequest;
  userId: number;
  amr: string[];
  sid: string | null;
}

/**
 * The end of every successful OIDC authorization: issue a code, unless the
 * client is not trusted and the user has not yet agreed to share these
 * scopes with it - then park the request and send the browser to the
 * consent screen, which comes back here once the user approves.
 *
 * `sid` is the IdP session the user is signed in with; its creation time is
 * the auth_time reported in the id_token.
 */
export async function finishOidcAuthorize(
  env: Env,
  req: PendingAuthorizeRequest,
  userId: number,
  amr: string[],
  sid: string | null,
  opts: { consented?: boolean } = {}
): Promise<{ redirectTo: string }> {
  const client = await getClientByClientId(env, req.clientId);
  // App assignment: a restricted client refuses anyone outside its assigned
  // users/groups, whichever path got here (reused session, fresh login,
  // consent, MFA resume). The redirect_uri was validated when the request was
  // parked, so the denial goes back to the client per RFC 6749 4.1.2.1.
  if (client && !appAccessAllowed(client, await getUserGroupIds(env, userId), userId)) {
    await logAudit(env, { id: userId, upn: String(userId) }, "oauth.app_denied", client.name, { client_id: client.client_id });
    return { redirectTo: authorizeErrorRedirect(env.ISSUER_URL, req.redirectUri, "access_denied", req.state, "Your account is not allowed to use this application.") };
  }
  // Defence in depth: the step-up lives on the session-reuse and password
  // paths, but any flow that arrives here without the factor still fails.
  if (client?.require_mfa && !amrSatisfiesMfa(amr)) {
    await logAudit(env, { id: userId, upn: String(userId) }, "oauth.app_denied", client.name, { client_id: client.client_id, reason: "mfa_required" });
    return { redirectTo: authorizeErrorRedirect(env.ISSUER_URL, req.redirectUri, "access_denied", req.state, "This application requires a sign-in with a second factor.") };
  }
  const prompts = new Set((req.prompt ?? "").split(/\s+/).filter(Boolean));
  if (client && !opts.consented && (!client.trusted || prompts.has("consent"))) {
    const requestedGroups = [...effectiveClaimGroups(client, req.scope, [...(req.claimGroups?.id_token ?? []), ...(req.claimGroups?.userinfo ?? [])])];
    const alreadyAgreed = !prompts.has("consent") && (await hasConsent(env, userId, client.client_id, req.scope, requestedGroups));
    if (!alreadyAgreed) {
      if (prompts.has("none")) return { redirectTo: authorizeErrorRedirect(env.ISSUER_URL, req.redirectUri, "consent_required", req.state) };
      const consentId = randomToken(16);
      const pending: PendingConsent = { request: req, userId, amr, sid };
      await env.SESSIONS_KV.put(`consent:${consentId}`, JSON.stringify(pending), { expirationTtl: CONSENT_TTL_SECONDS });
      return { redirectTo: `/consent/${consentId}` };
    }
  }

  const authTime = sid
    ? Math.floor(new Date((await env.DB.prepare("SELECT created_at FROM sessions WHERE id = ?").bind(sid).first<{ created_at: string }>())?.created_at ?? Date.now()).getTime() / 1000)
    : Math.floor(Date.now() / 1000);

  const code = randomToken(24);
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  await env.DB.prepare(
    `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, amr, auth_time, sid, claims)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      code,
      req.clientId,
      userId,
      req.redirectUri,
      req.scope,
      req.nonce ?? null,
      req.codeChallenge ?? null,
      req.codeChallengeMethod ?? null,
      expiresAt,
      JSON.stringify(amr),
      authTime,
      sid,
      req.claimGroups ? JSON.stringify(req.claimGroups) : null
    )
    .run();
  // Remembered for front- and back-channel logout: ending this session notifies this client.
  if (sid) {
    await env.DB.prepare("INSERT OR IGNORE INTO session_clients (session_id, client_id, created_at) VALUES (?, ?, ?)").bind(sid, req.clientId, new Date().toISOString()).run();
  }

  const redirect = new URL(req.redirectUri);
  redirect.searchParams.set("code", code);
  redirect.searchParams.set("iss", env.ISSUER_URL);
  if (req.state) redirect.searchParams.set("state", req.state);
  // OIDC Session Management: the RP keeps this salted hash and polls the OP's
  // check-session iframe to learn when the session here ends.
  if (sid) redirect.searchParams.set("session_state", await sessionState(env, req.clientId, req.redirectUri, sid));
  return { redirectTo: redirect.toString() };
}

/**
 * Third-party-initiated login (OIDC Core §4): a third party calls
 * `/oidc/init-login?iss={client_id}` to have the OP start an authentication
 * for that relying party. Only clients that registered an
 * `initiate_login_uri` opt in; the flow then runs a normal authorization
 * request on their behalf (their first registered redirect_uri, fresh
 * state+nonce). `login_hint` passes through; `target_link_uri` is the RP's
 * own concern and is ignored here.
 */
authorize.get("/oidc/init-login", async (c) => {
  const iss = c.req.query("iss") ?? "";
  const client = iss ? await getClientByClientId(c.env, iss) : null;
  if (!client || !client.initiate_login_uri) {
    return renderAuthMessage(c, 400, appConfigError("It is not registered for third-party sign-in."));
  }
  const [redirectUri] = JSON.parse(client.redirect_uris) as string[];
  if (!redirectUri) {
    return renderAuthMessage(c, 400, appConfigError("It has no redirect URI registered."));
  }
  const params = new URLSearchParams({ response_type: "code", client_id: iss, redirect_uri: redirectUri, scope: "openid", state: randomToken(16), nonce: randomToken(16) });
  const hint = c.req.query("login_hint");
  if (hint) params.set("login_hint", hint);
  return c.redirect(`/authorize?${params.toString()}`, 302);
});

// OpenID Connect Core 3.1.2.1: the authorization endpoint takes GET and POST
// (form-encoded), with the same parameters.
authorize.get("/authorize", (c) => authorizeEndpoint(c, new URL(c.req.url).searchParams));
authorize.post("/authorize", async (c) => {
  const body = await c.req.parseBody();
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) if (typeof v === "string") params.set(k, v);
  return authorizeEndpoint(c, params);
});

async function authorizeEndpoint(c: Context<{ Bindings: Env }>, params: URLSearchParams) {
  // JAR (RFC 9101): with request/request_uri the client_id may live only
  // inside the object. Decode it unverified to find the client row - the
  // parameters it carries earn trust only when the signature verifies below.
  let clientId = params.get("client_id");
  if (!clientId && params.has("request")) {
    try {
      const payload = decodeJwt(params.get("request")!);
      clientId = typeof payload.client_id === "string" ? payload.client_id : payload.iss ?? null;
    } catch {
      clientId = null;
    }
  }
  if (!clientId) {
    return renderAuthMessage(c, 400, appConfigError("The sign-in request it sent is missing required parameters."));
  }

  const client = await getClientByClientId(c.env, clientId);
  if (!client) return renderAuthMessage(c, 400, appConfigError("It is not registered with this sign-in service."));

  if (params.has("request") || params.has("request_uri")) {
    const resolved = await resolveRequestObject(c.env, params, client);
    if (!resolved.ok) {
      // The object itself can't be trusted, so its redirect_uri can't either.
      // A query-side redirect_uri that is registered for the client is a safe
      // place to return the error; otherwise the user gets our page. The
      // object's own response_mode may still shape the error's encoding - it
      // cannot change where it goes, only how it gets there.
      const queryRedirect = params.get("redirect_uri");
      if (queryRedirect && redirectUriAllowed(client, queryRedirect)) {
        const queryState = params.get("state") ?? "";
        let objectMode: string | undefined;
        try {
          const m = decodeJwt(params.get("request") ?? "").response_mode;
          objectMode = typeof m === "string" ? m : undefined;
        } catch {
          objectMode = undefined;
        }
        const mode = params.get("response_mode") === "form_post" || objectMode === "form_post" ? "form_post" : undefined;
        return respondAuthorize(c, authorizeErrorRedirect(c.env.ISSUER_URL, queryRedirect, resolved.error, queryState, resolved.description), mode);
      }
      return renderAuthMessage(c, 400, appConfigError(resolved.description));
    }
    params = resolved.params;
  }

  const url = { searchParams: params };
  const redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type");
  // Stored verbatim on the grant rows, so bound it; anything beyond known
  // scopes releases nothing (effectiveClaimGroups intersects allowed_claims).
  const scope = (url.searchParams.get("scope") ?? "openid").slice(0, 512);
  const state = url.searchParams.get("state") ?? "";
  const nonce = url.searchParams.get("nonce") ?? undefined;
  const codeChallenge = url.searchParams.get("code_challenge") ?? undefined;
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? undefined;
  const prompt = url.searchParams.get("prompt") ?? undefined;
  const maxAgeRaw = url.searchParams.get("max_age");
  const responseMode = url.searchParams.get("response_mode");

  if (!redirectUri) {
    return renderAuthMessage(c, 400, appConfigError("The sign-in request it sent is missing required parameters."));
  }
  if (!redirectUriAllowed(client, redirectUri)) {
    return renderAuthMessage(c, 400, appConfigError("The address it asked to return to (redirect_uri) is not registered for it."));
  }

  // From here the redirect_uri is known to be the client's own, so errors go
  // back to it (RFC 6749 4.1.2.1) rather than stranding the user on our page.
  const fail = (error: string, description: string) => respondAuthorize(c, authorizeErrorRedirect(c.env.ISSUER_URL, redirectUri, error, state, description), responseMode === "form_post" ? "form_post" : undefined);
  if (responseType !== "code") return fail("unsupported_response_type", "Only response_type=code is supported.");
  if (responseMode !== null && responseMode !== "query" && responseMode !== "form_post") {
    return fail("invalid_request", "response_mode must be query or form_post.");
  }

  // PKCE is S256 only. "plain" sends the verifier's equivalent in the clear, and
  // a challenge with no method defaults to plain (RFC 7636 §4.3), so both are
  // refused. A public client has no secret, so for it PKCE is the only thing
  // binding the code to the app that asked: required, not optional.
  if (codeChallenge && codeChallengeMethod !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
  if (client.client_type === "public" && !codeChallenge) return fail("invalid_request", "Public clients must use PKCE (code_challenge with S256).");

  const prompts = new Set((prompt ?? "").split(/\s+/).filter(Boolean));
  if (prompts.has("none") && prompts.size > 1) return fail("invalid_request", "prompt=none cannot be combined with other values.");
  const maxAge = maxAgeRaw !== null && /^\d+$/.test(maxAgeRaw) ? Number(maxAgeRaw) : undefined;

  // OIDC ui_locales (Core 3.1.2.1): the first language FlareID has, for the
  // sign-in page and the consent page after it (see requestLocale).
  const uiLocale = uiLocalesPreference(url.searchParams.get("ui_locales"));
  const claimGroups = claimGroupsFromParameter(url.searchParams.get("claims"));
  if (claimGroups === "invalid") return fail("invalid_request", "The claims parameter is not valid JSON.");
  const pendingRequest: PendingAuthorizeRequest = {
    ...(claimGroups.id_token.length || claimGroups.userinfo.length ? { claimGroups } : {}),
    clientId,
    redirectUri,
    scope,
    state,
    nonce,
    codeChallenge,
    codeChallengeMethod,
    ...(prompt ? { prompt } : {}),
    ...(maxAge !== undefined ? { maxAge } : {}),
    ...(uiLocale ? { uiLocale } : {}),
    ...(responseMode === "form_post" ? { responseMode } : {}),
  };

  // SSO: if there's already a valid FlareID session in this browser, skip the
  // login form and issue a fresh code - unless the client asked for a fresh
  // login (prompt=login), or the session is older than its max_age.
  const session = await getSession(c.req.raw, c.env);
  const user = session ? await getUserById(c.env, session.userId) : null;
  const sessionAge = session ? (Date.now() - new Date(session.createdAt).getTime()) / 1000 : Infinity;
  const reusable = session && user && user.status === "active" && !prompts.has("login") && (maxAge === undefined || sessionAge <= maxAge) && (await canSignIn(c.env, user.id));
  if (reusable) {
    // A password-only session minted before forced enrollment must not mint
    // credentials either: park this request and send the browser through MFA
    // setup; resumeLoginFlow finishes the code issue afterwards.
    const gate = await secondFactorGate(c.env, user, session.amr);
    if (gate === "login") {
      if (prompts.has("none")) return fail("login_required", "This app needs a second factor; sign in again.");
    } else if (gate === "enrol") {
      if (prompts.has("none")) return fail("interaction_required", "Multi-factor enrolment is required.");
      const resumeFlowId = await storeLoginFlow(c.env, { kind: "oidc", request: pendingRequest, resumeFor: user.id });
      return c.redirect(`/account/mfa/setup?resume=${resumeFlowId}`, 302);
    } else {
      if (client.require_mfa && !amrSatisfiesMfa(session.amr)) {
        // The app demands a factor this session never presented. With no
        // factor enrolled there is nothing to step up with; otherwise park
        // the request behind a fresh second-step challenge - completing it
        // mints an upgraded session and finishes the authorize.
        if (prompts.has("none")) return fail("login_required", "This app needs a sign-in with a second factor.");
        const factors = await secondStepFactors(c.env, user);
        if (!Object.values(factors).some(Boolean)) {
          return fail("access_denied", "This application requires a sign-in with a second factor, but your account has none enrolled.");
        }
        const mfaAppearance = await loginAppearance(c, { userId: user.id, locale: uiLocale, clientId });
        const stepFlowId = await sealLoginFlow(c.env, { kind: "oidc", request: pendingRequest, locale: mfaAppearance.locale });
        const mfaId = await storePendingMfa(c.env, user.id, stepFlowId, mfaAppearance.locale);
        return c.html(mfaForm(mfaId, mfaAppearance, msg("mfa.appRequired"), factors));
      }
      const { redirectTo } = await finishOidcAuthorize(c.env, pendingRequest, user.id, session.amr, session.id);
      return respondAuthorize(c, redirectTo, pendingRequest.responseMode);
    }
  }

  // prompt=none means "answer without showing anything": with no usable
  // session, the answer is login_required.
  if (prompts.has("none")) return fail("login_required", "No active session.");

  if (!(await isSetupCompleted(c.env))) {
    return renderAuthMessage(c, 503, AUTH_MESSAGES.notReady);
  }

  // OIDC login_hint (Core 3.1.2.1): its domain brands the sign-in page.
  const brandDomain = domainFromHint(url.searchParams.get("login_hint"));
  const appearance = await loginAppearance(c, { domain: brandDomain, locale: uiLocale, clientId });
  const flowId = await sealLoginFlow(c.env, { kind: "oidc", request: pendingRequest, ...(brandDomain ? { brandDomain } : {}), locale: appearance.locale });
  return sendLoginForm(c, flowId, appearance);
}

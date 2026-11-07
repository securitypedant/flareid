import { Hono } from "hono";
import type { Env } from "../env.js";
import { appConfigError, AUTH_MESSAGES, loginForm, renderAuthMessage } from "../lib/login-views.js";
import { getClientByClientId, getUserById } from "../lib/db.js";
import { randomToken } from "../lib/tokens.js";
import { sealLoginFlow, storeLoginFlow, type PendingAuthorizeRequest } from "../lib/authorize-state.js";
import { getSession } from "../lib/sessions.js";
import { getLoginAppearance, isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { authorizeErrorRedirect, hasConsent, redirectUriAllowed } from "../lib/oidc.js";

export const authorize = new Hono<{ Bindings: Env }>();

const CONSENT_TTL_SECONDS = 600;

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
  const prompts = new Set((req.prompt ?? "").split(/\s+/).filter(Boolean));
  if (client && !opts.consented && (!client.trusted || prompts.has("consent"))) {
    const alreadyAgreed = !prompts.has("consent") && (await hasConsent(env, userId, client.client_id, req.scope));
    if (!alreadyAgreed) {
      if (prompts.has("none")) return { redirectTo: authorizeErrorRedirect(req.redirectUri, "consent_required", req.state) };
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
    `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, amr, auth_time, sid)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
      sid
    )
    .run();

  const redirect = new URL(req.redirectUri);
  redirect.searchParams.set("code", code);
  if (req.state) redirect.searchParams.set("state", req.state);
  return { redirectTo: redirect.toString() };
}

authorize.get("/authorize", async (c) => {
  const url = new URL(c.req.url);
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type");
  const scope = url.searchParams.get("scope") ?? "openid";
  const state = url.searchParams.get("state") ?? "";
  const nonce = url.searchParams.get("nonce") ?? undefined;
  const codeChallenge = url.searchParams.get("code_challenge") ?? undefined;
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? undefined;
  const prompt = url.searchParams.get("prompt") ?? undefined;
  const maxAgeRaw = url.searchParams.get("max_age");

  if (!clientId || !redirectUri) {
    return renderAuthMessage(c, 400, appConfigError("The sign-in request it sent is missing required parameters."));
  }

  const client = await getClientByClientId(c.env, clientId);
  if (!client) return renderAuthMessage(c, 400, appConfigError("It is not registered with this sign-in service."));
  if (!redirectUriAllowed(client, redirectUri)) {
    return renderAuthMessage(c, 400, appConfigError("The address it asked to return to (redirect_uri) is not registered for it."));
  }

  // From here the redirect_uri is known to be the client's own, so errors go
  // back to it (RFC 6749 4.1.2.1) rather than stranding the user on our page.
  const fail = (error: string, description: string) => c.redirect(authorizeErrorRedirect(redirectUri, error, state, description), 302);
  if (responseType !== "code") return fail("unsupported_response_type", "Only response_type=code is supported.");

  // PKCE is S256 only. "plain" sends the verifier's equivalent in the clear, and
  // a challenge with no method defaults to plain (RFC 7636 §4.3), so both are
  // refused. A public client has no secret, so for it PKCE is the only thing
  // binding the code to the app that asked: required, not optional.
  if (codeChallenge && codeChallengeMethod !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
  if (client.client_type === "public" && !codeChallenge) return fail("invalid_request", "Public clients must use PKCE (code_challenge with S256).");

  const prompts = new Set((prompt ?? "").split(/\s+/).filter(Boolean));
  if (prompts.has("none") && prompts.size > 1) return fail("invalid_request", "prompt=none cannot be combined with other values.");
  const maxAge = maxAgeRaw !== null && /^\d+$/.test(maxAgeRaw) ? Number(maxAgeRaw) : undefined;

  const pendingRequest: PendingAuthorizeRequest = {
    clientId,
    redirectUri,
    scope,
    state,
    nonce,
    codeChallenge,
    codeChallengeMethod,
    ...(prompt ? { prompt } : {}),
    ...(maxAge !== undefined ? { maxAge } : {}),
  };

  // SSO: if there's already a valid FlareID session in this browser, skip the
  // login form and issue a fresh code - unless the client asked for a fresh
  // login (prompt=login), or the session is older than its max_age.
  const session = await getSession(c.req.raw, c.env);
  const user = session ? await getUserById(c.env, session.userId) : null;
  const sessionAge = session ? (Date.now() - new Date(session.createdAt).getTime()) / 1000 : Infinity;
  const reusable = session && user && user.status === "active" && !prompts.has("login") && (maxAge === undefined || sessionAge <= maxAge);
  if (reusable) {
    // A password-only session minted before forced enrollment must not mint
    // credentials either: park this request and send the browser through MFA
    // setup; resumeLoginFlow finishes the code issue afterwards.
    if (!user.mfa_enabled && (await isMfaRequired(c.env))) {
      if (prompts.has("none")) return fail("interaction_required", "Multi-factor enrolment is required.");
      const resumeFlowId = await storeLoginFlow(c.env, { kind: "oidc", request: pendingRequest });
      return c.redirect(`/account/mfa/setup?resume=${resumeFlowId}`, 302);
    }
    const { redirectTo } = await finishOidcAuthorize(c.env, pendingRequest, user.id, session.amr, session.id);
    return c.redirect(redirectTo, 302);
  }

  // prompt=none means "answer without showing anything": with no usable
  // session, the answer is login_required.
  if (prompts.has("none")) return fail("login_required", "No active session.");

  if (!(await isSetupCompleted(c.env))) {
    return renderAuthMessage(c, 503, AUTH_MESSAGES.notReady);
  }

  const flowId = await sealLoginFlow(c.env, { kind: "oidc", request: pendingRequest });
  return c.html(loginForm(c.get("appName"), flowId, await getLoginAppearance(c.env)));
});

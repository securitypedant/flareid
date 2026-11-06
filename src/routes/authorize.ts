import { Hono } from "hono";
import type { Env } from "../env.js";
import { appConfigError, AUTH_MESSAGES, loginForm, renderAuthMessage } from "../lib/login-views.js";
import { getClientByClientId, getUserById } from "../lib/db.js";
import { randomToken } from "../lib/tokens.js";
import { storeLoginFlow, type PendingAuthorizeRequest } from "../lib/authorize-state.js";
import { getSessionAmr, getSessionUserId } from "../lib/sessions.js";
import { getLoginAppearance, isMfaRequired, isSetupCompleted } from "../lib/settings.js";

export const authorize = new Hono<{ Bindings: Env }>();

export async function finishOidcAuthorize(
  env: Env,
  req: PendingAuthorizeRequest,
  userId: number,
  amr: string[] = ["pwd"]
): Promise<{ redirectTo: string }> {
  const code = randomToken(24);
  const expiresAt = new Date(Date.now() + 60_000).toISOString();

  await env.DB.prepare(
    `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, amr)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
      JSON.stringify(amr)
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

  if (!clientId || !redirectUri || responseType !== "code") {
    return renderAuthMessage(c, 400, appConfigError("The sign-in request it sent is missing required parameters."));
  }

  const client = await getClientByClientId(c.env, clientId);
  if (!client) return renderAuthMessage(c, 400, appConfigError("It is not registered with this sign-in service."));

  const allowedRedirectUris: string[] = JSON.parse(client.redirect_uris);
  if (!allowedRedirectUris.includes(redirectUri)) {
    return renderAuthMessage(c, 400, appConfigError("The address it asked to return to (redirect_uri) is not registered for it."));
  }

  // PKCE is S256 only. "plain" sends the verifier's equivalent in the clear, and
  // a challenge with no method defaults to plain (RFC 7636 §4.3), so both are
  // refused - back to the client, now that redirect_uri is known to be safe.
  if (codeChallenge && codeChallengeMethod !== "S256") {
    const error = new URL(redirectUri);
    error.searchParams.set("error", "invalid_request");
    error.searchParams.set("error_description", "code_challenge_method must be S256");
    if (state) error.searchParams.set("state", state);
    return c.redirect(error.toString(), 302);
  }

  const pendingRequest: PendingAuthorizeRequest = {
    clientId,
    redirectUri,
    scope,
    state,
    nonce,
    codeChallenge,
    codeChallengeMethod,
  };

  // SSO: if there's already a valid FlareID session in this browser, skip the
  // login form entirely and go straight to issuing a fresh code for this client.
  const existingUserId = await getSessionUserId(c.req.raw, c.env);
  if (existingUserId) {
    const user = await getUserById(c.env, existingUserId);
    if (user && user.status === "active") {
      // A password-only session minted before forced enrolment must not mint
      // credentials either: park this request and send the browser through
      // MFA setup; resumeLoginFlow finishes the code issue afterwards.
      if (!user.mfa_enabled && (await isMfaRequired(c.env))) {
        const resumeFlowId = await storeLoginFlow(c.env, { kind: "oidc", request: pendingRequest });
        return c.redirect(`/account/mfa/setup?resume=${resumeFlowId}`, 302);
      }
      const amr = await getSessionAmr(c.req.raw, c.env);
      const { redirectTo } = await finishOidcAuthorize(c.env, pendingRequest, user.id, amr);
      return c.redirect(redirectTo, 302);
    }
  }

  if (!(await isSetupCompleted(c.env))) {
    return renderAuthMessage(c, 503, AUTH_MESSAGES.notReady);
  }

  const flowId = await storeLoginFlow(c.env, { kind: "oidc", request: pendingRequest });
  return c.html(loginForm(c.get("appName"), flowId, await getLoginAppearance(c.env)));
});

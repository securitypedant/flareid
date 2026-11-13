import { frontchannelLogoutPage, frontchannelTargets } from "../lib/frontchannel.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { authPage, loginAppearance, msg, renderAuthMessage, requestLocale, type AuthMessage } from "../lib/login-views.js";
import { t, type MessageKey } from "../lib/i18n.js";
import { escapeHtml } from "../lib/html.js";
import { getClientByClientId } from "../lib/db.js";
import { clearSessionCookie, getSession, oidcSid, revokeSession } from "../lib/sessions.js";
import { authorizeErrorRedirect, effectiveClaimGroups, recordConsent } from "../lib/oidc.js";
import { verifyOwnIdToken } from "../lib/jwt.js";
import { logAudit } from "../lib/audit.js";
import { finishOidcAuthorize, type PendingConsent } from "./authorize.js";

/**
 * Consent for non-trusted clients, and RP-initiated logout - the two places
 * where the IdP session meets a relying party's request outside /authorize.
 */
export const oidcSession = new Hono<{ Bindings: Env }>();

async function loadConsent(c: Context<{ Bindings: Env }>): Promise<{ id: string; pending: PendingConsent } | null> {
  const id = c.req.param("id") ?? "";
  if (!/^[0-9a-f]{32}$/.test(id)) return null;
  const raw = await c.env.SESSIONS_KV.get(`consent:${id}`);
  if (!raw) return null;
  const pending = JSON.parse(raw) as PendingConsent;
  // Only the person who authenticated may answer: the consent id alone is not enough.
  const session = await getSession(c.req.raw, c.env);
  if (!session || session.userId !== pending.userId) return null;
  return { id, pending };
}

const REQUEST_EXPIRED: AuthMessage = { title: msg("msg.requestExpired.title"), message: msg("msg.requestExpired.message") };
const SIGN_OUT_FAILED = (reason: string): AuthMessage => ({ title: msg("msg.signOutFailed.title"), message: reason, action: null });

oidcSession.get("/consent/:id", async (c) => {
  const found = await loadConsent(c);
  if (!found) return renderAuthMessage(c, 400, REQUEST_EXPIRED);
  const client = await getClientByClientId(c.env, found.pending.request.clientId);
  const uiLocale = found.pending.request.uiLocale;
  if (!client) return renderAuthMessage(c, 400, { title: msg("msg.appUnregistered.title"), message: msg("msg.appUnregistered.message"), action: null }, { locale: uiLocale });

  const groups = [...effectiveClaimGroups(client, found.pending.request.scope, [...(found.pending.request.claimGroups?.id_token ?? []), ...(found.pending.request.claimGroups?.userinfo ?? [])])];
  const offline = found.pending.request.scope.split(/\s+/).includes("offline_access");
  // The person is known: their brand.
  const appearance = await loginAppearance(c, { userId: found.pending.userId, locale: uiLocale });
  const { appName, locale } = appearance;
  const tx = (key: MessageKey, vars?: Record<string, string>) => escapeHtml(t(locale, key, vars));
  return c.html(
    authPage(
      t(locale, "consent.title"),
      appearance,
      `
      <h1>${tx("consent.heading", { client: client.name })}</h1>
      <p class="sub" id="consent-asking">${tx("consent.asking", { appName })}</p>
      <ul class="consent-list" aria-labelledby="consent-asking">
        <li>${tx("consent.identifier")}</li>
        ${groups.map((g) => `<li>${tx(`consent.claims.${g}`)}</li>`).join("")}
        ${offline ? `<li>${tx("consent.offline")}</li>` : ""}
      </ul>
      <form method="POST" action="/consent/${found.id}">
        <div class="row" style="display:flex; gap:10px;">
          <button class="secondary" type="submit" name="decision" value="deny" style="flex:1;">${tx("consent.cancel")}</button>
          <button class="primary" type="submit" name="decision" value="allow" style="flex:1;">${tx("consent.allow")}</button>
        </div>
      </form>
      <p class="auth-alt muted">${tx("consent.withdraw")}</p>`
    )
  );
});

oidcSession.post("/consent/:id", async (c) => {
  const found = await loadConsent(c);
  if (!found) return renderAuthMessage(c, 400, REQUEST_EXPIRED);
  await c.env.SESSIONS_KV.delete(`consent:${found.id}`);
  const { request, userId, amr, sid } = found.pending;
  const decision = String((await c.req.parseBody()).decision ?? "");
  const client = await getClientByClientId(c.env, request.clientId);

  if (decision !== "allow" || !client) {
    await logAudit(c.env, { id: userId, upn: String(userId) }, "oauth.consent_denied", client?.name ?? request.clientId, undefined, c.req.raw);
    return c.redirect(authorizeErrorRedirect(request.redirectUri, "access_denied", request.state, "The user declined."), 302);
  }
  await recordConsent(c.env, userId, client.client_id, request.scope);
  await logAudit(c.env, { id: userId, upn: String(userId) }, "oauth.consent_granted", client.name, { scope: request.scope }, c.req.raw);
  const { redirectTo } = await finishOidcAuthorize(c.env, request, userId, amr, sid, { consented: true });
  return c.redirect(redirectTo, 302);
});

// ---------- RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0) ----------

interface LogoutRequest {
  idTokenHint?: string;
  clientId?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}

async function readLogoutRequest(c: Context<{ Bindings: Env }>): Promise<LogoutRequest> {
  const source: Record<string, unknown> = c.req.method === "POST" ? await c.req.parseBody() : Object.fromEntries(new URL(c.req.url).searchParams);
  const get = (k: string) => (typeof source[k] === "string" && source[k] !== "" ? (source[k] as string) : undefined);
  return { idTokenHint: get("id_token_hint"), clientId: get("client_id"), postLogoutRedirectUri: get("post_logout_redirect_uri"), state: get("state") };
}

/**
 * Validates where to send the browser afterwards. A post_logout_redirect_uri
 * is honoured only when it is registered for the client named by the hint's
 * audience (or client_id) - an unregistered one is an open redirect, so the
 * request is refused rather than followed.
 */
async function resolveLogout(c: Context<{ Bindings: Env }>, req: LogoutRequest) {
  const hint = req.idTokenHint ? await verifyOwnIdToken(c.env, req.idTokenHint) : null;
  if (req.idTokenHint && !hint) return { error: "The id_token_hint was not issued by this sign-in service." };
  const aud = hint ? (Array.isArray(hint.aud) ? hint.aud[0] : hint.aud) : undefined;
  if (aud && req.clientId && aud !== req.clientId) return { error: "client_id does not match the id_token_hint." };
  const client = aud || req.clientId ? await getClientByClientId(c.env, (aud ?? req.clientId)!) : null;

  let redirect: string | null = null;
  if (req.postLogoutRedirectUri) {
    const registered: string[] = client ? JSON.parse(client.post_logout_redirect_uris || "[]") : [];
    if (!registered.includes(req.postLogoutRedirectUri)) return { error: "post_logout_redirect_uri is not registered for this app." };
    const url = new URL(req.postLogoutRedirectUri);
    if (req.state) url.searchParams.set("state", req.state);
    redirect = url.toString();
  }
  return { hint, client, redirect };
}

async function signOut(c: Context<{ Bindings: Env }>, redirect: string | null, clientName?: string) {
  const session = await getSession(c.req.raw, c.env);
  const targets = session ? await frontchannelTargets(c.env, session.id) : [];
  if (session) {
    await revokeSession(c.env, session.id);
    await logAudit(c.env, { id: session.userId, upn: String(session.userId) }, "logout.rp_initiated", clientName, { frontchannel: targets.length }, c.req.raw);
  }
  c.header("Set-Cookie", clearSessionCookie());
  if (targets.length) {
    const { html, frameSrc } = frontchannelLogoutPage(c.get("appName") ?? "FlareID", targets, redirect, await requestLocale(c));
    c.header("X-FlareID-Frame-Src", frameSrc);
    return c.html(html);
  }
  if (redirect) return c.redirect(redirect, 302);
  return renderAuthMessage(c, 200, { title: msg("msg.signedOut.title"), message: msg("msg.signedOut.message"), action: { href: "/login", label: msg("common.signInAgain") } });
}

async function logoutEntry(c: Context<{ Bindings: Env }>) {
  const req = await readLogoutRequest(c);
  const resolved = await resolveLogout(c, req);
  if ("error" in resolved) return renderAuthMessage(c, 400, SIGN_OUT_FAILED(resolved.error!));

  const session = await getSession(c.req.raw, c.env);
  // No session on this request - including a cross-site POST, which carries
  // no SameSite=Lax cookie - means nothing to end: no Set-Cookie either.
  if (!session) {
    if (resolved.redirect) return c.redirect(resolved.redirect, 302);
    return renderAuthMessage(c, 200, { title: msg("msg.signedOut.title"), message: msg("msg.notSignedIn.message"), action: { href: "/login", label: msg("common.signIn") } });
  }

  // A hint for this very session (or this user) is proof the app is the one
  // the user signed in to: sign out straight away. Anything less asks first,
  // so a link on another site cannot sign people out.
  const hint = resolved.hint;
  // A hint without sid could be any token ever issued to this user, so only a
  // sid for this very session signs out without asking.
  const sameSession = hint && typeof hint.sid === "string" && hint.sid === (await oidcSid(session.id));
  if (sameSession) return signOut(c, resolved.redirect, resolved.client?.name);

  const hidden = (k: string, v?: string) => (v ? `<input type="hidden" name="${k}" value="${escapeHtml(v)}" />` : "");
  const appearance = await loginAppearance(c, { userId: session.userId });
  const { appName, locale } = appearance;
  return c.html(
    authPage(
      t(locale, "logout.title"),
      appearance,
      `
      <h1>${escapeHtml(t(locale, "logout.title"))}</h1>
      <p class="sub">${escapeHtml(resolved.client ? t(locale, "logout.askedBy", { client: resolved.client.name, appName }) : t(locale, "logout.confirm", { appName }))}</p>
      <form method="POST" action="/oidc/logout/confirm">
        ${hidden("id_token_hint", req.idTokenHint)}${hidden("client_id", req.clientId)}${hidden("post_logout_redirect_uri", req.postLogoutRedirectUri)}${hidden("state", req.state)}
        <div class="row"><button class="primary" type="submit">${escapeHtml(t(locale, "logout.submit"))}</button></div>
      </form>
      <p class="auth-alt"><a href="/account">${escapeHtml(t(locale, "logout.stay"))}</a></p>`
    )
  );
}

oidcSession.get("/oidc/logout", logoutEntry);
oidcSession.post("/oidc/logout", logoutEntry);

/** The user's own "yes, sign me out" - CSRF-checked like every other form here. */
oidcSession.post("/oidc/logout/confirm", async (c) => {
  const resolved = await resolveLogout(c, await readLogoutRequest(c));
  if ("error" in resolved) return renderAuthMessage(c, 400, SIGN_OUT_FAILED(resolved.error!));
  return signOut(c, resolved.redirect, resolved.client?.name);
});

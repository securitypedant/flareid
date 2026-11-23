import { frontchannelLogoutPage, frontchannelTargets } from "../lib/frontchannel.js";
import { markConsumed } from "../lib/one-shot.js";
import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { authPage, loginAppearance, msg, renderAuthMessage, requestLocale, type AuthMessage } from "../lib/login-views.js";
import { t, type MessageKey } from "../lib/i18n.js";
import { escapeHtml, scriptTag } from "../lib/html.js";
import { getClientByClientId } from "../lib/db.js";
import { clearSessionCookies, getSession, getSessionCheckSid, oidcSid, revokeSession, sessionLiveByOidcSid } from "../lib/sessions.js";
import { authorizeErrorRedirect, effectiveClaimGroups, recordConsent } from "../lib/oidc.js";
import { verifyOwnIdToken } from "../lib/jwt.js";
import { logAudit } from "../lib/audit.js";
import { finishOidcAuthorize, respondAuthorize, type PendingConsent } from "./authorize.js";

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
  if (!(await markConsumed(c.env, `consent:${found.id}`))) return renderAuthMessage(c, 400, REQUEST_EXPIRED);
  await c.env.SESSIONS_KV.delete(`consent:${found.id}`);
  const { request, userId, amr, sid } = found.pending;
  const decision = String((await c.req.parseBody()).decision ?? "");
  const client = await getClientByClientId(c.env, request.clientId);

  if (decision !== "allow" || !client) {
    await logAudit(c.env, { id: userId, upn: String(userId) }, "oauth.consent_denied", client?.name ?? request.clientId, undefined, c.req.raw);
    return respondAuthorize(c, authorizeErrorRedirect(c.env.ISSUER_URL, request.redirectUri, "access_denied", request.state, "The user declined."), request.responseMode);
  }
  const shownGroups = [...effectiveClaimGroups(client, request.scope, [...(request.claimGroups?.id_token ?? []), ...(request.claimGroups?.userinfo ?? [])])];
  await recordConsent(c.env, userId, client.client_id, request.scope, shownGroups);
  await logAudit(c.env, { id: userId, upn: String(userId) }, "oauth.consent_granted", client.name, { scope: request.scope }, c.req.raw);
  const { redirectTo } = await finishOidcAuthorize(c.env, c.req.raw, request, userId, amr, sid, { consented: true });
  return respondAuthorize(c, redirectTo, request.responseMode);
});

// ---------- Session Management (OpenID Connect Session Management 1.0) ----------

/**
 * The OP iframe RPs embed to poll login state (§4.2): it answers postMessage
 * with "unchanged" while the posted session_state still matches this session,
 * "changed" once it doesn't (or there's no session), "error" on a malformed
 * query. It exists to be framed, hence the frame-ancestors marker (which the
 * security-headers middleware turns into the CSP allowance).
 */
/**
 * Self-contained SHA-256 for the check_session iframe. It deliberately avoids
 * crypto.subtle / TextEncoder / Promise / Uint8Array: this page exists to be
 * driven by arbitrary RP clients, including headless test browsers whose
 * WebCrypto support is partial (the conformance suite's HtmlUnit rejects the
 * digest call and we answer "error"). Inputs are always ASCII. Exported so a
 * unit test can verify the exact shipped code against known vectors.
 */
export const CHECK_SESSION_SHA256_JS = `function sha256(a){
 function rr(v,n){return(v>>>n)|(v<<(32-n));}
 var mp=Math.pow,m232=mp(2,32),result="";
 var words=[],ab=a.length*8;
 var hh=sha256.h=sha256.h||[],kk=sha256.k=sha256.k||[],
  primeCount=kk.length,comp={};
 for(var cand=2;primeCount<64;cand++){
  if(!comp[cand]){
   for(var i=0;i<313;i+=cand)comp[i]=cand;
   hh[primeCount]=(mp(cand,0.5)*m232)|0;
   kk[primeCount++]=(mp(cand,1/3)*m232)|0;
  }
 }
 a+="\\x80";
 while(a.length%64-56)a+="\\x00";
 for(var i=0;i<a.length;i++){
  var j=a.charCodeAt(i);
  if(j>>8)return"";
  words[i>>2]|=j<<((3-i)%4)*8;
 }
 words[words.length]=(ab/m232)|0;
 words[words.length]=ab;
 for(var j2=0;j2<words.length;){
  var w=words.slice(j2,j2+=16),oldH=hh;
  hh=hh.slice(0,8);
  for(var i=0;i<64;i++){
   var w15=w[i-15],w2=w[i-2],hv=hh[0],he=hh[4];
   var t1=hh[7]+(rr(he,6)^rr(he,11)^rr(he,25))+((he&hh[5])^((~he)&hh[6]))+kk[i]
    +(w[i]=(i<16)?w[i]:(w[i-16]+(rr(w15,7)^rr(w15,18)^(w15>>>3))+w[i-7]+(rr(w2,17)^rr(w2,19)^(w2>>>10)))|0);
   var t2=(rr(hv,2)^rr(hv,13)^rr(hv,22))+((hv&hh[1])^(hv&hh[2])^(hh[1]&hh[2]));
   hh=[(t1+t2)|0].concat(hh);
   hh[4]=(hh[4]+t1)|0;
  }
  for(var i=0;i<8;i++)hh[i]=(hh[i]+oldH[i])|0;
 }
 for(var i=0;i<8;i++){
  for(var j=3;j+1;j--){
   var b=(hh[i]>>(j*8))&255;
   result+=((b<16)?"0":"")+b.toString(16);
  }
 }
 return result;
}`;

oidcSession.get("/check_session", async (c) => {
  // The marker cookie is what actually reaches this handler inside a
  // cross-origin iframe (SameSite=None); the real session cookie is Lax and
  // stays behind. The session lookup is the fallback for sessions minted
  // before the marker existed.
  const marked = getSessionCheckSid(c.req.raw);
  const session = marked ? null : await getSession(c.req.raw, c.env);
  const sid = marked ?? (session ? await oidcSid(session.id) : "");
  // The marker proves only that a cookie exists, not that the session lives:
  // a server-side revocation (admin sign-out, password change, SSF) cannot
  // clear it, so confirm a live session backs it - otherwise the iframe would
  // keep answering "unchanged" for a dead session until the cookie ages out.
  const live = session !== null || (sid !== "" && (await sessionLiveByOidcSid(c.env, sid)));
  const script = `var OP_SID=document.body.getAttribute("data-sid")||"";
${CHECK_SESSION_SHA256_JS}
window.addEventListener("message",function(e){
 var p=String(e.data).split(" "),cid=p[0],st=(p[1]||"").split("."),salt=st[1];
 function reply(m){if(e.source&&e.origin!=="null")e.source.postMessage(m,e.origin);}
 if(!cid||!salt){reply("error");return;}
 if(!OP_SID){reply("changed");return;}
 reply(sha256(cid+" "+e.origin+" "+OP_SID+" "+salt)===st[0]?"unchanged":"changed");
});`;
  c.header("X-FlareID-Frame-Ancestors", "*");
  return c.html(`<!doctype html><html><head><meta charset="utf-8"><title>check_session</title></head><body data-sid="${escapeHtml(live ? sid : "")}">${scriptTag(script)}</body></html>`);
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
  if (session) {
    // Back-channel first: notifySessionRevoked reads session_clients, which
    // frontchannelTargets then consumes (and deletes) for the iframe page.
    await revokeSession(c.env, session.id);
  }
  const targets = session ? await frontchannelTargets(c.env, session.id) : [];
  if (session) {
    await logAudit(c.env, { id: session.userId, upn: String(session.userId) }, "logout.rp_initiated", clientName, { frontchannel: targets.length }, c.req.raw);
  }
  for (const sc of clearSessionCookies()) c.header("Set-Cookie", sc, { append: true });
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

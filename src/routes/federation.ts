import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { logAudit } from "../lib/audit.js";
import {
  FederationError,
  getUpstreamIdp,
  idpConfig,
  NoLocalAccount,
  oidcAuthorizeUrl,
  oidcCallbackUrl,
  oidcExchange,
  oidcMetadata,
  pkcePair,
  profileFromClaims,
  resolveFederatedUser,
  samlAcsUrl,
  samlRedirectUrl,
  samlSpEntityId,
  storeFedState,
  takeFedState,
  verifySamlResponse,
  type FederatedProfile,
  type OidcIdpConfig,
  type SamlIdpConfig,
} from "../lib/federation.js";
import { appConfigError, AUTH_MESSAGES, renderAuthMessage } from "../lib/login-views.js";
import { getLoginFlow } from "../lib/authorize-state.js";
import { samlPostForm } from "../lib/saml/post-form.js";
import { samlId } from "../lib/saml/xml.js";
import { randomToken } from "../lib/tokens.js";
import { completeLoginFlow } from "./login.js";

/**
 * Inbound federation: the browser-facing half.
 *
 * /login/federated/:id starts the dance - the in-flight login flow, nonce and
 * PKCE verifier (or SAML request id) go into one state record under a random
 * key, and the browser leaves for the upstream IdP. The IdP returns it to
 * /federation/oidc/callback (code + state) or /federation/saml/acs/:id
 * (SAMLResponse + RelayState); the response is verified, the identity resolved
 * to a local account (linked, adopted by address, or JIT-provisioned), and the
 * original login flow completes exactly as a password sign-in would.
 */
export const federation = new Hono<{ Bindings: Env }>();

federation.get("/login/federated/:id", async (c) => {
  const idp = await getUpstreamIdp(c.env, Number(c.req.param("id")));
  const flowId = c.req.query("flow") ?? "";
  const flow = await getLoginFlow(c.env, flowId);
  if (!idp || !idp.enabled || !flow) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const origin = new URL(c.req.url).origin;

  if (idp.protocol === "oidc") {
    const cfg = idpConfig<OidcIdpConfig>(idp);
    let meta;
    try {
      meta = await oidcMetadata(c.env, cfg.issuer);
    } catch (e) {
      return renderAuthMessage(c, 400, appConfigError(e instanceof FederationError ? e.message : "The provider's configuration could not be read."), { domain: flow.brandDomain });
    }
    const { verifier, challenge } = await pkcePair();
    const nonce = randomToken(16);
    const state = await storeFedState(c.env, { flowId, idpId: idp.id, nonce, verifier, brandDomain: flow.brandDomain, locale: flow.locale });
    await logAudit(c.env, null, "federation.start", idp.name, { protocol: "oidc" }, c.req.raw);
    return c.redirect(oidcAuthorizeUrl(meta, cfg, oidcCallbackUrl(origin), state, nonce, challenge), 302);
  }

  const cfg = idpConfig<SamlIdpConfig>(idp);
  const requestId = samlId();
  const state = await storeFedState(c.env, { flowId, idpId: idp.id, requestId, brandDomain: flow.brandDomain, locale: flow.locale });
  const url = await samlRedirectUrl(cfg, samlSpEntityId(c.env.ISSUER_URL, idp.id), samlAcsUrl(origin, idp.id), requestId, state);
  await logAudit(c.env, null, "federation.start", idp.name, { protocol: "saml" }, c.req.raw);
  return c.redirect(url, 302);
});

/**
 * The finish shared by both protocols: resolve the local account and run the
 * rest of the original login flow (MFA gate, session, redirect/POST onwards).
 * `amr` says "external" so the session records an upstream authentication.
 */
async function finishFederatedLogin(c: Context<{ Bindings: Env }>, flowId: string, profile: FederatedProfile, idpId: number) {
  const idp = (await getUpstreamIdp(c.env, idpId))!;
  let user;
  try {
    user = await resolveFederatedUser(c.env, idp, profile);
  } catch (e) {
    if (e instanceof NoLocalAccount) {
      await logAudit(c.env, null, "federation.no_account", profile.subject, { idp: idp.name }, c.req.raw);
      return renderAuthMessage(
        c,
        403,
        appConfigError(`${idp.name} authenticated you, but no account here matches ${profile.email || profile.username || "that identity"}${idp.jit ? "" : ", and this provider does not create accounts"}.`)
      );
    }
    if (e instanceof FederationError) return renderAuthMessage(c, 400, appConfigError(e.message));
    throw e;
  }
  const flow = await getLoginFlow(c.env, flowId);
  if (!flow) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const { outcome, setCookie } = await completeLoginFlow(c.env, flow, user.id, ["ext"], c.req.raw, user);
  c.header("Set-Cookie", setCookie);
  await logAudit(c.env, user, "login.success", user.upn, { amr: ["ext"], via: idp.name }, c.req.raw);
  if (outcome.type === "saml-post") return c.html(samlPostForm(c.get("appName"), outcome.acsUrl, outcome.samlResponse, outcome.relayState));
  return c.redirect(outcome.to, 302);
}

federation.get("/federation/oidc/callback", async (c) => {
  const state = c.req.query("state") ?? "";
  const st = await takeFedState(c.env, state);
  if (!st) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const idp = await getUpstreamIdp(c.env, st.idpId);
  if (!idp || !idp.enabled || idp.protocol !== "oidc") return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const hint = { domain: st.brandDomain };

  const error = c.req.query("error");
  if (error) return renderAuthMessage(c, 400, appConfigError(`The provider refused the request: ${error}${c.req.query("error_description") ? ` - ${c.req.query("error_description")}` : ""}.`), hint);

  const code = c.req.query("code") ?? "";
  if (!code) return renderAuthMessage(c, 400, appConfigError("The provider returned no authorization code."), hint);

  const cfg = idpConfig<OidcIdpConfig>(idp);
  let claims;
  try {
    const meta = await oidcMetadata(c.env, cfg.issuer);
    claims = await oidcExchange(c.env, meta, cfg, code, oidcCallbackUrl(new URL(c.req.url).origin), st.verifier ?? "", st.nonce ?? "");
  } catch (e) {
    await logAudit(c.env, null, "federation.failed", idp.name, { error: e instanceof Error ? e.message : String(e) }, c.req.raw);
    return renderAuthMessage(c, 400, appConfigError(e instanceof FederationError ? e.message : "The provider's response could not be verified."), hint);
  }
  const profile = profileFromClaims(claims, String(claims.sub ?? ""));
  if (!profile.subject) return renderAuthMessage(c, 400, appConfigError("The provider's token carries no subject."), hint);
  return finishFederatedLogin(c, st.flowId, profile, idp.id);
});

federation.post("/federation/saml/acs/:id", async (c) => {
  const idp = await getUpstreamIdp(c.env, Number(c.req.param("id")));
  if (!idp || !idp.enabled || idp.protocol !== "saml") return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const body = await c.req.parseBody();
  const state = String(body.RelayState ?? "");
  const responseB64 = String(body.SAMLResponse ?? "");
  const st = await takeFedState(c.env, state);
  if (!st || st.idpId !== idp.id) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const hint = { domain: st.brandDomain };
  if (!responseB64) return renderAuthMessage(c, 400, appConfigError("The IdP posted no SAML response."), hint);

  const cfg = idpConfig<SamlIdpConfig>(idp);
  const origin = new URL(c.req.url).origin;
  let identity;
  try {
    identity = verifySamlResponse(cfg, responseB64, samlAcsUrl(origin, idp.id), samlSpEntityId(c.env.ISSUER_URL, idp.id), st.requestId);
  } catch (e) {
    await logAudit(c.env, null, "federation.failed", idp.name, { error: e instanceof Error ? e.message : String(e) }, c.req.raw);
    return renderAuthMessage(c, 400, appConfigError(e instanceof FederationError ? e.message : "The SAML response could not be verified."), hint);
  }
  const profile = profileFromClaims(identity.attributes, identity.subject, cfg.attr_map);
  return finishFederatedLogin(c, st.flowId, profile, idp.id);
});

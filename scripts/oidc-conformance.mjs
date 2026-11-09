#!/usr/bin/env node
// Scripted OpenID Connect conformance checks against a running FlareID,
// modelled on the OpenID Foundation's Basic OP test plan (oidcc-basic-
// certification-test-plan). It is not the official suite - that needs a
// browser and an account at certification.openid.net - but it exercises the
// same rules a Basic OP must satisfy, end to end, against a live deployment.
//
//   IDP=https://idp.example.com CLIENT_ID=... CLIENT_SECRET=... \
//   TEST_UPN=user@example.com TEST_PASSWORD=... \
//   REDIRECT_URI=https://conformance.invalid/cb POST_LOGOUT_URI=https://conformance.invalid/bye \
//   node scripts/oidc-conformance.mjs
//
// The client must be confidential and trusted, with REDIRECT_URI and
// POST_LOGOUT_URI registered; the user must be active and have no MFA.
// Exits non-zero if any check fails.
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { createHash, randomBytes } from "node:crypto";

const need = (k) => process.env[k] ?? (console.error(`${k} is required`), process.exit(2));
const IDP = need("IDP").replace(/\/$/, "");
const CLIENT_ID = need("CLIENT_ID");
const CLIENT_SECRET = need("CLIENT_SECRET");
const UPN = need("TEST_UPN");
const PASSWORD = need("TEST_PASSWORD");
const REDIRECT = need("REDIRECT_URI");
const POST_LOGOUT = need("POST_LOGOUT_URI");

const results = [];
function check(id, ok, detail = "") {
  results.push({ id, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${id}${detail ? `  - ${detail}` : ""}`);
}
const warn = (id, detail) => (results.push({ id, ok: true, warn: true, detail }), console.log(`WARN  ${id}  - ${detail}`));
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const basic = "Basic " + Buffer.from(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`).toString("base64");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function authorizeUrl(params = {}) {
  return `${IDP}/authorize?${new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: REDIRECT, response_type: "code", scope: "openid email profile", state: b64url(randomBytes(8)), nonce: b64url(randomBytes(8)), ...params })}`;
}

/** Follows /authorize through the login form (if shown). Returns the redirect back to the RP and the IdP session cookie. */
async function authorize(params = {}, cookie = "") {
  const url = authorizeUrl(params);
  const page = await fetch(url, { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} });
  if (page.status === 302) return { location: new URL(page.headers.get("location"), IDP), cookie, url, showedLogin: false };
  const flowId = /name="flow_id" value="([^"]+)"/.exec(await page.text())?.[1];
  if (!flowId) return { location: null, cookie, url, showedLogin: false, status: page.status };
  const res = await fetch(`${IDP}/login`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: IDP },
    body: new URLSearchParams({ flow_id: flowId, upn: UPN, password: PASSWORD }),
  });
  const set = res.headers.get("set-cookie")?.split(";")[0];
  return { location: res.headers.get("location") ? new URL(res.headers.get("location"), IDP) : null, cookie: set ?? cookie, url, showedLogin: true };
}

async function token(body, auth = "basic") {
  const res = await fetch(`${IDP}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(auth === "basic" ? { Authorization: basic } : {}) },
    body: new URLSearchParams({ ...body, ...(auth === "post" ? { client_id: CLIENT_ID, client_secret: CLIENT_SECRET } : {}) }),
  });
  return { status: res.status, headers: res.headers, json: await res.json().catch(() => ({})) };
}

// ---------------------------------------------------------------- discovery
const discoveryRes = await fetch(`${IDP}/.well-known/openid-configuration`);
const d = await discoveryRes.json();
check("discovery: served as JSON", discoveryRes.ok && (discoveryRes.headers.get("content-type") ?? "").includes("json"));
check("discovery: issuer equals the URL it was fetched from", d.issuer === IDP, d.issuer);
for (const f of ["authorization_endpoint", "token_endpoint", "jwks_uri", "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"]) {
  check(`discovery: required field ${f}`, d[f] !== undefined);
}
check("discovery: userinfo_endpoint (recommended)", Boolean(d.userinfo_endpoint));
check("discovery: response_types_supported includes code", d.response_types_supported?.includes("code"));
check("discovery: RS256 among signing algs", d.id_token_signing_alg_values_supported?.includes("RS256"));
check("discovery: endpoints are https", [d.authorization_endpoint, d.token_endpoint, d.jwks_uri, d.userinfo_endpoint].every((u) => u?.startsWith("https://")));
check("discovery: scopes_supported includes openid", d.scopes_supported?.includes("openid"));
check("discovery: claims_supported lists sub", d.claims_supported?.includes("sub"));
check("discovery: end_session_endpoint present", Boolean(d.end_session_endpoint));

const jwksRes = await fetch(d.jwks_uri);
const jwks = await jwksRes.json();
check("jwks: at least one RSA signing key with kid", Array.isArray(jwks.keys) && jwks.keys.some((k) => k.kty === "RSA" && k.kid && (k.use ?? "sig") === "sig"));
check("jwks: no private key material published", jwks.keys.every((k) => !("d" in k) && !("p" in k) && !("q" in k)));
const JWKS = createRemoteJWKSet(new URL(d.jwks_uri));

// ---------------------------------------------------------------- code flow
const nonce = b64url(randomBytes(12));
const state = b64url(randomBytes(12));
const first = await authorize({ nonce, state });
check("authorize: login form shown without a session", first.showedLogin);
check("authorize: redirects back to the registered redirect_uri", first.location?.origin + first.location?.pathname === REDIRECT, String(first.location));
check("authorize: state echoed unchanged", first.location?.searchParams.get("state") === state);
const code = first.location?.searchParams.get("code");
check("authorize: authorization code issued", Boolean(code));
let cookie = first.cookie;

const t = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT });
check("token: 200 for a valid code (client_secret_basic)", t.status === 200, JSON.stringify(t.json).slice(0, 120));
check("token: token_type Bearer", String(t.json.token_type).toLowerCase() === "bearer");
check("token: Cache-Control no-store (RFC 6749 5.1)", (t.headers.get("cache-control") ?? "").includes("no-store"));
check("token: expires_in present", typeof t.json.expires_in === "number");

let claims = {};
try {
  const { payload, protectedHeader } = await jwtVerify(t.json.id_token, JWKS, { issuer: IDP, audience: CLIENT_ID });
  claims = payload;
  check("id_token: signature verifies against jwks_uri", true);
  check("id_token: header kid matches a published key", jwks.keys.some((k) => k.kid === protectedHeader.kid));
  check("id_token: alg RS256", protectedHeader.alg === "RS256");
} catch (e) {
  check("id_token: signature, iss and aud verify", false, String(e));
}
check("id_token: iss is the issuer", claims.iss === IDP);
check("id_token: aud contains client_id", [].concat(claims.aud).includes(CLIENT_ID));
check("id_token: sub present, at most 255 chars", typeof claims.sub === "string" && claims.sub.length > 0 && claims.sub.length <= 255);
check("id_token: exp in the future, iat in the past", claims.exp > Date.now() / 1000 && claims.iat <= Date.now() / 1000 + 5);
check("id_token: nonce echoed", claims.nonce === nonce);
check("id_token: auth_time present and plausible", typeof claims.auth_time === "number" && claims.auth_time <= Date.now() / 1000 + 5);
check("id_token: azp equals client_id", claims.azp === CLIENT_ID);
const expectedAtHash = b64url(createHash("sha256").update(t.json.access_token ?? "").digest().subarray(0, 16));
check("id_token: at_hash matches the access token", claims.at_hash === expectedAtHash);
check("id_token: acr present", typeof claims.acr === "string");

const reuse = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT });
check("token: a used code is refused (invalid_grant)", reuse.status === 400 && reuse.json.error === "invalid_grant");

// -------------------------------------------------------------- client auth
const second = await authorize({}, cookie);
check("authorize: SSO with an existing session skips the form", !second.showedLogin && Boolean(second.location?.searchParams.get("code")));
const viaPost = await token({ grant_type: "authorization_code", code: second.location?.searchParams.get("code"), redirect_uri: REDIRECT }, "post");
check("token: client_secret_post accepted", viaPost.status === 200);
const badSecret = await fetch(`${IDP}/token`, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "authorization_code", code: "x", redirect_uri: REDIRECT, client_id: CLIENT_ID, client_secret: "wrong" }),
});
check("token: wrong client secret is invalid_client (401)", badSecret.status === 401 && (await badSecret.json()).error === "invalid_client");
const wrongRedirect = await authorize({}, cookie).catch(() => null);
const mismatched = await fetch(authorizeUrl({ redirect_uri: "https://attacker.invalid/cb" }), { redirect: "manual", headers: { Cookie: cookie } });
check("authorize: unregistered redirect_uri is not redirected to", !(mismatched.headers.get("location") ?? "").startsWith("https://attacker.invalid"), `HTTP ${mismatched.status}`);
void wrongRedirect;

// ----------------------------------------------------------------- userinfo
const ui = await fetch(d.userinfo_endpoint, { headers: { Authorization: `Bearer ${t.json.access_token}` } });
const uiJson = await ui.json();
check("userinfo: 200 with a valid access token", ui.status === 200);
check("userinfo: sub matches the id_token", uiJson.sub === claims.sub);
check("userinfo: email released for the email scope", typeof uiJson.email === "string");
const uiBad = await fetch(d.userinfo_endpoint, { headers: { Authorization: "Bearer not-a-token" } });
check("userinfo: invalid token is 401", uiBad.status === 401);
if (!uiBad.headers.get("www-authenticate")) warn("userinfo: WWW-Authenticate on 401 (RFC 6750 3)", "header missing");
else check("userinfo: WWW-Authenticate on 401 (RFC 6750 3)", true);

// -------------------------------------------------------- prompt and max_age
const noSessionNone = await fetch(authorizeUrl({ prompt: "none" }), { redirect: "manual" });
const nsLoc = new URL(noSessionNone.headers.get("location") ?? `${IDP}/`, IDP);
check("prompt=none without a session -> login_required", nsLoc.searchParams.get("error") === "login_required");
const withSessionNone = await authorize({ prompt: "none" }, cookie);
check("prompt=none with a session -> code, no UI", !withSessionNone.showedLogin && Boolean(withSessionNone.location?.searchParams.get("code")));
const login = await authorize({ prompt: "login" }, cookie);
check("prompt=login shows the login form despite a session", login.showedLogin);
cookie = login.cookie;
await sleep(2200);
const aged = await authorize({ max_age: "1" }, cookie);
check("max_age exceeded -> re-authentication", aged.showedLogin);
const agedTokens = await token({ grant_type: "authorization_code", code: aged.location?.searchParams.get("code"), redirect_uri: REDIRECT });
const agedClaims = agedTokens.json.id_token ? decodeJwt(agedTokens.json.id_token) : {};
check("max_age: auth_time reflects the fresh login", agedClaims.auth_time >= Math.floor(Date.now() / 1000) - 10);
cookie = aged.cookie;

const badType = await fetch(authorizeUrl({ response_type: "token" }), { redirect: "manual", headers: { Cookie: cookie } });
check("unsupported response_type -> error to the client", new URL(badType.headers.get("location") ?? `${IDP}/`, IDP).searchParams.get("error") === "unsupported_response_type");
const plain = await fetch(authorizeUrl({ code_challenge: "abc", code_challenge_method: "plain" }), { redirect: "manual", headers: { Cookie: cookie } });
check("PKCE plain is refused (S256 only)", new URL(plain.headers.get("location") ?? `${IDP}/`, IDP).searchParams.get("error") === "invalid_request");

// ------------------------------------------------------------------- refresh
const offline = await authorize({ scope: "openid offline_access" }, cookie);
const off = await token({ grant_type: "authorization_code", code: offline.location?.searchParams.get("code"), redirect_uri: REDIRECT });
check("offline_access: refresh_token issued", Boolean(off.json.refresh_token));
const r1 = await token({ grant_type: "refresh_token", refresh_token: off.json.refresh_token });
check("refresh: new tokens issued", r1.status === 200 && Boolean(r1.json.refresh_token) && r1.json.refresh_token !== off.json.refresh_token);
const r1Claims = r1.json.id_token ? decodeJwt(r1.json.id_token) : {};
check("refresh: id_token keeps iss, sub, aud, and the original auth_time", r1Claims.iss === IDP && r1Claims.sub === claims.sub && r1Claims.auth_time === decodeJwt(off.json.id_token).auth_time);
const replay = await token({ grant_type: "refresh_token", refresh_token: off.json.refresh_token });
check("refresh: a rotated token is refused (reuse detection)", replay.status === 400);
const afterReplay = await token({ grant_type: "refresh_token", refresh_token: r1.json.refresh_token });
check("refresh: reuse revokes the whole family", afterReplay.status === 400);

// -------------------------------------------------------------------- logout
const logoutState = b64url(randomBytes(6));
const finalId = (await token({ grant_type: "authorization_code", code: (await authorize({}, cookie)).location?.searchParams.get("code"), redirect_uri: REDIRECT })).json.id_token;
const out = await fetch(`${d.end_session_endpoint}?${new URLSearchParams({ id_token_hint: finalId, post_logout_redirect_uri: POST_LOGOUT, state: logoutState })}`, {
  redirect: "manual",
  headers: { Cookie: cookie },
});
check("logout: redirects to the registered post_logout_redirect_uri with state", out.headers.get("location") === `${POST_LOGOUT}?state=${logoutState}`, out.headers.get("location") ?? `HTTP ${out.status}`);
const afterLogout = await fetch(authorizeUrl({ prompt: "none" }), { redirect: "manual", headers: { Cookie: cookie } });
check("logout: the session is gone (prompt=none -> login_required)", new URL(afterLogout.headers.get("location") ?? `${IDP}/`, IDP).searchParams.get("error") === "login_required");
const evil = await fetch(`${d.end_session_endpoint}?${new URLSearchParams({ client_id: CLIENT_ID, post_logout_redirect_uri: "https://attacker.invalid/" })}`, { redirect: "manual" });
check("logout: an unregistered post_logout_redirect_uri is not followed", !(evil.headers.get("location") ?? "").startsWith("https://attacker.invalid"));

const failed = results.filter((r) => !r.ok);
const warned = results.filter((r) => r.warn);
console.log(`\n${results.length - failed.length - warned.length} passed, ${warned.length} warnings, ${failed.length} failed`);
process.exit(failed.length ? 1 : 0);

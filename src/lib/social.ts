import { SignJWT, importPKCS8 } from "jose";
import type { Env } from "../env.js";
import { unsealMaybe } from "./sealed.js";
import { FederationError, type OidcIdpConfig } from "./federation.js";

/**
 * Social sign-in: a curated catalog of consumer identity providers, each a
 * preset over the generic upstream-IdP machinery in federation.ts. A
 * configured provider is an ordinary `upstream_idps` row carrying
 * `config.social = <key>`; its protocol details come from this table, never
 * from admin-editable config, so a tampered row cannot redirect the code
 * exchange to a hostile endpoint.
 *
 * Three protocol shapes:
 * - "oidc": discovery-driven, no adapter - the catalog entry only supplies the
 *   issuer and scopes (Google, Microsoft, ...).
 * - "apple": OIDC, but the client_secret is a short-lived ES256 JWT minted
 *   here from the admin's .p8 key.
 * - "oauth2": no id_token at all (GitHub, Discord, X) - the code buys an
 *   access token, a userinfo call is normalized into OIDC-shaped claims.
 */

export interface SocialProvider {
  key: string;
  name: string;
  blurb: string;
  kind: "oidc" | "apple" | "oauth2";
  /** Discovery issuer for oidc/apple; "social:<key>" placeholder for oauth2 (no discovery). */
  issuer: string;
  scopes: string;
  /** Where an admin creates the OAuth app. */
  docsUrl: string;
  registerHint: string;
  /** Extra config field, e.g. Microsoft's tenant. */
  tenant?: { label: string; placeholder: string; help: string };
  /** OAuth2-only endpoints; oauth2 rows never run discovery. */
  endpoints?: { authorize: string; token: string; userinfo: string };
}

export const SOCIAL_PROVIDERS: readonly SocialProvider[] = [
  {
    key: "google",
    name: "Google",
    blurb: "Gmail and Google Workspace accounts.",
    kind: "oidc",
    issuer: "https://accounts.google.com",
    scopes: "openid profile email",
    docsUrl: "https://console.cloud.google.com/apis/credentials",
    registerHint: "Google Cloud console → APIs & Services → Credentials → Create an OAuth client ID (Web application).",
  },
  {
    key: "microsoft",
    name: "Microsoft",
    blurb: "Entra ID work accounts, Outlook.com, Xbox - one registration covers all when the tenant is \"common\".",
    kind: "oidc",
    issuer: "https://login.microsoftonline.com/{tenant}/v2.0",
    scopes: "openid profile email",
    docsUrl: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps",
    registerHint: "Entra admin centre → App registrations → New registration, with a Web redirect URI.",
    tenant: {
      label: "Directory (tenant)",
      placeholder: "common",
      help: "A tenant ID or domain restricts sign-in to that organisation; \"common\" accepts any Microsoft account, \"organizations\" any work account, \"consumers\" personal ones only.",
    },
  },
  {
    key: "apple",
    name: "Apple",
    blurb: "Sign in with Apple. The client secret is an ES256 JWT FlareID mints from your .p8 key at each sign-in.",
    kind: "apple",
    issuer: "https://appleid.apple.com",
    scopes: "openid name email",
    docsUrl: "https://developer.apple.com/account/resources/identifiers",
    registerHint: "Apple Developer → Identifiers: an App ID, a Services ID (its identifier is the client ID) with this redirect URI, and a Sign in with Apple key (.p8).",
  },
  {
    key: "facebook",
    name: "Facebook",
    blurb: "Facebook Login with OpenID Connect.",
    kind: "oidc",
    issuer: "https://www.facebook.com",
    scopes: "openid email",
    docsUrl: "https://developers.facebook.com/apps",
    registerHint: "Meta for Developers → your app → Facebook Login → Settings: add the redirect URI under Valid OAuth Redirect URIs.",
  },
  {
    key: "linkedin",
    name: "LinkedIn",
    blurb: "Sign in with LinkedIn using OpenID Connect.",
    kind: "oidc",
    issuer: "https://www.linkedin.com/oauth",
    scopes: "openid profile email",
    docsUrl: "https://www.linkedin.com/developers/apps",
    registerHint: "LinkedIn developer app → Auth: add the redirect URI and request the \"Sign In with LinkedIn using OpenID Connect\" product.",
  },
  {
    key: "slack",
    name: "Slack",
    blurb: "Sign in with Slack.",
    kind: "oidc",
    issuer: "https://slack.com",
    scopes: "openid profile email",
    docsUrl: "https://api.slack.com/apps",
    registerHint: "Slack app settings → OAuth & Permissions: add the redirect URL.",
  },
  {
    key: "yahoo",
    name: "Yahoo",
    blurb: "Yahoo sign-in over OpenID Connect.",
    kind: "oidc",
    issuer: "https://api.login.yahoo.com",
    scopes: "openid profile email",
    docsUrl: "https://developer.yahoo.com/apps",
    registerHint: "Yahoo developer console → create an app with the OpenID Connect (profile/email) permissions and this callback domain.",
  },
  {
    key: "twitch",
    name: "Twitch",
    blurb: "Twitch accounts over OpenID Connect.",
    kind: "oidc",
    issuer: "https://id.twitch.tv/oauth2",
    scopes: "openid",
    docsUrl: "https://dev.twitch.tv/console/apps",
    registerHint: "Twitch developer console → Register an application with this OAuth redirect URL.",
  },
  {
    key: "line",
    name: "LINE",
    blurb: "LINE Login (popular in Japan and Taiwan).",
    kind: "oidc",
    issuer: "https://access.line.me",
    scopes: "openid profile email",
    docsUrl: "https://developers.line.biz/console/",
    registerHint: "LINE Developers console → a LINE Login channel; set the callback URL and request the email permission.",
  },
  {
    key: "salesforce",
    name: "Salesforce",
    blurb: "Salesforce orgs via an external client app or connected app.",
    kind: "oidc",
    issuer: "https://login.salesforce.com",
    scopes: "openid profile email",
    docsUrl: "https://login.salesforce.com",
    registerHint: "Salesforce Setup → External Client Apps (or Connected Apps) → enable OAuth with this callback URL. For a My Domain org, replace the issuer below with https://<domain>.my.salesforce.com.",
  },
  {
    key: "gitlab",
    name: "GitLab",
    blurb: "gitlab.com or a self-managed GitLab (point the issuer at it).",
    kind: "oidc",
    issuer: "https://gitlab.com",
    scopes: "openid profile email",
    docsUrl: "https://gitlab.com/-/user_settings/applications",
    registerHint: "GitLab → Applications (user or group): redirect URI plus the openid, profile and email scopes.",
  },
  {
    key: "github",
    name: "GitHub",
    blurb: "GitHub accounts. OAuth 2.0 only - FlareID reads the profile (and the primary verified email when it is not public).",
    kind: "oauth2",
    issuer: "social:github",
    scopes: "read:user user:email",
    docsUrl: "https://github.com/settings/developers",
    registerHint: "GitHub → Developer settings → OAuth Apps → New OAuth App, with this Authorization callback URL.",
    endpoints: {
      authorize: "https://github.com/login/oauth/authorize",
      token: "https://github.com/login/oauth/access_token",
      userinfo: "https://api.github.com/user",
    },
  },
  {
    key: "discord",
    name: "Discord",
    blurb: "Discord accounts. OAuth 2.0 only - FlareID reads the @me profile.",
    kind: "oauth2",
    issuer: "social:discord",
    scopes: "identify email",
    docsUrl: "https://discord.com/developers/applications",
    registerHint: "Discord Developer Portal → OAuth2: add this redirect.",
    endpoints: {
      authorize: "https://discord.com/oauth2/authorize",
      token: "https://discord.com/api/v10/oauth2/token",
      userinfo: "https://discord.com/api/v10/users/@me",
    },
  },
  {
    key: "x",
    name: "X (Twitter)",
    blurb: "X accounts. OAuth 2.0 + PKCE - X returns no email address, so accounts link by username or provision without one.",
    kind: "oauth2",
    issuer: "social:x",
    scopes: "users.read tweet.read offline.access",
    docsUrl: "https://developer.x.com/en/portal/dashboard",
    registerHint: "X developer portal → your app → User authentication settings: OAuth 2.0, web app, this callback URI.",
    endpoints: {
      authorize: "https://twitter.com/i/oauth2/authorize",
      token: "https://api.twitter.com/2/oauth2/token",
      userinfo: "https://api.twitter.com/2/users/me",
    },
  },
];

export function socialProvider(key: string | undefined | null): SocialProvider | undefined {
  return key ? SOCIAL_PROVIDERS.find((p) => p.key === key) : undefined;
}

/** Fixed endpoints for an oauth2 provider, in the shape OIDC metadata has. */
export function socialMeta(provider: SocialProvider): { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string } {
  const e = provider.endpoints!;
  return { issuer: provider.issuer, authorization_endpoint: e.authorize, token_endpoint: e.token, jwks_uri: "" };
}

/** A resolved issuer: Microsoft's {tenant} placeholder filled in. */
export function socialIssuer(provider: SocialProvider, tenant?: string): string {
  if (!provider.tenant) return provider.issuer;
  const t = (tenant ?? "").trim() || "common";
  return provider.issuer.replace("{tenant}", encodeURIComponent(t));
}

// ---------------------------------------------------------------------------
// Apple: the client_secret is a JWT, ES256-signed with the developer's key.
// ---------------------------------------------------------------------------

export interface AppleSecretConfig {
  team_id: string;
  key_id: string;
  /** The .p8 contents, sealed at rest like a client_secret. */
  private_key: string;
}

const APPLE_AUD = "https://appleid.apple.com";
/** Apple's ceiling is six months; a shorter window limits a leaked minted secret. */
const APPLE_SECRET_TTL_S = 30 * 86400;

export async function appleClientSecret(env: Env, apple: AppleSecretConfig, clientId: string): Promise<string> {
  const pem = await unsealMaybe(env, apple.private_key);
  if (!pem) throw new FederationError("The Apple private key is not stored.");
  const key = await importPKCS8(pem, "ES256");
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: apple.key_id })
    .setIssuer(apple.team_id)
    .setSubject(clientId)
    .setAudience(APPLE_AUD)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + APPLE_SECRET_TTL_S)
    .sign(key);
}

// ---------------------------------------------------------------------------
// OAuth2-only providers: code -> access token -> userinfo -> OIDC-shaped claims
// ---------------------------------------------------------------------------

const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : "");

async function fetchJson(url: string, headers: Record<string, string>): Promise<unknown> {
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(10_000), redirect: "error" }).catch(() => null);
  if (!res?.ok) throw new FederationError(`The provider's profile endpoint could not be read (${res ? `HTTP ${res.status}` : "timed out"}).`);
  return res.json();
}

/** GitHub: /user, then /user/emails when the profile hides the address. */
async function githubClaims(token: string, userinfo: string): Promise<Record<string, unknown>> {
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "flareid" };
  const u = (await fetchJson(userinfo, headers)) as Record<string, unknown>;
  let email = str(u.email);
  if (!email) {
    const emails = (await fetchJson(`${userinfo}/emails`, headers).catch(() => [])) as { email?: string; primary?: boolean; verified?: boolean }[];
    email = str(emails.find((e) => e.primary && e.verified)?.email) || str(emails.find((e) => e.verified)?.email);
  }
  return { sub: String(u.id ?? ""), email, name: str(u.name), preferred_username: str(u.login), picture: str(u.avatar_url) };
}

/** Discord: @me - global_name is the display name, username the handle. */
async function discordClaims(token: string, userinfo: string): Promise<Record<string, unknown>> {
  const u = (await fetchJson(userinfo, { Authorization: `Bearer ${token}` })) as Record<string, unknown>;
  const id = String(u.id ?? "");
  return {
    sub: id,
    email: u.verified === false ? "" : str(u.email),
    name: str(u.global_name) || str(u.username),
    preferred_username: str(u.username),
    picture: u.avatar ? `https://cdn.discordapp.com/avatars/${id}/${String(u.avatar)}.png` : "",
  };
}

/** X: /2/users/me - the API never returns an email address. */
async function xClaims(token: string, userinfo: string): Promise<Record<string, unknown>> {
  const res = (await fetchJson(`${userinfo}?user.fields=name,username,profile_image_url`, { Authorization: `Bearer ${token}` })) as { data?: Record<string, unknown> };
  const u = res.data ?? {};
  return { sub: String(u.id ?? ""), name: str(u.name), preferred_username: str(u.username), picture: str(u.profile_image_url) };
}

const CLAIM_READERS: Record<string, (token: string, userinfo: string) => Promise<Record<string, unknown>>> = {
  github: githubClaims,
  discord: discordClaims,
  x: xClaims,
};

/**
 * The full exchange for an oauth2 provider: the code buys an access token,
 * then the provider's claim reader normalizes its profile into the claim
 * names profileFromClaims expects. X authenticates the token call with HTTP
 * Basic when a secret is set (it treats the client as confidential); GitHub
 * and Discord take it in the form like an OIDC exchange.
 */
export async function socialExchange(env: Env, provider: SocialProvider, cfg: OidcIdpConfig, code: string, callbackUrl: string, verifier: string): Promise<Record<string, unknown>> {
  const e = provider.endpoints!;
  const secret = await unsealMaybe(env, cfg.client_secret);
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: callbackUrl, code_verifier: verifier });
  if (provider.key === "x") {
    if (secret) headers.Authorization = `Basic ${btoa(`${cfg.client_id}:${secret}`)}`;
    else body.set("client_id", cfg.client_id);
  } else {
    body.set("client_id", cfg.client_id);
    if (secret) body.set("client_secret", secret);
  }
  const res = await fetch(e.token, { method: "POST", headers, body, signal: AbortSignal.timeout(10_000), redirect: "error" }).catch(() => null);
  if (!res?.ok) throw new FederationError(`The code exchange failed (${res ? `HTTP ${res.status}` : "timed out"}).`);
  const tokens = (await res.json()) as { access_token?: string; error?: string };
  if (!tokens.access_token) throw new FederationError(`The provider did not return an access token${tokens.error ? ` (${tokens.error})` : ""}.`);
  const claims = await CLAIM_READERS[provider.key]!(tokens.access_token, e.userinfo);
  if (!claims.sub) throw new FederationError("The provider's profile carries no subject.");
  return claims;
}

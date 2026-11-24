import { DOMParser, type Element as XmlElement, type Node as XmlNode } from "@xmldom/xmldom";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { SignedXml } from "xml-crypto";
import { normalizeCertPem } from "./saml/x509.js";
import { grantsAdminRoleGroup, grantsWritePermission, rolePermissions } from "./admin-roles.js";
import type { Env } from "../env.js";
import { defaultSchemaId } from "./schemas.js";
import { getUserByLoginIdentifier } from "./db.js";
import { domainExists } from "./domains.js";
import { getUserByAnyEmail } from "./user-emails.js";
import { randomToken } from "./tokens.js";
import { sealMaybe, unsealMaybe } from "./sealed.js";
import { appleClientSecret, socialProvider, type AppleSecretConfig } from "./social.js";
import { claimOnce } from "./one-shot.js";
import type { UserRow } from "./types.js";
import { effectiveMappings, getCollisionPolicy, JIT_COLUMN_TARGETS, resolveIdentifierCollision, resolveUsernameCollision } from "./mappings.js";
import { parseIdentifier } from "./identifier.js";
import { evalExpression, parseExpression, scalar, strOf } from "./expr.js";

/**
 * Inbound federation: sign in *through* an upstream identity provider.
 *
 * FlareID is the OIDC provider and SAML IdP for downstream apps; this module
 * is the reverse - a relying party toward OIDC providers and a service
 * provider toward SAML IdPs - so an organisation that already has an IdP can
 * put FlareID behind it. Each `upstream_idps` row is one upstream IdP; a
 * `federated_identities` row binds an upstream subject (OIDC `sub`, SAML
 * NameID) to a local account, made on first sign-in by an address match or
 * by JIT provisioning.
 */

export interface UpstreamIdpRow {
  id: number;
  name: string;
  protocol: "oidc" | "saml";
  enabled: number;
  config: string;
  jit: number;
  jit_domain: string | null;
  /** JSON array of group ids every JIT-provisioned account joins at creation. */
  jit_groups: string;
  created_at: string;
  updated_at: string;
}

export interface OidcIdpConfig {
  issuer: string;
  client_id: string;
  client_secret: string;
  scopes?: string;
  /** Social-provider key from lib/social.ts; set on rows the Social sign-in section manages. */
  social?: string;
  /** Apple: the client_secret is generated from this key material at exchange time. */
  apple?: { team_id: string; key_id: string; private_key: string };
}

export interface SamlIdpConfig {
  idp_entity_id: string;
  sso_url: string;
  certificate: string;
  nameid_format?: string;
  /** attribute-name -> FlareID field overrides; defaults cover the common OIDs. */
  attr_map?: Record<string, string>;
}

export type UpstreamIdpConfig = OidcIdpConfig | SamlIdpConfig;

export class FederationError extends Error {}

const now = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Configuration CRUD
// ---------------------------------------------------------------------------

export async function listUpstreamIdps(env: Env): Promise<UpstreamIdpRow[]> {
  return (await env.DB.prepare("SELECT * FROM upstream_idps ORDER BY name").all<UpstreamIdpRow>()).results;
}

export async function getUpstreamIdp(env: Env, id: number): Promise<UpstreamIdpRow | null> {
  return env.DB.prepare("SELECT * FROM upstream_idps WHERE id = ?").bind(id).first<UpstreamIdpRow>();
}

export function idpConfig<T extends UpstreamIdpConfig>(idp: UpstreamIdpRow): T {
  return JSON.parse(idp.config) as T;
}

export interface UpstreamIdpInput {
  name: string;
  protocol: "oidc" | "saml";
  config: Record<string, string | Record<string, string>>;
  jit: boolean;
  jitDomain: string;
  /** Group ids every JIT account joins; absent means none. */
  jitGroups?: number[];
}

/** The most groups one provider's JIT list may name. */
export const MAX_JIT_GROUPS = 32;

/** The group ids a provider's JIT accounts join, parsed from the stored JSON. */
export function upstreamJitGroups(idp: Pick<UpstreamIdpRow, "jit_groups">): number[] {
  try {
    const v = JSON.parse(idp.jit_groups || "[]") as unknown;
    return Array.isArray(v) ? v.map(Number).filter((n) => Number.isInteger(n) && n > 0) : [];
  } catch {
    return [];
  }
}

/** Validates and normalizes an upstream IdP definition; throws FederationError on bad input. */
export async function validateUpstreamIdp(env: Env, input: UpstreamIdpInput, existingId?: number): Promise<UpstreamIdpRow> {
  const name = input.name.trim();
  if (!name) throw new FederationError("A name is required.");
  const dup = await env.DB.prepare("SELECT id FROM upstream_idps WHERE name = ? AND id != ?").bind(name, existingId ?? -1).first();
  if (dup) throw new FederationError(`An upstream IdP named "${name}" already exists.`);
  const jitDomain = input.jitDomain.trim().toLowerCase();
  if (jitDomain && !(await domainExists(env, jitDomain))) throw new FederationError(`"${jitDomain}" is not a managed domain - JIT accounts could never be created under it.`);

  // jit_groups: the admin's explicit pick of groups every JIT account joins.
  // Each id must be a real group, and - unlike the claim-derived rules
  // checked at provisioning time - a group may grant an admin role, but only
  // a read-only one: a write-capable role would let whoever can save this
  // provider hand admin write power to every account the upstream asserts.
  const jitGroups = [...new Set((input.jitGroups ?? []).map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  if (jitGroups.length > MAX_JIT_GROUPS) throw new FederationError(`At most ${MAX_JIT_GROUPS} JIT groups.`);
  if (jitGroups.length) {
    const { results: groups } = await env.DB.prepare("SELECT id FROM groups WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(jitGroups)).all<{ id: number }>();
    const found = new Set(groups.map((g) => g.id));
    const missing = jitGroups.filter((id) => !found.has(id));
    if (missing.length) throw new FederationError(`Unknown group id${missing.length === 1 ? "" : "s"}: ${missing.join(", ")}.`);
    const { results: roleGrants } = await env.DB
      .prepare(
        `SELECT g.name AS group_name, r.name AS role_name, r.permissions
         FROM admin_role_groups rg JOIN admin_roles r ON r.id = rg.role_id JOIN groups g ON g.id = rg.group_id
         WHERE rg.group_id IN (SELECT value FROM json_each(?))`
      )
      .bind(JSON.stringify(jitGroups))
      .all<{ group_name: string; role_name: string; permissions: string }>();
    const bad = roleGrants.find((r) => grantsWritePermission(rolePermissions(r)));
    if (bad) throw new FederationError(`The group "${bad.group_name}" grants the "${bad.role_name}" role, which can change things - pick a group whose roles are read-only (*:read), or make the role read-only first.`);
  }
  const jitGroupsJson = JSON.stringify(jitGroups);

  if (input.protocol === "oidc") {
    const cfg = input.config as Partial<OidcIdpConfig>;
    const issuer = (cfg.issuer ?? "").trim().replace(/\/+$/, "");
    const social = cfg.social ? socialProvider(cfg.social) : undefined;
    if (cfg.social && !social) throw new FederationError(`Unknown social provider "${cfg.social}".`);
    // OAuth2-only providers never run discovery - their issuer is the
    // catalog's "social:<key>" placeholder, kept only for display.
    if (social?.kind !== "oauth2" && (!issuer || !/^https:\/\//.test(issuer))) throw new FederationError("The issuer must be an https:// URL.");
    if (!(cfg.client_id ?? "").trim()) throw new FederationError("A client id is required.");
    const apple = social?.kind === "apple" ? cfg.apple : undefined;
    if (social?.kind === "apple" && !(apple?.team_id?.trim() && apple?.key_id?.trim())) throw new FederationError("Apple needs the developer Team ID and the Sign in with Apple key's Key ID.");
    const config: OidcIdpConfig = {
      issuer,
      client_id: cfg.client_id!.trim(),
      client_secret: cfg.client_secret ? await sealMaybe(env, cfg.client_secret) : "",
      ...(cfg.scopes?.trim() ? { scopes: cfg.scopes.trim() } : {}),
      ...(social ? { social: social.key } : {}),
      ...(apple
        ? {
            apple: {
              team_id: apple.team_id!.trim(),
              key_id: apple.key_id!.trim(),
              private_key: apple.private_key?.trim() ? await sealMaybe(env, apple.private_key.trim()) : "",
            },
          }
        : {}),
    };
    return { id: existingId ?? 0, name, protocol: "oidc", enabled: 1, config: JSON.stringify(config), jit: input.jit ? 1 : 0, jit_domain: jitDomain || null, jit_groups: jitGroupsJson, created_at: "", updated_at: "" };
  }

  const cfg = input.config as Partial<SamlIdpConfig>;
  const ssoUrl = (cfg.sso_url ?? "").trim();
  if (!ssoUrl || !/^https:\/\//.test(ssoUrl)) throw new FederationError("The SSO URL must be an https:// URL.");
  const certificate = normalizeCertPem(cfg.certificate ?? "");
  if (!certificate) throw new FederationError("The signing certificate could not be parsed - paste the PEM or bare base64 DER.");
  const config: SamlIdpConfig = {
    idp_entity_id: (cfg.idp_entity_id ?? "").trim(),
    sso_url: ssoUrl,
    certificate,
    ...(cfg.nameid_format?.trim() ? { nameid_format: cfg.nameid_format.trim() } : {}),
    ...(cfg.attr_map && Object.keys(cfg.attr_map).length ? { attr_map: cfg.attr_map } : {}),
  };
  return { id: existingId ?? 0, name, protocol: "saml", enabled: 1, config: JSON.stringify(config), jit: input.jit ? 1 : 0, jit_domain: jitDomain || null, jit_groups: jitGroupsJson, created_at: "", updated_at: "" };
}

export async function createUpstreamIdp(env: Env, input: UpstreamIdpInput): Promise<UpstreamIdpRow> {
  const v = await validateUpstreamIdp(env, input);
  const t = now();
  const { meta } = await env.DB.prepare("INSERT INTO upstream_idps (name, protocol, enabled, config, jit, jit_domain, jit_groups, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)")
    .bind(v.name, v.protocol, v.config, v.jit, v.jit_domain, v.jit_groups, t, t)
    .run();
  return (await getUpstreamIdp(env, Number(meta.last_row_id)))!;
}

export async function updateUpstreamIdp(env: Env, id: number, input: UpstreamIdpInput & { enabled: boolean; keepSecret?: boolean }): Promise<UpstreamIdpRow> {
  const existing = await getUpstreamIdp(env, id);
  if (!existing) throw new FederationError("That upstream IdP doesn't exist any more.");
  const v = await validateUpstreamIdp(env, input, id);
  // An empty secret on an OIDC update keeps the stored one - and the Apple key.
  if (input.protocol === "oidc" && input.keepSecret) {
    const prev = idpConfig<OidcIdpConfig>(existing);
    const next = idpConfig<OidcIdpConfig>(v as UpstreamIdpRow);
    const merged = { ...next, client_secret: next.client_secret || prev.client_secret };
    if (next.apple) merged.apple = { ...next.apple, private_key: next.apple.private_key || prev.apple?.private_key || "" };
    v.config = JSON.stringify(merged);
  }
  await env.DB.prepare("UPDATE upstream_idps SET name = ?, protocol = ?, enabled = ?, config = ?, jit = ?, jit_domain = ?, jit_groups = ?, updated_at = ? WHERE id = ?")
    .bind(v.name, v.protocol, input.enabled ? 1 : 0, v.config, v.jit, v.jit_domain, v.jit_groups, now(), id)
    .run();
  return (await getUpstreamIdp(env, id))!;
}

export async function deleteUpstreamIdp(env: Env, id: number): Promise<boolean> {
  return (await env.DB.prepare("DELETE FROM upstream_idps WHERE id = ?").bind(id).run()).meta.changes > 0;
}

// ---------------------------------------------------------------------------
// The round-trip state: what an in-flight federation must remember.
// ---------------------------------------------------------------------------

export interface FedState {
  /** The login flow the person was in (sealed or KV id) - resumed on return. */
  flowId: string;
  idpId: number;
  /** OIDC nonce + PKCE verifier, or the SAML request ID we sent. */
  nonce?: string;
  verifier?: string;
  requestId?: string;
  brandDomain?: string;
  locale?: string;
}

const FED_TTL_SECONDS = 600;

export async function storeFedState(env: Env, state: FedState): Promise<string> {
  const key = randomToken(16);
  await env.SESSIONS_KV.put(`fed:${key}`, JSON.stringify(state), { expirationTtl: FED_TTL_SECONDS });
  return key;
}

/** One-shot: a callback state is consumed, never replayed. */
export async function takeFedState(env: Env, key: string): Promise<FedState | null> {
  const raw = await claimOnce(env, `fed:${key}`);
  return raw ? (JSON.parse(raw) as FedState) : null;
}

// ---------------------------------------------------------------------------
// OIDC relying party
// ---------------------------------------------------------------------------

interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

/** The provider's discovery document, cached in KV for an hour - failures for one minute, so a stalling or down upstream doesn't get re-fetched by every anonymous sign-in attempt. */
export async function oidcMetadata(env: Env, issuer: string): Promise<OidcMetadata> {
  const kvKey = `fed:meta:${issuer}`;
  const cached = await env.SESSIONS_KV.get(kvKey);
  if (cached === "!") throw new FederationError("The provider's discovery document could not be fetched (upstream error).");
  if (cached) return JSON.parse(cached) as OidcMetadata;
  let res: Response | null = null;
  try {
    res = await fetch(`${issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000), redirect: "error" });
  } catch {
    // res stays null - timeout or network failure, negative-cached below.
  }
  if (!res || !res.ok) {
    await env.SESSIONS_KV.put(kvKey, "!", { expirationTtl: 60 });
    throw new FederationError(`The provider's discovery document could not be fetched (${res ? `HTTP ${res.status}` : "timed out"}).`);
  }
  const meta = (await res.json()) as Partial<OidcMetadata>;
  if (!meta.authorization_endpoint || !meta.token_endpoint || !meta.jwks_uri) throw new FederationError("The provider's discovery document is missing endpoints.");
  const out: OidcMetadata = {
    issuer: meta.issuer ?? issuer,
    authorization_endpoint: meta.authorization_endpoint,
    token_endpoint: meta.token_endpoint,
    jwks_uri: meta.jwks_uri,
  };
  await env.SESSIONS_KV.put(kvKey, JSON.stringify(out), { expirationTtl: 3600 });
  return out;
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function oidcCallbackUrl(origin: string): string {
  return `${origin}/federation/oidc/callback`;
}

/** The upstream authorize URL, PKCE-protected: a public-client-grade flow even when there is a secret. */
export function oidcAuthorizeUrl(meta: OidcMetadata, cfg: OidcIdpConfig, callbackUrl: string, state: string, nonce: string, challenge: string): string {
  const u = new URL(meta.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.client_id);
  u.searchParams.set("redirect_uri", callbackUrl);
  u.searchParams.set("scope", cfg.scopes ?? "openid profile email");
  u.searchParams.set("state", state);
  if (nonce) u.searchParams.set("nonce", nonce);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}

/** Exchange the code and verify the id_token; returns its claims. */
export async function oidcExchange(env: Env, meta: OidcMetadata, cfg: OidcIdpConfig, code: string, callbackUrl: string, verifier: string, expectedNonce: string): Promise<JWTPayload> {
  const clientSecret = cfg.apple ? await appleClientSecret(env, cfg.apple, cfg.client_id) : await unsealMaybe(env, cfg.client_secret);
  const res = await fetch(meta.token_endpoint, {
    method: "POST",
    signal: AbortSignal.timeout(10_000),
    // A 307/308 from a discovery-supplied endpoint must not forward the code
    // and client_secret to a different origin.
    redirect: "error",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl,
      client_id: cfg.client_id,
      ...(clientSecret ? { client_secret: clientSecret } : {}),
      code_verifier: verifier,
    }),
  });
  if (!res.ok) throw new FederationError(`The code exchange failed (HTTP ${res.status}).`);
  const tokens = (await res.json()) as { id_token?: string; error?: string };
  if (!tokens.id_token) throw new FederationError(`The provider did not return an id_token${tokens.error ? ` (${tokens.error})` : ""}.`);
  const { payload } = await jwtVerify(tokens.id_token, createRemoteJWKSet(new URL(meta.jwks_uri), { timeoutDuration: 10_000 }), {
    issuer: meta.issuer,
    audience: cfg.client_id,
  });
  if (payload.nonce !== expectedNonce) throw new FederationError("The provider's nonce does not match the request.");
  return payload;
}

// ---------------------------------------------------------------------------
// SAML service provider
// ---------------------------------------------------------------------------

const SAML_SP_ENTITY_SUFFIX = "federation/saml";
export function samlSpEntityId(issuer: string, idpId: number): string {
  return `${issuer.replace(/\/+$/, "")}/${SAML_SP_ENTITY_SUFFIX}/${idpId}`;
}
export function samlAcsUrl(origin: string, idpId: number): string {
  return `${origin}/federation/saml/acs/${idpId}`;
}

/** The IdP-redirect URL carrying a DEFLATEd AuthnRequest (HTTP-Redirect binding). */
export async function samlRedirectUrl(cfg: SamlIdpConfig, spEntityId: string, acsUrl: string, requestId: string, relayState: string): Promise<string> {
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${requestId}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}"` +
    ` Destination="${cfg.sso_url.replace(/&/g, "&amp;").replace(/"/g, "&quot;")}" AssertionConsumerServiceURL="${acsUrl}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
    `<saml:Issuer>${spEntityId}</saml:Issuer>` +
    `<samlp:NameIDPolicy Format="${cfg.nameid_format ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}" AllowCreate="true"/></samlp:AuthnRequest>`;
  const compressed = await new Response(new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer();
  const u = new URL(cfg.sso_url);
  let bin = "";
  for (const b of new Uint8Array(compressed)) bin += String.fromCharCode(b);
  u.searchParams.set("SAMLRequest", btoa(bin));
  u.searchParams.set("RelayState", relayState);
  return u.toString();
}

export interface SamlIdentity {
  subject: string;
  attributes: Record<string, string[]>;
  sessionIndex?: string;
}

const CLOCK_SKEW_MS = 5 * 60 * 1000;

/** Validates an inbound SAML Response (or bare Assertion) against the configured IdP certificate. */
export function verifySamlResponse(cfg: SamlIdpConfig, responseB64: string, acsUrl: string, spEntityId: string, expectedRequestId?: string): SamlIdentity {
  let xml: string;
  try {
    xml = new TextDecoder().decode(Uint8Array.from(atob(responseB64), (ch) => ch.charCodeAt(0)));
  } catch {
    throw new FederationError("The SAML response was not valid base64.");
  }
  if (xml.length > 256 * 1024) throw new FederationError("The SAML response is too large.");
  const doc = new DOMParser().parseFromString(xml, "text/xml");

  const responseEls = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "Response");
  const assertionEls = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
  const root = responseEls[0] ?? assertionEls[0];
  if (!root) throw new FederationError("No SAML Response or Assertion in the document.");

  // Signature: the Response or the Assertion must be signed - either way the
  // signed element's digest+signature is validated against the IdP cert.
  // getCertFromKeyInfo is forced null: without it xml-crypto would verify
  // against whatever X509Certificate the document embeds, letting an attacker
  // self-sign. Verification must pin the configured IdP certificate.
  const sigs = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
  if (sigs.length === 0) throw new FederationError("The SAML response is unsigned.");
  let verified = false;
  let signedIds: string[] = [];
  for (let i = 0; i < sigs.length && !verified; i++) {
    const sig = new SignedXml({ publicCert: cfg.certificate, getCertFromKeyInfo: () => null });
    sig.loadSignature(sigs[i]!.toString());
    try {
      verified = sig.checkSignature(xml);
      if (verified) signedIds = sig.getReferences().map((r) => r.uri ?? "").filter((u) => u.startsWith("#")).map((u) => u.slice(1));
    } catch {
      verified = false;
    }
  }
  if (!verified) throw new FederationError("The SAML signature did not verify.");

  const assertion = assertionEls[0];
  if (!assertion) throw new FederationError("The response carries no assertion.");

  // Wrapping check: the assertion we read must be the signed element, or sit
  // inside it (a signed Response wrapping its assertion). Otherwise a forged
  // unsigned sibling could ride next to a validly-signed decoy.
  const covered = signedIds.some((id) => {
    let node: XmlNode | null = assertion;
    while (node && node.nodeType === 1) {
      const el = node as XmlElement;
      if (el.getAttribute("ID") === id || el.getAttribute("Id") === id || el.getAttribute("id") === id) return true;
      node = node.parentNode;
    }
    return false;
  });
  if (!covered) throw new FederationError("The assertion is not covered by the signature.");

  // Issuer, when the upstream declares one.
  const issuerEls = assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
  if (cfg.idp_entity_id && issuerEls[0]?.textContent?.trim() !== cfg.idp_entity_id) throw new FederationError("The assertion came from a different IdP.");

  // Conditions: window and audience. A signed assertion without Conditions
  // carries no expiry at all - it is replayable forever, so it is refused
  // rather than accepted.
  const t = Date.now();
  const condEls = assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Conditions");
  const cond = condEls[0] as XmlElement | undefined;
  if (!cond) throw new FederationError("The assertion has no Conditions element.");
  {
    const nb = cond.getAttribute("NotBefore");
    const noa = cond.getAttribute("NotOnOrAfter");
    const nbT = nb ? Date.parse(nb) : null;
    const noaT = noa ? Date.parse(noa) : null;
    if (nb && (nbT === null || Number.isNaN(nbT) || t + CLOCK_SKEW_MS < nbT)) throw new FederationError("The assertion is not valid yet.");
    if (noa && (noaT === null || Number.isNaN(noaT) || t - CLOCK_SKEW_MS >= noaT)) throw new FederationError("The assertion has expired.");
  }
  const audEls = assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Audience");
  if (audEls.length > 0 && ![...Array(audEls.length)].some((_, i) => audEls[i]!.textContent?.trim() === spEntityId)) {
    throw new FederationError("The assertion is addressed to a different service provider.");
  }

  // SubjectConfirmation: recipient and replay binding. The bearer profile
  // requires it - an assertion without one is not bound to this ACS or
  // request and can be replayed anywhere.
  const scdEls = assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmationData");
  const scd = scdEls[0] as XmlElement | undefined;
  if (!scd) throw new FederationError("The assertion has no SubjectConfirmationData.");
  {
    const recipient = scd.getAttribute("Recipient");
    if (recipient && recipient !== acsUrl) throw new FederationError("The assertion was issued for a different recipient.");
    const inResponseTo = scd.getAttribute("InResponseTo");
    if (expectedRequestId && inResponseTo !== expectedRequestId) throw new FederationError("The assertion answers a different request.");
    const noa = scd.getAttribute("NotOnOrAfter");
    const noaT = noa ? Date.parse(noa) : null;
    if (noa && (noaT === null || Number.isNaN(noaT) || t - CLOCK_SKEW_MS >= noaT)) throw new FederationError("The assertion has expired.");
  }

  const nameIdEls = assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
  const subject = nameIdEls[0]?.textContent?.trim();
  if (!subject) throw new FederationError("The assertion has no NameID.");

  const attributes: Record<string, string[]> = {};
  const attrEls = assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
  for (let i = 0; i < attrEls.length; i++) {
    const el = attrEls[i] as XmlElement;
    const name = el.getAttribute("Name") ?? el.getAttribute("FriendlyName") ?? "";
    if (!name) continue;
    const values = el.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
    attributes[name] = [...Array(values.length)].map((_, j) => values[j]!.textContent ?? "");
    const friendly = el.getAttribute("FriendlyName");
    if (friendly && friendly !== name && !(friendly in attributes)) attributes[friendly] = attributes[name]!;
  }

  return { subject, attributes };
}

// ---------------------------------------------------------------------------
// Claims -> identity
// ---------------------------------------------------------------------------

/** The common claim/attribute spellings, in preference order, for each field. */
const CLAIM_NAMES = {
  email: ["email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"],
  given: ["given_name", "givenname", "givenName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42"],
  family: ["family_name", "surname", "familyName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4"],
  display: ["name", "display_name", "displayName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "urn:oid:2.16.840.1.113730.3.1.241"],
  username: ["preferred_username", "upn", "username", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "urn:oid:0.9.2342.19200300.100.1.1"],
} as const;

export interface FederatedProfile {
  subject: string;
  email: string;
  username: string;
  givenName: string;
  familyName: string;
  displayName: string;
  /** The IdP's email_verified claim, when it asserts one - false means the address must not be trusted for account matching. */
  emailVerified?: boolean;
  /** Scalar user columns the IdP's JIT mappings produced (job_title, department...). */
  cols?: Record<string, string>;
  /** custom.* attributes the JIT mappings produced. */
  custom?: Record<string, string>;
}

function first(claims: Record<string, unknown>, names: readonly string[]): string {
  for (const n of names) {
    const v = claims[n];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (Array.isArray(v) && typeof v[0] === "string" && v[0].trim()) return v[0].trim();
  }
  return "";
}

/** Turns upstream claims (id_token payload or SAML attributes) into a profile. */
export function profileFromClaims(claims: Record<string, unknown>, subject: string, attrMap?: Record<string, string>): FederatedProfile {
  const mapped = { ...claims };
  if (attrMap) for (const [k, target] of Object.entries(attrMap)) if (claims[k] !== undefined) mapped[target] = claims[k];
  const email = first(mapped, CLAIM_NAMES.email);
  let username = first(mapped, CLAIM_NAMES.username);
  if (!username && email.includes("@")) username = email;
  const display = first(mapped, CLAIM_NAMES.display);
  const given = first(mapped, CLAIM_NAMES.given) || display.split(/\s+/)[0] || username.split("@")[0] || "User";
  const family = first(mapped, CLAIM_NAMES.family) || display.split(/\s+/).slice(1).join(" ");
  const ev = claims["email_verified"];
  return {
    subject,
    email: email.toLowerCase(),
    username: username.toLowerCase(),
    givenName: given,
    familyName: family,
    displayName: display || `${given} ${family}`.trim(),
    emailVerified: ev === undefined ? undefined : ev === true || ev === "true",
  };
}

/**
 * profileFromClaims with the IdP's JIT mappings applied: the `jit` mapping
 * channel's rows (the IdP's own set, else the seeded global set) evaluate over
 * the claims and override whichever profile fields they produce. Rows that
 * yield nothing leave the built-in derivation in place, so the pure function
 * stays the floor the way the hardcoded claim lists were before the channel
 * existed.
 */
export async function mappedProfileFromClaims(
  env: Env,
  claims: Record<string, unknown>,
  subject: string,
  attrMap?: Record<string, string>,
  idpId?: number
): Promise<FederatedProfile> {
  const mapped = { ...claims };
  if (attrMap) for (const [k, t] of Object.entries(attrMap)) if (claims[k] !== undefined) mapped[t] = claims[k];
  const rows = await effectiveMappings(env, "jit", idpId ? String(idpId) : "");
  const base = profileFromClaims(mapped, subject);
  if (!rows.length) return base;
  const profile: FederatedProfile = { ...base, cols: {}, custom: {} };
  for (const row of rows) {
    if (!row.enabled) continue;
    let value: unknown;
    try {
      value = evalExpression(parseExpression(row.expression), mapped);
    } catch {
      continue; // a bad stored expression must not take sign-in down
    }
    const s = strOf(scalar(value)).trim();
    if (!s) continue;
    if (row.target === "email") profile.email = s.toLowerCase();
    else if (row.target === "username") profile.username = s.toLowerCase();
    else if (row.target === "display_name") profile.displayName = s;
    else if (row.target === "given_name") profile.givenName = s;
    else if (row.target === "family_name") profile.familyName = s;
    else if (row.target.startsWith("custom.")) profile.custom![row.target.slice(7)] = s;
    else if (JIT_COLUMN_TARGETS.has(row.target)) profile.cols![row.target] = s;
  }
  return profile;
}

// ---------------------------------------------------------------------------
// Resolving the profile to a local account
// ---------------------------------------------------------------------------

export class NoLocalAccount extends Error {
  constructor(public profile: FederatedProfile) {
    super("No local account for this identity.");
  }
}

/**
 * The first factor's answer to "who is this?": an existing federated link, an
 * address match (adopting the account and linking it), or - with JIT on - a
 * new account. A disabled account never signs in.
 */
export async function resolveFederatedUser(env: Env, idp: UpstreamIdpRow, profile: FederatedProfile): Promise<UserRow> {
  const link = await env.DB.prepare("SELECT user_id FROM federated_identities WHERE idp_id = ? AND subject = ?").bind(idp.id, profile.subject).first<{ user_id: number }>();
  if (link) {
    const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(link.user_id).first<UserRow>();
    if (user && user.status === "active") {
      await env.DB.prepare("UPDATE federated_identities SET last_login_at = ?, email = ? WHERE idp_id = ? AND subject = ?").bind(now(), profile.email || null, idp.id, profile.subject).run();
      return user;
    }
    throw new NoLocalAccount(profile);
  }

  // No link yet: adopt by identity, in order - a UPN already here, then any
  // contact address. An ambiguous or absent match falls through to JIT. An
  // address the IdP explicitly calls unverified is never an adoption key -
  // a claim the user could set themselves would link their login to a
  // stranger's account.
  let user = profile.username && profile.username.includes("@") ? await getUserByLoginIdentifier(env, profile.username) : null;
  if (!user && profile.email && profile.emailVerified !== false) user = await getUserByAnyEmail(env, profile.email);

  if (user) {
    if (user.status !== "active") throw new NoLocalAccount(profile);
    await linkIdentity(env, idp.id, profile, user.id);
    return user;
  }

  if (!idp.jit) throw new NoLocalAccount(profile);

  // JIT mints the upstream identifier verbatim: an @-form profile name is the
  // account's UPN (the domain does not have to be managed - the name is what
  // the IdP calls this user, not an address we serve); a bare handle mints
  // `{handle}-{idp-slug}` so GitHub's simon and GitLab's simon stay distinct
  // and self-describing. No usable profile name falls back to a UPN under a
  // managed domain as before.
  const idpSlug = idp.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || `idp${idp.id}`;
  const policy = await getCollisionPolicy(env);
  let upn: string;
  let candidate: string;
  const profileIdent = profile.username ? parseIdentifier(profile.username) : null;
  const handlePart = profile.username && !profile.username.includes("@")
    ? profile.username.toLowerCase().replace(/[^a-z0-9._-]/g, "").replace(/^[^a-z0-9]+/, "")
    : "";
  const mint = profileIdent?.kind === "upn" ? profileIdent
    : handlePart ? parseIdentifier(`${handlePart}-${idpSlug}`) : null;
  if (mint) {
    const resolved = await resolveIdentifierCollision(env, mint, { idp: idpSlug, email: profile.email }, policy);
    if (!resolved) throw new FederationError("JIT provisioning can't create the account: its sign-in name collides with an existing user.");
    upn = resolved;
    candidate = parseIdentifier(resolved)!.username;
  } else {
    const local = (profile.username.split("@")[0] || profile.email.split("@")[0] || randomToken(8)).toLowerCase();
    const emailDomain = profile.email.includes("@") ? profile.email.split("@")[1]! : "";
    let domain = idp.jit_domain || "";
    if (!domain && emailDomain && (await domainExists(env, emailDomain))) domain = emailDomain;
    if (!domain) domain = (await env.DB.prepare("SELECT domain FROM domains ORDER BY is_default DESC, domain LIMIT 1").first<{ domain: string }>())?.domain ?? "";
    if (!domain || !(await domainExists(env, domain))) throw new FederationError("JIT provisioning has no managed domain to create the account under.");
    const baseLocal = local.replace(/[^a-z0-9._-]/g, "").replace(/^[^a-z0-9]+/, "") || `u${randomToken(6)}`;
    candidate = await resolveUsernameCollision(env, baseLocal, { domain, email: profile.email }, policy) as string;
    if (!candidate) throw new FederationError("JIT provisioning can't create the account: its sign-in name collides with an existing user.");
    upn = `${candidate}@${domain}`;
  }
  // The sign-in name shares a namespace with contact addresses: spelled like
  // another account's user_emails alias or users.email, the same string
  // resolves to two accounts (SSF prefers the upn holder, email lookups the
  // alias owner) - the check SCIM POST /Users applies.
  const upnClash = await env.DB.prepare("SELECT 1 FROM user_emails WHERE email = ? UNION SELECT 1 FROM users WHERE email = ?").bind(upn, upn).first();
  if (upnClash) throw new FederationError(`JIT provisioning would create a sign-in name (${upn}) that collides with another account's email address.`);

  // The claimed address is unverified and must never collide with another
  // account's identifiers; a collision means adoption failed to match, not
  // that this account should claim the spelling. The email collision policy
  // decides: skip it (default) or refuse the sign-in.
  const jitEmail = (profile.email ?? "").trim().toLowerCase();
  let attachEmail = false;
  if (jitEmail) {
    const clash = await env.DB.prepare(
      "SELECT 1 FROM users WHERE upn = ? OR username = ? OR email = ? UNION SELECT 1 FROM user_emails WHERE email = ?"
    ).bind(jitEmail, jitEmail, jitEmail, jitEmail).first();
    if (clash && policy.email === "fail") throw new FederationError(`The claimed email address ${jitEmail} already belongs to another account.`);
    attachEmail = !clash;
  }

  const t = now();
  const schemaId = await defaultSchemaId(env, "user");
  const cols = profile.cols ?? {};
  const customJson = JSON.stringify(profile.custom ?? {});
  // The same boundary every other user writer honours: the IdP chose the
  // claims, so they must not land the new account in a group that grants an
  // admin role - a dynamic rule on username or display_name turns a JIT
  // account into an instant admin grant. Mapped columns and customs are part
  // of the check because rules can match them.
  const granted = await grantsAdminRoleGroup(env, null, {
    upn,
    username: candidate,
    display_name: profile.displayName || upn,
    given_name: profile.givenName,
    family_name: profile.familyName,
    external_id: "",
    job_title: cols.job_title ?? "",
    department: cols.department ?? "",
    employee_number: cols.employee_number ?? "",
    hire_date: cols.hire_date ?? "",
    employment_status: cols.employment_status ?? "",
    employment_type: cols.employment_type ?? "",
    location: cols.location ?? "",
    status: "active",
    manager_external_id: null,
    source_id: cols.source_id ?? null,
    custom_attributes: customJson,
    email: profile.email || null,
  } as UserRow);
  if (granted) throw new FederationError(`Provisioning would place the account in ${granted}, a group that grants an admin role.`);
  const inserted = await env.DB.prepare(
    `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department, employee_number, hire_date, employment_status, employment_type, location, source_id, password_hash, password_salt, password_iterations, is_admin, status, schema_id, custom_attributes, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '!', '', 0, 0, 'active', ?, ?, ?, ?) RETURNING id`
  )
    .bind(
      upn, candidate, profile.displayName || upn, profile.givenName, profile.familyName,
      `fed-${idp.id}-${randomToken(8)}`,
      cols.job_title ?? "", cols.department ?? "", cols.employee_number ?? "", cols.hire_date ?? "",
      cols.employment_status ?? "", cols.employment_type ?? "", cols.location ?? "",
      cols.source_id ?? null, schemaId, customJson, t, t
    )
    .first<{ id: number }>();
  const userId = inserted!.id;
  if (attachEmail) {
    await env.DB.prepare("INSERT INTO user_emails (user_id, email, type, is_primary, created_at) VALUES (?, ?, 'work', 1, ?)").bind(userId, jitEmail, t).run();
    await env.DB.prepare("UPDATE users SET email = ? WHERE id = ?").bind(jitEmail, userId).run();
  }
  // jit_groups: the admin's explicit list, applied at creation only (later
  // changes to it don't touch already-provisioned accounts). Deliberately
  // exempt from the dynamic-rule check above: these ids come from stored
  // configuration, not from attacker-influenceable claims, and the save-time
  // validation keeps the list to groups with no write-capable role.
  for (const gid of upstreamJitGroups(idp)) {
    await env.DB.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, userId).run();
  }
  await linkIdentity(env, idp.id, profile, userId);
  return (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first<UserRow>())!;
}

async function linkIdentity(env: Env, idpId: number, profile: FederatedProfile, userId: number): Promise<void> {
  await env.DB.prepare("INSERT OR IGNORE INTO federated_identities (idp_id, subject, user_id, email, last_login_at, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(idpId, profile.subject, userId, profile.email || null, now(), now())
    .run();
}

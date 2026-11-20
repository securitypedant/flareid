/**
 * Create/update logic for the two kinds of application FlareID signs people
 * in to - OIDC clients and SAML service providers.
 *
 * Every write path goes through here: the admin console forms, the REST API
 * (/api/v1/clients, /api/v1/saml/service-providers) and the app catalog's
 * create-from-template - so a rule changed once holds everywhere.
 */
import type { Env } from "../env.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import { CLAIM_GROUPS, isValidPostLogoutUri } from "../lib/oidc.js";
import { nameIdFormatUri } from "../lib/saml/messages.js";
import { USER_ATTRIBUTE_FIELDS } from "../lib/saml/attributes.js";
import { parseExpression } from "../lib/expr.js";
import { normalizeAttributeDefinitions, type SpAttributeDefinition } from "../lib/saml/service-providers.js";
import { normalizeCertPem } from "../lib/saml/x509.js";
import { catalogIconUrl, templateToClientInput, templateToSpInput, type CatalogEntry } from "../lib/catalog.js";
import { isIdTokenAlg, validFrontchannelUri } from "./clients.js";

// ---------------------------------------------------------------------------
// OIDC clients
// ---------------------------------------------------------------------------

/** The grants a client may declare (RFC 7591 grant_types); the /token endpoint's list, kept for catalog templates that ship one. */
export const CLIENT_GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"] as const;

/** The non-name/redirect fields a client carries, in stored (JSON/int) shape. */
export interface ClientSettings {
  /** JSON array of group ids restricting who may use the app; "[]" = everyone. */
  assignedGroups: string;
  trusted: number;
  /** JSON array of allowed claim-group names. */
  allowedClaims: string;
  /** JSON array of https/loopback post-logout redirect URIs. */
  postLogoutRedirectUris: string;
  frontchannelLogoutUri: string;
  logoUri: string;
  idTokenAlg: "RS256" | "ES256";
}

/** Reads the client form's fields into ClientSettings, dropping unusable values rather than storing them. */
export function readClientSettings(body: Record<string, string | File | (string | File)[]>): ClientSettings {
  const list = (v: unknown) => (Array.isArray(v) ? v : v ? [v] : []).map(String);
  return {
    assignedGroups: JSON.stringify(list(body.assigned_group_ids).map(Number).filter((n) => Number.isInteger(n) && n > 0)),
    trusted: body.trusted ? 1 : 0,
    allowedClaims: JSON.stringify(CLAIM_GROUPS.filter((g) => list(body.allowed_claims).includes(g))),
    // Unusable entries are dropped rather than stored: /oidc/logout follows only exact, valid matches.
    postLogoutRedirectUris: JSON.stringify(
      String(body.post_logout_redirect_uris ?? "")
        .split("\n")
        .map((s) => s.trim())
        .filter((u) => u && isValidPostLogoutUri(u))
    ),
    frontchannelLogoutUri: validFrontchannelUri(String(body.frontchannel_logout_uri ?? "").trim()),
    logoUri: validFrontchannelUri(String(body.logo_uri ?? "").trim()),
    // Anything unrecognised falls back to the default rather than being stored.
    idTokenAlg: isIdTokenAlg(body.id_token_signed_response_alg) ? body.id_token_signed_response_alg : "RS256",
  };
}

/**
 * The client INSERT shared by the console create form, the API and catalog
 * apply. Returns the row id, the client_id and (for a confidential client)
 * the plaintext secret, which exists only in this response.
 *
 * Seeded credentials, for provisioning that has to know them in advance.
 *
 * A lab provisions Cloudflare Access with Terraform, which needs this client's
 * id and secret to create the Access identity provider - but Terraform cannot
 * read a value out of an app it has not deployed yet. So it generates the
 * credential, passes it in here, and the identity provider is correct on the
 * first apply with nothing having to flow back.
 *
 * No new privilege: the callers are already privileged paths and an admin can
 * read a generated secret anyway, so choosing one instead grants nothing. Both
 * fields must be present together and the secret has a floor, so a partial or
 * trivially short value falls back to a generated one rather than quietly
 * creating a weak client.
 */
export async function insertClient(
  env: Env,
  input: {
    name: string;
    clientType: "confidential" | "public";
    redirectUris: string[];
    settings: ClientSettings;
    seededId?: string;
    seededSecret?: string;
    /** RFC 7591 grant_types to store; empty/undefined keeps NULL (every grant, the admin-created default). */
    grantTypes?: string[];
  }
): Promise<{ id: number; clientId: string; clientSecret: string }> {
  const isPublic = input.clientType === "public";
  const seeded = (input.seededId ?? "") !== "" && (input.seededSecret ?? "").length >= 24;
  const clientId = seeded ? input.seededId! : `flareid_${randomToken(8)}`;
  // A public client has no secret at all - an empty hash never matches.
  const clientSecret = isPublic ? "" : seeded ? input.seededSecret! : randomToken(24);
  const clientSecretHash = isPublic ? "" : await sha256Hex(clientSecret);

  const result = await env.DB.prepare(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, created_at, client_type, trusted, allowed_claims, post_logout_redirect_uris)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(clientId, clientSecretHash, input.name, JSON.stringify(input.redirectUris), new Date().toISOString(), isPublic ? "public" : "confidential", input.settings.trusted, input.settings.allowedClaims, input.settings.postLogoutRedirectUris)
    .run();
  await env.DB.prepare("UPDATE oauth_clients SET frontchannel_logout_uri = ?, id_token_signed_response_alg = ?, logo_uri = ?, assigned_groups = ? WHERE client_id = ?").bind(input.settings.frontchannelLogoutUri, input.settings.idTokenAlg, input.settings.logoUri, input.settings.assignedGroups, clientId).run();
  if (input.grantTypes?.length) await env.DB.prepare("UPDATE oauth_clients SET grant_types = ? WHERE client_id = ?").bind(JSON.stringify(input.grantTypes), clientId).run();
  return { id: Number(result.meta.last_row_id), clientId, clientSecret };
}

// ---------------------------------------------------------------------------
// SAML service providers
// ---------------------------------------------------------------------------

/** Splits pasted PEM text into certificates; invalid flags any block that fails to parse. */
export function parseCertsInput(input: string): { certs: string[]; invalid: boolean } {
  const blocks = input.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) {
    if (!input.trim()) return { certs: [], invalid: false };
    const single = normalizeCertPem(input);
    return { certs: single ? [single] : [], invalid: !single };
  }
  const certs: string[] = [];
  let invalid = false;
  for (const block of blocks) {
    const pem = normalizeCertPem(block);
    if (pem) certs.push(pem);
    else invalid = true;
  }
  return { certs, invalid };
}

export interface SpFormValues {
  name: string;
  entityId: string;
  acsUrls: string[];
  defaultAcsUrl: string;
  nameidFormat: string;
  attributeMap: Record<string, string>;
  attributeDefinitions: SpAttributeDefinition[];
  signResponse: boolean;
  signAssertion: boolean;
  wantSigned: boolean;
  signingCerts: string[];
  sloUrl: string;
  encryptionCert: string;
  subjectId: string;
  encryptAssertions: boolean;
  /** App icon for the launchpad; "" = letter tile. */
  logoUri: string;
  /** Group ids this SP is restricted to; [] = everyone. */
  assignedGroups: number[];
}

/** Parses and validates SP input (the create form's shape; the API and catalog feed the same fields). Returns the values, or a message for the caller. */
export function parseSpForm(body: Record<string, unknown>): SpFormValues | string {
  const name = String(body.name ?? "").trim();
  const entityId = String(body.entity_id ?? "").trim();
  if (!name || !entityId) return "name and entity_id are required.";

  const acsUrls = String(body.acs_urls ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (acsUrls.length === 0) return "At least one ACS URL is required.";
  for (const u of acsUrls) if (!/^https:\/\//.test(u)) return `ACS URL "${u}" must be https - assertions are bearer credentials.`;
  const defaultAcsUrl = String(body.default_acs_url ?? "").trim();
  if (defaultAcsUrl && !acsUrls.includes(defaultAcsUrl)) return "The default ACS URL must be one of the registered ACS URLs.";

  const nameidFormat = String(body.nameid_format ?? "transient");
  // "none" (IIP-IDP11): the assertion's Subject carries no <saml:NameID>.
  if (nameidFormat !== "none" && !nameIdFormatUri(nameidFormat)) return `Unsupported NameID format "${nameidFormat}".`;

  let attributeMap: Record<string, string> = {};
  const rawMap = String(body.attribute_map ?? "").trim();
  if (rawMap) {
    try {
      const parsed = JSON.parse(rawMap);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error();
      attributeMap = parsed as Record<string, string>;
      for (const [k, v] of Object.entries(attributeMap)) {
        try {
          parseExpression(v);
        } catch {
          return `"${v}" is not a valid expression - use a field name (${USER_ATTRIBUTE_FIELDS.join(", ")}, custom.<key>) or an expression.`;
        }
      }
    } catch (e) {
      if (typeof e === "string") return e;
      return "attribute_map must be a JSON object of {\"saml-attribute-name\": \"field\"}.";
    }
  }

  let attributeDefinitions: SpAttributeDefinition[] = [];
  const rawDefs = String(body.attribute_definitions ?? "").trim();
  if (rawDefs) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawDefs);
    } catch {
      return 'attribute_definitions must be a JSON array of {"name": ..., "field": ..., "name_format": ...}.';
    }
    const norm = normalizeAttributeDefinitions(parsed);
    if ("error" in norm) return norm.error;
    for (const def of norm.defs) {
      try {
        parseExpression(def.field);
      } catch {
        return `"${def.field}" is not a valid expression - use a field name (${USER_ATTRIBUTE_FIELDS.join(", ")}, custom.<key>) or an expression.`;
      }
    }
    attributeDefinitions = norm.defs;
  }

  const { certs, invalid } = parseCertsInput(String(body.signing_certs ?? ""));
  if (invalid) return "One of the pasted certificates could not be parsed.";
  if (body.want_authn_requests_signed && certs.length === 0) {
    return "Requiring signed requests needs at least one SP signing certificate.";
  }

  const sloUrl = String(body.slo_url ?? "").trim();
  if (sloUrl && !/^https:\/\//.test(sloUrl)) return "The Single Logout URL must be https.";
  const logoUri = String(body.logo_uri ?? "").trim();
  if (logoUri && !/^https:\/\//.test(logoUri)) return "The logo URL must be https.";
  const rawEnc = String(body.encryption_cert ?? "").trim();
  const encryptionCert = rawEnc ? normalizeCertPem(rawEnc) : "";
  if (rawEnc && !encryptionCert) return "The encryption certificate could not be parsed.";
  if (body.encrypt_assertions && !encryptionCert) return "Encrypting assertions needs the SP's encryption certificate.";

  return {
    name,
    entityId,
    acsUrls,
    defaultAcsUrl,
    nameidFormat,
    attributeMap,
    attributeDefinitions,
    signResponse: !!body.sign_response,
    signAssertion: !!body.sign_assertion,
    wantSigned: !!body.want_authn_requests_signed,
    signingCerts: certs,
    sloUrl,
    encryptionCert: encryptionCert ?? "",
    encryptAssertions: !!body.encrypt_assertions,
    logoUri,
    subjectId: ["subject-id", "pairwise-id"].includes(String(body.subject_id)) ? String(body.subject_id) : "",
    assignedGroups: (Array.isArray(body.assigned_group_ids) ? body.assigned_group_ids : body.assigned_group_ids ? [body.assigned_group_ids] : [])
      .map(Number)
      .filter((n) => Number.isInteger(n) && n > 0),
  };
}

/** The SP INSERT shared by the console create form, the API and catalog apply. Returns the new row id. */
export async function insertServiceProvider(env: Env, v: SpFormValues): Promise<number> {
  const now = new Date().toISOString();
  const result = await env.DB.prepare(
    `INSERT INTO saml_service_providers (entity_id, name, acs_urls, default_acs_url, nameid_format, attribute_map, attribute_definitions, sign_response, sign_assertion, want_authn_requests_signed, signing_certs, slo_url, encryption_cert, encrypt_assertions, logo_uri, assigned_groups, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(v.entityId, v.name, JSON.stringify(v.acsUrls), v.defaultAcsUrl || null, v.nameidFormat, JSON.stringify(v.attributeMap), v.attributeDefinitions.length ? JSON.stringify(v.attributeDefinitions) : null, v.signResponse ? 1 : 0, v.signAssertion ? 1 : 0, v.wantSigned ? 1 : 0, JSON.stringify(v.signingCerts), v.sloUrl || null, v.encryptionCert || null, v.encryptAssertions ? 1 : 0, v.logoUri || null, JSON.stringify(v.assignedGroups), now, now)
    .run();

  await env.DB.prepare("UPDATE saml_service_providers SET subject_id = ? WHERE id = ?").bind(v.subjectId, result.meta.last_row_id).run();
  return Number(result.meta.last_row_id);
}

// ---------------------------------------------------------------------------
// App catalog apply
// ---------------------------------------------------------------------------

export type CatalogApplyResult =
  | { ok: true; protocol: "saml"; id: number }
  | { ok: true; protocol: "oidc"; id: number; clientId: string; clientSecret: string | null }
  | { ok: false; error: string };

/**
 * Creates the app a catalog entry describes: the entry's template with the
 * caller's {placeholder} values substituted, through the same validation and
 * INSERTs the console create forms and the API use. `clientSecret` is set
 * only for a confidential OIDC client - it exists only in this return value.
 */
export async function applyCatalogEntry(env: Env, entry: CatalogEntry, values: Record<string, string>, issuer: string): Promise<CatalogApplyResult> {
  if (entry.protocol === "saml") {
    const tpl = templateToSpInput(entry, values);
    if (!tpl) return { ok: false, error: "That catalog entry has no SAML template." };
    const v = parseSpForm({ ...tpl, signing_certs: "", encryption_cert: "", assigned_group_ids: [] });
    if (typeof v === "string") return { ok: false, error: v };
    v.logoUri = catalogIconUrl(issuer, entry);
    const id = await insertServiceProvider(env, v);
    return { ok: true, protocol: "saml", id };
  }

  const tpl = templateToClientInput(entry, values);
  if (!tpl) return { ok: false, error: "That catalog entry has no OIDC template." };
  const settings: ClientSettings = {
    assignedGroups: "[]",
    trusted: tpl.trusted ? 1 : 0,
    allowedClaims: JSON.stringify(CLAIM_GROUPS.filter((g) => tpl.allowed_claims.includes(g))),
    postLogoutRedirectUris: JSON.stringify(
      tpl.post_logout_redirect_uris
        .split("\n")
        .map((s) => s.trim())
        .filter((u) => u && isValidPostLogoutUri(u))
    ),
    frontchannelLogoutUri: "",
    logoUri: catalogIconUrl(issuer, entry),
    idTokenAlg: "RS256",
  };
  const created = await insertClient(env, {
    name: tpl.name,
    clientType: tpl.client_type,
    redirectUris: tpl.redirect_uris
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    settings,
    grantTypes: tpl.grant_types.filter((g) => (CLIENT_GRANT_TYPES as readonly string[]).includes(g)),
  });
  return { ok: true, protocol: "oidc", id: created.id, clientId: created.clientId, clientSecret: tpl.client_type === "public" ? null : created.clientSecret };
}

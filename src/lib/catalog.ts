/**
 * The app catalog: onboarding templates for well-known applications, shipped
 * as JSON files under catalog/ and bundled into the Worker (there is no
 * filesystem to read them from at request time).
 *
 * Each entry has two halves:
 *
 *   - `instructions` - ordered steps for both sides of the integration, with
 *     {placeholders}. The {idp_*} names are deployment facts substituted from
 *     the issuer at render time; {client_id}, {client_secret} and app-side
 *     values like {team} cannot be known here, so they stay in the text as
 *     visible marks for the administrator to replace.
 *
 *   - `saml` / `oidc` - the field values the "New service provider" / "New
 *     OIDC client" console forms consume, produced by templateToSpInput and
 *     templateToClientInput in the same shapes those forms post.
 *
 * catalog/schema.json constrains the file format; test/catalog.test.ts
 * validates every entry against it, so a broken template fails CI rather than
 * the admin's afternoon.
 */
import type { SpAttributeDefinition } from "./saml/service-providers.js";

import atlassianCloud from "../../catalog/atlassian-cloud.json";
import awsSso from "../../catalog/aws-sso.json";
import cloudflareAccess from "../../catalog/cloudflare-access.json";
import githubEnterprise from "../../catalog/github-enterprise.json";
import gitlab from "../../catalog/gitlab.json";
import googleWorkspace from "../../catalog/google-workspace.json";
import grafana from "../../catalog/grafana.json";
import salesforce from "../../catalog/salesforce.json";
import slack from "../../catalog/slack.json";
import zoom from "../../catalog/zoom.json";

export interface CatalogAttributeDefinition {
  name: string;
  field: string;
  name_format?: string;
}

/** The template half of a SAML entry - the fields the SP form pre-fills. */
export interface CatalogSaml {
  entity_id: string;
  acs_urls: string[];
  default_acs_url?: string;
  nameid_format: string;
  attribute_map?: Record<string, string>;
  attribute_definitions: CatalogAttributeDefinition[];
  want_authn_requests_signed: boolean;
  sign_response: boolean;
  sign_assertion: boolean;
  encrypt_assertions: boolean;
  slo_url?: string;
  metadata_url?: string;
  subject_id?: string;
}

/** The template half of an OIDC entry - the fields the client form pre-fills. */
export interface CatalogOidc {
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  claims: string[];
  grant_types: string[];
  client_type?: "confidential" | "public";
  trusted: boolean;
}

export interface CatalogEntry {
  slug: string;
  name: string;
  protocol: "saml" | "oidc";
  website: string;
  /** The app's mark, catalog-relative ("icons/slack.svg"); served at /catalog-icons/<file>. */
  logo: string;
  instructions: { app: string[]; flareid: string[] };
  saml: CatalogSaml | null;
  oidc: CatalogOidc | null;
  connector: unknown;
}

const ENTRIES: CatalogEntry[] = [
  atlassianCloud,
  awsSso,
  cloudflareAccess,
  githubEnterprise,
  gitlab,
  googleWorkspace,
  grafana,
  salesforce,
  slack,
  zoom,
] as CatalogEntry[];

/** Every catalog entry, sorted by display name. */
export function listCatalog(): CatalogEntry[] {
  return [...ENTRIES].sort((a, b) => a.name.localeCompare(b.name));
}

/** One entry by slug, or null. */
export function getCatalogEntry(slug: string): CatalogEntry | null {
  return ENTRIES.find((e) => e.slug === slug) ?? null;
}

/** The URL an icon serves at on this deployment, e.g. for a created record's logo_uri. */
export function catalogIconUrl(issuer: string, entry: CatalogEntry): string {
  return `${issuer}/catalog-icons/${entry.logo.slice("icons/".length)}`;
}

const PLACEHOLDER = /\{([A-Za-z0-9_]+)\}/g;

/** The {name} tokens a string contains, in order of appearance. */
export function placeholdersIn(text: string): string[] {
  return [...text.matchAll(PLACEHOLDER)].map((m) => m[1]!);
}

/**
 * The placeholders a caller must supply to apply an entry: every {name} in
 * its instructions and URLs, minus the ones the IdP itself fills (idp_*,
 * client_id, client_secret).
 */
export function catalogValuePlaceholders(entry: CatalogEntry): string[] {
  const texts = [...entry.instructions.app, ...entry.instructions.flareid];
  if (entry.saml) texts.push(entry.saml.entity_id, ...entry.saml.acs_urls, entry.saml.default_acs_url ?? "", entry.saml.slo_url ?? "");
  if (entry.oidc) texts.push(...entry.oidc.redirect_uris, ...(entry.oidc.post_logout_redirect_uris ?? []));
  const names = new Set(texts.flatMap(placeholdersIn));
  for (const n of [...names]) if (n.startsWith("idp_") || n === "client_id" || n === "client_secret") names.delete(n);
  return [...names].sort();
}

/**
 * The {idp_*} values a deployment can fill in from its issuer alone. These
 * are the endpoints already published in the OIDC discovery document and the
 * SAML metadata, spelled here so a template never hardcodes a path.
 *
 * {client_id} and {client_secret} are deliberately absent - they only exist
 * after the client is created, so they stay as visible marks.
 */
export function idpPlaceholders(issuer: string): Record<string, string> {
  return {
    idp_issuer: issuer,
    idp_entity_id: issuer,
    idp_discovery_url: `${issuer}/.well-known/openid-configuration`,
    idp_jwks_url: `${issuer}/jwks.json`,
    idp_authorize_url: `${issuer}/authorize`,
    idp_token_url: `${issuer}/token`,
    idp_userinfo_url: `${issuer}/userinfo`,
    idp_logout_url: `${issuer}/oidc/logout`,
    idp_metadata_url: `${issuer}/saml/metadata`,
    idp_sso_url: `${issuer}/saml/sso`,
    idp_slo_url: `${issuer}/saml/slo`,
    idp_cert_url: `${issuer}/saml/cert.pem`,
  };
}

export interface RenderContext {
  /** The deployment's issuer (env.ISSUER_URL). Empty leaves every {idp_*} token marked. */
  issuer?: string;
  /** App-side values the administrator has already supplied, e.g. { team: "acme" }. */
  values?: Record<string, string>;
}

export interface RenderedInstructions {
  app: string[];
  flareid: string[];
  /**
   * Placeholder names still unresolved in the rendered text - shown so a UI
   * can warn that the steps are not fully concrete yet. Names stay wrapped in
   * braces in the text itself: a half-substituted URL must look unfinished,
   * not silently wrong.
   */
  placeholders: string[];
}

/**
 * Substitutes every {name} that `values` knows - the {idp_*} facts from the
 * issuer plus any app-side overrides - and reports the names it could not.
 */
export function substitutePlaceholders(text: string, values: Record<string, string>): { text: string; missing: string[] } {
  const missing = new Set<string>();
  const out = text.replace(PLACEHOLDER, (raw, name: string) => {
    const v = values[name];
    if (v === undefined || v === "") {
      missing.add(name);
      return raw;
    }
    return v;
  });
  return { text: out, missing: [...missing].sort() };
}

/**
 * The instruction steps with {idp_*} tokens resolved from the issuer and any
 * caller-supplied app values applied. Placeholders nobody could fill stay in
 * the text and are listed in `placeholders`.
 */
export function renderInstructions(entry: CatalogEntry, ctx: RenderContext): RenderedInstructions {
  const values: Record<string, string> = { ...(ctx.issuer ? idpPlaceholders(ctx.issuer) : {}), ...(ctx.values ?? {}) };
  const missing = new Set<string>();
  const render = (steps: string[]) =>
    steps.map((s) => {
      const r = substitutePlaceholders(s, values);
      for (const m of r.missing) missing.add(m);
      return r.text;
    });
  return { app: render(entry.instructions.app), flareid: render(entry.instructions.flareid), placeholders: [...missing].sort() };
}

/**
 * The SP form's field values (the shape parseSpForm posts: acs_urls and the
 * JSON textareas as strings). Placeholders like {team} stay marked in the
 * values - the administrator replaces them before saving, and the form's own
 * https checks still pass because the URLs keep their scheme.
 */
export interface SpTemplateValues {
  name: string;
  entity_id: string;
  acs_urls: string;
  default_acs_url: string;
  nameid_format: string;
  attribute_map: string;
  attribute_definitions: string;
  sign_response: boolean;
  sign_assertion: boolean;
  want_authn_requests_signed: boolean;
  slo_url: string;
  encrypt_assertions: boolean;
  subject_id: string;
}

export function templateToSpInput(entry: CatalogEntry, values?: Record<string, string>): SpTemplateValues | null {
  const saml = entry.saml;
  if (entry.protocol !== "saml" || !saml) return null;
  const sub = (s: string) => (values ? substitutePlaceholders(s, values).text : s);
  const defs: SpAttributeDefinition[] = saml.attribute_definitions.map((d) => (d.name_format ? { name: d.name, field: d.field, nameFormat: d.name_format } : { name: d.name, field: d.field }));
  // attribute_definitions is written back in the form's input spelling
  // (name_format), matching how the edit form round-trips stored rows.
  const defsForForm = defs.map((d) => ({ name: d.name, field: d.field, ...(d.nameFormat ? { name_format: d.nameFormat } : {}) }));
  return {
    name: entry.name,
    entity_id: sub(saml.entity_id),
    acs_urls: saml.acs_urls.map(sub).join("\n"),
    default_acs_url: saml.default_acs_url ? sub(saml.default_acs_url) : "",
    nameid_format: saml.nameid_format,
    attribute_map: saml.attribute_map && Object.keys(saml.attribute_map).length > 0 ? JSON.stringify(saml.attribute_map, null, 2) : "",
    attribute_definitions: defsForForm.length > 0 ? JSON.stringify(defsForForm, null, 2) : "",
    sign_response: saml.sign_response,
    sign_assertion: saml.sign_assertion,
    want_authn_requests_signed: saml.want_authn_requests_signed,
    slo_url: saml.slo_url ? sub(saml.slo_url) : "",
    encrypt_assertions: saml.encrypt_assertions,
    subject_id: saml.subject_id ?? "",
  };
}

/**
 * The OIDC client form's field values: redirect URIs one per line as the
 * textarea takes them, and claims as claim-group names for the checkboxes.
 */
export interface ClientTemplateValues {
  name: string;
  redirect_uris: string;
  post_logout_redirect_uris: string;
  client_type: "confidential" | "public";
  trusted: boolean;
  allowed_claims: string[];
  grant_types: string[];
}

export function templateToClientInput(entry: CatalogEntry, values?: Record<string, string>): ClientTemplateValues | null {
  const oidc = entry.oidc;
  if (entry.protocol !== "oidc" || !oidc) return null;
  const sub = (s: string) => (values ? substitutePlaceholders(s, values).text : s);
  return {
    name: entry.name,
    redirect_uris: oidc.redirect_uris.map(sub).join("\n"),
    post_logout_redirect_uris: (oidc.post_logout_redirect_uris ?? []).map(sub).join("\n"),
    client_type: oidc.client_type ?? "confidential",
    trusted: oidc.trusted,
    allowed_claims: [...oidc.claims],
    grant_types: [...oidc.grant_types],
  };
}

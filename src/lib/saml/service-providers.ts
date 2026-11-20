import type { Env } from "../../env.js";
import type { SamlServiceProviderRow } from "../types.js";
import { CONTENT_ALGORITHMS, DEFAULT_ENCRYPTION_POLICY, TRANSPORT_ALGORITHMS, type EncryptionPolicy } from "./encrypt.js";

export function getSpByEntityId(env: Env, entityId: string): Promise<SamlServiceProviderRow | null> {
  return env.DB.prepare("SELECT * FROM saml_service_providers WHERE entity_id = ?")
    .bind(entityId)
    .first<SamlServiceProviderRow>()
    .then((row) => row ?? null);
}

export function getSpById(env: Env, id: number): Promise<SamlServiceProviderRow | null> {
  return env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?")
    .bind(id)
    .first<SamlServiceProviderRow>()
    .then((row) => row ?? null);
}

export function listSps(env: Env): Promise<{ results: SamlServiceProviderRow[] }> {
  return env.DB.prepare("SELECT * FROM saml_service_providers ORDER BY name").all<SamlServiceProviderRow>();
}

function parseJson<T>(raw: string | null, fallback: T): T {
  try {
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

/** The registered AssertionConsumerService endpoints - an exact-match allowlist, not a pattern. */
export function spAcsUrls(sp: SamlServiceProviderRow): string[] {
  return parseJson<string[]>(sp.acs_urls, []);
}

export function spSigningCerts(sp: SamlServiceProviderRow): string[] {
  return parseJson<string[]>(sp.signing_certs, []);
}

export function spAttributeMap(sp: SamlServiceProviderRow): Record<string, string> {
  return parseJson<Record<string, string>>(sp.attribute_map, {});
}

/** A released attribute as configured per SP: arbitrary SAML Name, optional NameFormat, and the user field feeding it (IIP-IDP01). */
export interface SpAttributeDefinition {
  name: string;
  field: string;
  nameFormat?: string;
}

export const ATTRIBUTE_DEFINITIONS_MAX = 64;

/**
 * The SP's attribute definitions - the richer alternative to attribute_map:
 * each entry names the released attribute (arbitrary xs:string), its optional
 * NameFormat (arbitrary xs:anyURI) and the user field feeding it. Stored as a
 * JSON array; a malformed row resolves to [] so a hand edit cannot break SSO.
 */
export function spAttributeDefinitions(sp: SamlServiceProviderRow): SpAttributeDefinition[] {
  const raw = parseJson<unknown>(sp.attribute_definitions, []);
  if (!Array.isArray(raw)) return [];
  const out: SpAttributeDefinition[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const d = item as Record<string, unknown>;
    const name = typeof d.name === "string" ? d.name : "";
    const field = typeof d.field === "string" ? d.field : "";
    if (!name || !field) continue;
    const nameFormat = typeof d.nameFormat === "string" && d.nameFormat ? d.nameFormat : typeof d.name_format === "string" && d.name_format ? d.name_format : undefined;
    out.push(nameFormat ? { name, field, nameFormat } : { name, field });
  }
  return out;
}

/**
 * Write-path validation for attribute_definitions (console textarea JSON and
 * the API array): returns the normalized entries or an error message for the
 * administrator. `field` vocabulary is the caller's check
 * (USER_ATTRIBUTE_FIELDS), so this only rules on shape.
 */
export function normalizeAttributeDefinitions(input: unknown): { defs: SpAttributeDefinition[] } | { error: string } {
  if (!Array.isArray(input)) return { error: 'attribute_definitions must be a JSON array of {"name": ..., "field": ..., "name_format": ...}.' };
  const defs: SpAttributeDefinition[] = [];
  const seen = new Set<string>();
  for (const item of input) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return { error: 'Each attribute definition must be an object {"name": ..., "field": ..., "name_format": ...}.' };
    const d = item as Record<string, unknown>;
    const name = String(d.name ?? "").trim();
    // Name is an arbitrary xs:string - the only rule is that there is one.
    if (!name) return { error: "Every attribute definition needs a non-empty name." };
    const field = typeof d.field === "string" ? d.field.trim() : "";
    if (!field) return { error: `Attribute "${name}" needs a field.` };
    // NameFormat is an arbitrary xs:anyURI; absent means the IdP default.
    const nameFormat = String(d.name_format ?? d.nameFormat ?? "").trim();
    if (seen.has(name)) return { error: `Attribute "${name}" is defined twice.` };
    seen.add(name);
    defs.push(nameFormat ? { name, field, nameFormat } : { name, field });
  }
  if (defs.length > ATTRIBUTE_DEFINITIONS_MAX) return { error: `At most ${ATTRIBUTE_DEFINITIONS_MAX} attribute definitions per service provider.` };
  return { defs };
}

/**
 * nameid_format "none" (IIP-IDP11): the assertion's <saml:Subject> carries
 * only SubjectConfirmation - no <saml:NameID> at all.
 */
export function spOmitsNameId(sp: Pick<SamlServiceProviderRow, "nameid_format">): boolean {
  return sp.nameid_format === "none";
}

/**
 * Every spelling a configured algorithm can be recognised by in the
 * disabled_algorithms deny list: the full URI, its #-fragment and the short
 * token the API accepts (aes256-cbc, rsa-oaep, sha256).
 */
function algorithmAliases(value: string): Set<string> {
  const aliases = new Set([value]);
  const hash = value.indexOf("#");
  if (hash >= 0) aliases.add(value.slice(hash + 1));
  const content = CONTENT_ALGORITHMS[value as keyof typeof CONTENT_ALGORITHMS];
  if (content) aliases.add(content.token);
  const transport = TRANSPORT_ALGORITHMS[value as keyof typeof TRANSPORT_ALGORITHMS];
  if (transport) aliases.add(transport.token);
  return aliases;
}

/** Whether `algorithm` (URI, fragment or token) is on the deny list. */
export function isAlgorithmDisabled(disabled: readonly string[], algorithm: string | null | undefined): boolean {
  if (!algorithm) return false;
  const aliases = algorithmAliases(algorithm);
  return disabled.some((entry) => {
    const d = entry.trim();
    if (aliases.has(d)) return true;
    const hash = d.indexOf("#");
    return hash >= 0 && aliases.has(d.slice(hash + 1));
  });
}

/** The mask hash the policy emits, mirroring encryptAssertion: mgf1p fixes MGF1-SHA1; the parameterized URI takes the declared mgf, defaulting to SHA-1. */
function effectiveMgf(transport: string, mgf: string | null | undefined): string {
  return TRANSPORT_ALGORITHMS[transport as keyof typeof TRANSPORT_ALGORITHMS]?.parameterized ? (mgf ?? "sha1") : "sha1";
}

/**
 * The first deny-listed algorithm the policy would emit once the defaults
 * fill its gaps, or null when the resolved policy is clean. Fields are
 * resolved exactly as emission resolves them - an unset content algorithm is
 * the default aes256-gcm, an unset MGF is the effective mask hash.
 */
export function disabledAlgorithmInPolicy(
  policy: { content?: string | null; transport?: string | null; digest?: string | null; mgf?: string | null },
  disabled: readonly string[]
): { field: "content" | "transport" | "digest" | "mgf"; value: string } | null {
  const content = policy.content ?? DEFAULT_ENCRYPTION_POLICY.content;
  const transport = policy.transport ?? DEFAULT_ENCRYPTION_POLICY.transport;
  const digest = policy.digest ?? DEFAULT_ENCRYPTION_POLICY.digest;
  if (isAlgorithmDisabled(disabled, content)) return { field: "content", value: content };
  if (isAlgorithmDisabled(disabled, transport)) return { field: "transport", value: transport };
  if (isAlgorithmDisabled(disabled, digest)) return { field: "digest", value: digest };
  const mgf = effectiveMgf(transport, policy.mgf);
  if (isAlgorithmDisabled(disabled, mgf)) return { field: "mgf", value: mgf };
  return null;
}

/**
 * The group ids an app is restricted to, from its `assigned_groups` column.
 * NULL, unparseable or '[]' all mean "everyone" - a hand-edited row degrades
 * to open, matching how every other JSON column here resolves malformed.
 */
export function parseAssignedGroupIds(raw: string | null | undefined): number[] {
  const parsed = parseJson<unknown>(raw ?? null, []);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((id): id is number => typeof id === "number" && Number.isInteger(id));
}

/**
 * Whether an app with this assignment list is visible to a user holding
 * `userGroupIds` (their effective memberships, static and dynamic). An empty
 * assignment is everyone; otherwise one shared group is enough.
 */
export function appVisibleTo(assignedJson: string | null | undefined, userGroupIds: readonly number[]): boolean {
  const ids = parseAssignedGroupIds(assignedJson);
  if (ids.length === 0) return true;
  return ids.some((id) => userGroupIds.includes(id));
}

/**
 * The md:EncryptionMethod URIs an SP advertised, mapped onto what this Worker
 * can emit. `disabled` is the instance deny list (getDisabledAlgorithms):
 * denied URIs are skipped rather than selected (IIP-ALG08).
 */
export function encryptionPolicyFromUris(uris: string[], disabled?: readonly string[]): { content: EncryptionPolicy["content"]; transport: EncryptionPolicy["transport"] } | null {
  const allowed = (u: string) => !disabled || !isAlgorithmDisabled(disabled, u);
  const content = uris.find((u) => u in CONTENT_ALGORITHMS && allowed(u)) as EncryptionPolicy["content"] | undefined;
  const transport = uris.find((u) => u in TRANSPORT_ALGORITHMS && allowed(u)) as EncryptionPolicy["transport"] | undefined;
  return content || transport ? { content: content ?? DEFAULT_ENCRYPTION_POLICY.content, transport: transport ?? DEFAULT_ENCRYPTION_POLICY.transport } : null;
}

/**
 * The SP's encryption choice for EncryptedAssertion emission: the stored
 * policy merged over the defaults. Malformed fields fall back individually -
 * a hand-edited row must not break SSO issuance.
 *
 * `disabled` is the instance deny list (getDisabledAlgorithms): when given,
 * a resolved policy that selects a denied algorithm throws instead of being
 * returned - fail closed at emission (IIP-ALG08.a).
 */
export function spEncryptionPolicy(sp: SamlServiceProviderRow, disabled?: readonly string[]): Partial<EncryptionPolicy> {
  const raw = parseJson<Record<string, unknown>>(sp.encryption_policy, {});
  const out: Partial<EncryptionPolicy> = {};
  if (typeof raw.content === "string" && raw.content in CONTENT_ALGORITHMS) out.content = raw.content as EncryptionPolicy["content"];
  if (typeof raw.transport === "string" && raw.transport in TRANSPORT_ALGORITHMS) out.transport = raw.transport as EncryptionPolicy["transport"];
  if (raw.digest === "sha1" || raw.digest === "sha256" || raw.digest === "sha384" || raw.digest === "sha512") out.digest = raw.digest;
  if (raw.mgf === "sha1" || raw.mgf === "sha256" || raw.mgf === "sha384" || raw.mgf === "sha512") out.mgf = raw.mgf;
  if (raw.mgf === null) out.mgf = null;
  if (disabled && disabled.length > 0) {
    const bad = disabledAlgorithmInPolicy(out, disabled);
    if (bad) throw new Error(`SAML encryption ${bad.field} algorithm "${bad.value}" is disabled by this instance's disabled_algorithms policy.`);
  }
  return out;
}

/**
 * The ACS a response goes to: the URL the request asked for when it named one
 * (already allowlist-checked by the caller), otherwise the configured default,
 * otherwise the sole registered endpoint.
 */
export function resolveAcsUrl(sp: SamlServiceProviderRow, requested: string | null): string | null {
  // Re-check the scheme at use time: writes require https, but rows written
  // before that rule (or edited outside it) must not redirect a bearer
  // assertion to cleartext or a non-URL scheme.
  const https = (u: string | null | undefined) => (u && u.startsWith("https://") ? u : null);
  if (requested) return https(requested);
  // The default must also be a registered ACS - writes enforce membership,
  // and the read-side check keeps a stale or hand-edited row from
  // redirecting assertions somewhere the allowlist never approved.
  const registered = spAcsUrls(sp);
  if (sp.default_acs_url && registered.includes(sp.default_acs_url)) return https(sp.default_acs_url);
  return registered.find((u) => u.startsWith("https://")) ?? null;
}

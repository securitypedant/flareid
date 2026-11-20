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

/** The md:EncryptionMethod URIs an SP advertised, mapped onto what this Worker can emit. */
export function encryptionPolicyFromUris(uris: string[]): { content: EncryptionPolicy["content"]; transport: EncryptionPolicy["transport"] } | null {
  const content = uris.find((u) => u in CONTENT_ALGORITHMS) as EncryptionPolicy["content"] | undefined;
  const transport = uris.find((u) => u in TRANSPORT_ALGORITHMS) as EncryptionPolicy["transport"] | undefined;
  return content || transport ? { content: content ?? DEFAULT_ENCRYPTION_POLICY.content, transport: transport ?? DEFAULT_ENCRYPTION_POLICY.transport } : null;
}

/**
 * The SP's encryption choice for EncryptedAssertion emission: the stored
 * policy merged over the defaults. Malformed fields fall back individually -
 * a hand-edited row must not break SSO issuance.
 */
export function spEncryptionPolicy(sp: SamlServiceProviderRow): Partial<EncryptionPolicy> {
  const raw = parseJson<Record<string, unknown>>(sp.encryption_policy, {});
  const out: Partial<EncryptionPolicy> = {};
  if (typeof raw.content === "string" && raw.content in CONTENT_ALGORITHMS) out.content = raw.content as EncryptionPolicy["content"];
  if (typeof raw.transport === "string" && raw.transport in TRANSPORT_ALGORITHMS) out.transport = raw.transport as EncryptionPolicy["transport"];
  if (raw.digest === "sha1" || raw.digest === "sha256" || raw.digest === "sha384" || raw.digest === "sha512") out.digest = raw.digest;
  if (raw.mgf === "sha1" || raw.mgf === "sha256" || raw.mgf === "sha384" || raw.mgf === "sha512") out.mgf = raw.mgf;
  if (raw.mgf === null) out.mgf = null;
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

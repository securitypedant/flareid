import type { Env } from "../../env.js";
import type { SamlServiceProviderRow } from "../types.js";

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

/**
 * The ACS a response goes to: the URL the request asked for when it named one
 * (already allowlist-checked by the caller), otherwise the configured default,
 * otherwise the sole registered endpoint.
 */
export function resolveAcsUrl(sp: SamlServiceProviderRow, requested: string | null): string | null {
  if (requested) return requested;
  return sp.default_acs_url || spAcsUrls(sp)[0] || null;
}

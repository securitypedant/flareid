import type { Env } from "../env.js";
import { getSetting, setSetting } from "../lib/settings.js";
import { getDefaultDomain } from "../lib/domains.js";
import { escapeDnValue, parseDn } from "./dn.js";
import { randomToken } from "../lib/tokens.js";

/**
 * The ldap_* settings, resolved together (LDAP.md sections 6-13). Anything
 * blank falls back to a derived value - the base DN from the default domain,
 * the NetBIOS name from its first label.
 */
export interface LdapSettings {
  enabled: boolean;
  /** Base DN as parsed RDNs, e.g. [dc=example, dc=com]. Empty when setup has not run. */
  base: { type: string; value: string }[];
  baseDn: string;
  hostname: string;
  netbios: string;
  /** Slug of the app unattributed user binds land on; '' = deny them. */
  unscopedBindApp: string;
  domainSid: string;
  guidNamespace: string;
  posixUidBase: number;
  posixGidBase: number;
  posixDefaultGid: number;
  posixShell: string;
  posixHome: string;
  idleTimeoutMinutes: number;
  otpRebindSeconds: number;
}

const KEYS = [
  "ldap_enabled",
  "ldap_base_dn",
  "ldap_hostname",
  "ldap_netbios_name",
  "ldap_unscoped_bind_app",
  "ldap_domain_sid",
  "ldap_guid_namespace",
  "ldap_posix_uid_base",
  "ldap_posix_gid_base",
  "ldap_posix_default_gid",
  "ldap_posix_shell",
  "ldap_posix_home",
  "ldap_idle_timeout_minutes",
  "ldap_otp_rebind_seconds",
] as const;

export function domainToBaseDn(domain: string): string {
  return domain
    .split(".")
    .filter(Boolean)
    .map((p) => `dc=${escapeDnValue(p.toLowerCase())}`)
    .join(",");
}

export async function getLdapSettings(env: Env): Promise<LdapSettings> {
  const rows = (
    await env.DB.prepare(`SELECT key, value FROM idp_settings WHERE key IN (${KEYS.map(() => "?").join(",")})`)
      .bind(...KEYS)
      .all<{ key: string; value: string }>()
  ).results;
  const get = (k: string) => rows.find((r) => r.key === k)?.value ?? "";

  // The default domain supplies the naming context and the NetBIOS name.
  const defaultDomain = await getDefaultDomain(env);
  const baseDn = get("ldap_base_dn") || (defaultDomain ? domainToBaseDn(defaultDomain) : "");
  let base: LdapSettings["base"] = [];
  try {
    if (baseDn) base = parseDn(baseDn);
  } catch {
    base = [];
  }

  return {
    enabled: get("ldap_enabled") === "true",
    base,
    baseDn,
    hostname: get("ldap_hostname") || (defaultDomain ? `ldap.${defaultDomain}` : ""),
    netbios: (get("ldap_netbios_name") || defaultDomain.split(".")[0] || "").toUpperCase(),
    unscopedBindApp: get("ldap_unscoped_bind_app"),
    domainSid: get("ldap_domain_sid"),
    guidNamespace: get("ldap_guid_namespace"),
    posixUidBase: Number(get("ldap_posix_uid_base")) || 10000,
    posixGidBase: Number(get("ldap_posix_gid_base")) || 20000,
    posixDefaultGid: Number(get("ldap_posix_default_gid")) || 100,
    posixShell: get("ldap_posix_shell") || "/bin/bash",
    posixHome: get("ldap_posix_home") || "/home/{username}",
    idleTimeoutMinutes: Math.min(Math.max(Number(get("ldap_idle_timeout_minutes")) || 15, 1), 120),
    otpRebindSeconds: Math.min(Math.max(Number(get("ldap_otp_rebind_seconds")) || 120, 30), 600),
  };
}

/** First enable generates the domain SID's random part and the GUID namespace once. */
export async function enableLdap(env: Env): Promise<void> {
  await setSetting(env, "ldap_enabled", "true");
  if (!(await getSetting(env, "ldap_domain_sid"))) {
    // S-1-5-21 plus three random 32-bit sub-authorities, as AD domains get.
    const rand = () => Math.floor(Math.random() * 0x40000000);
    await setSetting(env, "ldap_domain_sid", `S-1-5-21-${rand()}-${rand()}-${rand()}`);
  }
  if (!(await getSetting(env, "ldap_guid_namespace"))) {
    await setSetting(env, "ldap_guid_namespace", crypto.randomUUID());
  }
}

export async function disableLdap(env: Env): Promise<void> {
  await setSetting(env, "ldap_enabled", "false");
}

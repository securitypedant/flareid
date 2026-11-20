import { randomToken, sha256Hex } from "../tokens.js";
import type { Env } from "../../env.js";
import type { SamlServiceProviderRow, UserRow } from "../types.js";
import { getManagerEmail, getUserGroupNames } from "../db.js";
import { spAttributeDefinitions, spAttributeMap, type SpAttributeDefinition } from "./service-providers.js";
import { parseCustomAttributes } from "../schemas.js";

/**
 * One attribute for the AttributeStatement: the SAML Name, its optional
 * NameFormat (absent = the IdP's default attrname-format:uri), and values.
 * messages.ts emits `NameFormat: a.nameFormat ?? ATTR_NAME_FORMAT`.
 */
export interface ResolvedAttribute {
  name: string;
  nameFormat?: string;
  values: string[];
}

/**
 * Maps a user onto SAML attributes for one service provider.
 *
 * The SP's attribute_map is a JSON object of { "SAML attribute name": field },
 * where field is one of the keys below - the same attribute names the OIDC
 * claims use where they overlap, so an operator configuring both protocols
 * writes one vocabulary. An empty map falls back to DEFAULT_ATTRIBUTE_MAP,
 * which is what Cloudflare Access expects out of the box.
 *
 * A non-empty attribute_definitions column (arbitrary Name plus optional
 * arbitrary NameFormat per attribute - IIP-IDP01) replaces the map entirely.
 */

const DEFAULT_ATTRIBUTE_MAP: Record<string, string> = {
  email: "email",
  name: "name",
  given_name: "given_name",
  family_name: "family_name",
  groups: "groups",
};

export const USER_ATTRIBUTE_FIELDS = [
  "email",
  "upn",
  "username",
  "name",
  "given_name",
  "family_name",
  "id",
  "groups",
  "job_title",
  "department",
  "manager",
  "employee_number",
  "hire_date",
  "employment_status",
  "employment_type",
  "location",
] as const;

export async function resolveAttributes(
  env: Env,
  sp: SamlServiceProviderRow,
  user: UserRow
): Promise<ResolvedAttribute[]> {
  const definitions = spAttributeDefinitions(sp);
  const configured = spAttributeMap(sp);
  const map = Object.keys(configured).length > 0 ? configured : DEFAULT_ATTRIBUTE_MAP;
  // attribute_definitions wins over the plain map when any are configured.
  const wanted: SpAttributeDefinition[] = definitions.length > 0 ? definitions : Object.entries(map).map(([name, field]) => ({ name, field }));

  const groups = await getUserGroupNames(env, user.id);
  const fields: Record<string, string | string[] | null> = {
    email: user.upn,
    upn: user.upn,
    username: user.username,
    name: user.display_name,
    given_name: user.given_name,
    family_name: user.family_name,
    id: user.external_id,
    groups,
    job_title: user.job_title,
    department: user.department,
    manager: await getManagerEmail(env, user.manager_external_id),
    employee_number: user.employee_number,
    hire_date: user.hire_date,
    employment_status: user.employment_status,
    employment_type: user.employment_type,
    location: user.location,
  };

  const custom = parseCustomAttributes(user.custom_attributes);
  const attributes: ResolvedAttribute[] = [];
  for (const def of wanted) {
    // Fields outside the fixed vocabulary resolve against custom attributes -
    // that is how schema-defined attributes reach an SP.
    const value = def.field in fields ? fields[def.field] : custom[def.field];
    if (value === undefined || value === null) continue;
    const values = (Array.isArray(value) ? value : [value]).filter((v) => v !== "");
    if (values.length === 0) continue;
    attributes.push(def.nameFormat ? { name: def.name, nameFormat: def.nameFormat, values } : { name: def.name, values });
  }
  const subject = await subjectIdentifier(env, sp, user);
  if (subject) attributes.push(subject);
  return attributes;
}

export const SUBJECT_ID = "urn:oasis:names:tc:SAML:attribute:subject-id";
export const PAIRWISE_ID = "urn:oasis:names:tc:SAML:attribute:pairwise-id";

/**
 * subject-id: the user's immutable external id, scoped to their UPN domain.
 * pairwise-id: a per-SP value (HMAC-style hash with an instance secret) so
 * two SPs cannot correlate a user. Both scopes are published as shibmd:Scope.
 */
async function subjectIdentifier(env: Env, sp: SamlServiceProviderRow, user: UserRow): Promise<ResolvedAttribute | null> {
  if (sp.subject_id !== "subject-id" && sp.subject_id !== "pairwise-id") return null;
  const scope = user.upn.split("@")[1]?.toLowerCase() ?? "";
  if (!scope) return null;
  if (sp.subject_id === "subject-id") return { name: SUBJECT_ID, values: [`${user.external_id.toLowerCase()}@${scope}`] };
  const salt = await pairwiseSalt(env);
  const value = await sha256Hex(`flareid pairwise-id v1\n${salt}\n${user.external_id}\n${sp.entity_id}`);
  return { name: PAIRWISE_ID, values: [`${value}@${scope}`] };
}

async function pairwiseSalt(env: Env): Promise<string> {
  const row = await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'saml_pairwise_salt'").first<{ value: string }>();
  if (row?.value) return row.value;
  await env.DB.prepare("INSERT OR IGNORE INTO idp_settings (key, value, updated_at) VALUES ('saml_pairwise_salt', ?, ?)").bind(randomToken(32), new Date().toISOString()).run();
  return (await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'saml_pairwise_salt'").first<{ value: string }>())!.value;
}

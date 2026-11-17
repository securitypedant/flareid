import type { GroupRow, LdapAppRow, UserRow } from "../lib/types.js";
import { escapeDnValue } from "./dn.js";
import type { DirectoryView } from "./directory.js";
import type { LdapSettings } from "./settings.js";
import { GROUP_RID_BASE, USER_RID_BASE, objectCategory, sidToBytes, toGeneralizedTime, uuidToGuidBytes, uuidV5 } from "./ad.js";
import type { EvalEntry } from "./filter.js";

/**
 * Entry materialisation (LDAP.md section 8): users, groups, containers, the
 * root DSE and the subschema entry, built from a DirectoryView so an app only
 * ever sees its own slice of the directory.
 */

export type LdapEntry = EvalEntry;

const enc = new TextEncoder();

function put(attrs: Map<string, (string | Uint8Array)[]>, name: string, ...values: (string | Uint8Array | undefined | null)[]): void {
  const vs = values.filter((v): v is string | Uint8Array => v !== undefined && v !== null && v !== "");
  if (vs.length) attrs.set(name.toLowerCase(), vs);
}

export const USER_RDN = (username: string, slug: string, baseDn: string) => `uid=${escapeDnValue(username)},ou=people,ou=${escapeDnValue(slug)},${baseDn}`;
export const GROUP_RDN = (name: string, slug: string, baseDn: string) => `cn=${escapeDnValue(name)},ou=groups,ou=${escapeDnValue(slug)},${baseDn}`;
export const APP_BRANCH_DN = (slug: string, baseDn: string) => `ou=${escapeDnValue(slug)},${baseDn}`;
export const PEOPLE_DN = (slug: string, baseDn: string) => `ou=people,${APP_BRANCH_DN(slug, baseDn)}`;
export const GROUPS_DN = (slug: string, baseDn: string) => `ou=groups,${APP_BRANCH_DN(slug, baseDn)}`;
export const SERVICES_BRANCH_DN = (baseDn: string) => `ou=services,${baseDn}`;
export const SERVICE_DN = (slug: string, baseDn: string) => `cn=${escapeDnValue(slug)},${SERVICES_BRANCH_DN(baseDn)}`;

/** LDAP attribute names that must never leave the directory (LDAP.md section 8). */
const NEVER_RETURNED = new Set(["userpassword", "password_hash", "password_salt", "totp_secret", "totp_last_counter", "unicodepwd", "scim_id"]);
const CUSTOM_ATTR_NAME = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;

export async function userEntry(user: UserRow, view: DirectoryView, app: LdapAppRow, settings: LdapSettings): Promise<LdapEntry> {
  const dn = USER_RDN(user.username, app.slug, settings.baseDn);
  const attrs = new Map<string, (string | Uint8Array)[]>();
  const active = user.status === "active";
  put(attrs, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson", "user", "posixAccount", "shadowAccount");
  put(attrs, "uid", user.username);
  put(attrs, "cn", user.display_name || user.username);
  put(attrs, "displayName", user.display_name);
  put(attrs, "givenName", user.given_name);
  put(attrs, "sn", user.family_name || user.display_name || user.username); // person requires sn
  put(attrs, "mail", user.email ?? user.upn);
  put(attrs, "userPrincipalName", user.upn);
  put(attrs, "sAMAccountName", user.username);
  put(attrs, "title", user.job_title);
  put(attrs, "department", user.department);
  put(attrs, "employeeNumber", user.employee_number);
  put(attrs, "employeeType", user.employment_type);
  put(attrs, "l", user.location);
  const manager = user.manager_external_id ? [...view.userById.values()].find((u) => u.external_id === user.manager_external_id) : undefined;
  if (manager && view.users.includes(manager)) put(attrs, "manager", USER_RDN(manager.username, app.slug, settings.baseDn));
  put(
    attrs,
    "memberOf",
    ...(view.userGroups.get(user.id) ?? []).map((gid) => {
      const g = view.groups.find((x) => x.id === gid);
      return g ? GROUP_RDN(g.name, app.slug, settings.baseDn) : "";
    })
  );
  put(attrs, "entryUUID", user.external_id);
  try {
    attrs.set("objectguid", [uuidToGuidBytes(user.external_id)]);
  } catch {
    /* a non-UUID external_id gets no objectGUID */
  }
  if (settings.domainSid) {
    try {
      attrs.set("objectsid", [sidToBytes(`${settings.domainSid}-${USER_RID_BASE + user.id}`)]);
    } catch {
      /* malformed generated SID */
    }
  }
  put(attrs, "objectCategory", objectCategory("Person", settings.baseDn));
  put(attrs, "sAMAccountType", "805306368");
  put(attrs, "userAccountControl", active ? "512" : "514");
  // POSIX (section 12)
  put(attrs, "uidNumber", String(settings.posixUidBase + user.id));
  put(attrs, "gidNumber", String(settings.posixDefaultGid));
  put(attrs, "homeDirectory", settings.posixHome.replace("{username}", user.username));
  put(attrs, "loginShell", settings.posixShell);
  put(attrs, "gecos", (user.display_name || user.username).replace(/[^\x20-\x7e]/g, ""));
  // Timestamps
  const created = toGeneralizedTime(user.created_at);
  const changed = toGeneralizedTime(user.updated_at);
  put(attrs, "whenCreated", created);
  put(attrs, "createTimestamp", created);
  put(attrs, "whenChanged", changed);
  put(attrs, "modifyTimestamp", changed);
  put(attrs, "distinguishedName", dn);
  // Schema attributes that survive as valid LDAP attribute names (section 8).
  try {
    const custom = JSON.parse(user.custom_attributes || "{}") as Record<string, string>;
    for (const [k, v] of Object.entries(custom)) {
      const name = k.toLowerCase();
      if (CUSTOM_ATTR_NAME.test(k) && !attrs.has(name) && !NEVER_RETURNED.has(name)) put(attrs, k, String(v).slice(0, 1024));
    }
  } catch {
    /* malformed custom_attributes JSON adds nothing */
  }
  return { dn, attrs };
}

export async function groupEntry(group: GroupRow, view: DirectoryView, app: LdapAppRow, settings: LdapSettings): Promise<LdapEntry> {
  const dn = GROUP_RDN(group.name, app.slug, settings.baseDn);
  const attrs = new Map<string, (string | Uint8Array)[]>();
  const memberIds = view.groupMembers.get(group.id) ?? [];
  const memberDns = memberIds
    .map((id) => view.userById.get(id))
    .filter((u): u is UserRow => !!u)
    .map((u) => USER_RDN(u.username, app.slug, settings.baseDn));
  const memberNames = memberIds
    .map((id) => view.userById.get(id))
    .filter((u): u is UserRow => !!u)
    .map((u) => u.username);
  // groupOfNames + groupOfUniqueNames together is technically two structural
  // classes; deliberate (LDAP.md section 8) - vCenter wants the latter.
  put(attrs, "objectClass", "top", "groupOfNames", "groupOfUniqueNames", "posixGroup", "group");
  put(attrs, "cn", group.name);
  put(attrs, "description", group.description ?? "");
  put(attrs, "member", ...memberDns);
  put(attrs, "uniqueMember", ...memberDns);
  put(attrs, "memberUid", ...memberNames);
  put(attrs, "gidNumber", String(settings.posixGidBase + group.id));
  put(attrs, "sAMAccountName", group.name);
  put(attrs, "groupType", "-2147483646");
  put(attrs, "sAMAccountType", "268435456");
  put(attrs, "objectCategory", objectCategory("Group", settings.baseDn));
  const uuid = await uuidV5(settings.guidNamespace || "00000000-0000-5000-8000-000000000000", `group:${group.id}`);
  put(attrs, "entryUUID", uuid);
  attrs.set("objectguid", [uuidToGuidBytes(uuid)]);
  if (settings.domainSid) {
    try {
      attrs.set("objectsid", [sidToBytes(`${settings.domainSid}-${GROUP_RID_BASE + group.id}`)]);
    } catch {
      /* malformed generated SID */
    }
  }
  put(attrs, "distinguishedName", dn);
  return { dn, attrs };
}

/** The naming-context and per-app container entries (section 8). */
export function containerEntries(app: LdapAppRow, settings: LdapSettings): LdapEntry[] {
  const out: LdapEntry[] = [];
  const base = settings.baseDn;
  if (!base) return out;
  const domainAttrs = new Map<string, (string | Uint8Array)[]>();
  put(domainAttrs, "objectClass", "top", "domain", "dcObject");
  put(domainAttrs, "dc", settings.base[0]?.value ?? "");
  out.push({ dn: base, attrs: domainAttrs });
  const ou = (dn: string, name: string): LdapEntry => {
    const a = new Map<string, (string | Uint8Array)[]>();
    put(a, "objectClass", "top", "organizationalUnit");
    put(a, "ou", name);
    return { dn, attrs: a };
  };
  out.push(ou(APP_BRANCH_DN(app.slug, base), app.slug));
  out.push(ou(PEOPLE_DN(app.slug, base), "people"));
  out.push(ou(GROUPS_DN(app.slug, base), "groups"));
  return out;
}

export function rootDse(settings: LdapSettings): LdapEntry {
  const attrs = new Map<string, (string | Uint8Array)[]>();
  put(attrs, "namingContexts", settings.baseDn);
  put(attrs, "defaultNamingContext", settings.baseDn);
  put(attrs, "rootDomainNamingContext", settings.baseDn);
  put(attrs, "subschemaSubentry", "cn=Subschema");
  put(attrs, "supportedLDAPVersion", "3");
  put(attrs, "supportedControl", "1.2.840.113556.1.4.319");
  put(attrs, "supportedControl", "1.2.840.113556.1.4.473");
  put(attrs, "supportedExtension", "1.3.6.1.4.1.4203.1.11.3");
  put(attrs, "supportedFeatures", "1.3.6.1.4.1.4203.1.5.1");
  put(attrs, "vendorName", "FlareID");
  put(attrs, "dnsHostName", settings.hostname);
  return { dn: "", attrs };
}

/**
 * The subschema entry. `objectClasses` / `attributeTypes` / `matchingRules` /
 * `ldapSyntaxes` cover exactly what the entries above emit, so the schema and
 * the entries cannot drift: both come from the same attribute table.
 */
export function subschemaEntry(): LdapEntry {
  const attrs = new Map<string, (string | Uint8Array)[]>();
  attrs.set("objectclass", ["top", "subschema"]);
  attrs.set("cn", ["Subschema"]);
  attrs.set(
    "attributetypes",
    Object.entries(ATTRIBUTE_DEFS).map(([name, d]) => `( ${d.oid} NAME '${name}'${d.sup ? ` SUP ${d.sup}` : ""} EQUALITY ${d.eq} ORDERING ${d.ord ?? d.eq} SUBSTR ${d.sub ?? d.eq} SYNTAX ${d.syntax} )`)
  );
  attrs.set(
    "objectclasses",
    OBJECT_CLASSES.map(
      ([name, oid, sup, must, may]) =>
        `( ${oid} NAME '${name}' SUP ${sup} STRUCTURAL MUST ( ${must.join(" $ ")} )${may.length ? ` MAY ( ${may.join(" $ ")} )` : ""} )`
    )
  );
  attrs.set(
    "matchingrules",
    MATCHING_RULES.map(([oid, syntax]) => `( ${oid} NAME '${MATCHING_NAMES[oid] ?? oid}' SYNTAX ${syntax} )`)
  );
  attrs.set("ldapsyntaxes", SYNTAXES.map(([oid, desc]) => `( ${oid} DESC '${desc}' )`));
  return { dn: "cn=Subschema", attrs };
}

// The attribute table the subschema is generated from (RFC 4517 syntaxes /
// matching rules; MS-ADSC for the AD attributes).
const DIR_STRING = "1.3.6.1.4.1.1466.115.121.1.15";
const INTEGER_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.27";
const GT_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.24";
const DN_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.12";
const BINARY_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.40";
const IA5_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.26";
const CI = "caseIgnoreMatch";
const CE = "caseExactMatch";
const DNM = "distinguishedNameMatch";
const IM = "integerMatch";
const IO = "integerOrderingMatch";
const GT = "generalizedTimeMatch";
const GTO = "generalizedTimeOrderingMatch";

interface AttrDef { oid: string; syntax: string; eq: string; ord?: string; sub?: string; sup?: string }

const ATTRIBUTE_DEFS: Record<string, AttrDef> = {
  uid: { oid: "0.9.2342.19200300.100.1.1", syntax: DIR_STRING, eq: CI, sub: "caseIgnoreSubstringsMatch" },
  cn: { oid: "2.5.4.3", syntax: DIR_STRING, eq: CI, sub: "caseIgnoreSubstringsMatch" },
  sn: { oid: "2.5.4.4", syntax: DIR_STRING, eq: CI, sub: "caseIgnoreSubstringsMatch" },
  dc: { oid: "0.9.2342.19200300.100.1.25", syntax: DIR_STRING, eq: CI },
  ou: { oid: "2.5.4.11", syntax: DIR_STRING, eq: CI },
  displayName: { oid: "2.16.840.1.113730.3.1.241", syntax: DIR_STRING, eq: CI, sub: "caseIgnoreSubstringsMatch" },
  givenName: { oid: "2.5.4.42", syntax: DIR_STRING, eq: CI, sub: "caseIgnoreSubstringsMatch" },
  mail: { oid: "0.9.2342.19200300.100.1.3", syntax: IA5_SYNTAX, eq: "caseIgnoreIA5Match", sub: "caseIgnoreIA5SubstringsMatch" },
  title: { oid: "2.5.4.12", syntax: DIR_STRING, eq: CI },
  department: { oid: "2.16.840.1.113730.3.1.1", syntax: DIR_STRING, eq: CI },
  l: { oid: "2.5.4.7", syntax: DIR_STRING, eq: CI },
  description: { oid: "2.5.4.13", syntax: DIR_STRING, eq: CI },
  gecos: { oid: "1.3.6.1.1.1.1.2", syntax: IA5_SYNTAX, eq: CE },
  userPrincipalName: { oid: "1.2.840.113556.1.4.656", syntax: DIR_STRING, eq: CI },
  sAMAccountName: { oid: "1.2.840.113556.1.4.221", syntax: DIR_STRING, eq: CI },
  sAMAccountType: { oid: "1.2.840.113556.1.4.302", syntax: INTEGER_SYNTAX, eq: IM, ord: IO },
  userAccountControl: { oid: "1.2.840.113556.1.4.8", syntax: INTEGER_SYNTAX, eq: IM, ord: IO },
  groupType: { oid: "1.2.840.113556.1.4.750", syntax: INTEGER_SYNTAX, eq: IM, ord: IO },
  objectCategory: { oid: "1.2.840.113556.1.4.782", syntax: DN_SYNTAX, eq: DNM },
  distinguishedName: { oid: "2.5.4.49", syntax: DN_SYNTAX, eq: DNM },
  member: { oid: "2.5.4.31", syntax: DN_SYNTAX, eq: DNM },
  uniqueMember: { oid: "2.5.4.50", syntax: DN_SYNTAX, eq: DNM },
  memberOf: { oid: "1.2.840.113556.1.4.222", syntax: DN_SYNTAX, eq: DNM },
  manager: { oid: "0.9.2342.19200300.100.1.10", syntax: DN_SYNTAX, eq: DNM },
  memberUid: { oid: "1.3.6.1.1.1.1.12", syntax: IA5_SYNTAX, eq: CE },
  uidNumber: { oid: "1.3.6.1.1.1.1.0", syntax: INTEGER_SYNTAX, eq: IM, ord: IO },
  gidNumber: { oid: "1.3.6.1.1.1.1.1", syntax: INTEGER_SYNTAX, eq: IM, ord: IO },
  homeDirectory: { oid: "1.3.6.1.1.1.1.3", syntax: IA5_SYNTAX, eq: CE },
  loginShell: { oid: "1.3.6.1.1.1.1.4", syntax: IA5_SYNTAX, eq: CE },
  employeeNumber: { oid: "2.16.840.1.113730.3.1.3", syntax: DIR_STRING, eq: CI },
  employeeType: { oid: "2.16.840.1.113730.3.1.4", syntax: DIR_STRING, eq: CI },
  entryUUID: { oid: "1.3.6.1.1.16.4", syntax: DIR_STRING, eq: "uuidMatch" },
  objectGUID: { oid: "1.2.840.113556.1.4.2", syntax: "1.2.840.113556.1.4.906", eq: "octetStringMatch" },
  objectSid: { oid: "1.2.840.113556.1.4.146", syntax: "1.2.840.113556.1.4.907", eq: "octetStringMatch" },
  whenCreated: { oid: "1.2.840.113556.1.4.26", syntax: GT_SYNTAX, eq: GT, ord: GTO },
  createTimestamp: { oid: "2.5.4.1", syntax: GT_SYNTAX, eq: GT, ord: GTO },
  whenChanged: { oid: "1.2.840.113556.1.4.25", syntax: GT_SYNTAX, eq: GT, ord: GTO },
  modifyTimestamp: { oid: "2.5.4.3", syntax: GT_SYNTAX, eq: GT, ord: GTO },
  hasSubordinates: { oid: "2.5.18.9", syntax: "1.3.6.1.4.1.1466.115.121.1.7", eq: "booleanMatch" },
  subschemaSubentry: { oid: "2.5.18.10", syntax: DN_SYNTAX, eq: DNM },
};

const OBJECT_CLASSES: [string, string, string, string[], string[]][] = [
  ["top", "2.5.6.0", "top", ["objectClass"], []],
  ["person", "2.5.6.6", "top", ["sn", "cn"], []],
  ["organizationalPerson", "2.5.6.7", "person", [], ["title", "l", "ou"]],
  ["inetOrgPerson", "2.16.840.1.113730.3.2.2", "organizationalPerson", [], ["displayName", "givenName", "mail", "uid", "employeeNumber", "employeeType", "manager"]],
  ["user", "1.2.840.113556.1.5.9", "organizationalPerson", [], ["sAMAccountName", "userPrincipalName", "userAccountControl", "sAMAccountType", "objectCategory", "objectGUID", "objectSid"]],
  ["posixAccount", "1.3.6.1.1.1.2.0", "top", ["cn", "uid", "uidNumber", "gidNumber", "homeDirectory"], ["loginShell", "gecos"]],
  ["shadowAccount", "1.3.6.1.1.1.2.1", "top", ["uid"], []],
  ["groupOfNames", "2.5.6.9", "top", ["cn", "member"], ["description"]],
  ["groupOfUniqueNames", "2.5.6.17", "top", ["cn", "uniqueMember"], ["description"]],
  ["posixGroup", "1.3.6.1.1.1.2.2", "top", ["cn", "gidNumber"], ["memberUid", "description"]],
  ["group", "1.2.840.113556.1.5.24", "top", ["cn"], ["member", "sAMAccountName", "groupType", "sAMAccountType", "objectGUID", "objectSid"]],
  ["domain", "1.2.840.113556.1.5.66", "top", ["dc"], []],
  ["dcObject", "1.3.6.1.4.1.1466.344", "top", ["dc"], []],
  ["organizationalUnit", "2.5.6.5", "top", ["ou"], []],
  ["subschema", "2.5.20.1", "top", [], ["objectClasses", "attributeTypes", "matchingRules", "ldapSyntaxes"]],
];

const MATCHING_RULES: [string, string][] = [
  ["2.5.13.2", DIR_STRING],
  ["2.5.13.5", IA5_SYNTAX],
  ["2.5.13.8", INTEGER_SYNTAX],
  ["2.5.13.10", INTEGER_SYNTAX],
  ["2.5.13.11", DIR_STRING],
  ["2.5.13.14", DN_SYNTAX],
  ["2.5.13.16", IA5_SYNTAX],
  ["2.5.13.19", IA5_SYNTAX],
  ["2.5.13.20", IA5_SYNTAX],
  ["2.5.13.27", GT_SYNTAX],
  ["2.5.13.28", GT_SYNTAX],
];
const MATCHING_NAMES: Record<string, string> = {
  "2.5.13.2": "caseIgnoreMatch",
  "2.5.13.5": "caseExactMatch",
  "2.5.13.8": "integerMatch",
  "2.5.13.10": "integerOrderingMatch",
  "2.5.13.11": "caseIgnoreListMatch",
  "2.5.13.14": "distinguishedNameMatch",
  "2.5.13.16": "octetStringMatch",
  "2.5.13.19": "caseIgnoreIA5Match",
  "2.5.13.20": "caseIgnoreSubstringsMatch",
  "2.5.13.27": "generalizedTimeMatch",
  "2.5.13.28": "generalizedTimeOrderingMatch",
};
const SYNTAXES: [string, string][] = [
  [DIR_STRING, "Directory String"],
  [INTEGER_SYNTAX, "INTEGER"],
  [GT_SYNTAX, "Generalized Time"],
  [DN_SYNTAX, "DN"],
  [BINARY_SYNTAX, "Octet String"],
  [IA5_SYNTAX, "IA5 String"],
  ["1.3.6.1.4.1.1466.115.121.1.7", "BOOLEAN"],
  ["1.2.840.113556.1.4.906", "Large Integer"],
  ["1.2.840.113556.1.4.907", "SID"],
];

/** Does a named attribute get returned? (Filters evaluate separately.) */
export function isReturnable(name: string): boolean {
  return !NEVER_RETURNED.has(name.toLowerCase());
}

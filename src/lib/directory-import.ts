import { getUserGroupNames } from "./db.js";
import { getPasswordPolicy, isBreachedPasswordCheckEnabled, validatePassword, type PasswordPolicy } from "./settings.js";
import { breachCount, breachMessage } from "./breached-passwords.js";
import { revokeAccountTokens } from "./account-tokens.js";
import type { Env } from "../env.js";
import { hashPassword, type PasswordHash } from "./password.js";
import { ensureDomain, getDefaultDomain, isValidDomain } from "./domains.js";
import { resolveNewAccountPassword } from "./settings.js";
import { SUPER_ADMINS_GROUP } from "./middleware.js";
import { adminRoleGroupIds, adminRoleGroupNames, grantsAdminRoleGroup } from "./admin-roles.js";
import { findSchema, getSchemaAttributes, splitUserAttributes, parseCustomAttributes, defaultSchemaId, userEditableAttributeNames } from "./schemas.js";
import { parseRule, userMatchesRule, type GroupRule } from "./groups.js";
import { WATCHLIST_GROUP_NAME } from "./cfone.js";
import { deleteUserStatements, revokeAllSessionsForUser, revokeTokensForUser } from "./sessions.js";
import { deleteGroupScim, deleteUserScim, isScimConfigured, pushUser, syncGroupsAllTargets, scimDeprovisionStatementsForMany, drainScimDeprovisionQueue } from "./scim-client.js";
import { setUserEmails, UserEmailError } from "./user-emails.js";
import type { GroupRow, UserRow } from "./types.js";

/**
 * Bulk directory import.
 *
 * The important property of the bundle format is that it carries NO domain on
 * its users: each one is identified by `username`, and the UPN is composed
 * server-side as `username@domain` from the `domain` field (or the instance's
 * default). That is what makes one bundle importable onto any deployment, and
 * it is what replaced an earlier arrangement where the demo suite seeded users
 * at @company.com in a migration and then rewrote every text column in every
 * database afterwards to match the real zone.
 *
 * Group membership is deliberately explicit. The admin UI auto-joins new users
 * to "All Employees", because a human filling in a form should not have to
 * remember; an import describes the directory it wants and gets exactly that,
 * because a bundle that silently gains memberships is a bundle you cannot
 * reason about. A service account that should not be in "All Employees" simply
 * does not list it.
 */

/** No password can ever verify against this (see verifyPassword): the account waits for an invitation or reset. */
const UNUSABLE_PASSWORD = { hash: "!", salt: "", iterations: 0 };

/** Per-request cap. PBKDF2 is ~30-60ms per new user, so this bounds CPU time; callers chunk. */
export const MAX_USERS_PER_IMPORT = 100;

/**
 * Imported passwords are checked against breached-password data only when the
 * import carries at most this many users with explicit passwords, so a big
 * import is not held up by a round-trip per password. (With the per-request
 * cap above, every request currently qualifies; the browser's CSV import sends
 * chunks, each checked on its own.)
 */
export const IMPORT_BREACH_CHECK_MAX_USERS = 200;
/** Concurrent range requests during an import's breach check. */
const IMPORT_BREACH_CHECK_CONCURRENCY = 6;

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

/**
 * The breached passwords among an import's explicit passwords, each mapped to
 * its message. Each distinct password is asked about once; passwords the
 * policy already refuses are not asked about at all. If the service cannot
 * answer, the remaining passwords are not checked (the check fails open).
 */
async function breachedImportPasswords(env: Env, users: DirectoryUser[], policy: PasswordPolicy): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  const explicit = users.map((u) => u.password).filter((p): p is string => typeof p === "string" && p !== "");
  if (explicit.length === 0 || explicit.length > IMPORT_BREACH_CHECK_MAX_USERS || !(await isBreachedPasswordCheckEnabled(env))) return found;
  const distinct = [...new Set(explicit)].filter((p) => !validatePassword(p, policy));
  for (let i = 0; i < distinct.length; i += IMPORT_BREACH_CHECK_CONCURRENCY) {
    const batch = distinct.slice(i, i + IMPORT_BREACH_CHECK_CONCURRENCY);
    const counts = await Promise.all(batch.map((p) => breachCount(p)));
    counts.forEach((n, j) => {
      if (n) found.set(batch[j]!, breachMessage(n));
    });
    if (counts.includes(null)) break;
  }
  return found;
}

export interface DirectoryGroup {
  /** Dynamic membership rule JSON, e.g. {"all":[{"field":"employment_type","op":"eq","value":"full_time"}]}. */
  name: string;
  description?: string;
  rule?: string;
}

export interface DirectoryUser {
  username: string;
  display_name?: string;
  given_name?: string;
  family_name?: string;
  /** Omit or null to use the configured default/generated password. Ignored for users that already exist. */
  password?: string | null;
  /** Omit to leave existing membership alone; [] to clear it; a list to set it exactly. */
  groups?: string[];
  job_title?: string;
  department?: string;
  employee_number?: string;
  hire_date?: string;
  employment_status?: string;
  employment_type?: string;
  location?: string;
  /** Another user's `username`, resolved to their external_id in a second pass. */
  manager?: string | null;
  status?: "active" | "disabled";
  /** Where email for the account goes, when not the UPN. Omit to leave as is; "" to clear. */
  email?: string;
  super_admin?: boolean;
  /** Schema name (e.g. "FlareID HR") the user should conform to; defaults to the deployment's Bare schema. */
  schema?: string;
  /** Attribute values keyed by schema attribute name; names matching built-in fields map to columns, the rest become custom attributes. */
  attributes?: Record<string, string>;
}

export interface DirectoryBundle {
  version?: number;
  mode?: "merge" | "replace";
  /**
   * For new users with no `password`: "default" (the new-account password
   * setting - generated or shared) or "none" - no usable password at all, so
   * the account is activated by an invitation or an admin reset. "none" costs
   * no hashing, which is what makes a 10,000-row CSV import feasible.
   */
  passwords?: "default" | "none";
  domain?: string;
  groups?: DirectoryGroup[];
  users?: DirectoryUser[];
}

export interface ImportResult {
  domain: string;
  mode: "merge" | "replace";
  users: { created: number; updated: number; skipped: number };
  groups: { created: number; updated: number };
  /** Only for users created during this import whose password was generated rather than supplied. */
  generated_passwords: Record<string, string>;
  managers_resolved: number;
  errors: { username?: string; group?: string; message: string }[];
  /** Present when SCIM is configured: what was pushed to, or removed from, the SCIM server. */
  scim?: { users_pushed: number; users_removed: number; groups_pushed: number; groups_removed: number; errors: number };
}

export class ImportValidationError extends Error {}

function cleanString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Rejects a bundle outright, before anything is written.
 *
 * Validation is all up front rather than per-row because a bundle with a
 * malformed username is a generator bug, and half-importing it leaves a
 * directory that is neither the old one nor the new one.
 */
export function validateBundle(bundle: DirectoryBundle): { users: DirectoryUser[]; groups: DirectoryGroup[] } {
  if (bundle.version !== undefined && bundle.version !== 1) {
    throw new ImportValidationError(`Unsupported bundle version ${bundle.version}; this FlareID understands version 1.`);
  }
  if (bundle.mode !== undefined && bundle.mode !== "merge" && bundle.mode !== "replace") {
    throw new ImportValidationError(`mode must be "merge" or "replace", got "${bundle.mode}".`);
  }

  const users = Array.isArray(bundle.users) ? bundle.users : [];
  const groups = Array.isArray(bundle.groups) ? bundle.groups : [];

  if (users.length > MAX_USERS_PER_IMPORT) {
    throw new ImportValidationError(
      `${users.length} users in one request; the maximum is ${MAX_USERS_PER_IMPORT}. Split the bundle into chunks - the import is idempotent by username, so chunking is safe.`
    );
  }

  const seen = new Set<string>();
  for (const user of users) {
    const username = cleanString(user.username).toLowerCase();
    if (!username) throw new ImportValidationError("Every user needs a username.");
    if (!USERNAME_PATTERN.test(username)) {
      throw new ImportValidationError(
        `Invalid username "${username}". Usernames are the local part of a UPN: lowercase letters, digits, dot, underscore and hyphen, starting with a letter or digit.`
      );
    }
    if (seen.has(username)) throw new ImportValidationError(`Duplicate username "${username}" in the same bundle.`);
    seen.add(username);

    if (user.email !== undefined && user.email !== "" && !/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(String(user.email))) {
      throw new ImportValidationError(`User "${username}" has an invalid email "${user.email}".`);
    }
    if (user.status !== undefined && user.status !== "active" && user.status !== "disabled") {
      throw new ImportValidationError(`User "${username}" has status "${user.status}"; expected "active" or "disabled".`);
    }
  }

  for (const group of groups) {
    if (!cleanString(group.name)) throw new ImportValidationError("Every group needs a name.");
  }

  return { users, groups };
}

/**
 * Wipes everything a previous import created, keeping the built-in groups and
 * anyone who administers the directory.
 *
 * Super Admins survive on purpose: `mode: "replace"` is for reshaping the
 * directory, not for locking yourself out of it. A caller that genuinely wants
 * an empty instance can delete the administrators afterwards.
 */
/** Rules of the dynamic groups linked to admin roles - who holds a role by attribute, not by a group_members row. */
async function dynamicAdminRules(env: Env): Promise<GroupRule[]> {
  const ids = await adminRoleGroupIds(env);
  if (!ids.size) return [];
  const { results } = await env.DB.prepare("SELECT rule FROM groups WHERE rule != '' AND id IN (SELECT value FROM json_each(?))")
    .bind(JSON.stringify([...ids]))
    .all<{ rule: string }>();
  return results.map((r) => parseRule(r.rule)).filter((r): r is GroupRule => r !== null);
}

async function replaceExistingDirectory(env: Env): Promise<{ users: UserRow[]; groups: GroupRow[] }> {
  // Replace keeps the administrators - everyone holding an admin role - and
  // the two built-in groups the docs promise survive (role groups plus All
  // Employees). All Employees is not a keep-everyone clause: it lands only
  // in the group list, users are still decided by role membership.
  const roleNames = await adminRoleGroupNames(env);
  const roles = JSON.stringify(roleNames);
  const keepGroups = JSON.stringify([...roleNames, "All Employees"]);
  const { results: doomedStatic } = await env.DB.prepare(
    `SELECT * FROM users
      WHERE id NOT IN (
        SELECT user_id FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE name IN (SELECT value FROM json_each(?)))
      )`
  )
    .bind(roles)
    .all<UserRow>();
  // Admins by dynamic membership have no group_members row to keep them - keep them too.
  const dynRules = await dynamicAdminRules(env);
  const doomed = dynRules.length ? doomedStatic.filter((u) => !dynRules.some((r) => userMatchesRule(u, r))) : doomedStatic;
  const { results: doomedGroups } = await env.DB.prepare("SELECT * FROM groups WHERE name NOT IN (SELECT value FROM json_each(?)) AND system = ''").bind(keepGroups).all<GroupRow>();

  // The remote ids are queued in the same batch as the deletion: once the
  // rows (and their links) are gone, the queue is the only way to find these
  // objects downstream.
  const queue = [
    ...(await scimDeprovisionStatementsForMany(env, "user", doomed.map((u) => ({ id: u.id, label: u.upn })))),
    ...(await scimDeprovisionStatementsForMany(env, "group", doomedGroups.map((g) => ({ id: g.id, label: g.name })))),
  ];
  const linkedUsers = new Set(queue.length ? (await env.DB.prepare("SELECT user_id AS id FROM scim_user_links WHERE user_id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(doomed.map((u) => u.id))).all<{ id: number }>()).results.map((r) => r.id) : []);
  const linkedGroups = new Set(queue.length ? (await env.DB.prepare("SELECT group_id AS id FROM scim_group_links WHERE group_id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(doomedGroups.map((g) => g.id))).all<{ id: number }>()).results.map((r) => r.id) : []);
  await env.DB.batch([
    ...queue,
    ...(doomed.length > 0 ? deleteUserStatements(env, ...doomed.map((r) => r.id)) : []),
    env.DB.prepare(`DELETE FROM groups WHERE name NOT IN (SELECT value FROM json_each(?)) AND system = ''`).bind(keepGroups),
  ]);

  // Returned so the caller knows remote DELETEs are queued: the linked rows
  // are gone after this, their queued remote ids are what survives.
  return { users: doomed.filter((u) => linkedUsers.has(u.id)), groups: doomedGroups.filter((g) => linkedGroups.has(g.id)) };
}

export interface ImportOptions {
  /**
   * Whether the caller may use the bundle features that grant or seize Super
   * Admin: super_admin:true, "Super Admins" in a user's groups, or any row
   * whose username matches an existing Super Admin (which would reset that
   * admin's password and attributes). The import route passes the caller's
   * `admin` scope; the bootstrap setup and break-glass paths pass true.
   */
  allowPrivileged?: boolean;
}

/** Above this many people, an import re-pushes every group rather than working out which changed. */
const SCIM_TARGETED_LIMIT = 200;

async function groupIdsForUser(env: Env, userId: number): Promise<number[]> {
  const names = await getUserGroupNames(env, userId);
  if (!names.length) return [];
  const { results } = await env.DB.prepare("SELECT id FROM groups WHERE name IN (SELECT value FROM json_each(?))").bind(JSON.stringify(names)).all<{ id: number }>();
  return results.map((r) => r.id);
}

async function groupIdsOfUsernames(env: Env, usernames: string[]): Promise<Set<number>> {
  const { results } = await env.DB.prepare("SELECT id FROM users WHERE username IN (SELECT value FROM json_each(?))").bind(JSON.stringify(usernames)).all<{ id: number }>();
  const out = new Set<number>();
  for (const r of results) for (const g of await groupIdsForUser(env, r.id)) out.add(g);
  return out;
}

async function affectedGroupIds(env: Env, before: Set<number>, userIds: number[], bundleGroupNames: string[]): Promise<number[]> {
  const out = new Set(before);
  for (const id of userIds) for (const g of await groupIdsForUser(env, id)) out.add(g);
  if (bundleGroupNames.length) {
    const { results } = await env.DB.prepare("SELECT id FROM groups WHERE name IN (SELECT value FROM json_each(?))").bind(JSON.stringify(bundleGroupNames)).all<{ id: number }>();
    for (const r of results) out.add(r.id);
  }
  return [...out];
}

export async function importDirectory(env: Env, bundle: DirectoryBundle, opts: ImportOptions = {}): Promise<ImportResult> {
  const { users, groups } = validateBundle(bundle);
  // Groups the bundle's existing people are in now, so a SCIM push after the
  // import can update them even if this import takes someone out.
  const groupsBefore = users.length <= SCIM_TARGETED_LIMIT && (await isScimConfigured(env)) ? await groupIdsOfUsernames(env, users.map((u) => cleanString(u.username).toLowerCase())) : new Set<number>();

  if (!opts.allowPrivileged) {
    const ROLE_GROUP_NAMES = await adminRoleGroupNames(env);
    const { results: adminRows } = await env.DB.prepare(
      `SELECT u.username FROM users u
       JOIN group_members gm ON gm.user_id = u.id
       JOIN groups g ON g.id = gm.group_id WHERE g.name IN (SELECT value FROM json_each(?))`
    )
      .bind(JSON.stringify(ROLE_GROUP_NAMES))
      .all<{ username: string }>();
    const adminUsernames = new Set(adminRows.map((r) => r.username));
    // Dynamic role members have no group_members row; resolve them by rule.
    const dynRules = await dynamicAdminRules(env);
    if (dynRules.length) {
      const bundleNames = users.map((u) => cleanString(u.username).toLowerCase()).filter(Boolean);
      if (bundleNames.length) {
        const { results: existing } = await env.DB.prepare("SELECT * FROM users WHERE username IN (SELECT value FROM json_each(?))")
          .bind(JSON.stringify(bundleNames))
          .all<UserRow>();
        for (const u of existing) if (dynRules.some((r) => userMatchesRule(u, r))) adminUsernames.add(u.username);
      }
    }
    for (const user of users) {
      const username = cleanString(user.username).toLowerCase();
      if (user.super_admin) {
        throw new ImportValidationError(`User "${username}" sets super_admin, which requires an admin-scoped token.`);
      }
      const roleGroup = (user.groups ?? []).map((name) => cleanString(name)).find((name) => ROLE_GROUP_NAMES.includes(name));
      if (roleGroup) {
        throw new ImportValidationError(`User "${username}" lists "${roleGroup}", an admin role, which requires an admin-scoped token.`);
      }
      if (adminUsernames.has(username)) {
        throw new ImportValidationError(`User "${username}" holds an admin role; overwriting them requires an admin-scoped token.`);
      }
    }
  }

  const mode = bundle.mode ?? "merge";
  const domain = (cleanString(bundle.domain) || (await getDefaultDomain(env))).toLowerCase();
  if (cleanString(bundle.domain) && !isValidDomain(domain)) {
    throw new ImportValidationError(`"${domain}" is not a valid DNS domain name.`);
  }

  const result: ImportResult = {
    domain,
    mode,
    users: { created: 0, updated: 0, skipped: 0 },
    groups: { created: 0, updated: 0 },
    generated_passwords: {},
    managers_resolved: 0,
    errors: [],
  };

  await ensureDomain(env, domain);
  const removed = mode === "replace" ? await replaceExistingDirectory(env) : { users: [], groups: [] };
  const touchedUserIds: number[] = [];

  // --- Groups -------------------------------------------------------------
  // Every name the bundle mentions, whether in `groups` or only as a user's
  // membership, so a bundle does not have to declare the same thing twice.
  const described = new Map<string, string | null>();
  const ruleByName = new Map<string, string>();
  const editableAttrs = await userEditableAttributeNames(env);
  for (const group of groups) {
    const name = cleanString(group.name);
    described.set(name, cleanString(group.description) || null);
    if (!group.rule) continue;
    // Super Admins gates /admin: membership by attribute would let anyone who
    // can edit an attribute grant themselves the console.
    if (name === SUPER_ADMINS_GROUP) result.errors.push({ group: name, message: `${SUPER_ADMINS_GROUP} cannot be a dynamic group - rule ignored.` });
    else if (!parseRule(group.rule)) result.errors.push({ group: name, message: "Rule is not valid rule JSON - rule ignored." });
    else if ((parseRule(group.rule)?.all ?? []).some((cond) => editableAttrs.has(cond.field.replace(/^custom\./, ""))))
      result.errors.push({ group: name, message: "Rule matches on a user-editable attribute, which would let users choose their own groups - rule ignored." });
    // Stored normalised - the parsed conditions only - so every later reader
    // (rule guards, evaluators) sees exactly what is evaluated.
    else ruleByName.set(name, JSON.stringify(parseRule(group.rule)));
  }
  for (const user of users) {
    for (const name of user.groups ?? []) {
      const clean = cleanString(name);
      if (clean && !described.has(clean)) described.set(clean, null);
    }
  }
  if (users.some((u) => u.super_admin)) described.set(SUPER_ADMINS_GROUP, described.get(SUPER_ADMINS_GROUP) ?? null);

  const groupIdByName = new Map<string, number>();
  const systemGroupIds = new Set<number>();
  const roleGroupIds = opts.allowPrivileged ? new Set<number>() : await adminRoleGroupIds(env);
  const roleGroupNameSet = opts.allowPrivileged ? new Set<string>() : new Set(await adminRoleGroupNames(env));
  for (const [name, description] of described) {
    try {
      const existing = await env.DB.prepare("SELECT id, system FROM groups WHERE name = ?").bind(name).first<{ id: number; system: string }>();
      if (existing) {
        const rule = ruleByName.get(name);
        if (existing.system) {
          // A system group's definition (and membership) is maintained by
          // code - the watchlist mirrors user_watch rows - so a bundle may
          // not rewrite it, whoever the caller is.
          systemGroupIds.add(existing.id);
          if (description !== null || rule !== undefined) {
            result.errors.push({ group: name, message: `"${name}" is a system group - its definition cannot be imported.` });
          }
        } else if (roleGroupIds.has(existing.id)) {
          // A rule or description write on a role-linked group redefines who
          // holds the role - that is an admin grant, not a group update.
          if (description !== null || rule !== undefined) {
            result.errors.push({ group: name, message: `"${name}" grants an admin role; changing it requires an admin-scoped token.` });
          }
        } else if (description !== null || rule !== undefined) {
          await env.DB.prepare("UPDATE groups SET description = COALESCE(?, description), rule = COALESCE(?, rule) WHERE id = ?")
            .bind(description, rule ?? null, existing.id)
            .run();
          result.groups.updated++;
        }
        groupIdByName.set(name, existing.id);
      } else {
        if (roleGroupNameSet.has(name)) {
          result.errors.push({ group: name, message: `"${name}" is an admin role group name; creating it requires an admin-scoped token.` });
          continue;
        }
        // A name a lazily-created system group will claim: squatting it would
        // break that creation and borrow its meaning downstream, so it is
        // reserved on ordinary rows too.
        if (name === WATCHLIST_GROUP_NAME) {
          result.errors.push({ group: name, message: `"${name}" is reserved for the system watchlist.` });
          continue;
        }
        const inserted = await env.DB.prepare("INSERT INTO groups (name, description, rule) VALUES (?, ?, ?) RETURNING id")
          .bind(name, description, ruleByName.get(name) ?? "")
          .first<{ id: number }>();
        if (inserted) {
          groupIdByName.set(name, inserted.id);
          result.groups.created++;
        }
      }
    } catch (err) {
      result.errors.push({ group: name, message: String(err) });
    }
  }

  // Dynamic groups take no explicit members - their membership is the rule.
  const dynamicGroupIds = new Set(
    (await env.DB.prepare("SELECT id FROM groups WHERE rule != ''").all<{ id: number }>()).results.map((g) => g.id)
  );
  if (dynamicGroupIds.size > 0) {
    await env.DB.prepare("DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE rule != '')").run();
  }

  // --- Users --------------------------------------------------------------
  // Sequential rather than batched, and each row in its own try: one bad row
  // (a UPN that collides with an account under a different username, say)
  // should be reported, not abort the other ninety-nine.
  const externalIdByUsername = new Map<string, string>();

  // One hash per distinct password in this import. A bundle typically gives
  // dozens of people the same default password, and scrypt costs ~100 ms of
  // CPU per hash; reusing it for an identical, admin-known password loses
  // nothing a per-user salt would have protected.
  const hashes = new Map<string, Promise<PasswordHash>>();
  const hashOnce = (password: string) => {
    if (!hashes.has(password)) hashes.set(password, hashPassword(password, env));
    return hashes.get(password)!;
  };

  const passwordPolicy = await getPasswordPolicy(env);
  const breached = await breachedImportPasswords(env, users, passwordPolicy);
  for (const user of users) {
    const username = cleanString(user.username).toLowerCase();
    const upn = `${username}@${domain}`;
    // An explicit password meets the same policy as every other way of setting one.
    if (typeof user.password === "string" && user.password !== "") {
      const weak = validatePassword(user.password, passwordPolicy) ?? breached.get(user.password) ?? null;
      if (weak) {
        result.errors.push({ username, message: `Password rejected: ${weak}` });
        continue;
      }
    }

    try {
      const existing = await env.DB.prepare("SELECT id, external_id, status, upn FROM users WHERE username = ?")
        .bind(username)
        .first<{ id: number; external_id: string; status: string; upn: string }>();

      // The UPN shares a namespace with contact addresses: spelled like
      // another account's user_emails alias or users.email, the same string
      // resolves to two accounts (SSF prefers the upn holder, email lookups
      // the alias owner). SCIM POST /Users applies the same check.
      const nsClash = await env.DB.prepare(
        "SELECT 1 FROM user_emails WHERE email = ? AND user_id != ? UNION SELECT 1 FROM users WHERE email = ? AND id != ?"
      )
        .bind(upn, existing?.id ?? -1, upn, existing?.id ?? -1)
        .first();
      if (nsClash) {
        result.errors.push({ username, message: `The sign-in name ${upn} collides with another account's email address.` });
        result.users.skipped++;
        continue;
      }

      const givenName = cleanString(user.given_name);
      const familyName = cleanString(user.family_name);
      const displayName = cleanString(user.display_name) || `${givenName} ${familyName}`.trim() || username;
      const now = new Date().toISOString();

      const schemaName = cleanString(user.schema);
      const schema = schemaName ? await findSchema(env, "user", schemaName) : null;
      if (schemaName && !schema) {
        result.errors.push({ username, message: `Unknown user schema "${schemaName}".` });
        result.users.skipped++;
        continue;
      }
      const schemaAttrs = schema ? await getSchemaAttributes(env, schema.id) : [];
      const { columns: attrColumns, custom: attrCustom } = splitUserAttributes(schemaAttrs, user.attributes ?? {});

      // The attribute columns every write path sets, computed once.
      const vals = {
        job_title: cleanString(user.job_title) || String(attrColumns.job_title ?? ""),
        department: cleanString(user.department) || String(attrColumns.department ?? ""),
        employee_number: cleanString(user.employee_number) || String(attrColumns.employee_number ?? ""),
        hire_date: cleanString(user.hire_date) || String(attrColumns.hire_date ?? ""),
        employment_status: cleanString(user.employment_status) || String(attrColumns.employment_status ?? ""),
        employment_type: cleanString(user.employment_type) || String(attrColumns.employment_type ?? ""),
        location: cleanString(user.location) || String(attrColumns.location ?? ""),
      };

      let userId: number;
      if (existing) {
        const existingRow = (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(existing.id).first<UserRow>())!;
        const existingCustom = parseCustomAttributes(existingRow.custom_attributes);
        const mergedCustom = { ...existingCustom, ...attrCustom };
        if (!opts.allowPrivileged) {
          // An attribute update can move the user into a dynamic admin-role
          // group; that grant is reserved to admin-scoped tokens.
          const after = {
            ...existingRow, upn, display_name: displayName, given_name: givenName, family_name: familyName,
            ...vals, status: user.status ?? "disabled", custom_attributes: JSON.stringify(mergedCustom),
          } as UserRow;
          const granted = await grantsAdminRoleGroup(env, existingRow, after);
          if (granted) {
            result.errors.push({ username, message: `The update moves "${username}" into ${granted}, an admin role group, which requires an admin-scoped token.` });
            result.users.skipped++;
            continue;
          }
        }
        if (existing.upn !== upn) await revokeAccountTokens(env, existing.id);
        await env.DB.prepare(
          `UPDATE users SET upn = ?, display_name = ?, given_name = ?, family_name = ?, job_title = ?, department = ?,
             employee_number = ?, hire_date = ?, employment_status = ?, employment_type = ?, location = ?,
             status = ?, is_admin = ?, schema_id = ?, custom_attributes = ?, updated_at = ?
           WHERE id = ?`
        )
          .bind(
            upn,
            displayName,
            givenName,
            familyName,
            vals.job_title,
            vals.department,
            vals.employee_number,
            vals.hire_date,
            vals.employment_status,
            vals.employment_type,
            vals.location,
            user.status ?? "disabled",
            user.super_admin ? 1 : 0,
            schema?.id ?? null,
            JSON.stringify(mergedCustom),
            now,
            existing.id
          )
          .run();

        // Deactivation takes effect now, not at the next sign-in - the same
        // contract as the console's account switch (admin.ts), so a dormant
        // session cannot come back to life on re-activation.
        if ((user.status ?? "disabled") === "disabled") {
          await revokeAllSessionsForUser(env, existing.id);
          await revokeTokensForUser(env, existing.id);
        }

        // An explicit password resets it; omitting it leaves whatever the user
        // has chosen since, which is the only safe default for a re-import.
        if (typeof user.password === "string" && user.password !== "") {
          const { hash, salt, iterations } = await hashOnce(user.password);
          await env.DB.prepare(
            "UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ? WHERE id = ?"
          )
            .bind(hash, salt, iterations, existing.id)
            .run();
          // A password set by import is a reset like any other: whoever held
          // the old one - a session, a refresh token, a link - is out.
          await revokeAllSessionsForUser(env, existing.id);
          await revokeTokensForUser(env, existing.id);
        }

        userId = existing.id;
        touchedUserIds.push(userId);
        externalIdByUsername.set(username, existing.external_id);
        result.users.updated++;
      } else {
        const supplied = typeof user.password === "string" && user.password !== "" ? user.password : null;
        const noPassword = !supplied && bundle.passwords === "none";
        const { password, generated } = supplied
          ? { password: supplied, generated: false }
          : noPassword
            ? { password: "", generated: false }
            : await resolveNewAccountPassword(env);
        const { hash, salt, iterations } = noPassword ? UNUSABLE_PASSWORD : await hashOnce(password);
        const externalId = crypto.randomUUID();

        if (!opts.allowPrivileged) {
          // A new account can be born matching a dynamic admin-role rule.
          const after = {
            upn, username, display_name: displayName, given_name: givenName, family_name: familyName,
            ...vals, status: user.status ?? "disabled", manager_external_id: null, custom_attributes: JSON.stringify(attrCustom),
          } as UserRow;
          const granted = await grantsAdminRoleGroup(env, null, after);
          if (granted) {
            result.errors.push({ username, message: `The account lands in ${granted}, an admin role group, which requires an admin-scoped token.` });
            result.users.skipped++;
            continue;
          }
        }

        const inserted = await env.DB.prepare(
          `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department,
             employee_number, hire_date, employment_status, employment_type, location, password_hash, password_salt,
             password_iterations, is_admin, status, schema_id, custom_attributes, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id`
        )
          .bind(
            upn,
            username,
            displayName,
            givenName,
            familyName,
            externalId,
            vals.job_title,
            vals.department,
            vals.employee_number,
            vals.hire_date,
            vals.employment_status,
            vals.employment_type,
            vals.location,
            hash,
            salt,
            iterations,
            user.super_admin ? 1 : 0,
            user.status ?? "disabled",
            schema?.id ?? (await defaultSchemaId(env, "user")),
            JSON.stringify(attrCustom),
            now,
            now
          )
          .first<{ id: number }>();

        if (!inserted) throw new Error("insert returned no row");
        userId = inserted.id;
        touchedUserIds.push(userId);
        externalIdByUsername.set(username, externalId);
        if (generated) result.generated_passwords[upn] = password;
        result.users.created++;
      }

      if (user.email !== undefined) {
        const email = cleanString(user.email).toLowerCase();
        // The address table is the record; it mirrors the primary into users.email.
        try {
          const primaryChanged = await setUserEmails(env, userId, email ? [{ value: email }] : []);
          // A link sent to the previous address is void once the address changes.
          if (primaryChanged) await revokeAccountTokens(env, userId);
        } catch (e) {
          // An address claimed by another account is a row error, not an abort.
          if (e instanceof UserEmailError) result.errors.push({ username, message: e.message });
          else throw e;
        }
      }

      // --- Membership ---
      if (user.groups !== undefined || user.super_admin) {
        const wanted = new Set<number>();
        for (const name of user.groups ?? []) {
          const clean = cleanString(name);
          const gid = groupIdByName.get(clean);
          if (gid === undefined) {
            result.errors.push({ username, group: clean, message: `Unknown group "${clean}" - membership skipped.` });
            continue;
          }
          if (dynamicGroupIds.has(gid)) {
            result.errors.push({ username, group: clean, message: `"${clean}" is a dynamic group - membership follows its rule, so this listing was skipped.` });
            continue;
          }
          if (systemGroupIds.has(gid)) {
            result.errors.push({ username, group: clean, message: `"${clean}" is a system group - its membership is maintained automatically, so this listing was skipped.` });
            continue;
          }
          wanted.add(gid);
        }
        if (user.super_admin) {
          const gid = groupIdByName.get(SUPER_ADMINS_GROUP);
          if (gid !== undefined) wanted.add(gid);
        }

        await env.DB.prepare("DELETE FROM group_members WHERE user_id = ?").bind(userId).run();
        if (wanted.size > 0) {
          await env.DB.batch(
            [...wanted].map((gid) =>
              env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, userId)
            )
          );
        }
      }
    } catch (err) {
      result.users.skipped++;
      result.errors.push({ username, message: String(err) });
    }
  }

  // --- Managers -----------------------------------------------------------
  // A second pass, because a manager can appear later in the bundle than their
  // reports - and on a re-import may not be in this chunk at all, which is why
  // an unresolved name falls back to a database lookup before being reported.
  for (const user of users) {
    const manager = cleanString(user.manager);
    if (!manager) continue;
    const username = cleanString(user.username).toLowerCase();
    // Only rows this import actually wrote: the write keys on username, so
    // without this a row the grant check skipped would get its manager set
    // anyway.
    if (!externalIdByUsername.has(username)) continue;

    try {
      let managerExternalId = externalIdByUsername.get(manager.toLowerCase());
      if (!managerExternalId) {
        const row = await env.DB.prepare("SELECT external_id FROM users WHERE username = ?")
          .bind(manager.toLowerCase())
          .first<{ external_id: string }>();
        managerExternalId = row?.external_id;
      }
      if (!managerExternalId) {
        result.errors.push({ username, message: `Unknown manager "${manager}" - left unset.` });
        continue;
      }
      if (!opts.allowPrivileged) {
        // `manager` is a live group-rule field, so this write is exactly the
        // attribute change the per-user grant check exists to refuse - and it
        // runs after that check. Re-check the post-write image before the
        // UPDATE, like the first pass does for every other column.
        const row = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first<UserRow>();
        const granted = row ? await grantsAdminRoleGroup(env, row, { ...row, manager_external_id: managerExternalId }) : null;
        if (granted) {
          result.errors.push({ username, message: `Giving "${username}" that manager puts them in ${granted}, an admin role group, which requires an admin-scoped token.` });
          continue;
        }
      }
      await env.DB.prepare("UPDATE users SET manager_external_id = ? WHERE username = ?")
        .bind(managerExternalId, username)
        .run();
      result.managers_resolved++;
    } catch (err) {
      result.errors.push({ username, message: `Setting manager failed: ${String(err)}` });
    }
  }

  // --- SCIM -----------------------------------------------------------------
  // The admin console pushes every change it makes; an import has to as well,
  // or users it disables (or replace mode deletes) stay active downstream - in
  // Cloudflare Access, say - for good. Best-effort, like the console: a SCIM
  // failure is counted and reported, never a reason to undo the import.
  if (await isScimConfigured(env)) {
    const scim = { users_pushed: 0, users_removed: 0, groups_pushed: 0, groups_removed: 0, errors: 0 };
    // Replace-mode removals were queued with the deletion; send a bounded
    // batch now. The rest (and any failure) drains on later syncs and the
    // hourly cron, so nothing is orphaned downstream.
    if (removed.users.length + removed.groups.length > 0) {
      const drained = await drainScimDeprovisionQueue(env);
      scim.users_removed = drained.removedUsers;
      scim.groups_removed = drained.removedGroups;
      scim.errors += drained.failed;
      (scim as Record<string, number>).deprovision_pending = drained.remaining;
    }
    for (const id of touchedUserIds) {
      const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
      if (!user) continue;
      // pushUser sends active:false for a disabled user - deprovisioning, not deletion.
      const r = await pushUser(env, user);
      r.ok ? scim.users_pushed++ : scim.errors++;
    }
    // Only groups this import could have changed: the ones it names, and every
    // group (dynamic ones included) its people were in before or are in now.
    // Re-pushing the whole directory for a one-person import took minutes.
    // A large import (or a replace) still re-pushes everything.
    const affected = bundle.mode === "replace" || touchedUserIds.length > SCIM_TARGETED_LIMIT ? undefined : await affectedGroupIds(env, groupsBefore, touchedUserIds, groups.map((g) => cleanString(g.name)));
    const { groups: groupsPushed, groupErrors } = await syncGroupsAllTargets(env, affected);
    scim.groups_pushed = groupsPushed - groupErrors;
    scim.errors += groupErrors;
    result.scim = scim;
  }

  return result;
}

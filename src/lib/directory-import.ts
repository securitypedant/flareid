import type { Env } from "../env.js";
import { hashPassword, type PasswordHash } from "./password.js";
import { getDefaultDomain } from "./domains.js";
import { resolveNewAccountPassword } from "./settings.js";
import { SUPER_ADMINS_GROUP } from "./middleware.js";
import { findSchema, getSchemaAttributes, splitUserAttributes, parseCustomAttributes, defaultSchemaId, userEditableAttributeNames } from "./schemas.js";
import { parseRule } from "./groups.js";
import { deleteUserStatements, revokeAllSessionsForUser, revokeTokensForUser } from "./sessions.js";
import { deleteGroupScim, deleteUserScim, isScimConfigured, pushUser, syncGroups } from "./scim-client.js";
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

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

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

/** Ensures the domain exists as a row, so users created under it show up correctly in /admin/domains. */
async function ensureDomain(env: Env, domain: string): Promise<void> {
  await env.DB.prepare("INSERT INTO domains (domain, is_default, created_at) VALUES (?, 0, ?) ON CONFLICT(domain) DO NOTHING")
    .bind(domain, new Date().toISOString())
    .run();
}

/**
 * Wipes everything a previous import created, keeping the built-in groups and
 * anyone who administers the directory.
 *
 * Super Admins survive on purpose: `mode: "replace"` is for reshaping the
 * directory, not for locking yourself out of it. A caller that genuinely wants
 * an empty instance can delete the administrators afterwards.
 */
async function replaceExistingDirectory(env: Env): Promise<{ users: UserRow[]; groups: GroupRow[] }> {
  const { results: doomed } = await env.DB.prepare(
    `SELECT * FROM users
      WHERE id NOT IN (
        SELECT user_id FROM group_members WHERE group_id = (SELECT id FROM groups WHERE name = ?)
      )`
  )
    .bind(SUPER_ADMINS_GROUP)
    .all<UserRow>();
  const { results: doomedGroups } = await env.DB.prepare("SELECT * FROM groups WHERE name != ?").bind(SUPER_ADMINS_GROUP).all<GroupRow>();

  if (doomed.length > 0) await env.DB.batch(deleteUserStatements(env, ...doomed.map((r) => r.id)));
  await env.DB.prepare(`DELETE FROM groups WHERE name != ?`).bind(SUPER_ADMINS_GROUP).run();

  // Returned so the caller can remove them from the SCIM server too: once the
  // rows are gone, their scim_ids are the only way to find them there.
  return { users: doomed.filter((u) => u.scim_id), groups: doomedGroups.filter((g) => g.scim_id) };
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

export async function importDirectory(env: Env, bundle: DirectoryBundle, opts: ImportOptions = {}): Promise<ImportResult> {
  const { users, groups } = validateBundle(bundle);

  if (!opts.allowPrivileged) {
    const { results: adminRows } = await env.DB.prepare(
      `SELECT u.username FROM users u
       JOIN group_members gm ON gm.user_id = u.id
       JOIN groups g ON g.id = gm.group_id WHERE g.name = ?`
    )
      .bind(SUPER_ADMINS_GROUP)
      .all<{ username: string }>();
    const adminUsernames = new Set(adminRows.map((r) => r.username));
    for (const user of users) {
      const username = cleanString(user.username).toLowerCase();
      if (user.super_admin) {
        throw new ImportValidationError(`User "${username}" sets super_admin, which requires an admin-scoped token.`);
      }
      if ((user.groups ?? []).some((name) => cleanString(name) === SUPER_ADMINS_GROUP)) {
        throw new ImportValidationError(`User "${username}" lists "${SUPER_ADMINS_GROUP}", which requires an admin-scoped token.`);
      }
      if (adminUsernames.has(username)) {
        throw new ImportValidationError(
          `User "${username}" would overwrite an existing member of "${SUPER_ADMINS_GROUP}", which requires an admin-scoped token.`
        );
      }
    }
  }

  const mode = bundle.mode ?? "merge";
  const domain = (cleanString(bundle.domain) || (await getDefaultDomain(env))).toLowerCase();

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
    else ruleByName.set(name, group.rule);
  }
  for (const user of users) {
    for (const name of user.groups ?? []) {
      const clean = cleanString(name);
      if (clean && !described.has(clean)) described.set(clean, null);
    }
  }
  if (users.some((u) => u.super_admin)) described.set(SUPER_ADMINS_GROUP, described.get(SUPER_ADMINS_GROUP) ?? null);

  const groupIdByName = new Map<string, number>();
  for (const [name, description] of described) {
    try {
      const existing = await env.DB.prepare("SELECT id FROM groups WHERE name = ?").bind(name).first<{ id: number }>();
      if (existing) {
        const rule = ruleByName.get(name);
        if (description !== null || rule !== undefined) {
          await env.DB.prepare("UPDATE groups SET description = COALESCE(?, description), rule = COALESCE(?, rule) WHERE id = ?")
            .bind(description, rule ?? null, existing.id)
            .run();
          result.groups.updated++;
        }
        groupIdByName.set(name, existing.id);
      } else {
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

  for (const user of users) {
    const username = cleanString(user.username).toLowerCase();
    const upn = `${username}@${domain}`;

    try {
      const existing = await env.DB.prepare("SELECT id, external_id, status FROM users WHERE username = ?")
        .bind(username)
        .first<{ id: number; external_id: string; status: string }>();

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

      let userId: number;
      if (existing) {
        const existingCustom = parseCustomAttributes(
          (await env.DB.prepare("SELECT custom_attributes FROM users WHERE id = ?").bind(existing.id).first<{ custom_attributes: string }>())?.custom_attributes
        );
        const mergedCustom = { ...existingCustom, ...attrCustom };
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
            cleanString(user.job_title) || String(attrColumns.job_title ?? ""),
            cleanString(user.department) || String(attrColumns.department ?? ""),
            cleanString(user.employee_number) || String(attrColumns.employee_number ?? ""),
            cleanString(user.hire_date) || String(attrColumns.hire_date ?? ""),
            cleanString(user.employment_status) || String(attrColumns.employment_status ?? ""),
            cleanString(user.employment_type) || String(attrColumns.employment_type ?? ""),
            cleanString(user.location) || String(attrColumns.location ?? ""),
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
            cleanString(user.job_title) || String(attrColumns.job_title ?? ""),
            cleanString(user.department) || String(attrColumns.department ?? ""),
            cleanString(user.employee_number) || String(attrColumns.employee_number ?? ""),
            cleanString(user.hire_date) || String(attrColumns.hire_date ?? ""),
            cleanString(user.employment_status) || String(attrColumns.employment_status ?? ""),
            cleanString(user.employment_type) || String(attrColumns.employment_type ?? ""),
            cleanString(user.location) || String(attrColumns.location ?? ""),
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
        await env.DB.prepare("UPDATE users SET email = ? WHERE id = ?").bind(cleanString(user.email).toLowerCase() || null, userId).run();
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
    for (const user of removed.users) {
      const r = await deleteUserScim(env, user);
      r.ok ? scim.users_removed++ : scim.errors++;
    }
    for (const group of removed.groups) {
      const r = await deleteGroupScim(env, group);
      r.ok ? scim.groups_removed++ : scim.errors++;
    }
    for (const id of touchedUserIds) {
      const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
      if (!user) continue;
      // pushUser sends active:false for a disabled user - deprovisioning, not deletion.
      const r = await pushUser(env, user);
      r.ok ? scim.users_pushed++ : scim.errors++;
    }
    // Memberships (dynamic ones included) may have changed for any group.
    const { groups, groupErrors } = await syncGroups(env);
    scim.groups_pushed = groups - groupErrors;
    scim.errors += groupErrors;
    result.scim = scim;
  }

  return result;
}

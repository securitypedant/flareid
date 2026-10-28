import type { Env } from "../env.js";
import { hashPassword } from "./password.js";
import { getDefaultDomain } from "./domains.js";
import { resolveNewAccountPassword } from "./settings.js";
import { SUPER_ADMINS_GROUP } from "./middleware.js";

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

/** Per-request cap. PBKDF2 is ~30-60ms per new user, so this bounds CPU time; callers chunk. */
export const MAX_USERS_PER_IMPORT = 100;

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

export interface DirectoryGroup {
  name: string;
  description?: string;
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
  super_admin?: boolean;
}

export interface DirectoryBundle {
  version?: number;
  mode?: "merge" | "replace";
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
async function replaceExistingDirectory(env: Env): Promise<void> {
  const { results: doomed } = await env.DB.prepare(
    `SELECT id FROM users
      WHERE id NOT IN (
        SELECT user_id FROM group_members WHERE group_id = (SELECT id FROM groups WHERE name = ?)
      )`
  )
    .bind(SUPER_ADMINS_GROUP)
    .all<{ id: number }>();

  const ids = doomed.map((r) => r.id);
  if (ids.length > 0) {
    const placeholders = ids.map(() => "?").join(",");
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM group_members WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM sessions WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM access_tokens WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM refresh_tokens WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM auth_codes WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM mfa_backup_codes WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM trusted_devices WHERE user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`UPDATE audit_log SET actor_user_id = NULL WHERE actor_user_id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(`DELETE FROM users WHERE id IN (${placeholders})`).bind(...ids),
    ]);
  }

  await env.DB.prepare(`DELETE FROM groups WHERE name NOT IN (?, 'All Employees')`).bind(SUPER_ADMINS_GROUP).run();
}

export async function importDirectory(env: Env, bundle: DirectoryBundle): Promise<ImportResult> {
  const { users, groups } = validateBundle(bundle);

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
  if (mode === "replace") await replaceExistingDirectory(env);

  // --- Groups -------------------------------------------------------------
  // Every name the bundle mentions, whether in `groups` or only as a user's
  // membership, so a bundle does not have to declare the same thing twice.
  const described = new Map<string, string | null>();
  for (const group of groups) described.set(cleanString(group.name), cleanString(group.description) || null);
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
        if (description !== null) {
          await env.DB.prepare("UPDATE groups SET description = ? WHERE id = ?").bind(description, existing.id).run();
          result.groups.updated++;
        }
        groupIdByName.set(name, existing.id);
      } else {
        const inserted = await env.DB.prepare("INSERT INTO groups (name, description) VALUES (?, ?) RETURNING id")
          .bind(name, description)
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

  // --- Users --------------------------------------------------------------
  // Sequential rather than batched, and each row in its own try: one bad row
  // (a UPN that collides with an account under a different username, say)
  // should be reported, not abort the other ninety-nine.
  const externalIdByUsername = new Map<string, string>();

  for (const user of users) {
    const username = cleanString(user.username).toLowerCase();
    const upn = `${username}@${domain}`;

    try {
      const existing = await env.DB.prepare("SELECT id, external_id FROM users WHERE username = ?")
        .bind(username)
        .first<{ id: number; external_id: string }>();

      const givenName = cleanString(user.given_name);
      const familyName = cleanString(user.family_name);
      const displayName = cleanString(user.display_name) || `${givenName} ${familyName}`.trim() || username;
      const now = new Date().toISOString();

      let userId: number;
      if (existing) {
        await env.DB.prepare(
          `UPDATE users SET upn = ?, display_name = ?, given_name = ?, family_name = ?, job_title = ?, department = ?,
             employee_number = ?, hire_date = ?, employment_status = ?, employment_type = ?, location = ?,
             status = ?, is_admin = ?, updated_at = ?
           WHERE id = ?`
        )
          .bind(
            upn,
            displayName,
            givenName,
            familyName,
            cleanString(user.job_title),
            cleanString(user.department),
            cleanString(user.employee_number),
            cleanString(user.hire_date),
            cleanString(user.employment_status),
            cleanString(user.employment_type),
            cleanString(user.location),
            user.status ?? "active",
            user.super_admin ? 1 : 0,
            now,
            existing.id
          )
          .run();

        // An explicit password resets it; omitting it leaves whatever the user
        // has chosen since, which is the only safe default for a re-import.
        if (typeof user.password === "string" && user.password !== "") {
          const { hash, salt, iterations } = await hashPassword(user.password);
          await env.DB.prepare(
            "UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ? WHERE id = ?"
          )
            .bind(hash, salt, iterations, existing.id)
            .run();
        }

        userId = existing.id;
        externalIdByUsername.set(username, existing.external_id);
        result.users.updated++;
      } else {
        const supplied = typeof user.password === "string" && user.password !== "" ? user.password : null;
        const { password, generated } = supplied
          ? { password: supplied, generated: false }
          : await resolveNewAccountPassword(env);
        const { hash, salt, iterations } = await hashPassword(password);
        const externalId = crypto.randomUUID();

        const inserted = await env.DB.prepare(
          `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department,
             employee_number, hire_date, employment_status, employment_type, location, password_hash, password_salt,
             password_iterations, is_admin, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id`
        )
          .bind(
            upn,
            username,
            displayName,
            givenName,
            familyName,
            externalId,
            cleanString(user.job_title),
            cleanString(user.department),
            cleanString(user.employee_number),
            cleanString(user.hire_date),
            cleanString(user.employment_status),
            cleanString(user.employment_type),
            cleanString(user.location),
            hash,
            salt,
            iterations,
            user.super_admin ? 1 : 0,
            user.status ?? "active",
            now,
            now
          )
          .first<{ id: number }>();

        if (!inserted) throw new Error("insert returned no row");
        userId = inserted.id;
        externalIdByUsername.set(username, externalId);
        if (generated) result.generated_passwords[upn] = password;
        result.users.created++;
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

  return result;
}

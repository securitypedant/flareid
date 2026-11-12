import type { Env } from "../env.js";
import { sendInvitation, sendPasswordReset } from "../lib/account-email.js";
import { revokeAccountTokens } from "../lib/account-tokens.js";
import { deleteBackupCodes } from "../lib/backup-codes.js";
import { isEmailAddress, recipientFor } from "../lib/email.js";
import { hashPassword } from "../lib/password.js";
import { conformUserAttributes, defaultSchemaId, getSchemaAttributes, splitUserAttributes } from "../lib/schemas.js";
import { drainScimDeprovisionQueue, queueScimDeprovision } from "../lib/scim-client.js";
import { deleteUserStatements, revokeAllSessionsForUser, revokeTokensForUser } from "../lib/sessions.js";
import { getPasswordPolicy, resolveNewAccountPassword, validatePassword } from "../lib/settings.js";
import { removePasskey } from "../lib/passkeys.js";
import { deleteTrustedDevicesForUser } from "../lib/trusted-devices.js";
import type { UserRow } from "../lib/types.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";
import { assertMayAssignGroups, assertMayTouchUser } from "./guards.js";
import { scimConfigured, syncGroupBestEffort, syncUserBestEffort } from "./scim-sync.js";

/** Either the shared default password, or a freshly generated one that respects the configured complexity policy - per the "New account password" setting. */
export async function generateAccountPassword(env: Env): Promise<string> {
  return (await resolveNewAccountPassword(env)).password;
}

export async function getUserById(env: Env, id: number): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
}

/** Only static groups take explicit members - dynamic membership follows the rule. */
async function staticOnly(env: Env, groupIds: number[]): Promise<number[]> {
  const staticIds = new Set((await env.DB.prepare("SELECT id FROM groups WHERE rule = ''").all<{ id: number }>()).results.map((g) => g.id));
  return groupIds.filter((gid) => staticIds.has(gid));
}

const TAKEN = (username: string) => `Username "${username}" is already taken by another account (usernames must be unique across every domain).`;

export interface NewUser {
  username: string;
  domain: string;
  givenName: string;
  familyName: string;
  /** 0/undefined = the default user schema. */
  schemaId?: number;
  /** Values for the schema's attributes, by attribute name. */
  attributes: Record<string, string>;
  groupIds: number[];
  /** A chosen password (checked against the policy); omitted = the "New account password" setting. */
  password?: string;
  status?: "active" | "disabled";
  /** Contact address for email, when not the UPN. */
  email?: string;
}

/**
 * Creates one account. New accounts start inactive unless asked otherwise:
 * the console activates them from their page once they are ready.
 */
export async function createUser(ctx: ServiceCtx, input: NewUser): Promise<{ id: number; upn: string; password: string; chosen: boolean }> {
  const username = input.username.trim().toLowerCase();
  const domain = input.domain.trim().toLowerCase();
  const givenName = input.givenName.trim();
  const familyName = input.familyName.trim();
  if (!username || !domain || !givenName) throw new ServiceError(400, "username, domain, and first name are required");
  const upn = `${username}@${domain}`;
  const displayName = `${givenName} ${familyName}`.trim();
  const schemaId = Number(input.schemaId) || (await defaultSchemaId(ctx.env, "user"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(ctx.env, schemaId) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(input.attributes[a.name] ?? "").trim()]));
  const { columns, custom } = splitUserAttributes(schemaAttrs, attrValues);
  const groupIds = await staticOnly(ctx.env, input.groupIds);
  await assertMayAssignGroups(ctx, groupIds);

  if (await ctx.env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first()) throw new ServiceError(409, TAKEN(username));
  const email = String(input.email ?? "").trim().toLowerCase() || null;
  if (email && !isEmailAddress(email)) throw new ServiceError(400, "email is not a valid email address.");
  if (input.password) {
    const policyError = validatePassword(input.password, await getPasswordPolicy(ctx.env));
    if (policyError) throw new ServiceError(400, policyError);
  }

  const password = input.password || (await generateAccountPassword(ctx.env));
  const { hash, salt, iterations } = await hashPassword(password, ctx.env);
  const now = new Date().toISOString();
  const result = await ctx.env.DB.prepare(
    `INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, job_title, department, manager_external_id, employee_number, hire_date, employment_status, employment_type, location, password_hash, password_salt, password_iterations, status, schema_id, custom_attributes, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      upn,
      username,
      displayName,
      givenName,
      familyName,
      crypto.randomUUID(),
      String(columns.job_title ?? ""),
      String(columns.department ?? ""),
      (columns.manager_external_id as string | null) ?? null,
      String(columns.employee_number ?? ""),
      String(columns.hire_date ?? ""),
      String(columns.employment_status ?? ""),
      String(columns.employment_type ?? ""),
      String(columns.location ?? ""),
      hash,
      salt,
      iterations,
      input.status === "active" ? "active" : "disabled",
      schemaId,
      JSON.stringify(custom),
      now,
      now
    )
    .run();

  const userId = Number(result.meta.last_row_id);
  if (email) await ctx.env.DB.prepare("UPDATE users SET email = ? WHERE id = ?").bind(email, userId).run();
  if (groupIds.length > 0) {
    await ctx.env.DB.batch(groupIds.map((gid) => ctx.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, userId)));
  }

  await audit(ctx, "user.created", upn);
  await syncUserBestEffort(ctx, userId, "push");
  for (const gid of groupIds) await syncGroupBestEffort(ctx, gid);
  return { id: userId, upn, password, chosen: Boolean(input.password) };
}

export interface UserProfile {
  username: string;
  domain: string;
  givenName: string;
  familyName: string;
  schemaId?: number;
  /** The complete set of values for the schema: what it defines is saved, everything else is cleared. */
  attributes: Record<string, string>;
  /** The complete set of static groups. */
  groupIds: number[];
  /** Contact address for email; undefined leaves it alone, null/"" clears it (mail then goes to the UPN). */
  email?: string | null;
}

/** Replaces a user's identity, attributes (conformed to the schema) and static groups. Status is setUserStatus's. */
export async function updateUserProfile(ctx: ServiceCtx, id: number, input: UserProfile): Promise<{ upn: string }> {
  const existing = await getUserById(ctx.env, id);
  if (!existing) throw new ServiceError(404, "Not found");
  await assertMayTouchUser(ctx, id);
  const username = input.username.trim().toLowerCase();
  const domain = input.domain.trim().toLowerCase();
  if (!username || !domain) throw new ServiceError(400, "username and domain are required");
  const upn = `${username}@${domain}`;
  const givenName = input.givenName.trim();
  const familyName = input.familyName.trim();
  const displayName = `${givenName} ${familyName}`.trim();
  const status = existing.status; // changed only through setUserStatus
  const groupIds = await staticOnly(ctx.env, input.groupIds);
  await assertMayAssignGroups(ctx, groupIds);

  // Conform to the chosen schema: what it defines is saved, everything else is cleared.
  const schemaId = Number(input.schemaId) || (await defaultSchemaId(ctx.env, "user"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(ctx.env, schemaId) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(input.attributes[a.name] ?? "").trim()]));
  const { columns, custom } = conformUserAttributes(schemaAttrs, attrValues);

  let managerExternalId = (columns.manager_external_id as string | null) ?? null;
  if (managerExternalId && managerExternalId === existing.external_id) managerExternalId = null; // can't manage yourself

  if (await ctx.env.DB.prepare("SELECT id FROM users WHERE username = ? AND id != ?").bind(username, id).first()) throw new ServiceError(409, TAKEN(username));

  let email = existing.email;
  if (input.email !== undefined) {
    email = String(input.email ?? "").trim().toLowerCase() || null;
    if (email && !isEmailAddress(email)) throw new ServiceError(400, "email is not a valid email address.");
  }

  // A rename (or a new contact address) moves where recovery mail goes: links sent to the old one are void.
  if (existing.upn !== upn || existing.email !== email) await revokeAccountTokens(ctx.env, id);
  await ctx.env.DB.prepare(
    `UPDATE users SET upn = ?, username = ?, display_name = ?, given_name = ?, family_name = ?, job_title = ?, department = ?, manager_external_id = ?,
     employee_number = ?, hire_date = ?, employment_status = ?, employment_type = ?, location = ?, status = ?, schema_id = ?, custom_attributes = ?, email = ?, updated_at = ? WHERE id = ?`
  )
    .bind(
      upn,
      username,
      displayName,
      givenName,
      familyName,
      String(columns.job_title ?? ""),
      String(columns.department ?? ""),
      managerExternalId,
      String(columns.employee_number ?? ""),
      String(columns.hire_date ?? ""),
      String(columns.employment_status ?? ""),
      String(columns.employment_type ?? ""),
      String(columns.location ?? ""),
      status,
      schemaId,
      JSON.stringify(custom),
      email,
      new Date().toISOString(),
      id
    )
    .run();

  const { results: previous } = await ctx.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?").bind(id).all<{ group_id: number }>();
  await ctx.env.DB.prepare("DELETE FROM group_members WHERE user_id = ?").bind(id).run();
  if (groupIds.length > 0) {
    await ctx.env.DB.batch(groupIds.map((gid) => ctx.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, id)));
  }

  await audit(ctx, "user.updated", upn);
  await syncUserBestEffort(ctx, id, status === "active" ? "push" : "deactivate");
  // Groups they left, groups they joined, and every dynamic group - an
  // attribute edit can move them in or out of any rule.
  const { results: dynamicRows } = await ctx.env.DB.prepare("SELECT id FROM groups WHERE rule != ''").all<{ id: number }>();
  const affected = new Set([...previous.map((p) => p.group_id), ...groupIds, ...dynamicRows.map((g) => g.id)]);
  for (const gid of affected) await syncGroupBestEffort(ctx, gid);
  return { upn };
}

/** The account switch. Deactivation takes effect now: sessions end and tokens stop working. */
export async function setUserStatus(ctx: ServiceCtx, id: number, status: "active" | "disabled"): Promise<void> {
  const user = await getUserById(ctx.env, id);
  if (!user) throw new ServiceError(404, "Not found");
  if (id === ctx.selfId) throw new ServiceError(400, "You cannot deactivate your own account.");
  await assertMayTouchUser(ctx, id);
  await ctx.env.DB.prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ?").bind(status, new Date().toISOString(), id).run();
  // Deactivation should take effect now, not at the next sign-in - and not at
  // the next introspection or refresh grant either.
  if (status === "disabled") {
    await revokeAllSessionsForUser(ctx.env, id);
    await revokeTokensForUser(ctx.env, id);
  }
  await audit(ctx, status === "active" ? "user.activated" : "user.deactivated", user.upn);
  await syncUserBestEffort(ctx, id, status === "active" ? "push" : "deactivate");
}

/** Sets a chosen password (policy-checked) or generates one. A reset is a compromise response: every session and token ends. */
export async function resetUserPassword(ctx: ServiceCtx, id: number, chosen: string): Promise<{ password: string; user: UserRow }> {
  const user = await getUserById(ctx.env, id);
  if (!user) throw new ServiceError(404, "Not found");
  await assertMayTouchUser(ctx, id);
  if (chosen) {
    const policyError = validatePassword(chosen, await getPasswordPolicy(ctx.env));
    if (policyError) throw new ServiceError(400, policyError);
  }
  const password = chosen || (await generateAccountPassword(ctx.env));
  const { hash, salt, iterations } = await hashPassword(password, ctx.env);
  await ctx.env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?")
    .bind(hash, salt, iterations, new Date().toISOString(), id)
    .run();
  // Same as the self-service change, which keeps only its own session.
  await revokeAllSessionsForUser(ctx.env, id);
  await revokeTokensForUser(ctx.env, id);
  await audit(ctx, "user.password_reset", user.upn, { chosen: Boolean(chosen) });
  return { password, user };
}

/** Clears the authenticator, backup codes and remembered devices; they enrol again at next sign-in. */
export async function resetUserMfa(ctx: ServiceCtx, id: number): Promise<void> {
  await assertMayTouchUser(ctx, id);
  await ctx.env.DB.prepare("UPDATE users SET totp_secret = NULL, mfa_enabled = 0, totp_last_counter = NULL, updated_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), id)
    .run();
  await deleteBackupCodes(ctx.env, id);
  await deleteTrustedDevicesForUser(ctx.env, id);
  await audit(ctx, "user.mfa_reset", String(id));
}

export async function revokeUserSessions(ctx: ServiceCtx, id: number): Promise<number> {
  await assertMayTouchUser(ctx, id);
  const count = await revokeAllSessionsForUser(ctx.env, id);
  await audit(ctx, "user.sessions_revoked_all", String(id), { count });
  return count;
}

/** The OAuth apps a user currently holds tokens for. */
export async function connectedApps(env: Env, id: number): Promise<{ id: number; client_id: string; name: string }[]> {
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT oc.id, oc.client_id, oc.name FROM access_tokens at
     JOIN oauth_clients oc ON oc.client_id = at.client_id
     WHERE at.user_id = ? AND at.expires_at > ?
     UNION
     SELECT DISTINCT oc.id, oc.client_id, oc.name FROM refresh_tokens rt
     JOIN oauth_clients oc ON oc.client_id = rt.client_id
     WHERE rt.user_id = ? AND rt.revoked_at IS NULL`
  )
    .bind(id, new Date().toISOString(), id)
    .all<{ id: number; client_id: string; name: string }>();
  return results;
}

/** Ends one app's access: its access tokens deleted, its refresh tokens revoked. False when there is no such client. */
export async function revokeUserAppAccess(ctx: ServiceCtx, id: number, clientDbId: number): Promise<boolean> {
  await assertMayTouchUser(ctx, id);
  const client = await ctx.env.DB.prepare("SELECT client_id, name FROM oauth_clients WHERE id = ?").bind(clientDbId).first<{ client_id: string; name: string }>();
  if (!client) return false;
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?").bind(id, client.client_id),
    ctx.env.DB.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ?").bind(new Date().toISOString(), id, client.client_id),
  ]);
  await audit(ctx, "user.app_access_revoked", client.name, { userId: id });
  return true;
}

export async function deleteUser(ctx: ServiceCtx, id: number): Promise<UserRow> {
  const user = await getUserById(ctx.env, id);
  if (!user) throw new ServiceError(404, "Not found");
  if (id === ctx.selfId) throw new ServiceError(400, "You cannot delete your own account.");
  await assertMayTouchUser(ctx, id);

  // Local first, in one batch, and only then the remote delete. The other way
  // round, a local failure (a trusted_devices row the batch didn't cover, once)
  // left the user deleted downstream but alive here.
  await ctx.env.DB.batch([...(user.scim_id ? [queueScimDeprovision(ctx.env, "user", user.scim_id, user.upn)] : []), ...deleteUserStatements(ctx.env, id)]);

  if (await scimConfigured(ctx.env)) {
    // A failure stays queued and is retried by every sync and the hourly cron.
    const result = await drainScimDeprovisionQueue(ctx.env);
    if (result.failed) await audit(ctx, "scim.user_sync_failed", user.upn, { action: "delete", queued: result.remaining });
  }
  await audit(ctx, "user.deleted", user.upn);
  return user;
}

/** Invitation (choosing a password activates the account) or a password reset link, by email. */
export async function sendUserLink(ctx: ServiceCtx, user: UserRow, kind: "invite" | "reset"): Promise<{ ok: true } | { ok: false; error: string }> {
  await assertMayTouchUser(ctx, user.id);
  const result = kind === "invite" ? await sendInvitation(ctx.env, user) : await sendPasswordReset(ctx.env, user);
  await audit(ctx, kind === "invite" ? "user.invitation_sent" : "user.password_reset_link_sent", user.upn, {
    to: recipientFor(user),
    sent: result.ok,
    ...(result.ok ? {} : { error: result.error }),
  });
  return result.ok ? { ok: true } : { ok: false, error: result.error };
}

/** Removes one of a user's passkeys (a lost device); false when they have no such credential. */
export async function removeUserPasskey(ctx: ServiceCtx, user: UserRow, credentialId: string): Promise<boolean> {
  await assertMayTouchUser(ctx, user.id);
  const row = await ctx.env.DB.prepare("SELECT name FROM webauthn_credentials WHERE id = ? AND user_id = ?").bind(credentialId, user.id).first<{ name: string }>();
  if (!row) return false;
  await removePasskey(ctx.env, user.id, credentialId);
  await audit(ctx, "user.passkey_removed", user.upn, { name: row.name });
  return true;
}

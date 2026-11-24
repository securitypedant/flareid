import type { Env } from "../env.js";
import { sendInvitation, sendPasswordReset } from "../lib/account-email.js";
import { revokeAccountTokens } from "../lib/account-tokens.js";
import { deleteBackupCodes } from "../lib/backup-codes.js";
import { domainExists } from "../lib/domains.js";
import { recipientFor } from "../lib/email.js";
import { hashPassword } from "../lib/password.js";
import { conformUserAttributes, defaultSchemaId, getSchemaAttributes, splitUserAttributes, userAttributeValue } from "../lib/schemas.js";
import { getMasteredFields, masteringKeyFor } from "../lib/scim-mapping.js";
import { drainScimDeprovisionQueue, scimDeprovisionStatements } from "../lib/scim-client.js";
import { deleteUserStatements, revokeAllSessionsForUser, revokeTokensForUser } from "../lib/sessions.js";
import { emitAndDrain, SSF_EVENTS } from "../lib/ssf.js";
import { resolveNewAccountPassword } from "../lib/settings.js";
import { newPasswordError } from "../lib/breached-passwords.js";
import { removePasskey } from "../lib/passkeys.js";
import { deleteTrustedDevicesForUser } from "../lib/trusted-devices.js";
import { assertEmailsUsable, setUserEmails, UserEmailError, type UserEmailInput } from "../lib/user-emails.js";
import type { UserRow } from "../lib/types.js";
import { afterResponse, audit, ServiceError, type ServiceCtx } from "./context.js";
import { assertMayAssignGroups, assertMayTouchUser, assertNoAdminRoleGrant } from "./guards.js";
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

// The local part of every UPN: the same pattern the SCIM server and the directory
// import apply, so all three writers admit the same identities.
const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

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
  /** The full address list (work/home/aliases); `email` alone becomes a single work primary. */
  emails?: UserEmailInput[];
}

/** `emails` wins when both are sent; `email` alone is a single work primary. */
function emailInputs(input: { email?: string | null; emails?: UserEmailInput[] }): UserEmailInput[] {
  if (input.emails) return input.emails;
  const email = String(input.email ?? "").trim().toLowerCase();
  return email ? [{ value: email }] : [];
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
  if (!USERNAME_PATTERN.test(username)) throw new ServiceError(400, `"${username}" is not a valid username.`);
  // The UPN is where recovery mail goes: its domain must be one the IdP manages.
  if (!(await domainExists(ctx.env, domain))) throw new ServiceError(400, `No domain "${domain}".`);
  const upn = `${username}@${domain}`;
  const displayName = `${givenName} ${familyName}`.trim();
  const schemaId = Number(input.schemaId) || (await defaultSchemaId(ctx.env, "user"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(ctx.env, schemaId) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(input.attributes[a.name] ?? "").trim()]));
  const { columns, custom } = splitUserAttributes(schemaAttrs, attrValues);
  const groupIds = await staticOnly(ctx.env, input.groupIds);
  await assertMayAssignGroups(ctx, groupIds);

  if (await ctx.env.DB.prepare("SELECT id FROM users WHERE username = ? OR upn = ?").bind(username, upn).first()) throw new ServiceError(409, TAKEN(username));
  if (await ctx.env.DB.prepare("SELECT 1 FROM user_emails WHERE email = ?").bind(upn).first()) throw new ServiceError(409, TAKEN(username));
  const emails = emailInputs(input);
  try {
    await assertEmailsUsable(ctx.env, null, emails);
  } catch (e) {
    if (e instanceof UserEmailError) throw new ServiceError(400, e.message);
    throw e;
  }
  if (input.password) {
    const policyError = await newPasswordError(ctx.env, input.password);
    if (policyError) throw new ServiceError(400, policyError);
  }

  await assertNoAdminRoleGrant(ctx, null, {
    id: 0,
    upn,
    username,
    display_name: displayName,
    given_name: givenName,
    family_name: familyName,
    password_hash: "",
    password_salt: "",
    password_iterations: 0,
    totp_secret: null,
    email: null,
    totp_last_counter: null,
    mfa_enabled: 0,
    email_otp_enabled: 0,
    security_questions_enabled: 0,
    is_admin: 0,
    status: input.status === "active" ? "active" : "disabled",
    created_at: "",
    updated_at: "",
    scim_id: null,
    source_id: null,
    external_id: "",
    job_title: String(columns.job_title ?? ""),
    department: String(columns.department ?? ""),
    manager_external_id: (columns.manager_external_id as string | null) ?? null,
    employee_number: String(columns.employee_number ?? ""),
    hire_date: String(columns.hire_date ?? ""),
    employment_status: String(columns.employment_status ?? ""),
    employment_type: String(columns.employment_type ?? ""),
    location: String(columns.location ?? ""),
    schema_id: schemaId ?? null,
    custom_attributes: JSON.stringify(custom),
  });

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
  // The address table is the record: it writes users.email itself.
  await setUserEmails(ctx.env, userId, emails);
  if (groupIds.length > 0) {
    await ctx.env.DB.batch(groupIds.map((gid) => ctx.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, userId)));
  }

  await audit(ctx, "user.created", upn);
  await afterResponse(ctx, async (later) => {
    await syncUserBestEffort(later, userId, "push");
    for (const gid of groupIds) await syncGroupBestEffort(later, gid);
  });
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
  /** The complete replacement address list; takes precedence over `email`. */
  emails?: UserEmailInput[];
}

/** Replaces a user's identity, attributes (conformed to the schema) and static groups. Status is setUserStatus's. */
export async function updateUserProfile(ctx: ServiceCtx, id: number, input: UserProfile): Promise<{ upn: string }> {
  const existing = await getUserById(ctx.env, id);
  if (!existing) throw new ServiceError(404, "Not found");
  await assertMayTouchUser(ctx, id);
  // Mastered fields belong to the upstream provisioner: whatever the caller
  // sent (or left off a read-only form), the existing value survives. The API
  // layer rejects mastered fields outright.
  const mastered = new Set(await getMasteredFields(ctx.env));
  let username = input.username.trim().toLowerCase();
  let domain = input.domain.trim().toLowerCase();
  let upn: string;
  if (mastered.has("upn")) {
    username = existing.username;
    domain = existing.upn.slice(existing.upn.lastIndexOf("@") + 1);
    upn = existing.upn;
  } else {
    if (!username || !domain) throw new ServiceError(400, "username and domain are required");
    if (!USERNAME_PATTERN.test(username)) throw new ServiceError(400, `"${username}" is not a valid username.`);
    if (!(await domainExists(ctx.env, domain))) throw new ServiceError(400, `No domain "${domain}".`);
    upn = `${username}@${domain}`;
  }
  const givenName = mastered.has("given_name") ? existing.given_name : input.givenName.trim();
  const familyName = mastered.has("family_name") ? existing.family_name : input.familyName.trim();
  const displayName = mastered.has("display_name") ? existing.display_name : `${givenName} ${familyName}`.trim();
  const status = existing.status; // changed only through setUserStatus
  const groupIds = await staticOnly(ctx.env, input.groupIds);
  await assertMayAssignGroups(ctx, groupIds);

  // Conform to the chosen schema: what it defines is saved, everything else is cleared.
  const schemaId = Number(input.schemaId) || (await defaultSchemaId(ctx.env, "user"));
  const schemaAttrs = schemaId ? await getSchemaAttributes(ctx.env, schemaId) : [];
  const attrValues = Object.fromEntries(schemaAttrs.map((a) => [a.name, String(input.attributes[a.name] ?? "").trim()]));
  if (mastered.size) {
    for (const a of schemaAttrs) {
      if (mastered.has(masteringKeyFor(a))) attrValues[a.name] = userAttributeValue(existing, a);
    }
  }
  const { columns, custom } = conformUserAttributes(schemaAttrs, attrValues);

  let managerExternalId = (columns.manager_external_id as string | null) ?? null;
  if (managerExternalId && managerExternalId === existing.external_id) managerExternalId = null; // can't manage yourself

  if (await ctx.env.DB.prepare("SELECT id FROM users WHERE (username = ? OR upn = ?) AND id != ?").bind(username, upn, id).first()) throw new ServiceError(409, TAKEN(username));
  if (await ctx.env.DB.prepare("SELECT 1 FROM user_emails WHERE email = ? AND user_id != ?").bind(upn, id).first()) throw new ServiceError(409, TAKEN(username));

  let email = existing.email;
  let emails: UserEmailInput[] | undefined;
  if (mastered.has("emails")) {
    // The address list belongs to the provisioner; leave it entirely alone.
  } else if (input.emails !== undefined) {
    emails = input.emails;
    email = emails.length > 0 ? String((emails.find((e) => e.primary) ?? emails[0])!.value).trim().toLowerCase() : null;
  } else if (input.email !== undefined) {
    email = String(input.email ?? "").trim().toLowerCase() || null;
    emails = email ? [{ value: email }] : [];
  }
  if (emails !== undefined) {
    try {
      await assertEmailsUsable(ctx.env, id, emails);
    } catch (e) {
      if (e instanceof UserEmailError) throw new ServiceError(400, e.message);
      throw e;
    }
  }

  await assertNoAdminRoleGrant(ctx, existing, {
    ...existing,
    upn,
    username,
    display_name: displayName,
    given_name: givenName,
    family_name: familyName,
    job_title: String(columns.job_title ?? ""),
    department: String(columns.department ?? ""),
    manager_external_id: managerExternalId,
    employee_number: String(columns.employee_number ?? ""),
    hire_date: String(columns.hire_date ?? ""),
    employment_status: String(columns.employment_status ?? ""),
    employment_type: String(columns.employment_type ?? ""),
    location: String(columns.location ?? ""),
    schema_id: schemaId ?? null,
    custom_attributes: JSON.stringify(custom),
    email,
  });

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

  // The address table is the record; undefined leaves it untouched.
  if (emails !== undefined) await setUserEmails(ctx.env, id, emails);

  const { results: previous } = await ctx.env.DB.prepare("SELECT group_id FROM group_members WHERE user_id = ?").bind(id).all<{ group_id: number }>();
  await ctx.env.DB.prepare("DELETE FROM group_members WHERE user_id = ?").bind(id).run();
  if (groupIds.length > 0) {
    await ctx.env.DB.batch(groupIds.map((gid) => ctx.env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(gid, id)));
  }

  await audit(ctx, "user.updated", upn);
  await afterResponse(ctx, async (later) => {
    await syncUserBestEffort(later, id, status === "active" ? "push" : "deactivate");
    // Groups they left, groups they joined, and every dynamic group - an
    // attribute edit can move them in or out of any rule.
    const { results: dynamicRows } = await ctx.env.DB.prepare("SELECT id FROM groups WHERE rule != ''").all<{ id: number }>();
    const affected = new Set([...previous.map((p) => p.group_id), ...groupIds, ...dynamicRows.map((g) => g.id)]);
    for (const gid of affected) await syncGroupBestEffort(later, gid);
  });
  return { upn };
}

/** The account switch. Deactivation takes effect now: sessions end and tokens stop working. */
export async function setUserStatus(ctx: ServiceCtx, id: number, status: "active" | "disabled"): Promise<void> {
  const user = await getUserById(ctx.env, id);
  if (!user) throw new ServiceError(404, "Not found");
  if (id === ctx.selfId) throw new ServiceError(400, "You cannot deactivate your own account.");
  await assertMayTouchUser(ctx, id);
  // `status` is a rule field: a status change can put someone into a dynamic admin role group.
  await assertNoAdminRoleGrant(ctx, user, { ...user, status });
  await ctx.env.DB.prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ?").bind(status, new Date().toISOString(), id).run();
  // Deactivation should take effect now, not at the next sign-in - and not at
  // the next introspection or refresh grant either.
  if (status === "disabled") {
    await revokeAllSessionsForUser(ctx.env, id);
    await revokeTokensForUser(ctx.env, id);
  }
  await audit(ctx, status === "active" ? "user.activated" : "user.deactivated", user.upn);
  if (status === "disabled") {
    // CAEP out: receivers step the account down on their side too (lib/ssf.ts).
    await afterResponse(ctx, () => emitAndDrain(ctx.env, SSF_EVENTS["risc.account-disabled"], { format: "email", email: user.upn }));
  }
  await afterResponse(ctx, (later) => syncUserBestEffort(later, id, status === "active" ? "push" : "deactivate"));
}

/** Sets a chosen password (policy-checked) or generates one. A reset is a compromise response: every session and token ends. */
export async function resetUserPassword(ctx: ServiceCtx, id: number, chosen: string): Promise<{ password: string; user: UserRow }> {
  const user = await getUserById(ctx.env, id);
  if (!user) throw new ServiceError(404, "Not found");
  await assertMayTouchUser(ctx, id);
  if (chosen) {
    const policyError = await newPasswordError(ctx.env, chosen);
    if (policyError) throw new ServiceError(400, policyError);
  }
  const password = chosen || (await generateAccountPassword(ctx.env));
  const { hash, salt, iterations } = await hashPassword(password, ctx.env);
  await ctx.env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?")
    .bind(hash, salt, iterations, new Date().toISOString(), id)
    .run();
  // Same compromise response as the self-service change: sessions, tokens
  // and passkeys all go - a passkey minted while the account was exposed
  // would otherwise keep authenticating without the new password. The rest of
  // the MFA state goes with it: a hijacked fresh session can enrol its own
  // authenticator and harvest the backup-code set, and none of that may
  // survive a password reset either.
  await ctx.env.DB.prepare("DELETE FROM webauthn_credentials WHERE user_id = ?").bind(id).run();
  await resetUserMfa(ctx, id);
  await revokeAllSessionsForUser(ctx.env, id);
  await revokeTokensForUser(ctx.env, id);
  await audit(ctx, "user.password_reset", user.upn, { chosen: Boolean(chosen) });
  await afterResponse(ctx, () => emitAndDrain(ctx.env, SSF_EVENTS["caep.credential-change"], { format: "email", email: user.upn }));
  return { password, user };
}

/** Clears the authenticator, backup codes, email codes, security questions and remembered devices; they enrol again at next sign-in. */
export async function resetUserMfa(ctx: ServiceCtx, id: number): Promise<void> {
  await assertMayTouchUser(ctx, id);
  await ctx.env.DB.batch([
    ctx.env.DB.prepare(
      "UPDATE users SET totp_secret = NULL, mfa_enabled = 0, totp_last_counter = NULL, email_otp_enabled = 0, security_questions_enabled = 0, updated_at = ? WHERE id = ?"
    ).bind(new Date().toISOString(), id),
    ctx.env.DB.prepare("DELETE FROM user_security_answers WHERE user_id = ?").bind(id),
  ]);
  await deleteBackupCodes(ctx.env, id);
  await deleteTrustedDevicesForUser(ctx.env, id);
  await audit(ctx, "user.mfa_reset", String(id));
}

export async function revokeUserSessions(ctx: ServiceCtx, id: number): Promise<number> {
  await assertMayTouchUser(ctx, id);
  const user = await getUserById(ctx.env, id);
  const count = await revokeAllSessionsForUser(ctx.env, id);
  await audit(ctx, "user.sessions_revoked_all", String(id), { count });
  if (count > 0 && user) await afterResponse(ctx, () => emitAndDrain(ctx.env, SSF_EVENTS["caep.session-revoked"], { format: "email", email: user.upn }));
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
    // An unredeemed authorization code dies with the grant it belongs to.
    ctx.env.DB.prepare("DELETE FROM auth_codes WHERE user_id = ? AND client_id = ?").bind(id, client.client_id),
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
  await ctx.env.DB.batch([...(await scimDeprovisionStatements(ctx.env, "user", id, user.upn)), ...deleteUserStatements(ctx.env, id)]);

  await afterResponse(ctx, async (later) => {
    if (await scimConfigured(later.env)) {
      // A failure stays queued and is retried by every sync and the hourly cron.
      const result = await drainScimDeprovisionQueue(later.env);
      if (result.failed) await audit(later, "scim.user_sync_failed", user.upn, { action: "delete", queued: result.remaining });
    }
  });
  await audit(ctx, "user.deleted", user.upn);
  return user;
}

/** Invitation (choosing a password activates the account) or a password reset link, by email. */
export async function sendUserLink(ctx: ServiceCtx, user: UserRow, kind: "invite" | "reset"): Promise<{ ok: true } | { ok: false; error: string }> {
  await assertMayTouchUser(ctx, user.id);
  // An invitation activates the account; `status` is a rule field, so sending
  // one can be an admin grant the caller had no business making.
  if (kind === "invite") await assertNoAdminRoleGrant(ctx, user, { ...user, status: "active" });
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

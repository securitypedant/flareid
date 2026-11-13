import { importDirectory, type ImportResult } from "../lib/directory-import.js";
import { addDomain, listDomains, setDefaultDomain } from "../lib/domains.js";
import { SUPER_ADMINS_GROUP } from "../lib/middleware.js";
import { setRateLimitPolicy } from "../lib/rate-limit.js";
import {
  getCursorTrail,
  getSessionPolicy,
  isHexColor,
  isSetupCompleted,
  markSetupCompleted,
  setAppName,
  setCursorTrail,
  setDefaultPassword,
  setLoginGradient,
  setLoginSubtitle,
  setMfaRequired,
  setNewUserPasswordMode,
  setPasswordPolicy,
  setSessionPolicy,
  type PasswordPolicy,
} from "../lib/settings.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";

/**
 * First-run setup, shared by POST /api/v1/setup and the browser page at
 * /setup, so the two cannot apply different rules: the same settings, the
 * same administrator import (password policy and breached-password check
 * included), the same completion step.
 */
export interface SetupInput {
  domain?: string;
  admin?: { username?: string; password?: string; display_name?: string; given_name?: string; family_name?: string };
  default_password?: string;
  app_name?: string;
  login_subtitle?: string;
  login_gradient?: { from?: string; to?: string };
  require_mfa?: boolean;
  /**
   * Whether administrators need a second factor: true (what a fresh install
   * does) keeps Super Admins in "Password and a second factor"; false takes
   * them out of every policy that requires one and makes "Password only" the
   * default, so the first administrator signs in with the password alone.
   * Omitted leaves the policies as they are.
   */
  admin_mfa?: boolean;
  new_user_password_mode?: "default" | "random";
  password_policy?: Partial<PasswordPolicy>;
  rate_limit?: { max_attempts?: number; window_minutes?: number };
  cursor_trail?: { enabled?: boolean; characters?: string };
  session_limits?: { max_hours?: number; idle_minutes?: number };
  complete?: boolean;
}

export interface SetupResult {
  applied: string[];
  setup_completed: boolean;
  admin?: { upn: string; password?: string };
}

/**
 * Secure by default, but the instance's choice: Super Admins in (or out of)
 * the policy that requires a second factor. Out also makes the password-only
 * policy the default, or the default would still require one of them.
 */
async function setAdminMfa(env: ServiceCtx["env"], required: boolean): Promise<void> {
  const group = await env.DB.prepare("SELECT id FROM groups WHERE name = ?").bind(SUPER_ADMINS_GROUP).first<{ id: number }>();
  if (!group) return;
  if (required) {
    const policy = await env.DB.prepare("SELECT id FROM auth_policies WHERE requirement = 'mfa' ORDER BY name = 'Password and a second factor' DESC, priority, id LIMIT 1").first<{ id: number }>();
    if (policy) await env.DB.prepare("INSERT OR IGNORE INTO auth_policy_groups (policy_id, group_id) VALUES (?, ?)").bind(policy.id, group.id).run();
    return;
  }
  await env.DB.prepare("DELETE FROM auth_policy_groups WHERE group_id = ? AND policy_id IN (SELECT id FROM auth_policies WHERE requirement = 'mfa')").bind(group.id).run();
  await setMfaRequired(env, false);
}

/** The administrator could not be created; `details` are the import's per-user errors. */
export class SetupAdminError extends Error {
  constructor(public details: ImportResult["errors"]) {
    super("Could not create the administrator.");
  }
}

/**
 * Settings first, then the administrator, then `admin_mfa`, then the
 * completion flag - and that order matters. The account is created with whatever `new_user_password_mode`
 * and `default_password` say, so applying those afterwards would mint an
 * administrator with the wrong credential; and `complete` is last because it is
 * what stops the bootstrap token working, so anything after it would be locked
 * out of its own setup call.
 */
export async function runSetup(ctx: ServiceCtx, body: SetupInput, via: "api" | "setup_page"): Promise<SetupResult> {
  const { env } = ctx;
  // Creating or resetting an administrator grants Super Admin, and with it key
  // minting - that is admin authority, not settings authority. Refuse it
  // before anything is applied so a rejected request has no partial effects.
  if (body.admin?.username && !ctx.privileged) {
    throw new ServiceError(403, 'Creating an administrator requires the "admin" scope.');
  }
  // Validated with everything else, before anything is applied.
  if (body.login_gradient !== undefined && (!isHexColor(body.login_gradient.from) || !isHexColor(body.login_gradient.to))) {
    throw new ServiceError(400, "login_gradient.from and .to must both be #rrggbb hex colours.");
  }
  // Letting administrators (Super Admins included) sign in with a password
  // alone weakens administrator accounts: the same authority as creating one.
  if (body.admin_mfa === false && !ctx.privileged) {
    throw new ServiceError(403, 'admin_mfa: false requires the "admin" scope.');
  }
  if (body.admin_mfa === false && body.require_mfa === true) {
    throw new ServiceError(400, "admin_mfa: false cannot be combined with require_mfa: true - the default policy would still make administrators use a second factor.");
  }
  const applied: string[] = [];

  if (body.domain !== undefined) {
    const domain = String(body.domain).trim().toLowerCase();
    if (!domain) throw new ServiceError(400, "domain cannot be empty.");
    const existing = await listDomains(env);
    if (!existing.some((d) => d.domain === domain)) await addDomain(env, domain);
    const row = (await listDomains(env)).find((d) => d.domain === domain);
    if (row) await setDefaultDomain(env, row.id);
    applied.push(`domain=${domain}`);
  }

  if (body.default_password !== undefined) {
    await setDefaultPassword(env, String(body.default_password));
    applied.push("default_password");
  }
  if (body.new_user_password_mode !== undefined) {
    await setNewUserPasswordMode(env, body.new_user_password_mode === "default" ? "default" : "random");
    applied.push(`new_user_password_mode=${body.new_user_password_mode}`);
  }
  if (body.app_name !== undefined) {
    await setAppName(env, String(body.app_name));
    applied.push("app_name");
  }
  if (body.login_subtitle !== undefined) {
    await setLoginSubtitle(env, String(body.login_subtitle));
    applied.push("login_subtitle");
  }
  if (body.login_gradient?.from && body.login_gradient?.to) {
    await setLoginGradient(env, { from: body.login_gradient.from, to: body.login_gradient.to });
    applied.push("login_gradient");
  }
  if (body.require_mfa !== undefined) {
    await setMfaRequired(env, Boolean(body.require_mfa));
    applied.push(`require_mfa=${Boolean(body.require_mfa)}`);
  }
  if (body.password_policy !== undefined) {
    const p = body.password_policy;
    await setPasswordPolicy(env, {
      minLength: Number(p.minLength ?? 8),
      requireUppercase: Boolean(p.requireUppercase),
      requireLowercase: Boolean(p.requireLowercase),
      requireNumber: Boolean(p.requireNumber),
      requireSymbol: Boolean(p.requireSymbol),
    });
    applied.push("password_policy");
  }
  if (body.rate_limit !== undefined) {
    await setRateLimitPolicy(env, {
      maxAttempts: Number(body.rate_limit.max_attempts ?? 5),
      windowMinutes: Number(body.rate_limit.window_minutes ?? 15),
    });
    applied.push("rate_limit");
  }
  if (body.cursor_trail !== undefined) {
    const current = await getCursorTrail(env);
    await setCursorTrail(env, {
      enabled: body.cursor_trail.enabled ?? current.enabled,
      characters: body.cursor_trail.characters !== undefined ? String(body.cursor_trail.characters) : current.characters,
    });
    applied.push("cursor_trail");
  }
  if (body.session_limits !== undefined) {
    const current = await getSessionPolicy(env);
    await setSessionPolicy(env, {
      maxHours: body.session_limits.max_hours ?? current.maxHours,
      idleMinutes: body.session_limits.idle_minutes ?? current.idleMinutes,
    });
    applied.push("session_limits");
  }

  // The administrator, routed through the ordinary import so there is exactly
  // one code path that creates a user.
  let admin: { upn: string; password?: string } | undefined;
  if (body.admin?.username) {
    const username = String(body.admin.username).trim().toLowerCase();
    const result = await importDirectory(
      env,
      {
        version: 1,
        domain: body.domain,
        groups: [{ name: SUPER_ADMINS_GROUP, description: "Members can administer this directory" }],
        users: [
          {
            username,
            display_name: body.admin.display_name ?? "Administrator",
            given_name: body.admin.given_name ?? "Administrator",
            family_name: body.admin.family_name ?? "",
            password: body.admin.password ?? null,
            status: "active",
            super_admin: true,
          },
        ],
      },
      // The admin check already ran above; this bundle is built internally.
      { allowPrivileged: true }
    );

    if (result.errors.length > 0) throw new SetupAdminError(result.errors);
    const upn = `${username}@${result.domain}`;
    admin = { upn, ...(result.generated_passwords[upn] ? { password: result.generated_passwords[upn] } : {}) };
    applied.push(`admin=${upn}`);
  }

  // After the administrator, so a rejected account (a weak password on the
  // setup page) leaves the policies as they were for the next attempt.
  if (body.admin_mfa !== undefined) {
    await setAdminMfa(env, body.admin_mfa !== false);
    applied.push(`admin_mfa=${body.admin_mfa !== false}`);
  }

  // Also fixes the issuer (see markSetupCompleted).
  if (body.complete) {
    await markSetupCompleted(env);
    applied.push("setup_completed");
  }

  await audit(ctx, "idp.setup_completed", body.domain, { applied, via, ...(body.admin_mfa === false ? { admin_mfa_relaxed: true } : {}) });

  return { applied, setup_completed: await isSetupCompleted(env), ...(admin ? { admin } : {}) };
}

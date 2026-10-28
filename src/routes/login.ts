import { Hono } from "hono";
import type { Env } from "../env.js";
import { loginForm, mfaForm } from "../lib/login-views.js";
import { getUserById, getUserByLoginIdentifier } from "../lib/db.js";
import { verifyPassword } from "../lib/password.js";
import { verifyTotp } from "../lib/totp.js";
import {
  deleteLoginFlow,
  deletePendingMfa,
  getLoginFlow,
  getPendingMfa,
  storeLoginFlow,
  storePendingMfa,
  type LoginFlow,
} from "../lib/authorize-state.js";
import { clearSessionCookie, createSession, getSession, getSessionUserId, revokeSession } from "../lib/sessions.js";
import { finishOidcAuthorize } from "./authorize.js";
import { getLoginGradient, getLoginSubtitle, isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { isSuperAdmin } from "../lib/middleware.js";
import { logAudit } from "../lib/audit.js";
import { clearLoginAttempts, getClientIp, isLoginRateLimited, recordFailedLogin } from "../lib/rate-limit.js";
import { verifyAndConsumeBackupCode } from "../lib/backup-codes.js";
import { isDeviceTrusted, trustDevice } from "../lib/trusted-devices.js";

export const login = new Hono<{ Bindings: Env }>();

/** Direct login entry point for /account and /admin - not tied to an OIDC request. */
login.get("/login", async (c) => {
  const next = c.req.query("next") ?? "/account";

  const existingUserId = await getSessionUserId(c.req.raw, c.env);
  if (existingUserId) return c.redirect(next, 302);

  const flowId = await storeLoginFlow(c.env, { kind: "direct", next });
  return c.html(loginForm(c.get("appName"), flowId, await getLoginGradient(c.env), await getLoginSubtitle(c.env)));
});

login.post("/logout", async (c) => {
  const session = await getSession(c.req.raw, c.env);
  if (session) await revokeSession(c.env, session.id);
  c.header("Set-Cookie", clearSessionCookie());
  return c.redirect("/login", 302);
});

async function completeLoginFlow(
  env: Env,
  flow: LoginFlow,
  userId: number,
  amr: string[],
  request: Request,
  user: { mfa_enabled: number }
): Promise<{ redirectTo: string; setCookie: string }> {
  const { setCookie } = await createSession(env, userId, amr, request);

  // Until initial setup is complete, always land on the setup wizard -
  // regardless of whether this login came from an OIDC request or a direct
  // /account visit - nothing else should be usable yet.
  const setupCompleted = await isSetupCompleted(env);
  if (!setupCompleted) {
    return { redirectTo: "/admin/setup", setCookie };
  }

  // Once setup is done, MFA can be made mandatory - anyone without it enrolled
  // gets forced through setup (with backup codes) before reaching their
  // original destination, whether that's a direct /account visit or an OIDC
  // login to a relying party.
  if (!user.mfa_enabled && (await isMfaRequired(env))) {
    const resumeFlowId = await storeLoginFlow(env, flow);
    return { redirectTo: `/account/mfa/setup?resume=${resumeFlowId}`, setCookie };
  }

  if (flow.kind === "direct") return { redirectTo: flow.next, setCookie };
  const { redirectTo } = await finishOidcAuthorize(env, flow.request, userId, amr);
  return { redirectTo, setCookie };
}

login.post("/login", async (c) => {
  const body = await c.req.parseBody();
  const flowId = String(body.flow_id ?? "");
  const upn = String(body.upn ?? "");
  const password = String(body.password ?? "");
  const ip = getClientIp(c.req.raw);

  const flow = await getLoginFlow(c.env, flowId);
  if (!flow) return c.text("Login session expired, please try again.", 400);
  const gradient = await getLoginGradient(c.env);
  const subtitle = await getLoginSubtitle(c.env);

  if (await isLoginRateLimited(c.env, upn, ip)) {
    await logAudit(c.env, null, "login.rate_limited", upn, { ip }, c.req.raw);
    return c.html(
      loginForm(c.get("appName"), flowId, gradient, subtitle, "Too many attempts. Please wait a few minutes before trying again.")
    );
  }

  const user = await getUserByLoginIdentifier(c.env, upn);
  const valid = user && user.status === "active" && (await verifyPassword(password, user));

  if (!valid || !user) {
    await recordFailedLogin(c.env, upn, ip);
    await logAudit(c.env, null, "login.failed", upn, { ip }, c.req.raw);
    return c.html(loginForm(c.get("appName"), flowId, gradient, subtitle, "Incorrect username/UPN or password."));
  }

  await clearLoginAttempts(c.env, upn);

  if (!(await isSetupCompleted(c.env)) && !(await isSuperAdmin(c.env, user.id))) {
    return c.html(
      loginForm(c.get("appName"), flowId, gradient, subtitle, "FlareID hasn't finished initial setup yet. Only administrators can sign in right now.")
    );
  }

  if (user.mfa_enabled && !(await isDeviceTrusted(c.env, c.req.raw, user.id))) {
    const mfaId = await storePendingMfa(c.env, user.id, flowId);
    return c.html(mfaForm(c.get("appName"), mfaId, gradient));
  }

  const amr = user.mfa_enabled ? ["pwd", "mfa_remembered_device"] : ["pwd"];
  await deleteLoginFlow(c.env, flowId);
  const { redirectTo, setCookie } = await completeLoginFlow(c.env, flow, user.id, amr, c.req.raw, user);
  c.header("Set-Cookie", setCookie);
  if (user.mfa_enabled) await logAudit(c.env, user, "login.mfa_skipped_trusted_device", user.upn, undefined, c.req.raw);
  await logAudit(c.env, user, "login.success", user.upn, { amr }, c.req.raw);
  return c.redirect(redirectTo, 302);
});

login.post("/login/mfa", async (c) => {
  const body = await c.req.parseBody();
  const mfaId = String(body.mfa_id ?? "");
  const code = String(body.code ?? "");
  const rememberDevice = !!body.remember_device;
  const ip = getClientIp(c.req.raw);

  const pending = await getPendingMfa(c.env, mfaId);
  if (!pending) return c.text("Login session expired, please try again.", 400);

  const user = await getUserById(c.env, pending.userId);
  if (!user || !user.totp_secret) return c.text("MFA is not configured for this account.", 400);
  const gradient = await getLoginGradient(c.env);
  const subtitle = await getLoginSubtitle(c.env);

  if (await isLoginRateLimited(c.env, `mfa:${user.upn}`, ip)) {
    await logAudit(c.env, null, "login.mfa_rate_limited", user.upn, { ip }, c.req.raw);
    return c.html(mfaForm(c.get("appName"), mfaId, gradient, "Too many attempts. Please wait a few minutes before trying again."));
  }

  let amr = ["pwd", "mfa"];
  const validTotp = await verifyTotp(user.totp_secret, code);
  if (!validTotp) {
    const validBackupCode = await verifyAndConsumeBackupCode(c.env, user.id, code);
    if (!validBackupCode) {
      await recordFailedLogin(c.env, `mfa:${user.upn}`, ip);
      await logAudit(c.env, null, "login.mfa_failed", user.upn, { ip }, c.req.raw);
      return c.html(mfaForm(c.get("appName"), mfaId, gradient, "Incorrect code, please try again."));
    }
    amr = ["pwd", "mfa", "backup_code"];
    await logAudit(c.env, user, "login.mfa_backup_code_used", user.upn, undefined, c.req.raw);
  }

  await clearLoginAttempts(c.env, `mfa:${user.upn}`);

  const flow = await getLoginFlow(c.env, pending.flowId);
  if (!flow) return c.text("Login session expired, please try again.", 400);

  await deletePendingMfa(c.env, mfaId);
  await deleteLoginFlow(c.env, pending.flowId);

  const { redirectTo, setCookie } = await completeLoginFlow(c.env, flow, user.id, amr, c.req.raw, user);
  c.header("Set-Cookie", setCookie, { append: true });

  if (rememberDevice) {
    const deviceCookie = await trustDevice(c.env, c.req.raw, user.id);
    c.header("Set-Cookie", deviceCookie, { append: true });
    await logAudit(c.env, user, "user.device_trusted", user.upn, undefined, c.req.raw);
  }

  await logAudit(c.env, user, "login.success", user.upn, { amr }, c.req.raw);
  return c.redirect(redirectTo, 302);
});

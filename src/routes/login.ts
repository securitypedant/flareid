import { canSignIn } from "../lib/admin-roles.js";
import { hasSecondFactor, isFactorEnabled, mfaRequiredFor, secondFactorGate, userHasPasskey } from "../lib/auth-policy.js";
import { frontchannelLogoutPage, frontchannelTargets } from "../lib/frontchannel.js";
import { randomToken } from "../lib/tokens.js";
import { authenticationOptions, finishAuthentication } from "../lib/passkeys.js";
import { Hono } from "hono";
import type { Env } from "../env.js";
import { AUTH_MESSAGES, loginForm, mfaForm, renderAuthMessage } from "../lib/login-views.js";
import { getUserById, getUserByLoginIdentifier } from "../lib/db.js";
import { hashPassword, upgradePasswordHashIfNeeded, verifyPassword, type StoredPassword } from "../lib/password.js";
import { claimTotpCounter, matchTotpCounter } from "../lib/totp.js";
import {
  deleteLoginFlow,
  deletePendingMfa,
  getLoginFlow,
  getPendingMfa,
  sealLoginFlow,
  storeLoginFlow,
  storePendingMfa,
  type LoginFlow,
} from "../lib/authorize-state.js";
import { clearSessionCookie, createSession, getSession, getSessionUserId, revokeSession } from "../lib/sessions.js";
import { finishOidcAuthorize } from "./authorize.js";
import { issueSamlResponse } from "./saml.js";
import { getSpById } from "../lib/saml/service-providers.js";
import { samlPostForm } from "../lib/saml/post-form.js";
import { getLoginAppearance, isMfaRequired, isSetupCompleted } from "../lib/settings.js";
import { isSuperAdmin } from "../lib/middleware.js";
import { logAudit } from "../lib/audit.js";
import { clearLoginAttempts, clearMfaAttempts, getClientIp, loginRateKey, recordLoginAttempt, recordMfaAttempt } from "../lib/rate-limit.js";
import { verifyAndConsumeBackupCode } from "../lib/backup-codes.js";
import { isDeviceTrusted, trustDevice } from "../lib/trusted-devices.js";

export const login = new Hono<{ Bindings: Env }>();

/**
 * Where a direct login may send the browser afterwards: a path on this origin,
 * nothing else. "//evil.test" and "/\\evil.test" are protocol-relative to
 * browsers, so a leading slash alone is not enough. Capped in length, since it
 * rides inside the sealed flow.
 */
export function safeNextPath(next: string | undefined): string {
  if (!next || next.length > 512 || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/account";
  if (/[\u0000-\u001f\u007f]/.test(next)) return "/account";
  return next;
}

/**
 * A hash of a random password with the deployment's current hasher, verified
 * against on every miss. Computed once per isolate and per hasher: it is a
 * constant, not request state, and hashing it per request would double the
 * cost of every failed sign-in.
 */
const dummyHashes = new Map<string, Promise<StoredPassword>>();
function dummyPasswordHash(env: Env): Promise<StoredPassword> {
  const key = env.PASSWORD_HASHER ?? "scrypt";
  if (!dummyHashes.has(key)) {
    dummyHashes.set(
      key,
      hashPassword(crypto.randomUUID(), env).then((h) => ({ password_hash: h.hash, password_salt: h.salt, password_iterations: h.iterations }))
    );
  }
  return dummyHashes.get(key)!;
}

/** Direct login entry point for /account and /admin - not tied to an OIDC request. */
login.get("/login", async (c) => {
  const next = safeNextPath(c.req.query("next"));

  const existingUserId = await getSessionUserId(c.req.raw, c.env);
  if (existingUserId) return c.redirect(next, 302);

  // Sealed rather than stored: this page is anonymous, and a KV write per page
  // load let anyone spend the deployment's write quota (see sealLoginFlow).
  const flowId = await sealLoginFlow(c.env, { kind: "direct", next });
  const denied = c.req.query("denied") ? "This account is not allowed to sign in. Ask an administrator." : undefined;
  return c.html(loginForm(c.get("appName"), flowId, await getLoginAppearance(c.env), denied));
});

login.post("/logout", async (c) => {
  const session = await getSession(c.req.raw, c.env);
  const targets = session ? await frontchannelTargets(c.env, session.id) : [];
  if (session) await revokeSession(c.env, session.id);
  c.header("Set-Cookie", clearSessionCookie());
  if (targets.length) {
    const { html, frameSrc } = frontchannelLogoutPage(c.get("appName"), targets, "/login");
    c.header("X-FlareID-Frame-Src", frameSrc);
    return c.html(html);
  }
  // No Clear-Site-Data: Chrome can stall a navigation for a long time clearing
  // the cache, so sign-out appeared to hang. Signed-in pages are sent
  // Cache-Control: no-store (security-headers.ts), so nothing is cached anyway.
  return c.redirect("/login", 302);
});

/**
 * What happens at the end of a completed login: most flows end in a redirect
 * (back to the RP with a code, or to wherever a direct login was heading),
 * while a SAML flow ends in an auto-submitting POST form carrying the
 * response to the service provider's ACS.
 */
export type LoginFlowOutcome =
  | { type: "redirect"; to: string }
  | { type: "saml-post"; acsUrl: string; samlResponse: string; relayState: string | null };

async function completeLoginFlow(
  env: Env,
  flow: LoginFlow,
  userId: number,
  amr: string[],
  request: Request,
  user: { mfa_enabled: number }
): Promise<{ outcome: LoginFlowOutcome; setCookie: string }> {
  // Roles decide whether this account may sign in at all (permission "signin").
  if (!(await canSignIn(env, userId))) return { outcome: { type: "redirect", to: "/login?denied=1" }, setCookie: clearSessionCookie() };
  const { sessionId, setCookie } = await createSession(env, userId, amr, request);

  // Until initial setup is complete, always land on the setup wizard -
  // regardless of whether this login came from an OIDC request or a direct
  // /account visit - nothing else should be usable yet.
  const setupCompleted = await isSetupCompleted(env);
  if (!setupCompleted) {
    return { outcome: { type: "redirect", to: "/admin/setup" }, setCookie };
  }

  // Once setup is done, MFA can be made mandatory - anyone without it enrolled
  // gets forced through setup (with backup codes) before reaching their
  // original destination, whether that's a direct /account visit or an OIDC
  // login to a relying party.
  // The user's authentication policy decides; a passkey sign-in (amr "hwk") is
  // already multi-factor.
  if ((await secondFactorGate(env, { id: userId, mfa_enabled: user.mfa_enabled }, amr)) !== "ok") {
    const resumeFlowId = await storeLoginFlow(env, { ...flow, resumeFor: userId });
    return { outcome: { type: "redirect", to: `/account/mfa/setup?resume=${resumeFlowId}` }, setCookie };
  }

  if (flow.kind === "direct") return { outcome: { type: "redirect", to: safeNextPath(flow.next) }, setCookie };

  if (flow.kind === "saml") {
    const sp = await getSpById(env, flow.request.spId);
    const fullUser = await getUserById(env, userId);
    if (!sp || !fullUser) return { outcome: { type: "redirect", to: "/account" }, setCookie };
    const issued = await issueSamlResponse(env, sp, flow.request, fullUser, sessionId, new Date());
    // Already answered (a replayed request): the sign-in still stands, but no second response.
    if (!issued) return { outcome: { type: "redirect", to: "/account" }, setCookie };
    await logAudit(env, fullUser, "saml.assertion_issued", sp.entity_id, { request_id: flow.request.requestId }, request);
    return { outcome: { type: "saml-post", ...issued }, setCookie };
  }

  const { redirectTo } = await finishOidcAuthorize(env, flow.request, userId, amr, sessionId);
  return { outcome: { type: "redirect", to: redirectTo }, setCookie };
}

login.post("/login", async (c) => {
  const body = await c.req.parseBody();
  const flowId = String(body.flow_id ?? "");
  // Bounded like the recovery form: the identifier becomes a rate-limit key
  // and an audit target, so its size must not be the caller's choice.
  const upn = String(body.upn ?? "").slice(0, 254);
  const password = String(body.password ?? "").slice(0, 1024);
  const ip = getClientIp(c.req.raw);

  const flow = await getLoginFlow(c.env, flowId);
  if (!flow) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const appearance = await getLoginAppearance(c.env);

  // Resolve first: the bucket must bind to the account, not the spelling, or
  // "admin", " admin" and "admin@x" would each get their own failure budget.
  // Recording before verifying keeps the increment and the limit decision
  // atomic - a burst can never see a stale under-limit count.
  const user = await getUserByLoginIdentifier(c.env, upn);
  const rateKey = loginRateKey(upn, user);

  if (await recordLoginAttempt(c.env, rateKey, ip)) {
    await logAudit(c.env, null, "login.rate_limited", upn, { ip }, c.req.raw);
    return c.html(
      loginForm(c.get("appName"), flowId, appearance, "Too many attempts. Please wait a few minutes before trying again.")
    );
  }

  // An unknown or disabled account still costs one real hash verification, so
  // the response time no longer tells an attacker which usernames exist
  // (previously ~70 ms for a real account against ~5 ms for a miss).
  // An account with no usable password (imported, awaiting an invitation)
  // costs the same, too - its "!" hash would otherwise fail instantly.
  const usable = user && user.status === "active" && !user.password_hash.startsWith("!");
  const valid = usable ? await verifyPassword(password, user) : (await verifyPassword(password, await dummyPasswordHash(c.env)), false);

  if (!valid || !user) {
    await logAudit(c.env, null, "login.failed", upn, { ip }, c.req.raw);
    return c.html(loginForm(c.get("appName"), flowId, appearance, "Incorrect username/UPN or password."));
  }

  await clearLoginAttempts(c.env, rateKey, ip);
  // Legacy PBKDF2 hashes move to scrypt now, while the password is in hand.
  if (await upgradePasswordHashIfNeeded(c.env, user, password)) {
    await logAudit(c.env, null, "user.password_rehashed", user.upn, undefined, c.req.raw);
  }

  if (!(await isSetupCompleted(c.env)) && !(await isSuperAdmin(c.env, user.id))) {
    return c.html(
      loginForm(c.get("appName"), flowId, appearance, "FlareID hasn't finished initial setup yet. Only administrators can sign in right now.")
    );
  }

  // Second step: the authenticator app when enrolled (unless this device is
  // remembered); otherwise a passkey when the user's policy needs a second factor.
  const totp = Boolean(user.mfa_enabled) && (await isFactorEnabled(c.env, "totp"));
  const passkey = (await isFactorEnabled(c.env, "passkey")) && (await userHasPasskey(c.env, user.id));
  const needsStep = totp ? !(await isDeviceTrusted(c.env, c.req.raw, user.id)) : passkey && (await mfaRequiredFor(c.env, user.id));
  if (needsStep) {
    const mfaId = await storePendingMfa(c.env, user.id, flowId);
    return c.html(mfaForm(c.get("appName"), mfaId, appearance, undefined, { totp, passkey }));
  }

  const amr = totp ? ["pwd", "mfa_remembered_device"] : ["pwd"];
  await deleteLoginFlow(c.env, flowId);
  const { outcome, setCookie } = await completeLoginFlow(c.env, flow, user.id, amr, c.req.raw, user);
  c.header("Set-Cookie", setCookie);
  if (totp) await logAudit(c.env, user, "login.mfa_skipped_trusted_device", user.upn, undefined, c.req.raw);
  await logAudit(c.env, user, "login.success", user.upn, { amr }, c.req.raw);
  if (outcome.type === "saml-post") {
    return c.html(samlPostForm(c.get("appName"), outcome.acsUrl, outcome.samlResponse, outcome.relayState));
  }
  return c.redirect(outcome.to, 302);
});

// Passkey sign-in (discoverable credentials, no username typed).
login.get("/login/passkey/options", async (c) => {
  const flowId = c.req.query("flow_id") ?? "";
  if (!(await getLoginFlow(c.env, flowId))) return c.json({ error: "expired" }, 400);
  const attempt = randomToken(16);
  return c.json({ attempt, options: await authenticationOptions(c.env, attempt) });
});

login.post("/login/passkey", async (c) => {
  const body = await c.req.parseBody();
  const flowId = String(body.flow_id ?? "");
  const flow = await getLoginFlow(c.env, flowId);
  if (!flow) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const appearance = await getLoginAppearance(c.env);
  let response: unknown;
  try {
    response = JSON.parse(String(body.response ?? "").slice(0, 16_384));
  } catch {
    response = null;
  }
  const userId = response ? await finishAuthentication(c.env, String(body.attempt ?? ""), response as never) : null;
  const user = userId ? await getUserById(c.env, userId) : null;
  if (!user || user.status !== "active") {
    await logAudit(c.env, null, "login.passkey_failed", undefined, { ip: getClientIp(c.req.raw) }, c.req.raw);
    return c.html(loginForm(c.get("appName"), flowId, appearance, "That passkey could not sign you in."));
  }
  if (!(await isSetupCompleted(c.env)) && !(await isSuperAdmin(c.env, user.id))) {
    return c.html(loginForm(c.get("appName"), flowId, appearance, "FlareID hasn't finished initial setup yet. Only administrators can sign in right now."));
  }
  const amr = ["hwk", "mfa"];
  await deleteLoginFlow(c.env, flowId);
  const { outcome, setCookie } = await completeLoginFlow(c.env, flow, user.id, amr, c.req.raw, user);
  c.header("Set-Cookie", setCookie);
  await logAudit(c.env, user, "login.success", user.upn, { amr }, c.req.raw);
  if (outcome.type === "saml-post") return c.html(samlPostForm(c.get("appName"), outcome.acsUrl, outcome.samlResponse, outcome.relayState));
  return c.redirect(outcome.to, 302);
});

// The second step with a passkey instead of a code.
login.get("/login/mfa/passkey/options", async (c) => {
  const pending = await getPendingMfa(c.env, c.req.query("mfa_id") ?? "");
  if (!pending) return c.json({ error: "expired" }, 400);
  const attempt = randomToken(16);
  return c.json({ attempt, options: await authenticationOptions(c.env, attempt, pending.userId) });
});

login.post("/login/mfa/passkey", async (c) => {
  const body = await c.req.parseBody();
  const mfaId = String(body.mfa_id ?? "");
  const pending = await getPendingMfa(c.env, mfaId);
  if (!pending) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const flow = await getLoginFlow(c.env, pending.flowId);
  if (!flow) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  const appearance = await getLoginAppearance(c.env);
  let response: unknown;
  try {
    response = JSON.parse(String(body.response ?? "").slice(0, 16_384));
  } catch {
    response = null;
  }
  const provedUser = response ? await finishAuthentication(c.env, String(body.attempt ?? ""), response as never) : null;
  const user = await getUserById(c.env, pending.userId);
  if (!user || user.status !== "active" || provedUser !== pending.userId) {
    await logAudit(c.env, null, "login.mfa_failed", user?.upn, { method: "passkey" }, c.req.raw);
    return c.html(mfaForm(c.get("appName"), mfaId, appearance, "That passkey could not confirm it's you.", { totp: Boolean(user?.mfa_enabled), passkey: true }));
  }
  await deletePendingMfa(c.env, mfaId);
  await deleteLoginFlow(c.env, pending.flowId);
  const amr = ["pwd", "hwk", "mfa"];
  const { outcome, setCookie } = await completeLoginFlow(c.env, flow, user.id, amr, c.req.raw, user);
  c.header("Set-Cookie", setCookie);
  await logAudit(c.env, user, "login.success", user.upn, { amr }, c.req.raw);
  if (outcome.type === "saml-post") return c.html(samlPostForm(c.get("appName"), outcome.acsUrl, outcome.samlResponse, outcome.relayState));
  return c.redirect(outcome.to, 302);
});

login.post("/login/mfa", async (c) => {
  const body = await c.req.parseBody();
  const mfaId = String(body.mfa_id ?? "");
  const code = String(body.code ?? "");
  const rememberDevice = !!body.remember_device;
  const ip = getClientIp(c.req.raw);

  const pending = await getPendingMfa(c.env, mfaId);
  if (!pending) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);

  const user = await getUserById(c.env, pending.userId);
  // The account is re-checked here, not just at the password step: a user
  // deactivated while the challenge was pending must not complete it.
  if (!user || user.status !== "active") {
    await deletePendingMfa(c.env, mfaId);
    return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);
  }
  if (!user.totp_secret) {
    return renderAuthMessage(c, 400, {
      title: "Two-step verification isn't set up",
      message: "This account no longer has an authenticator enrolled. Start the sign-in again; if it keeps happening, ask your administrator.",
    });
  }
  const appearance = await getLoginAppearance(c.env);

  // The bucket is keyed on the user id, not any submitted string - nothing in
  // the password step can reach this namespace.
  if (await recordMfaAttempt(c.env, user.id, ip)) {
    await logAudit(c.env, null, "login.mfa_rate_limited", user.upn, { ip }, c.req.raw);
    return c.html(mfaForm(c.get("appName"), mfaId, appearance, "Too many attempts. Please wait a few minutes before trying again."));
  }

  let amr = ["pwd", "mfa"];
  // A code inside its window that was already accepted is a replay, and counts
  // as a failure - the claim only lands while the stored counter is lower.
  const counter = await matchTotpCounter(user.totp_secret, code);
  if (counter === null || !(await claimTotpCounter(c.env, user.id, counter))) {
    const validBackupCode = await verifyAndConsumeBackupCode(c.env, user.id, code);
    if (!validBackupCode) {
      await logAudit(c.env, null, "login.mfa_failed", user.upn, { ip }, c.req.raw);
      return c.html(mfaForm(c.get("appName"), mfaId, appearance, "Incorrect code, please try again."));
    }
    amr = ["pwd", "mfa", "backup_code"];
    await logAudit(c.env, user, "login.mfa_backup_code_used", user.upn, undefined, c.req.raw);
  }

  await clearMfaAttempts(c.env, user.id, ip);

  const flow = await getLoginFlow(c.env, pending.flowId);
  if (!flow) return renderAuthMessage(c, 400, AUTH_MESSAGES.expired);

  await deletePendingMfa(c.env, mfaId);
  await deleteLoginFlow(c.env, pending.flowId);

  const { outcome, setCookie } = await completeLoginFlow(c.env, flow, user.id, amr, c.req.raw, user);
  c.header("Set-Cookie", setCookie, { append: true });

  if (rememberDevice) {
    const deviceCookie = await trustDevice(c.env, c.req.raw, user.id);
    c.header("Set-Cookie", deviceCookie, { append: true });
    await logAudit(c.env, user, "user.device_trusted", user.upn, undefined, c.req.raw);
  }

  await logAudit(c.env, user, "login.success", user.upn, { amr }, c.req.raw);
  if (outcome.type === "saml-post") {
    return c.html(samlPostForm(c.get("appName"), outcome.acsUrl, outcome.samlResponse, outcome.relayState));
  }
  return c.redirect(outcome.to, 302);
});

import type { Env } from "../env.js";
import type { GroupRow, LdapAppRow, UserRow } from "../lib/types.js";
import { getUserByLoginIdentifier } from "../lib/db.js";
import { resolveManyGroupMemberUserIds } from "../lib/groups.js";
import { clearLoginAttempts, loginRateKey, recordLoginAttempt, recordMfaAttempt, clearMfaAttempts, rateKeyOverLimit, rateLimitAddress, recordRateAttempt } from "../lib/rate-limit.js";
import { upgradePasswordHashIfNeeded, storedHashFormat, verifyPassword, hashPassword, type StoredPassword } from "../lib/password.js";
import { timed } from "../lib/metrics.js";
import { claimTotpCounter, matchTotpCounter } from "../lib/totp.js";
import { sha256Hex } from "../lib/tokens.js";
import { unsealMaybe } from "../lib/sealed.js";
import { mfaRequiredFor, isFactorEnabled } from "../lib/auth-policy.js";
import { isSetupCompleted } from "../lib/settings.js";
import { getLdapAppBySlug } from "./apps.js";
import { parseDn } from "./dn.js";
import type { LdapSettings } from "./settings.js";

/**
 * Bind resolution and verification (LDAP.md section 9). Mirrors POST /login:
 * the same account/IP lockout buckets, the same dummy-hash timing, and the
 * same invalidCredentials for every failure reason - the real reason goes to
 * the audit log, never to the client.
 */

/** AD's "bad credentials" text: clients that parse it expect data 52e; the other sub-codes leak account state. */
export const AD_BAD_CREDENTIALS = "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v4563";

export type BindName =
  | { kind: "service"; slug: string }
  | { kind: "user"; username: string; upnForm: boolean; appSlug: string | null }
  | { kind: "anonymous" }
  | { kind: "invalid" };

/**
 * Resolve a bind name: a DN in our tree, a UPN, a NetBIOS\user down-level
 * name, or a bare username, tried in that order (section 9).
 */
export function resolveBindName(name: string, settings: LdapSettings): BindName {
  if (!name) return { kind: "anonymous" };
  if (name.includes("=")) {
    let rdns;
    try {
      rdns = parseDn(name);
    } catch {
      return { kind: "invalid" };
    }
    const base = settings.base;
    if (base.length === 0 || rdns.length < base.length) return { kind: "invalid" };
    const tail = rdns.slice(0, rdns.length - base.length);
    const baseOk = rdns.slice(rdns.length - base.length).every((r, i) => r.type === base[i]!.type && r.value.toLowerCase() === base[i]!.value.toLowerCase());
    if (!baseOk) return { kind: "invalid" };
    // cn=<slug>,ou=services,<base> -> service bind
    if (tail.length === 2 && tail[0]!.type === "cn" && tail[1]!.type === "ou" && tail[1]!.value.toLowerCase() === "services") {
      return { kind: "service", slug: tail[0]!.value.toLowerCase() };
    }
    // uid=<username>,ou=people,ou=<slug>,<base> -> attributed user bind
    if (tail.length === 3 && tail[0]!.type === "uid" && tail[1]!.type === "ou" && tail[1]!.value.toLowerCase() === "people" && tail[2]!.type === "ou") {
      return { kind: "user", username: tail[0]!.value, upnForm: false, appSlug: tail[2]!.value.toLowerCase() };
    }
    return { kind: "invalid" };
  }
  if (name.includes("@")) return { kind: "user", username: name, upnForm: true, appSlug: null };
  const bs = name.indexOf("\\");
  if (bs >= 0) {
    if (name.slice(0, bs).toUpperCase() !== settings.netbios.toUpperCase()) return { kind: "invalid" };
    return { kind: "user", username: name.slice(bs + 1), upnForm: false, appSlug: null };
  }
  return { kind: "user", username: name, upnForm: false, appSlug: null };
}

export type BindOutcome =
  | { ok: true; bound: { kind: "service"; app: LdapAppRow } | { kind: "user"; user: UserRow; app: LdapAppRow | null } | { kind: "anonymous" }; app: LdapAppRow | null }
  | { ok: false; reason: string; disconnect?: boolean };

export interface BindCtx {
  env: Env;
  settings: LdapSettings;
  /** Sticky app context set by a service bind earlier on this connection (section 9). */
  app: LdapAppRow | null;
  ip: string;
  kv: KVNamespace | null;
}

export async function ldapBind(ctx: BindCtx, name: string, password: Uint8Array): Promise<BindOutcome> {
  const { env, settings, ip } = ctx;
  const resolved = resolveBindName(name, settings);
  const passwordStr = new TextDecoder().decode(password);

  // Anonymous bind: empty name AND empty password. A named empty-password
  // bind is the unauthenticated bind, always refused (RFC 4513 5.1.2) - many
  // apps treat a successful one as a login.
  if (resolved.kind === "anonymous") return password.length === 0 ? { ok: true, bound: { kind: "anonymous" }, app: ctx.app } : { ok: false, reason: "unauthenticated" };
  if (resolved.kind === "invalid") return { ok: false, reason: "bad_dn" };
  if (password.length === 0) return { ok: false, reason: "unauthenticated" };

  if (resolved.kind === "service") {
    // Failures only, and per (slug, source): a busy application must not be
    // able to burn its own bind budget with successful binds, and one hostile
    // source must not be able to lock the app out for everyone else. The
    // per-IP counter stays an all-attempts volumetric cap.
    const svcKey = `ldap:svc:${resolved.slug}:${rateLimitAddress(ip)}`;
    if ((await rateKeyOverLimit(env, svcKey, 20, 15)) || (await recordRateAttempt(env, `ldap:svcip:${ip}`, 60, 15))) {
      return { ok: false, reason: "svc_rate_limited" };
    }
    const app = await getLdapAppBySlug(env, resolved.slug);
    if (!app || app.revoked_at || (await sha256Hex(passwordStr)) !== app.secret_hash) {
      await recordRateAttempt(env, svcKey, 20, 15);
      return { ok: false, reason: app?.revoked_at ? "app_revoked" : "bad_password" };
    }
    return { ok: true, bound: { kind: "service", app }, app };
  }

  // User bind. Attribute the app: the DN carries it, else the connection's
  // sticky service context, else the configured unscoped-bind app.
  let app: LdapAppRow | null = ctx.app;
  if (resolved.appSlug) app = await getLdapAppBySlug(env, resolved.appSlug);
  else if (app) {
    // The sticky row is an in-memory snapshot last refreshed on a non-bind
    // op - re-read it so a revocation or policy edit since then applies to
    // this bind too ("binds fail immediately", api/ldap.ts).
    app = (await env.DB.prepare("SELECT * FROM ldap_apps WHERE id = ?").bind(app.id).first<LdapAppRow>()) ?? null;
  } else if (settings.unscopedBindApp) app = await getLdapAppBySlug(env, settings.unscopedBindApp);
  if (!app) return { ok: false, reason: resolved.appSlug ? "unknown_app" : "unattributed" };
  if (app.revoked_at) return { ok: false, reason: "app_revoked" };
  if (!(await isSetupCompleted(env))) return { ok: false, reason: "setup_incomplete" };

  const identifier = resolved.username;
  // Both DN shapes resolve through the identifier rules: uid=simon hits a
  // handle's exact upn or a unique local part (an ambiguous local part fails
  // like any bad credential), uid=simon@d1.com the UPN/alias paths.
  const user = await getUserByLoginIdentifier(env, identifier);

  // Shared lockout with web sign-in: LDAP must not double an attacker's budget.
  const rateKey = loginRateKey(identifier, user);
  if (await recordLoginAttempt(env, rateKey, ip)) return { ok: false, reason: "rate_limited" };

  const inGroups = user !== null && (await inAppGroups(env, user, app));
  const usable = user !== null && user.status === "active" && !user.password_hash.startsWith("!") && inGroups;

  // MFA split (section 13): <password>,<6 digits>, split on the LAST comma,
  // and only when the tail is exactly six digits.
  const comma = passwordStr.lastIndexOf(",");
  const otp = comma >= 0 && /^\d{6}$/.test(passwordStr.slice(comma + 1)) ? passwordStr.slice(comma + 1) : null;
  const pw = otp !== null ? passwordStr.slice(0, comma) : passwordStr;

  // Unknown or unusable users still pay a verification, against the dummy
  // hash - timing must not reveal which accounts exist. And like the web
  // sign-in (login.ts), the cost must not depend on the stored format: a
  // legacy PBKDF2 row verifies cheaper than scrypt, so every failure is
  // padded to one verification of each.
  const stored: StoredPassword = usable && user ? { password_hash: user.password_hash, password_salt: user.password_salt, password_iterations: user.password_iterations } : await dummyHash(env);
  // Only a usable account runs the real verify; the padding below then always
  // lands on exactly two verifications (one real + one dummy, or two dummies).
  const ok = usable && user ? await timed(env, "auth.verify", verifyPassword(pw, stored)) : false;

  if (!ok || !usable || !user) {
    const format = usable && user ? storedHashFormat(stored) : null;
    if (format !== "scrypt") await verifyPassword(pw, await dummyHash(env, "scrypt"));
    if (format !== "pbkdf2") await verifyPassword(pw, await dummyHash(env, "pbkdf2"));
    const reason = !user ? "unknown_user" : user.status !== "active" ? "disabled" : user.password_hash.startsWith("!") ? "no_usable_password" : !inGroups ? "not_in_app_groups" : "bad_password";
    return { ok: false, reason };
  }

  // Does this bind need an OTP? (section 13 table)
  const enrolled = Boolean(user.mfa_enabled) && (await isFactorEnabled(env, "totp"));
  const globalMfa = await mfaRequiredFor(env, user.id);
  const needOtp = enrolled ? app.mfa_mode !== "password" : app.mfa_mode === "otp_required" || (app.mfa_mode === "otp_if_enrolled" && globalMfa);

  if (needOtp) {
    // Every failure past this point has already paid for one real verify; it
    // must pay the same padding the bad-password path above runs, or wall
    // time confirms "password correct, OTP missing/wrong" (LDAP.md section
    // 14 req 3).
    const mfaFail = async (reason: string): Promise<BindOutcome> => {
      const format = storedHashFormat(stored);
      if (format !== "scrypt") await verifyPassword(pw, await dummyHash(env, "scrypt"));
      if (format !== "pbkdf2") await verifyPassword(pw, await dummyHash(env, "pbkdf2"));
      return { ok: false, reason };
    };
    if (!enrolled) return mfaFail("mfa_enrollment_required");
    if (otp === null) {
      // An OTP is required and the field has no ,NNNNNN shape: never fall
      // back to treating the whole field as the password.
      return mfaFail("otp_missing");
    }
    if (!(await rebindOk(ctx, app, user, passwordStr))) {
      if (await recordMfaAttempt(env, user.id, ip)) return mfaFail("otp_rate_limited");
      const counter = await matchTotpCounter((await unsealMaybe(env, user.totp_secret)) ?? "", otp);
      if (counter === null || !(await claimTotpCounter(env, user.id, counter))) return mfaFail("otp_invalid");
      await clearMfaAttempts(env, user.id, ip);
      await rememberRebind(ctx, app, user, passwordStr);
    }
  }

  await clearLoginAttempts(env, rateKey, ip);
  await upgradePasswordHashIfNeeded(env, { id: user.id, password_hash: user.password_hash, password_salt: user.password_salt, password_iterations: user.password_iterations }, pw);
  return { ok: true, bound: { kind: "user", user, app }, app };
}

export async function inAppGroups(env: Env, user: UserRow, app: LdapAppRow): Promise<boolean> {
  let ids: number[];
  try {
    ids = JSON.parse(app.user_group_ids || "[]");
  } catch {
    return false;
  }
  if (!ids.length) return true;
  const rows = (await env.DB.prepare(`SELECT * FROM groups WHERE id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all<GroupRow>()).results as unknown as GroupRow[];
  if (!rows.length) return false;
  const map = await resolveManyGroupMemberUserIds(env, rows);
  for (const members of map.values()) if (members.includes(user.id)) return true;
  return false;
}

/** The dummy verify target (same idea as login.ts's dummyPasswordHash, kept local so both share the pattern). */
const dummyHashes = new Map<string, Promise<StoredPassword>>();
async function dummyHash(env: Env, hasher?: "scrypt" | "pbkdf2"): Promise<StoredPassword> {
  const key = hasher ?? env.PASSWORD_HASHER ?? "scrypt";
  if (!dummyHashes.has(key)) {
    dummyHashes.set(key, hashPassword(crypto.randomUUID(), { PASSWORD_HASHER: key }).then((h) => ({ password_hash: h.hash, password_salt: h.salt, password_iterations: h.iterations })));
  }
  return dummyHashes.get(key)!;
}

/** The OTP re-bind window (section 13): the exact credential field, app-scoped. */
const rebindKey = (app: LdapAppRow, user: UserRow, credentialField: string) => sha256Hex(`ldap:rebind:${app.id}:${user.id}:${credentialField}`);

async function rebindOk(ctx: BindCtx, app: LdapAppRow, user: UserRow, credentialField: string): Promise<boolean> {
  if (!ctx.kv) return false;
  return (await ctx.kv.get(await rebindKey(app, user, credentialField))) !== null;
}
async function rememberRebind(ctx: BindCtx, app: LdapAppRow, user: UserRow, credentialField: string): Promise<void> {
  if (!ctx.kv) return;
  await ctx.kv.put(await rebindKey(app, user, credentialField), "1", { expirationTtl: ctx.settings.otpRebindSeconds });
}

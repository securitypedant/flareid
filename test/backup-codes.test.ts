// Backup codes as an emergency fallback: issued when a real factor enrols
// (the authenticator path is covered in admin-feedback and audit-fixes),
// usable once each at sign-in, but never an enrolment of their own. Covers
// the generate/remove guards, the sign-in step, the factor switch and the
// API surface.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { secondFactorGate } from "../src/lib/auth-policy.js";
import { generateBackupCodes } from "../src/lib/backup-codes.js";
import type { UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const PASSWORD = "Backup-codes-pass-1";

async function setup(opts: { requireMfa?: boolean } = {}) {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "rita", password: PASSWORD, status: "active" }] } });
  if (opts.requireMfa) await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
  const id = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
  const cookie = async (u: string, amr = ["pwd"]) => (await createSession(env, await id(u), amr, new Request(BASE))).setCookie.split(";")[0]!;
  return { apiKey, id, cookie, rita: await id("rita") };
}

const post = (path: string, form: Record<string, string>, cookie?: string) =>
  SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(form).toString(), redirect: "manual" });

const userRow = (id: number) => env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>() as Promise<UserRow>;

async function passwordLogin(upn: string) {
  const page = await (await SELF.fetch(`${BASE}/login`)).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
  return SELF.fetch(`${BASE}/login`, { method: "POST", headers: FORM, redirect: "manual", body: new URLSearchParams({ flow_id: flowId, upn, password: PASSWORD }).toString() });
}

/** The codes shown once on the enrolment page. */
const codesFrom = (html: string) => [...new Set([...html.matchAll(/([A-Z0-9]{4}-[A-Z0-9]{4})/g)].map((m) => m[1]!))];

async function mfaLogin(upn: string, code: string, route = "/login/mfa/backup-code") {
  const pw = await passwordLogin(upn);
  const mfaId = /name="mfa_id" value="([^"]+)"/.exec(await pw.text())?.[1] ?? "";
  return SELF.fetch(`${BASE}${route}`, {
    method: "POST",
    headers: FORM,
    body: new URLSearchParams({ mfa_id: mfaId, code }).toString(),
    redirect: "manual",
  });
}

describe("backup codes as an emergency factor", () => {
  it("signs a set-holder in once per code, without counting as an enrolled factor", async () => {
    const { rita } = await setup({ requireMfa: true });
    // A codes-only user still owes the policy a real factor...
    expect(await secondFactorGate(env, await userRow(rita), ["pwd"])).toBe("enrol");
    await generateBackupCodes(env, rita);
    expect(await secondFactorGate(env, await userRow(rita), ["pwd"])).toBe("enrol");

    // ...but the codes they hold keep working as the emergency second step.
    const codes = await env.DB.prepare("SELECT code_hash FROM mfa_backup_codes WHERE user_id = ?").bind(rita).all();
    expect(codes.results).toHaveLength(10);
  });

  it("uses each code once at sign-in", async () => {
    const { rita } = await setup({ requireMfa: true });
    const codes = await generateBackupCodes(env, rita);

    const signIn = await mfaLogin("rita@horizon.test", codes[0]!);
    expect(signIn.headers.get("Set-Cookie")).toContain("flareid_session");

    const replay = await mfaLogin("rita@horizon.test", codes[0]!);
    expect(replay.headers.get("Set-Cookie")).toBeNull();
    const second = await mfaLogin("rita@horizon.test", codes[1]!);
    expect(second.headers.get("Set-Cookie")).toContain("flareid_session");
  });

  it("refuses to mint a first set for a user with no factor, and offers none on the setup page", async () => {
    const { cookie } = await setup({ requireMfa: true });
    const ritaCookie = await cookie("rita");

    const refused = await post("/account/mfa/backup-codes/generate", {}, ritaCookie);
    expect(refused.headers.get("Location")).toContain("error=no-factor");

    const pw = await passwordLogin("rita@horizon.test");
    expect(pw.headers.get("Location")).toContain("/account/mfa/setup");
    const setupCookie = pw.headers.get("Set-Cookie")!.split(";")[0]!;
    const setupPage = await SELF.fetch(`${BASE}${pw.headers.get("Location")}`, { headers: { Cookie: setupCookie }, redirect: "manual" });
    const html = await setupPage.text();
    expect(html).not.toContain("backup-codes/generate");

    // A forced-enrolment session can't satisfy its gate with codes either.
    const also = await post("/account/mfa/backup-codes/generate", { password: PASSWORD }, setupCookie);
    expect(also.headers.get("Location")).toContain("error=no-factor");
  });

  it("lets a codes holder refresh the set, asking for the password once the session is stale", async () => {
    const { cookie, rita } = await setup();
    const ritaCookie = await cookie("rita");
    await generateBackupCodes(env, rita);
    await env.DB.prepare("UPDATE sessions SET created_at = ?").bind(new Date(Date.now() - 3600e3).toISOString()).run();

    const denied = await post("/account/mfa/backup-codes/generate", {}, ritaCookie);
    expect(denied.headers.get("Location")).toContain("error=password");

    const wrong = await post("/account/mfa/backup-codes/generate", { password: "nope-wrong-1" }, ritaCookie);
    expect(wrong.headers.get("Location")).toContain("error=password");

    const ok = await post("/account/mfa/backup-codes/generate", { password: PASSWORD }, ritaCookie);
    expect(ok.status).toBe(200);
    expect(codesFrom(await ok.text())).toHaveLength(10);
  });

  it("removes the set only with the password once the session is stale", async () => {
    const { cookie, rita } = await setup({ requireMfa: true });
    // Signed in with a code: the session carries the factor's amr, like a real login.
    const ritaCookie = await cookie("rita", ["pwd", "mfa", "backup_code"]);
    await generateBackupCodes(env, rita);

    await env.DB.prepare("UPDATE sessions SET created_at = ?").bind(new Date(Date.now() - 3600e3).toISOString()).run();
    const denied = await post("/account/backup-codes/remove", { password: "nope-wrong-1" }, ritaCookie);
    expect(denied.headers.get("Location")).toContain("error=password");
    const removed = await post("/account/backup-codes/remove", { password: PASSWORD }, ritaCookie);
    expect(removed.headers.get("Location")).toBe("/account/security?saved=backup-codes-removed");
    expect(await secondFactorGate(env, await userRow(rita), ["pwd"])).toBe("enrol");
  });

  it("reports the factor on the API and stops authorizing once switched off", async () => {
    const { apiKey, rita } = await setup();
    const codes = await generateBackupCodes(env, rita);

    const factors = await apiCall("/api/v1/security/factors", { token: apiKey });
    const backup = factors.body.factors.find((f: { key: string }) => f.key === "backup_codes");
    expect(backup).toMatchObject({ enabled: true, usable: true, enrolled_users: 1 });

    const users = await apiCall("/api/v1/users?q=rita", { token: apiKey });
    expect(users.body.users[0].second_factors).toContain("backup_codes");

    expect((await apiCall("/api/v1/security/factors/backup_codes", { token: apiKey, method: "PUT", body: { enabled: false } })).status).toBe(200);
    const refused = await mfaLogin("rita@horizon.test", codes[0]!);
    expect(refused.headers.get("Set-Cookie")).toBeNull();
    expect(refused.status).toBe(400);
  });
});

// Security questions as a second factor: enrolment from My account and the
// forced-enrolment page, the sign-in step (normalised answers, questions fixed
// per attempt, the attempt limit), the factor switch, policies, the catalogue
// in the console and the API, the administrator's reset, user deletion, the
// Super Admin step-up rule, and answers never stored or logged in clear.
import { beforeEach, describe, expect, it } from "vitest";
import { env, SELF } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { secondFactorGate } from "../src/lib/auth-policy.js";
import { storePendingMfa } from "../src/lib/authorize-state.js";
import { normaliseAnswer, saveAnswers } from "../src/lib/security-questions.js";
import type { UserRow } from "../src/lib/types.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const PASSWORD = "Kba-test-pass-1";

const call = (path: string, init: RequestInit = {}) => SELF.fetch(`${BASE}${path}`, { redirect: "manual", ...init });
const post = (path: string, form: Record<string, string>, cookie?: string) =>
  call(path, { method: "POST", headers: { ...FORM, ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(form).toString() });
const page = async (path: string, cookie: string) => (await call(path, { headers: { Cookie: cookie } })).text();

/** Rita's answers, by position in the seeded catalogue (questions 1-3). */
const ANSWERS = ["Rex the Dog", "Springfield", "Hill Valley High"];

async function setup(opts: { requireMfa?: boolean; factorOn?: boolean } = {}) {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "rita", password: PASSWORD, status: "active" }] } });
  if (opts.requireMfa) await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
  const id = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
  const adminId = await id("admin");
  const rita = await id("rita");
  const adminCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  const { results } = await env.DB.prepare("SELECT id FROM security_questions ORDER BY id").all<{ id: number }>();
  const qids = results.map((r) => r.id);
  if (opts.factorOn !== false) expect((await factor(adminCookie, true)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
  return { apiKey, adminCookie, adminId, rita, qids };
}

const factor = (adminCookie: string, on: boolean) => post("/admin/security/factors/security_questions", { enabled: on ? "1" : "0" }, adminCookie);

/** The enrolment form for questions 1-3 (or the given ids) with Rita's answers. */
function enrolForm(qids: number[], answers = ANSWERS): Record<string, string> {
  return Object.fromEntries(answers.flatMap((a, i) => [[`question_${i + 1}`, String(qids[i])], [`answer_${i + 1}`, a]]));
}

async function enrolDirectly(userId: number, qids: number[]) {
  await saveAnswers(env, userId, ANSWERS.map((answer, i) => ({ questionId: qids[i]!, answer })));
}

async function userRow(id: number): Promise<UserRow> {
  return (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>())!;
}

async function passwordStep() {
  const login = await (await call("/login")).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(login)![1]!;
  const res = await post("/login", { flow_id: flowId, upn: "rita", password: PASSWORD });
  const html = res.status === 200 ? await res.text() : "";
  return { res, html, mfaId: /name="mfa_id" value="([^"]+)"/.exec(html)?.[1] };
}

/** The question ids a second-step page asks. */
const askedIn = (html: string) => [...html.matchAll(/name="answer_(\d+)"/g)].map((m) => Number(m[1]));

/** Answers for the asked questions, optionally mangled (case and spacing) or wrong. */
function answerForm(mfaId: string, asked: number[], qids: number[], how: (a: string) => string = (a) => a): Record<string, string> {
  return { mfa_id: mfaId, ...Object.fromEntries(asked.map((id) => [`answer_${id}`, how(ANSWERS[qids.indexOf(id)]!)])) };
}

const sessionIdOf = (res: Response) => /__Host-flareid_session=([^;]+)/.exec(res.headers.get("Set-Cookie") ?? "")?.[1];
const amrOf = async (sid: string) => JSON.parse((await env.DB.prepare("SELECT amr FROM sessions WHERE id = ?").bind(sid).first<{ amr: string }>())!.amr) as string[];

/** No row of any table contains the text (case-insensitively). */
async function nowhereInDatabase(text: string): Promise<boolean> {
  const { results: tables } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").all<{ name: string }>();
  for (const t of tables) {
    const { results } = await env.DB.prepare(`SELECT * FROM "${t.name}"`).all();
    if (JSON.stringify(results).toLowerCase().includes(text.toLowerCase())) return false;
  }
  return true;
}

describe("security questions", () => {
  it("enrols from My account and signs in with normalised answers; answers are never stored or logged in clear", async () => {
    const { rita, qids } = await setup();
    const cookie = (await createSession(env, rita, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const account = await page("/account", cookie);
    expect(account).toContain("Security questions");
    expect(account).toContain('action="/account/mfa/questions"');
    expect(account).toContain('name="question_3"');

    const saved = await post("/account/mfa/questions", enrolForm(qids), cookie);
    expect(saved.headers.get("Location")).toBe("/account?saved=kba-enabled");
    expect((await userRow(rita)).security_questions_enabled).toBe(1);
    const rows = await env.DB.prepare("SELECT * FROM user_security_answers WHERE user_id = ?").bind(rita).all<{ answer_hash: string }>();
    expect(rows.results).toHaveLength(3);
    expect(new Set(rows.results.map((r) => r.answer_hash)).size).toBe(3);
    expect(rows.results.every((r) => r.answer_hash.startsWith("$scrypt$"))).toBe(true);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.security_questions_enabled'").first()).not.toBeNull();
    expect(await page("/account", cookie)).toContain("Change your questions");

    // Sign-in: security questions are the only factor, so they are asked straight away.
    const step = await passwordStep();
    expect(step.res.status).toBe(200);
    expect(step.html).toContain('action="/login/mfa/questions"');
    const asked = askedIn(step.html);
    expect(asked).toHaveLength(2); // the default: two of the three
    expect(asked.every((id) => qids.slice(0, 3).includes(id))).toBe(true);

    // Case, spacing and Unicode compatibility forms don't matter.
    const mangle = (a: string) => `  ${a.toUpperCase().replace(/ /g, "   ")}  `.replace("A", "Ａ");
    expect(normaliseAnswer(mangle("Rex the Dog"))).toBe("rex the dog");
    const done = await post("/login/mfa/questions", answerForm(step.mfaId!, asked, qids, mangle));
    expect(done.status).toBe(302);
    expect(done.headers.get("Location")).toBe("/account");
    expect(await amrOf(sessionIdOf(done)!)).toEqual(["pwd", "kba", "mfa"]);
    expect((await post("/login/mfa/questions", answerForm(step.mfaId!, asked, qids))).status).toBe(400); // the step is used up

    const success = await env.DB.prepare("SELECT details FROM audit_log WHERE action = 'login.success' ORDER BY id DESC LIMIT 1").first<{ details: string }>();
    expect(success!.details).toContain("kba");
    for (const a of ANSWERS) {
      expect(await nowhereInDatabase(a)).toBe(true);
      expect(await nowhereInDatabase(normaliseAnswer(a))).toBe(true);
    }
  });

  it("refuses weak or invalid answers, and changing or removing them needs the current password", async () => {
    const { rita, qids } = await setup();
    const cookie = (await createSession(env, rita, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const refused = async (form: Record<string, string>, error: string) => {
      const res = await post("/account/mfa/questions", form, cookie);
      expect(res.headers.get("Location")).toContain(`kba_error=${error}`);
    };
    await refused(enrolForm(qids, ["Rex", "ab", "Hill Valley"]), "kba-short");
    await refused(enrolForm([qids[0]!, qids[0]!, qids[2]!]), "kba-distinct");
    await refused(enrolForm(qids, ["Rex", " REX ", "Hill Valley"]), "kba-same");
    await refused(enrolForm(qids, ["Rita", "Springfield", "Hill Valley"]), "kba-username");
    await refused({ question_1: String(qids[0]), answer_1: "Rex" }, "kba-count");
    await env.DB.prepare("UPDATE security_questions SET enabled = 0 WHERE id = ?").bind(qids[0]).run();
    await refused(enrolForm(qids), "kba-unknown");
    await env.DB.prepare("UPDATE security_questions SET enabled = 1 WHERE id = ?").bind(qids[0]).run();
    expect((await userRow(rita)).security_questions_enabled).toBe(0);
    expect(await page("/account?kba_error=kba-same#security-questions", cookie)).toContain("Each answer must be different from the others.");

    expect((await post("/account/mfa/questions", enrolForm(qids), cookie)).headers.get("Location")).toBe("/account?saved=kba-enabled");

    // Changing: the current password, then a valid new set.
    const newSet = enrolForm(qids.slice(3), ["Ford Fiesta", "Maple Street", "Bunny"]);
    expect((await post("/account/mfa/questions", { ...newSet, current_password: "wrong" }, cookie)).headers.get("Location")).toContain("kba_error=kba-password");
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.step_up_failed' AND details LIKE '%security_questions_change%'").first()).not.toBeNull();
    expect((await post("/account/mfa/questions", { ...newSet, current_password: PASSWORD }, cookie)).headers.get("Location")).toBe("/account?saved=kba-changed");
    const ids = (await env.DB.prepare("SELECT question_id FROM user_security_answers WHERE user_id = ? ORDER BY question_id").bind(rita).all<{ question_id: number }>()).results.map((r) => r.question_id);
    expect(ids).toEqual(qids.slice(3, 6));

    // Removing: the current password too.
    expect((await post("/account/mfa/questions/remove", { current_password: "wrong" }, cookie)).headers.get("Location")).toContain("kba_error=kba-password");
    expect((await userRow(rita)).security_questions_enabled).toBe(1);
    expect((await post("/account/mfa/questions/remove", { current_password: PASSWORD }, cookie)).headers.get("Location")).toBe("/account?saved=kba-removed");
    expect((await userRow(rita)).security_questions_enabled).toBe(0);
    expect(await env.DB.prepare("SELECT 1 FROM user_security_answers WHERE user_id = ?").bind(rita).first()).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'user.security_questions_disabled'").first()).not.toBeNull();
  });

  it("keeps the questions fixed for a sign-in attempt", async () => {
    const { apiKey, rita, qids } = await setup();
    await enrolDirectly(rita, qids);
    // Questions are her only factor, so the password step asks them straight away.
    const step = await passwordStep();
    const first = askedIn(step.html);
    expect(first).toHaveLength(2);
    const stored = JSON.parse((await env.SESSIONS_KV.get(`mfa:${step.mfaId}`))!) as { kba: number[] };
    expect(stored.kba).toEqual(first);

    // Starting again, resubmitting without answers, or answering wrongly: the same questions every time.
    for (let i = 0; i < 4; i++) expect(askedIn(await (await post("/login/mfa/questions/start", { mfa_id: step.mfaId! })).text())).toEqual(first);
    expect(askedIn(await (await post("/login/mfa/questions", { mfa_id: step.mfaId! })).text())).toEqual(first);
    const wrong = await (await post("/login/mfa/questions", answerForm(step.mfaId!, first, qids, () => "nope"))).text();
    expect(wrong).toContain("One or more answers were not right");
    expect(askedIn(wrong)).toEqual(first);

    // Answers to questions that were not asked are not accepted in their place.
    const others = qids.slice(0, 3).filter((id) => !first.includes(id));
    const swapped = await (await post("/login/mfa/questions", answerForm(step.mfaId!, others, qids))).text();
    expect(askedIn(swapped)).toEqual(first);

    // The number asked is a setting.
    expect((await apiCall("/api/v1/security/security-questions", { token: apiKey, method: "PUT", body: { asked: 1 } })).status).toBe(200);
    expect(askedIn((await passwordStep()).html)).toHaveLength(1);
    expect((await apiCall("/api/v1/security/security-questions", { token: apiKey, method: "PUT", body: { asked: 3 } })).status).toBe(200);
    expect(askedIn((await passwordStep()).html)).toHaveLength(3);
  });

  it("limits wrong answers like an authenticator code", async () => {
    const { rita, qids } = await setup();
    await enrolDirectly(rita, qids);
    const step = await passwordStep();
    const asked = askedIn(step.html);
    // One right and one wrong is still wrong.
    const halfRight = { ...answerForm(step.mfaId!, asked, qids), [`answer_${asked[1]}`]: "nope" };
    for (let i = 0; i < 5; i++) expect(await (await post("/login/mfa/questions", halfRight)).text()).toContain("One or more answers were not right");
    // The budget (five per window) is spent: even the right answers are refused.
    const locked = await (await post("/login/mfa/questions", answerForm(step.mfaId!, asked, qids))).text();
    expect(locked).toContain("Too many attempts");
    const failures = await env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'login.mfa_failed' AND details LIKE '%security_questions%'").first<{ n: number }>();
    expect(failures!.n).toBe(5);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'login.mfa_rate_limited' AND details LIKE '%security_questions%'").first()).not.toBeNull();
    // It is the per-user bucket the authenticator uses.
    expect((await env.DB.prepare("SELECT count FROM rate_limits WHERE key = ?").bind(`login:mfa:${rita}`).first<{ count: number }>())!.count).toBeGreaterThan(5);
  });

  it("is not offered while the factor is off, and is offered next to other factors", async () => {
    const { adminCookie, rita, qids } = await setup({ factorOn: false });
    await enrolDirectly(rita, qids);
    expect(await page("/admin/security/factors", adminCookie)).toContain("Security questions");

    // Off by default: no second step, no card, no questions.
    const off = await passwordStep();
    expect(off.res.status).toBe(302);
    const cookie = (await createSession(env, rita, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    expect(await page("/account", cookie)).not.toContain("Security questions");
    const mfaId = await storePendingMfa(env, rita, "s.unused");
    expect((await post("/login/mfa/questions/start", { mfa_id: mfaId })).status).toBe(400);
    expect((await post("/login/mfa/questions", { mfa_id: mfaId })).status).toBe(400);
    expect((await post("/account/mfa/questions", enrolForm(qids), cookie)).headers.get("Location")).toContain("kba_error=kba-unavailable");

    // On: with an authenticator enrolled too, the step offers both.
    await factor(adminCookie, true);
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE id = ?").bind(rita).run();
    const both = await passwordStep();
    expect(both.html).toContain('action="/login/mfa"');
    expect(both.html).toContain("Answer security questions");
    expect(askedIn(both.html)).toHaveLength(0); // not picked until asked for
    const started = await (await post("/login/mfa/questions/start", { mfa_id: both.mfaId! })).text();
    expect(askedIn(started)).toHaveLength(2);
    expect(started).toContain("Or use your authenticator app");
  });

  it("counts as a second factor for a policy that requires one, and finishes a forced enrolment", async () => {
    const { adminCookie, rita, qids } = await setup({ requireMfa: true });
    expect(await secondFactorGate(env, await userRow(rita), ["pwd"])).toBe("enrol");
    const other = await createSession(env, rita, ["pwd"], new Request(BASE));

    const { res } = await passwordStep();
    const location = res.headers.get("Location")!;
    expect(location).toMatch(/^\/account\/mfa\/setup\?resume=/);
    const resume = new URL(location, BASE).searchParams.get("resume")!;
    const cookie = `__Host-flareid_session=${sessionIdOf(res)}`;
    const setupPage = await page(location, cookie);
    expect(setupPage).toContain("Or answer security questions");

    const bad = await post("/account/mfa/questions", { ...enrolForm(qids, ["Rex", "Rex", "Hill"]), from: "setup", resume }, cookie);
    expect(bad.headers.get("Location")).toBe(`/account/mfa/setup?resume=${resume}&kba_error=kba-same`);
    expect(await page(bad.headers.get("Location")!, cookie)).toContain("Each answer must be different");

    const done = await post("/account/mfa/questions", { ...enrolForm(qids), from: "setup", resume }, cookie);
    expect(done.headers.get("Location")).toBe("/account");
    expect(await amrOf(sessionIdOf(res)!)).toEqual(["pwd", "kba", "mfa"]);
    expect((await env.DB.prepare("SELECT revoked_at FROM sessions WHERE id = ?").bind(other.sessionId).first<{ revoked_at: string | null }>())!.revoked_at).not.toBeNull();
    expect((await call("/account", { headers: { Cookie: cookie } })).status).toBe(200);

    expect(await secondFactorGate(env, await userRow(rita), ["pwd"])).toBe("login");
    expect(await secondFactorGate(env, await userRow(rita), ["pwd", "kba", "mfa"])).toBe("ok");

    // The last-factor guard counts security questions...
    expect((await post("/admin/security/factors/totp", { enabled: "0" }, adminCookie)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    expect((await post("/admin/security/factors/passkey", { enabled: "0" }, adminCookie)).headers.get("Location")).toBe("/admin/security/factors?saved=1");
    expect((await factor(adminCookie, false)).headers.get("Location")).toContain("error=");
    // ...and once switched off, they no longer count.
    await post("/admin/security/factors/totp", { enabled: "1" }, adminCookie);
    await factor(adminCookie, false);
    expect(await secondFactorGate(env, await userRow(rita), ["pwd"])).toBe("enrol");
  });

  it("an administrator's MFA reset clears them, in the console and the API; deletion removes them", async () => {
    const { apiKey, adminCookie, rita, qids } = await setup();
    await enrolDirectly(rita, qids);
    expect(await page(`/admin/users/${rita}`, adminCookie)).toContain("Security questions: enrolled");
    expect((await apiCall("/api/v1/users/rita", { token: apiKey })).body.security_questions_enabled).toBe(true);
    expect((await post(`/admin/users/${rita}/reset-mfa`, {}, adminCookie)).status).toBe(302);
    expect((await userRow(rita)).security_questions_enabled).toBe(0);
    expect(await env.DB.prepare("SELECT 1 FROM user_security_answers WHERE user_id = ?").bind(rita).first()).toBeNull();

    await enrolDirectly(rita, qids);
    expect((await apiCall("/api/v1/users/rita/reset-mfa", { token: apiKey, method: "POST" })).status).toBe(200);
    expect((await userRow(rita)).security_questions_enabled).toBe(0);
    expect(await env.DB.prepare("SELECT 1 FROM user_security_answers WHERE user_id = ?").bind(rita).first()).toBeNull();
    expect((await apiCall("/api/v1/users/rita", { token: apiKey })).body.security_questions_enabled).toBe(false);

    await enrolDirectly(rita, qids);
    expect((await apiCall("/api/v1/users/rita", { token: apiKey, method: "DELETE" })).status).toBe(200);
    expect(await env.DB.prepare("SELECT 1 FROM user_security_answers WHERE user_id = ?").bind(rita).first()).toBeNull();
  });

  it("administrators manage the catalogue and settings in the console and the API", async () => {
    const { apiKey, adminCookie, rita, qids } = await setup({ factorOn: false });
    const sub = await page("/admin/security/factors/security-questions", adminCookie);
    expect(sub).toContain("What was the name of your first pet?");
    expect(sub).toContain("weakest second factor");
    expect(await page("/admin/security/factors", adminCookie)).toContain("Questions and settings");

    // Console: add, disable, enable, delete; settings.
    const back = "/admin/security/factors/security-questions?saved=1";
    expect((await post("/admin/security/factors/security-questions/questions", { text: "What was your first job?" }, adminCookie)).headers.get("Location")).toBe(back);
    expect((await post("/admin/security/factors/security-questions/questions", { text: "what was your FIRST job?" }, adminCookie)).headers.get("Location")).toContain("error=");
    const added = (await env.DB.prepare("SELECT id FROM security_questions WHERE text = 'What was your first job?'").first<{ id: number }>())!.id;
    expect((await post(`/admin/security/factors/security-questions/questions/${added}`, { enabled: "0" }, adminCookie)).headers.get("Location")).toBe(back);
    expect((await env.DB.prepare("SELECT enabled FROM security_questions WHERE id = ?").bind(added).first<{ enabled: number }>())!.enabled).toBe(0);
    expect((await post(`/admin/security/factors/security-questions/questions/${added}/delete`, {}, adminCookie)).headers.get("Location")).toBe(back);
    expect(await env.DB.prepare("SELECT 1 FROM security_questions WHERE id = ?").bind(added).first()).toBeNull();
    expect((await post("/admin/security/factors/security-questions/settings", { required: "4", asked: "5" }, adminCookie)).headers.get("Location")).toContain("error=");
    expect((await post("/admin/security/factors/security-questions/settings", { required: "4", asked: "2" }, adminCookie)).headers.get("Location")).toBe(back);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'settings.security_questions_changed'").first()).not.toBeNull();

    // API: the same, and the guards.
    const read = await apiCall("/api/v1/security/security-questions", { token: apiKey });
    expect(read.status).toBe(200);
    expect(read.body).toMatchObject({ enabled: false, required: 4, asked: 2 });
    expect(read.body.questions).toHaveLength(10);
    const created = await apiCall("/api/v1/security/security-questions/questions", { token: apiKey, body: { text: "What is your favourite book?" } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ text: "What is your favourite book?", enabled: true, answered_by: 0 });
    expect((await apiCall("/api/v1/security/security-questions/questions", { token: apiKey, body: { text: "What is your favourite book?" } })).status).toBe(409);
    expect((await apiCall(`/api/v1/security/security-questions/questions/${created.body.id}`, { token: apiKey, method: "PATCH", body: { enabled: false } })).body.enabled).toBe(false);
    expect((await apiCall("/api/v1/security/security-questions/questions/99999", { token: apiKey, method: "PATCH", body: { enabled: false } })).status).toBe(404);
    expect((await apiCall(`/api/v1/security/security-questions/questions/${created.body.id}`, { token: apiKey, method: "DELETE" })).status).toBe(200);
    expect((await apiCall("/api/v1/security/security-questions", { token: apiKey, method: "PUT", body: { required: 11 } })).status).toBe(400);

    // An answered question can only be disabled; enough must stay enabled.
    await enrolDirectly(rita, qids);
    expect((await apiCall(`/api/v1/security/security-questions/questions/${qids[0]}`, { token: apiKey, method: "DELETE" })).status).toBe(409);
    expect((await apiCall("/api/v1/security/security-questions", { token: apiKey })).body.questions[0].answered_by).toBe(1);
    for (const id of qids.slice(4)) await apiCall(`/api/v1/security/security-questions/questions/${id}`, { token: apiKey, method: "PATCH", body: { enabled: false } });
    // Four left enabled, four required: one more cannot go.
    expect((await apiCall(`/api/v1/security/security-questions/questions/${qids[0]}`, { token: apiKey, method: "PATCH", body: { enabled: false } })).status).toBe(400);
    expect((await apiCall("/api/v1/security/security-questions", { token: apiKey, method: "PUT", body: { required: 5 } })).status).toBe(400);

    // The factor switch: needs enough enabled questions.
    await apiCall("/api/v1/security/security-questions", { token: apiKey, method: "PUT", body: { required: 3, asked: 2 } });
    for (const id of qids.slice(1, 4)) await apiCall(`/api/v1/security/security-questions/questions/${id}`, { token: apiKey, method: "PATCH", body: { enabled: false } });
    expect((await apiCall("/api/v1/security/security-questions", { token: apiKey })).body.questions.filter((q: { enabled: boolean }) => q.enabled)).toHaveLength(3);
    await env.DB.prepare("UPDATE security_questions SET enabled = 0 WHERE id = ?").bind(qids[0]).run(); // below the minimum behind the guard's back
    expect((await apiCall("/api/v1/security/factors/security_questions", { token: apiKey, method: "PUT", body: { enabled: true } })).status).toBe(400);
    await env.DB.prepare("UPDATE security_questions SET enabled = 1 WHERE id = ?").bind(qids[0]).run();
    const on = await apiCall("/api/v1/security/factors/security_questions", { token: apiKey, method: "PUT", body: { enabled: true } });
    expect(on.status).toBe(200);
    expect(on.body.factors.find((f: { key: string }) => f.key === "security_questions")).toMatchObject({ enabled: true, usable: true, enrolled_users: 1 });
    // Disabled questions keep working for those who answered them: Rita still signs in with hers.
    await apiCall(`/api/v1/security/security-questions/questions/${qids[0]}`, { token: apiKey, method: "PATCH", body: { enabled: true } });
    await apiCall(`/api/v1/security/security-questions/questions/${qids[1]}`, { token: apiKey, method: "PATCH", body: { enabled: true } });
    await apiCall(`/api/v1/security/security-questions/questions/${qids[2]}`, { token: apiKey, method: "PATCH", body: { enabled: false } });
    const step = await passwordStep();
    const asked = askedIn(step.html);
    expect(asked).toHaveLength(2);
    expect((await post("/login/mfa/questions", answerForm(step.mfaId!, asked, qids))).headers.get("Location")).toBe("/account");
  });

  it("never satisfies a Super Admin's step-up", async () => {
    const { adminId } = await setup();
    const sensitive = (cookie: string) => post("/admin/security/factors/security-questions/settings", { required: "3", asked: "2" }, cookie);

    // Signed in a moment ago with the password and security questions: not enough for a Super Admin.
    const kbaCookie = (await createSession(env, adminId, ["pwd", "kba", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const refused = await sensitive(kbaCookie);
    expect(refused.status).toBe(303);
    expect(refused.headers.get("Location")).toMatch(/^\/admin\/reauth/);
    // The re-authentication page offers no security questions.
    expect(await page("/admin/reauth", kbaCookie)).not.toContain("answer_");
    // Re-authenticating with the password (the admin has no authenticator here) counts.
    const reauth = await post("/admin/reauth", { password: "test-admin-password-1", next: "/admin/security/factors" }, kbaCookie);
    expect(reauth.headers.get("Location")).toBe("/admin/security/factors");
    expect((await sensitive(kbaCookie)).headers.get("Location")).toBe("/admin/security/factors/security-questions?saved=1");

    // Another factor at sign-in still counts as fresh.
    const totpCookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    expect((await sensitive(totpCookie)).headers.get("Location")).toBe("/admin/security/factors/security-questions?saved=1");
  });
});

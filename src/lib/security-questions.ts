import type { Env } from "../env.js";
import { isFactorUsable } from "./auth-policy.js";
import { setPendingMfaQuestions, type PendingMfa } from "./authorize-state.js";
import { hashPassword, verifyPassword } from "./password.js";
import { getSetting, setSetting } from "./settings.js";

/**
 * Security questions: a knowledge-based second factor (amr "kba").
 *
 * Administrators keep a catalogue of questions (migration 0025 seeds ten);
 * a person picks `required` different ones and answers each. Answers are
 * normalised - Unicode NFKC, trimmed, runs of whitespace collapsed, lower-cased
 * - so "  Rex " and "rex" match, then hashed with the password KDF
 * (password.ts: scrypt, or PBKDF2 on PASSWORD_HASHER=pbkdf2) and a salt of
 * their own. The clear answer is never stored, logged or audited.
 *
 * At sign-in `asked` of the person's questions are picked at random and bound
 * to the pending second step (its mfa id), so refreshing or resubmitting the
 * page cannot re-roll them into easier ones; every one must be right, and
 * wrong answers count against the same per-user budget as an authenticator
 * code.
 *
 * Security questions are the weakest factor - answers can be guessed,
 * researched or phished - so they are off by default, the Factors page says
 * so, and they never satisfy the admin step-up (/admin/reauth, step-up.ts).
 */

export const KBA_DEFAULT_REQUIRED = 3;
export const KBA_DEFAULT_ASKED = 2;
export const KBA_MAX_REQUIRED = 10;
export const KBA_MIN_ANSWER = 3;
export const KBA_MAX_ANSWER = 100;
export const KBA_MAX_QUESTION = 200;
export const KBA_MAX_QUESTIONS = 100;

export interface SecurityQuestionRow {
  id: number;
  text: string;
  enabled: number;
  created_at: string;
}

export interface KbaSettings {
  /** How many questions each person sets. */
  required: number;
  /** How many of them are asked at sign-in (never more than required). */
  asked: number;
}

/** Whether security questions can be used at all: the administrator switched them on. */
export function securityQuestionsAvailable(env: Env): Promise<boolean> {
  return isFactorUsable(env, "security_questions");
}

/** Whether this user signs in with security questions right now. */
export async function userHasSecurityQuestions(env: Env, user: { security_questions_enabled: number }): Promise<boolean> {
  return Boolean(user.security_questions_enabled) && (await securityQuestionsAvailable(env));
}

export async function getKbaSettings(env: Env): Promise<KbaSettings> {
  const [r, a] = await Promise.all([getSetting(env, "kba_questions_required"), getSetting(env, "kba_questions_asked")]);
  const required = Math.min(Math.max(Number(r) || KBA_DEFAULT_REQUIRED, 1), KBA_MAX_REQUIRED);
  const asked = Math.min(Math.max(Number(a) || KBA_DEFAULT_ASKED, 1), required);
  return { required, asked };
}

export async function setKbaSettings(env: Env, s: KbaSettings): Promise<void> {
  await Promise.all([setSetting(env, "kba_questions_required", String(s.required)), setSetting(env, "kba_questions_asked", String(s.asked))]);
}

/** The catalogue, with how many people answered each question. */
export async function listSecurityQuestions(env: Env): Promise<(SecurityQuestionRow & { answered_by: number })[]> {
  const { results } = await env.DB.prepare(
    `SELECT q.id, q.text, q.enabled, q.created_at, (SELECT COUNT(*) FROM user_security_answers a WHERE a.question_id = q.id) AS answered_by
       FROM security_questions q ORDER BY q.id`
  ).all<SecurityQuestionRow & { answered_by: number }>();
  return results;
}

/** The questions people can choose when they enrol. */
export async function enabledSecurityQuestions(env: Env): Promise<SecurityQuestionRow[]> {
  const { results } = await env.DB.prepare("SELECT id, text, enabled, created_at FROM security_questions WHERE enabled = 1 ORDER BY id").all<SecurityQuestionRow>();
  return results;
}

/** The questions this user answered (whatever their catalogue state now). */
export async function userSecurityQuestions(env: Env, userId: number): Promise<{ id: number; text: string }[]> {
  const { results } = await env.DB.prepare(
    "SELECT q.id, q.text FROM user_security_answers a JOIN security_questions q ON q.id = a.question_id WHERE a.user_id = ? ORDER BY q.id"
  )
    .bind(userId)
    .all<{ id: number; text: string }>();
  return results;
}

/** The comparison form of an answer: NFKC, trimmed, whitespace collapsed, case folded. */
export function normaliseAnswer(answer: string): string {
  return answer.normalize("NFKC").trim().replace(/\s+/gu, " ").toLowerCase().normalize("NFKC");
}

export interface AnswerEntry {
  questionId: number;
  answer: string;
}

/** Why a set of answers was refused; the key is used in redirects, the text is shown. */
export const KBA_ERRORS: Record<string, string> = {
  "kba-count": "Choose a question for every row and answer each one.",
  "kba-unknown": "Choose your questions from the list.",
  "kba-distinct": "Choose a different question for each answer.",
  "kba-short": `Each answer needs at least ${KBA_MIN_ANSWER} characters.`,
  "kba-long": `Answers can be at most ${KBA_MAX_ANSWER} characters.`,
  "kba-same": "Each answer must be different from the others.",
  "kba-username": "An answer can't be your username.",
  "kba-password": "Your current password is not right.",
  "kba-unavailable": "Security questions aren't available right now.",
  "kba-too-many": "Too many attempts. Please wait a few minutes before trying again.",
};

/** Reads `question_1..n` / `answer_1..n` from an enrolment form. */
export function answersFromForm(body: Record<string, unknown>, count: number): AnswerEntry[] {
  return Array.from({ length: count }, (_, i) => ({
    questionId: Number(body[`question_${i + 1}`] ?? 0),
    answer: String(body[`answer_${i + 1}`] ?? "").slice(0, KBA_MAX_ANSWER * 4),
  }));
}

/**
 * Checks a proposed set against the rules, returning a KBA_ERRORS key or null:
 * exactly `required` entries, each an enabled question, all questions
 * distinct, each answer 3-100 characters once normalised, answers different
 * from each other and from the person's username (and UPN).
 */
export async function checkAnswers(env: Env, user: { username: string; upn: string }, entries: AnswerEntry[]): Promise<string | null> {
  const { required } = await getKbaSettings(env);
  if (entries.length !== required || entries.some((e) => !Number.isInteger(e.questionId) || e.questionId <= 0 || !e.answer.trim())) return "kba-count";
  const enabled = new Set((await enabledSecurityQuestions(env)).map((q) => q.id));
  if (entries.some((e) => !enabled.has(e.questionId))) return "kba-unknown";
  if (new Set(entries.map((e) => e.questionId)).size !== entries.length) return "kba-distinct";
  const normalised = entries.map((e) => normaliseAnswer(e.answer));
  if (normalised.some((a) => [...a].length < KBA_MIN_ANSWER)) return "kba-short";
  if (normalised.some((a) => [...a].length > KBA_MAX_ANSWER)) return "kba-long";
  if (new Set(normalised).size !== normalised.length) return "kba-same";
  const names = new Set([normaliseAnswer(user.username), normaliseAnswer(user.upn)]);
  if (normalised.some((a) => names.has(a))) return "kba-username";
  return null;
}

/** Replaces the user's answers with these (already checked) ones and marks the factor enrolled. */
export async function saveAnswers(env: Env, userId: number, entries: AnswerEntry[]): Promise<void> {
  const now = new Date().toISOString();
  // A fresh salt per answer: hashPassword draws one each call.
  const hashed = await Promise.all(entries.map(async (e) => ({ questionId: e.questionId, ...(await hashPassword(normaliseAnswer(e.answer), env)) })));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM user_security_answers WHERE user_id = ?").bind(userId),
    ...hashed.map((h) =>
      env.DB.prepare("INSERT INTO user_security_answers (user_id, question_id, answer_hash, answer_salt, answer_iterations, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(
        userId,
        h.questionId,
        h.hash,
        h.salt,
        h.iterations,
        now
      )
    ),
    env.DB.prepare("UPDATE users SET security_questions_enabled = 1, updated_at = ? WHERE id = ?").bind(now, userId),
  ]);
}

/** Removes the user's answers (self-service removal, an administrator's MFA reset). */
export function clearAnswersStatements(env: Env, userId: number): D1PreparedStatement[] {
  return [
    env.DB.prepare("DELETE FROM user_security_answers WHERE user_id = ?").bind(userId),
    env.DB.prepare("UPDATE users SET security_questions_enabled = 0, updated_at = ? WHERE id = ?").bind(new Date().toISOString(), userId),
  ];
}

/** A uniformly random integer in [0, n). */
function randomBelow(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0]! >= limit);
  return buf[0]! % n;
}

function pickRandom<T>(items: T[], k: number): T[] {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1);
    [a[i], a[j]] = [a[j]!, a[i]!];
  }
  return a.slice(0, k);
}

/**
 * The questions this pending sign-in asks: the ones already bound to it, or
 * (the first time) `asked` of the user's questions picked at random and
 * stored with the pending step. Re-picked only if the bound ones no longer
 * match the user's answers (they changed them meanwhile). Null when the user
 * has none.
 */
export async function challengeQuestions(env: Env, mfaId: string, pending: PendingMfa): Promise<{ id: number; text: string }[] | null> {
  const mine = await userSecurityQuestions(env, pending.userId);
  if (mine.length === 0) return null;
  const byId = new Map(mine.map((q) => [q.id, q]));
  if (pending.kba?.length && pending.kba.every((id) => byId.has(id))) return pending.kba.map((id) => byId.get(id)!);
  const { asked } = await getKbaSettings(env);
  const chosen = pickRandom(mine, Math.min(asked, mine.length));
  await setPendingMfaQuestions(env, mfaId, pending, chosen.map((q) => q.id));
  return chosen;
}

/**
 * Checks answers to the given questions: "ok" when every one matches, "wrong"
 * otherwise (all are checked, whichever is wrong), "stale" when the user no
 * longer has an answer to one of them.
 */
export async function verifyAnswers(env: Env, userId: number, questionIds: number[], answers: Record<number, string>): Promise<"ok" | "wrong" | "stale"> {
  if (questionIds.length === 0) return "stale";
  const { results } = await env.DB.prepare(
    "SELECT question_id, answer_hash, answer_salt, answer_iterations FROM user_security_answers WHERE user_id = ? AND question_id IN (SELECT value FROM json_each(?))"
  )
    .bind(userId, JSON.stringify(questionIds))
    .all<{ question_id: number; answer_hash: string; answer_salt: string; answer_iterations: number }>();
  if (results.length !== new Set(questionIds).size) return "stale";
  const checks = await Promise.all(
    results.map((r) =>
      verifyPassword(normaliseAnswer(String(answers[r.question_id] ?? "").slice(0, KBA_MAX_ANSWER * 4)), {
        password_hash: r.answer_hash,
        password_salt: r.answer_salt,
        password_iterations: r.answer_iterations,
      })
    )
  );
  return checks.every(Boolean) ? "ok" : "wrong";
}

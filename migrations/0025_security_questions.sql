-- Security questions as a second factor (knowledge-based, amr "kba").
--
-- security_questions is the catalogue administrators manage under Security ->
-- Factors -> Security questions: people pick from the enabled ones when they
-- enrol. A question somebody has answered is never deleted (it can only be
-- disabled, which stops new enrolments choosing it while existing answers keep
-- working), so an answer always has its question.
--
-- user_security_answers holds one row per answered question: the answer is
-- normalised (NFKC, trimmed, whitespace collapsed, lower-cased) and hashed
-- with the password KDF and a salt of its own (the hash/salt/iterations triple
-- of password.ts). The answer itself is never stored.
--
-- The factor is off until an administrator turns it on (setting
-- factor_security_questions_enabled); how many questions a person sets and how
-- many are asked at sign-in are the settings kba_questions_required (default
-- 3) and kba_questions_asked (default 2).
CREATE TABLE security_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE user_security_answers (
  user_id INTEGER NOT NULL REFERENCES users(id),
  question_id INTEGER NOT NULL REFERENCES security_questions(id),
  answer_hash TEXT NOT NULL,
  answer_salt TEXT NOT NULL DEFAULT '',
  answer_iterations INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, question_id)
);
CREATE INDEX user_security_answers_question ON user_security_answers(question_id);

ALTER TABLE users ADD COLUMN security_questions_enabled INTEGER NOT NULL DEFAULT 0;

INSERT INTO security_questions (text, enabled, created_at) VALUES
  ('What was the name of your first pet?', 1, '2026-01-01T00:00:00.000Z'),
  ('In what city or town were you born?', 1, '2026-01-01T00:00:00.000Z'),
  ('What was the name of your first school?', 1, '2026-01-01T00:00:00.000Z'),
  ('What is the first name of your oldest cousin?', 1, '2026-01-01T00:00:00.000Z'),
  ('What was the make and model of your first car?', 1, '2026-01-01T00:00:00.000Z'),
  ('What was the name of the street you grew up on?', 1, '2026-01-01T00:00:00.000Z'),
  ('What was your childhood nickname?', 1, '2026-01-01T00:00:00.000Z'),
  ('In what city or town did your parents meet?', 1, '2026-01-01T00:00:00.000Z'),
  ('What was the first concert you attended?', 1, '2026-01-01T00:00:00.000Z'),
  ('What was the name of your favourite teacher?', 1, '2026-01-01T00:00:00.000Z');

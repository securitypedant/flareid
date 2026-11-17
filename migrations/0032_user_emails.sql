-- Multiple contact addresses per user. users.email stays the denormalized
-- primary (every existing read path - mail attribute, recovery links, email
-- OTP, the SCIM primary entry - keeps working); this table is the full list.
-- An address can only ever belong to one account so recovery-by-email stays
-- unambiguous.
CREATE TABLE user_emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'work',
  is_primary INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (user_id, email)
);

CREATE UNIQUE INDEX idx_user_emails_email ON user_emails(email);
CREATE INDEX idx_user_emails_user ON user_emails(user_id);

INSERT INTO user_emails (user_id, email, type, is_primary, created_at)
  SELECT id, email, 'work', 1, datetime('now')
  FROM users WHERE email IS NOT NULL AND email != '';

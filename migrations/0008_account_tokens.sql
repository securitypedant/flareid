-- Single-use links sent by email: password recovery and invitations.
-- Only a SHA-256 of the token is stored, so a database read does not yield a
-- working link. used_at is set by a conditional UPDATE, which is what makes a
-- link single-use even when two requests race.
CREATE TABLE account_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  purpose TEXT NOT NULL CHECK (purpose IN ('reset', 'invite')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX idx_account_tokens_user ON account_tokens(user_id, purpose);
CREATE INDEX idx_account_tokens_expires ON account_tokens(expires_at);

-- Where email for this account goes, when it is not the UPN (a UPN does not
-- have to be a real mailbox). NULL means "send to the UPN".
ALTER TABLE users ADD COLUMN email TEXT;

-- A person flags a session or remembered device on their Security page as
-- not theirs (account -> Security -> Report). The item is signed out at once
-- and an open report lands in administrators' notifications until someone
-- marks it reviewed.
CREATE TABLE account_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('session', 'device')),
  ip TEXT,
  user_agent TEXT,
  item_created_at TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  resolved_by INTEGER
);
CREATE INDEX idx_account_reports_status ON account_reports(status, created_at);
CREATE INDEX idx_account_reports_user ON account_reports(user_id, created_at);

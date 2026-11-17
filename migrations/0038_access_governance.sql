-- Access governance: self-service requests for group membership and periodic
-- certification campaigns reviewing it. Both only ever touch explicit
-- group_members rows - a dynamic group's membership follows its rule and is
-- neither requestable nor revocable here.

-- A static group opts in to being requestable on My account.
ALTER TABLE groups ADD COLUMN requestable INTEGER NOT NULL DEFAULT 0;

CREATE TABLE access_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled')),
  -- The approving/denying admin; null for a requester-cancelled request.
  decided_by INTEGER,
  decided_at TEXT,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
-- One open request per person per group; decided ones can be asked again.
CREATE UNIQUE INDEX idx_access_requests_one_pending ON access_requests(user_id, group_id) WHERE status = 'pending';
CREATE INDEX idx_access_requests_status ON access_requests(status);

CREATE TABLE cert_campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  -- JSON array of the group ids whose memberships are under review.
  group_ids TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  created_by INTEGER,
  created_at TEXT NOT NULL,
  closed_at TEXT
);

-- One review item per explicit membership in scope, snapshotted at creation.
CREATE TABLE cert_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL REFERENCES cert_campaigns(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  decision TEXT NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending', 'certify', 'revoke')),
  decided_by INTEGER,
  decided_at TEXT,
  UNIQUE (campaign_id, user_id, group_id)
);

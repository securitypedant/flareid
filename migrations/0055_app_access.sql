-- Application access governance: an app can be open to everyone or restricted
-- to named users and/or groups (static or dynamic - dynamic membership is
-- resolved the same way group checks already are). Apps may additionally
-- require a second-factor sign-in, and may opt in to access requests the
-- same way static groups do.

ALTER TABLE oauth_clients ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'restricted' CHECK (access_mode IN ('everyone', 'restricted'));
ALTER TABLE oauth_clients ADD COLUMN assigned_users TEXT NOT NULL DEFAULT '[]';
ALTER TABLE oauth_clients ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_clients ADD COLUMN requestable INTEGER NOT NULL DEFAULT 0;

ALTER TABLE saml_service_providers ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'restricted' CHECK (access_mode IN ('everyone', 'restricted'));
ALTER TABLE saml_service_providers ADD COLUMN assigned_users TEXT NOT NULL DEFAULT '[]';
ALTER TABLE saml_service_providers ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE saml_service_providers ADD COLUMN requestable INTEGER NOT NULL DEFAULT 0;

-- Existing group assignments stay meaningful in restricted mode; an app with
-- no assignees is reachable by no-one, which is the new default everywhere.

-- Access requests now cover groups and both app kinds. group_id becomes a
-- generic (target_type, target_id) pair - one column can't carry a foreign
-- key to three tables, so request cleanup on delete moves to the delete
-- paths in code.
CREATE TABLE access_requests_v2 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL DEFAULT 'group' CHECK (target_type IN ('group', 'oidc_app', 'saml_app')),
  target_id INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled')),
  decided_by INTEGER,
  decided_at TEXT,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO access_requests_v2 (id, user_id, target_type, target_id, reason, status, decided_by, decided_at, note, created_at, updated_at)
  SELECT id, user_id, 'group', group_id, reason, status, decided_by, decided_at, note, created_at, updated_at FROM access_requests;
DROP TABLE access_requests;
ALTER TABLE access_requests_v2 RENAME TO access_requests;
CREATE UNIQUE INDEX idx_access_requests_one_pending ON access_requests(user_id, target_type, target_id) WHERE status = 'pending';
CREATE INDEX idx_access_requests_status ON access_requests(status);
CREATE INDEX idx_access_requests_target ON access_requests(target_type, target_id);

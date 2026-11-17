-- Outbound SCIM becomes multi-target: one row per downstream SCIM server
-- (Cloudflare Access, Google Workspace, a second Access account, ...), each
-- with its own endpoint, credential, sync scope and tuning - the same shape
-- OIDC clients and SAML service providers already have.
--
-- The legacy single-target keys in idp_settings (scim_endpoint, scim_secret,
-- scim_scope_*, scim_pace_ms, scim_members_per_request, scim_sync_batch) seed
-- the first target, then stay in place unused - a rollback keeps working.
CREATE TABLE scim_targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  endpoint TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT '',
  scope_mode TEXT NOT NULL DEFAULT 'all' CHECK (scope_mode IN ('all', 'selected')),
  scope_group_ids TEXT NOT NULL DEFAULT '[]',
  pace_ms INTEGER NOT NULL DEFAULT 200,
  members_per_request INTEGER NOT NULL DEFAULT 50,
  sync_batch INTEGER NOT NULL DEFAULT 50,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT INTO scim_targets (name, endpoint, secret, scope_mode, scope_group_ids, pace_ms, members_per_request, sync_batch, created_at, updated_at)
SELECT 'Default',
  e.value, s.value,
  CASE WHEN m.value = 'selected' THEN 'selected' ELSE 'all' END,
  COALESCE(NULLIF(g.value, ''), '[]'),
  CAST(COALESCE(NULLIF(p.value, ''), '200') AS INTEGER),
  CAST(COALESCE(NULLIF(mp.value, ''), '50') AS INTEGER),
  CAST(COALESCE(NULLIF(sb.value, ''), '50') AS INTEGER),
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM (SELECT 1) d
LEFT JOIN idp_settings e ON e.key = 'scim_endpoint'
LEFT JOIN idp_settings s ON s.key = 'scim_secret'
LEFT JOIN idp_settings m ON m.key = 'scim_scope_mode'
LEFT JOIN idp_settings g ON g.key = 'scim_scope_group_ids'
LEFT JOIN idp_settings p ON p.key = 'scim_pace_ms'
LEFT JOIN idp_settings mp ON mp.key = 'scim_members_per_request'
LEFT JOIN idp_settings sb ON sb.key = 'scim_sync_batch'
WHERE e.value IS NOT NULL AND e.value <> '';

-- Per-target link between a local row and the remote resource id it was
-- pushed as. users.scim_id and groups.scim_id stay populated as they were -
-- writes move here; the columns become read-only history.
CREATE TABLE scim_user_links (
  target_id INTEGER NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  PRIMARY KEY (target_id, user_id)
) WITHOUT ROWID;

CREATE TABLE scim_group_links (
  target_id INTEGER NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  PRIMARY KEY (target_id, group_id)
) WITHOUT ROWID;

INSERT INTO scim_user_links (target_id, user_id, scim_id)
SELECT t.id, u.id, u.scim_id FROM users u JOIN scim_targets t ON t.id = (SELECT MIN(id) FROM scim_targets)
WHERE u.scim_id IS NOT NULL;

INSERT INTO scim_group_links (target_id, group_id, scim_id)
SELECT t.id, g.id, g.scim_id FROM groups g JOIN scim_targets t ON t.id = (SELECT MIN(id) FROM scim_targets)
WHERE g.scim_id IS NOT NULL;

-- The pushed-membership snapshot and the deprovision queue are per target
-- too, so both tables are rebuilt with target_id in the key. Rows for a
-- directory that never configured a target have nowhere to belong - dropping
-- them only forces a full push when a target is configured later.
CREATE TABLE scim_group_state_new (
  target_id INTEGER NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  pushed_at TEXT NOT NULL,
  PRIMARY KEY (target_id, group_id)
) WITHOUT ROWID;

INSERT INTO scim_group_state_new (target_id, group_id, scim_id, display_name, pushed_at)
SELECT t.id, s.group_id, s.scim_id, s.display_name, s.pushed_at FROM scim_group_state s
JOIN scim_targets t ON t.id = (SELECT MIN(id) FROM scim_targets);

CREATE TABLE scim_group_members_new (
  target_id INTEGER NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  PRIMARY KEY (target_id, group_id, user_id)
) WITHOUT ROWID;

INSERT INTO scim_group_members_new (target_id, group_id, user_id, scim_id)
SELECT t.id, m.group_id, m.user_id, m.scim_id FROM scim_group_members m
JOIN scim_targets t ON t.id = (SELECT MIN(id) FROM scim_targets);

CREATE TABLE scim_deprovision_queue_new (
  target_id INTEGER NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'group')),
  scim_id TEXT NOT NULL,
  label TEXT NOT NULL,
  queued_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  PRIMARY KEY (target_id, kind, scim_id)
) WITHOUT ROWID;

INSERT INTO scim_deprovision_queue_new (target_id, kind, scim_id, label, queued_at, attempts, last_error)
SELECT t.id, q.kind, q.scim_id, q.label, q.queued_at, q.attempts, q.last_error FROM scim_deprovision_queue q
JOIN scim_targets t ON t.id = (SELECT MIN(id) FROM scim_targets);

DROP TABLE scim_group_state;
DROP TABLE scim_group_members;
DROP TABLE scim_deprovision_queue;
ALTER TABLE scim_group_state_new RENAME TO scim_group_state;
ALTER TABLE scim_group_members_new RENAME TO scim_group_members;
ALTER TABLE scim_deprovision_queue_new RENAME TO scim_deprovision_queue;

CREATE INDEX idx_scim_group_members_user ON scim_group_members(user_id);
CREATE INDEX idx_scim_user_links_user ON scim_user_links(user_id);
CREATE INDEX idx_scim_group_links_group ON scim_group_links(group_id);

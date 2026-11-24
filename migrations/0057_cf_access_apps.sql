-- Cloudflare Access applications, pulled read-only from the connected
-- account's Zero Trust. Access-fronted apps are not federated through FlareID
-- (Access itself is the RP), so they are not clients or SPs here - a row maps
-- one Access application to the directory group whose membership grants it,
-- which is all FlareID owns: Access policies Include the group claim, the
-- launchpad shows the app to members, and an approved access request adds the
-- person to the granting group.
CREATE TABLE cf_access_apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cf_app_id TEXT NOT NULL UNIQUE,           -- the Access application's UUID in the account
  name TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT '',            -- self_hosted / saas / ssh / bookmark / ...
  hostname TEXT NOT NULL DEFAULT '',        -- launch target: first self_hosted_domain, else domain
  granting_group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
  grant_hint TEXT NOT NULL DEFAULT '[]',    -- JSON array: FlareID group names seen in the app's Allow policies at last sync
  requestable INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

-- Access applications join the requestable targets. target_type's CHECK has
-- to be rebuilt to admit 'cfapp' (0055 did the same for the app kinds).
CREATE TABLE access_requests_v3 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL DEFAULT 'group' CHECK (target_type IN ('group', 'oidc_app', 'saml_app', 'cfapp')),
  target_id INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled')),
  decided_by INTEGER,
  decided_at TEXT,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO access_requests_v3 (id, user_id, target_type, target_id, reason, status, decided_by, decided_at, note, created_at, updated_at)
  SELECT id, user_id, target_type, target_id, reason, status, decided_by, decided_at, note, created_at, updated_at FROM access_requests;
DROP TABLE access_requests;
ALTER TABLE access_requests_v3 RENAME TO access_requests;

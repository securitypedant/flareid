-- Cloudflare One integrations.
--
-- auth_policies.device_cert: require a verified WARP device certificate
--   (request.cf.tlsClientAuth.certVerified = 'SUCCESS' when the zone enforces
--   mTLS) for the sign-in to proceed at all.
-- auth_policies.max_risk: deny sign-in when the user's Cloudflare Zero Trust
--   risk score ('' = no check) is above the level named.
-- groups.system: '' for ordinary groups, 'watchlist' for the risk watchlist -
--   membership is maintained by code and cannot be edited by hand.
-- groups.cf_list_sync: this group's member emails are kept in a Cloudflare One
--   gateway email list (cf_lists tracks the remote list ids).
ALTER TABLE auth_policies ADD COLUMN device_cert INTEGER NOT NULL DEFAULT 0;
ALTER TABLE auth_policies ADD COLUMN max_risk TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN system TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN cf_list_sync INTEGER NOT NULL DEFAULT 0;

-- The risk watchlist: who is flagged, why, and when the flag lapses. The
-- watchlist group (groups.system = 'watchlist') holds a member row per row
-- here; a SCIM target syncing groups pushes it downstream like any group.
CREATE TABLE user_watch (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,            -- 'manual' | 'auto:fails'
  flagged_at TEXT NOT NULL,
  expires_at TEXT                  -- NULL: stays until someone clears it
);
CREATE INDEX idx_user_watch_expires ON user_watch(expires_at);

-- Cloudflare One lists we keep in sync (gateway/lists). `key` names the sync:
-- 'watchlist', 'deprovisioned', 'managed-domains', 'auth-fail-ips',
-- 'group:{id}' for a synced group.
CREATE TABLE cf_lists (
  key TEXT PRIMARY KEY,
  cf_list_id TEXT NOT NULL,
  kind TEXT NOT NULL,              -- EMAIL | DOMAIN | IP
  item_count INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT
);

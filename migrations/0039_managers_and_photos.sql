-- Delegated group ownership: named people manage a group's members and answer
-- its access requests without holding the groups:write console permission.
CREATE TABLE IF NOT EXISTS group_managers (
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

-- Profile photos: uploaded on My account or written by inbound provisioning,
-- served by the /account/photo/:id route to any signed-in user. `data` holds
-- base64 text like brand_assets - D1 does not round-trip a bound ArrayBuffer
-- reliably.
CREATE TABLE IF NOT EXISTS user_photos (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  content_type TEXT NOT NULL,
  data BLOB NOT NULL,
  updated_at TEXT NOT NULL
);

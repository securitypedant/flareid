-- What was last pushed for each group to the outbound SCIM server, so a group
-- update can send only the change (RFC 7644 3.5.2 PATCH add/remove on
-- members) instead of PUT-ing every member again. A one-person import used to
-- re-send company-wide groups of thousands of members in full.
--
-- scim_group_state: one row per group whose remote membership is known, for
-- the remote group scim_id it describes (a recreated remote group has a new
-- id, which makes the old state void) and the displayName sent.
-- scim_group_members: the members in that push, with the remote user id each
-- was sent as (a user recreated downstream has a new one and is re-added).
--
-- Written only after the SCIM server accepted the push; without a row in
-- scim_group_state the next push is a full PUT (or POST), which rewrites it.
CREATE TABLE scim_group_state (
  group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  pushed_at TEXT NOT NULL
);

CREATE TABLE scim_group_members (
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id)
) WITHOUT ROWID;

CREATE INDEX idx_scim_group_members_user ON scim_group_members(user_id);

-- Personal launchpad layout (account -> Applications): each person can group
-- the apps they can reach into their own named sections. Placement is by a
-- stable app key ('oidc:<id>', 'saml:<id>', 'access:<id>'), so a placement for
-- an app they later lose access to is simply not shown; deleting a section
-- returns its apps to the unsorted list.
CREATE TABLE user_app_sections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_user_app_sections_user ON user_app_sections(user_id, position);

CREATE TABLE user_app_placements (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_key TEXT NOT NULL,
  section_id INTEGER NOT NULL REFERENCES user_app_sections(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, app_key)
);

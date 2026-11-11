-- Authentication policies: what a person must present to sign in, assigned
-- to groups. The lowest-priority-number policy that matches one of a user's
-- groups (dynamic groups included) applies; otherwise the default does.
CREATE TABLE auth_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  -- 'password' (a password, or a passkey) | 'mfa' (a password plus a second factor, or a passkey)
  requirement TEXT NOT NULL CHECK (requirement IN ('password', 'mfa')),
  priority INTEGER NOT NULL DEFAULT 100,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE auth_policy_groups (
  policy_id INTEGER NOT NULL REFERENCES auth_policies(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (policy_id, group_id)
);

-- The two starting policies. The old instance-wide "Require MFA" setting
-- decides which one is the default.
INSERT INTO auth_policies (name, description, requirement, priority, is_default, created_at) VALUES
  ('Password only', 'A password (or a passkey). A second factor is optional.', 'password', 100,
   CASE WHEN (SELECT value FROM idp_settings WHERE key = 'require_mfa') = 'true' THEN 0 ELSE 1 END, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ('Password and a second factor', 'A password plus an authenticator app code, or a passkey.', 'mfa', 100,
   CASE WHEN (SELECT value FROM idp_settings WHERE key = 'require_mfa') = 'true' THEN 1 ELSE 0 END, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- FlareID: the complete schema.
--
-- This is a squashed baseline. FlareID grew up inside a demo repository and
-- reached sixteen migrations, several of which existed only to seed that
-- demo's thirty fictional employees, its company.com domain and an
-- administrator whose password hash was committed in plain sight. None of that
-- belongs in an identity provider anyone else is expected to deploy, and a
-- migration chain cannot un-ship data - so the chain was collapsed here
-- instead.
--
-- Consequence worth knowing before you upgrade rather than install: this will
-- not apply cleanly on top of a database created by the old chain, because
-- d1_migrations already records migrations that no longer exist. See
-- docs/upgrading.md.
--
-- Users are identified by their UPN, a User Principal Name in email form.
-- Groups are flat; there is no nesting, by design.

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  upn TEXT NOT NULL UNIQUE,
  -- The local part of the UPN, unique across every domain so it can be used on
  -- its own to log in. That uniqueness is deliberate: it means an operator can
  -- change every account's domain without changing how anyone signs in.
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  given_name TEXT NOT NULL DEFAULT '',
  family_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  -- Stored per row so the cost can be raised later without invalidating
  -- existing hashes.
  password_iterations INTEGER NOT NULL DEFAULT 100000,
  totp_secret TEXT,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  -- Legacy. Membership of the "Super Admins" group is what actually authorizes
  -- /admin; this column is kept because SCIM payloads and some older queries
  -- still read it.
  is_admin INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  -- Remote SCIM resource id, once this user has been pushed to a SCIM server.
  scim_id TEXT,
  -- Stable UUID. Issued as the OIDC "id" claim and the SCIM externalId, and
  -- used as the manager reference below - so re-pointing someone's manager
  -- survives that manager's email changing.
  external_id TEXT NOT NULL UNIQUE,
  job_title TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  manager_external_id TEXT,
  employee_number TEXT NOT NULL DEFAULT '',
  hire_date TEXT NOT NULL DEFAULT '',
  employment_status TEXT NOT NULL DEFAULT '',
  employment_type TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_manager_external_id ON users(manager_external_id);

CREATE TABLE groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  scim_id TEXT
);

CREATE TABLE group_members (
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_members_user ON group_members(user_id);

-- The domains accounts may be created under. Multiple are allowed; exactly one
-- is the default that new accounts get.
CREATE TABLE domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL UNIQUE,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

-- Registered OIDC relying parties - one row per application allowed to sign
-- users in with this directory.
CREATE TABLE oauth_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL, -- JSON array of allowed redirect URIs
  created_at TEXT NOT NULL
);

-- Short-lived authorization codes, single use. `amr` records which
-- authentication methods were actually used, so the id_token can report them.
CREATE TABLE auth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT,
  code_challenge_method TEXT,
  expires_at TEXT NOT NULL,
  amr TEXT NOT NULL DEFAULT 'pwd'
);

-- Opaque access tokens, used only to authorize calls to /userinfo.
CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  amr TEXT NOT NULL DEFAULT 'pwd'
);

CREATE TABLE refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  scope TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  amr TEXT NOT NULL DEFAULT 'pwd'
);

-- Server-tracked sessions, so they can be listed and revoked - self-service
-- "sign out everywhere" and admin-forced logout - rather than a purely
-- stateless cookie.
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amr TEXT NOT NULL DEFAULT '["pwd"]',
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  revoked_at TEXT
);

CREATE INDEX idx_sessions_user ON sessions(user_id);

-- "Remember this device": lets a user skip the MFA challenge on a device they
-- have already verified recently, without disabling MFA itself.
CREATE TABLE trusted_devices (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  user_agent TEXT,
  ip TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_trusted_devices_user ON trusted_devices(user_id);

-- MFA backup/recovery codes. One-time use, hashed like passwords.
CREATE TABLE mfa_backup_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);

-- Security-relevant administrative and authentication actions.
--
-- actor_user_id is nullable because not every actor is a user: an action taken
-- through the provisioning API is attributed to an API key, which is recorded
-- by name in actor_upn with a null id.
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor_user_id INTEGER REFERENCES users(id),
  actor_upn TEXT,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT, -- JSON
  ip TEXT,
  user_agent TEXT
);

CREATE INDEX idx_audit_log_at ON audit_log(at);

-- Bearer tokens for the provisioning API at /api/v1.
--
-- Stored only as a SHA-256 hash; the plaintext is shown once at creation and
-- never again. `prefix` is the first few characters, kept in the clear purely
-- so the admin UI can tell two keys apart. There is deliberately no user_id: a
-- key is not a person. `created_by` records which administrator minted it,
-- which is a different question from who is using it.
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT '["admin"]', -- JSON array
  created_at TEXT NOT NULL,
  created_by TEXT,
  last_used_at TEXT,
  expires_at TEXT,
  revoked_at TEXT
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- Generic key/value settings, read through src/lib/settings.ts.
CREATE TABLE idp_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Starting settings.
--
-- `setup_completed` is false, which gates login to Super Admins only until an
-- administrator has confirmed the domain and the basics - either at
-- /admin/setup or through POST /api/v1/setup.
--
-- `default_password` is deliberately empty. It is the shared password new
-- accounts get when `new_user_password_mode` is 'default', and shipping a
-- value here would mean shipping a known credential; with no value set,
-- account creation generates a random password per account instead and returns
-- it once to whoever asked.
INSERT INTO idp_settings (key, value, updated_at) VALUES
  ('setup_completed', 'false', CURRENT_TIMESTAMP),
  ('default_password', '', CURRENT_TIMESTAMP),
  ('new_user_password_mode', 'random', CURRENT_TIMESTAMP),
  ('password_policy', '{"minLength":8,"requireUppercase":false,"requireLowercase":false,"requireNumber":false,"requireSymbol":false}', CURRENT_TIMESTAMP),
  ('require_mfa', 'false', CURRENT_TIMESTAMP),
  ('rate_limit_max_attempts', '5', CURRENT_TIMESTAMP),
  ('rate_limit_window_minutes', '15', CURRENT_TIMESTAMP),
  ('scim_endpoint', '', CURRENT_TIMESTAMP),
  ('scim_secret', '', CURRENT_TIMESTAMP),
  ('scim_scope_mode', 'all', CURRENT_TIMESTAMP),
  ('scim_scope_group_ids', '[]', CURRENT_TIMESTAMP);

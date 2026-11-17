-- LDAP interface: registered LDAP applications and their policy.
-- See LDAP.md.
CREATE TABLE ldap_apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- Branch RDN and service-account CN: ou=<slug>,<base> and cn=<slug>,ou=services,<base>.
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  -- SHA-256 of the service-account secret. High-entropy and generated, so a
  -- fast hash is correct here, as for api_keys.
  secret_hash TEXT NOT NULL,
  secret_prefix TEXT NOT NULL,
  -- JSON array of group ids whose members may bind and are visible to this
  -- app. '[]' = every active user.
  user_group_ids TEXT NOT NULL DEFAULT '[]',
  -- JSON array of group ids this app can see as group entries. '[]' = all.
  exposed_group_ids TEXT NOT NULL DEFAULT '[]',
  -- 'password' | 'otp_if_enrolled' | 'otp_required'. LDAP.md section 13.
  mfa_mode TEXT NOT NULL DEFAULT 'otp_if_enrolled'
    CHECK (mfa_mode IN ('password', 'otp_if_enrolled', 'otp_required')),
  -- Show disabled users (userAccountControl 514) so syncing apps can deactivate them.
  include_disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

INSERT INTO idp_settings (key, value, updated_at) VALUES
  ('ldap_enabled', 'false', CURRENT_TIMESTAMP),
  ('ldap_base_dn', '', CURRENT_TIMESTAMP),           -- '' = derive from default domain
  ('ldap_hostname', '', CURRENT_TIMESTAMP),          -- e.g. ldap.example.com, for dnsHostName and UI snippets
  ('ldap_netbios_name', '', CURRENT_TIMESTAMP),      -- '' = uppercased first label of the default domain
  ('ldap_unscoped_bind_app', '', CURRENT_TIMESTAMP), -- slug, or '' = deny unattributed user binds (section 9)
  ('ldap_domain_sid', '', CURRENT_TIMESTAMP),        -- generated on first enable (section 11)
  ('ldap_guid_namespace', '', CURRENT_TIMESTAMP),    -- generated on first enable (section 11)
  ('ldap_posix_uid_base', '10000', CURRENT_TIMESTAMP),
  ('ldap_posix_gid_base', '20000', CURRENT_TIMESTAMP),
  ('ldap_posix_default_gid', '100', CURRENT_TIMESTAMP),
  ('ldap_posix_shell', '/bin/bash', CURRENT_TIMESTAMP),
  ('ldap_posix_home', '/home/{username}', CURRENT_TIMESTAMP),
  ('ldap_idle_timeout_minutes', '15', CURRENT_TIMESTAMP),
  ('ldap_otp_rebind_seconds', '120', CURRENT_TIMESTAMP);

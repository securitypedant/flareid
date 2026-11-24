-- Multi-form sign-in identifiers (docs/identifiers.md): users.upn stays the
-- unique canonical name but its grammar widens to UPN / handle / phone.
-- users.username drops UNIQUE (a local part repeats across domains now) -
-- SQLite can't drop a constraint, so the table is rebuilt.
--
-- D1 enforces foreign keys at all times - PRAGMA foreign_keys and
-- writable_schema are not honored remotely, and deferred checks still fail at
-- commit on rows that referenced a dropped parent. So instead every table
-- referencing users(id) is backed up and emptied first: with no child rows,
-- the DROP is clean and enforcement stays on throughout, then the rows are
-- restored against the rebuilt table.

CREATE TABLE user_phones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  phone TEXT NOT NULL,                        -- E.164, '+' required
  type TEXT NOT NULL DEFAULT 'mobile',
  is_primary INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE (user_id, phone)
);
CREATE UNIQUE INDEX idx_user_phones_phone ON user_phones(phone);
CREATE INDEX idx_user_phones_user ON user_phones(user_id);

-- 1. Back up rows of every table with REFERENCES users(id).
CREATE TABLE _bak_group_members AS SELECT * FROM group_members;
CREATE TABLE _bak_auth_codes AS SELECT * FROM auth_codes;
CREATE TABLE _bak_access_tokens AS SELECT * FROM access_tokens;
CREATE TABLE _bak_refresh_tokens AS SELECT * FROM refresh_tokens;
CREATE TABLE _bak_sessions AS SELECT * FROM sessions;
CREATE TABLE _bak_trusted_devices AS SELECT * FROM trusted_devices;
CREATE TABLE _bak_mfa_backup_codes AS SELECT * FROM mfa_backup_codes;
CREATE TABLE _bak_audit_log AS SELECT * FROM audit_log;
CREATE TABLE _bak_account_tokens AS SELECT * FROM account_tokens;
CREATE TABLE _bak_oauth_consents AS SELECT * FROM oauth_consents;
CREATE TABLE _bak_webauthn_credentials AS SELECT * FROM webauthn_credentials;
CREATE TABLE _bak_user_security_answers AS SELECT * FROM user_security_answers;
CREATE TABLE _bak_user_emails AS SELECT * FROM user_emails;
CREATE TABLE _bak_device_codes AS SELECT * FROM device_codes;
CREATE TABLE _bak_scim_user_links AS SELECT * FROM scim_user_links;
CREATE TABLE _bak_scim_group_members AS SELECT * FROM scim_group_members;
CREATE TABLE _bak_federated_identities AS SELECT * FROM federated_identities;
CREATE TABLE _bak_cert_items AS SELECT * FROM cert_items;
CREATE TABLE _bak_group_managers AS SELECT * FROM group_managers;
CREATE TABLE _bak_user_photos AS SELECT * FROM user_photos;
CREATE TABLE _bak_user_watch AS SELECT * FROM user_watch;
CREATE TABLE _bak_access_requests AS SELECT * FROM access_requests;

-- 2. Empty the children so nothing references users during the swap.
DELETE FROM group_members;
DELETE FROM auth_codes;
DELETE FROM access_tokens;
DELETE FROM refresh_tokens;
DELETE FROM sessions;
DELETE FROM trusted_devices;
DELETE FROM mfa_backup_codes;
DELETE FROM audit_log;
DELETE FROM account_tokens;
DELETE FROM oauth_consents;
DELETE FROM webauthn_credentials;
DELETE FROM user_security_answers;
DELETE FROM user_emails;
DELETE FROM device_codes;
DELETE FROM scim_user_links;
DELETE FROM scim_group_members;
DELETE FROM federated_identities;
DELETE FROM cert_items;
DELETE FROM group_managers;
DELETE FROM user_photos;
DELETE FROM user_watch;
DELETE FROM access_requests;

-- 3. Rebuild users without UNIQUE(username).
CREATE TABLE users_v2 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  upn TEXT NOT NULL UNIQUE,
  -- The local part of a UPN, or the identifier itself for handle/phone
  -- accounts. No longer unique: a resolution candidate, never a key.
  username TEXT NOT NULL,
  display_name TEXT NOT NULL,
  given_name TEXT NOT NULL DEFAULT '',
  family_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_iterations INTEGER NOT NULL DEFAULT 100000,
  totp_secret TEXT,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  scim_id TEXT,
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
  updated_at TEXT NOT NULL,
  schema_id INTEGER,
  custom_attributes TEXT NOT NULL DEFAULT '{}',
  totp_last_counter INTEGER,
  email TEXT,
  email_otp_enabled INTEGER NOT NULL DEFAULT 0,
  security_questions_enabled INTEGER NOT NULL DEFAULT 0,
  source_id TEXT
);
INSERT INTO users_v2 (id, upn, username, display_name, given_name, family_name, password_hash, password_salt, password_iterations, totp_secret, mfa_enabled, is_admin, status, scim_id, external_id, job_title, department, manager_external_id, employee_number, hire_date, employment_status, employment_type, location, created_at, updated_at, schema_id, custom_attributes, totp_last_counter, email, email_otp_enabled, security_questions_enabled, source_id)
  SELECT id, upn, username, display_name, given_name, family_name, password_hash, password_salt, password_iterations, totp_secret, mfa_enabled, is_admin, status, scim_id, external_id, job_title, department, manager_external_id, employee_number, hire_date, employment_status, employment_type, location, created_at, updated_at, schema_id, custom_attributes, totp_last_counter, email, email_otp_enabled, security_questions_enabled, source_id FROM users;
DROP TABLE users;
ALTER TABLE users_v2 RENAME TO users;
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_manager_external_id ON users(manager_external_id);
CREATE INDEX idx_users_source_id ON users(source_id);

-- 4. Restore child rows against the rebuilt table, then drop the backups.
INSERT INTO group_members SELECT * FROM _bak_group_members;
INSERT INTO auth_codes SELECT * FROM _bak_auth_codes;
INSERT INTO access_tokens SELECT * FROM _bak_access_tokens;
INSERT INTO refresh_tokens SELECT * FROM _bak_refresh_tokens;
INSERT INTO sessions SELECT * FROM _bak_sessions;
INSERT INTO trusted_devices SELECT * FROM _bak_trusted_devices;
INSERT INTO mfa_backup_codes SELECT * FROM _bak_mfa_backup_codes;
INSERT INTO audit_log SELECT * FROM _bak_audit_log;
INSERT INTO account_tokens SELECT * FROM _bak_account_tokens;
INSERT INTO oauth_consents SELECT * FROM _bak_oauth_consents;
INSERT INTO webauthn_credentials SELECT * FROM _bak_webauthn_credentials;
INSERT INTO user_security_answers SELECT * FROM _bak_user_security_answers;
INSERT INTO user_emails SELECT * FROM _bak_user_emails;
INSERT INTO device_codes SELECT * FROM _bak_device_codes;
INSERT INTO scim_user_links SELECT * FROM _bak_scim_user_links;
INSERT INTO scim_group_members SELECT * FROM _bak_scim_group_members;
INSERT INTO federated_identities SELECT * FROM _bak_federated_identities;
INSERT INTO cert_items SELECT * FROM _bak_cert_items;
INSERT INTO group_managers SELECT * FROM _bak_group_managers;
INSERT INTO user_photos SELECT * FROM _bak_user_photos;
INSERT INTO user_watch SELECT * FROM _bak_user_watch;
INSERT INTO access_requests SELECT * FROM _bak_access_requests;

DROP TABLE _bak_group_members;
DROP TABLE _bak_auth_codes;
DROP TABLE _bak_access_tokens;
DROP TABLE _bak_refresh_tokens;
DROP TABLE _bak_sessions;
DROP TABLE _bak_trusted_devices;
DROP TABLE _bak_mfa_backup_codes;
DROP TABLE _bak_audit_log;
DROP TABLE _bak_account_tokens;
DROP TABLE _bak_oauth_consents;
DROP TABLE _bak_webauthn_credentials;
DROP TABLE _bak_user_security_answers;
DROP TABLE _bak_user_emails;
DROP TABLE _bak_device_codes;
DROP TABLE _bak_scim_user_links;
DROP TABLE _bak_scim_group_members;
DROP TABLE _bak_federated_identities;
DROP TABLE _bak_cert_items;
DROP TABLE _bak_group_managers;
DROP TABLE _bak_user_photos;
DROP TABLE _bak_user_watch;
DROP TABLE _bak_access_requests;

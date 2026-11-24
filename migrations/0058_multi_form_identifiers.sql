-- Multi-form sign-in identifiers (docs/identifiers.md): users.upn stays the
-- unique canonical name but its grammar widens to UPN / handle / phone.
-- users.username drops UNIQUE (a local part repeats across domains now) -
-- SQLite can't drop a constraint, so the table is rebuilt like 0057 did.

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

-- Rebuilding a referenced table: foreign keys must be off or the DROP below
-- implicit-deletes users and cascades through every child table. D1 executes
-- each statement in the file on the same session, so this holds.
PRAGMA foreign_keys = OFF;

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

PRAGMA foreign_keys = ON;

-- Roles as data: a role is a named set of permissions (src/lib/permissions.ts,
-- the same model API keys use), granted to groups - or, for a default role,
-- to everyone. The four roles from 0019 are seeded here and linked to their groups,
-- so nothing changes for existing role holders; new roles can be created in
-- Admin -> Security -> Roles. Permissions are "<area>:read" or "<area>:write"
-- (write implies read). "Super Admin" is built in and holds everything,
-- including managing roles, which no other role can be given.
CREATE TABLE admin_roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  builtin INTEGER NOT NULL DEFAULT 0,
  -- A default role applies to every user, whatever their groups ("User").
  is_default INTEGER NOT NULL DEFAULT 0,
  permissions TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE admin_role_groups (
  role_id INTEGER NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, group_id)
);

INSERT INTO admin_roles (name, description, builtin, is_default, permissions, created_at) VALUES
  ('User', 'What every account can do: sign in, and manage its own account.', 1, 1,
   '["signin","account:read","account:write"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
INSERT INTO admin_roles (name, description, builtin, permissions, created_at) VALUES
  ('Super Admin', 'Everything, including roles, security settings and API keys.', 1, '["*"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ('Directory Admin', 'Users, groups, domains, schemas and CSV import.', 1,
   '["users:write","groups:write","domains:write","schemas:write","import:write","audit:read","performance:read"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ('Application Admin', 'OIDC clients, SAML apps, SCIM provisioning and email.', 1,
   '["oidc:write","saml:write","scim:write","email:write","audit:read","performance:read"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ('Auditor', 'Read-only access to the directory, integrations, the overview and the log.', 1,
   '["users:read","groups:read","domains:read","schemas:read","oidc:read","saml:read","scim:read","email:read","audit:read","performance:read"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT OR IGNORE INTO admin_role_groups (role_id, group_id)
  SELECT r.id, g.id FROM admin_roles r JOIN groups g ON
    (r.name = 'Super Admin' AND g.name = 'Super Admins') OR
    (r.name = 'Directory Admin' AND g.name = 'Directory Admins') OR
    (r.name = 'Application Admin' AND g.name = 'Application Admins') OR
    (r.name = 'Auditor' AND g.name = 'Auditors');

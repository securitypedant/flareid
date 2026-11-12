-- Granular administration. Like "Super Admins", each role is an ordinary group
-- whose name FlareID knows:
--   Directory Admins    - users, groups, domains, schemas, CSV import
--   Application Admins  - OIDC clients, SAML apps, SCIM provisioning, email
--   Auditors            - read-only access to the whole console and the log
-- Only Super Admins can change who holds a role, touch an account that holds
-- one, or reach security settings, branding and API keys.
INSERT OR IGNORE INTO groups (name, description) VALUES
  ('Directory Admins', 'Members manage users, groups, domains and schemas'),
  ('Application Admins', 'Members manage OIDC clients, SAML apps, SCIM provisioning and email'),
  ('Auditors', 'Members have read-only access to the admin console and the log');

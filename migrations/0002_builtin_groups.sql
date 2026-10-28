-- The two groups FlareID itself knows about by name.
--
-- "Super Admins" is the authorization boundary for /admin - it is an ordinary
-- group, managed like any other, which is why it is a row here rather than a
-- flag on a column.
--
-- "All Employees" is a convention rather than a mechanism: a company-wide group
-- that is a convenient target for Access policies and SCIM sync scope. The
-- admin UI auto-joins accounts created through a form to it, on the grounds
-- that somebody filling in a form should not have to remember. The provisioning
-- API does not, because an import should produce exactly the directory it
-- describes - so a service account that should not be in it simply does not
-- list it.
--
-- Note what is NOT here: no users, no domain, no sample directory. A freshly
-- migrated FlareID has nobody in it at all, and is configured through
-- POST /api/v1/setup using the BOOTSTRAP_TOKEN secret. That is the deliberate
-- alternative to shipping an administrator with a known password.
INSERT INTO groups (name, description) VALUES
  ('Super Admins', 'Members can administer this directory'),
  ('All Employees', 'Every person in the organization');

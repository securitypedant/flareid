-- Repairs for two name-keyed bindings earlier migrations made silently.
--
-- 1) admin_role_groups (0019 seeded the role groups, 0023 bound them by name).
--    Matching on the group name meant an operator's own group that happened to
--    carry 'Super Admins', 'Directory Admins', 'Application Admins' or
--    'Auditors' was silently granted the built-in role on upgrade. The groups
--    FlareID seeds carry fixed descriptions (0002, 0019), so a bound group
--    whose description differs was never FlareID's - the binding comes off.
--    A deliberate re-bind is still possible under Admin -> Security -> Roles.
DELETE FROM admin_role_groups
 WHERE (role_id, group_id) IN (
   SELECT r.id, g.id FROM admin_roles r JOIN groups g ON
     (r.name = 'Super Admin'       AND g.name = 'Super Admins'       AND g.description <> 'Members can administer this directory') OR
     (r.name = 'Directory Admin'   AND g.name = 'Directory Admins'   AND g.description <> 'Members manage users, groups, domains and schemas') OR
     (r.name = 'Application Admin' AND g.name = 'Application Admins' AND g.description <> 'Members manage OIDC clients, SAML apps, SCIM provisioning and email') OR
     (r.name = 'Auditor'           AND g.name = 'Auditors'           AND g.description <> 'Members have read-only access to the admin console and the log')
 );

-- 2) auth_policy_groups (0022 bound the MFA policy to 'Super Admins' by the
--    policy's display name, which is mutable). A renamed or deleted policy
--    meant no binding and no error - administrators fell back to the default
--    policy and signed in with a password alone. When no mfa-requirement
--    policy is bound to Super Admins, bind the strongest existing one
--    (default first, then lowest priority number and id); if none exists,
--    create it. If the binding was deliberately removed under Security >
--    Policies, relax it again there - the silent case is the dangerous one.
INSERT INTO auth_policies (name, description, requirement, priority, is_default, created_at)
SELECT 'Password and a second factor', 'Sign in with a password, then prove a second factor.', 'mfa', 1, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
 WHERE NOT EXISTS (SELECT 1 FROM auth_policies WHERE requirement = 'mfa')
   AND NOT EXISTS (
     SELECT 1 FROM auth_policy_groups pg
       JOIN auth_policies q ON q.id = pg.policy_id
       JOIN groups x ON x.id = pg.group_id
      WHERE x.name = 'Super Admins' AND q.requirement = 'mfa'
   );

UPDATE auth_policies SET priority = 1
 WHERE id = (SELECT id FROM auth_policies WHERE requirement = 'mfa' ORDER BY is_default DESC, priority, id LIMIT 1)
   AND NOT EXISTS (
     SELECT 1 FROM auth_policy_groups pg
       JOIN auth_policies q ON q.id = pg.policy_id
       JOIN groups x ON x.id = pg.group_id
      WHERE x.name = 'Super Admins' AND q.requirement = 'mfa'
   );

INSERT OR IGNORE INTO auth_policy_groups (policy_id, group_id)
  SELECT p.id, g.id FROM auth_policies p, groups g
   WHERE g.name = 'Super Admins'
     AND p.id = (SELECT id FROM auth_policies WHERE requirement = 'mfa' ORDER BY is_default DESC, priority, id LIMIT 1)
     AND NOT EXISTS (
       SELECT 1 FROM auth_policy_groups pg
         JOIN auth_policies q ON q.id = pg.policy_id
         JOIN groups x ON x.id = pg.group_id
        WHERE x.name = 'Super Admins' AND q.requirement = 'mfa'
     );

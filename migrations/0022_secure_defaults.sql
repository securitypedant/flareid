-- Secure by default: administrators need a second factor (changeable: setup's
-- admin_mfa, or taking Super Admins out of the policy under Security > Policies).
-- "Password and a second factor" applies to Super Admins on every install
-- (priority 1, ahead of anything else); a fresh install - nobody in the
-- directory yet - also makes it the default policy for everyone.
UPDATE auth_policies SET priority = 1 WHERE name = 'Password and a second factor';
INSERT OR IGNORE INTO auth_policy_groups (policy_id, group_id)
  SELECT p.id, g.id FROM auth_policies p, groups g
   WHERE p.name = 'Password and a second factor' AND g.name = 'Super Admins';
UPDATE auth_policies
   SET is_default = CASE WHEN requirement = 'mfa' THEN 1 ELSE 0 END
 WHERE (SELECT COUNT(*) FROM users) = 0
   AND name IN ('Password only', 'Password and a second factor');

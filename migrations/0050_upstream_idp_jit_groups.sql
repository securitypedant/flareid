-- Per-provider JIT group assignment: a JSON array of group ids that every
-- account the upstream IdP just-in-time provisions joins at creation.
-- Unlike claim-derived dynamic-rule membership (which resolveFederatedUser
-- refuses when it would grant an admin role), this list is the admin's
-- explicit configuration, so a group granting a read-only admin role is
-- allowed; validateUpstreamIdp still refuses a group whose role carries any
-- write permission.
ALTER TABLE upstream_idps ADD COLUMN jit_groups TEXT NOT NULL DEFAULT '[]';

-- An app may name the authentication policy that applies to sign-ins into it.
-- The policy is the same object Security -> Policies defines for people:
-- its requirement steps a session up (or, for device-cert/risk conditions,
-- denies the sign-in outright). NULL = the person's own policy applies,
-- which is every existing app's behaviour.

ALTER TABLE oauth_clients ADD COLUMN policy_id INTEGER;
ALTER TABLE saml_service_providers ADD COLUMN policy_id INTEGER;

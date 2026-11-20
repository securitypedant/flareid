-- A SCIM target can belong to one application (an OIDC client or a SAML
-- service provider): it then shows on that app's page as its provisioning
-- setup, created from the app's "Set up provisioning" link. NULL/NULL keeps
-- the pre-existing standalone behaviour - a directory-wide target managed
-- from the SCIM page.
ALTER TABLE scim_targets ADD COLUMN app_type TEXT CHECK (app_type IS NULL OR app_type IN ('oidc', 'saml'));
ALTER TABLE scim_targets ADD COLUMN app_id INTEGER;

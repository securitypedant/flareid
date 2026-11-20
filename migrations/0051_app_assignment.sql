-- App assignment: each OIDC client / SAML service provider can name the
-- groups whose members may see it on the My account launchpad and single
-- sign-on into it. A JSON array of group ids; NULL or '[]' means everyone
-- (the pre-assignment behaviour), so existing apps are unaffected.
ALTER TABLE oauth_clients ADD COLUMN assigned_groups TEXT;
ALTER TABLE saml_service_providers ADD COLUMN assigned_groups TEXT;

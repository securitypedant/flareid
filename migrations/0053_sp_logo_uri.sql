-- An app icon for the launchpad: OIDC clients already carry RFC 7591
-- logo_uri; service providers get the same so every app tile can show a mark.
-- Absolute https URL (e.g. the deployment's own /catalog-icons/<file>.svg).
ALTER TABLE saml_service_providers ADD COLUMN logo_uri TEXT;

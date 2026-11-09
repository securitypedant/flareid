-- SAML for v3: Single Logout. (encrypt_assertions and encryption_cert were
-- reserved in 0003_saml.sql and are used from v3 on.)
-- Where the SP receives LogoutResponses (HTTP-Redirect). NULL = no SLO.
ALTER TABLE saml_service_providers ADD COLUMN slo_url TEXT;

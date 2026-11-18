-- RFC 7591 display metadata for dynamic clients: the relying-party logo and
-- links to its policy/terms-of-service documents, shown on the sign-in page
-- so people can see which app they are authenticating to (and verify the
-- OIDCC logo_uri/policy_uri/tos_uri registration tests).
ALTER TABLE oauth_clients ADD COLUMN logo_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN policy_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN tos_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN client_uri TEXT;

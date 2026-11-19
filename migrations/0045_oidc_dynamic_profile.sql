-- OIDC dynamic-profile client metadata (RFC 7591 + OIDC Registration 3.2):
-- pairwise subject identifiers, sector hints, request_uri pinning and
-- signed userinfo responses.
ALTER TABLE oauth_clients ADD COLUMN subject_type TEXT;
ALTER TABLE oauth_clients ADD COLUMN sector_identifier_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN request_uris TEXT;
ALTER TABLE oauth_clients ADD COLUMN userinfo_signed_response_alg TEXT;

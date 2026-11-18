-- The remaining OIDC OP conformance profiles: back-channel logout and
-- third-party-initiated login add client metadata columns; dynamic client
-- registration stores the registration access token (hash, not plaintext) and
-- the client's signing material for private_key_jwt assertions.

ALTER TABLE oauth_clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN initiate_login_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN registration_token_hash TEXT;

-- RFC 7591 jwks (an embedded JWKS JSON document) or jwks_uri (fetched and
-- cached): either authenticates the client's private_key_jwt assertions.
ALTER TABLE oauth_clients ADD COLUMN jwks TEXT;
ALTER TABLE oauth_clients ADD COLUMN jwks_uri TEXT;

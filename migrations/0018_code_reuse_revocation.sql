-- RFC 6749 4.1.2: when an authorization code is used twice, tokens already
-- issued from it should be revoked. Redeemed codes are now kept (marked used)
-- until they expire, and tokens remember which code issued them.
ALTER TABLE auth_codes ADD COLUMN used_at TEXT;
ALTER TABLE access_tokens ADD COLUMN code_hash TEXT;
ALTER TABLE refresh_tokens ADD COLUMN code_hash TEXT;
CREATE INDEX access_tokens_code_hash ON access_tokens(code_hash);
CREATE INDEX refresh_tokens_code_hash ON refresh_tokens(code_hash);

-- OpenID Connect Core 5.5: claim groups asked for with the `claims` request
-- parameter (JSON array), carried from the code to the tokens and /userinfo.
ALTER TABLE auth_codes ADD COLUMN claims TEXT;
ALTER TABLE access_tokens ADD COLUMN claims TEXT;
ALTER TABLE refresh_tokens ADD COLUMN claims TEXT;

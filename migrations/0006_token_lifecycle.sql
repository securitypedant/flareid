-- Refresh-token lifecycle, and indexes for the scheduled cleanup.
--
-- Refresh tokens used to live forever and be handed back unchanged on every
-- refresh. Now each one has an expiry, and every use rotates it: the
-- presented token is marked rotated_at and a new token in the same family is
-- issued. Presenting a token that has already been rotated means two parties
-- hold it - the client and whoever copied it - so the whole family is
-- revoked (RFC 9700 §4.14.2, refresh token reuse detection).
--
-- family_id is the token_hash of the first token in the chain. Existing rows
-- become the head of their own family, expiring 30 days after they were
-- created - long-lived tokens issued before this migration are not grandfathered
-- in forever.
ALTER TABLE refresh_tokens ADD COLUMN expires_at TEXT;
ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN rotated_at TEXT;

UPDATE refresh_tokens
   SET family_id = token_hash,
       expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '+30 days')
 WHERE family_id IS NULL;

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- The cleanup job deletes by these columns every hour.
CREATE INDEX idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX idx_sessions_created ON sessions(created_at);
CREATE INDEX idx_trusted_devices_expires ON trusted_devices(expires_at);

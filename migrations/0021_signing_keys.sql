-- Signing keys in the database, so rotation needs no redeploy. Private keys are
-- stored encrypted (AES-256-GCM) under the KEY_ENCRYPTION_KEY secret. The
-- RS256 key from the SIGNING_KEY_PKCS8 secret is imported on first use with its
-- existing kid, so tokens already issued stay verifiable.
CREATE TABLE signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL CHECK (alg IN ('RS256', 'ES256')),
  public_jwk TEXT NOT NULL,
  private_jwk_enc TEXT NOT NULL,
  -- 'active' signs new tokens (one per alg); 'retired' is still published until it can no longer verify anything.
  status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
  created_at TEXT NOT NULL,
  retired_at TEXT
);

-- Per-client id_token signing algorithm (OIDC Dynamic Registration's
-- id_token_signed_response_alg), RS256 unless the client asks for ES256.
ALTER TABLE oauth_clients ADD COLUMN id_token_signed_response_alg TEXT NOT NULL DEFAULT 'RS256';

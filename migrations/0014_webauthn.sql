-- WebAuthn / passkeys. One row per registered credential; the public key is
-- stored as COSE (base64url), the credential id as base64url.
CREATE TABLE webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  name TEXT NOT NULL DEFAULT 'Passkey',
  backed_up INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

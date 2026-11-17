-- Revealable LDAP app secrets: the bind secret stays verified by its SHA-256,
-- and this ciphertext (AES-256-GCM under KEY_ENCRYPTION_KEY) lets an admin
-- re-copy it from the console without rotating.
ALTER TABLE ldap_apps ADD COLUMN secret_enc TEXT;

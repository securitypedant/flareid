-- Per-SP XML Encryption policy: which content/key-transport algorithms the
-- EncryptedAssertion carries. NULL keeps the historical default
-- (aes256-gcm + rsa-oaep-mgf1p/SHA-1). Populated from md:EncryptionMethod in
-- imported SP metadata, or set directly through the admin API.
ALTER TABLE saml_service_providers ADD COLUMN encryption_policy TEXT;

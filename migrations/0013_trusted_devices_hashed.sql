-- Trusted-device rows now store sha256(cookie value) instead of the value
-- itself. Existing plaintext rows cannot be converted in SQL, so they are
-- dropped: affected users answer one MFA prompt and can remember the device again.
DELETE FROM trusted_devices;

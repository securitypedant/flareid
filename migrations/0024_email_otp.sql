-- Email one-time codes as a second factor. A user who enrolled (by entering a
-- code sent to their address from My account) is asked for an emailed code
-- after the password. The codes themselves live in KV, hashed, for ten
-- minutes; nothing about them is stored here.
--
-- The factor is off until an administrator turns it on under Security ->
-- Factors (setting factor_email_otp_enabled), and it only works while email
-- is configured.
ALTER TABLE users ADD COLUMN email_otp_enabled INTEGER NOT NULL DEFAULT 0;

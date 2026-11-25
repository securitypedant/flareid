-- SMS one-time codes as a second factor (lib/sms-otp.ts), off until the
-- person enrols on account -> Security; needs a verified phone number and an
-- SMS provider (Integrations -> SMS). The factor switch itself lives in
-- idp_settings (factor_sms_otp_enabled), off by default.
ALTER TABLE users ADD COLUMN sms_otp_enabled INTEGER NOT NULL DEFAULT 0;

-- Step-up re-authentication for sensitive admin actions: when the session's
-- user last proved their credentials (password and second factor, or a
-- passkey) on the re-authentication page. NULL = only at sign-in (created_at).
ALTER TABLE sessions ADD COLUMN stepped_up_at TEXT;

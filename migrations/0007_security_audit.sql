-- Atomic fixed-window rate-limit accounting. The KV get/increment/put pair it
-- replaces could lose increments and let a burst see a stale under-limit count;
-- a single INSERT .. ON CONFLICT .. DO UPDATE .. RETURNING cannot.
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

-- TOTP replay guard: the last time-step counter accepted for this user. A code
-- is only accepted while its counter is greater than the stored one, claimed
-- by a conditional UPDATE so two concurrent submissions cannot both pass.
ALTER TABLE users ADD COLUMN totp_last_counter INTEGER;

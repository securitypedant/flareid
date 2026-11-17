-- RFC 8628 device authorization: what a polling device holds while it waits
-- for a person to approve the sign-in on another screen.
CREATE TABLE IF NOT EXISTS device_codes (
  -- The device_code is a bearer secret; only its hash is stored.
  device_code_hash TEXT PRIMARY KEY,
  -- The code a person types at /device: 8 chars, no separator (normalized).
  user_code TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  -- pending -> approved|denied (terminal); expiry is the other terminal state.
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  user_id INTEGER REFERENCES users(id),
  -- The approver's authentication context at approval time, for the token grant.
  amr TEXT,
  auth_time INTEGER,
  sid TEXT,
  -- RFC 8628 3.5 poll pacing: slow_down answers grow the interval by 5s.
  poll_interval INTEGER NOT NULL DEFAULT 5,
  last_poll_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes(expires_at);

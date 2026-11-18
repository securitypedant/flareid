-- Audit tamper-evidence and Shared Signals Framework.
--
-- audit_log.chain_hash: sha256(previous row's chain_hash + this row's
-- fields), so deleting or editing a written row breaks every hash after it.
-- Verification walks id order and reports the first break (or a fork, when
-- two concurrent writes shared a parent).
ALTER TABLE audit_log ADD COLUMN chain_hash TEXT;
CREATE INDEX idx_audit_log_chain ON audit_log(chain_hash);

-- ssf_streams: receivers we push Security Event Tokens to (Okta, Entra,
-- Google-style receivers register their endpoint here). Each row is one
-- outbound stream; `events` is the JSON list of CAEP/RISC event URIs it
-- gets. `aud` is the audience the receiver expects in the SET.
CREATE TABLE ssf_streams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  aud TEXT NOT NULL DEFAULT '',
  events TEXT NOT NULL DEFAULT '[]',
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_push_at TEXT,
  last_error TEXT
);

-- ssf_outbox: one row per stream per emitted event; drained inline at emit
-- time and again by the scheduled job for failures.
CREATE TABLE ssf_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stream_id INTEGER NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
  event_uri TEXT NOT NULL,
  subject TEXT NOT NULL,          -- JSON sub_id, e.g. {"format":"email","email":"a@b.c"}
  queued_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
CREATE INDEX idx_ssf_outbox_stream ON ssf_outbox(stream_id);

-- ssf_transmitters: issuers whose SETs we accept at POST /ssf/receive.
-- jwks_url is fetched on demand and cached per issuer in the isolate.
CREATE TABLE ssf_transmitters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  issuer TEXT NOT NULL UNIQUE,
  jwks_url TEXT NOT NULL,
  created_at TEXT NOT NULL
);

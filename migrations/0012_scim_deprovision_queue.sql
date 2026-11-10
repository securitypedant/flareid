-- Durable outbound SCIM deprovisioning. Replace-mode import and directory
-- reset delete local rows; a user's scim_id is the only way to find it at the
-- SCIM target afterwards. Queued here in the same batch as the deletion, then
-- drained in bounded steps (the import itself, every sync, the hourly cron),
-- so a failed or budget-cut DELETE is retried instead of orphaning an active
-- downstream account.
CREATE TABLE scim_deprovision_queue (
  kind TEXT NOT NULL CHECK (kind IN ('user', 'group')),
  scim_id TEXT NOT NULL,
  label TEXT NOT NULL,
  queued_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  PRIMARY KEY (kind, scim_id)
);

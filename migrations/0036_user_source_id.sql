-- The provisioner's own stable id for a user (SCIM externalId, an HR system's
-- person id). Correlation rules can match inbound writes on it, and manager
-- references resolve through it. Nullable; unique when present.
ALTER TABLE users ADD COLUMN source_id TEXT;
CREATE UNIQUE INDEX idx_users_source_id ON users(source_id) WHERE source_id IS NOT NULL;

-- The pre-0034 single-target SCIM bearer token. Migration 0034 copied it into
-- scim_targets (whose secret column is sealed at rest via sealMaybe) and left
-- this idp_settings row in place "unused, for rollback" - which also left a
-- still-valid remote credential sitting plaintext in the table and in every
-- backup export. Nothing reads the key any more; dropping the row retires it.
-- The non-secret siblings (scim_endpoint, scim_scope_*, the tuning keys) stay:
-- they are configuration, not credentials, and keep a rollback readable.
DELETE FROM idp_settings WHERE key = 'scim_secret';

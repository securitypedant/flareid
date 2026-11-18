-- grant_types: the grants a dynamically registered client declared it would
-- use (RFC 7591 metadata), enforced at /token - NULL means "every supported
-- grant", which is what admin-created and pre-existing rows get.
-- registered_scope: the `scope` metadata the client registered; when set, a
-- client_credentials request's scope must be a subset of it.
ALTER TABLE oauth_clients ADD COLUMN grant_types TEXT;
ALTER TABLE oauth_clients ADD COLUMN registered_scope TEXT;

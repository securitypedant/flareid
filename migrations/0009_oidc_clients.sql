-- OIDC client model for v3: public clients, consent, per-client claims, and
-- RP-initiated logout. Existing clients keep today's behaviour: confidential,
-- trusted (no consent screen), every claim group (allowed_claims NULL).
ALTER TABLE oauth_clients ADD COLUMN client_type TEXT NOT NULL DEFAULT 'confidential' CHECK (client_type IN ('confidential', 'public'));
ALTER TABLE oauth_clients ADD COLUMN trusted INTEGER NOT NULL DEFAULT 1;
-- JSON array of claim groups (email, profile, groups, hr, custom); NULL = all.
ALTER TABLE oauth_clients ADD COLUMN allowed_claims TEXT;
-- JSON array; RP-initiated logout may only send the browser to one of these.
ALTER TABLE oauth_clients ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';

-- When the user actually authenticated (epoch seconds) and which IdP session
-- it was, carried from the code to the id_token (auth_time, sid) and on
-- through refresh.
ALTER TABLE auth_codes ADD COLUMN auth_time INTEGER;
ALTER TABLE auth_codes ADD COLUMN sid TEXT;
ALTER TABLE refresh_tokens ADD COLUMN auth_time INTEGER;
ALTER TABLE refresh_tokens ADD COLUMN sid TEXT;

-- What a user has agreed to share with a non-trusted client. A request for
-- scopes beyond the stored set asks again.
CREATE TABLE oauth_consents (
  user_id INTEGER NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (user_id, client_id)
);

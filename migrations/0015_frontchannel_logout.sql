-- OpenID Connect Front-Channel Logout 1.0. A client may register a
-- frontchannel_logout_uri; FlareID loads it in a hidden iframe when the
-- session that signed the user in to that client ends.
ALTER TABLE oauth_clients ADD COLUMN frontchannel_logout_uri TEXT NOT NULL DEFAULT '';

-- Which clients each IdP session has signed the user in to.
CREATE TABLE session_clients (
  session_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (session_id, client_id)
);

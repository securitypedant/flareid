-- oidc_sid: the derived sid the check_session marker cookie carries (never the
-- session id itself - SameSite=None would hand any site embedding the OP a
-- bearer credential). Indexed so /check_session can confirm the marker still
-- names a live session: a server-side revocation cannot clear the cookie, so
-- its presence alone proved nothing.
ALTER TABLE sessions ADD COLUMN oidc_sid TEXT;
CREATE INDEX idx_sessions_oidc_sid ON sessions(oidc_sid);

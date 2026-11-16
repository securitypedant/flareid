-- Consent recorded by claim group, not only by scope (src/lib/oidc.ts,
-- src/routes/oidc-session.ts). The consent screen lists the claim groups the
-- client would receive - including any asked for through the OIDC `claims`
-- request parameter, which is not part of the scope string - but until now
-- only the scope was stored and compared, so a `claims` request could draw
-- groups the person never saw. claim_groups is the JSON array of group names
-- shown at grant time; NULL marks rows recorded before this column, which
-- re-prompt once.
ALTER TABLE oauth_consents ADD COLUMN claim_groups TEXT;

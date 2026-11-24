-- Identifier trust model (docs/identifiers.md): three switches that decide how
-- much external data may act as a credential.
--
-- upstream_idps.allow_linking: whether a provider's claims may claim an
-- existing account (adoption) or only mint fresh JIT accounts. Default on to
-- preserve every configured provider's behaviour; existing federated_identities
-- links are unaffected either way.
--
-- user_emails.verified / user_phones.verified: whether the owner proved the
-- address/number is theirs. Rows written by admins, SCIM or imports are
-- attested (1); self-service adds start unverified until a code sent to the
-- address/number comes back. Sign-in and federated adoption only consume
-- verified rows.
--
-- idp_settings.alias_signin: when 'false', alias tables are delivery data only
-- - the login prompt resolves users.upn (plus the unambiguous local-part
-- rule), never an email/phone alias.
--
-- sms_provider etc. have no seeded rows: absent keys mean "not configured",
-- saved by Admin -> Integrations -> SMS.

ALTER TABLE upstream_idps ADD COLUMN allow_linking INTEGER NOT NULL DEFAULT 1;
ALTER TABLE user_emails ADD COLUMN verified INTEGER NOT NULL DEFAULT 1;
ALTER TABLE user_phones ADD COLUMN verified INTEGER NOT NULL DEFAULT 1;
INSERT INTO idp_settings (key, value, updated_at) VALUES ('alias_signin', 'true', CURRENT_TIMESTAMP);

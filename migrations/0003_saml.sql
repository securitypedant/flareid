-- SAML 2.0 service provider registry.
--
-- One row per SP allowed to sign users in over SAML. The model follows
-- SAML-implementation.md: v1 consumes the columns an administrator fills in
-- by hand; the metadata_* and encryption columns exist now so the
-- metadata-driven registry (saml2int [SDP-MD01]) and encrypted assertions
-- ([SDP-IDP11]) arrive as data, not schema changes.
--
-- signing_certs is a JSON *array* even though most SPs register exactly one:
-- certificate rollover has to be representable, or rotating a cert means a
-- login outage ([SDP-IDP32]).
CREATE TABLE saml_service_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  -- JSON array of absolute https URLs. An AuthnRequest may name any of them
  -- in AssertionConsumerServiceURL, and only them - this exact-match
  -- allowlist is what stops an unsigned request redirecting a signed
  -- assertion somewhere unregistered.
  acs_urls TEXT NOT NULL,
  -- Used when the AuthnRequest omits AssertionConsumerServiceURL.
  default_acs_url TEXT,
  -- 'transient' (the default, per saml2int [SDP-IDP12]), 'emailAddress' (the
  -- user's UPN) or 'persistent' (the stable external_id).
  nameid_format TEXT NOT NULL DEFAULT 'transient',
  -- JSON object mapping a SAML attribute name to a user field, e.g.
  -- {"email": "email", "groups": "groups"}. Empty object falls back to the
  -- default map in src/lib/saml/attributes.ts.
  attribute_map TEXT NOT NULL DEFAULT '{}',
  sign_response INTEGER NOT NULL DEFAULT 1,
  sign_assertion INTEGER NOT NULL DEFAULT 1,
  -- Reject unsigned AuthnRequests from this SP ([SDP-IDP05]).
  want_authn_requests_signed INTEGER NOT NULL DEFAULT 0,
  -- JSON array of PEM certificates, any of which may have signed a request.
  signing_certs TEXT NOT NULL DEFAULT '[]',
  -- Assertion encryption ([SDP-IDP11]) - not yet implemented; the columns are
  -- here so enabling it later is a code change only.
  encrypt_assertions INTEGER NOT NULL DEFAULT 0,
  encryption_cert TEXT,
  -- Metadata-driven configuration ([SDP-MD01]) - not yet implemented.
  metadata_url TEXT,
  metadata_last_refreshed_at TEXT,
  metadata_valid_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_saml_sp_entity_id ON saml_service_providers(entity_id);

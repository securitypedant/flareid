-- Inbound federation: upstream identity providers people can sign in
-- through (FlareID as OIDC relying party and SAML service provider), plus
-- the per-identity links that tie an upstream subject to a local account.
CREATE TABLE upstream_idps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
  enabled INTEGER NOT NULL DEFAULT 1,
  -- Protocol configuration JSON:
  --   oidc: {issuer, client_id, client_secret, scopes?}
  --   saml: {idp_entity_id, sso_url, certificate, nameid_format?, attr_map?}
  config TEXT NOT NULL DEFAULT '{}',
  -- JIT provisioning: 1 creates (and links) a local account for an upstream
  -- identity nobody here has seen; 0 signs in only already-linked or matched
  -- accounts.
  jit INTEGER NOT NULL DEFAULT 0,
  -- The domain JIT accounts are created under; empty falls back to the
  -- claim's email domain when it is a managed one, else the default domain.
  jit_domain TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- An upstream subject (OIDC `sub`, SAML NameID) bound to a local account.
-- First sign-in either finds this link, adopts a same-address account, or
-- (with jit) creates one - then the link makes every later sign-in direct.
CREATE TABLE federated_identities (
  idp_id INTEGER NOT NULL REFERENCES upstream_idps(id) ON DELETE CASCADE,
  subject TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT,
  last_login_at TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (idp_id, subject)
);
CREATE INDEX idx_federated_identities_user ON federated_identities(user_id);

-- The new federation permission area joins every role that already manages
-- or audits the other integrations (matched on what the role holds, so
-- builtin and custom roles are covered alike).
UPDATE admin_roles
SET permissions = json_insert(permissions, '$[#]', 'federation:write')
WHERE permissions LIKE '%"saml:write"%' AND permissions NOT LIKE '%federation%';
UPDATE admin_roles
SET permissions = json_insert(permissions, '$[#]', 'federation:read')
WHERE permissions NOT LIKE '%"saml:write"%' AND permissions LIKE '%"saml:read"%' AND permissions NOT LIKE '%federation%';

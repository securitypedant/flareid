-- Unified attribute mappings. Every attribute flow - inbound SCIM, JIT
-- federation, outbound SCIM, and per-client OIDC claims - reads its rules
-- from one table evaluated by the shared expression engine (src/lib/expr.ts).
--
--   direction  'in' (external document -> user fields) or 'out' (user fields
--              -> external attribute names)
--   channel    'scim-in' | 'jit' | 'scim-out' | 'oidc'
--   owner      '' = the channel's global/default set; otherwise the owning
--              record's id (upstream_idp.id, scim_target.id, client_id)
--   resource   'user' (group mappings may follow)
--   target     inbound: a FlareID field; outbound: the external name (SCIM
--              attribute, OIDC claim)
--   expression the expression evaluated over the source document
CREATE TABLE mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  channel TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  resource TEXT NOT NULL DEFAULT 'user',
  target TEXT NOT NULL,
  expression TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(channel, owner, resource, target)
);
CREATE INDEX idx_mappings_lookup ON mappings(channel, owner, resource, enabled, position);

-- Existing inbound SCIM mappings carry over unchanged.
INSERT INTO mappings (direction, channel, owner, resource, target, expression, position, enabled, created_at, updated_at)
  SELECT 'in', 'scim-in', '', resource, target, expression, position, enabled, created_at, updated_at FROM scim_mappings;
DROP TABLE scim_mappings;

-- JIT defaults: the claim-name preference lists the federation code applied
-- implicitly, seeded as editable global rows. Per-IdP rows (owner = the IdP's
-- id) replace the whole set for that provider when any exist.
INSERT INTO mappings (direction, channel, owner, resource, target, expression, position, enabled, created_at, updated_at) VALUES
  ('in', 'jit', '', 'user', 'email',
   'coalesce(email, mail, attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"), attr("urn:oid:0.9.2342.19200300.100.1.3"))',
   0, 1, datetime('now'), datetime('now')),
  ('in', 'jit', '', 'user', 'username',
   'coalesce(preferred_username, upn, username, attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"), attr("urn:oid:0.9.2342.19200300.100.1.1"))',
   1, 1, datetime('now'), datetime('now')),
  ('in', 'jit', '', 'user', 'display_name',
   'coalesce(name, display_name, displayName, attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"), attr("urn:oid:2.16.840.1.113730.3.1.241"))',
   2, 1, datetime('now'), datetime('now')),
  ('in', 'jit', '', 'user', 'given_name',
   'coalesce(given_name, givenname, givenName, attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"), attr("urn:oid:2.5.4.42"))',
   3, 1, datetime('now'), datetime('now')),
  ('in', 'jit', '', 'user', 'family_name',
   'coalesce(family_name, surname, familyName, attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), attr("urn:oid:2.5.4.4"))',
   4, 1, datetime('now'), datetime('now'));

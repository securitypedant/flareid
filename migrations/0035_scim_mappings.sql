-- Inbound attribute mappings: when an upstream provisioner (HR system, another
-- IdP) writes users over the SCIM server API, each row rewrites one FlareID
-- field from an expression evaluated over the incoming SCIM body. Fields with
-- no mapping keep the standard SCIM attribute mapping.
CREATE TABLE scim_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- Which SCIM resource the mapping applies to ('user'; groups may follow).
  resource TEXT NOT NULL DEFAULT 'user',
  -- The FlareID field the expression feeds: a user column name, 'upn',
  -- 'active', 'manager', 'emails', or 'custom.<key>' for custom attributes.
  target TEXT NOT NULL,
  -- Expression over the SCIM body (paths, filters, functions - see
  -- src/lib/scim-mapping.ts).
  expression TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(resource, target)
);
CREATE INDEX idx_scim_mappings_resource ON scim_mappings(resource, enabled, position);

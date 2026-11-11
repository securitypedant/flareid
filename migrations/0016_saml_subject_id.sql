-- SAML V2.0 Subject Identifier Attributes Profile: per-SP choice of releasing
-- urn:oasis:names:tc:SAML:attribute:subject-id or ...:pairwise-id
-- ('' = neither). Set from the SP's metadata (subject-id:req) or by an admin.
ALTER TABLE saml_service_providers ADD COLUMN subject_id TEXT NOT NULL DEFAULT '';

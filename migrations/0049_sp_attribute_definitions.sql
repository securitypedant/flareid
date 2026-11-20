-- Per-SP attribute definitions: the richer alternative to attribute_map.
-- A JSON array of {name, field, nameFormat?} entries letting an SP release
-- each attribute under an arbitrary SAML Name (xs:string) and NameFormat
-- (xs:anyURI) - IIP-IDP01. NULL/empty falls back to attribute_map.
ALTER TABLE saml_service_providers ADD COLUMN attribute_definitions TEXT;

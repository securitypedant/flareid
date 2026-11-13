-- Uploaded logos and per-domain brands (src/lib/brands.ts).
--
-- brand_assets: an uploaded logo, PNG or JPEG only (validated by magic bytes,
-- at most 256 KB), stored base64-encoded so no R2 bucket is needed. An asset
-- never changes: a new upload is a new row, and the content hash is part of
-- its URL (/brand/logo/<id>-<hash>.<ext>), which is what lets it be served
-- with a year-long immutable cache lifetime. Replaced and removed logos are
-- deleted.
CREATE TABLE brand_assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_type TEXT NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg')),
  data TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

-- brands: a look for the people on one or more domains. The default brand is
-- not a row: it is the existing idp_settings (app_name, login_subtitle,
-- login_gradient_*, email_accent, plus brand_logo_asset_id and custom_css /
-- custom_css_hash). In a row, an empty app_name, a NULL subtitle, gradient or
-- accent, no logo and empty custom_css each fall back to the default brand's
-- value. css_hash is the first 16 hex digits of the SHA-256 of custom_css
-- ('' when empty): it names the stylesheet URL without loading the CSS.
CREATE TABLE brands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  app_name TEXT NOT NULL DEFAULT '',
  login_subtitle TEXT,
  gradient_from TEXT,
  gradient_to TEXT,
  email_accent TEXT,
  logo_asset_id INTEGER REFERENCES brand_assets(id) ON DELETE SET NULL,
  custom_css TEXT NOT NULL DEFAULT '',
  css_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- The brand a domain's people see; NULL is the default brand. A plain column
-- rather than a declared foreign key (domains predates brands): deleting a
-- brand clears it in the same batch.
ALTER TABLE domains ADD COLUMN brand_id INTEGER;
CREATE INDEX idx_domains_brand ON domains(brand_id);

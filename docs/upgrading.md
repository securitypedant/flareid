# Upgrading an existing deployment

## The migration chain was squashed

FlareID's migrations were collapsed from sixteen files to two. Several of the
old ones existed only to seed a workshop's thirty fictional employees, its
`company.com` domain, and an administrator whose PBKDF2 hash was committed in
plain sight - none of which belongs in an identity provider anyone else
deploys. A migration chain cannot un-ship data, so the chain was replaced.

**A fresh install needs to do nothing.** `npm run deploy` applies
`0001_schema.sql` and `0002_builtin_groups.sql` and that is the whole story.

**An existing database created by the old chain will not accept them.** Its
`d1_migrations` table records sixteen migrations that no longer exist, and
`0001_schema.sql` will fail trying to create tables that are already there.

## Option 1: recreate the database (recommended)

This is now genuinely cheap, which is the point of the provisioning API.

```bash
# Keep a copy first, in case anything in there mattered.
npx wrangler d1 export flareid-db --remote --output flareid-backup.sql

npx wrangler d1 delete flareid-db
npm run deploy                     # creates it, migrates it, deploys
```

Then re-run your provisioning: `POST /api/v1/setup` for the administrator and
the domain, and `POST /api/v1/directory/import` for everyone else. If your
users came from a directory bundle, the result is identical to what you had.

What you lose: TOTP enrolments, backup codes, trusted devices, active sessions,
and the audit log. Everyone re-enrols MFA and signs in again.

## Option 2: adopt the schema in place

For a deployment whose MFA enrolments or audit history you need to keep.

The old chain and the new baseline describe the **same schema**, with one
addition - the `api_keys` table. So the work is to create that table and then
convince D1 that the new migrations have already run.

```bash
# 1. The one genuinely new table.
npx wrangler d1 execute flareid-db --remote --command "
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT '[\"admin\"]',
  created_at TEXT NOT NULL,
  created_by TEXT,
  last_used_at TEXT,
  expires_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
"

# 2. Clear the old history and record the new baseline as applied.
npx wrangler d1 execute flareid-db --remote --command "
DELETE FROM d1_migrations;
INSERT INTO d1_migrations (name, applied_at) VALUES
  ('0001_schema.sql', CURRENT_TIMESTAMP),
  ('0002_builtin_groups.sql', CURRENT_TIMESTAMP);
"
```

Then check the schema really does match, because the point of this option is
that it does:

```bash
npx wrangler d1 execute flareid-db --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
```

Expected: `access_tokens`, `api_keys`, `audit_log`, `auth_codes`, `d1_migrations`,
`domains`, `group_members`, `groups`, `idp_settings`, `mfa_backup_codes`,
`oauth_clients`, `refresh_tokens`, `sessions`, `trusted_devices`, `users`.

If anything is missing, take option 1.

## The default password changed meaning

The old `0003` migration seeded `default_password` as `Savetheinternet!1`, and
`getDefaultPassword()` fell back to the same string in code. Both are gone.
`default_password` now starts empty, and an empty value means "generate a random
password per account and return it once" rather than "use the built-in one".

If you were relying on a shared password for new accounts, set it explicitly:

```bash
curl -X POST https://idp.example.com/api/v1/setup \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"default_password":"...","new_user_password_mode":"default"}'
```

`applyDefaultPasswordToAllUsers()` now refuses and returns 0 when no default is
set, rather than setting every password in the directory to the empty string.

## Other removals

- **`ROOT_DOMAIN`** is gone from `wrangler.jsonc` and `Env`. It existed so the
  IdP could build a sibling demo application's URL for an app launcher, and the
  launcher is gone with the rest of the demo chrome. Harmless to leave in an
  old config; nothing reads it.
- **The app launcher and the "demo application with fake data" footer** no
  longer render.
- **The default login subtitle** is now "Sign in to continue." rather than
  naming a fictional company. It was already overridable from Admin → Security,
  and now also by `POST /api/v1/setup`.
- **`npm run seed:generate`** and `scripts/generate-seed.mjs` are gone. They
  read another repository's migrations to emit a FlareID migration. Directory
  data now arrives over the API.
- **`npm run deploy`** now runs `scripts/deploy.mjs`, which does rather more
  than `wrangler deploy` - creating resources, migrating, generating keys and
  setting secrets. `npm run deploy:worker-only` is the old behaviour.

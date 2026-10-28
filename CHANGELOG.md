# Changelog

Notable changes to FlareID. This project follows [semantic
versioning](https://semver.org/) from v1.0.0 onward; until then, minor versions
may break things.

## [0.1.0] - 2026-10-28

First release as a standalone project. FlareID previously lived inside a
workshop repository, and most of this release is the work of getting it out.

### Added

- **Provisioning API** at `/api/v1`: status, first-run setup, domains,
  bulk directory import, OIDC client registration, SCIM configuration, API key
  management, and a break-glass administrator reset. Documented in
  [docs/api.md](docs/api.md).
- **API keys**, managed from Admin → Integrations, stored as SHA-256 hashes and
  scoped (`directory:read`, `directory:write`, `clients:write`,
  `settings:write`, `admin`).
- **`BOOTSTRAP_TOKEN`**, a deploy-time Worker secret that configures a brand
  new instance and then retires itself once setup completes.
- **A test suite**: 73 tests running inside the Workers runtime against a local
  D1 migrated from the real migration files - the password KDF, TOTP against
  the RFC 6238 vectors, the full authorization-code and PKCE flow with
  `id_token` verification against `/jwks.json`, the refresh grant,
  introspection and revocation, and the whole provisioning API.
- **CI**: typecheck, tests, and a `wrangler deploy --dry-run` build check.
- **`npm run deploy`** (`scripts/deploy.mjs`): creates the D1 database and KV
  namespace, applies migrations, generates a signing keypair, sets the secrets,
  picks an issuer, attaches a custom domain when given a zone, and prints the
  one call needed to create the first administrator.
- **[SAML-implementation.md](SAML-implementation.md)**: a full feasibility
  assessment and implementation plan for SAML 2.0, including a correction to
  the previous claim that XML signing was impractical on Workers.
- **[docs/upgrading.md](docs/upgrading.md)**, for existing deployments.

### Changed

- **The migration chain was squashed from sixteen files to two.** Several
  existed only to seed a workshop's thirty fictional employees, its
  `company.com` domain, and an administrator whose password hash was committed.
  **This will not apply cleanly over a database built by the old chain** - see
  [docs/upgrading.md](docs/upgrading.md).
- **A deployment now starts empty**: no users, no domain row, no default
  password. The first administrator is created over the API.
- `default_password` starts unset, and unset now means "generate a random
  password per account and return it once" rather than falling back to a
  built-in string. `applyDefaultPasswordToAllUsers()` refuses when no default
  is configured, instead of blanking every password in the directory.
- `wrangler.jsonc` ships with placeholder resource ids and a localhost issuer;
  `npm run deploy` fills them in.
- `nodejs_compat` and a current `compatibility_date` are now set.
- The default login subtitle is generic, and is settable through the API.

### Removed

- **Every trace of the demo suite**: the thirty seeded users, the seeded
  administrator and its published password hash, the `company.com` domain row,
  the app launcher linking to five sibling demo applications, the "demo
  application with fake data" footer, and the `ROOT_DOMAIN` binding that
  existed to support the launcher.
- `scripts/generate-seed.mjs` and `npm run seed:generate`, which read another
  repository's migrations to emit a FlareID migration.

### Security

- No credential of any kind is shipped in this repository, other than a
  deliberately committed test-only signing key at `test/fixtures/signing-key.ts`
  (see [SECURITY.md](SECURITY.md)).
- `GET /api/v1/users` selects columns explicitly so that password and TOTP
  material cannot leave the database, and there is a test asserting it.
- Registering an OIDC client with a seeded secret shorter than 24 characters is
  now a `400`. It used to be silently replaced with a generated one, which left
  the relying party holding a credential FlareID had never heard of.

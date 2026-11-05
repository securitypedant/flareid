# Changelog

Notable changes to FlareID. This project follows [semantic
versioning](https://semver.org/) from v1.0.0 onward; until then, minor versions
may break things.

## [Unreleased]

### Security

Fixes from the v2.0.0 independent security audit (all confirmed findings of
medium severity and above; migration `0007` adds the `rate_limits` table and
`users.totp_last_counter`):

- **API scope boundaries.** `directory:write` keys can no longer grant
  `super_admin`, add members to `Super Admins`, or overwrite an existing Super
  Admin through the import; `settings:write` keys can no longer create or
  reset an administrator through `POST /api/v1/setup` after setup. Both were
  effectively admin.
- **Mandatory MFA enforced at issuance.** A password-only session minted
  before forced enrolment no longer produces OIDC codes or SAML assertions at
  the SSO endpoints - the request is parked at enrolment and resumed
  afterwards.
- **Lifecycle consistency.** Deactivating a user (console or import) now
  revokes their sessions *and* token grants immediately; `/introspect` reports
  a deactivated user's tokens inactive; the MFA step re-checks account status
  so a pending challenge cannot complete for a disabled account; password
  change and admin reset sign out the user's other sessions.
- **SAML request handling.** `/saml/complete` only redeems flows bound to the
  user who just finished login+enrolment, so an ambient session alone cannot
  answer a `ForceAuthn` request. Inflated `SAMLRequest`s are capped at 64 KB
  before any DOM parsing.
- **Login rate limiting rewritten.** Attempts are counted atomically in D1
  (the KV read-modify-write could lose increments under bursts), keyed on the
  resolved account rather than the submitted spelling, the MFA bucket moved to
  a namespace password-step input cannot reach, and the shared per-IP budget
  raised to 20x so colleagues behind one egress address can't lock each other
  out.
- **TOTP replay.** A code already accepted cannot be used again inside its
  validity window, for login or for disabling MFA.

## [2.0.0] - 2026-11-03

### Added

- **Directory schemas.** Named attribute vocabularies per object type at
  Admin → Schemas and `/api/v1/schemas` (list, create, update, delete,
  `POST /:id/apply`). Ships two provided user schemas - "Basic" (identity
  fields only, the default for new objects) and "FlareID HR" (the full
  built-in HR set) - plus a Basic group schema. Attribute names matching
  built-in fields map to columns; everything else lives in
  `custom_attributes`. Moving an object to a schema conforms it: same-named
  attributes carry over, the rest are cleared (the admin UI previews the move
  and lists what will be cleared before you save). Custom attributes reach
  SAML SPs via `attribute_map` and OIDC clients under the `custom` claim.
  Attributes are edited as add/remove rows.
- **Dynamic groups.** A group is static (assigned members) or dynamic (rule
  matches only). Rules are built in the admin UI as rows of schema ›
  attribute, `=`/`!=`, value - with suggestions drawn from values already in
  the directory - and stored as
  `{"all":[{"schema":"FlareID HR","field":"department","op":"eq","value":"Sales"}]}`.
  Membership resolves everywhere: claims, SAML attributes, SCIM pushes,
  admin pages and the API. Import bundles accept `rule` on groups.
  `Super Admins` can never be dynamic.
- **Admin console redesign.** Navigation is a left sidebar (Schemas after
  Security; breadcrumbs kept). Users list gains a Schema column and filter
  and a row menu (Edit / Delete). The user page has an Active switch in the
  header that applies immediately and signs the user out when switched off,
  attributes in two columns, a searchable manager picker that never offers
  the user themselves, a Groups section listing assigned and dynamic
  membership separately, and a reorganised Security section. Groups list
  shows Static/Dynamic with a type filter; dynamic groups list their computed
  members. You cannot deactivate or delete your own account.
- **Chosen passwords on reset.** The admin reset form accepts an optional
  password (policy-validated); blank still generates one.
- **Branding page.** App name, sign-in message and login gradient moved from
  /admin/security to their own /admin/branding tab.
- **`GET /saml/cert.pem`** downloads the IdP signing certificate - the file
  SPs like Salesforce ask to upload - linked from the SP admin pages.
- 8 new tests covering schemas, conforming, and dynamic groups (98 total).
- **SAML 2.0 service-provider-initiated SSO.** `/saml/sso` accepts
  HTTP-Redirect AuthnRequests (unsigned, or signed per the SP's registered
  certificates - including mid-rollover), and answers with an HTTP-POST
  Response carrying a signed Assertion in a signed Response. Per-SP registry
  in Admin → Integrations and `/api/v1/saml/service-providers`: ACS URL
  allowlist, NameID format (transient / emailAddress / persistent), attribute
  mapping, signing policy. IdP metadata at `/saml/metadata`; request IDs are
  single-use, `ForceAuthn` is honoured, and POSTed AuthnRequests are rejected
  by design (see SAML-implementation.md §4). Responses and Assertions are
  signed "canonically by construction" - the emitted XML is already
  exclusive-C14N form, verified in tests against `xml-crypto`.
- **`npm run saml:keygen`** (`scripts/generate-saml-cert.mjs`) mints the
  RSA-3072 self-signed certificate + PKCS8 key the endpoints need
  (`SAML_SIGNING_CERT` var, `SAML_SIGNING_KEY_PKCS8` secret); `npm run deploy`
  generates them automatically when absent.
- 16 new tests covering the metadata endpoint, the full login and SSO paths,
  signature verification, `ForceAuthn`, NameID formats, the ACS allowlist,
  request replay, signed-request verification, and the SP provisioning API.

### Changed

- **Users are created disabled.** New accounts - from the admin form or the
  import API - cannot sign in until activated via the Active control on the
  user page or `status: "active"` in the bundle. The setup/admin-reset
  administrator stays explicitly active.
- **The seeded "All Employees" group is gone.** A bare install ships only
  Super Admins. Deployments that want a company-wide group define it as a
  dynamic group (e.g. `employment_type = full_time`), which also keeps
  membership correct as attributes change. The admin form's auto-join is
  gone with it.
- **Admin layout** spans the window with the topbar's gutter, so the sidebar
  sits under the logo at every width. After creating a user you can replace
  the temporary password with one of your own (policy-checked).
- **Refresh tokens rotate.** Each use returns a new refresh token; clients
  must store it. Presenting an old one revokes the whole family.

### Security

- **Password hashing moves to scrypt** (N=2^13, r=8, p=10, ~100 ms CPU per
  hash), stored as PHC strings. Legacy PBKDF2 hashes keep working and are
  upgraded at the next sign-in. Workers caps PBKDF2 at 100,000 iterations in
  production - a limit local dev doesn't enforce - so raising it wasn't an
  option. Set `PASSWORD_HASHER=pbkdf2` on the Workers Free plan.
- **CSRF defence**: browser POSTs are verified against `Origin` /
  `Sec-Fetch-Site` / `Referer` and refused unless same-origin - sibling
  subdomains included, which `SameSite=Lax` alone allowed.
- **Security headers and CSP**: HSTS, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin`, COOP, `Permissions-Policy`, and a CSP that
  allows only FlareID's own inline scripts by SHA-256 hash. Inline event
  handlers are replaced by `data-` attributes.
- **Refresh-token lifecycle**: 30-day expiry, rotation on use, reuse
  detection (RFC 9700) that revokes the family; `/revoke` ends the family.
- **PKCE is S256-only**; `plain` and challenges without a method are refused.
- **Hourly cleanup** (Cron Trigger) of expired codes, tokens, sessions and
  trusted devices, and audit entries past a configurable retention (Admin →
  Security, default 365 days).

### Fixed

- **Dynamic groups never reached tokens or SAML assertions.** Group
  resolution loaded only the user's id before evaluating rules, so sign-ins
  carried no dynamic groups even though the admin UI listed the members.
- **Stored XSS in the multi-select**: chip labels (user and group names,
  which the import API and SCIM can set) were inserted with `innerHTML`.
- 23 new tests (121 total).

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

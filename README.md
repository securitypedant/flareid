# FlareID

A small, standalone OpenID Connect identity provider that runs on Cloudflare
Workers and D1. One Worker, no build step, no client-side framework: server
-rendered HTML for login, MFA, self-service and admin, plus the OIDC endpoints.

It exists because workshops and demos regularly need a real identity provider
and cannot have one - nobody is going to provision an Okta tenant for an
afternoon. It turned out to be useful beyond that, so it is being pulled out
into its own project.

**This is not an official Cloudflare product.** It is a personal project that
happens to run on Cloudflare's platform.

## What it does

- **OIDC**: `/authorize`, `/token` (authorization_code + refresh_token, PKCE),
  `/userinfo`, `/jwks.json`, `/introspect`, `/revoke`,
  `/.well-known/openid-configuration`. Works with Cloudflare Access's Generic
  OIDC integration, or any standards-compliant relying party.
- **Authentication**: username (or full UPN) and password, with optional
  per-user TOTP MFA, backup codes, trusted devices, and a setting to require
  MFA for everyone.
- **Directory**: users, flat groups (no nesting), multiple UPN domains, and
  HR-style attributes - job title, department, manager, employee number, hire
  date, employment status/type, location - exposed as claims so relying parties
  can write policy against them.
- **SCIM 2.0 client**: pushes users and groups to an external SCIM server, such
  as the endpoint Cloudflare Access generates for an identity provider. Scoped
  to all groups or a chosen set.
- **Admin UX** at `/admin`: users, groups, OIDC clients, API keys, domains,
  security settings, branding, and an audit log.
- **Self-service** at `/account`: MFA enrolment, password change, active
  sessions and connected applications.
- **Provisioning API** at `/api/v1`: everything above, without a browser. See
  [docs/api.md](docs/api.md).

It does not implement SAML yet. [SAML-implementation.md](SAML-implementation.md)
is the full assessment of what that would take - including a correction to the
"SAML is impractical on Workers" claim this README used to make.

## It starts empty, on purpose

A freshly migrated FlareID has **no users and no default password**. There is
nothing to log in as.

That is deliberate. The obvious alternative is to seed an administrator in a
migration, which means committing a password hash to a public repository, which
means every deployment that forgets to change it shares one known credential.
So instead the first administrator is created over the API, authenticated by a
`BOOTSTRAP_TOKEN` secret set at deploy time, and the token retires itself once
setup completes.

`npm run deploy` prints the token and the single call that uses it.

## Deploying

```bash
npm install
npx wrangler login                 # or export CLOUDFLARE_API_TOKEN
npm run deploy
```

That creates the D1 database and KV namespace, applies the migrations,
generates an RS256 signing keypair, sets the three secrets, picks an issuer,
deploys, and prints what to do next. **It writes to `wrangler.jsonc`** - the
resource ids, the issuer and the signing key's public half all live there
because they are what the Worker is deployed with, so expect a dirty working
tree afterwards.

Useful environment variables:

| Variable | Effect |
|---|---|
| `CLOUDFLARE_ACCOUNT_ID` | Required if your token can see more than one account |
| `ZONE_NAME` | Puts FlareID on `idp.<ZONE_NAME>` and makes that the issuer |
| `FLAREID_SUBDOMAIN` | Default `idp` |
| `FLAREID_ISSUER_URL` | Set the issuer explicitly |
| `FORCE_ROTATE_SIGNING_KEY` | `true` to mint a new signing keypair on redeploy |

### A note on `workers.dev` and Zero Trust

Some accounts have Access or Gateway protection over every `*.workers.dev`
hostname, which answers unauthenticated requests with `error code: 1050`. That
is fatal for an identity provider specifically: browsers and relying parties
have to reach it *before* they are authenticated, so it fails in the middle of
a login rather than at deploy time. Either add an Access bypass policy for the
hostname, or set `ZONE_NAME` and use a custom domain. The deploy script says so
too.

## First-run setup

```bash
curl -X POST https://idp.example.com/api/v1/setup \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "domain": "example.com",
        "admin": { "username": "admin" },
        "complete": true
      }'
```

The response carries the generated administrator password. Sign in at `/login`
and go to `/admin`.

For anything ongoing - CI, Terraform, a provisioning script - mint an API key
from **Admin → Integrations** instead; the bootstrap token only answers the
documented break-glass route once setup is complete.

## Local development

```bash
npm install
npm run keygen                     # once, or to rotate the signing key
npm run db:migrations:local
npm run dev                        # http://localhost:8790
```

`.dev.vars` (gitignored) needs:

```
COOKIE_ENCRYPTION_KEY=<any random string>
SIGNING_KEY_PKCS8="<private key PEM from npm run keygen>"
BOOTSTRAP_TOKEN=<any random string>
```

Then run the setup call above against `http://localhost:8790`.

## Tests

```bash
npm test          # 73 tests: crypto, OIDC flows, the provisioning API
npm run typecheck
```

The suite runs inside the Workers runtime via `@cloudflare/vitest-plugin`,
against a local D1 migrated from the real migration files - so the schema under
test is the schema that ships. CI runs both plus a `wrangler deploy --dry-run`.

## Architecture

| Piece | Where |
|---|---|
| Users, groups, membership, domains | D1: `users`, `groups`, `group_members`, `domains` |
| Registered relying parties | D1: `oauth_clients` |
| Authorization codes, access and refresh tokens | D1: `auth_codes`, `access_tokens`, `refresh_tokens` |
| Sessions, trusted devices, backup codes | D1: `sessions`, `trusted_devices`, `mfa_backup_codes` |
| Provisioning API keys | D1: `api_keys` (SHA-256 hashes only) |
| Settings, audit log | D1: `idp_settings`, `audit_log` |
| Short-lived login-flow and pending-MFA state, rate limits | KV: `SESSIONS_KV` |
| `id_token` signing | RS256 via `jose`; keypair from `scripts/generate-keypair.mjs` |
| Password hashing | PBKDF2-SHA256 via Web Crypto, iteration count stored per row |
| TOTP | RFC 6238 by hand (HMAC-SHA1, 6 digits, 30s), authenticator-app compatible |

## Wiring into Cloudflare Access (Generic OIDC)

1. In FlareID, **Admin → Integrations → + New client**. Give it a name and the
   redirect URI Access will call back to - something like
   `https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`. Copy the
   client id and the secret, which is shown once.
2. In [Cloudflare Zero Trust](https://one.dash.cloudflare.com) →
   **Integrations** → **Identity providers** → **Add new** → **OpenID
   Connect**, fill in:
   - **App ID**: the client id
   - **Client secret**: the secret
   - **Auth URL**: `https://<flareid-host>/authorize`
   - **Token URL**: `https://<flareid-host>/token`
   - **Certificate URL**: `https://<flareid-host>/jwks.json`
   - **Scopes**: `openid email profile groups`
   - Optional claims: `groups`
3. Save, then add it to your Access applications.

Access policies can then match on `email` or on the `groups` claim directly.
Enabling SCIM on the identity provider and configuring the endpoint and secret
under **Admin → Integrations** makes group names appear in the policy builder,
but is not required for group matching to work.

The whole of this can be done over the API instead - see
[docs/api.md](docs/api.md).

## Roadmap

[ROADMAP.md](ROADMAP.md) is honest about what this is: a functional identity
provider with a list of things that have to be true before it should be pointed
at anything that matters. The current head of that list is that there was no
test suite at all until recently, and that CSRF defence, security headers and a
stronger password KDF are still outstanding.
